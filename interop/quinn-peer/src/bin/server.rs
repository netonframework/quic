//! quinn echo server: `server <listen addr> <cert.pem> <key.pem> [connections]`.
//! Echoes every bidirectional stream, each echo in a new key phase forced 300 ms after the stream was read.
//! Accepts 0-RTT from clients holding one of its tickets.

#[path = "../common.rs"]
mod common;

use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use quinn::crypto::rustls::{HandshakeData, QuicServerConfig};

#[tokio::main]
async fn main() -> Result<()> {
    common::init_tracing();
    let args: Vec<String> = std::env::args().collect();
    let listen: SocketAddr = args[1].parse()?;
    let conns: usize = args.get(4).map(|s| s.parse()).transpose()?.unwrap_or(1);

    let mut tls = rustls::ServerConfig::builder_with_provider(common::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(common::certs(&args[2])?, common::key(&args[3])?)?;
    tls.alpn_protocols = vec![common::ALPN.to_vec()];
    // 0-RTT (QUIC allows only 0 or u32::MAX); tickets and the stateful session cache are rustls's defaults
    tls.max_early_data_size = u32::MAX;
    let cfg = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    let endpoint = quinn::Endpoint::server(cfg, listen)?;
    eprintln!("[quinn interop] server listening on {}", endpoint.local_addr()?);

    for n in 0..conns {
        let Some(incoming) = endpoint.accept().await else { break };
        // A client with a ticket sends 0-RTT data, which the connection accepts during the handshake (into_0rtt is
        // only needed to answer before the handshake completes)
        let conn = match incoming.await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[quinn interop] conn {n}: handshake failed: {e}");
                continue;
            }
        };
        let hd = conn.handshake_data().unwrap().downcast::<HandshakeData>().unwrap();
        eprintln!(
            "[quinn interop] conn {n}: from {}; ALPN {:?}; SNI {:?}",
            conn.remote_address(),
            hd.protocol.as_deref().map(String::from_utf8_lossy),
            hd.server_name
        );
        let mut streams = 0;
        loop {
            match conn.accept_bi().await {
                Ok((mut send, mut recv)) => {
                    let data = recv.read_to_end(64 << 20).await?;
                    // the client's update came with this stream; once it is discarded (3 PTO), update ours and send
                    // the echo in the new key phase
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    conn.force_key_update();
                    send.write_all(&data).await?;
                    send.finish()?;
                    streams += 1;
                }
                Err(e) => {
                    let s = conn.stats();
                    eprintln!(
                        "[quinn interop] conn {n}: closed: {e}; streams echoed {streams}; sent {} / lost {} packets",
                        s.path.sent_packets, s.path.lost_packets
                    );
                    break;
                }
            }
        }
    }
    endpoint.wait_idle().await;
    eprintln!("[quinn interop] server done");
    Ok(())
}
