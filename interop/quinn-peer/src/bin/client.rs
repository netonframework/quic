//! quinn echo client: `client <server addr> <server name> <ca.pem> [streams] [alpn]`.
//! Opens streams one after another, each echoed and compared, each in a new key phase forced 300 ms after the previous echo; closes with 0x42.
//! With a wrong CA or ALPN the connection error is printed and the exit status is 2.

#[path = "../common.rs"]
mod common;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{bail, Result};
use quinn::crypto::rustls::{HandshakeData, QuicClientConfig};

#[tokio::main]
async fn main() -> Result<()> {
    common::init_tracing();
    let args: Vec<String> = std::env::args().collect();
    let addr: SocketAddr = args[1].parse()?;
    let name = &args[2];
    let streams: usize = args.get(4).map(|s| s.parse()).transpose()?.unwrap_or(8);
    let alpn = args.get(5).map(|s| s.as_bytes().to_vec()).unwrap_or_else(|| common::ALPN.to_vec());

    let mut roots = rustls::RootCertStore::empty();
    for c in common::certs(&args[3])? {
        roots.add(c)?;
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(common::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![alpn];
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?)));

    let conn = match endpoint.connect(addr, name)?.await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[quinn interop] client: connection failed: {e}");
            std::process::exit(2);
        }
    };
    let hd = conn.handshake_data().unwrap().downcast::<HandshakeData>().unwrap();
    let certs = conn.peer_identity().unwrap().downcast::<Vec<rustls::pki_types::CertificateDer>>().unwrap();
    eprintln!(
        "[quinn interop] client connected to {name}; ALPN {:?}; server chain {} certificate(s)",
        hd.protocol.as_deref().map(String::from_utf8_lossy),
        certs.len()
    );
    let mut total = 0;
    for i in 0..streams {
        let (mut send, mut recv) = conn.open_bi().await?;
        let msg = common::data(100_000 + i * 997, i as u64);
        let writer = tokio::spawn(async move {
            send.write_all(&msg).await?;
            send.finish()?;
            anyhow::Ok(msg)
        });
        let back = recv.read_to_end(64 << 20).await?;
        let msg = writer.await??;
        if back != msg {
            bail!("stream {i}: echo differs ({} vs {} bytes)", back.len(), msg.len());
        }
        total += back.len();
        // the server's update came with the echo; once it is discarded (3 PTO), update ours and send the next
        // stream in the new key phase
        tokio::time::sleep(Duration::from_millis(300)).await;
        conn.force_key_update();
    }
    let s = conn.stats();
    eprintln!(
        "[quinn interop] client echoed {streams} streams, {total} bytes; sent {} / lost {} packets",
        s.path.sent_packets, s.path.lost_packets
    );
    conn.close(0x42u32.into(), b"done");
    endpoint.wait_idle().await;
    eprintln!("[quinn interop] client closed: {:?}", conn.close_reason());
    Ok(())
}
