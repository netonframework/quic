use std::{fs::File, io::BufReader, sync::Arc};

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub const ALPN: &[u8] = b"neton-interop";

pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
}

pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub fn certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut r = BufReader::new(File::open(path).with_context(|| path.to_string())?);
    Ok(rustls_pemfile::certs(&mut r).collect::<Result<Vec<_>, _>>()?)
}

pub fn key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let mut r = BufReader::new(File::open(path).with_context(|| path.to_string())?);
    rustls_pemfile::private_key(&mut r)?.context("no private key")
}

/// Deterministic test data.
pub fn data(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}
