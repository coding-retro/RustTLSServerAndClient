use anyhow::{Context, Result};
use rustls::{ClientConfig, RootCertStore};
use std::{io::Cursor, sync::Arc};
use tokio::{ io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream };
use tokio_rustls::TlsConnector;

const CA_CERT: &[u8] = include_bytes!("../ca-cert.pem");

#[tokio::main]
async fn main() -> Result<()> {
    let mut roots = RootCertStore::empty();
    let mut cursor = Cursor::new(CA_CERT);

    let certs = rustls_pemfile::certs(&mut cursor).collect::<std::io::Result<Vec<_>>>()?;
    for cert in certs { roots.add(cert)?; }

    let config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let addr = "127.0.0.1:8443";
    let domain = "localhost".try_into().context("invalid DNS name")?;

    println!("Connecting to {addr}...");
    let stream = TcpStream::connect(addr).await?;
    let mut tls = connector.connect(domain, stream).await?;

    let msg = b"hello from client\n";
    tls.write_all(msg).await?;
    println!("> sent: {}", String::from_utf8_lossy(msg));

    let mut buf = vec![0u8; 1024];
    let n = tls.read(&mut buf).await?;
    println!("< recv: {}", String::from_utf8_lossy(&buf[..n]));

    Ok(())
}
