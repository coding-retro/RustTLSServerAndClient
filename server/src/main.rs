use rcgen::*;
use rustls::{Certificate as RCert, PrivateKey, ServerConfig};
use std::{fs, io::{Read, BufReader}, net::SocketAddr, sync::Arc};
use std::fs::File;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener};
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() {
    if !(fs::exists("ca-cert.pem").unwrap() && fs::exists("server-cert.pem").unwrap() && fs::exists("server-key.pem").unwrap()) {
        let mut ca = CertificateParams::default();
        ca.distinguished_name.push(DnType::CommonName, "Home CA");
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_pair = Some(KeyPair::generate(&PKCS_ECDSA_P256_SHA256).unwrap());
        let ca_cert = Certificate::from_params(ca).unwrap();
        fs::write("ca-cert.pem", ca_cert.serialize_pem().unwrap()).unwrap();
        fs::write("ca-key.pem", ca_cert.serialize_private_key_pem()).unwrap();
        println!("CA generated");

        let mut p = CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]);
        p.distinguished_name.push(DnType::CommonName, "Local Server");
        p.key_pair = Some(KeyPair::generate(&PKCS_ECDSA_P256_SHA256).unwrap());
        let srv = Certificate::from_params(p).unwrap();
        let pem = srv.serialize_pem_with_signer(&ca_cert).unwrap();
        fs::write("server-cert.pem", &pem).unwrap();
        fs::write("server-key.pem", srv.serialize_private_key_pem()).unwrap();
        println!("Server cert generated");
    } else { 
        println!("Using existing certificates"); 
    }

    let mut pem = String::new();
    File::open("server-cert.pem").unwrap().read_to_string(&mut pem).unwrap();
    let mut certs: Vec<_> = rustls_pemfile::certs(&mut pem.as_bytes()).unwrap().into_iter().map(RCert).collect();
    let mut ca_pem = String::new();
    File::open("ca-cert.pem").unwrap().read_to_string(&mut ca_pem).unwrap();
    for c in rustls_pemfile::certs(&mut ca_pem.as_bytes()).unwrap() {
        certs.push(RCert(c));
    }

    let key = {
        let f = File::open("server-key.pem").unwrap();
        let mut reader = BufReader::new(f);
        let mut keys = rustls_pemfile::pkcs8_private_keys(&mut reader).unwrap();
        if keys.is_empty() {
            let f2 = File::open("server-key.pem").unwrap();
            let mut reader2 = BufReader::new(f2);
            keys = rustls_pemfile::rsa_private_keys(&mut reader2).unwrap();
        }
        if keys.is_empty() {
            panic!("no private keys found in server-key.pem");
        }
        PrivateKey(keys.remove(0))
    };

    let cfg = Arc::new(ServerConfig::builder().with_safe_defaults().with_no_client_auth().with_single_cert(certs, key).unwrap());

    let acceptor = TlsAcceptor::from(cfg);
    let addr: SocketAddr = "0.0.0.0:8443".parse().unwrap();
    let listener = TcpListener::bind(addr).await.unwrap();
    println!("Listening on {addr}");

    loop {
        let (tcp, peer) = listener.accept().await.unwrap();
        let acc = acceptor.clone();
        tokio::spawn(async move {
            let mut stream = acc.accept(tcp).await.unwrap();
            println!("{peer} connected");
            let mut buf = [0; 1024];
            loop {
                let num = match stream.read(&mut buf).await { Ok(0) => break, Ok(num) => num, Err(_) => break };
                println!("{peer} recv: {}", String::from_utf8_lossy(&buf[..num]));
                if stream.write_all(&buf[..num]).await.is_err() { break }
            }
            println!("{peer} closed");
        });
    }
}
