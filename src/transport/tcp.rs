use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener as TokioTcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tracing::{error, info};

use crate::error::Result;

const INITIAL_BACKOFF: Duration = Duration::from_millis(50);
const MAX_BACKOFF: Duration = Duration::from_secs(5);

pub struct TcpListener {
    inner: TokioTcpListener,
    tls_acceptor: TlsAcceptor,
}

impl TcpListener {
    pub async fn bind(addr: SocketAddr, tls_config: Arc<rustls::ServerConfig>) -> Result<Self> {
        let inner: TokioTcpListener = TokioTcpListener::bind(addr).await?;
        let tls_acceptor: TlsAcceptor = TlsAcceptor::from(tls_config);

        info!(%addr, "TCP listener bound");

        return Ok(Self { inner, tls_acceptor });
    }
}

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, TcpListener>>
    for super::ConnectAddr
{
    fn connect_info(target: axum::serve::IncomingStream<'_, TcpListener>) -> Self {
        return Self(*target.remote_addr());
    }
}

impl axum::serve::Listener for TcpListener {
    type Io = TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let mut backoff: Duration = INITIAL_BACKOFF;

        loop {
            match self.inner.accept().await {
                Ok((tcp_stream, peer_addr)) => {
                    backoff = INITIAL_BACKOFF;
                    match self.tls_acceptor.accept(tcp_stream).await {
                        Ok(tls_stream) => {
                            return (tls_stream, peer_addr);
                        }
                        Err(e) => {
                            error!(error = %e, "TLS handshake failed");
                            continue;
                        }
                    }
                }
                Err(e) => {
                    error!(error = %e, backoff_ms = backoff.as_millis(), "TCP accept failed, backing off");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        return self.inner.local_addr();
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;
    use crate::tls::certs::build_server_config;

    fn generate_ca() -> rcgen::CertifiedKey {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String("Test CA".to_string()),
        );
        let cert = params.self_signed(&key).unwrap();
        return rcgen::CertifiedKey { cert, key_pair: key };
    }

    fn generate_signed_cert(ca: &rcgen::CertifiedKey) -> rcgen::CertifiedKey {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String("localhost".to_string()),
        );
        let cert = params.signed_by(&key, &ca.cert, &ca.key_pair).unwrap();
        return rcgen::CertifiedKey { cert, key_pair: key };
    }

    fn write_pem(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        return f;
    }

    fn make_server_tls_config() -> Arc<rustls::ServerConfig> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = generate_ca();
        let leaf = generate_signed_cert(&ca);

        let ca_file = write_pem(&ca.cert.pem());
        let cert_file = write_pem(&leaf.cert.pem());
        let key_file = write_pem(&leaf.key_pair.serialize_pem());

        let config = build_server_config(
            cert_file.path(),
            key_file.path(),
            ca_file.path(),
        ).unwrap();
        return Arc::new(config);
    }

    #[tokio::test]
    async fn test_tcp_listener_bind_and_local_addr() {
        let tls_config = make_server_tls_config();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr, tls_config).await.unwrap();
        let local = axum::serve::Listener::local_addr(&listener).unwrap();
        assert_eq!(local.ip(), std::net::IpAddr::from([127, 0, 0, 1]));
        assert_ne!(local.port(), 0);
    }

    #[tokio::test]
    async fn test_tcp_listener_binds_ephemeral_port() {
        let tls_config = make_server_tls_config();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr, tls_config).await.unwrap();
        let local = axum::serve::Listener::local_addr(&listener).unwrap();
        assert!(local.port() > 0);
    }

    #[tokio::test]
    async fn test_tcp_listener_two_listeners_different_ports() {
        let tls_config = make_server_tls_config();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener1 = TcpListener::bind(addr, tls_config.clone()).await.unwrap();
        let listener2 = TcpListener::bind(addr, tls_config).await.unwrap();
        let port1 = axum::serve::Listener::local_addr(&listener1).unwrap().port();
        let port2 = axum::serve::Listener::local_addr(&listener2).unwrap().port();
        assert_ne!(port1, port2);
    }

    #[test]
    fn test_initial_backoff_constant() {
        assert_eq!(INITIAL_BACKOFF, Duration::from_millis(50));
    }

    #[test]
    fn test_max_backoff_constant() {
        assert_eq!(MAX_BACKOFF, Duration::from_secs(5));
    }

    #[test]
    fn test_connect_addr_deref() {
        let addr = super::super::ConnectAddr("10.0.0.1:5000".parse().unwrap());
        let socket_addr: &SocketAddr = &*addr;
        assert_eq!(socket_addr.port(), 5000);
    }
}
