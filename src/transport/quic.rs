use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::{Endpoint, Incoming, RecvStream, SendStream, ServerConfig};
use quinn::crypto::rustls::QuicServerConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::error::{ReductionError, Result};

pub struct QuicStream {
    send: SendStream,
    recv: RecvStream,
}

impl QuicStream {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        return Self { send, recv };
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        return Pin::new(&mut self.recv).poll_read(cx, buf);
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        return Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map(|r| r.map_err(io::Error::other));
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        return Pin::new(&mut self.send).poll_flush(cx);
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        return Pin::new(&mut self.send).poll_shutdown(cx);
    }
}

impl Unpin for QuicStream {}

const STREAM_CHANNEL_CAPACITY: usize = 256;

pub struct QuicListener {
    stream_rx: mpsc::Receiver<(QuicStream, SocketAddr)>,
    local_addr: SocketAddr,
}

impl QuicListener {
    pub fn bind(addr: SocketAddr, server_config: ServerConfig) -> Result<Self> {
        let endpoint: Endpoint = Endpoint::server(server_config, addr)
            .map_err(|e| ReductionError::Transport(format!("QUIC bind: {e}")))?;

        let local_addr: SocketAddr = endpoint
            .local_addr()
            .map_err(|e| ReductionError::Transport(format!("QUIC local addr: {e}")))?;

        info!(%addr, "QUIC listener bound");

        let (stream_tx, stream_rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
        tokio::spawn(accept_connections(endpoint, stream_tx));

        return Ok(Self { stream_rx, local_addr });
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        return Ok(self.local_addr);
    }
}

async fn accept_connections(
    endpoint: Endpoint,
    stream_tx: mpsc::Sender<(QuicStream, SocketAddr)>,
) {
    while let Some(incoming) = endpoint.accept().await {
        let remote_addr: SocketAddr = incoming.remote_address();
        let tx: mpsc::Sender<(QuicStream, SocketAddr)> = stream_tx.clone();

        tokio::spawn(async move {
            handle_connection(incoming, remote_addr, tx).await;
        });
    }
    debug!("QUIC endpoint closed, connection acceptor stopping");
}

async fn handle_connection(
    incoming: Incoming,
    remote_addr: SocketAddr,
    stream_tx: mpsc::Sender<(QuicStream, SocketAddr)>,
) {
    let connection: quinn::Connection = match incoming.await {
        Ok(conn) => conn,
        Err(e) => {
            error!(error = %e, %remote_addr, "QUIC connection handshake failed");
            return;
        }
    };

    debug!(%remote_addr, "QUIC connection established");

    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let stream: QuicStream = QuicStream::new(send, recv);
                if stream_tx.send((stream, remote_addr)).await.is_err() {
                    return;
                }
            }
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                debug!(%remote_addr, "QUIC connection closed by peer");
                return;
            }
            Err(e) => {
                debug!(error = %e, %remote_addr, "QUIC connection ended");
                return;
            }
        }
    }
}

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, QuicListener>>
    for super::ConnectAddr
{
    fn connect_info(target: axum::serve::IncomingStream<'_, QuicListener>) -> Self {
        return Self(*target.remote_addr());
    }
}

impl axum::serve::Listener for QuicListener {
    type Io = QuicStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        return self
            .stream_rx
            .recv()
            .await
            .expect("QUIC acceptor task stopped unexpectedly");
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        return Ok(self.local_addr);
    }
}

pub fn build_quic_server_config(
    rustls_config: Arc<rustls::ServerConfig>,
) -> Result<ServerConfig> {
    let quic_crypto: QuicServerConfig = QuicServerConfig::try_from(rustls_config)
        .map_err(|e| ReductionError::Config(format!("QUIC crypto config: {e}")))?;

    let quic_config: ServerConfig = ServerConfig::with_crypto(Arc::new(quic_crypto));
    return Ok(quic_config);
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

    fn make_server_rustls_config() -> Arc<rustls::ServerConfig> {
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

    #[test]
    fn test_build_quic_server_config_valid() {
        let rustls_config = make_server_rustls_config();
        let result = build_quic_server_config(rustls_config);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_quic_listener_bind_and_local_addr() {
        let rustls_config = make_server_rustls_config();
        let quic_config = build_quic_server_config(rustls_config).unwrap();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = QuicListener::bind(addr, quic_config).unwrap();
        let local = listener.local_addr().unwrap();
        assert_eq!(local.ip(), std::net::IpAddr::from([127, 0, 0, 1]));
        assert_ne!(local.port(), 0);
    }

    #[tokio::test]
    async fn test_quic_listener_local_addr_via_listener_trait() {
        let rustls_config = make_server_rustls_config();
        let quic_config = build_quic_server_config(rustls_config).unwrap();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = QuicListener::bind(addr, quic_config).unwrap();
        let local: SocketAddr = axum::serve::Listener::local_addr(&listener).unwrap();
        assert_eq!(local.ip(), std::net::IpAddr::from([127, 0, 0, 1]));
    }

    #[test]
    fn test_connect_addr_from_quic_stream() {
        let addr = super::super::ConnectAddr("10.0.0.1:5000".parse().unwrap());
        assert_eq!(*addr, "10.0.0.1:5000".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_stream_channel_capacity_constant() {
        assert_eq!(STREAM_CHANNEL_CAPACITY, 256);
    }
}
