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
