use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::{Endpoint, Incoming, RecvStream, SendStream, ServerConfig};
use quinn::crypto::rustls::QuicServerConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{error, info};

use crate::error::Result;

const INITIAL_BACKOFF: Duration = Duration::from_millis(50);
const MAX_BACKOFF: Duration = Duration::from_secs(5);

// Wraps a QUIC bidirectional stream to implement AsyncRead + AsyncWrite.
pub struct QuicStream {
    send: SendStream,
    recv: RecvStream,
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

pub struct QuicListener {
    endpoint: Endpoint,
}

impl QuicListener {
    pub fn bind(addr: SocketAddr, server_config: ServerConfig) -> Result<Self> {
        let endpoint: Endpoint = Endpoint::server(server_config, addr)
            .map_err(|e| crate::error::ReductionError::Transport(format!("QUIC bind: {e}")))?;

        info!(%addr, "QUIC listener bound");

        return Ok(Self { endpoint });
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        return self.endpoint.local_addr();
    }
}

impl axum::serve::Listener for QuicListener {
    type Io = QuicStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let mut backoff: Duration = INITIAL_BACKOFF;

        loop {
            let incoming: Incoming = match self.endpoint.accept().await {
                Some(incoming) => incoming,
                None => {
                    error!("QUIC endpoint closed");
                    std::future::pending::<()>().await;
                    unreachable!();
                }
            };

            let remote_addr: SocketAddr = incoming.remote_address();

            let connection = match incoming.await {
                Ok(conn) => {
                    backoff = INITIAL_BACKOFF;
                    conn
                }
                Err(e) => {
                    error!(error = %e, backoff_ms = backoff.as_millis(), "QUIC connection failed, backing off");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    continue;
                }
            };

            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    return (QuicStream { send, recv }, remote_addr);
                }
                Err(e) => {
                    error!(error = %e, "QUIC stream accept failed");
                    continue;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        return self.endpoint.local_addr();
    }
}

// Build a quinn ServerConfig from a rustls ServerConfig.
pub fn build_quic_server_config(
    rustls_config: Arc<rustls::ServerConfig>,
) -> Result<ServerConfig> {
    let quic_crypto: QuicServerConfig = QuicServerConfig::try_from(rustls_config)
        .map_err(|e| crate::error::ReductionError::Config(format!("QUIC crypto config: {e}")))?;

    let quic_config: ServerConfig = ServerConfig::with_crypto(Arc::new(quic_crypto));
    return Ok(quic_config);
}
