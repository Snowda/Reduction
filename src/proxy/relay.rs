use std::io;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::error::{ReductionError, Result};

pub struct RelayStats {
    pub bytes_a_to_b: u64,
    pub bytes_b_to_a: u64,
    pub duration: Duration,
}

pub async fn relay_bidirectional<A, B>(
    mut a: A,
    mut b: B,
    idle_timeout: Duration,
    shutdown: CancellationToken,
) -> Result<RelayStats>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let start: Instant = Instant::now();

    let result: io::Result<(u64, u64)> = tokio::select! {
        result = tokio::time::timeout(idle_timeout, tokio::io::copy_bidirectional(&mut a, &mut b)) => {
            match result {
                Ok(r) => r,
                Err(_) => {
                    debug!("relay idle timeout reached");
                    return Ok(RelayStats {
                        bytes_a_to_b: 0,
                        bytes_b_to_a: 0,
                        duration: start.elapsed(),
                    });
                }
            }
        }
        _ = shutdown.cancelled() => {
            debug!("relay cancelled by shutdown");
            return Ok(RelayStats {
                bytes_a_to_b: 0,
                bytes_b_to_a: 0,
                duration: start.elapsed(),
            });
        }
    };

    match result {
        Ok((a_to_b, b_to_a)) => {
            return Ok(RelayStats {
                bytes_a_to_b: a_to_b,
                bytes_b_to_a: b_to_a,
                duration: start.elapsed(),
            });
        }
        Err(e) => {
            return Err(ReductionError::ConnectTunnel(format!("relay error: {e}")));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::duplex;

    #[tokio::test]
    async fn test_relay_bidirectional_basic() {
        let (client, proxy_client) = duplex(1024);
        let (proxy_backend, backend) = duplex(1024);
        let shutdown: CancellationToken = CancellationToken::new();

        let relay_handle = tokio::spawn(relay_bidirectional(
            proxy_client,
            proxy_backend,
            Duration::from_secs(5),
            shutdown,
        ));

        let send_handle = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut cr, mut cw) = tokio::io::split(client);
            let (mut br, mut bw) = tokio::io::split(backend);

            cw.write_all(b"hello backend").await.unwrap();
            cw.shutdown().await.unwrap();

            let mut buf: Vec<u8> = Vec::new();
            br.read_to_end(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello backend");

            bw.write_all(b"hello client").await.unwrap();
            bw.shutdown().await.unwrap();

            let mut buf2: Vec<u8> = Vec::new();
            cr.read_to_end(&mut buf2).await.unwrap();
            assert_eq!(&buf2, b"hello client");
        });

        send_handle.await.unwrap();
        let stats: RelayStats = relay_handle.await.unwrap().unwrap();
        assert_eq!(stats.bytes_a_to_b, 13);
        assert_eq!(stats.bytes_b_to_a, 12);
    }

    #[tokio::test]
    async fn test_relay_cancelled_by_shutdown() {
        let (proxy_client, _client) = duplex(1024);
        let (proxy_backend, _backend) = duplex(1024);
        let shutdown: CancellationToken = CancellationToken::new();

        shutdown.cancel();

        let stats: RelayStats = relay_bidirectional(
            proxy_client,
            proxy_backend,
            Duration::from_secs(5),
            shutdown,
        )
        .await
        .unwrap();

        assert_eq!(stats.bytes_a_to_b, 0);
        assert_eq!(stats.bytes_b_to_a, 0);
    }

    #[tokio::test]
    async fn test_relay_idle_timeout() {
        let (proxy_client, _client) = duplex(1024);
        let (proxy_backend, _backend) = duplex(1024);
        let shutdown: CancellationToken = CancellationToken::new();

        let stats: RelayStats = relay_bidirectional(
            proxy_client,
            proxy_backend,
            Duration::from_millis(10),
            shutdown,
        )
        .await
        .unwrap();

        assert_eq!(stats.bytes_a_to_b, 0);
    }

    #[tokio::test]
    async fn test_relay_empty_streams() {
        let (client, proxy_client) = duplex(1024);
        let (proxy_backend, backend) = duplex(1024);
        let shutdown: CancellationToken = CancellationToken::new();

        drop(client);
        drop(backend);

        let stats: RelayStats = relay_bidirectional(
            proxy_client,
            proxy_backend,
            Duration::from_secs(5),
            shutdown,
        )
        .await
        .unwrap();

        assert_eq!(stats.bytes_a_to_b, 0);
        assert_eq!(stats.bytes_b_to_a, 0);
    }
}
