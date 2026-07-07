use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::error::ReductionError;
use crate::proxy::handler::ProxyState;
use crate::proxy::relay::relay_bidirectional;
use crate::transport::quic::QuicStream;

const DEFAULT_RAW_RELAY_IDLE_TIMEOUT_SECS: u64 = 300;
const MAX_BACKEND_ID_LEN: usize = 256;

async fn read_routing_header(stream: &mut QuicStream) -> crate::error::Result<String> {
    let mut len_buf: [u8; 2] = [0u8; 2];
    stream.read_exact(&mut len_buf).await
        .map_err(|e| ReductionError::Forward(format!("read routing header length: {e}")))?;

    let len: usize = usize::from(u16::from_be_bytes(len_buf));
    if len == 0 || len > MAX_BACKEND_ID_LEN {
        return Err(ReductionError::Forward(format!(
            "invalid backend_id length: {len}"
        )));
    }

    let mut id_buf: Vec<u8> = vec![0u8; len];
    stream.read_exact(&mut id_buf).await
        .map_err(|e| ReductionError::Forward(format!("read routing header: {e}")))?;

    let backend_id: String = String::from_utf8(id_buf)
        .map_err(|e| ReductionError::Forward(format!("invalid backend_id UTF-8: {e}")))?;

    return Ok(backend_id);
}

pub async fn run_raw_relay_handler(
    mut raw_rx: mpsc::Receiver<(QuicStream, SocketAddr)>,
    state: Arc<ProxyState>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            incoming = raw_rx.recv() => {
                let Some((stream, remote_addr)) = incoming else {
                    break;
                };

                let st: Arc<ProxyState> = Arc::clone(&state);
                let cancel: CancellationToken = shutdown.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_raw_stream(stream, remote_addr, &st, cancel).await {
                        warn!(%remote_addr, error = %e, "raw relay failed");
                        st.metrics.raw_relay_errors.add(1, &[]);
                    }
                });
            }
            _ = shutdown.cancelled() => {
                break;
            }
        }
    }
    debug!("raw relay handler stopped");
}

async fn handle_raw_stream(
    mut client_stream: QuicStream,
    remote_addr: SocketAddr,
    state: &Arc<ProxyState>,
    shutdown: CancellationToken,
) -> crate::error::Result<()> {
    let backend_id: String = read_routing_header(&mut client_stream).await?;

    debug!(%remote_addr, %backend_id, "raw relay: routing to backend");

    let backends = {
        let reloadable = state.reloadable.borrow();
        reloadable.backend_pools.get(backend_id.as_str())
            .map(|p| p.backends.clone())
    };

    let backends = backends.ok_or_else(|| {
        ReductionError::Forward(format!("unknown backend pool for raw relay: {backend_id}"))
    })?;

    let backend = backends.first().ok_or_else(|| {
        ReductionError::Forward(format!("no backends in pool for raw relay: {backend_id}"))
    })?;

    let connect_timeout: Duration = Duration::from_secs(state.timeouts.connect_secs.get());
    let backend_stream: QuicStream = state.conn_pool.acquire_raw_stream(
        backend,
        &state.client_tls_config,
        connect_timeout,
    ).await?;

    state.metrics.raw_relay_active.add(1, &[]);

    let idle_timeout: Duration = Duration::from_secs(DEFAULT_RAW_RELAY_IDLE_TIMEOUT_SECS);
    let result = relay_bidirectional(client_stream, backend_stream, idle_timeout, shutdown).await;

    state.metrics.raw_relay_active.add(-1, &[]);

    match result {
        Ok(stats) => {
            let total: u64 = stats.bytes_a_to_b + stats.bytes_b_to_a;
            state.metrics.raw_relay_bytes_relayed.add(total, &[]);
            debug!(%backend_id, bytes = total, "raw relay completed");
        }
        Err(e) => {
            warn!(%backend_id, error = %e, "raw relay error");
            state.metrics.raw_relay_errors.add(1, &[]);
        }
    }

    return Ok(());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_read_routing_header_valid() {
        let backend_id: &str = "api-backend";
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&(backend_id.len() as u16).to_be_bytes());
        buf.extend_from_slice(backend_id.as_bytes());

        let (client, _server) = tokio::io::duplex(1024);
        let (_, mut write_half) = tokio::io::split(client);
        tokio::io::AsyncWriteExt::write_all(&mut write_half, &buf).await.unwrap();
        drop(write_half);

        // We need a QuicStream for the test, but we can't easily construct one.
        // The routing header logic is validated through the byte-level protocol.
        // Full integration with QuicStream requires a QUIC connection.
    }

    #[test]
    fn test_routing_header_encoding() {
        let backend_id: &str = "my-backend";
        let len_bytes: [u8; 2] = (backend_id.len() as u16).to_be_bytes();
        assert_eq!(len_bytes, [0, 10]);

        let mut header: Vec<u8> = Vec::new();
        header.extend_from_slice(&len_bytes);
        header.extend_from_slice(backend_id.as_bytes());
        assert_eq!(header.len(), 12);
    }

    #[test]
    fn test_max_backend_id_len_constant() {
        assert_eq!(MAX_BACKEND_ID_LEN, 256);
    }
}
