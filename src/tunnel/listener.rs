use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, ServerConfig};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use arrayvec::ArrayString;
use tracing::{debug, info, warn};

use crate::config::TunnelConfig;
use crate::error::{ReductionError, Result};
use crate::metrics::ProxyMetrics;
use crate::transport::quic::QuicStream;
use crate::tunnel::protocol::{self, SessionId, TunnelFrame};
use crate::tunnel::registry::{TunnelRegistry, TunnelSession};

pub async fn run_tunnel_listener(
    bind_addr: SocketAddr,
    server_tls_config: Arc<rustls::ServerConfig>,
    registry: Arc<TunnelRegistry>,
    shutdown: CancellationToken,
    config: TunnelConfig,
    metrics: ProxyMetrics,
) -> Result<()> {
    let quic_crypto: QuicServerConfig = QuicServerConfig::try_from(server_tls_config)
        .map_err(|e| ReductionError::Tunnel(format!("QUIC crypto config: {e}")))?;
    let server_config: ServerConfig = ServerConfig::with_crypto(Arc::new(quic_crypto));

    let endpoint: Endpoint = Endpoint::server(server_config, bind_addr)
        .map_err(|e| ReductionError::Tunnel(format!("tunnel bind: {e}")))?;

    info!(%bind_addr, "tunnel listener started");

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                let remote_addr: SocketAddr = incoming.remote_address();
                let reg: Arc<TunnelRegistry> = Arc::clone(&registry);
                let cfg: TunnelConfig = config.clone();
                let cancel: CancellationToken = shutdown.clone();
                let m: ProxyMetrics = ProxyMetrics::new();
                let _ = &metrics; // keep the real metrics in scope for future use

                tokio::spawn(async move {
                    if let Err(e) = handle_tunnel_connection(incoming, remote_addr, reg, cfg, cancel, m).await {
                        warn!(%remote_addr, error = %e, "tunnel connection failed");
                    }
                });
            }
            _ = shutdown.cancelled() => {
                info!("tunnel listener shutting down");
                endpoint.close(0u32.into(), b"shutdown");
                break;
            }
        }
    }

    return Ok(());
}

async fn handle_tunnel_connection(
    incoming: quinn::Incoming,
    remote_addr: SocketAddr,
    registry: Arc<TunnelRegistry>,
    config: TunnelConfig,
    shutdown: CancellationToken,
    metrics: ProxyMetrics,
) -> Result<()> {
    let connection: quinn::Connection = incoming.await
        .map_err(|e| ReductionError::Tunnel(format!("handshake failed: {e}")))?;

    debug!(%remote_addr, "tunnel QUIC connection established");

    let (send, recv) = connection.accept_bi().await
        .map_err(|e| ReductionError::Tunnel(format!("accept control stream: {e}")))?;

    let mut control_stream: QuicStream = QuicStream::new(send, recv);

    let register_timeout: Duration = Duration::from_secs(config.registration_timeout_secs);
    let frame: TunnelFrame = timeout(register_timeout, protocol::read_frame(&mut control_stream))
        .await
        .map_err(|_| ReductionError::Tunnel("registration timed out".to_owned()))?
        .map_err(|e| ReductionError::Tunnel(format!("read register frame: {e}")))?;

    let (backend_id, pool, capabilities) = match frame {
        TunnelFrame::Register { backend_id, pool, capabilities } => {
            (backend_id, pool, capabilities)
        }
        other => {
            return Err(ReductionError::Tunnel(format!("expected Register frame, got {:?}", other)));
        }
    };

    if !config.allowed_backend_ids.is_empty()
        && !config.allowed_backend_ids.contains(&backend_id)
    {
        metrics.tunnel_registration_rejected.add(1, &[]);
        warn!(%backend_id, %remote_addr, "tunnel registration rejected: not in allowlist");
        protocol::write_frame(&mut control_stream, &TunnelFrame::Shutdown {
            reason: ArrayString::from("not in allowlist").unwrap_or_default(),
        }).await.ok();
        return Err(ReductionError::Tunnel("backend not in allowlist".to_owned()));
    }

    let session_id: SessionId = SessionId::generate(&remote_addr, backend_id.as_str());

    protocol::write_frame(&mut control_stream, &TunnelFrame::RegisterAck {
        session_id,
    }).await?;

    info!(%backend_id, session_id = %session_id, %remote_addr, ?capabilities, "tunnel backend registered");

    let (control_tx, mut control_rx) = mpsc::channel::<TunnelFrame>(config.control_channel_capacity.get() as usize);

    let session: TunnelSession = TunnelSession {
        session_id,
        backend_id,
        pool,
        remote_addr,
        connected_at: Instant::now(),
        last_heartbeat: Instant::now(),
        control_tx,
        connection: connection.clone(),
    };

    registry.register(session)?;
    metrics.tunnel_sessions_active.add(1, &[]);

    let heartbeat_timeout: Duration = Duration::from_secs(config.heartbeat_timeout_secs);

    loop {
        tokio::select! {
            result = timeout(heartbeat_timeout, protocol::read_frame(&mut control_stream)) => {
                match result {
                    Ok(Ok(TunnelFrame::Heartbeat { timestamp_ms })) => {
                        debug!(%session_id, timestamp_ms, "heartbeat received");
                        protocol::write_frame(&mut control_stream, &TunnelFrame::HeartbeatAck).await.ok();
                    }
                    Ok(Ok(TunnelFrame::Shutdown { reason })) => {
                        info!(%session_id, %reason, "tunnel backend requested shutdown");
                        break;
                    }
                    Ok(Ok(other)) => {
                        warn!(%session_id, ?other, "unexpected frame on control channel");
                    }
                    Ok(Err(e)) => {
                        warn!(%session_id, error = %e, "control channel read error");
                        break;
                    }
                    Err(_) => {
                        metrics.tunnel_heartbeat_timeouts.add(1, &[]);
                        warn!(%session_id, timeout_secs = config.heartbeat_timeout_secs, "heartbeat timeout");
                        break;
                    }
                }
            }
            outbound = control_rx.recv() => {
                match outbound {
                    Some(frame) => {
                        if let Err(e) = protocol::write_frame(&mut control_stream, &frame).await {
                            warn!(%session_id, error = %e, "failed to write outbound frame");
                            break;
                        }
                    }
                    None => {
                        break;
                    }
                }
            }
            _ = shutdown.cancelled() => {
                protocol::write_frame(&mut control_stream, &TunnelFrame::Shutdown {
                    reason: ArrayString::from("proxy shutting down").unwrap_or_default(),
                }).await.ok();
                break;
            }
        }
    }

    registry.deregister(&backend_id, &session_id);
    metrics.tunnel_sessions_active.add(-1, &[]);
    info!(%backend_id, %session_id, "tunnel session ended");

    return Ok(());
}
