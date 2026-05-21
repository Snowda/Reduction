use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use dashmap::DashMap;
use quinn::Connection;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::error::{ReductionError, Result};
use crate::transport::quic::QuicStream;
use crate::tunnel::protocol::TunnelFrame;

static NEXT_STREAM_ID: AtomicU64 = AtomicU64::new(1);

pub struct TunnelSession {
    pub session_id: String,
    pub backend_id: String,
    pub pool: String,
    pub remote_addr: SocketAddr,
    pub connected_at: Instant,
    pub last_heartbeat: Instant,
    pub control_tx: mpsc::Sender<TunnelFrame>,
    pub connection: Connection,
}

pub struct TunnelRegistry {
    sessions: DashMap<String, Vec<TunnelSession>>,
    rr_counter: AtomicUsize,
    max_sessions_per_backend: usize,
}

impl TunnelRegistry {
    pub fn new(max_sessions_per_backend: usize) -> Self {
        return Self {
            sessions: DashMap::new(),
            rr_counter: AtomicUsize::new(0),
            max_sessions_per_backend,
        };
    }

    pub fn register(&self, session: TunnelSession) -> Result<()> {
        let backend_id: String = session.backend_id.clone();
        let session_id: String = session.session_id.clone();

        let mut entry = self.sessions.entry(backend_id.clone()).or_default();
        if entry.len() >= self.max_sessions_per_backend {
            return Err(ReductionError::Tunnel(format!(
                "max sessions ({}) reached for backend {}",
                self.max_sessions_per_backend, backend_id,
            )));
        }
        entry.push(session);
        info!(%backend_id, %session_id, count = entry.len(), "tunnel session registered");
        return Ok(());
    }

    pub fn deregister(&self, backend_id: &str, session_id: &str) -> bool {
        if let Some(mut entry) = self.sessions.get_mut(backend_id) {
            let before: usize = entry.len();
            entry.retain(|s| s.session_id != session_id);
            let removed: bool = entry.len() < before;
            if removed {
                info!(%backend_id, %session_id, remaining = entry.len(), "tunnel session deregistered");
            }
            if entry.is_empty() {
                drop(entry);
                self.sessions.remove(backend_id);
            }
            return removed;
        }
        return false;
    }

    pub fn deregister_all(&self, backend_id: &str) -> usize {
        if let Some((_, sessions)) = self.sessions.remove(backend_id) {
            let count: usize = sessions.len();
            info!(%backend_id, count, "all tunnel sessions deregistered");
            return count;
        }
        return 0;
    }

    pub fn is_tunnel_backend(&self, backend_id: &str) -> bool {
        return self
            .sessions
            .get(backend_id)
            .map(|e| !e.is_empty())
            .unwrap_or(false);
    }

    pub fn session_count(&self, backend_id: &str) -> usize {
        return self
            .sessions
            .get(backend_id)
            .map(|e| e.len())
            .unwrap_or(0);
    }

    pub fn total_sessions(&self) -> usize {
        return self.sessions.iter().map(|e| e.value().len()).sum();
    }

    pub async fn acquire_stream(&self, backend_id: &str) -> Result<QuicStream> {
        let (connection, session_id) = {
            let entry = self.sessions.get(backend_id)
                .ok_or_else(|| ReductionError::Tunnel(format!("no tunnel sessions for backend {backend_id}")))?;

            let sessions: &Vec<TunnelSession> = entry.value();
            if sessions.is_empty() {
                return Err(ReductionError::Tunnel(format!("no tunnel sessions for backend {backend_id}")));
            }

            let idx: usize = self.rr_counter.fetch_add(1, Ordering::Relaxed) % sessions.len();
            let session: &TunnelSession = &sessions[idx];

            if session.connection.close_reason().is_some() {
                let sid: String = session.session_id.clone();
                warn!(backend_id, session_id = %sid, "tunnel connection closed, removing");
                drop(entry);
                self.deregister(backend_id, &sid);
                return Err(ReductionError::Tunnel("tunnel connection closed".to_string()));
            }

            (session.connection.clone(), session.session_id.clone())
        };

        let stream_id: u64 = NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed);
        debug!(backend_id, %session_id, stream_id, "opening tunnel stream");

        let (send, recv) = connection.open_bi().await
            .map_err(|e| ReductionError::Tunnel(format!("open stream: {e}")))?;

        return Ok(QuicStream::new(send, recv));
    }

    pub async fn shutdown_all(&self) {
        for entry in self.sessions.iter() {
            for session in entry.value() {
                let _ = session.control_tx.try_send(TunnelFrame::Shutdown {
                    reason: "proxy shutting down".to_string(),
                });
                session.connection.close(0u32.into(), b"shutdown");
            }
        }
        self.sessions.clear();
        info!("all tunnel sessions shut down");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_registry(max: usize) -> TunnelRegistry {
        return TunnelRegistry::new(max);
    }

    #[test]
    fn test_registry_starts_empty() {
        let reg: TunnelRegistry = make_registry(8);
        assert_eq!(reg.total_sessions(), 0);
        assert!(!reg.is_tunnel_backend("api"));
        assert_eq!(reg.session_count("api"), 0);
    }

    #[test]
    fn test_deregister_nonexistent() {
        let reg: TunnelRegistry = make_registry(8);
        assert!(!reg.deregister("api", "sess-1"));
    }

    #[test]
    fn test_deregister_all_empty() {
        let reg: TunnelRegistry = make_registry(8);
        assert_eq!(reg.deregister_all("api"), 0);
    }
}
