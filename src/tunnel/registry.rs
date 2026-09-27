use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use arrayvec::ArrayString;
use dashmap::DashMap;
use quinn::Connection;
use tokio::sync::{Notify, mpsc};
use tokio::time::{Duration, Instant as TokioInstant, sleep_until, timeout};
use tracing::{debug, info, warn};

use crate::error::{ReductionError, Result};
use crate::tls::PeerIdentity;
use crate::transport::quic::QuicStream;
use crate::tunnel::protocol::{SessionId, TunnelFrame, write_frame};
use crate::tunnel::revocation::RevocationSet;

static NEXT_STREAM_ID: AtomicU64 = AtomicU64::new(1);

// Reason sent on the Shutdown frame when a session is terminated by a revocation sweep, so the client
// can distinguish a revocation from an ordinary shutdown.
const REVOKED_REASON: &str = "revoked";

pub struct TunnelSession {
	pub session_id: SessionId,
	pub backend_id: ArrayString<256>,
	pub pool: ArrayString<32>,
	pub remote_addr: SocketAddr,
	pub connected_at: Instant,
	pub last_heartbeat: Instant,
	pub control_tx: mpsc::Sender<TunnelFrame>,
	pub connection: Connection,
	// Handshake-proven identity captured at registration. Retained so a later revocation update can
	// match a live session by its key SPKI (not just its backend_id) and terminate it.
	pub identity: PeerIdentity,
	// F1/F4: a control-plane peer (registered with CONTROL_CAPABILITY). Its connection receives pushed
	// `Wake` frames; it is not a routable backend.
	pub is_control_peer: bool,
}

// Per-control-peer bound on a wake push, so a wedged connection cannot stall a parked request.
const WAKE_DISPATCH_TIMEOUT: Duration = Duration::from_secs(2);

pub struct TunnelRegistry {
	sessions: DashMap<ArrayString<256>, Vec<TunnelSession>>,
	rr_counter: AtomicUsize,
	max_sessions_per_backend: u32,
	// F1: per-backend wakeup for parked requests. `register` notifies waiters so a request parked on a
	// cold (`wakeable`) backend releases the instant that backend's first session registers.
	wake_notify: DashMap<ArrayString<256>, Arc<Notify>>,
	// F1/F4: connections of registered control-plane peers, keyed by session. `dispatch_wake` pushes a
	// `Wake` frame to each on a fresh uni-stream when a request parks.
	control_peers: DashMap<SessionId, Connection>,
	// F1: backends a control peer has refused to wake (e.g. over budget). `await_refusal` releases a
	// parked request at once so it 503s immediately instead of waiting out the deadline.
	refused: DashMap<ArrayString<256>, ()>,
}

impl TunnelRegistry {
	#[must_use]
	pub fn new(max_sessions_per_backend: u32) -> Self {
		return Self {
			sessions: DashMap::new(),
			rr_counter: AtomicUsize::new(0),
			max_sessions_per_backend,
			wake_notify: DashMap::new(),
			control_peers: DashMap::new(),
			refused: DashMap::new(),
		};
	}

	/// Record a control peer's refusal to wake `backend_id`, and release any parked waiter at once.
	pub fn note_refusal(&self, backend_id: &str) {
		if let Ok(id) = ArrayString::<256>::from(backend_id) {
			self.refused.insert(id, ());
			self.notify_session_waiters(backend_id);
		}
	}

	// Take (clear) a pending refusal for `backend_id`, returning whether one was set.
	fn take_refusal(&self, backend_id: &str) -> bool {
		return self.refused.remove(backend_id).is_some();
	}

	/// Resolve only once `backend_id` is refused (F1). Used by the park to race refusal against
	/// reachability so a budget-refused wake 503s immediately rather than at the deadline.
	pub async fn await_refusal(&self, backend_id: &str) {
		let Some(notify) = self.wake_handle(backend_id) else {
			return;
		};
		loop {
			let armed = notify.notified();
			if self.take_refusal(backend_id) {
				return;
			}
			armed.await;
		}
	}

	/// Push a `Wake` for `backend_id` to every registered control-plane peer, each on its own fresh
	/// uni-stream (write-only, so it never races the peer's control-stream reads). Best-effort: a peer
	/// that cannot be reached is skipped — the parked request still 503s at its deadline (finding F1).
	pub async fn dispatch_wake(&self, backend_id: &str, timeout_ms: u64) {
		let Ok(id) = ArrayString::<256>::from(backend_id) else {
			return;
		};
		let frame: TunnelFrame = TunnelFrame::Wake { backend_id: id, timeout_ms };
		let peers: Vec<Connection> = self.control_peers.iter().map(|e| e.value().clone()).collect();
		for conn in peers {
			// Bound each push so a wedged control-peer connection cannot stall the parked request.
			match timeout(WAKE_DISPATCH_TIMEOUT, conn.open_uni()).await {
				Ok(Ok(mut send)) => {
					if timeout(WAKE_DISPATCH_TIMEOUT, write_frame(&mut send, &frame)).await.map(|r| r.is_ok()).unwrap_or(false) {
						let _ = send.finish();
					}
				}
				Ok(Err(e)) => debug!(backend_id, error = %e, "could not open wake stream to a control peer"),
				Err(_) => debug!(backend_id, "opening a wake stream to a control peer timed out"),
			}
		}
	}

	// The wakeup handle for `backend_id`, created on first use. Cloned out so the caller never holds a
	// DashMap guard across an `.await` (which would risk a shard deadlock).
	fn wake_handle(&self, backend_id: &str) -> Option<Arc<Notify>> {
		let key: ArrayString<256> = ArrayString::from(backend_id).ok()?;
		return Some(Arc::clone(&self.wake_notify.entry(key).or_insert_with(|| Arc::new(Notify::new()))));
	}

	/// Park until `backend_id` has a live session, or `deadline` passes. Returns true if a session is
	/// present (F1's park-and-release), false on timeout. Lost-wakeup-safe: the wakeup is armed before
	/// each presence check, so a `register` racing the check still releases the waiter.
	pub async fn wait_for_session(&self, backend_id: &str, deadline: TokioInstant) -> bool {
		let Some(notify) = self.wake_handle(backend_id) else {
			return self.is_tunnel_backend(backend_id);
		};
		loop {
			let armed = notify.notified();
			if self.is_tunnel_backend(backend_id) {
				return true;
			}
			tokio::select! {
				() = armed => {}
				() = sleep_until(deadline) => return false,
			}
		}
	}

	// Wake any requests parked on `backend_id` (called after a session is committed).
	fn notify_session_waiters(&self, backend_id: &str) {
		if let Some(notify) = self.wake_notify.get(backend_id) {
			notify.notify_waiters();
		}
	}

	pub fn register(&self, session: TunnelSession) -> Result<()> {
		let backend_id: ArrayString<256> = session.backend_id;
		let session_id: SessionId = session.session_id;
		let is_control_peer: bool = session.is_control_peer;
		let control_conn: Option<Connection> = is_control_peer.then(|| session.connection.clone());

		{
			let mut entry = self.sessions.entry(backend_id).or_default();
			if entry.len() >= usize::try_from(self.max_sessions_per_backend).unwrap_or(usize::MAX) {
				return Err(ReductionError::Tunnel(format!(
					"max sessions ({}) reached for backend {}",
					self.max_sessions_per_backend, backend_id,
				)));
			}
			entry.push(session);
			info!(%backend_id, %session_id, count = entry.len(), "tunnel session registered");
		}
		if let Some(conn) = control_conn {
			self.control_peers.insert(session_id, conn);
		}
		// F1: release any request parked waiting for this backend's first session. Done after the
		// sessions-entry guard is dropped so no DashMap guard is held across the wake.
		self.notify_session_waiters(&backend_id);
		return Ok(());
	}

	pub fn deregister(&self, backend_id: &str, session_id: &SessionId) -> bool {
		self.control_peers.remove(session_id);
		if let Some(mut entry) = self.sessions.get_mut(backend_id) {
			let before: usize = entry.len();
			entry.retain(|s| s.session_id != *session_id);
			let removed: bool = entry.len() < before;
			if removed {
				info!(%backend_id, session_id = %session_id, remaining = entry.len(), "tunnel session deregistered");
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

	// Terminate every live session whose identity the revocation set now denies. Called on each
	// revocation-set update: registration-time denial alone leaves a standing clone tunnel alive until
	// it happens to reconnect, so the set change must actively sweep. Queues a Shutdown frame carrying
	// the reason, then drops the session — dropping its control_tx ends the session's control loop,
	// which flushes the queued Shutdown to the client and then tears down the QUIC connection (its last
	// remaining handle). Closing the connection here instead would race ahead of that flush and the
	// client would see a bare CONNECTION_CLOSE rather than the reason. Returns the count revoked so the
	// caller can record the metric.
	pub fn revoke_matching(&self, revocation: &RevocationSet) -> usize {
		let mut revoked: usize = 0;
		for mut entry in self.sessions.iter_mut() {
			entry.value_mut().retain(|session| {
				if !revocation.is_revoked(&session.identity) {
					return true;
				}
				let _ = session.control_tx.try_send(TunnelFrame::Shutdown {
					reason: ArrayString::from(REVOKED_REASON).unwrap_or_default(),
				});
				warn!(
					backend_id = session.backend_id.as_str(),
					session_id = %session.session_id,
					"tunnel session revoked and terminated",
				);
				revoked += 1;
				return false;
			});
		}
		// Drop now-empty backend buckets so is_tunnel_backend / session_count report accurately.
		self.sessions.retain(|_, sessions| !sessions.is_empty());
		return revoked;
	}

	// Stamp the live session's last_heartbeat so the field tracks actual liveness rather than the
	// registration moment. Returns false when the session is already gone (swept or deregistered).
	pub fn record_heartbeat(&self, backend_id: &str, session_id: &SessionId) -> bool {
		if let Some(mut entry) = self.sessions.get_mut(backend_id)
			&& let Some(session) = entry.iter_mut().find(|s| s.session_id == *session_id)
		{
			session.last_heartbeat = Instant::now();
			return true;
		}
		return false;
	}

	// Last recorded heartbeat for a session; the registration moment until the first heartbeat lands.
	pub fn last_heartbeat(&self, backend_id: &str, session_id: &SessionId) -> Option<Instant> {
		return self.sessions.get(backend_id).and_then(|entry| {
			entry
				.iter()
				.find(|s| s.session_id == *session_id)
				.map(|s| s.last_heartbeat)
		});
	}

	pub fn is_tunnel_backend(&self, backend_id: &str) -> bool {
		return self.sessions.get(backend_id).map(|e| !e.is_empty()).unwrap_or(false);
	}

	pub fn session_count(&self, backend_id: &str) -> usize {
		return self.sessions.get(backend_id).map(|e| e.len()).unwrap_or(0);
	}

	pub fn total_sessions(&self) -> usize {
		return self.sessions.iter().map(|e| e.value().len()).sum();
	}

	pub async fn acquire_stream(&self, backend_id: &str) -> Result<QuicStream> {
		let (connection, session_id) = {
			let entry = self
				.sessions
				.get(backend_id)
				.ok_or_else(|| ReductionError::NoBackendSession(backend_id.to_owned()))?;

			let sessions: &Vec<TunnelSession> = entry.value();
			if sessions.is_empty() {
				return Err(ReductionError::NoBackendSession(backend_id.to_owned()));
			}

			let idx: usize = self.rr_counter.fetch_add(1, Ordering::Relaxed) % sessions.len();
			let session: &TunnelSession = &sessions[idx];

			if session.connection.close_reason().is_some() {
				let sid: SessionId = session.session_id;
				warn!(backend_id, session_id = %sid, "tunnel connection closed, removing");
				drop(entry);
				self.deregister(backend_id, &sid);
				return Err(ReductionError::Tunnel("tunnel connection closed".to_owned()));
			}

			(session.connection.clone(), session.session_id)
		};

		let stream_id: u64 = NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed);
		debug!(backend_id, session_id = %session_id, stream_id, "opening tunnel stream");

		let (send, recv) = connection
			.open_bi()
			.await
			.map_err(|e| ReductionError::Tunnel(format!("open stream: {e}")))?;

		return Ok(QuicStream::new(send, recv));
	}

	pub async fn shutdown_all(&self) {
		for entry in self.sessions.iter() {
			for session in entry.value() {
				let _ = session.control_tx.try_send(TunnelFrame::Shutdown {
					reason: ArrayString::from("proxy shutting down").unwrap_or_default(),
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
	use std::sync::Arc;
	use std::time::Duration;

	use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
	use quinn::{ClientConfig, Endpoint, ServerConfig};
	use aws_lc_rs::digest::{SHA256, digest};

	use super::*;
	use crate::test_support::{generate_ca, generate_signed_cert, write_pem};
	use crate::tls::certs::{build_client_config, build_server_config};
	use crate::tls::identity::SPKI_SHA256_LEN;
	use crate::tunnel::protocol::SESSION_ID_LEN;

	fn make_registry(max: u32) -> TunnelRegistry {
		return TunnelRegistry::new(max);
	}

	// Distinct, readable SessionId per test session — built directly (not via the random generate())
	// so sessions stay individually addressable in asserts.
	fn sid(n: u8) -> SessionId {
		let mut bytes: [u8; SESSION_ID_LEN] = [b'0'; SESSION_ID_LEN];
		bytes[0..5].copy_from_slice(b"sess-");
		bytes[SESSION_ID_LEN - 1] = b'a' + n;
		return SessionId(bytes);
	}

	fn identity(cn: &str, seed: &[u8]) -> PeerIdentity {
		let spki: [u8; SPKI_SHA256_LEN] = digest(&SHA256, seed).as_ref().try_into().unwrap();
		return PeerIdentity {
			common_name: ArrayString::from(cn).unwrap(),
			spki_sha256: spki,
		};
	}

	// A live loopback QUIC connection. Holds both endpoints and the client side so the server-side
	// Connection the registry stores stays usable (open_bi, close_reason) for the duration of a test.
	struct ConnPair {
		server_conn: Connection,
		_client_conn: Connection,
		_client_ep: Endpoint,
		_server_ep: Endpoint,
	}

	async fn connected_pair() -> ConnPair {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let server_leaf = generate_signed_cert(
			&ca,
			"reduction-server",
			vec![rcgen::SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1]))],
		);
		let client_leaf = generate_signed_cert(&ca, "device-1", vec![]);

		let ca_file = write_pem(&ca.cert.pem());
		let server_cert_file = write_pem(&server_leaf.cert.pem());
		let server_key_file = write_pem(&server_leaf.signing_key.serialize_pem());
		let client_cert_file = write_pem(&client_leaf.cert.pem());
		let client_key_file = write_pem(&client_leaf.signing_key.serialize_pem());

		let (server_tls, _r1) =
			build_server_config(server_cert_file.path(), server_key_file.path(), ca_file.path()).unwrap();
		let (client_tls, _r2, _v2) =
			build_client_config(client_cert_file.path(), client_key_file.path(), ca_file.path()).unwrap();

		let quic_crypto = QuicServerConfig::try_from(Arc::new(server_tls)).unwrap();
		let server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
		let server_ep = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
		let addr: SocketAddr = server_ep.local_addr().unwrap();

		let accept_ep = server_ep.clone();
		let accept = tokio::spawn(async move {
			let incoming = accept_ep.accept().await.unwrap();
			return incoming.await.unwrap();
		});

		let quic_client_crypto = QuicClientConfig::try_from(Arc::new(client_tls)).unwrap();
		let mut client_ep = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
		client_ep.set_default_client_config(ClientConfig::new(Arc::new(quic_client_crypto)));
		let client_conn = client_ep.connect(addr, "127.0.0.1").unwrap().await.unwrap();

		let server_conn = accept.await.unwrap();
		return ConnPair {
			server_conn,
			_client_conn: client_conn,
			_client_ep: client_ep,
			_server_ep: server_ep,
		};
	}

	// Build a session bound to `conn`. Returns the control-channel receiver so the caller can hold it
	// (dropping it would let a queued Shutdown fail to send) and observe revocation Shutdown frames.
	fn make_session(
		conn: &Connection,
		backend_id: &str,
		session_id: SessionId,
		identity: PeerIdentity,
	) -> (TunnelSession, mpsc::Receiver<TunnelFrame>) {
		let (tx, rx) = mpsc::channel::<TunnelFrame>(4);
		let session = TunnelSession {
			session_id,
			backend_id: ArrayString::from(backend_id).unwrap(),
			pool: ArrayString::from("default").unwrap(),
			remote_addr: conn.remote_address(),
			connected_at: Instant::now(),
			last_heartbeat: Instant::now(),
			control_tx: tx,
			connection: conn.clone(),
			identity,
			is_control_peer: false,
		};
		return (session, rx);
	}

	// A control-peer session (receives pushed Wake frames).
	fn make_control_session(
		conn: &Connection,
		backend_id: &str,
		session_id: SessionId,
		identity: PeerIdentity,
	) -> (TunnelSession, mpsc::Receiver<TunnelFrame>) {
		let (session, rx) = make_session(conn, backend_id, session_id, identity);
		return (TunnelSession { is_control_peer: true, ..session }, rx);
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
		let fake_id: SessionId = SessionId::generate().unwrap();
		assert!(!reg.deregister("api", &fake_id));
	}

	#[test]
	fn test_deregister_all_empty() {
		let reg: TunnelRegistry = make_registry(8);
		assert_eq!(reg.deregister_all("api"), 0);
	}

	#[tokio::test]
	async fn test_register_tracks_counts_across_backends() {
		let pair = connected_pair().await;
		let reg = make_registry(8);

		let (s1, _r1) = make_session(&pair.server_conn, "api", sid(0), identity("api", b"k0"));
		let (s2, _r2) = make_session(&pair.server_conn, "api", sid(1), identity("api", b"k1"));
		let (s3, _r3) = make_session(&pair.server_conn, "db", sid(2), identity("db", b"k2"));
		reg.register(s1).unwrap();
		reg.register(s2).unwrap();
		reg.register(s3).unwrap();

		assert_eq!(reg.session_count("api"), 2);
		assert_eq!(reg.session_count("db"), 1);
		assert_eq!(reg.total_sessions(), 3);
		assert!(reg.is_tunnel_backend("api"));
		assert!(reg.is_tunnel_backend("db"));
	}

	// last_heartbeat must be LIVE data: record_heartbeat advances it past the registration stamp,
	// and both accessors report a missing session honestly.
	#[tokio::test]
	async fn test_record_heartbeat_advances_last_heartbeat() {
		let pair = connected_pair().await;
		let reg: TunnelRegistry = make_registry(8);
		let session_id: SessionId = sid(1);
		let (session, _rx) = make_session(&pair.server_conn, "api", session_id, identity("api", b"hb"));
		reg.register(session).unwrap();

		let registered_at: Instant = reg.last_heartbeat("api", &session_id).expect("session present");
		tokio::time::sleep(Duration::from_millis(20)).await;
		assert!(
			reg.record_heartbeat("api", &session_id),
			"a live session must accept a heartbeat stamp"
		);
		let stamped: Instant = reg.last_heartbeat("api", &session_id).expect("session still present");
		assert!(stamped > registered_at, "record_heartbeat must advance last_heartbeat");

		let ghost: SessionId = sid(2);
		assert!(
			!reg.record_heartbeat("api", &ghost),
			"an unknown session must not be stamped"
		);
		assert!(reg.last_heartbeat("ghost", &ghost).is_none());
	}

	#[tokio::test]
	async fn test_register_rejects_when_backend_full() {
		let pair = connected_pair().await;
		let reg = make_registry(1);

		let (s1, _r1) = make_session(&pair.server_conn, "api", sid(0), identity("api", b"k0"));
		let (s2, _r2) = make_session(&pair.server_conn, "api", sid(1), identity("api", b"k1"));
		reg.register(s1).unwrap();

		let err = reg.register(s2).unwrap_err();
		assert!(matches!(err, ReductionError::Tunnel(_)));
		assert!(format!("{err}").contains("max sessions"));
		assert_eq!(reg.session_count("api"), 1, "the rejected session must not be stored");
	}

	#[tokio::test]
	async fn test_deregister_one_of_many_keeps_bucket() {
		let pair = connected_pair().await;
		let reg = make_registry(8);
		let (s1, _r1) = make_session(&pair.server_conn, "api", sid(0), identity("api", b"k0"));
		let (s2, _r2) = make_session(&pair.server_conn, "api", sid(1), identity("api", b"k1"));
		reg.register(s1).unwrap();
		reg.register(s2).unwrap();

		assert!(
			reg.deregister("api", &sid(0)),
			"removing a present session returns true"
		);
		assert_eq!(reg.session_count("api"), 1);
		assert!(
			reg.is_tunnel_backend("api"),
			"bucket with a remaining session stays live"
		);
	}

	#[tokio::test]
	async fn test_deregister_last_removes_bucket() {
		let pair = connected_pair().await;
		let reg = make_registry(8);
		let (s1, _r1) = make_session(&pair.server_conn, "api", sid(0), identity("api", b"k0"));
		reg.register(s1).unwrap();

		assert!(reg.deregister("api", &sid(0)));
		assert_eq!(reg.session_count("api"), 0);
		assert!(!reg.is_tunnel_backend("api"), "emptied bucket is dropped");
	}

	#[tokio::test]
	async fn test_deregister_unknown_id_in_live_bucket_returns_false() {
		let pair = connected_pair().await;
		let reg = make_registry(8);
		let (s1, _r1) = make_session(&pair.server_conn, "api", sid(0), identity("api", b"k0"));
		reg.register(s1).unwrap();

		// A session id absent from an existing bucket is a no-op, and the present session survives.
		assert!(!reg.deregister("api", &sid(9)));
		assert_eq!(reg.session_count("api"), 1);
	}

	#[tokio::test]
	async fn test_deregister_all_returns_count_and_clears() {
		let pair = connected_pair().await;
		let reg = make_registry(8);
		// Keep the control-channel receivers alive for the session lifetime, mirroring a real control
		// loop; deregister_all itself never touches them.
		let mut receivers: Vec<mpsc::Receiver<TunnelFrame>> = Vec::new();
		for n in 0..3u8 {
			let (s, r) = make_session(&pair.server_conn, "api", sid(n), identity("api", &[n]));
			reg.register(s).unwrap();
			receivers.push(r);
		}
		assert_eq!(reg.deregister_all("api"), 3);
		assert!(!reg.is_tunnel_backend("api"));
		assert_eq!(reg.total_sessions(), 0);
	}

	// acquire_stream returns QuicStream, which is not Debug, so unwrap_err() won't compile — match out
	// the error instead.
	fn expect_acquire_err(result: Result<QuicStream>) -> ReductionError {
		return match result {
			Ok(_) => panic!("expected acquire_stream to error"),
			Err(e) => e,
		};
	}

	#[tokio::test]
	async fn test_acquire_stream_no_backend_errors() {
		let reg = make_registry(8);
		let err = expect_acquire_err(reg.acquire_stream("absent").await);
		assert!(matches!(err, ReductionError::NoBackendSession(_)), "a no-session miss is distinct from a Tunnel failure (F2)");
		assert!(format!("{err}").contains("no tunnel sessions"));
	}

	#[tokio::test]
	async fn test_acquire_stream_opens_stream_on_live_session() {
		let pair = connected_pair().await;
		let reg = make_registry(8);
		let (s1, _r1) = make_session(&pair.server_conn, "api", sid(0), identity("api", b"k0"));
		reg.register(s1).unwrap();

		// A live connection yields a real bidirectional stream.
		let stream = reg.acquire_stream("api").await;
		assert!(
			stream.is_ok(),
			"acquire_stream over a live connection should open a stream"
		);
	}

	#[tokio::test]
	async fn test_acquire_stream_evicts_closed_connection() {
		let pair = connected_pair().await;
		let reg = make_registry(8);
		let (s1, _r1) = make_session(&pair.server_conn, "api", sid(0), identity("api", b"k0"));
		reg.register(s1).unwrap();

		// Close the underlying connection; acquire must detect it, evict the session, and error.
		pair.server_conn.close(0u32.into(), b"gone");
		let err = expect_acquire_err(reg.acquire_stream("api").await);
		assert!(format!("{err}").contains("tunnel connection closed"));
		assert_eq!(reg.session_count("api"), 0, "a closed session must be deregistered");
	}

	#[tokio::test]
	async fn test_shutdown_all_clears_every_session() {
		let pair = connected_pair().await;
		let reg = make_registry(8);
		let (s1, _r1) = make_session(&pair.server_conn, "api", sid(0), identity("api", b"k0"));
		let (s2, _r2) = make_session(&pair.server_conn, "db", sid(1), identity("db", b"k1"));
		reg.register(s1).unwrap();
		reg.register(s2).unwrap();

		reg.shutdown_all().await;
		assert_eq!(reg.total_sessions(), 0);
		assert!(!reg.is_tunnel_backend("api"));
		assert!(!reg.is_tunnel_backend("db"));
	}

	#[tokio::test]
	async fn test_revoke_matching_removes_only_matching_session() {
		let pair = connected_pair().await;
		let reg = make_registry(8);
		// Two sessions under distinct names; revoke one by backend_id.
		let (keep, _rk) = make_session(&pair.server_conn, "keep", sid(0), identity("keep", b"k0"));
		let (drop_it, mut rx_drop) = make_session(&pair.server_conn, "gone", sid(1), identity("gone", b"k1"));
		reg.register(keep).unwrap();
		reg.register(drop_it).unwrap();

		let set = RevocationSet::parse("[[revoked]]\nbackend_id = \"gone\"\nreason = \"x\"\n").unwrap();
		assert_eq!(reg.revoke_matching(&set), 1, "exactly the matching session is revoked");

		assert_eq!(reg.session_count("gone"), 0, "revoked bucket is dropped");
		assert_eq!(reg.session_count("keep"), 1, "unmatched session survives");
		// The revoked session was sent a Shutdown carrying the reason before being dropped.
		match rx_drop.try_recv() {
			Ok(TunnelFrame::Shutdown { reason }) => assert_eq!(reason.as_str(), "revoked"),
			other => panic!("expected queued Shutdown(revoked), got {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_revoke_matching_none_matching_is_noop() {
		let pair = connected_pair().await;
		let reg = make_registry(8);
		let (s1, _r1) = make_session(&pair.server_conn, "api", sid(0), identity("api", b"k0"));
		reg.register(s1).unwrap();

		let set = RevocationSet::parse("[[revoked]]\nbackend_id = \"other\"\nreason = \"x\"\n").unwrap();
		assert_eq!(reg.revoke_matching(&set), 0);
		assert_eq!(reg.session_count("api"), 1, "a non-matching set revokes nothing");
	}

	// F1 park primitive: a request parked on a cold backend releases the moment a session registers.
	#[tokio::test]
	async fn wait_for_session_releases_when_a_session_registers() {
		let pair = connected_pair().await;
		let reg: Arc<TunnelRegistry> = Arc::new(make_registry(8));
		let deadline: TokioInstant = TokioInstant::now() + Duration::from_secs(5);
		let waiter = {
			let r: Arc<TunnelRegistry> = Arc::clone(&reg);
			tokio::spawn(async move { r.wait_for_session("api", deadline).await })
		};
		// Register after the waiter has parked; the notify must release it.
		tokio::time::sleep(Duration::from_millis(50)).await;
		let (s1, _r1) = make_session(&pair.server_conn, "api", sid(0), identity("api", b"k0"));
		reg.register(s1).unwrap();
		assert!(waiter.await.unwrap(), "a registered session must release the parked waiter");
	}

	// with != without: no session ⇒ the park times out and reports false (the caller then 503s).
	#[tokio::test]
	async fn wait_for_session_times_out_with_no_session() {
		let reg: TunnelRegistry = make_registry(8);
		let deadline: TokioInstant = TokioInstant::now() + Duration::from_millis(100);
		assert!(!reg.wait_for_session("ghost", deadline).await, "no session within the deadline ⇒ false");
	}

	#[tokio::test]
	async fn wait_for_session_returns_immediately_when_already_present() {
		let pair = connected_pair().await;
		let reg: TunnelRegistry = make_registry(8);
		let (s1, _r1) = make_session(&pair.server_conn, "api", sid(0), identity("api", b"k0"));
		reg.register(s1).unwrap();
		let deadline: TokioInstant = TokioInstant::now() + Duration::from_secs(5);
		assert!(reg.wait_for_session("api", deadline).await, "an existing session releases immediately");
	}

	// F1 wake dispatch: a parked request drives a `Wake` frame to the registered control peer, on a
	// fresh uni-stream, naming the cold backend and the park budget.
	#[tokio::test]
	async fn dispatch_wake_pushes_a_wake_to_a_control_peer() {
		let pair = connected_pair().await;
		let reg: TunnelRegistry = make_registry(8);
		let (cp, _rx) = make_control_session(&pair.server_conn, "moist-control", sid(0), identity("moist-control", b"kc"));
		reg.register(cp).unwrap();

		reg.dispatch_wake("api", 30_000).await;

		let mut recv = tokio::time::timeout(Duration::from_secs(5), pair._client_conn.accept_uni())
			.await
			.expect("a wake uni-stream should arrive")
			.expect("accept_uni ok");
		match crate::tunnel::protocol::read_frame(&mut recv).await.unwrap() {
			TunnelFrame::Wake { backend_id, timeout_ms } => {
				assert_eq!(backend_id.as_str(), "api");
				assert_eq!(timeout_ms, 30_000);
			}
			other => panic!("expected a Wake frame, got {other:?}"),
		}
	}

	// F1 abort-park: a refusal releases the waiter promptly (the sub-100ms mechanism, isolated from
	// the request path's connect latency).
	#[tokio::test]
	async fn await_refusal_returns_promptly_after_note_refusal() {
		let reg: Arc<TunnelRegistry> = Arc::new(make_registry(8));
		let waiter = {
			let r: Arc<TunnelRegistry> = Arc::clone(&reg);
			tokio::spawn(async move { r.await_refusal("api").await })
		};
		tokio::time::sleep(Duration::from_millis(20)).await;
		let refused_at: TokioInstant = TokioInstant::now();
		reg.note_refusal("api");
		waiter.await.unwrap();
		assert!(refused_at.elapsed() < Duration::from_millis(100), "refusal must release the waiter promptly");
	}

	// with != without: a non-control peer receives no wake (nothing pushed on its connection).
	#[tokio::test]
	async fn dispatch_wake_does_not_reach_a_non_control_peer() {
		let pair = connected_pair().await;
		let reg: TunnelRegistry = make_registry(8);
		let (s1, _r1) = make_session(&pair.server_conn, "api", sid(0), identity("api", b"k0"));
		reg.register(s1).unwrap();

		reg.dispatch_wake("api", 30_000).await;

		let got = tokio::time::timeout(Duration::from_millis(300), pair._client_conn.accept_uni()).await;
		assert!(got.is_err(), "a non-control peer must not receive a wake uni-stream");
	}
}
