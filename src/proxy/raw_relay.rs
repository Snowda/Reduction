use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use opentelemetry::KeyValue;
use tokio::io::AsyncReadExt;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::balancer::BackendPool;
use crate::circuit::{CircuitState, HalfOpenGuard};
use crate::config::BackendConfig;
use crate::error::ReductionError;
use crate::proxy::handler::ProxyState;
use crate::proxy::raw_authz::RawRelayAuthz;
use crate::proxy::relay::{RelayEnd, RelayStats, relay_bidirectional};
use crate::tls::PeerIdentity;
use crate::transport::quic::QuicStream;

mod admission;
mod lifetime;

use admission::check_admission;
use lifetime::{cancel_on_acl_denial, cancel_on_revocation};

const DEFAULT_RAW_RELAY_IDLE_TIMEOUT_SECS: u64 = 300;
const MAX_BACKEND_ID_LEN: usize = 256;
const ROUTING_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
// The raw path opens one task per stream and can hold a stream for its relay lifetime. Bound the
// global task count so a device cannot accumulate streams across backend pools or connections.
const MAX_CONCURRENT_RAW_RELAYS: usize = 128;

// Width of the big-endian length prefix framing the routing header (a u16 byte count).
const ROUTING_HEADER_LEN_PREFIX_BYTES: usize = 2;
// Metric attribute (on raw_relay_rejected) distinguishing why a raw stream was refused admission.
const REJECT_REASON_KEY: &str = "reason";
const REJECT_REASON_ACL: &str = "acl";
const REJECT_REASON_RATE_LIMIT: &str = "rate_limit";
const REJECT_REASON_NO_IDENTITY: &str = "no_identity";
const REJECT_REASON_REVOKED: &str = "revoked";
// Device authenticated and unrevoked, but not on the target backend's raw-relay allowlist (finding #33).
const REJECT_REASON_UNAUTHORIZED: &str = "unauthorized";
const REJECT_REASON_CAPACITY: &str = "capacity";
// Every pool member is offline or fully connection-pressured — the balancer returned no backend.
const REJECT_REASON_NO_BACKEND: &str = "no_backend";
// The selected backend's circuit breaker is open (recent failures) — do not dial it.
const REJECT_REASON_CIRCUIT_OPEN: &str = "circuit_open";

async fn read_routing_header(stream: &mut QuicStream) -> crate::error::Result<String> {
	return read_routing_header_with_timeout(stream, ROUTING_HEADER_TIMEOUT).await;
}

async fn read_routing_header_with_timeout(
	stream: &mut QuicStream,
	header_timeout: Duration,
) -> crate::error::Result<String> {
	let read_header = async {
		let mut len_buf: [u8; ROUTING_HEADER_LEN_PREFIX_BYTES] = [0u8; ROUTING_HEADER_LEN_PREFIX_BYTES];
		stream
			.read_exact(&mut len_buf)
			.await
			.map_err(|e| ReductionError::Forward(format!("read routing header length: {e}")))?;

		let len: usize = usize::from(u16::from_be_bytes(len_buf));
		if len == 0 || len > MAX_BACKEND_ID_LEN {
			return Err(ReductionError::Forward(format!("invalid backend_id length: {len}")));
		}

		let mut id_buf: Vec<u8> = vec![0u8; len];
		stream
			.read_exact(&mut id_buf)
			.await
			.map_err(|e| ReductionError::Forward(format!("read routing header: {e}")))?;

		let backend_id: String =
			String::from_utf8(id_buf).map_err(|e| ReductionError::Forward(format!("invalid backend_id UTF-8: {e}")))?;

		return Ok(backend_id);
	};

	return timeout(header_timeout, read_header)
		.await
		.map_err(|_| ReductionError::Forward("routing header timed out".to_owned()))?;
}

pub async fn run_raw_relay_handler(
	mut raw_rx: mpsc::Receiver<(QuicStream, SocketAddr)>,
	state: Arc<ProxyState>,
	raw_authz: Arc<RawRelayAuthz>,
	shutdown: CancellationToken,
) {
	let relay_permits: Arc<Semaphore> = Arc::new(Semaphore::new(MAX_CONCURRENT_RAW_RELAYS));
	loop {
		tokio::select! {
			incoming = raw_rx.recv() => {
				let Some((stream, remote_addr)) = incoming else {
					break;
				};

				let permit: OwnedSemaphorePermit = match Arc::clone(&relay_permits).try_acquire_owned() {
					Ok(permit) => permit,
					Err(_) => {
						state.metrics.raw_relay_rejected.add(1, &[KeyValue::new(REJECT_REASON_KEY, REJECT_REASON_CAPACITY)]);
						warn!(%remote_addr, "raw relay rejected: concurrent relay cap reached");
						continue;
					}
				};

				let st: Arc<ProxyState> = Arc::clone(&state);
				let authz: Arc<RawRelayAuthz> = Arc::clone(&raw_authz);
				let cancel: CancellationToken = shutdown.clone();

				tokio::spawn(async move {
					let _permit: OwnedSemaphorePermit = permit;
					if let Err(e) = handle_raw_stream(stream, remote_addr, &st, &authz, cancel).await {
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

// A linear dial pipeline: resolve pool, select a healthy member, gate on circuit + connection permit, dial, relay.
// cognitive_complexity here is the per-gate match arms plus log macros, not branching logic.
#[allow(clippy::cognitive_complexity)]
async fn handle_raw_stream(
	mut client_stream: QuicStream,
	remote_addr: SocketAddr,
	state: &Arc<ProxyState>,
	raw_authz: &RawRelayAuthz,
	shutdown: CancellationToken,
) -> crate::error::Result<()> {
	// Edge admission (ACL / rate-limit / revocation + proven mTLS identity + per-device authorization), mirroring
	// the HTTP path. None = the peer was cleanly turned away (rejection metric already emitted), a terminal Ok.
	let client_ip: IpAddr = remote_addr.ip();
	let Some((identity, backend_id)) = authorize_raw_edge(&mut client_stream, remote_addr, state, raw_authz).await?
	else {
		return Ok(());
	};

	let pool: BackendPool = {
		let reloadable = state.reloadable.borrow();
		reloadable.backend_pools.get(backend_id.as_str()).cloned()
	}
	.ok_or_else(|| ReductionError::Forward(format!("unknown backend pool for raw relay: {backend_id}")))?;

	// Balancer selection — parity with the HTTP path, which the raw path once skipped via `pool.backends.first()`.
	// Route through the weighted-rendezvous selector (health, pressure, affinity). None = all offline/pressured: turn away cleanly.
	let backend: &BackendConfig = {
		let health = state.health_rx.borrow();
		let pressure_fn =
			|b: &BackendConfig| -> f64 { state.conn_pool.connection_pressure(b.id.as_str(), b.max_connections) };
		match pool.select_with_pressure(client_ip, &health, &pressure_fn) {
			Some(b) => b,
			None => {
				state
					.metrics
					.raw_relay_rejected
					.add(1, &[KeyValue::new(REJECT_REASON_KEY, REJECT_REASON_NO_BACKEND)]);
				warn!(%remote_addr, %backend_id, "raw relay rejected: no available backend in pool");
				return Ok(());
			}
		}
	};

	// Per-backend circuit-breaker gate — parity with handler.rs. An open circuit turns the stream away cleanly;
	// a half-open probe holds its guard for the relay's lifetime so only one probe is admitted while recovering.
	let _half_open_guard: Option<HalfOpenGuard> = match state.circuit_breakers.check(backend.id.as_str()) {
		(CircuitState::Open, _) => {
			state
				.metrics
				.raw_relay_rejected
				.add(1, &[KeyValue::new(REJECT_REASON_KEY, REJECT_REASON_CIRCUIT_OPEN)]);
			warn!(%remote_addr, %backend_id, backend = backend.id.as_str(), "raw relay rejected: circuit open");
			return Ok(());
		}
		(_, guard) => guard,
	};

	// Connection admission — parity with the HTTP path, which the raw path once skipped: draw a permit from the
	// same per-backend semaphore (sized to max_connections) so raw streams can't exceed the cap. At capacity, turn
	// away cleanly (Ok, no connect). Held for the relay's lifetime — the permit releases on drop when this returns.
	let _conn_permit: OwnedSemaphorePermit = match state.conn_pool.try_acquire_conn_permit(backend) {
		Ok(permit) => permit,
		Err(_) => {
			state
				.metrics
				.backend_conn_limit_rejected
				.add(1, &[KeyValue::new("backend", String::from(backend.id.as_str()))]);
			warn!(%remote_addr, %backend_id, max = backend.max_connections, "raw relay rejected: backend connection limit reached");
			return Ok(());
		}
	};

	let connect_timeout: Duration = Duration::from_secs(state.timeouts.connect_secs.get());
	let backend_stream: QuicStream = match state
		.conn_pool
		.acquire_raw_stream(backend, &state.client_tls_config, connect_timeout)
		.await
	{
		Ok(stream) => stream,
		Err(e) => {
			// A failed dial is a backend failure the breaker must see; the half-open probe (if any) is released as failed by dropping its guard.
			state.circuit_breakers.record_failure(backend.id.as_str());
			return Err(e);
		}
	};

	state.metrics.raw_relay_active.add(1, &[]);

	// Tie the relay's lifetime to this device's revocation status: a child of the global `shutdown` token (so a
	// proxy-wide shutdown tears the pipe down) additionally cancelled once `identity` lands on the revocation set.
	// Admission checks revocation only once; without this a pipe established just before a revocation would outlive it.
	let relay_token: CancellationToken = shutdown.child_token();
	tokio::spawn(cancel_on_revocation(
		state.revocation.clone(),
		identity,
		relay_token.clone(),
	));
	// Same parity for the IP ACL: a pipe established before an [access] hot-reload that newly denies this source
	// IP would outlive the denial. Tears the pipe down the moment the ACL rejects client_ip, via the shared child token.
	tokio::spawn(cancel_on_acl_denial(
		state.reloadable.clone(),
		client_ip,
		relay_token.clone(),
	));

	let idle_timeout: Duration = Duration::from_secs(DEFAULT_RAW_RELAY_IDLE_TIMEOUT_SECS);
	let result = relay_bidirectional(client_stream, backend_stream, idle_timeout, relay_token.clone()).await;

	// The relay has ended (idle, EOF, revocation, or shutdown); cancel the token so the revocation watcher exits.
	// Idempotent, and cancels only this child — never the shared `shutdown`.
	relay_token.cancel();

	state.metrics.raw_relay_active.add(-1, &[]);

	record_relay_outcome(state, backend, &backend_id, result);

	return Ok(());
}

// Records the terminal outcome of a finished raw relay: feeds the circuit breaker (clean end = success that can
// close a half-open circuit; transport error = failure), emits byte/error metrics, and logs how the stream ended.
// `backend` is the selected pool member (drives the breaker); `backend_id` is the requested routing key (logs only).
#[allow(clippy::cognitive_complexity)]
fn record_relay_outcome(
	state: &Arc<ProxyState>,
	backend: &BackendConfig,
	backend_id: &str,
	result: crate::error::Result<RelayStats>,
) {
	match result {
		Ok(stats) => {
			state.circuit_breakers.record_success(backend.id.as_str());
			let total: u64 = stats.bytes_a_to_b.saturating_add(stats.bytes_b_to_a);
			state.metrics.raw_relay_bytes_relayed.add(total, &[]);
			match stats.end {
				RelayEnd::Completed => debug!(%backend_id, bytes = total, "raw relay completed"),
				RelayEnd::IdleTimeout => debug!(%backend_id, bytes = total,
                    idle_secs = DEFAULT_RAW_RELAY_IDLE_TIMEOUT_SECS, "raw relay closed after idle timeout"),
				RelayEnd::Cancelled => debug!(%backend_id, bytes = total, "raw relay cancelled"),
			}
		}
		Err(e) => {
			state.circuit_breakers.record_failure(backend.id.as_str());
			warn!(%backend_id, error = %e, "raw relay error");
			state.metrics.raw_relay_errors.add(1, &[]);
		}
	}
}

// Edge admission for a raw stream — parity with the HTTP path, which the raw path once skipped: an ACL-blocked,
// rate-limited, unparseable-identity, or unauthorized peer must never get a byte pipe. Returns the proven identity
// and requested backend_id; Ok(None) when cleanly turned away. A malformed routing header is a hard read error.
async fn authorize_raw_edge(
	client_stream: &mut QuicStream,
	remote_addr: SocketAddr,
	state: &Arc<ProxyState>,
	raw_authz: &RawRelayAuthz,
) -> crate::error::Result<Option<(PeerIdentity, String)>> {
	let client_ip: IpAddr = remote_addr.ip();
	let identity: Option<PeerIdentity> = client_stream.peer_identity();
	// Borrow the revocation set only for the synchronous admission decision; the watch::Ref is dropped off the awaits below.
	let admission: std::result::Result<(), &'static str> = {
		let reloadable = state.reloadable.borrow();
		let revocation = state.revocation.borrow();
		check_admission(
			&reloadable.acl,
			&state.rate_limiter,
			client_ip,
			identity.as_ref(),
			&revocation,
		)
	};
	if let Err(reason) = admission {
		state
			.metrics
			.raw_relay_rejected
			.add(1, &[KeyValue::new(REJECT_REASON_KEY, reason)]);
		warn!(%remote_addr, reason, "raw relay rejected");
		return Ok(None);
	}

	// Admission proved identity is present (None is rejected as no_identity above); bind it so the relay can be torn down if revoked mid-stream.
	let Some(identity) = identity else {
		return Ok(None);
	};

	let backend_id: String = read_routing_header(client_stream).await?;

	debug!(%remote_addr, %backend_id, "raw relay: routing to backend");

	// Per-device authorization at the proxy edge: a backend must have an explicit allowlist and admits only listed
	// device CNs / key SPKIs. The opaque byte relay can't forward identity, so "who may reach this backend" is decided here.
	if !raw_authz.is_allowed(&backend_id, &identity) {
		state
			.metrics
			.raw_relay_rejected
			.add(1, &[KeyValue::new(REJECT_REASON_KEY, REJECT_REASON_UNAUTHORIZED)]);
		warn!(%remote_addr, %backend_id, cn = identity.common_name.as_str(),
            "raw relay rejected: device not authorized for backend");
		return Ok(None);
	}

	return Ok(Some((identity, backend_id)));
}

// Fixtures shared across this module's test submodules (admission, lifetime, and the streaming tests).
#[cfg(test)]
mod testutil {
	use arrayvec::ArrayString;
	use aws_lc_rs::digest::{SHA256, digest};

	use crate::tls::PeerIdentity;
	use crate::tls::identity::SPKI_SHA256_LEN;

	// A fixed test identity (CN "device-1"), the peer every relay test presents.
	pub fn some_identity() -> PeerIdentity {
		let spki: [u8; SPKI_SHA256_LEN] = digest(&SHA256, b"raw-peer").as_ref().try_into().unwrap();
		return PeerIdentity {
			common_name: ArrayString::from("device-1").unwrap(),
			spki_sha256: spki,
		};
	}
}

#[cfg(test)]
mod tests {
	use std::collections::{HashMap, HashSet};
	use std::num::NonZeroU64;

	use arrayvec::ArrayString;
	use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
	use quinn::{ClientConfig, Endpoint, ServerConfig};
	use tokio::time::timeout;

	use super::testutil::some_identity;
	use super::*;
	use crate::acl::AccessControl;
	use crate::balancer::BackendPool;
	use crate::config::{BackendConfig, RawRelayAuthzEntry, TimeoutConfig, TransportKind};
	use crate::proxy::handler::{ProxyState, ReloadableState, TestProxyStateParams};
	use crate::proxy::router::Router;
	use crate::test_support::{generate_ca, generate_signed_cert, write_pem};
	use crate::tls::PeerIdentity;
	use crate::tls::certs::{build_client_config, build_server_config};
	use crate::tunnel::revocation::RevocationSet;

	#[test]
	fn test_routing_header_encoding() {
		let backend_id: &str = "my-backend";
		let len_bytes: [u8; 2] = u16::try_from(backend_id.len()).unwrap().to_be_bytes();
		assert_eq!(len_bytes, [0, 10]);

		let mut header: Vec<u8> = Vec::new();
		header.extend_from_slice(&len_bytes);
		header.extend_from_slice(backend_id.as_bytes());
		assert_eq!(header.len(), 12);
	}

	// ── Streaming-path harness: real QUIC bi-streams + a minimal ProxyState ──

	// Build explicit test policies for the backends a test intends to reach. Production policy is
	// fail-closed, so tests that need to exercise behavior after authorization must opt in too.
	fn authz_allowing(backend_ids: &[&str]) -> RawRelayAuthz {
		let known: HashSet<ArrayString<256>> = backend_ids.iter().map(|id| ArrayString::from(id).unwrap()).collect();
		let entries: Vec<RawRelayAuthzEntry> = backend_ids
			.iter()
			.map(|id| RawRelayAuthzEntry {
				backend_id: ArrayString::from(id).unwrap(),
				allowed_cns: vec![ArrayString::from("device-1").unwrap()],
				allowed_spkis: vec![],
			})
			.collect();
		return RawRelayAuthz::new(&entries, &known).unwrap();
	}

	// A live QUIC connection plus a real ProxyState wired to it. The client_tls_config is a genuine
	// mTLS config so acquire_raw_stream can attempt (and fail against a dead) backend.
	struct Harness {
		_server_ep: Endpoint,
		_client_ep: Endpoint,
		server_conn: quinn::Connection,
		client_conn: quinn::Connection,
		client_tls: std::sync::Arc<rustls::ClientConfig>,
	}

	async fn harness() -> Harness {
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
		let client_tls = std::sync::Arc::new(client_tls);

		let quic_crypto = QuicServerConfig::try_from(std::sync::Arc::new(server_tls)).unwrap();
		let server_ep = Endpoint::server(
			ServerConfig::with_crypto(std::sync::Arc::new(quic_crypto)),
			"127.0.0.1:0".parse().unwrap(),
		)
		.unwrap();
		let addr: SocketAddr = server_ep.local_addr().unwrap();

		let accept_ep = server_ep.clone();
		let accept = tokio::spawn(async move { accept_ep.accept().await.unwrap().await.unwrap() });

		let client_crypto = QuicClientConfig::try_from(client_tls.clone()).unwrap();
		let mut client_ep = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
		client_ep.set_default_client_config(ClientConfig::new(std::sync::Arc::new(client_crypto)));
		let client_conn = client_ep.connect(addr, "127.0.0.1").unwrap().await.unwrap();

		let server_conn = accept.await.unwrap();
		return Harness {
			_server_ep: server_ep,
			_client_ep: client_ep,
			server_conn,
			client_conn,
			client_tls,
		};
	}

	// The client opens a bi stream, writes `payload`, and finishes it; the server accepts it and wraps
	// it as the incoming QuicStream that read_routing_header / handle_raw_stream will read from.
	async fn incoming_stream(h: &Harness, payload: &[u8], identity: Option<PeerIdentity>) -> QuicStream {
		let (mut c_send, _c_recv) = h.client_conn.open_bi().await.unwrap();
		c_send.write_all(payload).await.unwrap();
		c_send.finish().unwrap();
		let (s_send, s_recv) = h.server_conn.accept_bi().await.unwrap();
		return QuicStream::new(s_send, s_recv).with_peer_identity(identity);
	}

	fn routing_header(backend_id: &str) -> Vec<u8> {
		let mut buf: Vec<u8> = Vec::new();
		buf.extend_from_slice(&u16::try_from(backend_id.len()).unwrap().to_be_bytes());
		buf.extend_from_slice(backend_id.as_bytes());
		return buf;
	}

	// Fixed request/response idle budgets for the streaming-path test harness; only the connect
	// timeout varies per test.
	const REQUEST_TIMEOUT_SECS: u64 = 30;
	const RESPONSE_IDLE_TIMEOUT_SECS: u64 = 60;

	fn build_state(
		h: &Harness,
		acl: AccessControl,
		backend_pools: HashMap<ArrayString<256>, BackendPool>,
		connect_secs: u64,
		revocation: RevocationSet,
	) -> Arc<ProxyState> {
		let reloadable: ReloadableState = ReloadableState {
			router: Router::new(&[]),
			backend_pools,
			acl,
		};
		let timeouts: TimeoutConfig = TimeoutConfig {
			connect_secs: NonZeroU64::new(connect_secs).unwrap(),
			handshake_secs: NonZeroU64::new(connect_secs).unwrap(),
			request_secs: NonZeroU64::new(REQUEST_TIMEOUT_SECS).unwrap(),
			response_idle_secs: NonZeroU64::new(RESPONSE_IDLE_TIMEOUT_SECS).unwrap(),
		};
		return ProxyState::for_test(TestProxyStateParams::new(
			reloadable,
			revocation,
			h.client_tls.clone(),
			timeouts,
		));
	}

	#[tokio::test]
	async fn test_read_routing_header_valid() {
		let h = harness().await;
		let mut stream = incoming_stream(&h, &routing_header("api-backend"), None).await;
		let id = read_routing_header(&mut stream).await.unwrap();
		assert_eq!(id, "api-backend");
	}

	#[tokio::test]
	async fn test_read_routing_header_times_out_when_client_stalls() {
		let h = harness().await;
		// Send one length byte, then keep the stream open. The server must not reserve a raw-relay
		// task indefinitely while waiting for the remainder of an untrusted routing header.
		let (mut client_send, _client_recv) = h.client_conn.open_bi().await.unwrap();
		client_send.write_all(&[0]).await.unwrap();
		let (server_send, server_recv) = h.server_conn.accept_bi().await.unwrap();
		let mut stream = QuicStream::new(server_send, server_recv);

		let err = read_routing_header_with_timeout(&mut stream, Duration::from_millis(20))
			.await
			.unwrap_err();
		assert!(format!("{err}").contains("routing header timed out"));
	}

	#[tokio::test]
	async fn test_read_routing_header_zero_length_rejected() {
		let h = harness().await;
		let mut stream = incoming_stream(&h, &[0u8, 0u8], None).await;
		let err = read_routing_header(&mut stream).await.unwrap_err();
		assert!(format!("{err}").contains("invalid backend_id length"));
	}

	#[tokio::test]
	async fn test_read_routing_header_too_long_rejected() {
		let h = harness().await;
		// Declared length 257 exceeds MAX_BACKEND_ID_LEN (256); rejected before reading the body.
		let mut stream = incoming_stream(&h, &257u16.to_be_bytes(), None).await;
		let err = read_routing_header(&mut stream).await.unwrap_err();
		assert!(format!("{err}").contains("invalid backend_id length"));
	}

	#[tokio::test]
	async fn test_read_routing_header_max_len_accepted() {
		// Boundary: exactly MAX_BACKEND_ID_LEN bytes must be accepted (the reject test proves MAX + 1 is not);
		// together they fail if the constant moves either way.
		let h = harness().await;
		let id: String = "a".repeat(MAX_BACKEND_ID_LEN);
		let mut payload: Vec<u8> = u16::try_from(MAX_BACKEND_ID_LEN).unwrap().to_be_bytes().to_vec();
		payload.extend_from_slice(id.as_bytes());
		let mut stream = incoming_stream(&h, &payload, None).await;
		let read_id = read_routing_header(&mut stream).await.unwrap();
		assert_eq!(read_id, id);
	}

	#[tokio::test]
	async fn test_read_routing_header_invalid_utf8_rejected() {
		let h = harness().await;
		let mut payload: Vec<u8> = 2u16.to_be_bytes().to_vec();
		payload.extend_from_slice(&[0xff, 0xff]); // not valid UTF-8
		let mut stream = incoming_stream(&h, &payload, None).await;
		let err = read_routing_header(&mut stream).await.unwrap_err();
		assert!(format!("{err}").contains("invalid backend_id UTF-8"));
	}

	#[tokio::test]
	async fn test_read_routing_header_eof_on_length() {
		let h = harness().await;
		// Finish the stream with no bytes: reading the 2-byte length hits EOF.
		let mut stream = incoming_stream(&h, &[], None).await;
		let err = read_routing_header(&mut stream).await.unwrap_err();
		assert!(format!("{err}").contains("read routing header length"));
	}

	#[tokio::test]
	async fn test_read_routing_header_eof_on_body() {
		let h = harness().await;
		// Length says 5 but only 2 body bytes follow before EOF.
		let mut payload: Vec<u8> = 5u16.to_be_bytes().to_vec();
		payload.extend_from_slice(b"ab");
		let mut stream = incoming_stream(&h, &payload, None).await;
		let err = read_routing_header(&mut stream).await.unwrap_err();
		assert!(format!("{err}").contains("read routing header"));
	}

	#[tokio::test]
	async fn test_handle_raw_stream_rejects_acl_blocked_peer() {
		let h = harness().await;
		let acl = AccessControl::new(vec![], vec!["127.0.0.0/8".parse().unwrap()]);
		let state = build_state(&h, acl, HashMap::new(), 1, RevocationSet::default());
		let stream = incoming_stream(&h, &routing_header("api"), Some(some_identity())).await;

		// A blocked peer is a clean terminal outcome (Ok) — never handed a byte pipe — and the backend
		// is never consulted (empty pools would otherwise surface an "unknown backend" error).
		let result = handle_raw_stream(
			stream,
			h.client_conn.remote_address(),
			&state,
			&authz_allowing(&["api"]),
			CancellationToken::new(),
		)
		.await;
		assert!(
			result.is_ok(),
			"ACL-blocked peer must be rejected cleanly, got {result:?}"
		);
	}

	// Regression for the raw-relay revocation bypass: a revoked identity is rejected cleanly (Ok, no byte pipe),
	// the backend never consulted. Proves handle_raw_stream reads state.revocation, not just pure check_admission.
	#[tokio::test]
	async fn test_handle_raw_stream_rejects_revoked_identity() {
		let h = harness().await;
		// A non-empty pool would surface an "unknown backend" error if the revocation gate failed open,
		// so reaching a clean Ok proves the peer was turned away before any backend lookup.
		let backend = BackendConfig::new("svc", "127.0.0.1:1".parse().unwrap(), 1.0, TransportKind::Quic).unwrap();
		let pool = BackendPool::new(vec![backend]).unwrap();
		let mut pools: HashMap<ArrayString<256>, BackendPool> = HashMap::new();
		pools.insert(ArrayString::from("svc").unwrap(), pool);
		let revocation =
			RevocationSet::parse("[[revoked]]\nbackend_id = \"device-1\"\nreason = \"clone detected\"\n").unwrap();
		let state = build_state(&h, AccessControl::new(vec![], vec![]), pools, 1, revocation);
		let stream = incoming_stream(&h, &routing_header("svc"), Some(some_identity())).await;

		let result = handle_raw_stream(
			stream,
			h.client_conn.remote_address(),
			&state,
			&authz_allowing(&["svc"]),
			CancellationToken::new(),
		)
		.await;
		assert!(
			result.is_ok(),
			"revoked peer must be rejected cleanly before any backend connect, got {result:?}"
		);
	}

	#[tokio::test]
	async fn test_handle_raw_stream_unknown_backend_errors() {
		let h = harness().await;
		let acl = AccessControl::new(vec![], vec![]);
		let state = build_state(&h, acl, HashMap::new(), 1, RevocationSet::default()); // no pools, no revocation
		let stream = incoming_stream(&h, &routing_header("missing"), Some(some_identity())).await;

		let result = handle_raw_stream(
			stream,
			h.client_conn.remote_address(),
			&state,
			&authz_allowing(&["missing"]),
			CancellationToken::new(),
		)
		.await;
		let err = match result {
			Ok(()) => panic!("expected an error for an unknown backend"),
			Err(e) => e,
		};
		assert!(format!("{err}").contains("unknown backend pool"));
	}

	#[tokio::test]
	async fn test_handle_raw_stream_dead_backend_errors() {
		let h = harness().await;
		// A pool whose only backend points at a dead QUIC address; acquire_raw_stream must fail.
		let backend = BackendConfig::new("svc", "127.0.0.1:1".parse().unwrap(), 1.0, TransportKind::Quic).unwrap();
		let pool = BackendPool::new(vec![backend]).unwrap();
		let mut pools: HashMap<ArrayString<256>, BackendPool> = HashMap::new();
		pools.insert(ArrayString::from("svc").unwrap(), pool);
		let state = build_state(
			&h,
			AccessControl::new(vec![], vec![]),
			pools,
			1,
			RevocationSet::default(),
		);
		let stream = incoming_stream(&h, &routing_header("svc"), Some(some_identity())).await;

		let result = timeout(
			Duration::from_secs(10),
			handle_raw_stream(
				stream,
				h.client_conn.remote_address(),
				&state,
				&authz_allowing(&["svc"]),
				CancellationToken::new(),
			),
		)
		.await
		.expect("handle_raw_stream hung");
		assert!(result.is_err(), "connecting to a dead backend must error");
	}

	// Regression for the raw-path connection-limit bypass (#37): a per-backend permit is drawn before connecting,
	// so a backend at its max_connections cap turns the stream away cleanly (Ok, no connect). Vs the dead-backend
	// test (permit free, so it reaches the backend and errors), here the single permit is pre-held so it's rejected first.
	#[tokio::test]
	async fn test_handle_raw_stream_rejects_when_conn_limit_reached() {
		let h = harness().await;
		let backend = BackendConfig::new("svc", "127.0.0.1:1".parse().unwrap(), 1.0, TransportKind::Quic)
			.unwrap()
			.with_max_connections(1)
			.unwrap();
		let pool = BackendPool::new(vec![backend.clone()]).unwrap();
		let mut pools: HashMap<ArrayString<256>, BackendPool> = HashMap::new();
		pools.insert(ArrayString::from("svc").unwrap(), pool);
		let state = build_state(
			&h,
			AccessControl::new(vec![], vec![]),
			pools,
			1,
			RevocationSet::default(),
		);

		// Exhaust the single connection permit for backend "svc" before the relay runs; the raw path draws
		// from the same per-backend semaphore, so it must now find none available.
		let _held: OwnedSemaphorePermit = state
			.conn_pool
			.try_acquire_conn_permit(&backend)
			.expect("first permit must be available");

		let stream = incoming_stream(&h, &routing_header("svc"), Some(some_identity())).await;
		let result = timeout(
			Duration::from_secs(10),
			handle_raw_stream(
				stream,
				h.client_conn.remote_address(),
				&state,
				&authz_allowing(&["svc"]),
				CancellationToken::new(),
			),
		)
		.await
		.expect("handle_raw_stream hung");
		assert!(
			result.is_ok(),
			"a backend at its connection cap must reject the raw stream cleanly before any connect, got {result:?}",
		);
	}

	// Regression for #33 (option C): a device not on a backend's raw-relay allowlist is rejected cleanly (Ok, no
	// connect) before any backend lookup. Vs the admit test below, only the allowlist differs: here it names
	// "device-authorized" and device-1 is turned away; there it names "device-1" and the same device passes.
	#[tokio::test]
	async fn test_handle_raw_stream_rejects_unauthorized_device() {
		let h = harness().await;
		// A live-looking pool so a failed gate would surface a backend error rather than a clean Ok.
		let backend = BackendConfig::new("svc", "127.0.0.1:1".parse().unwrap(), 1.0, TransportKind::Quic).unwrap();
		let pool = BackendPool::new(vec![backend]).unwrap();
		let mut pools: HashMap<ArrayString<256>, BackendPool> = HashMap::new();
		pools.insert(ArrayString::from("svc").unwrap(), pool);
		let state = build_state(
			&h,
			AccessControl::new(vec![], vec![]),
			pools,
			1,
			RevocationSet::default(),
		);

		// Policy admits only "device-authorized"; some_identity() presents CN "device-1" → denied.
		let authz = RawRelayAuthz::new(
			&[RawRelayAuthzEntry {
				backend_id: ArrayString::from("svc").unwrap(),
				allowed_cns: vec![ArrayString::from("device-authorized").unwrap()],
				allowed_spkis: vec![],
			}],
			&HashSet::from([ArrayString::from("svc").unwrap()]),
		)
		.unwrap();

		let stream = incoming_stream(&h, &routing_header("svc"), Some(some_identity())).await;
		let result = handle_raw_stream(
			stream,
			h.client_conn.remote_address(),
			&state,
			&authz,
			CancellationToken::new(),
		)
		.await;
		assert!(
			result.is_ok(),
			"an unauthorized device must be rejected cleanly before any backend connect, got {result:?}",
		);
	}

	// Regression for the default-allow authorization flaw: an authenticated device targeting a real
	// backend with no raw_relay_authz entry is rejected before any backend connection is attempted.
	#[tokio::test]
	async fn test_handle_raw_stream_rejects_backend_without_policy() {
		let h = harness().await;
		// A dead-but-configured backend makes a failed authorization gate observable: if the request
		// were forwarded, it would return a connection error instead of the clean rejection below.
		let backend = BackendConfig::new("svc", "127.0.0.1:1".parse().unwrap(), 1.0, TransportKind::Quic).unwrap();
		let pool = BackendPool::new(vec![backend]).unwrap();
		let mut pools: HashMap<ArrayString<256>, BackendPool> = HashMap::new();
		pools.insert(ArrayString::from("svc").unwrap(), pool);
		let state = build_state(
			&h,
			AccessControl::new(vec![], vec![]),
			pools,
			1,
			RevocationSet::default(),
		);
		let no_policy = RawRelayAuthz::new(&[], &HashSet::from([ArrayString::from("svc").unwrap()])).unwrap();

		let stream = incoming_stream(&h, &routing_header("svc"), Some(some_identity())).await;
		let result = handle_raw_stream(
			stream,
			h.client_conn.remote_address(),
			&state,
			&no_policy,
			CancellationToken::new(),
		)
		.await;
		assert!(
			result.is_ok(),
			"a backend without policy must be rejected cleanly, got {result:?}"
		);
	}

	// Complement to the reject test: the SAME device IS admitted when the policy lists its CN, then connects to
	// the dead backend and errors — proving the gate authorizes rather than blanket-denies a listed device.
	#[tokio::test]
	async fn test_handle_raw_stream_admits_authorized_device() {
		let h = harness().await;
		let backend = BackendConfig::new("svc", "127.0.0.1:1".parse().unwrap(), 1.0, TransportKind::Quic).unwrap();
		let pool = BackendPool::new(vec![backend]).unwrap();
		let mut pools: HashMap<ArrayString<256>, BackendPool> = HashMap::new();
		pools.insert(ArrayString::from("svc").unwrap(), pool);
		let state = build_state(
			&h,
			AccessControl::new(vec![], vec![]),
			pools,
			1,
			RevocationSet::default(),
		);

		// Policy lists device-1 (some_identity's CN) → admitted, then reaches the dead backend and errors.
		let authz = RawRelayAuthz::new(
			&[RawRelayAuthzEntry {
				backend_id: ArrayString::from("svc").unwrap(),
				allowed_cns: vec![ArrayString::from("device-1").unwrap()],
				allowed_spkis: vec![],
			}],
			&HashSet::from([ArrayString::from("svc").unwrap()]),
		)
		.unwrap();

		let stream = incoming_stream(&h, &routing_header("svc"), Some(some_identity())).await;
		let result = timeout(
			Duration::from_secs(10),
			handle_raw_stream(
				stream,
				h.client_conn.remote_address(),
				&state,
				&authz,
				CancellationToken::new(),
			),
		)
		.await
		.expect("handle_raw_stream hung");
		assert!(
			result.is_err(),
			"an authorized device must pass the gate and reach the (dead) backend, got {result:?}",
		);
	}

	#[tokio::test]
	async fn test_run_raw_relay_handler_stops_on_channel_close() {
		let h = harness().await;
		let state = build_state(
			&h,
			AccessControl::new(vec![], vec![]),
			HashMap::new(),
			1,
			RevocationSet::default(),
		);
		let (tx, rx) = mpsc::channel::<(QuicStream, SocketAddr)>(4);
		let handle = tokio::spawn(run_raw_relay_handler(
			rx,
			state,
			Arc::new(authz_allowing(&[])),
			CancellationToken::new(),
		));

		drop(tx); // no senders left → recv yields None → handler returns
		timeout(Duration::from_secs(5), handle)
			.await
			.expect("handler did not stop on channel close")
			.unwrap();
	}

	#[tokio::test]
	async fn test_run_raw_relay_handler_stops_on_shutdown() {
		let h = harness().await;
		let state = build_state(
			&h,
			AccessControl::new(vec![], vec![]),
			HashMap::new(),
			1,
			RevocationSet::default(),
		);
		let (_tx, rx) = mpsc::channel::<(QuicStream, SocketAddr)>(4);
		let shutdown = CancellationToken::new();
		let handle = tokio::spawn(run_raw_relay_handler(
			rx,
			state,
			Arc::new(authz_allowing(&[])),
			shutdown.clone(),
		));

		shutdown.cancel(); // cancellation breaks the loop even with a live sender
		timeout(Duration::from_secs(5), handle)
			.await
			.expect("handler did not stop on shutdown")
			.unwrap();
	}

	#[tokio::test]
	async fn test_run_raw_relay_handler_dispatches_incoming_stream() {
		let h = harness().await;
		// Deny-all ACL so the dispatched handler rejects (clean Ok) without needing a live backend.
		let acl = AccessControl::new(vec![], vec!["127.0.0.0/8".parse().unwrap()]);
		let state = build_state(&h, acl, HashMap::new(), 1, RevocationSet::default());
		let (tx, rx) = mpsc::channel::<(QuicStream, SocketAddr)>(4);
		let handle = tokio::spawn(run_raw_relay_handler(
			rx,
			state,
			Arc::new(authz_allowing(&["api"])),
			CancellationToken::new(),
		));

		let stream = incoming_stream(&h, &routing_header("api"), Some(some_identity())).await;
		let peer: SocketAddr = h.client_conn.remote_address();
		tx.send((stream, peer)).await.unwrap();

		// Closing the channel lets the handler drain the queued stream (spawning handle_raw_stream)
		// and then return — exercising the recv-Some dispatch branch.
		drop(tx);
		timeout(Duration::from_secs(5), handle)
			.await
			.expect("handler did not drain and stop")
			.unwrap();
	}
}
