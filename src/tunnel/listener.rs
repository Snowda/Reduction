use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arrayvec::{ArrayString, ArrayVec};
use opentelemetry::KeyValue;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, IdleTimeout, ServerConfig, TransportConfig, VarInt};
use tokio::io::AsyncWriteExt;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
// Aliased: std::time::Instant is already in scope for session bookkeeping (name-clash exception).
use tokio::time::{Instant as TokioInstant, timeout, timeout_at};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::TunnelConfig;
use crate::error::{ReductionError, Result};
use crate::health::state::{Availability, BackendHealth, HealthBroadcast, HealthState};
use crate::metrics::ProxyMetrics;
use crate::ratelimit::RateLimit;
use crate::tls::PeerIdentity;
use crate::transport::quic::QuicStream;
use crate::tunnel::protocol::{self, SessionId, TunnelFrame};
use crate::tunnel::registry::{TunnelRegistry, TunnelSession};
use crate::tunnel::revocation::RevocationSet;

// The per-connection registration pipeline (establish → admit → commit) lives in a submodule.
mod registration;
#[cfg(test)]
mod testutil;

use registration::{TunnelConn, handle_tunnel_connection};

// How often to sweep the accept rate limiter's per-IP map of fully-replenished entries, keeping it
// bounded by the active source set rather than every IP ever seen (mirrors the HTTP limiter GC).
const ACCEPT_LIMITER_GC_INTERVAL: Duration = Duration::from_secs(60);

// Metric attribute (on tunnel_registration_rejected) distinguishing why a registration was rejected.
const REJECT_REASON_KEY: &str = "reason";
const REJECT_REASON_CN_MISMATCH: &str = "cn_mismatch";
const REJECT_REASON_ALLOWLIST: &str = "allowlist";
const REJECT_REASON_REVOKED: &str = "revoked";
const REJECT_REASON_GLOBAL_CAP: &str = "global_cap";
const REJECT_REASON_BACKEND_CAP: &str = "backend_cap";
const REJECT_REASON_PENDING_CAP: &str = "pending_cap";
const REJECT_REASON_VERSION: &str = "version";

// Connections are expensive before registration (mid-handshake or awaiting the first control stream).
// Bounded independently of the session caps so slow clients can't create unbounded tasks.
const MAX_CONCURRENT_PENDING_REGISTRATIONS: usize = 128;

// Grace added on top of heartbeat_timeout_secs for the QUIC-level idle timeout, so the app-level
// heartbeat timeout (which records the metric and logs the reason) always fires first.
const TUNNEL_IDLE_GRACE_SECS: u64 = 15;
// Client-initiated bidi streams on a tunnel connection: the control stream plus slack for protocol
// evolution. Proxied data streams are opened by the proxy side and do not count against this.
const TUNNEL_CLIENT_BIDI_STREAMS: u32 = 4;
// The protocol uses no unidirectional streams; refuse them outright.
const TUNNEL_UNI_STREAMS: u32 = 0;
// Connection-level receive window. Quinn's default is unbounded (VarInt::MAX, verified in
// quinn-proto 0.11 config/transport.rs); bound what one tunnel connection may buffer toward us.
const TUNNEL_RECEIVE_WINDOW_BYTES: u32 = 8 * 1024 * 1024;

// Explicit QUIC transport contract: quinn's 30s default idle timeout would kill a quiet-but-healthy session
// before the app heartbeat timeout fires, so idle is derived from the configured heartbeat timeout.
fn tunnel_transport_config(config: &TunnelConfig) -> Result<TransportConfig> {
	let idle_secs: u64 = config.heartbeat_timeout_secs.saturating_add(TUNNEL_IDLE_GRACE_SECS);
	let idle: IdleTimeout = IdleTimeout::try_from(Duration::from_secs(idle_secs)).map_err(|_| {
		ReductionError::Tunnel(format!(
			"tunnel.heartbeat_timeout_secs too large for a QUIC idle timeout: {idle_secs}s"
		))
	})?;
	let mut transport: TransportConfig = TransportConfig::default();
	transport.max_idle_timeout(Some(idle));
	transport.max_concurrent_bidi_streams(VarInt::from_u32(TUNNEL_CLIENT_BIDI_STREAMS));
	transport.max_concurrent_uni_streams(VarInt::from_u32(TUNNEL_UNI_STREAMS));
	transport.receive_window(VarInt::from_u32(TUNNEL_RECEIVE_WINDOW_BYTES));
	return Ok(transport);
}

// Whether accepting one more session would exceed the global cap. None = unlimited. Pure so the
// boundary is unit-testable without a live listener.
#[inline]
fn exceeds_session_cap(current_total: usize, cap: Option<NonZeroU32>) -> bool {
	return match cap {
		None => false,
		Some(limit) => current_total >= usize::try_from(limit.get()).unwrap_or(usize::MAX),
	};
}

// How long to keep a rejected connection open after sending its Shutdown frame, so quinn actually
// transmits the frame before the connection is dropped. Resolves early once the peer closes.
const REJECT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

// Ceiling on any single control-stream write: quinn buffers until the peer's flow-control window fills, so
// a peer that stays alive but stops reading its control stream would otherwise park the writer forever.
const CONTROL_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

// Rejections drain on their own fixed budget (callers drop the admission permit before reject_and_close), so a
// reject flood can't pin the admission budget; at the cap the reason frame is abandoned but the rejection still happens.
const MAX_CONCURRENT_REJECT_DRAINS: usize = 64;
static REJECT_DRAIN_BUDGET: Semaphore = Semaphore::const_new(MAX_CONCURRENT_REJECT_DRAINS);

// Bounded control-stream write: false = error or stall past CONTROL_WRITE_TIMEOUT (peer wedged its control
// stream), so the caller must tear the session down rather than write again (framing may be unusable).
async fn bounded_control_write<W: AsyncWriteExt + Unpin>(stream: &mut W, frame: &TunnelFrame) -> bool {
	return matches!(
		timeout(CONTROL_WRITE_TIMEOUT, protocol::write_frame(stream, frame)).await,
		Ok(Ok(())),
	);
}

// Send a rejection Shutdown and drain: finish the stream and keep the connection alive until the peer closes
// (or the drain timeout elapses), so the reason isn't lost to an abrupt drop. A peer that won't accept the write gets neither.
async fn reject_and_close(mut control_stream: QuicStream, connection: &quinn::Connection, reason: &str) {
	let Ok(_drain_slot) = REJECT_DRAIN_BUDGET.try_acquire() else {
		debug!(
			reason,
			"reject drain budget exhausted; dropping connection without a reason frame"
		);
		return;
	};
	let delivered: bool = bounded_control_write(
		&mut control_stream,
		&TunnelFrame::Shutdown {
			reason: ArrayString::from(reason).unwrap_or_default(),
		},
	)
	.await;
	if delivered {
		control_stream.finish();
		timeout(REJECT_DRAIN_TIMEOUT, connection.closed()).await.ok();
	}
}

// Signature-preserving entry point (control-plane health transport OFF). Existing consumers and
// Charon's integration test call this; behavior is byte-identical to before F4.
pub async fn run_tunnel_listener(
	bind_addr: SocketAddr,
	server_tls_config: Arc<rustls::ServerConfig>,
	registry: Arc<TunnelRegistry>,
	shutdown: CancellationToken,
	config: TunnelConfig,
	metrics: ProxyMetrics,
	revocation_rx: watch::Receiver<RevocationSet>,
) -> Result<()> {
	return run_tunnel_listener_inner(bind_addr, server_tls_config, registry, shutdown, config, metrics, revocation_rx, None).await;
}

// F4 entry point: a control peer's `Health` frames are applied to `health_tx`. Moist's Phase 2
// deployment uses this; `None` (the plain entry point) is the flag-off Phase 1 behavior.
#[allow(clippy::too_many_arguments)]
pub async fn run_tunnel_listener_with_health(
	bind_addr: SocketAddr,
	server_tls_config: Arc<rustls::ServerConfig>,
	registry: Arc<TunnelRegistry>,
	shutdown: CancellationToken,
	config: TunnelConfig,
	metrics: ProxyMetrics,
	revocation_rx: watch::Receiver<RevocationSet>,
	health_tx: watch::Sender<HealthState>,
) -> Result<()> {
	return run_tunnel_listener_inner(bind_addr, server_tls_config, registry, shutdown, config, metrics, revocation_rx, Some(health_tx))
		.await;
}

// The tokio::select! accept loop inflates cognitive complexity via macro expansion; its arms are a
// cohesive accept/GC/shutdown set that must share one select to stay cancellation-correct.
#[allow(clippy::too_many_arguments, clippy::cognitive_complexity)]
async fn run_tunnel_listener_inner(
	bind_addr: SocketAddr,
	server_tls_config: Arc<rustls::ServerConfig>,
	registry: Arc<TunnelRegistry>,
	shutdown: CancellationToken,
	config: TunnelConfig,
	metrics: ProxyMetrics,
	revocation_rx: watch::Receiver<RevocationSet>,
	health_tx: Option<watch::Sender<HealthState>>,
) -> Result<()> {
	let quic_crypto: QuicServerConfig = QuicServerConfig::try_from(server_tls_config)
		.map_err(|e| ReductionError::Tunnel(format!("QUIC crypto config: {e}")))?;
	let mut server_config: ServerConfig = ServerConfig::with_crypto(Arc::new(quic_crypto));
	server_config.transport_config(Arc::new(tunnel_transport_config(&config)?));

	let endpoint: Endpoint =
		Endpoint::server(server_config, bind_addr).map_err(|e| ReductionError::Tunnel(format!("tunnel bind: {e}")))?;

	// Per-source-IP accept rate limiter. None = unlimited (feature off). NonZeroU32 guarantees a
	// valid rate, so RateLimit::new never errors here.
	let accept_limiter: Option<RateLimit> = match config.max_accepts_per_second_per_ip {
		Some(rps) => Some(RateLimit::new(rps.get())?),
		None => None,
	};
	if accept_limiter.is_some() {
		info!(%bind_addr, "tunnel accept rate limiting enabled");
	}
	let mut gc_interval = tokio::time::interval(ACCEPT_LIMITER_GC_INTERVAL);
	let pending_registrations: Arc<Semaphore> = Arc::new(Semaphore::new(MAX_CONCURRENT_PENDING_REGISTRATIONS));

	info!(%bind_addr, "tunnel listener started");

	loop {
		tokio::select! {
			incoming = endpoint.accept() => {
				let Some(incoming) = incoming else {
					break;
				};
				let remote_addr: SocketAddr = incoming.remote_address();

				// Accept-rate limit BEFORE the handshake: drop a flood cheaply (no handshake/crypto/spawn).
				// ignore() sends nothing back, so a spoofed-source flood can't use the proxy to amplify.
				if let Some(limiter) = &accept_limiter
					&& limiter.check(remote_addr.ip()).is_err()
				{
					metrics.tunnel_accepts_rate_limited.add(1, &[]);
					debug!(%remote_addr, "tunnel connection dropped: accept rate limit exceeded");
					incoming.ignore();
					continue;
				}

				// Bound handshake/registration work globally; the permit releases once registered, so active
				// tunnels don't consume this pre-registration budget. At capacity, ignore before spawning.
				let pending_registration: OwnedSemaphorePermit = match Arc::clone(&pending_registrations).try_acquire_owned() {
					Ok(permit) => permit,
					Err(_) => {
						metrics.tunnel_registration_rejected.add(1, &[KeyValue::new(REJECT_REASON_KEY, REJECT_REASON_PENDING_CAP)]);
						debug!(%remote_addr, "tunnel connection dropped: pending registration cap reached");
						incoming.ignore();
						continue;
					}
				};

				let reg: Arc<TunnelRegistry> = Arc::clone(&registry);
				let cfg: TunnelConfig = config.clone();
				let cancel: CancellationToken = shutdown.clone();
				let m: ProxyMetrics = ProxyMetrics::new();
				let _ = &metrics; // keep the real metrics in scope for future use
				let revocation: watch::Receiver<RevocationSet> = revocation_rx.clone();
				let conn_health_tx: Option<watch::Sender<HealthState>> = health_tx.clone();

				tokio::spawn(async move {
					if let Err(e) = handle_tunnel_connection(TunnelConn {
						incoming,
						remote_addr,
						registry: reg,
						config: cfg,
						shutdown: cancel,
						metrics: m,
						revocation_rx: revocation,
						pending_registration: Some(pending_registration),
						health_tx: conn_health_tx,
					}).await {
						warn!(%remote_addr, error = %e, "tunnel connection failed");
					}
				});
			}
			_ = gc_interval.tick(), if accept_limiter.is_some() => {
				if let Some(limiter) = &accept_limiter {
					limiter.retain_recent();
				}
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

// The immutable per-session context for one control loop: everything the loop reads but never mutates,
// bundled so the registration pipeline threads a single value instead of a long positional argument list.
pub struct ControlLoopContext<'a> {
	pub connection: &'a quinn::Connection,
	pub registry: &'a Arc<TunnelRegistry>,
	pub shutdown: &'a CancellationToken,
	pub metrics: &'a ProxyMetrics,
	pub backend_id: &'a str,
	pub session_id: SessionId,
	pub heartbeat_timeout: Duration,
	pub is_control_peer: bool,
	// F4: where a control peer's Health frames are applied. None = health transport off (Phase 1).
	pub health_tx: Option<watch::Sender<HealthState>>,
}

#[allow(clippy::cognitive_complexity)]
pub async fn run_control_loop(
	control_stream: &mut QuicStream,
	control_rx: &mut mpsc::Receiver<TunnelFrame>,
	ctx: ControlLoopContext<'_>,
) {
	let ControlLoopContext {
		connection,
		registry,
		shutdown,
		metrics,
		backend_id,
		session_id,
		heartbeat_timeout,
		is_control_peer,
		health_tx,
	} = ctx;
	let mut last_heartbeat: TokioInstant = TokioInstant::now();

	loop {
		let heartbeat_deadline: TokioInstant = last_heartbeat + heartbeat_timeout;
		tokio::select! {
			result = timeout_at(heartbeat_deadline, protocol::read_frame(control_stream)) => {
				match result {
					Ok(Ok(TunnelFrame::Heartbeat { timestamp_ms })) => {
						debug!(%session_id, timestamp_ms, "heartbeat received");
						last_heartbeat = TokioInstant::now();
						registry.record_heartbeat(backend_id, &session_id);
						// A stalled ack means the peer stopped reading its control stream; without the
						// bound the loop parks here where no other select! branch can run.
						if !bounded_control_write(control_stream, &TunnelFrame::HeartbeatAck).await {
							warn!(%session_id, "heartbeat ack write failed or stalled; ending session");
							break;
						}
					}
					Ok(Ok(TunnelFrame::Shutdown { reason })) => {
						info!(%session_id, %reason, "tunnel backend requested shutdown");
						break;
					}
					Ok(Ok(TunnelFrame::Health { backend_id: reported, available })) => {
						// F4: only a control-plane peer may publish health, and only when a sender is wired
						// (the flag). A non-control peer's Health frame is dropped — it must not steer routing
						// for other backends. Not liveness, so last_heartbeat is untouched.
						if is_control_peer && let Some(tx) = health_tx.as_ref() {
							let availability: Availability = if available { Availability::Online } else { Availability::Offline };
							let entry: BackendHealth = BackendHealth { backend_id: reported, load: 0.0, latency_ms: 0, availability };
							tx.send_modify(|state| state.update(HealthBroadcast { entries: vec![entry] }));
							debug!(%session_id, backend = reported.as_str(), available, "control-plane health update applied");
						} else {
							warn!(%session_id, "health frame from a non-control peer or with no sink; ignored");
						}
					}
					Ok(Ok(TunnelFrame::RefuseWake { backend_id: refused })) => {
						// F1: only a control peer may refuse a wake; it releases the parked request to 503 at once.
						if is_control_peer {
							registry.note_refusal(refused.as_str());
							debug!(%session_id, backend = refused.as_str(), "control-plane refused wake");
						} else {
							warn!(%session_id, "refuse-wake frame from a non-control peer; ignored");
						}
					}
					Ok(Ok(other)) => {
						// Deliberately does NOT touch last_heartbeat: junk is traffic, not liveness.
						warn!(%session_id, ?other, "unexpected frame on control channel");
					}
					Ok(Err(e)) => {
						warn!(%session_id, error = %e, "control channel read error");
						break;
					}
					Err(_) => {
						metrics.tunnel_heartbeat_timeouts.add(1, &[]);
						warn!(%session_id, timeout_secs = heartbeat_timeout.as_secs(), "heartbeat timeout");
						break;
					}
				}
			}
			outbound = control_rx.recv() => {
				// Every frame queued here is TERMINAL (producers send Shutdown). Must not loop back to reading:
				// winning the select! drops the in-progress read_frame (not cancel-safe), which would desync framing.
				match outbound {
					// Write the Shutdown, then finish and drain like a rejection so the frame reaches the client (a wedged peer gets neither).
					Some(TunnelFrame::Shutdown { reason }) => {
						if bounded_control_write(control_stream, &TunnelFrame::Shutdown { reason }).await {
							control_stream.finish();
							timeout(REJECT_DRAIN_TIMEOUT, connection.closed()).await.ok();
						}
					}
					Some(other) => {
						warn!(%session_id, ?other, "non-terminal frame queued on control channel; ending session");
					}
					None => {}
				}
				break;
			}
			_ = shutdown.cancelled() => {
				let _ = bounded_control_write(control_stream, &TunnelFrame::Shutdown {
					reason: ArrayString::from("proxy shutting down").unwrap_or_default(),
				}).await;
				break;
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use arrayvec::ArrayVec;
	use quinn::crypto::rustls::QuicClientConfig;
	use tokio::io::duplex;

	use super::testutil::{
		REGISTER_TEST_TIMEOUT_SECS, TestClient, assert_rejected, connect_and_register, connect_once, poll_session_count,
		read_next, revoke_spki, spawn_health_peer, spawn_server_and_register, spawn_server_and_register_with_config,
	};
	use super::*;
	use crate::tunnel::protocol::CONTROL_CAPABILITY;
	use crate::test_support::{generate_ca, generate_signed_cert, write_pem};
	use crate::tls::certs::{build_client_config, build_server_config};

	#[tokio::test(start_paused = true)]
	async fn test_bounded_control_write_reports_stall_on_non_reading_peer() {
		let (mut writer, _unread_peer) = duplex(1);
		let delivered: bool = bounded_control_write(&mut writer, &TunnelFrame::HeartbeatAck).await;
		assert!(
			!delivered,
			"a stalled control write must report failure after the bound"
		);
	}

	#[tokio::test]
	async fn test_bounded_control_write_delivers_to_reading_peer() {
		let (mut writer, mut reader) = duplex(1024);
		let delivered: bool = bounded_control_write(&mut writer, &TunnelFrame::HeartbeatAck).await;
		assert!(delivered, "a healthy control write must succeed");
		let frame: TunnelFrame = protocol::read_frame(&mut reader).await.unwrap();
		assert!(
			matches!(frame, TunnelFrame::HeartbeatAck),
			"the bounded write must produce a decodable frame"
		);
	}

	// #6: liveness is HEARTBEATS, not traffic. A client streaming junk frames (never a heartbeat) must still be
	// cut off at the deadline — a per-read timeout would re-arm on every junk frame and keep it registered forever.
	#[tokio::test(start_paused = true)]
	async fn test_junk_frames_do_not_extend_heartbeat_deadline() {
		let ca = generate_ca();
		let client_leaf = generate_signed_cert(&ca, "device-7", vec![]);
		let config: TunnelConfig = TunnelConfig {
			heartbeat_timeout_secs: 2,
			..Default::default()
		};
		let mut client =
			spawn_server_and_register_with_config(&ca, &client_leaf, "device-7", config, RevocationSet::default())
				.await;
		assert!(matches!(
			read_next(&mut client).await,
			Some(TunnelFrame::RegisterAck { .. })
		));
		assert!(poll_session_count(&client.registry, "device-7", 1).await);

		// Background junk stream: a NewStream frame every 300ms, far more often than the 2s deadline.
		let registry: Arc<TunnelRegistry> = Arc::clone(&client.registry);
		tokio::spawn(async move {
			let mut client: TestClient = client;
			for _ in 0..30 {
				let junk = TunnelFrame::NewStream { stream_id: 42 };
				if protocol::write_frame(&mut client.control, &junk).await.is_err() {
					break; // the server already tore the session down
				}
				tokio::time::sleep(Duration::from_millis(300)).await;
			}
		});

		// At 3.5s the junk is still flowing, but the deadline (2s, anchored to the last real
		// heartbeat — here, registration) has passed: the session must be gone.
		tokio::time::sleep(Duration::from_millis(3500)).await;
		assert_eq!(
			registry.session_count("device-7"),
			0,
			"junk traffic must not count as liveness — the session should end at the heartbeat deadline",
		);
	}

	// Positive half: real heartbeats DO extend the deadline. Runs on the wall clock (paused time would auto-advance to the QUIC idle timeout).
	#[tokio::test]
	async fn test_heartbeats_extend_session_past_the_deadline() {
		let ca = generate_ca();
		let client_leaf = generate_signed_cert(&ca, "device-7", vec![]);
		let config: TunnelConfig = TunnelConfig {
			heartbeat_timeout_secs: 2,
			..Default::default()
		};
		let mut client =
			spawn_server_and_register_with_config(&ca, &client_leaf, "device-7", config, RevocationSet::default())
				.await;
		assert!(matches!(
			read_next(&mut client).await,
			Some(TunnelFrame::RegisterAck { .. })
		));
		assert!(poll_session_count(&client.registry, "device-7", 1).await);

		// 5 heartbeats at 500ms — reaching ~2.5s, past the 2s deadline; each one must re-arm it.
		for timestamp_ms in 0u64..5 {
			protocol::write_frame(&mut client.control, &TunnelFrame::Heartbeat { timestamp_ms })
				.await
				.unwrap();
			let ack = read_next(&mut client).await;
			assert!(
				matches!(ack, Some(TunnelFrame::HeartbeatAck)),
				"expected HeartbeatAck, got {ack:?}"
			);
			tokio::time::sleep(Duration::from_millis(500)).await;
		}
		assert_eq!(
			client.registry.session_count("device-7"),
			1,
			"regular heartbeats must keep the session alive past the nominal deadline",
		);
	}

	#[test]
	fn test_tunnel_transport_config_derives_idle_from_heartbeat_timeout() {
		let config: TunnelConfig = TunnelConfig::default();
		let transport: TransportConfig = tunnel_transport_config(&config).unwrap();
		let expected_ms: u64 = (config.heartbeat_timeout_secs + TUNNEL_IDLE_GRACE_SECS) * 1000;
		let debug: String = format!("{transport:?}");
		assert!(
			debug.contains(&expected_ms.to_string()),
			"idle timeout {expected_ms}ms not applied to the transport config: {debug}",
		);
	}

	#[test]
	fn test_tunnel_transport_config_rejects_oversized_heartbeat_timeout() {
		let config: TunnelConfig = TunnelConfig {
			heartbeat_timeout_secs: u64::MAX,
			..Default::default()
		};
		assert!(
			tunnel_transport_config(&config).is_err(),
			"an idle timeout beyond VarInt range must error, not panic"
		);
	}

	// #12: a client speaking a different protocol version gets a reasoned Shutdown (readable in the
	#[tokio::test]
	async fn test_live_session_terminated_when_revocation_sweeps() {
		// A session that registered while healthy must be actively torn down when its key later lands on
		// the revocation set — denial at registration alone would leave the standing clone tunnel alive.
		let ca = generate_ca();
		let client_leaf = generate_signed_cert(&ca, "device-7", vec![]);
		let mut client =
			spawn_server_and_register(&ca, &client_leaf, "device-7", vec![], RevocationSet::default()).await;
		assert!(matches!(
			read_next(&mut client).await,
			Some(TunnelFrame::RegisterAck { .. })
		));
		assert!(
			poll_session_count(&client.registry, "device-7", 1).await,
			"session not registered"
		);

		// The set now names this key; sweep the registry.
		let revoked: usize = client.registry.revoke_matching(&revoke_spki(&client_leaf));
		assert_eq!(revoked, 1, "sweep should report exactly one revoked session");

		// The client observes the Shutdown carrying the reason, and the registry is emptied.
		assert_rejected(&read_next(&mut client).await, REJECT_REASON_REVOKED);
		assert!(
			poll_session_count(&client.registry, "device-7", 0).await,
			"revoked session was not removed from the registry",
		);
	}

	#[test]
	fn test_exceeds_session_cap_none_is_unlimited() {
		assert!(!exceeds_session_cap(1_000_000, None));
		assert!(!exceeds_session_cap(0, None));
	}

	#[test]
	fn test_exceeds_session_cap_boundaries() {
		let cap = NonZeroU32::new(3);
		assert!(!exceeds_session_cap(0, cap));
		assert!(!exceeds_session_cap(2, cap), "under the cap admits");
		assert!(exceeds_session_cap(3, cap), "at the cap rejects (no room for one more)");
		assert!(exceeds_session_cap(4, cap), "over the cap rejects");
	}

	#[test]
	fn test_pending_registration_admission_is_bounded_and_reusable() {
		let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_PENDING_REGISTRATIONS));
		let active: Vec<OwnedSemaphorePermit> = (0..MAX_CONCURRENT_PENDING_REGISTRATIONS)
			.map(|_| Arc::clone(&permits).try_acquire_owned().unwrap())
			.collect();

		assert!(
			Arc::clone(&permits).try_acquire_owned().is_err(),
			"the listener must reject a new registration before spawning it at capacity",
		);

		drop(active);
		assert!(
			Arc::clone(&permits).try_acquire_owned().is_ok(),
			"completed registrations must release admission capacity",
		);
	}

	#[tokio::test]
	async fn test_accept_rate_limit_drops_flood_then_recovers() {
		// Three parts: first connection establishes, an immediate second from the same IP is dropped at accept
		// (1/sec token spent), and after the token replenishes a later connection establishes again.
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let server_leaf = generate_signed_cert(
			&ca,
			"reduction-server",
			vec![rcgen::SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1]))],
		);
		let ca_file = write_pem(&ca.cert.pem());
		let server_cert_file = write_pem(&server_leaf.cert.pem());
		let server_key_file = write_pem(&server_leaf.signing_key.serialize_pem());
		let (server_tls, _r1) =
			build_server_config(server_cert_file.path(), server_key_file.path(), ca_file.path()).unwrap();

		let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
		let addr: SocketAddr = probe.local_addr().unwrap();
		drop(probe);

		let registry: Arc<TunnelRegistry> = Arc::new(TunnelRegistry::new(8));
		let shutdown = CancellationToken::new();
		let config = TunnelConfig {
			max_accepts_per_second_per_ip: Some(NonZeroU32::new(1).unwrap()),
			..Default::default()
		};
		let (_vtx, revocation_rx) = watch::channel(RevocationSet::default());

		let listener_shutdown = shutdown.clone();
		tokio::spawn(async move {
			let _ = run_tunnel_listener(
				addr,
				Arc::new(server_tls),
				registry,
				listener_shutdown,
				config,
				ProxyMetrics::new(),
				revocation_rx,
			)
			.await;
		});
		// Give the listener a moment to bind.
		tokio::time::sleep(Duration::from_millis(100)).await;

		let dev = generate_signed_cert(&ca, "device-1", vec![]);

		// (1) First connect consumes the single token and establishes.
		assert!(
			connect_once(addr, &ca, &dev, Duration::from_secs(5)).await,
			"first connection should establish"
		);

		// (2) Immediate second connect from the same IP is dropped at accept — never establishes.
		assert!(
			!connect_once(addr, &ca, &dev, Duration::from_millis(700)).await,
			"second immediate connection must be dropped by the accept rate limiter"
		);

		// (3) After the 1/sec token replenishes, a connection establishes again.
		tokio::time::sleep(Duration::from_millis(1200)).await;
		assert!(
			connect_once(addr, &ca, &dev, Duration::from_secs(5)).await,
			"connection should establish again once the accept token has replenished"
		);

		shutdown.cancel();
	}

	#[tokio::test]
	async fn test_revocation_sweep_leaves_unrevoked_sessions() {
		// The sweep must be surgical: a session whose identity is not on the set survives it.
		let mut client = connect_and_register("device-7", "device-7", vec![]).await;
		assert!(matches!(
			read_next(&mut client).await,
			Some(TunnelFrame::RegisterAck { .. })
		));
		assert!(
			poll_session_count(&client.registry, "device-7", 1).await,
			"session not registered"
		);

		// A set targeting a different device revokes nothing here.
		let other = RevocationSet::parse("[[revoked]]\nbackend_id = \"some-other-device\"\nreason = \"x\"\n").unwrap();
		assert_eq!(client.registry.revoke_matching(&other), 0);
		assert_eq!(
			client.registry.session_count("device-7"),
			1,
			"unrelated revocation must not touch this session"
		);
	}

	#[tokio::test]
	async fn test_registered_session_heartbeat_and_clean_shutdown() {
		let mut client = connect_and_register("device-7", "device-7", vec![]).await;
		assert!(matches!(
			read_next(&mut client).await,
			Some(TunnelFrame::RegisterAck { .. })
		));
		assert!(
			poll_session_count(&client.registry, "device-7", 1).await,
			"session not registered"
		);

		// Heartbeat → HeartbeatAck exercises the control-loop heartbeat branch.
		protocol::write_frame(&mut client.control, &TunnelFrame::Heartbeat { timestamp_ms: 123 })
			.await
			.unwrap();
		assert!(
			matches!(read_next(&mut client).await, Some(TunnelFrame::HeartbeatAck)),
			"expected HeartbeatAck",
		);

		// A client-sent Shutdown drives clean teardown: the session is deregistered.
		protocol::write_frame(
			&mut client.control,
			&TunnelFrame::Shutdown {
				reason: ArrayString::from("bye").unwrap_or_default(),
			},
		)
		.await
		.unwrap();
		assert!(
			poll_session_count(&client.registry, "device-7", 0).await,
			"session was not deregistered after Shutdown",
		);
	}

	#[tokio::test]
	async fn test_run_tunnel_listener_accepts_registration() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

		let ca = generate_ca();
		let server_leaf = generate_signed_cert(
			&ca,
			"reduction-server",
			vec![rcgen::SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1]))],
		);
		let client_leaf = generate_signed_cert(&ca, "device-5", vec![]);

		let ca_file = write_pem(&ca.cert.pem());
		let server_cert_file = write_pem(&server_leaf.cert.pem());
		let server_key_file = write_pem(&server_leaf.signing_key.serialize_pem());
		let client_cert_file = write_pem(&client_leaf.cert.pem());
		let client_key_file = write_pem(&client_leaf.signing_key.serialize_pem());

		let (server_tls, _r1) =
			build_server_config(server_cert_file.path(), server_key_file.path(), ca_file.path()).unwrap();
		let (client_tls, _r2, _v2) =
			build_client_config(client_cert_file.path(), client_key_file.path(), ca_file.path()).unwrap();

		// Grab a free UDP port, then hand it to the real listener entry point.
		let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
		let addr: SocketAddr = probe.local_addr().unwrap();
		drop(probe);

		let registry: Arc<TunnelRegistry> = Arc::new(TunnelRegistry::new(8));
		let shutdown = CancellationToken::new();
		let listener_registry = Arc::clone(&registry);
		let listener_shutdown = shutdown.clone();
		let (_revocation_tx, revocation_rx) = watch::channel(RevocationSet::default());
		tokio::spawn(async move {
			let _ = run_tunnel_listener(
				addr,
				Arc::new(server_tls),
				listener_registry,
				listener_shutdown,
				TunnelConfig::default(),
				ProxyMetrics::new(),
				revocation_rx,
			)
			.await;
		});

		// Let the endpoint bind before the client dials.
		assert!(poll_session_count(&registry, "device-5", 0).await);

		let quic_client_crypto = QuicClientConfig::try_from(Arc::new(client_tls)).unwrap();
		let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
		client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_client_crypto)));

		// The listener may not have bound yet on the first attempt; retry the dial briefly.
		let mut connection = None;
		for _ in 0..50 {
			match client_endpoint.connect(addr, "127.0.0.1").unwrap().await {
				Ok(conn) => {
					connection = Some(conn);
					break;
				}
				Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
			}
		}
		let connection = connection.expect("could not connect to tunnel listener");

		let (send, recv) = connection.open_bi().await.unwrap();
		let mut control = QuicStream::new(send, recv);
		protocol::write_preamble(&mut control).await.unwrap();
		protocol::write_frame(
			&mut control,
			&TunnelFrame::Register {
				backend_id: ArrayString::from("device-5").unwrap(),
				pool: ArrayString::from("default").unwrap(),
				capabilities: ArrayVec::new(),
			},
		)
		.await
		.unwrap();
		let server_version: u8 = protocol::read_preamble(&mut control).await.unwrap();
		assert_eq!(server_version, protocol::PROTOCOL_VERSION);

		let ack = timeout(
			Duration::from_secs(REGISTER_TEST_TIMEOUT_SECS),
			protocol::read_frame(&mut control),
		)
		.await
		.ok()
		.and_then(|r| r.ok());
		assert!(
			matches!(ack, Some(TunnelFrame::RegisterAck { .. })),
			"expected RegisterAck, got {ack:?}"
		);
		assert!(
			poll_session_count(&registry, "device-5", 1).await,
			"listener did not register the backend"
		);

		shutdown.cancel();
	}

	// Poll the health receiver until `id` reports `want` (the control loop applies frames async).
	async fn poll_availability(rx: &watch::Receiver<HealthState>, id: &str, want: Availability) -> bool {
		for _ in 0..100u32 {
			if let Some(health) = rx.borrow().get(id)
				&& health.availability == want
			{
				return true;
			}
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
		return false;
	}

	// F4 `with`: a control peer's Health frame reaches the shared HealthState and steers the balancer —
	// Offline drives weight_factor to 0 (dropped from selection), Online restores it.
	#[tokio::test]
	async fn control_peer_health_offline_then_online_is_applied() {
		let ca = generate_ca();
		let client_leaf = generate_signed_cert(&ca, "moist-control", vec![]);
		let mut caps: ArrayVec<ArrayString<8>, 4> = ArrayVec::new();
		caps.push(ArrayString::from(CONTROL_CAPABILITY).unwrap());
		let (mut client, health_rx) = spawn_health_peer(&ca, &client_leaf, "moist-control", caps).await;
		assert!(matches!(read_next(&mut client).await, Some(TunnelFrame::RegisterAck { .. })), "control peer must register");

		protocol::write_frame(&mut client.control, &TunnelFrame::Health { backend_id: ArrayString::from("api").unwrap(), available: false })
			.await
			.unwrap();
		assert!(poll_availability(&health_rx, "api", Availability::Offline).await, "Offline must be applied");
		assert_eq!(health_rx.borrow().weight_factor("api"), 0.0, "an Offline backend is not selectable");

		protocol::write_frame(&mut client.control, &TunnelFrame::Health { backend_id: ArrayString::from("api").unwrap(), available: true })
			.await
			.unwrap();
		assert!(poll_availability(&health_rx, "api", Availability::Online).await, "Online must be applied");
		assert_eq!(health_rx.borrow().weight_factor("api"), 1.0, "an Online backend is selectable again");
	}

	// F4 `without`: the same frame from a peer that did NOT advertise CONTROL_CAPABILITY is dropped —
	// a backend cannot steer routing for others; the health state never learns "api".
	#[tokio::test]
	async fn non_control_peer_health_is_ignored() {
		let ca = generate_ca();
		let client_leaf = generate_signed_cert(&ca, "device-7", vec![]);
		let (mut client, health_rx) = spawn_health_peer(&ca, &client_leaf, "device-7", ArrayVec::new()).await;
		assert!(matches!(read_next(&mut client).await, Some(TunnelFrame::RegisterAck { .. })), "backend must register");

		protocol::write_frame(&mut client.control, &TunnelFrame::Health { backend_id: ArrayString::from("api").unwrap(), available: false })
			.await
			.unwrap();
		tokio::time::sleep(Duration::from_millis(300)).await;
		assert!(health_rx.borrow().get("api").is_none(), "a non-control peer must not publish health");
	}
}
