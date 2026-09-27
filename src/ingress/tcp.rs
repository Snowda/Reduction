use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arrayvec::ArrayString;
use opentelemetry::metrics::{Counter, Histogram, Meter, UpDownCounter};
use opentelemetry::{KeyValue, global};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::acl::AccessControl;
use crate::balancer::BackendPool;
use crate::circuit::{CircuitBreakers, CircuitState};
use crate::config::{BackendConfig, IngressConfig};
use crate::error::{ReductionError, Result};
use crate::health::HealthState;
use crate::ingress::protocol::{self, Envelope, Peer};
use crate::proxy::pool::ConnPool;
use crate::ratelimit::RateLimit;
use crate::transport::quic::QuicStream;

// TCP ingress runs a single accept loop; the kernel already load-balances accepted connections across
// the per-connection tasks it spawns, so no SO_REUSEPORT fan-out is needed here.
const TCP_WORKER_ID: u16 = 0;
// Fallbacks when a TCP `[[ingress]]` entry omits the TCP-only fields.
pub const DEFAULT_TCP_MAX_CONNECTIONS: u32 = 10_000;
pub const DEFAULT_TCP_IDLE_TIMEOUT_SECS: u64 = 300;

// Why a TCP connection did not reach a backend. Every accepted connection ends as either a relayed
// count or exactly one of these. Shares the label vocabulary with the UDP drop reasons where they
// overlap (acl, rate_limit, no_backend, circuit_open, protocol); TCP adds `capacity` for the
// connection cap and has no oversize/backpressure (those are datagram concepts).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpDropReason {
	Acl,
	RateLimit,
	Capacity,
	NoBackend,
	CircuitOpen,
	Protocol,
}

impl TcpDropReason {
	#[must_use]
	pub const fn as_str(&self) -> &'static str {
		return match self {
			Self::Acl => "acl",
			Self::RateLimit => "rate_limit",
			Self::Capacity => "capacity",
			Self::NoBackend => "no_backend",
			Self::CircuitOpen => "circuit_open",
			Self::Protocol => "protocol",
		};
	}
}

struct TcpInstruments {
	accepted: Counter<u64>,
	relayed: Counter<u64>,
	dropped: Counter<u64>,
	active: UpDownCounter<i64>,
	bytes_relayed: Counter<u64>,
	relay_duration_ms: Histogram<u64>,
}

impl TcpInstruments {
	fn new() -> Self {
		let meter: Meter = global::meter("reduction");
		return Self {
			accepted: meter
				.u64_counter("proxy.ingress.tcp.accepted")
				.with_description("TCP connections accepted by an ingress listener")
				.build(),
			relayed: meter
				.u64_counter("proxy.ingress.tcp.relayed")
				.with_description("TCP connections that completed a relay to a backend")
				.build(),
			dropped: meter
				.u64_counter("proxy.ingress.tcp.dropped")
				.with_description("TCP connections dropped by an ingress listener, by reason")
				.build(),
			active: meter
				.i64_up_down_counter("proxy.ingress.tcp.active")
				.with_description("TCP connections currently relaying")
				.build(),
			bytes_relayed: meter
				.u64_counter("proxy.ingress.tcp.bytes_relayed")
				.with_description("Bytes relayed through TCP ingress connections")
				.build(),
			relay_duration_ms: meter
				.u64_histogram("proxy.ingress.tcp.relay_duration_ms")
				.with_description("Duration of a completed TCP ingress relay")
				.build(),
		};
	}
}

// Per-TCP-ingress accounting. Atomics are the tested source of truth for the invariant
// `accepted == relayed + Σ dropped` (once every connection has settled); each mutator also emits the
// matching OTel signal. Shared (Arc) across the accept loop and every per-connection task.
pub struct TcpIngressCounters {
	accepted: AtomicU64,
	relayed: AtomicU64,
	dropped_acl: AtomicU64,
	dropped_rate_limit: AtomicU64,
	dropped_capacity: AtomicU64,
	dropped_no_backend: AtomicU64,
	dropped_circuit_open: AtomicU64,
	dropped_protocol: AtomicU64,
	instruments: TcpInstruments,
	ingress_attrs: [KeyValue; 1],
}

impl TcpIngressCounters {
	#[must_use]
	pub fn new(ingress_id: &str) -> Self {
		return Self {
			accepted: AtomicU64::new(0),
			relayed: AtomicU64::new(0),
			dropped_acl: AtomicU64::new(0),
			dropped_rate_limit: AtomicU64::new(0),
			dropped_capacity: AtomicU64::new(0),
			dropped_no_backend: AtomicU64::new(0),
			dropped_circuit_open: AtomicU64::new(0),
			dropped_protocol: AtomicU64::new(0),
			instruments: TcpInstruments::new(),
			ingress_attrs: [KeyValue::new("ingress_id", ingress_id.to_owned())],
		};
	}

	pub fn record_accepted(&self) {
		self.accepted.fetch_add(1, Ordering::Relaxed);
		self.instruments.accepted.add(1, &self.ingress_attrs);
	}

	pub fn record_relayed(&self, bytes: u64, duration: Duration) {
		self.relayed.fetch_add(1, Ordering::Relaxed);
		self.instruments.relayed.add(1, &self.ingress_attrs);
		self.instruments.bytes_relayed.add(bytes, &self.ingress_attrs);
		let millis: u64 = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
		self.instruments.relay_duration_ms.record(millis, &self.ingress_attrs);
	}

	pub fn record_drop(&self, reason: TcpDropReason) {
		self.drop_atomic(reason).fetch_add(1, Ordering::Relaxed);
		let attrs: [KeyValue; 2] = [self.ingress_attrs[0].clone(), KeyValue::new("reason", reason.as_str())];
		self.instruments.dropped.add(1, &attrs);
	}

	pub fn active_add(&self, delta: i64) {
		self.instruments.active.add(delta, &self.ingress_attrs);
	}

	const fn drop_atomic(&self, reason: TcpDropReason) -> &AtomicU64 {
		return match reason {
			TcpDropReason::Acl => &self.dropped_acl,
			TcpDropReason::RateLimit => &self.dropped_rate_limit,
			TcpDropReason::Capacity => &self.dropped_capacity,
			TcpDropReason::NoBackend => &self.dropped_no_backend,
			TcpDropReason::CircuitOpen => &self.dropped_circuit_open,
			TcpDropReason::Protocol => &self.dropped_protocol,
		};
	}

	#[must_use]
	pub fn accepted(&self) -> u64 {
		return self.accepted.load(Ordering::Relaxed);
	}

	#[must_use]
	pub fn relayed(&self) -> u64 {
		return self.relayed.load(Ordering::Relaxed);
	}

	#[must_use]
	pub fn dropped(&self, reason: TcpDropReason) -> u64 {
		return self.drop_atomic(reason).load(Ordering::Relaxed);
	}

	#[must_use]
	pub fn total_dropped(&self) -> u64 {
		return self.dropped(TcpDropReason::Acl)
			+ self.dropped(TcpDropReason::RateLimit)
			+ self.dropped(TcpDropReason::Capacity)
			+ self.dropped(TcpDropReason::NoBackend)
			+ self.dropped(TcpDropReason::CircuitOpen)
			+ self.dropped(TcpDropReason::Protocol);
	}
}

// Admission for a TCP connection: ACL then per-IP rate limit (cheapest first). No size cap — TCP is a
// byte stream, not datagrams. Returns the drop reason so the caller counts by reason.
fn admit(acl: &AccessControl, rate_limiter: &RateLimit, peer: IpAddr) -> std::result::Result<(), TcpDropReason> {
	if acl.check(peer).is_err() {
		return Err(TcpDropReason::Acl);
	}
	if rate_limiter.check(peer).is_err() {
		return Err(TcpDropReason::RateLimit);
	}
	return Ok(());
}

// Open the backend stream and announce the peer: dial a raw QUIC stream, then write preamble + Hello +
// Open{peer}. The backend relays the raw bytes that follow. A dial or write failure is a backend
// failure the circuit breaker must see.
async fn open_backend_stream(
	backend: &BackendConfig,
	peer: SocketAddr,
	ingress_id: ArrayString<64>,
	conn_pool: &ConnPool,
	client_tls_config: &Arc<rustls::ClientConfig>,
	connect_timeout: Duration,
) -> Result<QuicStream> {
	let mut stream: QuicStream = conn_pool
		.acquire_raw_stream(backend, client_tls_config, connect_timeout)
		.await?;
	protocol::write_preamble(&mut stream).await?;
	protocol::write_frame(
		&mut stream,
		&Envelope::Hello {
			ingress_id,
			worker: TCP_WORKER_ID,
		},
	)
	.await?;
	protocol::write_frame(
		&mut stream,
		&Envelope::Open {
			peer: Peer::from_socket_addr(peer),
		},
	)
	.await?;
	return Ok(stream);
}

// Immutable per-connection context, so the accept loop hands one cheap-to-clone bundle to each task.
#[derive(Clone)]
pub struct TcpConnContext {
	pub pool: BackendPool,
	pub health_rx: watch::Receiver<HealthState>,
	pub conn_pool: Arc<ConnPool>,
	pub client_tls_config: Arc<rustls::ClientConfig>,
	pub circuit: Arc<CircuitBreakers>,
	pub counters: Arc<TcpIngressCounters>,
	pub ingress_id: ArrayString<64>,
	pub connect_timeout: Duration,
	pub idle_timeout: Duration,
}

// Relay one accepted TCP connection to a rendezvous-selected backend over a raw QUIC stream. Never
// bubbles an error — every exit is a relayed count or a reasoned drop. `client` is generic so tests
// can drive it with an in-memory or loopback stream; production passes a TcpStream.
// cognitive_complexity here is the linear select/dial/relay gate sequence plus its per-outcome log
// macros, not branching logic — the sub-steps are already helpers (open_backend_stream, admit).
#[allow(clippy::cognitive_complexity)]
async fn handle_connection<S>(client: S, peer: SocketAddr, ctx: TcpConnContext, shutdown: CancellationToken)
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	let peer_ip: IpAddr = peer.ip();

	// Selection borrows the local pool (which outlives this fn), so &backend is safe across the awaits
	// below; the health Ref is scoped to the block and never crosses an await.
	let backend: &BackendConfig = {
		let health: watch::Ref<'_, HealthState> = ctx.health_rx.borrow();
		match ctx.pool.select(peer_ip, &health) {
			Some(backend) => backend,
			None => {
				ctx.counters.record_drop(TcpDropReason::NoBackend);
				return;
			}
		}
	};

	// Circuit gate: an open breaker turns the connection away without a dial. The half-open guard is
	// held for the relay's lifetime so only one probe connection is admitted while the circuit recovers.
	let (circuit_state, _half_open_guard) = ctx.circuit.check(backend.id.as_str());
	if circuit_state == CircuitState::Open {
		ctx.counters.record_drop(TcpDropReason::CircuitOpen);
		return;
	}

	let backend_stream: QuicStream = match open_backend_stream(
		backend,
		peer,
		ctx.ingress_id,
		&ctx.conn_pool,
		&ctx.client_tls_config,
		ctx.connect_timeout,
	)
	.await
	{
		Ok(stream) => stream,
		Err(e) => {
			warn!(backend = %backend.id, %peer, error = %e, "tcp ingress backend dial/open failed");
			ctx.circuit.record_failure(backend.id.as_str());
			ctx.counters.record_drop(TcpDropReason::Protocol);
			return;
		}
	};

	ctx.counters.active_add(1);
	let result = relay_bidirectional_result(client, backend_stream, ctx.idle_timeout, shutdown).await;
	ctx.counters.active_add(-1);

	match result {
		Ok((bytes, duration)) => {
			ctx.circuit.record_success(backend.id.as_str());
			ctx.counters.record_relayed(bytes, duration);
			debug!(backend = %backend.id, %peer, bytes, "tcp ingress relay completed");
		}
		Err(e) => {
			warn!(backend = %backend.id, %peer, error = %e, "tcp ingress relay error");
			ctx.circuit.record_failure(backend.id.as_str());
			ctx.counters.record_drop(TcpDropReason::Protocol);
		}
	}
}

// Thin adapter over relay_bidirectional returning just the byte total and duration this module needs.
// copy_bidirectional inside it applies true backpressure: when the QUIC write stalls, the TCP read
// side stops, so nothing is dropped on this path.
async fn relay_bidirectional_result<S>(
	client: S,
	backend_stream: QuicStream,
	idle_timeout: Duration,
	shutdown: CancellationToken,
) -> Result<(u64, Duration)>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	let stats = crate::proxy::relay::relay_bidirectional(client, backend_stream, idle_timeout, shutdown).await?;
	let total: u64 = stats.bytes_a_to_b.saturating_add(stats.bytes_b_to_a);
	return Ok((total, stats.duration));
}

async fn run_accept_loop(
	listener: TcpListener,
	acl: AccessControl,
	rate_limiter: RateLimit,
	permits: Arc<Semaphore>,
	ctx: TcpConnContext,
	shutdown: CancellationToken,
) {
	debug!(ingress = %ctx.ingress_id, "tcp ingress accept loop running");
	loop {
		tokio::select! {
			_ = shutdown.cancelled() => return,
			accept = listener.accept() => {
				match accept {
					Ok((stream, peer)) => {
						ctx.counters.record_accepted();
						if let Err(reason) = admit(&acl, &rate_limiter, peer.ip()) {
							ctx.counters.record_drop(reason);
							// Dropping `stream` here closes the connection with nothing relayed.
							continue;
						}
						let permit: OwnedSemaphorePermit = match Arc::clone(&permits).try_acquire_owned() {
							Ok(permit) => permit,
							Err(_) => {
								ctx.counters.record_drop(TcpDropReason::Capacity);
								continue;
							}
						};
						let conn_ctx: TcpConnContext = ctx.clone();
						let conn_shutdown: CancellationToken = shutdown.clone();
						tokio::spawn(async move {
							let _permit: OwnedSemaphorePermit = permit;
							handle_connection(stream, peer, conn_ctx, conn_shutdown).await;
						});
					}
					// An accept error must never kill the loop; log and keep serving.
					Err(e) => warn!(error = %e, "tcp ingress accept failed"),
				}
			}
		}
	}
}

// Parameters for standing up one TCP ingress listener.
pub struct TcpIngressParams {
	pub config: IngressConfig,
	pub backends: Vec<BackendConfig>,
	pub acl: AccessControl,
	pub requests_per_second: u32,
	pub conn_pool: Arc<ConnPool>,
	pub client_tls_config: Arc<rustls::ClientConfig>,
	pub health_rx: watch::Receiver<HealthState>,
	pub circuit: Arc<CircuitBreakers>,
	pub connect_timeout: Duration,
	pub max_backends: u32,
	pub shutdown: CancellationToken,
}

// Bind the TCP listen socket and spawn the accept loop. Returns the shared counters so a supervisor
// can read the accounting. Binding is awaited here so a bind failure surfaces to the caller rather
// than only into a detached task's log.
pub async fn spawn_tcp_ingress(params: TcpIngressParams) -> Result<Arc<TcpIngressCounters>> {
	let listener: TcpListener = TcpListener::bind(params.config.listen)
		.await
		.map_err(|e| ReductionError::Ingress(format!("bind tcp {}: {e}", params.config.listen)))?;
	let counters: Arc<TcpIngressCounters> = Arc::new(TcpIngressCounters::new(params.config.id.as_str()));
	let pool: BackendPool = BackendPool::with_max(params.backends, params.max_backends)?;
	let max_connections: u32 = params.config.max_connections.unwrap_or(DEFAULT_TCP_MAX_CONNECTIONS);
	let permits: Arc<Semaphore> = Arc::new(Semaphore::new(usize::try_from(max_connections).unwrap_or(usize::MAX)));
	let idle_timeout: Duration =
		Duration::from_secs(params.config.idle_timeout_secs.unwrap_or(DEFAULT_TCP_IDLE_TIMEOUT_SECS));

	let ctx: TcpConnContext = TcpConnContext {
		pool,
		health_rx: params.health_rx,
		conn_pool: params.conn_pool,
		client_tls_config: params.client_tls_config,
		circuit: params.circuit,
		counters: Arc::clone(&counters),
		ingress_id: params.config.id,
		connect_timeout: params.connect_timeout,
		idle_timeout,
	};

	info!(
		ingress = %params.config.id,
		listen = %params.config.listen,
		max_connections,
		"tcp ingress listener started"
	);
	tokio::spawn(run_accept_loop(
		listener,
		params.acl,
		RateLimit::new(params.requests_per_second)?,
		permits,
		ctx,
		params.shutdown,
	));
	return Ok(counters);
}

#[cfg(test)]
mod tests {
	use ipnet::IpNet;
	use tokio::net::TcpStream;

	use super::*;
	use crate::config::{CircuitBreakerConfig, IngressProtocol, TransportKind};

	fn quic_backend(id: &str) -> BackendConfig {
		return BackendConfig::new(id, "127.0.0.1:9000".parse().unwrap(), 1.0, TransportKind::Quic).unwrap();
	}

	fn empty_client_config() -> Arc<rustls::ClientConfig> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		return Arc::new(
			rustls::ClientConfig::builder()
				.with_root_certificates(rustls::RootCertStore::empty())
				.with_no_client_auth(),
		);
	}

	fn breakers() -> Arc<CircuitBreakers> {
		return Arc::new(CircuitBreakers::new(&CircuitBreakerConfig::default()));
	}

	fn ctx_for(
		counters: Arc<TcpIngressCounters>,
		circuit: Arc<CircuitBreakers>,
		backends: Vec<BackendConfig>,
	) -> TcpConnContext {
		let (_health_tx, health_rx): (watch::Sender<HealthState>, watch::Receiver<HealthState>) =
			watch::channel(HealthState::new());
		return TcpConnContext {
			pool: BackendPool::with_max(backends, 64).unwrap(),
			health_rx,
			conn_pool: Arc::new(ConnPool::new()),
			client_tls_config: empty_client_config(),
			circuit,
			counters,
			ingress_id: ArrayString::from("site-tcp").unwrap(),
			connect_timeout: Duration::from_millis(50),
			idle_timeout: Duration::from_secs(1),
		};
	}

	#[test]
	fn test_tcp_drop_reason_labels_are_stable() {
		assert_eq!(TcpDropReason::Acl.as_str(), "acl");
		assert_eq!(TcpDropReason::RateLimit.as_str(), "rate_limit");
		assert_eq!(TcpDropReason::Capacity.as_str(), "capacity");
		assert_eq!(TcpDropReason::NoBackend.as_str(), "no_backend");
		assert_eq!(TcpDropReason::CircuitOpen.as_str(), "circuit_open");
		assert_eq!(TcpDropReason::Protocol.as_str(), "protocol");
	}

	#[test]
	fn test_counters_accounting_closes() {
		let counters: TcpIngressCounters = TcpIngressCounters::new("site-tcp");
		for _ in 0..6 {
			counters.record_accepted();
		}
		counters.record_relayed(1024, Duration::from_millis(5));
		counters.record_relayed(2048, Duration::from_millis(9));
		counters.record_drop(TcpDropReason::Acl);
		counters.record_drop(TcpDropReason::Capacity);
		counters.active_add(1);
		counters.active_add(-1);
		assert_eq!(counters.accepted(), 6);
		assert_eq!(counters.relayed(), 2);
		assert_eq!(counters.total_dropped(), 2);
		assert_eq!(
			counters.accepted(),
			counters.relayed() + counters.total_dropped() + 2,
			"two accepted connections are still in flight (accounting closes once they settle)"
		);
	}

	#[test]
	fn test_admit_denies_acl_before_rate_limit() {
		let acl: AccessControl = AccessControl::new(vec!["10.0.0.0/8".parse::<IpNet>().unwrap()], vec![]);
		let rate_limiter: RateLimit = RateLimit::new(1000).unwrap();
		assert_eq!(
			admit(&acl, &rate_limiter, "192.168.1.1".parse().unwrap()),
			Err(TcpDropReason::Acl)
		);
	}

	#[test]
	fn test_admit_rate_limits_after_acl_passes() {
		let acl: AccessControl = AccessControl::new(vec![], vec![]);
		let rate_limiter: RateLimit = RateLimit::new(1).unwrap();
		let ip: IpAddr = "10.0.0.5".parse().unwrap();
		assert_eq!(admit(&acl, &rate_limiter, ip), Ok(()));
		assert_eq!(admit(&acl, &rate_limiter, ip), Err(TcpDropReason::RateLimit));
	}

	#[tokio::test]
	async fn test_handle_connection_no_backend_when_pool_empty() {
		let counters: Arc<TcpIngressCounters> = Arc::new(TcpIngressCounters::new("site-tcp"));
		let ctx: TcpConnContext = ctx_for(Arc::clone(&counters), breakers(), vec![]);
		let (client, _server): (TcpStream, TcpStream) = connected_pair().await;
		handle_connection(client, "10.0.0.9:5000".parse().unwrap(), ctx, CancellationToken::new()).await;
		assert_eq!(
			counters.dropped(TcpDropReason::NoBackend),
			1,
			"an empty pool is a counted no_backend drop"
		);
	}

	#[tokio::test]
	async fn test_handle_connection_sheds_when_circuit_open() {
		let counters: Arc<TcpIngressCounters> = Arc::new(TcpIngressCounters::new("site-tcp"));
		let circuit: Arc<CircuitBreakers> = breakers();
		for _ in 0..5 {
			circuit.record_failure("ingest");
		}
		assert_eq!(circuit.state("ingest"), CircuitState::Open);
		let ctx: TcpConnContext = ctx_for(Arc::clone(&counters), circuit, vec![quic_backend("ingest")]);
		let (client, _server): (TcpStream, TcpStream) = connected_pair().await;
		handle_connection(client, "10.0.0.9:5000".parse().unwrap(), ctx, CancellationToken::new()).await;
		assert_eq!(
			counters.dropped(TcpDropReason::CircuitOpen),
			1,
			"an open circuit sheds without dialing"
		);
	}

	#[tokio::test]
	async fn test_handle_connection_dial_failure_counts_protocol() {
		// The backend points at an unreachable QUIC address; the dial fails and the connection is a
		// counted protocol drop, and the circuit breaker sees the failure.
		let counters: Arc<TcpIngressCounters> = Arc::new(TcpIngressCounters::new("site-tcp"));
		let circuit: Arc<CircuitBreakers> = breakers();
		let backend: BackendConfig =
			BackendConfig::new("ingest", "127.0.0.1:1".parse().unwrap(), 1.0, TransportKind::Quic)
				.unwrap()
				.with_host("localhost".to_owned());
		let ctx: TcpConnContext = ctx_for(Arc::clone(&counters), Arc::clone(&circuit), vec![backend]);
		let (client, _server): (TcpStream, TcpStream) = connected_pair().await;
		tokio::time::timeout(
			Duration::from_secs(5),
			handle_connection(client, "10.0.0.9:5000".parse().unwrap(), ctx, CancellationToken::new()),
		)
		.await
		.expect("handle_connection must not hang on a dead backend");
		assert_eq!(
			counters.dropped(TcpDropReason::Protocol),
			1,
			"a failed dial is a protocol drop"
		);
		assert_eq!(counters.relayed(), 0);
	}

	#[tokio::test]
	async fn test_spawn_tcp_ingress_binds_and_returns_counters() {
		let params: TcpIngressParams = make_params("127.0.0.1:0".parse().unwrap()).await;
		let shutdown: CancellationToken = params.shutdown.clone();
		let counters: Arc<TcpIngressCounters> = spawn_tcp_ingress(params).await.expect("bind on an ephemeral port");
		assert_eq!(
			counters.accepted(),
			0,
			"a freshly spawned tcp ingress has accepted nothing"
		);
		shutdown.cancel();
	}

	#[tokio::test]
	async fn test_spawn_tcp_ingress_rejects_unbindable_address() {
		let held: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let taken: SocketAddr = held.local_addr().unwrap();
		let mut params: TcpIngressParams = make_params(taken).await;
		params.config.listen = taken;
		assert!(
			spawn_tcp_ingress(params).await.is_err(),
			"an unbindable listen address must return Err"
		);
	}

	#[tokio::test]
	async fn test_accept_loop_drops_acl_denied_connection() {
		// Deny-all ACL: an accepted connection is counted then dropped as acl, never relayed.
		let counters: Arc<TcpIngressCounters> = Arc::new(TcpIngressCounters::new("site-tcp"));
		let ctx: TcpConnContext = ctx_for(Arc::clone(&counters), breakers(), vec![quic_backend("ingest")]);
		let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let addr: SocketAddr = listener.local_addr().unwrap();
		let shutdown: CancellationToken = CancellationToken::new();
		let acl: AccessControl = AccessControl::new(vec![], vec!["127.0.0.0/8".parse::<IpNet>().unwrap()]);
		let handle = tokio::spawn(run_accept_loop(
			listener,
			acl,
			RateLimit::new(1000).unwrap(),
			Arc::new(Semaphore::new(16)),
			ctx,
			shutdown.clone(),
		));

		let _client: TcpStream = TcpStream::connect(addr).await.unwrap();
		// Wait for the accept loop to process it.
		let mut waited: u64 = 0;
		while counters.dropped(TcpDropReason::Acl) == 0 && waited < 2000 {
			tokio::time::sleep(Duration::from_millis(20)).await;
			waited += 20;
		}
		assert_eq!(counters.accepted(), 1, "the connection must be counted as accepted");
		assert_eq!(
			counters.dropped(TcpDropReason::Acl),
			1,
			"a denied peer must be an acl drop"
		);
		shutdown.cancel();
		let _ = handle.await;
	}

	// A connected loopback TcpStream pair (client, server) for driving handle_connection with a real
	// AsyncRead+AsyncWrite stream.
	async fn connected_pair() -> (TcpStream, TcpStream) {
		let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let addr: SocketAddr = listener.local_addr().unwrap();
		let connect = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
		let (server, _peer) = listener.accept().await.unwrap();
		let client: TcpStream = connect.await.unwrap();
		return (client, server);
	}

	fn ingress_config(listen: SocketAddr) -> IngressConfig {
		return IngressConfig {
			id: ArrayString::from("site-tcp").unwrap(),
			protocol: IngressProtocol::Tcp,
			listen,
			workers: 0,
			recv_buffer_bytes: 8 * 1024 * 1024,
			max_datagram_bytes: 8192,
			backend_ids: vec![ArrayString::from("ingest").unwrap()],
			batch_max_datagrams: 512,
			batch_max_bytes: 61440,
			linger_ms: 20,
			queue_depth_per_backend: 4096,
			max_connections: Some(10_000),
			idle_timeout_secs: Some(300),
		};
	}

	async fn make_params(listen: SocketAddr) -> TcpIngressParams {
		let (_health_tx, health_rx): (watch::Sender<HealthState>, watch::Receiver<HealthState>) =
			watch::channel(HealthState::new());
		return TcpIngressParams {
			config: ingress_config(listen),
			backends: vec![quic_backend("ingest")],
			acl: AccessControl::new(vec![], vec![]),
			requests_per_second: 1000,
			conn_pool: Arc::new(ConnPool::new()),
			client_tls_config: empty_client_config(),
			health_rx,
			circuit: breakers(),
			connect_timeout: Duration::from_millis(50),
			max_backends: 64,
			shutdown: CancellationToken::new(),
		};
	}
}
