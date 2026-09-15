use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arrayvec::ArrayString;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::acl::AccessControl;
use crate::balancer::BackendPool;
use crate::circuit::CircuitBreakers;
use crate::config::{BackendConfig, IngressConfig, ReductionConfig, RetryConfig};
use crate::error::{ReductionError, Result};
use crate::health::HealthState;
use crate::ingress::batch::{Batch, BatchLimits};
use crate::ingress::protocol::{Datagram, Peer};
use crate::proxy::pool::ConnPool;
use crate::ratelimit::RateLimit;

// Metrics accounting and the per-backend QUIC writer live in submodules; re-exported for a stable path.
mod metrics;
mod writer;
#[cfg(test)]
mod testutil;

pub use metrics::{DropReason, IngressCounters};
use writer::BackendWriter;

// Largest possible UDP payload (65 535 − 8 UDP header − 20 IP header). The recv buffer is sized to
// this and reused across every datagram, so the recv syscall never allocates. Matches
// config::MAX_UDP_DATAGRAM_BYTES.
const RECV_BUF_LEN: usize = 65_507;

// Why a datagram did not reach a backend. Every datagram entering the recv loop leaves as either a
// relayed count or exactly one of these — never a silent drop. Variants are the Phase 2 metric label
// set (attribute `reason` on `proxy.ingress.dropped`).
// compares before any copy, so an oversize datagram is never truncated into a batch.
fn admit(
	acl: &AccessControl,
	rate_limiter: &RateLimit,
	peer: std::net::IpAddr,
	payload_len: usize,
	max_datagram_bytes: u32,
) -> std::result::Result<(), DropReason> {
	if acl.check(peer).is_err() {
		return Err(DropReason::Acl);
	}
	if rate_limiter.check(peer).is_err() {
		return Err(DropReason::RateLimit);
	}
	if payload_len > usize::try_from(max_datagram_bytes).unwrap_or(usize::MAX) {
		return Err(DropReason::Oversize);
	}
	return Ok(());
}

// Hand a completed batch to its backend writer without ever blocking the recv loop. A successful
// enqueue bumps the backend's queue-depth gauge; a full queue is a counted backpressure drop of the
// whole batch (the queue is bounded and never grows); a closed queue means the writer task is gone,
// counted as no_backend.
fn enqueue_batch(
	sender: &mpsc::Sender<Vec<Datagram>>,
	backend_id: &str,
	datagrams: Vec<Datagram>,
	counters: &IngressCounters,
) {
	if datagrams.is_empty() {
		return;
	}
	let count: u64 = u64::try_from(datagrams.len()).unwrap_or(u64::MAX);
	match sender.try_send(datagrams) {
		Ok(()) => counters.queue_depth_add(backend_id, 1),
		Err(TrySendError::Full(_)) => counters.record_drop(DropReason::Backpressure, count),
		Err(TrySendError::Closed(_)) => counters.record_drop(DropReason::NoBackend, count),
	}
}

// Ingress receive time in unix nanoseconds, saturating rather than failing if the clock is before the
// epoch — a timestamp is advisory metadata for the consumer, never a reason to drop a datagram.
fn now_unix_nanos() -> u64 {
	return match SystemTime::now().duration_since(UNIX_EPOCH) {
		Ok(elapsed) => u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX),
		Err(_) => 0,
	};
}

// Mutable per-backend writer state, kept in the run loop rather than the struct so the writer itself
// is immutable config.
// network write happens off this path in the backend writers, so the loop never awaits the wire.
struct UdpIngress {
	socket: UdpSocket,
	acl: AccessControl,
	rate_limiter: RateLimit,
	pool: BackendPool,
	health_rx: watch::Receiver<HealthState>,
	limits: BatchLimits,
	max_datagram_bytes: u32,
	batches: HashMap<ArrayString<256>, Batch>,
	senders: HashMap<ArrayString<256>, mpsc::Sender<Vec<Datagram>>>,
	counters: Arc<IngressCounters>,
	shutdown: CancellationToken,
	worker_id: u16,
	config_rx: watch::Receiver<ReductionConfig>,
	config_closed: bool,
	ingress_id: ArrayString<64>,
	// Structural fields whose change needs a restart; compared on reload to log a clear warning.
	restart_listen: SocketAddr,
	restart_backend_ids: Vec<ArrayString<256>>,
	restart_queue_depth: u32,
	restart_workers: u32,
}

impl UdpIngress {
	async fn run(mut self) {
		let mut buf: Vec<u8> = vec![0u8; RECV_BUF_LEN];
		let mut linger_timer: tokio::time::Interval = tokio::time::interval(self.limits.linger);
		linger_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
		debug!(ingress = %self.ingress_id, worker = self.worker_id, "ingress worker running");
		loop {
			tokio::select! {
				_ = self.shutdown.cancelled() => {
					self.flush_all();
					return;
				}
				_ = linger_timer.tick() => {
					self.flush_expired(Instant::now());
				}
				changed = self.config_rx.changed(), if !self.config_closed => {
					match changed {
						Ok(()) => {
							let cfg: ReductionConfig = self.config_rx.borrow_and_update().clone();
							if self.apply_reload(&cfg) {
								linger_timer = tokio::time::interval(self.limits.linger);
								linger_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
							}
						}
						// The config sender is gone; stop watching but keep serving on the last config.
						Err(_) => self.config_closed = true,
					}
				}
				result = self.socket.recv_from(&mut buf) => {
					match result {
						Ok((len, src)) => self.handle_datagram(&buf[..len], src),
						// A recv error must never kill the loop; log and keep serving.
						Err(e) => warn!(error = %e, "ingress recv_from failed"),
					}
				}
			}
		}
	}

	// Apply a config reload. Batch/linger/size tunables take effect immediately; structural changes
	// (listen, backend set, queue depth, worker count) are logged as needing a restart and otherwise
	// left in force. Returns whether the linger interval changed so the caller can rearm its timer.
	fn apply_reload(&mut self, cfg: &ReductionConfig) -> bool {
		let Some(entry) = cfg.ingress.iter().find(|i| i.id == self.ingress_id) else {
			warn!(ingress = %self.ingress_id, "ingress entry removed on reload; removing a listener requires a restart");
			return false;
		};
		if entry.listen != self.restart_listen
			|| entry.backend_ids != self.restart_backend_ids
			|| entry.queue_depth_per_backend != self.restart_queue_depth
			|| entry.workers != self.restart_workers
		{
			warn!(
				ingress = %self.ingress_id,
				"ingress listen/backend_ids/queue_depth/workers changed; that change needs a restart and was not applied live",
			);
		}
		let new_linger: Duration = Duration::from_millis(entry.linger_ms);
		let linger_changed: bool = self.limits.linger != new_linger;
		self.limits.max_datagrams = entry.batch_max_datagrams;
		self.limits.max_bytes = entry.batch_max_bytes;
		self.limits.linger = new_linger;
		self.max_datagram_bytes = entry.max_datagram_bytes;
		info!(ingress = %self.ingress_id, worker = self.worker_id, "ingress batch/linger tunables hot-reloaded");
		return linger_changed;
	}

	fn handle_datagram(&mut self, payload: &[u8], src: SocketAddr) {
		self.counters.record_received();
		let peer_ip: std::net::IpAddr = src.ip();
		if let Err(reason) = admit(
			&self.acl,
			&self.rate_limiter,
			peer_ip,
			payload.len(),
			self.max_datagram_bytes,
		) {
			self.counters.record_drop(reason, 1);
			return;
		}

		let backend_id: ArrayString<256> = {
			let health: watch::Ref<'_, HealthState> = self.health_rx.borrow();
			match self.pool.select(peer_ip, &health) {
				Some(backend) => backend.id,
				None => {
					self.counters.record_drop(DropReason::NoBackend, 1);
					return;
				}
			}
		};

		let datagram: Datagram = Datagram {
			peer: Peer::from_socket_addr(src),
			recv_at_unix_nanos: now_unix_nanos(),
			payload: payload.to_vec(),
		};

		let now: Instant = Instant::now();
		let batch: &mut Batch = self.batches.entry(backend_id).or_default();
		batch.push(now, datagram);
		if let Some(reason) = batch.fill_flush(&self.limits) {
			debug!(backend = %backend_id, ?reason, "ingress batch full, flushing");
			self.flush_backend(&backend_id);
		}
	}

	// Flush every batch whose linger deadline has passed.
	fn flush_expired(&mut self, now: Instant) {
		let due: Vec<ArrayString<256>> = self
			.batches
			.iter()
			.filter(|(_, batch)| batch.linger_expired(&self.limits, now))
			.map(|(id, _)| *id)
			.collect();
		for id in &due {
			self.flush_backend(id);
		}
	}

	// Flush every non-empty batch regardless of trigger — used on shutdown so buffered datagrams get
	// one last hand-off to their writers.
	fn flush_all(&mut self) {
		let ids: Vec<ArrayString<256>> = self.batches.keys().copied().collect();
		for id in &ids {
			self.flush_backend(id);
		}
	}

	fn flush_backend(&mut self, backend_id: &ArrayString<256>) {
		let Some(batch) = self.batches.get_mut(backend_id) else {
			return;
		};
		if batch.is_empty() {
			return;
		}
		let datagrams: Vec<Datagram> = batch.take();
		match self.senders.get(backend_id) {
			Some(sender) => enqueue_batch(sender, backend_id.as_str(), datagrams, &self.counters),
			None => {
				// No writer for this backend id (should not happen — senders mirror the pool). Count the
				// whole batch as no_backend rather than silently discarding it.
				let count: u64 = u64::try_from(datagrams.len()).unwrap_or(u64::MAX);
				self.counters.record_drop(DropReason::NoBackend, count);
			}
		}
	}
}

// Parameters for standing up one UDP ingress listener. Grouped into a struct so `spawn_udp_ingress`
// stays under the argument-count lint and the caller assembles named fields.
pub struct UdpIngressParams {
	pub config: IngressConfig,
	// The subset of `[[backends]]` this ingress fans out to — validated at config load to all be
	// transport = quic.
	pub backends: Vec<BackendConfig>,
	pub acl: AccessControl,
	pub requests_per_second: u32,
	pub conn_pool: Arc<ConnPool>,
	pub client_tls_config: Arc<rustls::ClientConfig>,
	pub health_rx: watch::Receiver<HealthState>,
	pub config_rx: watch::Receiver<ReductionConfig>,
	pub circuit: Arc<CircuitBreakers>,
	pub retry: RetryConfig,
	pub connect_timeout: Duration,
	pub max_backends: u32,
	pub shutdown: CancellationToken,
}

// One worker per CPU when configured 0 (Linux SO_REUSEPORT fan-out); otherwise the configured count.
// On non-Linux the fan-out is unavailable, so a single worker runs — a shared socket across tasks
// would interleave a peer's datagrams and break the per-peer ordering the design guarantees.
// Not const: the Linux path calls available_parallelism(); only the non-Linux stub is const-eligible.
#[allow(clippy::missing_const_for_fn)]
fn resolve_worker_count(configured: u32) -> usize {
	#[cfg(target_os = "linux")]
	{
		let count: usize = if configured == 0 {
			std::thread::available_parallelism().map(|p| p.get()).unwrap_or(1)
		} else {
			usize::try_from(configured).unwrap_or(1)
		};
		return count.max(1);
	}
	#[cfg(not(target_os = "linux"))]
	{
		let _ = configured;
		return 1;
	}
}

// Bind one UDP socket for a worker. On Linux/BSD SO_REUSEPORT lets every worker bind the same port
// and the kernel flow-hashes datagrams to exactly one worker per peer 4-tuple — preserving per-peer
// ordering while spreading load. SO_RCVBUF is sized best-effort (the OS may clamp).
fn bind_worker_socket(addr: SocketAddr, recv_buffer_bytes: u32) -> Result<UdpSocket> {
	use socket2::{Domain, Protocol, Socket, Type};

	let domain: Domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
	let socket: Socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
		.map_err(|e| ReductionError::Ingress(format!("create udp socket: {e}")))?;
	// SO_REUSEPORT exists on Linux/BSD, not on Windows; the non-Linux path binds a single worker so
	// address sharing is never needed there.
	#[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
	socket
		.set_reuse_port(true)
		.map_err(|e| ReductionError::Ingress(format!("set SO_REUSEPORT: {e}")))?;
	if recv_buffer_bytes > 0 {
		let _ = socket.set_recv_buffer_size(usize::try_from(recv_buffer_bytes).unwrap_or(usize::MAX));
	}
	socket
		.set_nonblocking(true)
		.map_err(|e| ReductionError::Ingress(format!("set nonblocking: {e}")))?;
	socket
		.bind(&addr.into())
		.map_err(|e| ReductionError::Ingress(format!("bind udp {addr}: {e}")))?;
	let std_socket: std::net::UdpSocket = socket.into();
	return UdpSocket::from_std(std_socket).map_err(|e| ReductionError::Ingress(format!("udp from_std: {e}")));
}

// Bind the worker sockets, spawn one writer task per backend per worker, and spawn each recv-loop
// worker. Returns the shared counters so a supervisor can read the accounting. Binding is done here so
// a bind failure surfaces to the caller rather than only into a detached task's log.
pub fn spawn_udp_ingress(params: &UdpIngressParams) -> Result<Arc<IngressCounters>> {
	let counters: Arc<IngressCounters> = Arc::new(IngressCounters::new(params.config.id.as_str()));
	let pool: BackendPool = BackendPool::with_max(params.backends.clone(), params.max_backends)?;
	let worker_count: usize = resolve_worker_count(params.config.workers);

	for worker_index in 0..worker_count {
		let socket: UdpSocket = bind_worker_socket(params.config.listen, params.config.recv_buffer_bytes)?;
		let worker_id: u16 = u16::try_from(worker_index).unwrap_or(u16::MAX);
		spawn_worker(params, &counters, &pool, socket, worker_id)?;
	}

	info!(
		ingress = %params.config.id,
		listen = %params.config.listen,
		workers = worker_count,
		"udp ingress listener started"
	);
	return Ok(counters);
}

// Wire one worker: its own writers (one per backend, each its own QUIC stream), its own recv loop.
// Counters, circuit breaker, and config watch are shared; the rate limiter and batches are per-worker
// (a peer always lands on one worker via SO_REUSEPORT, so per-worker buckets stay consistent).
fn spawn_worker(
	params: &UdpIngressParams,
	counters: &Arc<IngressCounters>,
	pool: &BackendPool,
	socket: UdpSocket,
	worker_id: u16,
) -> Result<()> {
	let queue_depth: usize = usize::try_from(params.config.queue_depth_per_backend).unwrap_or(usize::MAX);
	let mut senders: HashMap<ArrayString<256>, mpsc::Sender<Vec<Datagram>>> = HashMap::new();
	for backend in &params.backends {
		let (tx, rx): (mpsc::Sender<Vec<Datagram>>, mpsc::Receiver<Vec<Datagram>>) = mpsc::channel(queue_depth);
		senders.insert(backend.id, tx);
		let writer: BackendWriter = BackendWriter {
			backend: backend.clone(),
			ingress_id: params.config.id,
			worker: worker_id,
			conn_pool: Arc::clone(&params.conn_pool),
			client_tls_config: Arc::clone(&params.client_tls_config),
			connect_timeout: params.connect_timeout,
			counters: Arc::clone(counters),
			circuit: Arc::clone(&params.circuit),
			retry: params.retry.clone(),
		};
		let writer_shutdown: CancellationToken = params.shutdown.clone();
		tokio::spawn(async move {
			writer.run(rx, writer_shutdown).await;
		});
	}

	let ingress: UdpIngress = UdpIngress {
		socket,
		acl: params.acl.clone(),
		rate_limiter: RateLimit::new(params.requests_per_second)?,
		pool: pool.clone(),
		health_rx: params.health_rx.clone(),
		limits: BatchLimits {
			max_datagrams: params.config.batch_max_datagrams,
			max_bytes: params.config.batch_max_bytes,
			linger: Duration::from_millis(params.config.linger_ms),
		},
		max_datagram_bytes: params.config.max_datagram_bytes,
		batches: HashMap::new(),
		senders,
		counters: Arc::clone(counters),
		shutdown: params.shutdown.clone(),
		worker_id,
		config_rx: params.config_rx.clone(),
		config_closed: false,
		ingress_id: params.config.id,
		restart_listen: params.config.listen,
		restart_backend_ids: params.config.backend_ids.clone(),
		restart_queue_depth: params.config.queue_depth_per_backend,
		restart_workers: params.config.workers,
	};
	tokio::spawn(async move {
		ingress.run().await;
	});
	return Ok(());
}

#[cfg(test)]
mod tests {
	use std::net::IpAddr;

	use ipnet::IpNet;

	use super::testutil::{breakers, datagram, empty_client_config, quic_backend};
	use super::*;
	use crate::config::IngressProtocol;

	#[test]
	fn test_admit_denies_acl_before_rate_limit() {
		let acl: AccessControl = AccessControl::new(vec!["10.0.0.0/8".parse::<IpNet>().unwrap()], vec![]);
		let rate_limiter: RateLimit = RateLimit::new(1000).unwrap();
		let outside: IpAddr = "192.168.1.1".parse().unwrap();
		assert_eq!(admit(&acl, &rate_limiter, outside, 100, 8192), Err(DropReason::Acl));
	}

	#[test]
	fn test_admit_rate_limits_after_acl_passes() {
		let acl: AccessControl = AccessControl::new(vec![], vec![]);
		let rate_limiter: RateLimit = RateLimit::new(1).unwrap();
		let ip: IpAddr = "10.0.0.5".parse().unwrap();
		assert_eq!(admit(&acl, &rate_limiter, ip, 100, 8192), Ok(()));
		assert_eq!(
			admit(&acl, &rate_limiter, ip, 100, 8192),
			Err(DropReason::RateLimit),
			"second datagram in the same second must be rate limited"
		);
	}

	#[test]
	fn test_admit_rejects_oversize_after_acl_and_rate_limit() {
		let acl: AccessControl = AccessControl::new(vec![], vec![]);
		let rate_limiter: RateLimit = RateLimit::new(1000).unwrap();
		let ip: IpAddr = "10.0.0.6".parse().unwrap();
		assert_eq!(admit(&acl, &rate_limiter, ip, 8192, 8192), Ok(()));
		assert_eq!(admit(&acl, &rate_limiter, ip, 8193, 8192), Err(DropReason::Oversize));
	}

	// ── enqueue_batch ──

	#[tokio::test]
	async fn test_enqueue_overflow_is_counted_not_grown() {
		const CAP: usize = 2;
		let (tx, _rx): (mpsc::Sender<Vec<Datagram>>, mpsc::Receiver<Vec<Datagram>>) = mpsc::channel(CAP);
		let counters: IngressCounters = IngressCounters::new("test");

		enqueue_batch(&tx, "b", vec![datagram(b"a")], &counters);
		enqueue_batch(&tx, "b", vec![datagram(b"b")], &counters);
		assert_eq!(tx.capacity(), 0, "queue is full at its cap of two batches");
		assert_eq!(
			counters.dropped(DropReason::Backpressure),
			0,
			"no drops while under cap"
		);

		enqueue_batch(&tx, "b", vec![datagram(b"c")], &counters);
		enqueue_batch(
			&tx,
			"b",
			vec![datagram(b"d"), datagram(b"e"), datagram(b"f")],
			&counters,
		);
		assert_eq!(tx.capacity(), 0, "queue must not grow past its cap under overflow");
		assert_eq!(
			counters.dropped(DropReason::Backpressure),
			4,
			"one + three datagrams overflowed and must all be counted"
		);
	}

	#[tokio::test]
	async fn test_enqueue_closed_queue_counts_no_backend() {
		let (tx, rx): (mpsc::Sender<Vec<Datagram>>, mpsc::Receiver<Vec<Datagram>>) = mpsc::channel(4);
		drop(rx);
		let counters: IngressCounters = IngressCounters::new("test");
		enqueue_batch(&tx, "b", vec![datagram(b"a"), datagram(b"b")], &counters);
		assert_eq!(
			counters.dropped(DropReason::NoBackend),
			2,
			"a dead writer counts as no_backend"
		);
	}

	#[test]
	fn test_enqueue_empty_batch_is_noop() {
		let (tx, _rx): (mpsc::Sender<Vec<Datagram>>, mpsc::Receiver<Vec<Datagram>>) = mpsc::channel(1);
		let counters: IngressCounters = IngressCounters::new("test");
		enqueue_batch(&tx, "b", Vec::new(), &counters);
		assert_eq!(counters.dropped(DropReason::Backpressure), 0);
		assert_eq!(tx.capacity(), 1, "an empty batch must not consume a queue slot");
	}

	#[test]
	fn test_now_unix_nanos_is_after_epoch() {
		assert!(now_unix_nanos() > 0, "a live clock must be well past the unix epoch");
	}

	#[test]
	fn test_resolve_worker_count_is_at_least_one() {
		assert!(resolve_worker_count(0) >= 1);
		assert!(resolve_worker_count(4) >= 1);
	}

	// ── UdpIngress recv-path unit tests ──

	fn base_config_toml() -> String {
		return r#"
[listen]
address = "127.0.0.1:8443"
transport = "quic"

[tls.server.manual]
cert_path = "certs/server.crt"
key_path = "certs/server.key"
ca_cert_path = "certs/ca.crt"

[tls.client]
cert_path = "certs/client.crt"
key_path = "certs/client.key"
ca_cert_path = "certs/ca.crt"

[[backends]]
id = "ingest-a"
address = "10.0.0.5:9000"
weight = 1.0
transport = "quic"

[[routes]]
path_prefix = "/"
backend_id = "ingest-a"

[[ingress]]
id = "site-udp"
protocol = "udp"
listen = "10.20.0.1:5000"
backend_ids = ["ingest-a"]
"#
		.to_owned();
	}

	fn base_config() -> ReductionConfig {
		return toml::from_str(&base_config_toml()).unwrap();
	}

	// Build a worker over a real ephemeral UDP socket with one backend, returning the worker, its
	// backend's queue receiver, the shared counters, and the config sender (kept alive so the reload
	// arm pends rather than erroring). max_datagrams = 1 so a single admitted datagram flushes.
	async fn make_ingress(
		acl: AccessControl,
		rps: u32,
		max_datagram_bytes: u32,
	) -> (
		UdpIngress,
		mpsc::Receiver<Vec<Datagram>>,
		Arc<IngressCounters>,
		watch::Sender<ReductionConfig>,
	) {
		let socket: UdpSocket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		let counters: Arc<IngressCounters> = Arc::new(IngressCounters::new("site-udp"));
		let (_health_tx, health_rx): (watch::Sender<HealthState>, watch::Receiver<HealthState>) =
			watch::channel(HealthState::new());
		let (config_tx, config_rx): (watch::Sender<ReductionConfig>, watch::Receiver<ReductionConfig>) =
			watch::channel(base_config());
		let backend: BackendConfig = quic_backend("ingest-a");
		let (tx, rx): (mpsc::Sender<Vec<Datagram>>, mpsc::Receiver<Vec<Datagram>>) = mpsc::channel(16);
		let mut senders: HashMap<ArrayString<256>, mpsc::Sender<Vec<Datagram>>> = HashMap::new();
		senders.insert(backend.id, tx);
		let pool: BackendPool = BackendPool::with_max(vec![backend], 64).unwrap();
		let ingress: UdpIngress = UdpIngress {
			socket,
			acl,
			rate_limiter: RateLimit::new(rps).unwrap(),
			pool,
			health_rx,
			limits: BatchLimits {
				max_datagrams: 1,
				max_bytes: u32::MAX,
				linger: Duration::from_millis(20),
			},
			max_datagram_bytes,
			batches: HashMap::new(),
			senders,
			counters: Arc::clone(&counters),
			shutdown: CancellationToken::new(),
			worker_id: 0,
			config_rx,
			config_closed: false,
			ingress_id: ArrayString::from("site-udp").unwrap(),
			restart_listen: "10.20.0.1:5000".parse().unwrap(),
			restart_backend_ids: vec![ArrayString::from("ingest-a").unwrap()],
			restart_queue_depth: 4096,
			restart_workers: 0,
		};
		return (ingress, rx, counters, config_tx);
	}

	#[tokio::test]
	async fn test_handle_datagram_batches_admitted_and_preserves_peer_and_payload() {
		let (mut ingress, mut rx, counters, _cfg) = make_ingress(AccessControl::new(vec![], vec![]), 1000, 8192).await;
		let src: SocketAddr = "10.0.0.9:5000".parse().unwrap();
		ingress.handle_datagram(b"hello-ingress", src);

		assert_eq!(counters.received(), 1);
		let batch: Vec<Datagram> = rx
			.try_recv()
			.expect("admitted datagram must be enqueued to its backend");
		assert_eq!(batch.len(), 1);
		assert_eq!(
			batch[0].payload, b"hello-ingress",
			"payload must be preserved byte-for-byte"
		);
		assert_eq!(
			batch[0].peer.socket_addr(),
			src,
			"the original peer address must be preserved"
		);
		assert!(batch[0].recv_at_unix_nanos > 0, "receive time must be stamped");
	}

	#[tokio::test]
	async fn test_handle_datagram_acl_denied_is_counted_not_batched() {
		let acl: AccessControl = AccessControl::new(vec!["10.0.0.0/8".parse::<IpNet>().unwrap()], vec![]);
		let (mut ingress, mut rx, counters, _cfg) = make_ingress(acl, 1000, 8192).await;
		ingress.handle_datagram(b"blocked", "192.168.1.1:5000".parse().unwrap());

		assert_eq!(counters.received(), 1);
		assert_eq!(counters.dropped(DropReason::Acl), 1);
		assert!(
			rx.try_recv().is_err(),
			"a denied datagram must never reach a backend queue"
		);
	}

	#[tokio::test]
	async fn test_handle_datagram_oversize_is_counted_not_truncated() {
		let (mut ingress, mut rx, counters, _cfg) = make_ingress(AccessControl::new(vec![], vec![]), 1000, 4).await;
		ingress.handle_datagram(b"way too big", "10.0.0.9:5000".parse().unwrap());

		assert_eq!(counters.dropped(DropReason::Oversize), 1);
		assert!(
			rx.try_recv().is_err(),
			"an oversize datagram must never be truncated into a batch"
		);
	}

	#[tokio::test]
	async fn test_handle_datagram_no_backend_when_pool_empty() {
		let (mut ingress, _rx, counters, _cfg) = make_ingress(AccessControl::new(vec![], vec![]), 1000, 8192).await;
		// Replace the pool with an empty one and clear senders so selection yields None.
		ingress.pool = BackendPool::with_max(vec![], 64).unwrap();
		ingress.senders.clear();
		ingress.handle_datagram(b"nowhere", "10.0.0.9:5000".parse().unwrap());
		assert_eq!(
			counters.dropped(DropReason::NoBackend),
			1,
			"no eligible backend is a counted drop"
		);
	}

	#[tokio::test]
	async fn test_flush_expired_hands_off_lingering_batch() {
		let (mut ingress, mut rx, _counters, _cfg) = make_ingress(AccessControl::new(vec![], vec![]), 1000, 8192).await;
		ingress.limits.max_datagrams = u32::MAX;
		ingress.handle_datagram(b"waiting", "10.0.0.9:5000".parse().unwrap());
		assert!(
			rx.try_recv().is_err(),
			"batch must still be buffered before linger elapses"
		);

		ingress.flush_expired(Instant::now() + Duration::from_millis(50));
		let batch: Vec<Datagram> = rx
			.try_recv()
			.expect("a lingering batch must flush once its deadline passes");
		assert_eq!(batch[0].payload, b"waiting");
	}

	#[tokio::test]
	async fn test_flush_all_drains_every_buffered_batch() {
		let (mut ingress, mut rx, _counters, _cfg) = make_ingress(AccessControl::new(vec![], vec![]), 1000, 8192).await;
		ingress.limits.max_datagrams = u32::MAX;
		ingress.handle_datagram(b"one", "10.0.0.9:5000".parse().unwrap());
		ingress.flush_all();
		assert!(rx.try_recv().is_ok(), "flush_all must hand off buffered batches");
	}

	#[tokio::test]
	async fn test_apply_reload_updates_tunables_live() {
		let (mut ingress, _rx, _counters, _cfg) = make_ingress(AccessControl::new(vec![], vec![]), 1000, 8192).await;
		let updated_toml: String = base_config_toml().replace(
			"backend_ids = [\"ingest-a\"]",
			"backend_ids = [\"ingest-a\"]\nbatch_max_datagrams = 99\nlinger_ms = 500\nmax_datagram_bytes = 2048",
		);
		let updated: ReductionConfig = toml::from_str(&updated_toml).unwrap();

		let linger_changed: bool = ingress.apply_reload(&updated);
		assert!(linger_changed, "a changed linger must signal a timer rearm");
		assert_eq!(ingress.limits.max_datagrams, 99, "batch cap must reload live");
		assert_eq!(
			ingress.limits.linger,
			Duration::from_millis(500),
			"linger must reload live"
		);
		assert_eq!(ingress.max_datagram_bytes, 2048, "size cap must reload live");
	}

	#[tokio::test]
	async fn test_apply_reload_missing_entry_keeps_serving() {
		let (mut ingress, _rx, _counters, _cfg) = make_ingress(AccessControl::new(vec![], vec![]), 1000, 8192).await;
		let before: u32 = ingress.limits.max_datagrams;
		// A config with no matching ingress id: keep current tunables, no timer rearm.
		let no_ingress_toml: String = base_config_toml().replace("id = \"site-udp\"", "id = \"other-udp\"");
		let updated: ReductionConfig = toml::from_str(&no_ingress_toml).unwrap();
		assert!(
			!ingress.apply_reload(&updated),
			"a missing entry must not signal a rearm"
		);
		assert_eq!(
			ingress.limits.max_datagrams, before,
			"tunables unchanged when the entry is gone"
		);
	}

	#[tokio::test]
	async fn test_run_receives_datagram_and_stops_on_shutdown() {
		let (ingress, mut rx, counters, _cfg) = make_ingress(AccessControl::new(vec![], vec![]), 1000, 8192).await;
		let addr: SocketAddr = ingress.socket.local_addr().unwrap();
		let shutdown: CancellationToken = ingress.shutdown.clone();
		let handle = tokio::spawn(ingress.run());

		let client: UdpSocket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		client.send_to(b"live-datagram", addr).await.unwrap();

		let batch: Vec<Datagram> = tokio::time::timeout(Duration::from_secs(2), rx.recv())
			.await
			.expect("recv loop must deliver within the timeout")
			.expect("batch channel must yield the datagram");
		assert_eq!(batch[0].payload, b"live-datagram");
		assert!(counters.received() >= 1);

		shutdown.cancel();
		tokio::time::timeout(Duration::from_secs(2), handle)
			.await
			.expect("run must return after shutdown")
			.expect("run task must not panic");
	}

	// ── BackendWriter ──

	fn ingress_config(listen: SocketAddr) -> IngressConfig {
		return IngressConfig {
			id: ArrayString::from("site-udp").unwrap(),
			protocol: IngressProtocol::Udp,
			listen,
			workers: 0,
			recv_buffer_bytes: 8 * 1024 * 1024,
			max_datagram_bytes: 8192,
			backend_ids: vec![ArrayString::from("ingest-a").unwrap()],
			batch_max_datagrams: 512,
			batch_max_bytes: 61440,
			linger_ms: 20,
			queue_depth_per_backend: 4096,
			max_connections: None,
			idle_timeout_secs: None,
		};
	}

	fn make_params(listen: SocketAddr, shutdown: CancellationToken) -> UdpIngressParams {
		let (_health_tx, health_rx): (watch::Sender<HealthState>, watch::Receiver<HealthState>) =
			watch::channel(HealthState::new());
		// The config sender is dropped at the end of this helper; the worker's reload arm then simply
		// disables itself (config_closed) and keeps serving on the initial config — fine for these tests.
		let (_config_tx, config_rx): (watch::Sender<ReductionConfig>, watch::Receiver<ReductionConfig>) =
			watch::channel(base_config());
		return UdpIngressParams {
			config: ingress_config(listen),
			backends: vec![quic_backend("ingest-a")],
			acl: AccessControl::new(vec![], vec![]),
			requests_per_second: 1000,
			conn_pool: Arc::new(ConnPool::new()),
			client_tls_config: empty_client_config(),
			health_rx,
			config_rx,
			circuit: breakers(),
			retry: RetryConfig::default(),
			connect_timeout: Duration::from_millis(50),
			max_backends: 64,
			shutdown,
		};
	}

	#[tokio::test]
	async fn test_spawn_udp_ingress_binds_and_returns_counters() {
		let shutdown: CancellationToken = CancellationToken::new();
		let counters: Arc<IngressCounters> =
			spawn_udp_ingress(&make_params("127.0.0.1:0".parse().unwrap(), shutdown.clone()))
				.expect("bind on an ephemeral port");
		assert_eq!(counters.received(), 0, "a freshly spawned ingress has received nothing");
		shutdown.cancel();
	}

	#[tokio::test]
	async fn test_spawn_udp_ingress_rejects_unbindable_address() {
		// Hold a socket on an ephemeral port, then try to spawn an ingress on the same address: the
		// second bind fails, and that error must surface as a returned Err.
		let held: UdpSocket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		let taken: SocketAddr = held.local_addr().unwrap();
		assert!(
			spawn_udp_ingress(&make_params(taken, CancellationToken::new())).is_err(),
			"an unbindable listen address must return Err"
		);
	}

	#[tokio::test]
	async fn test_bind_worker_socket_binds_and_round_trips() {
		// from_std requires a running Tokio reactor, hence the async test.
		let socket: UdpSocket = bind_worker_socket("127.0.0.1:0".parse().unwrap(), 1024 * 1024)
			.expect("binding an ephemeral udp port must succeed");
		assert!(
			socket.local_addr().is_ok(),
			"the bound socket must report a local address"
		);
	}

	// SO_REUSEPORT (Linux/BSD) must let two worker sockets bind the exact same port — the mechanism the
	// multi-worker fan-out relies on. Linux-only: Windows has no SO_REUSEPORT, so the design binds a
	// single worker there.
	#[cfg(target_os = "linux")]
	#[tokio::test]
	async fn test_reuseport_allows_two_binds_on_the_same_port() {
		let addr: SocketAddr = {
			let probe: UdpSocket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
			probe.local_addr().unwrap()
		};
		let first: UdpSocket = bind_worker_socket(addr, 0).expect("first SO_REUSEPORT bind");
		let second: UdpSocket = bind_worker_socket(addr, 0).expect("second SO_REUSEPORT bind on the same port");
		assert_eq!(
			first.local_addr().unwrap(),
			second.local_addr().unwrap(),
			"both workers must share the one listen port",
		);
	}
}
