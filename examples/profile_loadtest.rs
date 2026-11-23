mod support;

#[cfg(not(feature = "dhat-heap"))]
use std::alloc::System;
use std::alloc::{GlobalAlloc, Layout};
use std::future::pending;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use std::{env, fs, io};

use arrayvec::ArrayString;
use http::header::CONTENT_TYPE;
use http::{HeaderValue, Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
use reduction::acl::AccessControl;
use reduction::balancer::BackendPool;
use reduction::body::Body;
use reduction::circuit::CircuitBreakers;
use reduction::config::MainListener;
use reduction::config::{
	self, BackendConfig, CircuitBreakerConfig, MAX_BACKEND_ID_LEN, ProxyConfig, ReductionConfig,
	RetryConfig, TimeoutConfig,
};
use reduction::fast_hash::FastMap;
use reduction::health::HealthState;
use reduction::metrics::ProxyMetrics;
use reduction::proxy::server::{serve, serve_with};
use reduction::proxy::{ConnPool, HttpAuthz, ProxyState, ReloadableState, Router};
use reduction::ratelimit::RateLimit;
use reduction::label_intern::LabelInterner;
use reduction::snapshot_map::SnapshotMap;
use reduction::transport::listener::Listener;
use reduction::tunnel::revocation::RevocationSet;
use reduction::tls;
use rustls::pki_types::ServerName;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, error, info, info_span, warn};
use tracing_chrome::{ChromeLayerBuilder, FlushGuard};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

use crate::support::Context;

// Show only the load-test text and any warnings from the library on stdout.
const LIBRARY_LOG_LEVEL: &str = "warn";
// The chrome trace records library spans at info.
const TRACE_LOG_LEVEL: &str = "info";
const TRACE_FILE: &str = "trace.json";
const PROXY_PORT: u16 = 18443;
const BACKEND_PORT: u16 = 19443;
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const DEFAULT_CONCURRENCY: usize = 10;
const DEFAULT_TOTAL_REQUESTS: usize = 1000;
// Positional arguments: concurrency, total requests, then flags.
const FIRST_FLAG_ARG: usize = 3;
const STARTUP_SETTLE: Duration = Duration::from_millis(500);
const READY_TIMEOUT: Duration = Duration::from_millis(50);
// Same as the library's listener: wait after an accept error, so the loop does not retry at full speed.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_secs(1);
const MILLIS_PER_SEC: f64 = 1000.0;
const PER_MILLE: u64 = 1000;
// Latency percentiles to report, in per-mille so the index math stays in integers.
const PERCENTILES: [(&str, u64); 5] = [
	("p50: ", 500),
	("p95: ", 950),
	("p99: ", 990),
	("p999:", 999),
	("max: ", 1000),
];

// Always-on process-wide allocation counter. This example runs the load driver, the backend, AND the
// proxy in one process, so this counts all three — a whole-system allocs/request figure, not proxy-
// isolated (build with --features dhat-heap for per-call-stack attribution). CountingAlloc is the sole
// #[global_allocator]; its inner allocator is dhat under the dhat-heap feature, so the counter and the
// dhat profiler compose rather than fight over the single global-allocator slot.
static TOTAL_ALLOCS: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "dhat-heap")]
const INNER_ALLOC: dhat::Alloc = dhat::Alloc;
#[cfg(not(feature = "dhat-heap"))]
const INNER_ALLOC: System = System;

struct CountingAlloc;

// GlobalAlloc is an unsafe trait, so a counting allocator cannot exist without this one impl. Per
// AGENTS.md (Safety), the allow covers only this impl.
// SAFETY: every method forwards unchanged to the inner allocator (dhat or System); the only added
// behaviour is a relaxed atomic increment on the allocating calls, which cannot affect memory safety.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for CountingAlloc {
	unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
		TOTAL_ALLOCS.fetch_add(1, Ordering::Relaxed);
		return unsafe { INNER_ALLOC.alloc(layout) };
	}
	unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
		unsafe { INNER_ALLOC.dealloc(ptr, layout) };
	}
	unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
		TOTAL_ALLOCS.fetch_add(1, Ordering::Relaxed);
		return unsafe { INNER_ALLOC.alloc_zeroed(layout) };
	}
	unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
		TOTAL_ALLOCS.fetch_add(1, Ordering::Relaxed);
		return unsafe { INNER_ALLOC.realloc(ptr, layout, new_size) };
	}
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

// Counts here stay far below 2^32, where u32 -> f64 is exact; saturate instead of wrap above that.
fn count_as_f64(n: u64) -> f64 {
	return f64::from(u32::try_from(n).unwrap_or(u32::MAX));
}

fn len_as_u64(n: usize) -> u64 {
	return u64::try_from(n).unwrap_or(u64::MAX);
}

struct LatencyHistogram {
	samples: Vec<f64>,
}

impl LatencyHistogram {
	fn new(capacity: usize) -> Self {
		return Self {
			samples: Vec::with_capacity(capacity),
		};
	}

	fn record(&mut self, ms: f64) {
		self.samples.push(ms);
	}

	// Nearest-rank percentile: index round(per_mille / 1000 * (len - 1)), computed in integers.
	fn percentile(&mut self, per_mille: u64) -> f64 {
		let Some(last) = self.samples.len().checked_sub(1) else {
			return 0.0;
		};
		self.samples.sort_by(f64::total_cmp);
		let rank: u64 = (per_mille * len_as_u64(last) + PER_MILLE / 2) / PER_MILLE;
		let idx: usize = usize::try_from(rank).map_or(last, |i| i.min(last));
		return self.samples[idx];
	}

	fn mean(&self) -> f64 {
		if self.samples.is_empty() {
			return 0.0;
		}
		return self.samples.iter().sum::<f64>() / count_as_f64(len_as_u64(self.samples.len()));
	}
}

// Reusable HTTP/1.1 keep-alive client over mTLS.
struct KeepAliveClient {
	connector: TlsConnector,
	addr: SocketAddr,
	sender: Option<http1::SendRequest<Body>>,
}

impl KeepAliveClient {
	const fn new(connector: TlsConnector, addr: SocketAddr) -> Self {
		return Self {
			connector,
			addr,
			sender: None,
		};
	}

	// A fresh connection, or None when any step of the dial fails (the caller counts that as an error).
	async fn connect(&self) -> Option<http1::SendRequest<Body>> {
		let tcp: TcpStream = TcpStream::connect(self.addr).await.ok()?;
		let server_name: ServerName<'static> = ServerName::IpAddress(self.addr.ip().into());
		let tls = self.connector.connect(server_name, tcp).await.ok()?;
		let (sender, conn) = http1::handshake(TokioIo::new(tls)).await.ok()?;
		tokio::spawn(conn);
		return Some(sender);
	}

	// The live sender, reconnecting first if the kept-alive one is gone or not ready in time.
	async fn ready_sender(&mut self) -> Option<&mut http1::SendRequest<Body>> {
		let is_ready: bool = match self.sender.as_mut() {
			Some(sender) => matches!(timeout(READY_TIMEOUT, sender.ready()).await, Ok(Ok(()))),
			None => false,
		};
		if !is_ready {
			self.sender = self.connect().await;
		}
		return self.sender.as_mut();
	}

	async fn send(&mut self, req: Request<Body>) -> bool {
		let Some(sender) = self.ready_sender().await else {
			return false;
		};
		let response = match sender.send_request(req).await {
			Ok(r) => r,
			Err(_) => {
				self.sender = None;
				return false;
			}
		};

		let status: StatusCode = response.status();
		let _ = response.into_body().collect().await;
		return status == StatusCode::OK;
	}

	fn host(&self) -> String {
		return format!("127.0.0.1:{}", self.addr.port());
	}

	async fn send_plain(&mut self, body: &str) -> Result<bool, String> {
		let req: Request<Body> = Request::builder()
			.method("POST")
			.uri("/api/echo")
			.header("host", self.host())
			.header("content-type", "application/json")
			.body(Body::from(body.to_owned()))
			.context("build POST /api/echo")?;
		return Ok(self.send(req).await);
	}
}

#[derive(Clone, Copy)]
struct RunOptions {
	concurrency: usize,
	total_requests: usize,
	is_tracing: bool,
}

fn parse_args() -> RunOptions {
	let args: Vec<String> = env::args().collect();
	let concurrency: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_CONCURRENCY);
	let total_requests: usize = args
		.get(2)
		.and_then(|s| s.parse().ok())
		.unwrap_or(DEFAULT_TOTAL_REQUESTS);
	let has_flag = |flag: &str| -> bool { args.iter().skip(FIRST_FLAG_ARG).any(|a| a == flag) };
	return RunOptions {
		concurrency,
		total_requests,
		is_tracing: has_flag("--trace"),
	};
}

// stdout text always; with --trace, also a chrome trace whose guard must live until the run ends.
fn init_tracing(is_tracing: bool) -> Option<FlushGuard> {
	let (chrome_layer, guard) = if is_tracing {
		let (layer, guard) = ChromeLayerBuilder::new().file(TRACE_FILE).include_args(true).build();
		(Some(layer.with_filter(EnvFilter::new(TRACE_LOG_LEVEL))), Some(guard))
	} else {
		(None, None)
	};
	tracing_subscriber::registry()
		.with(chrome_layer)
		.with(support::output_layer(LIBRARY_LOG_LEVEL))
		.init();
	return guard;
}

fn print_header(opts: RunOptions) {
	[
		"Reduction - Profile Load Test".to_owned(),
		"==============================".to_owned(),
		format!("  Concurrency: {}", opts.concurrency),
		format!("  Total requests: {}", opts.total_requests),
	]
	.iter()
	.for_each(|line| info!("{line}"));
}

#[tokio::main]
async fn main() -> Result<(), String> {
	#[cfg(feature = "dhat-heap")]
	let _dhat_profiler = dhat::Profiler::new_heap();

	let opts: RunOptions = parse_args();
	let _trace_guard: Option<FlushGuard> = init_tracing(opts.is_tracing);
	if opts.is_tracing {
		info!("  Tracing enabled -> {TRACE_FILE} (open in https://ui.perfetto.dev)");
	}

	rustls::crypto::aws_lc_rs::default_provider()
		.install_default()
		.map_err(|_| "install rustls crypto provider: a provider is already installed".to_owned())?;

	print_header(opts);

	let dir = tempfile::tempdir().context("create temp dir")?;
	let dir_path = dir.path();

	generate_certs(dir_path)?;
	let config_path = dir_path.join("config.toml");
	write_config(dir_path, &config_path)?;

	let _handles = start_services(dir_path, &config_path).await?;
	tokio::time::sleep(STARTUP_SETTLE).await;
	info!("  Backend (:{BACKEND_PORT}) and proxy (:{PROXY_PORT}) started");

	warm_up(dir_path).await?;

	let results: LoadResults = run_load(dir_path, opts).await?;
	print_results(results);
	print_footer(opts.is_tracing);
	return Ok(());
}

async fn warm_up(dir: &Path) -> Result<(), String> {
	let proxy_addr: SocketAddr = SocketAddr::new(LOOPBACK, PROXY_PORT);
	let mut warmup_client: KeepAliveClient = KeepAliveClient::new(build_client_connector(dir)?, proxy_addr);
	// The warm-up result is not measured: a failed warm-up only means the first measured request dials.
	let _ = warmup_client.send_plain("warmup").await?;
	info!("  Warmup complete");
	return Ok(());
}

async fn send_one(client: &mut KeepAliveClient, worker_id: usize, i: usize) -> Result<bool, String> {
	let body: String = format!(r#"{{"worker":{worker_id},"seq":{i},"data":"payload-for-load-test"}}"#);
	return client
		.send_plain(&body)
		.instrument(info_span!("request", worker = worker_id, seq = i))
		.await;
}

struct LoadResults {
	histogram: LatencyHistogram,
	completed: u64,
	errors: u64,
	total_secs: f64,
	alloc_delta: u64,
}

async fn run_worker(
	mut client: KeepAliveClient,
	worker_id: usize,
	requests: usize,
	errors: Arc<AtomicU64>,
) -> Result<Vec<f64>, String> {
	let mut latencies: Vec<f64> = Vec::with_capacity(requests);
	for i in 0..requests {
		let start: Instant = Instant::now();
		let is_ok: bool = send_one(&mut client, worker_id, i).await?;
		let elapsed_ms: f64 = start.elapsed().as_secs_f64() * MILLIS_PER_SEC;
		if is_ok {
			latencies.push(elapsed_ms);
		} else {
			errors.fetch_add(1, Ordering::Relaxed);
		}
	}
	return Ok(latencies);
}

async fn run_load(dir: &Path, opts: RunOptions) -> Result<LoadResults, String> {
	let proxy_addr: SocketAddr = SocketAddr::new(LOOPBACK, PROXY_PORT);
	let errors: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
	let requests_per_worker: usize = opts.total_requests / opts.concurrency.max(1);

	// Snapshot after warmup so one-time startup allocs (cert gen, TLS setup, config load, pool warm-up)
	// are excluded and the delta reflects only the measured request window.
	let allocs_before: u64 = TOTAL_ALLOCS.load(Ordering::Relaxed);
	let overall_start: Instant = Instant::now();

	let handles: Vec<JoinHandle<Result<Vec<f64>, String>>> = (0..opts.concurrency)
		.map(|worker_id| {
			let client: KeepAliveClient = KeepAliveClient::new(build_client_connector(dir)?, proxy_addr);
			let worker = run_worker(
				client,
				worker_id,
				requests_per_worker,
				Arc::clone(&errors),
			);
			return Ok(tokio::spawn(worker));
		})
		.collect::<Result<Vec<_>, String>>()?;

	let mut histogram: LatencyHistogram = LatencyHistogram::new(opts.total_requests);
	for handle in handles {
		let latencies: Vec<f64> = handle.await.context("load worker task")??;
		latencies.into_iter().for_each(|lat| histogram.record(lat));
	}
	let allocs_after: u64 = TOTAL_ALLOCS.load(Ordering::Relaxed);

	return Ok(LoadResults {
		completed: len_as_u64(histogram.samples.len()),
		histogram,
		errors: errors.load(Ordering::Relaxed),
		total_secs: overall_start.elapsed().as_secs_f64(),
		alloc_delta: allocs_after.saturating_sub(allocs_before),
	});
}

fn print_results(mut results: LoadResults) {
	let rps: f64 = count_as_f64(results.completed) / results.total_secs;
	let allocs_per_req: f64 = if results.completed > 0 {
		count_as_f64(results.alloc_delta) / count_as_f64(results.completed)
	} else {
		0.0
	};
	let mut lines: Vec<String> = vec![
		"-- Results --".to_owned(),
		format!("  Duration:  {:.2}s", results.total_secs),
		format!("  Completed: {}", results.completed),
		format!("  Errors:    {}", results.errors),
		format!("  RPS:       {rps:.0}"),
		format!(
			"  Allocs:    {} during load (whole process: driver + backend + proxy)",
			results.alloc_delta
		),
		format!(
			"  Allocs/req: {allocs_per_req:.1} (whole process; use --features dhat-heap for proxy-only attribution)"
		),
		String::new(),
		"  Latency (ms):".to_owned(),
		format!("    mean: {:.2}", results.histogram.mean()),
	];
	PERCENTILES.iter().for_each(|(label, per_mille)| {
		lines.push(format!("    {label} {:.2}", results.histogram.percentile(*per_mille)));
	});
	lines.iter().for_each(|line| info!("{line}"));
}

fn print_footer(is_tracing: bool) {
	let mut lines: Vec<String> = Vec::new();
	if is_tracing {
		lines.push(format!("  Trace written to {TRACE_FILE}"));
		lines.push("  Open in: https://ui.perfetto.dev".to_owned());
	}

	#[cfg(feature = "dhat-heap")]
	lines.push(
		"  dhat heap profile -> dhat-heap.json (open at https://nnethercote.github.io/dh_view/dh_view.html)".to_owned(),
	);

	lines.push("-- Load Test Complete --".to_owned());
	lines.iter().for_each(|line| info!("{line}"));
}

// ---------------------------------------------------------------------------
// Certificate generation (same as demo.rs)
// ---------------------------------------------------------------------------

fn generate_certs(dir: &Path) -> Result<(), String> {
	let (ca_cert, ca_key) = generate_ca()?;
	let (server_cert, server_key) = generate_signed_cert(
		&ca_cert,
		&ca_key,
		"Reduction Server",
		vec![SanType::IpAddress(LOOPBACK)],
	)?;
	let (client_cert, client_key) = generate_signed_cert(&ca_cert, &ca_key, "Reduction Client", vec![])?;

	let files: [(&str, String); 5] = [
		("ca.crt", ca_cert.pem()),
		("server.crt", server_cert.pem()),
		("server.key", server_key.serialize_pem()),
		("client.crt", client_cert.pem()),
		("client.key", client_key.serialize_pem()),
	];
	return files
		.iter()
		.try_for_each(|(name, pem)| write_file(&dir.join(name), pem));
}

fn write_file(path: &Path, contents: &str) -> Result<(), String> {
	return fs::write(path, contents).context(&format!("write {}", path.display()));
}

fn generate_ca() -> Result<(rcgen::Certificate, KeyPair), String> {
	let mut params = CertificateParams::new(vec![]).context("CA params")?;
	params.distinguished_name.push(DnType::CommonName, "Reduction Demo CA");
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	let key = KeyPair::generate().context("CA key")?;
	let cert = params.self_signed(&key).context("self-sign CA")?;
	return Ok((cert, key));
}

fn generate_signed_cert(
	ca_cert: &rcgen::Certificate,
	ca_key: &KeyPair,
	cn: &str,
	sans: Vec<SanType>,
) -> Result<(rcgen::Certificate, KeyPair), String> {
	let mut params = CertificateParams::new(vec![]).context(&format!("{cn} params"))?;
	params.distinguished_name.push(DnType::CommonName, cn);
	params.subject_alt_names = sans;
	let key = KeyPair::generate().context(&format!("{cn} key"))?;
	let issuer = rcgen::Issuer::from_ca_cert_der(ca_cert.der(), ca_key).context("CA issuer")?;
	let cert = params.signed_by(&key, &issuer).context(&format!("sign {cn}"))?;
	return Ok((cert, key));
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

fn path_str(path: &Path) -> String {
	return path.display().to_string().replace('\\', "/");
}

fn write_config(dir: &Path, config_path: &Path) -> Result<(), String> {
	let toml: String = format!(
		r#"[listen]
address = "127.0.0.1:{PROXY_PORT}"
transport = "tcp"

[tls.server.manual]
cert_path = "{server_crt}"
key_path = "{server_key}"
ca_cert_path = "{ca_crt}"

[tls.client]
cert_path = "{client_crt}"
key_path = "{client_key}"
ca_cert_path = "{ca_crt}"

[[backends]]
id = "backend-a"
address = "127.0.0.1:{BACKEND_PORT}"
weight = 1.0
transport = "tcp"

[[routes]]
path_prefix = "/api"
backend_id = "backend-a"
"#,
		server_crt = path_str(&dir.join("server.crt")),
		server_key = path_str(&dir.join("server.key")),
		client_crt = path_str(&dir.join("client.crt")),
		client_key = path_str(&dir.join("client.key")),
		ca_crt = path_str(&dir.join("ca.crt")),
	);
	return write_file(config_path, &toml);
}

// ---------------------------------------------------------------------------
// Backend server
// ---------------------------------------------------------------------------

struct DemoTlsListener {
	listener: TcpListener,
	acceptor: TlsAcceptor,
}

impl Listener for DemoTlsListener {
	type Io = TlsStream<TcpStream>;

	async fn accept(&mut self) -> (Self::Io, SocketAddr) {
		loop {
			let (stream, addr) = match self.listener.accept().await {
				Ok(accepted) => accepted,
				Err(e) => {
					warn!("backend accept failed: {e}");
					tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
					continue;
				}
			};
			match self.acceptor.accept(stream).await {
				Ok(tls) => return (tls, addr),
				Err(_) => continue,
			}
		}
	}

	fn local_addr(&self) -> io::Result<SocketAddr> {
		return self.listener.local_addr();
	}
}

async fn backend_handler(req: Request<Body>) -> Response<Body> {
	let path: String = req.uri().path().to_owned();
	let method: String = req.method().to_string();
	let body_bytes = req
		.into_body()
		.collect()
		.await
		.map(|b| b.to_bytes())
		.unwrap_or_default();
	let body_str: String = String::from_utf8_lossy(&body_bytes).into_owned();

	let response_body: String = format!(r#"{{"path":"{path}","method":"{method}","echo":"{body_str}"}}"#,);

	// Response::new defaults to 200 OK; building it directly cannot fail, unlike Response::builder().
	let mut response: Response<Body> = Response::new(Body::from(response_body));
	response
		.headers_mut()
		.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
	return response;
}

// ---------------------------------------------------------------------------
// Service startup
// ---------------------------------------------------------------------------

struct ServiceHandles {
	_health_tx: watch::Sender<HealthState>,
	_watcher: config::watcher::ConfigWatcher,
}

fn build_backend_pools(config: &ReductionConfig) -> Result<FastMap<ArrayString<MAX_BACKEND_ID_LEN>, BackendPool>, String> {
	let mut pools: FastMap<ArrayString<MAX_BACKEND_ID_LEN>, BackendPool> = FastMap::default();
	for pool_id in config.routes.iter().flat_map(|route| route.target().pools()) {
		let backends: Vec<BackendConfig> = config
			.backends
			.iter()
			.filter(|b| b.pool.as_str() == pool_id.as_str())
			.cloned()
			.collect();
		if !backends.is_empty() && !pools.contains_key(pool_id.as_str()) {
			let pool: BackendPool = BackendPool::new(backends).context(&format!("pool {pool_id}"))?;
			pools.insert(*pool_id, pool);
		}
	}
	return Ok(pools);
}

fn build_reloadable(config: &ReductionConfig) -> Result<ReloadableState, String> {
	return Ok(ReloadableState {
		router: Router::new(&config.routes),
		backend_pools: build_backend_pools(config)?,
		acl: AccessControl::new(config.access.allow.iter().copied(), config.access.deny.iter().copied()),
	});
}

async fn start_backend(dir: &Path) -> Result<(), String> {
	let (backend_tls_config, _) =
		tls::build_server_config(&dir.join("server.crt"), &dir.join("server.key"), &dir.join("ca.crt"))
			.context("backend TLS config")?;
	let backend_tls: Arc<rustls::ServerConfig> = Arc::new(backend_tls_config);

	let backend_addr: SocketAddr = SocketAddr::new(LOOPBACK, BACKEND_PORT);
	let backend_listener = TcpListener::bind(backend_addr)
		.await
		.context(&format!("bind backend {backend_addr}"))?;
	let demo_listener = DemoTlsListener {
		listener: backend_listener,
		acceptor: TlsAcceptor::from(backend_tls),
	};

	let make_handler = |_: &TlsStream<TcpStream>, _: SocketAddr| {
		return |req: Request<Incoming>| backend_handler(req.map(Body::new));
	};
	tokio::spawn(async move {
		if let Err(e) = serve_with(demo_listener, make_handler, pending::<()>()).await {
			error!("backend server stopped: {e}");
		}
	});
	return Ok(());
}

// Each reloaded config rebuilds the state and then goes on `config_tx`. A config that fails to build keeps the old state.
fn spawn_reload_task(
	mut reload_rx: mpsc::UnboundedReceiver<ReductionConfig>,
	config_tx: watch::Sender<ReductionConfig>,
	reloadable_tx: watch::Sender<ReloadableState>,
) {
	tokio::spawn(async move {
		while let Some(cfg) = reload_rx.recv().await {
			let built: Result<ReloadableState, String> = build_reloadable(&cfg);
			let _displaced: ReductionConfig = config_tx.send_replace(cfg);
			match built {
				Ok(state) => {
					if reloadable_tx.send(state).is_err() {
						return;
					}
				}
				Err(e) => warn!("reload rejected, keeping the previous state: {e}"),
			}
		}
	});
}

struct ProxyParts {
	state: &'static ProxyState,
	server_tls: Arc<rustls::ServerConfig>,
	reloadable_tx: watch::Sender<ReloadableState>,
	health_tx: watch::Sender<HealthState>,
}

fn build_proxy(config: &ReductionConfig) -> Result<ProxyParts, String> {
	let main: MainListener<'_> = config.require_main_listener().context("demo config has [listen] and [tls]")?;
	let manual = main
		.tls
		.server
		.as_manual()
		.context("demo config uses [tls.server.manual]")?;
	let server_key: &Path = manual.key_path.as_deref().context("demo config sets key_path")?;
	let (server_tls_config, _) = tls::build_server_config(&manual.cert_path, server_key, &manual.ca_cert_path)
		.context("proxy server TLS config")?;

	let client_identity = main
		.tls
		.client
		.as_ref()
		.context("demo config includes [tls.client]")?;
	let client_key: &Path = client_identity.key_path.as_deref().context("demo config sets key_path")?;
	let (client_tls_config, _, _) =
		tls::build_client_config(&client_identity.cert_path, client_key, &client_identity.ca_cert_path)
	.context("proxy client TLS config")?;
	let client_tls: Arc<rustls::ClientConfig> = Arc::new(client_tls_config);

	let (reloadable_tx, reloadable_rx) = watch::channel(build_reloadable(config)?);
	let (health_tx, health_rx) = watch::channel(HealthState::new());
	let (_, revocation_rx) = watch::channel(RevocationSet::default());

	let state: &'static ProxyState = Box::leak(Box::new(ProxyState {
		reloadable: reloadable_rx,
		revocation: revocation_rx,
		tls_connector: TlsConnector::from(Arc::clone(&client_tls)),
		client_tls_config: client_tls,
		health_rx,
		conn_pool: ConnPool::new(),
		rate_limiter: RateLimit::new(None),
		queues: SnapshotMap::new(),
		labels: LabelInterner::new(),
		default_queue_depth: config.balancer.queue_depth,
		metrics: ProxyMetrics::new(),
		circuit_breakers: CircuitBreakers::new(&CircuitBreakerConfig::default()),
		shutdown: CancellationToken::new(),
		timeouts: TimeoutConfig::default(),
		proxy_config: ProxyConfig::default(),
		retry_config: RetryConfig::default(),
		client_auth: main.listen.client_auth,
		device_id_source: main.listen.device_id_source,
		http_authz: HttpAuthz::default(),
	}));
	return Ok(ProxyParts {
		state,
		server_tls: Arc::new(server_tls_config),
		reloadable_tx,
		health_tx,
	});
}

async fn start_services(dir: &Path, config_path: &Path) -> Result<ServiceHandles, String> {
	let config: ReductionConfig = config::load_config(config_path).context("load demo config")?;
	let main: MainListener<'_> = config.require_main_listener().context("demo config has [listen] and [tls]")?;

	start_backend(dir).await?;
	let proxy: ProxyParts = build_proxy(&config)?;

	let (config_tx, config_rx) = watch::channel(config.clone());
	let (reload_tx, reload_rx) = mpsc::unbounded_channel::<ReductionConfig>();
	let watcher =
		config::watcher::ConfigWatcher::new(config_path, config_rx, reload_tx).context("config watcher")?;
	spawn_reload_task(reload_rx, config_tx, proxy.reloadable_tx);

	let proxy_listener = reduction::transport::tcp::TcpListener::bind(main.listen.address, proxy.server_tls, None)
		.await
		.context(&format!("bind proxy {}", main.listen.address))?;

	tokio::spawn(async move {
		if let Err(e) = serve(proxy_listener, proxy.state, None, pending::<()>()).await {
			error!("proxy server stopped: {e}");
		}
	});

	return Ok(ServiceHandles {
		_health_tx: proxy.health_tx,
		_watcher: watcher,
	});
}

// ---------------------------------------------------------------------------
// mTLS client
// ---------------------------------------------------------------------------

fn build_client_connector(dir: &Path) -> Result<TlsConnector, String> {
	let (client_config, _, _): (rustls::ClientConfig, _, _) =
		tls::build_client_config(&dir.join("client.crt"), &dir.join("client.key"), &dir.join("ca.crt"))
			.context("load-test client TLS config")?;
	return Ok(TlsConnector::from(Arc::new(client_config)));
}
