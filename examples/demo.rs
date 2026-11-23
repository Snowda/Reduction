mod support;

use std::future::pending;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::{fs, io};

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
	RetryConfig, TimeoutConfig, TransportKind,
};
use reduction::fast_hash::FastMap;
use reduction::health::{Availability, BackendHealth, HealthBroadcast, HealthState};
use reduction::metrics::ProxyMetrics;
use reduction::proxy::server::{serve, serve_with};
use reduction::proxy::{ConnPool, HttpAuthz, ProxyState, ReloadableState, Router};
use reduction::ratelimit::RateLimit;
use reduction::label_intern::LabelInterner;
use reduction::snapshot_map::SnapshotMap;
use reduction::tls;
use reduction::transport::listener::Listener;
use reduction::tunnel::revocation::RevocationSet;
use rustls::pki_types::ServerName;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio_rustls::server::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::support::Context;

// Show only the demo text and any warnings from the library.
const LIBRARY_LOG_LEVEL: &str = "warn";

const PROXY_PORT: u16 = 18443;
const BACKEND_PORT: u16 = 19443;
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const STARTUP_SETTLE: Duration = Duration::from_millis(500);
const RELOAD_SETTLE: Duration = Duration::from_secs(2);
// Same as the library's listener: wait after an accept error, so the loop does not retry at full speed.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_secs(1);

#[tokio::main]
async fn main() -> Result<(), String> {
	rustls::crypto::aws_lc_rs::default_provider()
		.install_default()
		.map_err(|_| "install rustls crypto provider: a provider is already installed".to_owned())?;

	tracing_subscriber::registry()
		.with(support::output_layer(LIBRARY_LOG_LEVEL))
		.init();

	info!("Reduction - M2M Reverse Proxy Demo");
	info!("===================================");

	let dir = tempfile::tempdir().context("create temp dir")?;
	let dir_path = dir.path();

	// -- Phase 1: TLS certificates --
	info!("-- Phase 1: TLS Certificate Generation --");
	generate_certs(dir_path)?;
	let config_path = dir_path.join("config.toml");
	write_config(dir_path, &config_path, &[("/api", "backend-a")])?;
	info!("  Written to {}", dir_path.display());

	// -- Phase 2: Data plane --
	info!("-- Phase 2: Data Plane --");
	let handles = start_services(dir_path, &config_path).await?;
	tokio::time::sleep(STARTUP_SETTLE).await;
	info!("  Backend (:{BACKEND_PORT}) and proxy (:{PROXY_PORT}) started");

	let client_connector = build_client_connector(dir_path)?;
	let proxy_addr: SocketAddr = SocketAddr::new(LOOPBACK, PROXY_PORT);

	let resp = send_request(
		&client_connector,
		proxy_addr,
		"POST",
		"/api/echo",
		"hello from M2M client",
	)
	.await?;
	info!("  POST /api/echo -> {resp}");

	let resp = send_request(
		&client_connector,
		proxy_addr,
		"POST",
		"/api/data",
		r#"{"sensor":"temp-01","value":23.5}"#,
	)
	.await?;
	info!("  POST /api/data -> {resp}");

	// -- Phase 3: Management plane - health --
	info!("-- Phase 3: Management Plane - Health State --");
	demonstrate_health(&handles.health_tx)?;

	// -- Phase 4: Management plane - config reload --
	info!("-- Phase 4: Management Plane - Config Reload --");
	demonstrate_config_reload(dir_path, &config_path, &client_connector, proxy_addr).await?;

	info!("-- Demo Complete --");
	return Ok(());
}

// ---------------------------------------------------------------------------
// Certificate generation
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
	files
		.iter()
		.try_for_each(|(name, pem)| write_file(&dir.join(name), pem))?;

	[
		"CA certificate",
		"Server certificate (SAN: 127.0.0.1)",
		"Client certificate",
	]
	.iter()
	.for_each(|made| info!("  [ok] {made}"));
	return Ok(());
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

fn write_config(dir: &Path, config_path: &Path, routes: &[(&str, &str)]) -> Result<(), String> {
	let mut toml = format!(
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
"#,
		server_crt = path_str(&dir.join("server.crt")),
		server_key = path_str(&dir.join("server.key")),
		client_crt = path_str(&dir.join("client.crt")),
		client_key = path_str(&dir.join("client.key")),
		ca_crt = path_str(&dir.join("ca.crt")),
	);

	for (prefix, backend_id) in routes {
		toml.push_str(&format!(
			"\n[[routes]]\npath_prefix = \"{prefix}\"\nbackend_id = \"{backend_id}\"\n"
		));
	}

	return write_file(config_path, &toml);
}

// ---------------------------------------------------------------------------
// Backend server (simulates an upstream M2M service)
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

	let response_body: String = if body_str.is_empty() {
		format!(r#"{{"path":"{path}","method":"{method}","backend":"backend-a"}}"#)
	} else {
		format!(r#"{{"path":"{path}","method":"{method}","backend":"backend-a","received":"{body_str}"}}"#)
	};

	// Response::new defaults to 200 OK; building it directly cannot fail, unlike Response::builder().
	let mut response: Response<Body> = Response::new(Body::from(response_body));
	response
		.headers_mut()
		.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
	return response;
}

// ---------------------------------------------------------------------------
// Service startup (assembles proxy from library components)
// ---------------------------------------------------------------------------

struct DemoHandles {
	health_tx: watch::Sender<HealthState>,
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

async fn start_services(dir: &Path, config_path: &Path) -> Result<DemoHandles, String> {
	let config: ReductionConfig = config::load_config(config_path).context("load demo config")?;

	start_backend(dir).await?;

	// -- Proxy --
	let main: MainListener<'_> = config.require_main_listener().context("demo config has [listen] and [tls]")?;
	let manual = main
		.tls
		.server
		.as_manual()
		.context("demo config uses [tls.server.manual]")?;
	let server_key: &Path = manual.key_path.as_deref().context("demo config sets key_path")?;
	let (server_tls_config, _) = tls::build_server_config(&manual.cert_path, server_key, &manual.ca_cert_path)
		.context("proxy server TLS config")?;
	let server_tls: Arc<rustls::ServerConfig> = Arc::new(server_tls_config);

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

	let tls_connector: TlsConnector = TlsConnector::from(Arc::clone(&client_tls));

	let (reloadable_tx, reloadable_rx) = watch::channel(build_reloadable(&config)?);
	let (health_tx, health_rx) = watch::channel(HealthState::new());
	let (_, revocation_rx) = watch::channel(RevocationSet::default());

	let proxy_state: &'static ProxyState = Box::leak(Box::new(ProxyState {
		reloadable: reloadable_rx,
		revocation: revocation_rx,
		tls_connector,
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

	// Config watcher + reload task
	let (config_tx, config_rx) = watch::channel(config.clone());
	let (reload_tx, mut reload_rx) = mpsc::unbounded_channel::<ReductionConfig>();
	let watcher =
		config::watcher::ConfigWatcher::new(config_path, config_rx, reload_tx).context("config watcher")?;

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

	let proxy_listener = reduction::transport::tcp::TcpListener::bind(main.listen.address, server_tls, None)
		.await
		.context(&format!("bind proxy {}", main.listen.address))?;

	tokio::spawn(async move {
		if let Err(e) = serve(proxy_listener, proxy_state, None, pending::<()>()).await {
			error!("proxy server stopped: {e}");
		}
	});

	return Ok(DemoHandles {
		health_tx,
		_watcher: watcher,
	});
}

// ---------------------------------------------------------------------------
// mTLS client
// ---------------------------------------------------------------------------

fn build_client_connector(dir: &Path) -> Result<TlsConnector, String> {
	let (client_config, _, _): (rustls::ClientConfig, _, _) =
		tls::build_client_config(&dir.join("client.crt"), &dir.join("client.key"), &dir.join("ca.crt"))
			.context("demo client TLS config")?;
	return Ok(TlsConnector::from(Arc::new(client_config)));
}

async fn send_request(
	connector: &TlsConnector,
	addr: SocketAddr,
	method: &str,
	path: &str,
	body: &str,
) -> Result<String, String> {
	let tcp: TcpStream = TcpStream::connect(addr).await.context(&format!("connect {addr}"))?;
	let server_name: ServerName<'static> = ServerName::IpAddress(addr.ip().into());
	let tls = connector
		.connect(server_name, tcp)
		.await
		.context("client TLS handshake")?;
	let io = TokioIo::new(tls);

	let (mut sender, conn) = http1::handshake(io).await.context("HTTP/1 handshake")?;
	tokio::spawn(conn);

	let req: Request<Body> = Request::builder()
		.method(method)
		.uri(path)
		.header("host", format!("127.0.0.1:{}", addr.port()))
		.body(Body::from(body.to_owned()))
		.context(&format!("build {method} {path}"))?;

	let response = sender
		.send_request(req)
		.await
		.context(&format!("send {method} {path}"))?;
	let status: StatusCode = response.status();
	let bytes = response
		.into_body()
		.collect()
		.await
		.context("read response body")?
		.to_bytes();
	let body_str: String = String::from_utf8_lossy(&bytes).into_owned();

	return Ok(format!("{status} {body_str}"));
}

// ---------------------------------------------------------------------------
// Phase 3: Health state demonstration
// ---------------------------------------------------------------------------

fn health_entry(id: &str, load: f64, latency_ms: u32, availability: Availability) -> Result<BackendHealth, String> {
	return Ok(BackendHealth {
		backend_id: ArrayString::from(id).context(&format!("backend id {id}"))?,
		load,
		latency_ms,
		availability,
	});
}

fn demo_backend(id: &str, last_octet: u8) -> Result<BackendConfig, String> {
	let addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)), 8080);
	return BackendConfig::new(id, addr, 1.0, TransportKind::Tcp).context(&format!("backend {id}"));
}

fn demonstrate_health(health_tx: &watch::Sender<HealthState>) -> Result<(), String> {
	show_wire_format()?;
	show_weighted_selection()?;
	return push_live_health(health_tx);
}

// Show bitcode wire format used for M2M health broadcasts, and that it decodes back.
fn show_wire_format() -> Result<(), String> {
	let broadcast: HealthBroadcast = HealthBroadcast {
		entries: vec![
			health_entry("node-1", 0.2, 30, Availability::Online)?,
			health_entry("node-2", 0.8, 200, Availability::Online)?,
		],
	};
	let wire: Vec<u8> = bitcode::encode(&broadcast);
	info!("  Wire format: 2 health entries -> {} bytes (bitcode)", wire.len());

	let decoded: HealthBroadcast = bitcode::decode(&wire).context("decode health broadcast")?;
	info!("  Decode check: {} entries recovered", decoded.entries.len());
	return Ok(());
}

// Each scenario is a label and the health the proxy has heard. With no entries, both backends are
// unknown and weigh 1.0.
fn selection_scenarios() -> Result<[(&'static str, Vec<BackendHealth>); 3], String> {
	return Ok([
		("Equal health   ", vec![]),
		(
			"node-1 loaded  ",
			vec![
				health_entry("node-1", 0.95, 800, Availability::Online)?,
				health_entry("node-2", 0.1, 20, Availability::Online)?,
			],
		),
		(
			"node-1 down    ",
			vec![
				health_entry("node-1", 0.0, 0, Availability::Offline)?,
				health_entry("node-2", 0.3, 50, Availability::Online)?,
			],
		),
	]);
}

// Demonstrate health-weighted backend selection
fn show_weighted_selection() -> Result<(), String> {
	let backends: Vec<BackendConfig> = vec![demo_backend("node-1", 1)?, demo_backend("node-2", 2)?];
	let pool: BackendPool = BackendPool::new(backends).context("demo pool")?;
	let client_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

	return selection_scenarios()?.into_iter().try_for_each(|(label, entries)| {
		let mut health: HealthState = HealthState::new();
		if !entries.is_empty() {
			health.update(HealthBroadcast { entries });
		}
		let selected: &BackendConfig = pool.select(client_ip, &health).context(label.trim_end())?;
		info!("  {label} -> selected: {}", selected.id);
		return Ok(());
	});
}

// Push a live health update to the proxy that runs in this process.
fn push_live_health(health_tx: &watch::Sender<HealthState>) -> Result<(), String> {
	let live: BackendHealth = health_entry("backend-a", 0.2, 30, Availability::Online)?;
	health_tx.send_modify(|state| {
		state.update(HealthBroadcast { entries: vec![live] });
	});
	info!("  Pushed live health update to running proxy (backend-a: load=0.2, latency=30ms)");
	return Ok(());
}

// ---------------------------------------------------------------------------
// Phase 4: Config hot-reload demonstration
// ---------------------------------------------------------------------------

async fn demonstrate_config_reload(
	dir: &Path,
	config_path: &Path,
	connector: &TlsConnector,
	proxy_addr: SocketAddr,
) -> Result<(), String> {
	// Add a new route via config file modification
	write_config(dir, config_path, &[("/api/v2", "backend-a"), ("/api", "backend-a")])?;
	info!("  Config updated: added /api/v2 route");

	// Wait for the file watcher to detect the change and rebuild state
	tokio::time::sleep(RELOAD_SETTLE).await;

	let resp = send_request(connector, proxy_addr, "GET", "/api/v2/status", "").await?;
	info!("  GET /api/v2/status -> {resp}");
	return Ok(());
}
