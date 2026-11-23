mod support;

use std::future::pending;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Range;
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
	RetryConfig, TimeoutConfig,
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
const BACKEND_A_PORT: u16 = 19443;
const BACKEND_B_PORT: u16 = 19444;
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const STARTUP_SETTLE: Duration = Duration::from_millis(500);
const RELOAD_SETTLE: Duration = Duration::from_secs(2);
// Same as the library's listener: wait after an accept error, so the loop does not retry at full speed.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_secs(1);
const MCP_PATH: &str = "/mcp";
const MCP_V2_PATH: &str = "/mcp/v2";

// JSON-RPC request ids for each burst of echo calls, so every request in the demo has its own id.
const AFFINITY_IDS: Range<u32> = 5..15;
const LOADED_IDS: Range<u32> = 20..30;
const DOWN_IDS: Range<u32> = 30..40;

// The single MCP calls of phase 2, in order: a heading and the JSON-RPC request.
const MCP_CALLS: [(&str, &str); 4] = [
	(
		"MCP initialize",
		r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"reduction-demo","version":"0.1.0"}}}"#,
	),
	(
		"MCP tools/list",
		r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
	),
	(
		"MCP tools/call (echo)",
		r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello from M2M client"}}}"#,
	),
	(
		"MCP tools/call (add)",
		r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"add","arguments":{"a":17,"b":25}}}"#,
	),
];

#[tokio::main]
async fn main() -> Result<(), String> {
	rustls::crypto::aws_lc_rs::default_provider()
		.install_default()
		.map_err(|_| "install rustls crypto provider: a provider is already installed".to_owned())?;

	tracing_subscriber::registry()
		.with(support::output_layer(LIBRARY_LOG_LEVEL))
		.init();

	info!("Reduction - MCP Reverse Proxy Demo");
	info!("===================================");

	let dir = tempfile::tempdir().context("create temp dir")?;
	let dir_path = dir.path();

	// -- Phase 1: TLS certificates --
	info!("-- Phase 1: TLS Certificate Generation --");
	generate_certs(dir_path)?;
	let config_path = dir_path.join("config.toml");
	write_config(dir_path, &config_path, &[(MCP_PATH, "mcp-servers")], true)?;
	info!("  Written to {}", dir_path.display());

	// -- Phase 2: MCP data plane --
	info!("-- Phase 2: MCP Data Plane --");
	let handles = start_services(dir_path, &config_path).await?;
	tokio::time::sleep(STARTUP_SETTLE).await;
	info!("  Backend A (:{BACKEND_A_PORT}), Backend B (:{BACKEND_B_PORT}), Proxy (:{PROXY_PORT}) started");

	let client_connector = build_client_connector(dir_path)?;
	let proxy_addr: SocketAddr = SocketAddr::new(LOOPBACK, PROXY_PORT);

	for (heading, request) in MCP_CALLS {
		info!("  --- {heading} ---");
		let resp = send_mcp_request(&client_connector, proxy_addr, MCP_PATH, request).await?;
		info!("  -> {resp}");
	}

	// Send multiple requests to show load balancing distribution.
	// All requests come from 127.0.0.1, so rendezvous hashing gives
	// deterministic affinity to one backend — this is by design.
	info!("  --- Load balancing (10 requests, same client IP) ---");
	let distribution = echo_distribution(&client_connector, proxy_addr, AFFINITY_IDS, "req").await?;
	report_distribution(&distribution, "  ");

	// -- Phase 3: Health-aware failover --
	info!("-- Phase 3: Health-Aware Failover --");
	demonstrate_failover(&handles.health_tx, &client_connector, proxy_addr).await?;

	// -- Phase 4: Config hot-reload --
	info!("-- Phase 4: Config Hot-Reload --");
	demonstrate_config_reload(dir_path, &config_path, &client_connector, proxy_addr).await?;

	info!("-- Demo Complete --");
	return Ok(());
}

// Send one echo call per id and count which backend answered each one.
async fn echo_distribution(
	connector: &TlsConnector,
	proxy_addr: SocketAddr,
	ids: Range<u32>,
	tag: &str,
) -> Result<FastMap<String, u32>, String> {
	let mut distribution: FastMap<String, u32> = FastMap::default();
	for i in ids {
		let req = format!(
			r#"{{"jsonrpc":"2.0","id":{i},"method":"tools/call","params":{{"name":"echo","arguments":{{"message":"{tag}-{i}"}}}}}}"#,
		);
		let resp = send_mcp_request(connector, proxy_addr, MCP_PATH, &req).await?;
		*distribution.entry(extract_backend_id(&resp)).or_insert(0) += 1;
	}
	return Ok(distribution);
}

fn report_distribution(distribution: &FastMap<String, u32>, indent: &str) {
	distribution
		.iter()
		.for_each(|(backend, count)| info!("{indent}{backend}: {count} requests"));
}

// ---------------------------------------------------------------------------
// MCP JSON-RPC handler (simulates an MCP server backend)
// ---------------------------------------------------------------------------

fn mcp_handle_request(backend_name: &str, body: &str) -> String {
	let method = extract_json_string(body, "method");
	let id = extract_json_number(body, "id");

	return match method.as_str() {
		"initialize" => format!(
			r#"{{"jsonrpc":"2.0","id":{id},"result":{{"protocolVersion":"2025-03-26","capabilities":{{"tools":{{}}}},"serverInfo":{{"name":"{backend_name}","version":"0.1.0"}}}}}}"#,
		),
		"tools/list" => format!(
			r#"{{"jsonrpc":"2.0","id":{id},"result":{{"tools":[{{"name":"echo","description":"Echoes back the input message","inputSchema":{{"type":"object","properties":{{"message":{{"type":"string"}}}},"required":["message"]}}}},{{"name":"add","description":"Adds two numbers","inputSchema":{{"type":"object","properties":{{"a":{{"type":"number"}},"b":{{"type":"number"}}}},"required":["a","b"]}}}}],"_backend":"{backend_name}"}}}}"#,
		),
		"tools/call" => {
			let tool_name = extract_nested_string(body, "name");
			let result_content = match tool_name.as_str() {
				"echo" => {
					let message = extract_nested_string(body, "message");
					format!(r#"{{"content":[{{"type":"text","text":"{message}"}}],"_backend":"{backend_name}"}}"#,)
				}
				"add" => {
					let a = extract_nested_number(body, "a");
					let b = extract_nested_number(body, "b");
					let sum: f64 = a + b;
					format!(r#"{{"content":[{{"type":"text","text":"{sum}"}}],"_backend":"{backend_name}"}}"#,)
				}
				_ => format!(
					r#"{{"isError":true,"content":[{{"type":"text","text":"unknown tool: {tool_name}"}}],"_backend":"{backend_name}"}}"#,
				),
			};
			format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result_content}}}"#)
		}
		_ => format!(
			r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":-32601,"message":"method not found: {method}","data":{{"backend":"{backend_name}"}}}}}}"#,
		),
	};
}

// Minimal JSON field extraction — avoids serde_json dependency
fn extract_json_string(json: &str, key: &str) -> String {
	let pattern = format!(r#""{key}":""#);
	if let Some(start) = json.find(&pattern) {
		let value_start = start + pattern.len();
		if let Some(end) = json[value_start..].find('"') {
			return json[value_start..value_start + end].to_owned();
		}
	}
	return String::new();
}

fn extract_json_number(json: &str, key: &str) -> String {
	let pattern = format!(r#""{key}":"#);
	if let Some(start) = json.find(&pattern) {
		let value_start = start + pattern.len();
		let rest = &json[value_start..];
		let end = rest
			.find(|c: char| !c.is_ascii_digit() && c != '.' && c != '-')
			.unwrap_or(rest.len());
		return rest[..end].to_owned();
	}
	return "0".to_owned();
}

fn extract_nested_string(json: &str, key: &str) -> String {
	let pattern = format!(r#""{key}":""#);
	if let Some(start) = json.rfind(&pattern) {
		let value_start = start + pattern.len();
		if let Some(end) = json[value_start..].find('"') {
			return json[value_start..value_start + end].to_owned();
		}
	}
	return String::new();
}

fn extract_nested_number(json: &str, key: &str) -> f64 {
	let pattern = format!(r#""{key}":"#);
	if let Some(start) = json.rfind(&pattern) {
		let value_start = start + pattern.len();
		let rest = &json[value_start..];
		let end = rest
			.find(|c: char| !c.is_ascii_digit() && c != '.' && c != '-')
			.unwrap_or(rest.len());
		if let Ok(n) = rest[..end].parse() {
			return n;
		}
	}
	return 0.0;
}

fn extract_backend_id(response: &str) -> String {
	let backend = extract_nested_string(response, "_backend");
	if backend.is_empty() {
		return "unknown".to_owned();
	}
	return backend;
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
		"Client certificate (mTLS)",
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

fn write_config(dir: &Path, config_path: &Path, routes: &[(&str, &str)], two_backends: bool) -> Result<(), String> {
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
id = "mcp-a"
pool = "mcp-servers"
address = "127.0.0.1:{BACKEND_A_PORT}"
weight = 1.0
transport = "tcp"
"#,
		server_crt = path_str(&dir.join("server.crt")),
		server_key = path_str(&dir.join("server.key")),
		client_crt = path_str(&dir.join("client.crt")),
		client_key = path_str(&dir.join("client.key")),
		ca_crt = path_str(&dir.join("ca.crt")),
	);

	if two_backends {
		toml.push_str(&format!(
			r#"
[[backends]]
id = "mcp-b"
pool = "mcp-servers"
address = "127.0.0.1:{BACKEND_B_PORT}"
weight = 1.0
transport = "tcp"
"#
		));
	}

	for (prefix, backend_id) in routes {
		toml.push_str(&format!(
			"\n[[routes]]\npath_prefix = \"{prefix}\"\nbackend_id = \"{backend_id}\"\n"
		));
	}

	return write_file(config_path, &toml);
}

// ---------------------------------------------------------------------------
// Backend MCP server (simulates upstream MCP services)
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

async fn mcp_backend_handler(backend_name: Arc<str>, req: Request<Body>) -> Response<Body> {
	let body_bytes = req
		.into_body()
		.collect()
		.await
		.map(|b| b.to_bytes())
		.unwrap_or_default();
	let body_str: String = String::from_utf8_lossy(&body_bytes).into_owned();

	let response_body: String = mcp_handle_request(&backend_name, &body_str);

	// Response::new defaults to 200 OK; building it directly cannot fail, unlike Response::builder().
	let mut response: Response<Body> = Response::new(Body::from(response_body));
	response
		.headers_mut()
		.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
	return response;
}

async fn start_mcp_backend(dir: &Path, port: u16, name: &str) -> Result<(), String> {
	let (backend_tls_config, _) =
		tls::build_server_config(&dir.join("server.crt"), &dir.join("server.key"), &dir.join("ca.crt"))
			.context(&format!("{name} TLS config"))?;
	let backend_tls: Arc<rustls::ServerConfig> = Arc::new(backend_tls_config);

	let addr: SocketAddr = SocketAddr::new(LOOPBACK, port);
	let listener = TcpListener::bind(addr).await.context(&format!("bind {name} {addr}"))?;
	let demo_listener = DemoTlsListener {
		listener,
		acceptor: TlsAcceptor::from(backend_tls),
	};

	let backend_name: Arc<str> = Arc::from(name);
	let make_handler = move |_: &TlsStream<TcpStream>, _: SocketAddr| {
		let backend_name: Arc<str> = Arc::clone(&backend_name);
		return move |req: Request<Incoming>| mcp_backend_handler(Arc::clone(&backend_name), req.map(Body::new));
	};

	let name: String = name.to_owned();
	tokio::spawn(async move {
		if let Err(e) = serve_with(demo_listener, make_handler, pending::<()>()).await {
			error!("{name} stopped: {e}");
		}
	});
	return Ok(());
}

// ---------------------------------------------------------------------------
// Service startup
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

async fn start_services(dir: &Path, config_path: &Path) -> Result<DemoHandles, String> {
	let config: ReductionConfig = config::load_config(config_path).context("load demo config")?;

	// -- MCP Backends --
	start_mcp_backend(dir, BACKEND_A_PORT, "mcp-backend-a").await?;
	start_mcp_backend(dir, BACKEND_B_PORT, "mcp-backend-b").await?;

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

async fn send_mcp_request(
	connector: &TlsConnector,
	addr: SocketAddr,
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
		.method("POST")
		.uri(path)
		.header("host", format!("127.0.0.1:{}", addr.port()))
		.header("content-type", "application/json")
		.body(Body::from(body.to_owned()))
		.context(&format!("build POST {path}"))?;

	let response = sender.send_request(req).await.context(&format!("send POST {path}"))?;
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
// Phase 3: Health-aware failover
// ---------------------------------------------------------------------------

fn health_entry(id: &str, load: f64, latency_ms: u32, availability: Availability) -> Result<BackendHealth, String> {
	return Ok(BackendHealth {
		backend_id: ArrayString::from(id).context(&format!("backend id {id}"))?,
		load,
		latency_ms,
		availability,
	});
}

fn push_health(health_tx: &watch::Sender<HealthState>, entries: Vec<BackendHealth>) {
	health_tx.send_modify(|state| {
		state.update(HealthBroadcast { entries });
	});
}

// mcp-a is heavily loaded and mcp-b is healthy.
fn loaded_health() -> Result<Vec<BackendHealth>, String> {
	return Ok(vec![
		health_entry("mcp-a", 0.95, 800, Availability::Online)?,
		health_entry("mcp-b", 0.1, 20, Availability::Online)?,
	]);
}

// mcp-a is offline and mcp-b is healthy.
fn down_health() -> Result<Vec<BackendHealth>, String> {
	return Ok(vec![
		health_entry("mcp-a", 0.0, 0, Availability::Offline)?,
		health_entry("mcp-b", 0.3, 50, Availability::Online)?,
	]);
}

async fn show_distribution(
	connector: &TlsConnector,
	proxy_addr: SocketAddr,
	ids: Range<u32>,
	tag: &str,
	heading: &str,
) -> Result<(), String> {
	let distribution = echo_distribution(connector, proxy_addr, ids, tag).await?;
	info!("  {heading} (10 requests):");
	report_distribution(&distribution, "    ");
	return Ok(());
}

async fn demonstrate_failover(
	health_tx: &watch::Sender<HealthState>,
	connector: &TlsConnector,
	proxy_addr: SocketAddr,
) -> Result<(), String> {
	push_health(health_tx, loaded_health()?);
	info!("  Pushed health update: mcp-a loaded (0.95), mcp-b healthy (0.1)");
	show_distribution(connector, proxy_addr, LOADED_IDS, "failover", "After health update").await?;

	push_health(health_tx, down_health()?);
	info!("  Pushed health update: mcp-a DOWN, mcp-b healthy");
	return show_distribution(connector, proxy_addr, DOWN_IDS, "down", "After failover").await;
}

// ---------------------------------------------------------------------------
// Phase 4: Config hot-reload
// ---------------------------------------------------------------------------

async fn show_tools_list(connector: &TlsConnector, proxy_addr: SocketAddr, path: &str) -> Result<(), String> {
	let req = r#"{"jsonrpc":"2.0","id":50,"method":"tools/list","params":{}}"#;
	let resp = send_mcp_request(connector, proxy_addr, path, req).await?;
	info!("  POST {path:<7} tools/list -> {resp}");
	return Ok(());
}

async fn demonstrate_config_reload(
	dir: &Path,
	config_path: &Path,
	connector: &TlsConnector,
	proxy_addr: SocketAddr,
) -> Result<(), String> {
	// Add a new /mcp/v2 route via config file modification
	write_config(
		dir,
		config_path,
		&[(MCP_V2_PATH, "mcp-servers"), (MCP_PATH, "mcp-servers")],
		true,
	)?;
	info!("  Config updated: added /mcp/v2 route");

	tokio::time::sleep(RELOAD_SETTLE).await;

	// The new route answers, and the original route still works.
	show_tools_list(connector, proxy_addr, MCP_V2_PATH).await?;
	return show_tools_list(connector, proxy_addr, MCP_PATH).await;
}
