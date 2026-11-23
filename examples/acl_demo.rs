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
use ipnet::IpNet;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
use reduction::acl::AccessControl;
use reduction::balancer::BackendPool;
use reduction::body::Body;
use reduction::circuit::CircuitBreakers;
use reduction::config::MainListener;
use reduction::config::{
	self, BackendConfig, MAX_BACKEND_ID_LEN, ProxyConfig, ReductionConfig, RetryConfig,
	TimeoutConfig,
};
use reduction::fast_hash::FastMap;
use reduction::health::HealthState;
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
use tokio::sync::watch;
use tokio_rustls::server::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::support::Context;

// Show only the demo text and any warnings from the library.
const LIBRARY_LOG_LEVEL: &str = "warn";

const BACKEND_PORT: u16 = 19443;
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const STARTUP_SETTLE: Duration = Duration::from_millis(500);
// Same as the library's listener: wait after an accept error, so the loop does not retry at full speed.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_secs(1);

// One ACL mode: the rules it installs, what the demo says about them, and the port its proxy uses.
struct Scenario {
	title: &'static str,
	rules: &'static str,
	effect: &'static [&'static str],
	allow: &'static [&'static str],
	deny: &'static [&'static str],
	port: u16,
	verdict: &'static str,
}

const SCENARIOS: [Scenario; 4] = [
	Scenario {
		title: "Scenario 1: Allow-List (default-deny)",
		rules: "allow 127.0.0.1/32, deny nothing",
		effect: &["only localhost can connect; all other IPs are rejected"],
		allow: &["127.0.0.1/32"],
		deny: &[],
		port: 18443,
		verdict: "allowed: client IP matches 127.0.0.1/32",
	},
	Scenario {
		title: "Scenario 2: Deny-List (default-allow)",
		rules: "allow nothing, deny 10.0.0.0/8",
		effect: &["everything is allowed except the 10.x.x.x range"],
		allow: &[],
		deny: &["10.0.0.0/8"],
		port: 18444,
		verdict: "allowed: 127.0.0.1 is not in deny list 10.0.0.0/8",
	},
	Scenario {
		title: "Scenario 3: Both Lists (deny-first)",
		rules: "allow 127.0.0.0/8, deny 127.0.0.1/32",
		effect: &[
			"deny is checked first, so 127.0.0.1 is blocked",
			"        even though it falls within the allow range",
		],
		allow: &["127.0.0.0/8"],
		deny: &["127.0.0.1/32"],
		port: 18445,
		verdict: "denied: 127.0.0.1 matches deny list, even though it's in allow range",
	},
	Scenario {
		title: "Scenario 4: Disabled (no rules)",
		rules: "allow nothing, deny nothing",
		effect: &["all traffic passes through (default when unconfigured)"],
		allow: &[],
		deny: &[],
		port: 18446,
		verdict: "allowed: no ACL rules configured",
	},
];

const SUMMARY: [&str; 11] = [
	"  Reduction supports CIDR-based IP access control with four modes:",
	"    1. Allow-list only  -> default-deny, only listed CIDRs pass",
	"    2. Deny-list only   -> default-allow, listed CIDRs blocked",
	"    3. Both lists       -> deny checked first, then allow, default-deny",
	"    4. Disabled         -> no rules, everything passes",
	"",
	"  Configure in config.toml:",
	"",
	"    [access]",
	"    allow = [\"10.0.0.0/24\", \"fd00::/64\"]",
	"    deny  = [\"10.0.0.99/32\"]",
];

#[tokio::main]
async fn main() -> Result<(), String> {
	rustls::crypto::aws_lc_rs::default_provider()
		.install_default()
		.map_err(|_| "install rustls crypto provider: a provider is already installed".to_owned())?;

	tracing_subscriber::registry()
		.with(support::output_layer(LIBRARY_LOG_LEVEL))
		.init();

	info!("Reduction - ACL (IP Allow/Deny) Demo");
	info!("=====================================");

	let dir = tempfile::tempdir().context("create temp dir")?;
	let dir_path = dir.path();

	generate_certs(dir_path)?;
	let config_path = dir_path.join("config.toml");
	// One backend serves the proxy of every scenario.
	start_backend(dir_path).await?;
	let connector = build_client_connector(dir_path)?;

	for scenario in &SCENARIOS {
		run_scenario(scenario, dir_path, &config_path, &connector).await?;
	}

	info!("-- Summary --");
	SUMMARY.iter().for_each(|line| info!("{line}"));

	info!("-- Demo Complete --");
	return Ok(());
}

fn parse_nets(cidrs: &[&str]) -> Result<Vec<IpNet>, String> {
	return cidrs
		.iter()
		.map(|cidr| cidr.parse::<IpNet>().context(&format!("CIDR {cidr}")))
		.collect();
}

fn announce(scenario: &Scenario) {
	info!("-- {} --", scenario.title);
	info!("  Rules: {}", scenario.rules);
	scenario.effect.iter().enumerate().for_each(|(i, line)| {
		let lead: &str = if i == 0 { "  Effect: " } else { "  " };
		info!("{lead}{line}");
	});
}

async fn run_scenario(
	scenario: &Scenario,
	dir: &Path,
	config_path: &Path,
	connector: &TlsConnector,
) -> Result<(), String> {
	announce(scenario);
	write_config(dir, config_path, scenario.port)?;
	let acl: AccessControl = AccessControl::new(parse_nets(scenario.allow)?, parse_nets(scenario.deny)?);
	start_proxy(config_path, acl).await?;
	tokio::time::sleep(STARTUP_SETTLE).await;

	let addr: SocketAddr = SocketAddr::new(LOOPBACK, scenario.port);
	let resp: String = send_request(connector, addr, "POST", "/api/echo", "hello").await;
	info!("  Request from 127.0.0.1 -> {resp}");
	info!("  ({})", scenario.verdict);
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

	info!("  [ok] Certificates generated");
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

fn write_config(dir: &Path, config_path: &Path, proxy_port: u16) -> Result<(), String> {
	let toml: String = format!(
		r#"[listen]
address = "127.0.0.1:{proxy_port}"
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

	let response_body: String = if body_str.is_empty() {
		format!(r#"{{"path":"{path}","method":"{method}"}}"#)
	} else {
		format!(r#"{{"path":"{path}","method":"{method}","received":"{body_str}"}}"#)
	};

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

async fn start_proxy(config_path: &Path, acl: AccessControl) -> Result<(), String> {
	let config: ReductionConfig = config::load_config(config_path).context("load demo config")?;

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

	let initial_state: ReloadableState = ReloadableState {
		router: Router::new(&config.routes),
		backend_pools: build_backend_pools(&config)?,
		acl,
	};

	let (_reloadable_tx, reloadable_rx) = watch::channel(initial_state);
	let (_health_tx, health_rx) = watch::channel(HealthState::new());
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
		circuit_breakers: CircuitBreakers::new(&config.circuit_breaker),
		metrics: ProxyMetrics::new(),
		shutdown: CancellationToken::new(),
		timeouts: TimeoutConfig::default(),
		proxy_config: ProxyConfig::default(),
		retry_config: RetryConfig::default(),
		client_auth: main.listen.client_auth,
		device_id_source: main.listen.device_id_source,
		http_authz: HttpAuthz::default(),
	}));

	let proxy_listener = reduction::transport::tcp::TcpListener::bind(main.listen.address, server_tls, None)
		.await
		.context(&format!("bind proxy {}", main.listen.address))?;

	tokio::spawn(async move {
		if let Err(e) = serve(proxy_listener, proxy_state, None, pending::<()>()).await {
			error!("proxy server stopped: {e}");
		}
	});
	return Ok(());
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

// This demo shows a refused or reset connection as a result, so each failure becomes the printed outcome.
async fn send_request(connector: &TlsConnector, addr: SocketAddr, method: &str, path: &str, body: &str) -> String {
	return match try_request(connector, addr, method, path, body).await {
		Ok(outcome) | Err(outcome) => outcome,
	};
}

async fn try_request(
	connector: &TlsConnector,
	addr: SocketAddr,
	method: &str,
	path: &str,
	body: &str,
) -> Result<String, String> {
	let tcp: TcpStream = TcpStream::connect(addr)
		.await
		.map_err(|e| format!("connection refused ({e})"))?;
	let server_name: ServerName<'static> = ServerName::IpAddress(addr.ip().into());
	let tls = connector
		.connect(server_name, tcp)
		.await
		.map_err(|e| format!("TLS handshake failed ({e})"))?;
	let io = TokioIo::new(tls);

	let (mut sender, conn) = http1::handshake(io).await.context("HTTP/1 handshake failed")?;
	tokio::spawn(conn);

	let req: Request<Body> = Request::builder()
		.method(method)
		.uri(path)
		.header("host", format!("127.0.0.1:{}", addr.port()))
		.body(Body::from(body.to_owned()))
		.context(&format!("build {method} {path}"))?;

	let response = sender.send_request(req).await.context("request failed")?;
	let status: StatusCode = response.status();
	let bytes = response
		.into_body()
		.collect()
		.await
		.context("response body failed")?
		.to_bytes();
	let body_str: String = String::from_utf8_lossy(&bytes).into_owned();

	return Ok(format!("{status} {body_str}"));
}
