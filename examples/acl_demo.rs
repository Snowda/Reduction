use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::http::{Request, Response, StatusCode};
use axum::routing::any;
use dashmap::DashMap;
use http_body_util::BodyExt;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use ipnet::IpNet;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::TlsConnector;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;

use reduction::acl::AccessControl;
use reduction::balancer::BackendPool;
use reduction::circuit::CircuitBreakers;
use reduction::config::{self, BackendConfig, ReductionConfig, TimeoutConfig};
use reduction::health::HealthState;
use reduction::metrics::ProxyMetrics;
use reduction::cache::ResponseCache;
use reduction::config::CacheConfig;
use reduction::proxy::{ConnPool, ProxyState, ReloadableState, Router, proxy_handler};
use reduction::ratelimit::RateLimit;
use reduction::tls;

const BACKEND_PORT: u16 = 19443;

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    println!("Reduction - ACL (IP Allow/Deny) Demo");
    println!("=====================================\n");

    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let dir_path = dir.path();

    generate_certs(dir_path);
    let config_path = dir_path.join("config.toml");

    // -- Scenario 1: Allow-list only --
    println!("-- Scenario 1: Allow-List (default-deny) --\n");
    println!("  Rules: allow 127.0.0.1/32, deny nothing");
    println!("  Effect: only localhost can connect; all other IPs are rejected\n");

    let port1: u16 = 18443;
    write_config(dir_path, &config_path, port1);
    let allow: Vec<IpNet> = vec!["127.0.0.1/32".parse().unwrap()];
    let deny: Vec<IpNet> = vec![];
    start_proxy(dir_path, &config_path, AccessControl::new(allow, deny)).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let connector = build_client_connector(dir_path);
    let addr: SocketAddr = ([127, 0, 0, 1], port1).into();

    let resp = send_request(&connector, addr, "POST", "/api/echo", "hello").await;
    println!("  Request from 127.0.0.1 -> {resp}");
    println!("  (allowed: client IP matches 127.0.0.1/32)\n");

    // -- Scenario 2: Deny-list only --
    println!("-- Scenario 2: Deny-List (default-allow) --\n");
    println!("  Rules: allow nothing, deny 10.0.0.0/8");
    println!("  Effect: everything is allowed except the 10.x.x.x range\n");

    let port2: u16 = 18444;
    write_config(dir_path, &config_path, port2);
    let allow: Vec<IpNet> = vec![];
    let deny: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
    start_proxy(dir_path, &config_path, AccessControl::new(allow, deny)).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let addr: SocketAddr = ([127, 0, 0, 1], port2).into();
    let resp = send_request(&connector, addr, "POST", "/api/echo", "hello").await;
    println!("  Request from 127.0.0.1 -> {resp}");
    println!("  (allowed: 127.0.0.1 is not in deny list 10.0.0.0/8)\n");

    // -- Scenario 3: Both lists (deny takes precedence) --
    println!("-- Scenario 3: Both Lists (deny-first) --\n");
    println!("  Rules: allow 127.0.0.0/8, deny 127.0.0.1/32");
    println!("  Effect: deny is checked first, so 127.0.0.1 is blocked");
    println!("          even though it falls within the allow range\n");

    let port3: u16 = 18445;
    write_config(dir_path, &config_path, port3);
    let allow: Vec<IpNet> = vec!["127.0.0.0/8".parse().unwrap()];
    let deny: Vec<IpNet> = vec!["127.0.0.1/32".parse().unwrap()];
    start_proxy(dir_path, &config_path, AccessControl::new(allow, deny)).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let addr: SocketAddr = ([127, 0, 0, 1], port3).into();
    let resp = send_request(&connector, addr, "POST", "/api/echo", "hello").await;
    println!("  Request from 127.0.0.1 -> {resp}");
    println!("  (denied: 127.0.0.1 matches deny list, even though it's in allow range)\n");

    // -- Scenario 4: Disabled (no rules) --
    println!("-- Scenario 4: Disabled (no rules) --\n");
    println!("  Rules: allow nothing, deny nothing");
    println!("  Effect: all traffic passes through (default when unconfigured)\n");

    let port4: u16 = 18446;
    write_config(dir_path, &config_path, port4);
    start_proxy(dir_path, &config_path, AccessControl::new(vec![], vec![])).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let addr: SocketAddr = ([127, 0, 0, 1], port4).into();
    let resp = send_request(&connector, addr, "POST", "/api/echo", "hello").await;
    println!("  Request from 127.0.0.1 -> {resp}");
    println!("  (allowed: no ACL rules configured)\n");

    // -- Summary --
    println!("-- Summary --\n");
    println!("  Reduction supports CIDR-based IP access control with four modes:");
    println!("    1. Allow-list only  -> default-deny, only listed CIDRs pass");
    println!("    2. Deny-list only   -> default-allow, listed CIDRs blocked");
    println!("    3. Both lists       -> deny checked first, then allow, default-deny");
    println!("    4. Disabled         -> no rules, everything passes");
    println!();
    println!("  Configure in config.toml:");
    println!();
    println!("    [access]");
    println!("    allow = [\"10.0.0.0/24\", \"fd00::/64\"]");
    println!("    deny  = [\"10.0.0.99/32\"]");

    println!("\n-- Demo Complete --");
}

// ---------------------------------------------------------------------------
// Certificate generation
// ---------------------------------------------------------------------------

fn generate_certs(dir: &Path) {
    let (ca_cert, ca_key) = generate_ca();
    let (server_cert, server_key) = generate_signed_cert(
        &ca_cert, &ca_key, "Reduction Server",
        vec![SanType::IpAddress(IpAddr::from([127, 0, 0, 1]))],
    );
    let (client_cert, client_key) = generate_signed_cert(
        &ca_cert, &ca_key, "Reduction Client", vec![],
    );

    std::fs::write(dir.join("ca.crt"), ca_cert.pem()).unwrap();
    std::fs::write(dir.join("server.crt"), server_cert.pem()).unwrap();
    std::fs::write(dir.join("server.key"), server_key.serialize_pem()).unwrap();
    std::fs::write(dir.join("client.crt"), client_cert.pem()).unwrap();
    std::fs::write(dir.join("client.key"), client_key.serialize_pem()).unwrap();

    println!("  [ok] Certificates generated\n");
}

fn generate_ca() -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.distinguished_name.push(DnType::CommonName, "Reduction Demo CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert, key)
}

fn generate_signed_cert(
    ca_cert: &rcgen::Certificate,
    ca_key: &KeyPair,
    cn: &str,
    sans: Vec<SanType>,
) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.distinguished_name.push(DnType::CommonName, cn);
    params.subject_alt_names = sans;
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, ca_cert, ca_key).unwrap();
    (cert, key)
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

fn path_str(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

fn write_config(dir: &Path, config_path: &Path, proxy_port: u16) {
    let toml: String = format!(
r#"[listen]
address = "127.0.0.1:{proxy_port}"
transport = "tcp"

[tls.server]
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
    std::fs::write(config_path, toml).unwrap();
}

// ---------------------------------------------------------------------------
// Backend server
// ---------------------------------------------------------------------------

struct DemoTlsListener {
    listener: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
}

impl axum::serve::Listener for DemoTlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, addr) = self.listener.accept().await.unwrap();
            match self.acceptor.accept(stream).await {
                Ok(tls) => return (tls, addr),
                Err(_) => continue,
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        return self.listener.local_addr();
    }
}

async fn backend_handler(req: Request<Body>) -> Response<Body> {
    let path: String = req.uri().path().to_string();
    let method: String = req.method().to_string();
    let body_bytes = req.into_body().collect().await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let body_str: String = String::from_utf8_lossy(&body_bytes).into_owned();

    let response_body: String = if body_str.is_empty() {
        format!(r#"{{"path":"{path}","method":"{method}"}}"#)
    } else {
        format!(r#"{{"path":"{path}","method":"{method}","received":"{body_str}"}}"#)
    };

    return Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(response_body))
        .unwrap();
}

// ---------------------------------------------------------------------------
// Service startup
// ---------------------------------------------------------------------------

static BACKEND_STARTED: std::sync::Once = std::sync::Once::new();

fn build_backend_pools(config: &ReductionConfig) -> HashMap<String, BackendPool> {
    let mut pools: HashMap<String, BackendPool> = HashMap::new();
    for route in &config.routes {
        let backends: Vec<BackendConfig> = config.backends.iter()
            .filter(|b| b.pool == route.backend_id)
            .cloned()
            .collect();
        if !backends.is_empty() && !pools.contains_key(&route.backend_id) {
            let pool: BackendPool = BackendPool::new(
                backends,
                config.balancer.jitter_factor,
            ).expect("too many backends");
            pools.insert(route.backend_id.clone(), pool);
        }
    }
    return pools;
}

async fn start_proxy(dir: &Path, config_path: &Path, acl: AccessControl) {
    let config: ReductionConfig = config::load_config(config_path).unwrap();

    // Start the shared backend once
    BACKEND_STARTED.call_once(|| {
        let dir_owned = dir.to_path_buf();
        tokio::spawn(async move {
            let (backend_tls_config, _) = tls::build_server_config(
                &dir_owned.join("server.crt"),
                &dir_owned.join("server.key"),
                &dir_owned.join("ca.crt"),
            ).unwrap();
            let backend_tls: Arc<rustls::ServerConfig> = Arc::new(backend_tls_config);
            let backend_addr: SocketAddr = ([127, 0, 0, 1], BACKEND_PORT).into();
            let backend_listener = tokio::net::TcpListener::bind(backend_addr).await.unwrap();
            let demo_listener = DemoTlsListener {
                listener: backend_listener,
                acceptor: tokio_rustls::TlsAcceptor::from(backend_tls),
            };
            let backend_app = axum::Router::new().fallback(any(backend_handler));
            axum::serve(demo_listener, backend_app).await.unwrap();
        });
    });

    // -- Proxy --
    let (server_tls_config, _) = tls::build_server_config(
        &config.tls.server.cert_path,
        &config.tls.server.key_path,
        &config.tls.server.ca_cert_path,
    ).unwrap();
    let server_tls: Arc<rustls::ServerConfig> = Arc::new(server_tls_config);

    let (client_tls_config, _) = tls::build_client_config(
        &config.tls.client.cert_path,
        &config.tls.client.key_path,
        &config.tls.client.ca_cert_path,
    ).unwrap();
    let client_tls: Arc<rustls::ClientConfig> = Arc::new(client_tls_config);

    let tls_connector: TlsConnector = TlsConnector::from(client_tls.clone());

    let initial_state: ReloadableState = ReloadableState {
        router: Router::new(&config.routes),
        backend_pools: build_backend_pools(&config),
    };

    let (_reloadable_tx, reloadable_rx) = watch::channel(initial_state);
    let (_health_tx, health_rx) = watch::channel(HealthState::new());

    let proxy_state: Arc<ProxyState> = Arc::new(ProxyState {
        reloadable: reloadable_rx,
        tls_connector,
        client_tls_config: client_tls,
        health_rx,
        conn_pool: ConnPool::new(),
        acl,
        rate_limiter: RateLimit::new(u32::MAX).unwrap(),
        queues: DashMap::new(),
        default_queue_depth: config.balancer.queue_depth,
        circuit_breakers: CircuitBreakers::new(&config.circuit_breaker),
        metrics: ProxyMetrics::new(),
        shutdown: CancellationToken::new(),
        timeouts: TimeoutConfig::default(),
        proxy_config: reduction::config::ProxyConfig::default(),
        compression_config: reduction::config::CompressionConfig::default(),
        retry_config: reduction::config::RetryConfig::default(),
        cache_config: CacheConfig::default(),
        response_cache: ResponseCache::new(&CacheConfig::default()),
    });

    let app = axum::Router::new()
        .fallback(any(proxy_handler))
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
        .with_state(proxy_state)
        .into_make_service_with_connect_info::<reduction::transport::ConnectAddr>();

    let proxy_listener = reduction::transport::tcp::TcpListener::bind(
        config.listen.address, server_tls,
    ).await.unwrap();

    tokio::spawn(async move {
        axum::serve(proxy_listener, app).await.unwrap();
    });
}

// ---------------------------------------------------------------------------
// mTLS client
// ---------------------------------------------------------------------------

fn build_client_connector(dir: &Path) -> TlsConnector {
    let (client_config, _): (rustls::ClientConfig, _) = tls::build_client_config(
        &dir.join("client.crt"),
        &dir.join("client.key"),
        &dir.join("ca.crt"),
    ).unwrap();
    return TlsConnector::from(Arc::new(client_config));
}

async fn send_request(
    connector: &TlsConnector,
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: &str,
) -> String {
    let tcp: TcpStream = match TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => return format!("connection refused ({e})"),
    };
    let server_name = ServerName::try_from("127.0.0.1").unwrap().to_owned();
    let tls = match connector.connect(server_name, tcp).await {
        Ok(s) => s,
        Err(e) => return format!("TLS handshake failed ({e})"),
    };
    let io = TokioIo::new(tls);

    let (mut sender, conn) = http1::handshake(io).await.unwrap();
    tokio::spawn(conn);

    let req: Request<Body> = Request::builder()
        .method(method)
        .uri(path)
        .header("host", format!("127.0.0.1:{}", addr.port()))
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = sender.send_request(req).await.unwrap();
    let status: StatusCode = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_str: String = String::from_utf8_lossy(&bytes).into_owned();

    return format!("{status} {body_str}");
}
