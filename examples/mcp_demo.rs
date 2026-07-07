// Example/demo code, outside the production lint gate (which lints only --lib --bins). Demos use
// unwrap/expect/panic, `&str` .to_string(), and lossy casts freely to stay readable; relax those
// restriction lints here rather than clutter the demo with error plumbing.
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::str_to_string)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arrayvec::ArrayString;
use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::http::{Request, Response, StatusCode};
use axum::routing::any;
use http_body_util::BodyExt;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::TlsConnector;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;

use dashmap::DashMap;
use reduction::balancer::BackendPool;
use reduction::circuit::CircuitBreakers;
use reduction::config::{self, BackendConfig, CircuitBreakerConfig, ReductionConfig, TimeoutConfig};
use reduction::health::{Availability, BackendHealth, HealthBroadcast, HealthState};
use reduction::metrics::ProxyMetrics;
use reduction::acl::AccessControl;
use reduction::cache::ResponseCache;
use reduction::config::CacheConfig;
use reduction::proxy::{ConnPool, ProxyState, ReloadableState, Router, proxy_handler};
use reduction::ratelimit::RateLimit;
use reduction::tls;

const PROXY_PORT: u16 = 18443;
const BACKEND_A_PORT: u16 = 19443;
const BACKEND_B_PORT: u16 = 19444;

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    println!("Reduction - MCP Reverse Proxy Demo");
    println!("===================================\n");

    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let dir_path = dir.path();

    // -- Phase 1: TLS certificates --
    println!("-- Phase 1: TLS Certificate Generation --\n");
    generate_certs(dir_path);
    let config_path = dir_path.join("config.toml");
    write_config(dir_path, &config_path, &[("/mcp", "mcp-servers")], true);
    println!("  Written to {}\n", dir_path.display());

    // -- Phase 2: MCP data plane --
    println!("-- Phase 2: MCP Data Plane --\n");
    let handles = start_services(dir_path, &config_path).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("  Backend A (:{BACKEND_A_PORT}), Backend B (:{BACKEND_B_PORT}), Proxy (:{PROXY_PORT}) started\n");

    let client_connector = build_client_connector(dir_path);
    let proxy_addr: SocketAddr = ([127, 0, 0, 1], PROXY_PORT).into();

    // MCP initialize
    println!("  --- MCP initialize ---");
    let init_request = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"reduction-demo","version":"0.1.0"}}}"#;
    let resp = send_mcp_request(&client_connector, proxy_addr, init_request).await;
    println!("  -> {resp}\n");

    // MCP tools/list
    println!("  --- MCP tools/list ---");
    let list_request = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
    let resp = send_mcp_request(&client_connector, proxy_addr, list_request).await;
    println!("  -> {resp}\n");

    // MCP tools/call — echo
    println!("  --- MCP tools/call (echo) ---");
    let call_request = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello from M2M client"}}}"#;
    let resp = send_mcp_request(&client_connector, proxy_addr, call_request).await;
    println!("  -> {resp}\n");

    // MCP tools/call — add
    println!("  --- MCP tools/call (add) ---");
    let call_request = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"add","arguments":{"a":17,"b":25}}}"#;
    let resp = send_mcp_request(&client_connector, proxy_addr, call_request).await;
    println!("  -> {resp}\n");

    // Send multiple requests to show load balancing distribution.
    // All requests come from 127.0.0.1, so rendezvous hashing gives
    // deterministic affinity to one backend — this is by design.
    println!("  --- Load balancing (10 requests, same client IP) ---");
    let mut distribution: HashMap<String, u32> = HashMap::new();
    for i in 5..15 {
        let req = format!(
            r#"{{"jsonrpc":"2.0","id":{i},"method":"tools/call","params":{{"name":"echo","arguments":{{"message":"req-{i}"}}}}}}"#,
        );
        let resp = send_mcp_request(&client_connector, proxy_addr, &req).await;
        let backend_id = extract_backend_id(&resp);
        *distribution.entry(backend_id).or_insert(0) += 1;
    }
    for (backend, count) in &distribution {
        println!("  {backend}: {count} requests");
    }

    // -- Phase 3: Health-aware failover --
    println!("\n-- Phase 3: Health-Aware Failover --\n");
    demonstrate_failover(&handles.health_tx, &client_connector, proxy_addr).await;

    // -- Phase 4: Config hot-reload --
    println!("\n-- Phase 4: Config Hot-Reload --\n");
    demonstrate_config_reload(dir_path, &config_path, &client_connector, proxy_addr).await;

    println!("\n-- Demo Complete --");
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
                    format!(
                        r#"{{"content":[{{"type":"text","text":"{message}"}}],"_backend":"{backend_name}"}}"#,
                    )
                }
                "add" => {
                    let a = extract_nested_number(body, "a");
                    let b = extract_nested_number(body, "b");
                    let sum: f64 = a + b;
                    format!(
                        r#"{{"content":[{{"type":"text","text":"{sum}"}}],"_backend":"{backend_name}"}}"#,
                    )
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
            return json[value_start..value_start + end].to_string();
        }
    }
    return String::new();
}

fn extract_json_number(json: &str, key: &str) -> String {
    let pattern = format!(r#""{key}":"#);
    if let Some(start) = json.find(&pattern) {
        let value_start = start + pattern.len();
        let rest = &json[value_start..];
        let end = rest.find(|c: char| !c.is_ascii_digit() && c != '.' && c != '-')
            .unwrap_or(rest.len());
        return rest[..end].to_string();
    }
    return "0".to_string();
}

fn extract_nested_string(json: &str, key: &str) -> String {
    let pattern = format!(r#""{key}":""#);
    if let Some(start) = json.rfind(&pattern) {
        let value_start = start + pattern.len();
        if let Some(end) = json[value_start..].find('"') {
            return json[value_start..value_start + end].to_string();
        }
    }
    return String::new();
}

fn extract_nested_number(json: &str, key: &str) -> f64 {
    let pattern = format!(r#""{key}":"#);
    if let Some(start) = json.rfind(&pattern) {
        let value_start = start + pattern.len();
        let rest = &json[value_start..];
        let end = rest.find(|c: char| !c.is_ascii_digit() && c != '.' && c != '-')
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
        return "unknown".to_string();
    }
    return backend;
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

    println!("  [ok] CA certificate");
    println!("  [ok] Server certificate (SAN: 127.0.0.1)");
    println!("  [ok] Client certificate (mTLS)");
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
    let issuer = rcgen::Issuer::from_ca_cert_der(ca_cert.der(), ca_key).unwrap();
    let cert = params.signed_by(&key, &issuer).unwrap();
    (cert, key)
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

fn path_str(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

fn write_config(dir: &Path, config_path: &Path, routes: &[(&str, &str)], two_backends: bool) {
    let mut toml = format!(
r#"[listen]
address = "127.0.0.1:{PROXY_PORT}"
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

    std::fs::write(config_path, toml).unwrap();
}

// ---------------------------------------------------------------------------
// Backend MCP server (simulates upstream MCP services)
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

async fn mcp_backend_handler(
    axum::extract::State(backend_name): axum::extract::State<String>,
    req: Request<Body>,
) -> Response<Body> {
    let body_bytes = req.into_body().collect().await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let body_str: String = String::from_utf8_lossy(&body_bytes).into_owned();

    let response_body: String = mcp_handle_request(&backend_name, &body_str);

    return Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(response_body))
        .unwrap();
}

async fn start_mcp_backend(dir: &Path, port: u16, name: &str) {
    let (backend_tls_config, _) = tls::build_server_config(
        &dir.join("server.crt"),
        &dir.join("server.key"),
        &dir.join("ca.crt"),
    ).unwrap();
    let backend_tls: Arc<rustls::ServerConfig> = Arc::new(backend_tls_config);

    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let demo_listener = DemoTlsListener {
        listener,
        acceptor: tokio_rustls::TlsAcceptor::from(backend_tls),
    };

    let app = axum::Router::new()
        .fallback(any(mcp_backend_handler))
        .with_state(name.to_string());

    tokio::spawn(async move {
        axum::serve(demo_listener, app).await.unwrap();
    });
}

// ---------------------------------------------------------------------------
// Service startup
// ---------------------------------------------------------------------------

struct DemoHandles {
    health_tx: watch::Sender<HealthState>,
    _watcher: config::watcher::ConfigWatcher,
}

fn build_backend_pools(config: &ReductionConfig) -> HashMap<ArrayString<256>, BackendPool> {
    let mut pools: HashMap<ArrayString<256>, BackendPool> = HashMap::new();
    for route in &config.routes {
        let backends: Vec<BackendConfig> = config.backends.iter()
            .filter(|b| b.pool.as_str() == route.backend_id.as_str())
            .cloned()
            .collect();
        if !backends.is_empty() && !pools.contains_key(route.backend_id.as_str()) {
            let pool: BackendPool = BackendPool::new(
                backends,
                config.balancer.jitter_factor,
            ).expect("too many backends");
            pools.insert(route.backend_id, pool);
        }
    }
    return pools;
}

async fn start_services(dir: &Path, config_path: &Path) -> DemoHandles {
    let config: ReductionConfig = config::load_config(config_path).unwrap();

    // -- MCP Backends --
    start_mcp_backend(dir, BACKEND_A_PORT, "mcp-backend-a").await;
    start_mcp_backend(dir, BACKEND_B_PORT, "mcp-backend-b").await;

    // -- Proxy --
    let (server_tls_config, _) = tls::build_server_config(
        &config.tls.server.as_manual().unwrap().cert_path,
        &config.tls.server.as_manual().unwrap().key_path,
        &config.tls.server.as_manual().unwrap().ca_cert_path,
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

    let (reloadable_tx, reloadable_rx) = watch::channel(initial_state);
    let (health_tx, health_rx) = watch::channel(HealthState::new());

    let proxy_state: Arc<ProxyState> = Arc::new(ProxyState {
        reloadable: reloadable_rx,
        tls_connector,
        client_tls_config: client_tls,
        health_rx,
        conn_pool: ConnPool::new(),
        acl: AccessControl::new(vec![], vec![]),
        rate_limiter: RateLimit::new(u32::MAX).unwrap(),
        queues: DashMap::new(),
        default_queue_depth: config.balancer.queue_depth,
        metrics: ProxyMetrics::new(),
        circuit_breakers: CircuitBreakers::new(&CircuitBreakerConfig::default()),
        shutdown: CancellationToken::new(),
        timeouts: TimeoutConfig::default(),
        proxy_config: reduction::config::ProxyConfig::default(),
        compression_config: reduction::config::CompressionConfig::default(),
        retry_config: reduction::config::RetryConfig::default(),
        cache_config: CacheConfig::default(),
        response_cache: ResponseCache::new(&CacheConfig::default()),
    });

    let (config_tx, config_rx) = watch::channel(config.clone());
    let watcher = config::watcher::ConfigWatcher::new(
        config_path.to_path_buf(), config_tx,
    ).unwrap();

    tokio::spawn({
        let mut config_rx = config_rx;
        async move {
            while config_rx.changed().await.is_ok() {
                let cfg: ReductionConfig = config_rx.borrow_and_update().clone();
                let new_state: ReloadableState = ReloadableState {
                    router: Router::new(&cfg.routes),
                    backend_pools: build_backend_pools(&cfg),
                };
                if reloadable_tx.send(new_state).is_err() {
                    return;
                }
            }
        }
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

    return DemoHandles { health_tx, _watcher: watcher };
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

async fn send_mcp_request(
    connector: &TlsConnector,
    addr: SocketAddr,
    body: &str,
) -> String {
    let tcp: TcpStream = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("127.0.0.1").unwrap().to_owned();
    let tls = connector.connect(server_name, tcp).await.unwrap();
    let io = TokioIo::new(tls);

    let (mut sender, conn) = http1::handshake(io).await.unwrap();
    tokio::spawn(conn);

    let req: Request<Body> = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", format!("127.0.0.1:{}", addr.port()))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = sender.send_request(req).await.unwrap();
    let status: StatusCode = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_str: String = String::from_utf8_lossy(&bytes).into_owned();

    return format!("{status} {body_str}");
}

// ---------------------------------------------------------------------------
// Phase 3: Health-aware failover
// ---------------------------------------------------------------------------

async fn demonstrate_failover(
    health_tx: &watch::Sender<HealthState>,
    connector: &TlsConnector,
    proxy_addr: SocketAddr,
) {
    // Mark backend-a as heavily loaded
    health_tx.send_modify(|state| {
        state.update(HealthBroadcast {
            entries: vec![
                BackendHealth { backend_id: ArrayString::from("mcp-a").unwrap(), load: 0.95, latency_ms: 800, availability: Availability::Online },
                BackendHealth { backend_id: ArrayString::from("mcp-b").unwrap(), load: 0.1, latency_ms: 20, availability: Availability::Online },
            ],
        });
    });
    println!("  Pushed health update: mcp-a loaded (0.95), mcp-b healthy (0.1)");

    let mut distribution: HashMap<String, u32> = HashMap::new();
    for i in 20..30 {
        let req = format!(
            r#"{{"jsonrpc":"2.0","id":{i},"method":"tools/call","params":{{"name":"echo","arguments":{{"message":"failover-{i}"}}}}}}"#,
        );
        let resp = send_mcp_request(connector, proxy_addr, &req).await;
        let backend_id = extract_backend_id(&resp);
        *distribution.entry(backend_id).or_insert(0) += 1;
    }
    println!("  After health update (10 requests):");
    for (backend, count) in &distribution {
        println!("    {backend}: {count} requests");
    }

    // Mark backend-a as unavailable
    health_tx.send_modify(|state| {
        state.update(HealthBroadcast {
            entries: vec![
                BackendHealth { backend_id: ArrayString::from("mcp-a").unwrap(), load: 0.0, latency_ms: 0, availability: Availability::Offline },
                BackendHealth { backend_id: ArrayString::from("mcp-b").unwrap(), load: 0.3, latency_ms: 50, availability: Availability::Online },
            ],
        });
    });
    println!("\n  Pushed health update: mcp-a DOWN, mcp-b healthy");

    let mut distribution: HashMap<String, u32> = HashMap::new();
    for i in 30..40 {
        let req = format!(
            r#"{{"jsonrpc":"2.0","id":{i},"method":"tools/call","params":{{"name":"echo","arguments":{{"message":"down-{i}"}}}}}}"#,
        );
        let resp = send_mcp_request(connector, proxy_addr, &req).await;
        let backend_id = extract_backend_id(&resp);
        *distribution.entry(backend_id).or_insert(0) += 1;
    }
    println!("  After failover (10 requests):");
    for (backend, count) in &distribution {
        println!("    {backend}: {count} requests");
    }
}

// ---------------------------------------------------------------------------
// Phase 4: Config hot-reload
// ---------------------------------------------------------------------------

async fn demonstrate_config_reload(
    dir: &Path,
    config_path: &Path,
    connector: &TlsConnector,
    proxy_addr: SocketAddr,
) {
    // Add a new /mcp/v2 route via config file modification
    write_config(dir, config_path, &[("/mcp/v2", "mcp-servers"), ("/mcp", "mcp-servers")], true);
    println!("  Config updated: added /mcp/v2 route");

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Send request to the new route
    let req = r#"{"jsonrpc":"2.0","id":50,"method":"tools/list","params":{}}"#;
    let resp = send_mcp_request_with_path(connector, proxy_addr, "/mcp/v2", req).await;
    println!("  POST /mcp/v2 tools/list -> {resp}");

    // Original route still works
    let resp = send_mcp_request(connector, proxy_addr, req).await;
    println!("  POST /mcp    tools/list -> {resp}");
}

async fn send_mcp_request_with_path(
    connector: &TlsConnector,
    addr: SocketAddr,
    path: &str,
    body: &str,
) -> String {
    let tcp: TcpStream = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("127.0.0.1").unwrap().to_owned();
    let tls = connector.connect(server_name, tcp).await.unwrap();
    let io = TokioIo::new(tls);

    let (mut sender, conn) = http1::handshake(io).await.unwrap();
    tokio::spawn(conn);

    let req: Request<Body> = Request::builder()
        .method("POST")
        .uri(path)
        .header("host", format!("127.0.0.1:{}", addr.port()))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = sender.send_request(req).await.unwrap();
    let status: StatusCode = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_str: String = String::from_utf8_lossy(&bytes).into_owned();

    return format!("{status} {body_str}");
}
