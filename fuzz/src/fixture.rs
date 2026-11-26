//! The live targets that the harnesses drive. Each process builds them once, on their own runtime.
//! There are three echo backends: cleartext HTTP/1.1, TLS HTTP/1.1 and TLS HTTP/2.
//! A ProxyState routes `/` to the cleartext backend, a listener redirects HTTP to HTTPS, and a health endpoint is Ready.

use std::future::{Future, pending};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU64;
use std::sync::{Arc, OnceLock};

use ahash::AHashMap;
use arrayvec::ArrayString;
use http::{Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use rcgen::{CertificateParams, KeyPair};
use reduction::acl::AccessControl;
use reduction::balancer::BackendPool;
use reduction::body::Body;
use reduction::circuit::CircuitBreakers;
use reduction::config::{
	BackendConfig, BackendProtocol, BackendScheme, CircuitBreakerConfig, ClientAuthPolicy, DeviceIdSource, HealthEndpointConfig, HttpRedirectConfig, MAX_BACKEND_ID_LEN, ProxyConfig, ReductionConfig,
	NonZeroDuration, RetryConfig, RouteConfig, Stickiness, TimeoutConfig, TransportKind,
};
use reduction::egress::spawn_egress;
use reduction::health::HealthState;
use reduction::health_endpoint::{Readiness, leaked_readiness, spawn_health_endpoint};
use reduction::metrics::ProxyMetrics;
use reduction::proxy::server::serve_with;
use reduction::proxy::{ConnPool, HttpAuthz, ProxyState, ReloadableState, Router};
use reduction::ratelimit::RateLimit;
use reduction::redirect::spawn_http_redirect;
use reduction::label_intern::LabelInterner;
use reduction::snapshot_map::SnapshotMap;
use reduction::transport::listener::Listener;
use reduction::tunnel::revocation::RevocationSet;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::copy;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::watch;
use tokio_rustls::server::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;

use crate::request;

/// Every echo reply starts with this, so a success proves that the backend wrote the body.
pub const ECHO_MARKER: &[u8] = b"reduction-fuzz-echo\n";
/// The canonical host the redirect listener points every client at.
pub const REDIRECT_HOST: &str = "fuzz.example";
/// The one allowlisted name that resolves to an exempt address, so a CONNECT to it can open a tunnel.
pub const EGRESS_HOST: &str = "localhost";
/// Allowlisted, but an internal address outside `allow_private_cidrs`: the gateway must refuse it as private.
pub const EGRESS_INTERNAL_HOST: &str = "127.0.0.2";
/// The gateway's dial limit. A refusal that comes from the dial arrives at most this long after the head.
pub const EGRESS_CONNECT_TIMEOUT_SECS: u64 = 2;
const LOOPBACK: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
const TLS_HOST: &str = "localhost";
const ALPN: [&[u8]; 2] = [b"h2", b"http/1.1"];
const PLAIN_ID: &str = "plain";
const ROUTE_PREFIX: &str = "/";
const WORKER_THREADS: usize = 2;
const QUEUE_DEPTH: u32 = 1000;
// Short timeouts, so an input that stalls the proxy costs seconds, not the 30 s production default.
const FUZZ_TIMEOUT_SECS: NonZeroU64 = match NonZeroU64::new(2) {
	Some(secs) => secs,
	None => NonZeroU64::MIN,
};
// An attempt starts only while the request deadline is more than one connect timeout away (remaining_budget).
const FUZZ_REQUEST_SECS: NonZeroU64 = match NonZeroU64::new(5) {
	Some(secs) => secs,
	None => NonZeroU64::MIN,
};

/// The backends `upstream_send` picks from with its first input byte.
pub struct Backends {
	pub plain_h1: BackendConfig,
	pub tls_h1: BackendConfig,
	pub tls_h2: BackendConfig,
}

/// States routing `/` to one TLS backend each, so the raw plane classifies GET and HEAD as well.
pub struct RawStates {
	pub h1: &'static ProxyState,
	pub h2: &'static ProxyState,
}

/// The egress gateway and the raw byte echo it may tunnel to: `localhost` on `echo_port` is its only allowed target.
pub struct Egress {
	pub gateway: SocketAddr,
	pub echo_port: u16,
}

pub struct Fixture {
	runtime: Runtime,
	pub state: &'static ProxyState,
	pub raw: RawStates,
	pub backends: Backends,
	pub redirect: SocketAddr,
	pub egress: Egress,
	pub health: SocketAddr,
}

impl Fixture {
	/// Run `future` to completion on the fixture runtime, where the backends and listeners live.
	pub fn block_on<F: Future>(&self, future: F) -> F::Output {
		return self.runtime.block_on(future);
	}

	/// The backend that `selector` names, one of three.
	#[must_use]
	pub const fn backend(&self, selector: u8) -> &BackendConfig {
		return match selector % 3 {
			0 => &self.backends.plain_h1,
			1 => &self.backends.tls_h1,
			_ => &self.backends.tls_h2,
		};
	}
}

static FIXTURE: OnceLock<Result<Fixture, String>> = OnceLock::new();

/// The process-wide fixture, started on first use; Err says why it could not start.
pub fn get() -> Result<&'static Fixture, &'static str> {
	return FIXTURE.get_or_init(|| return start()).as_ref().map_err(String::as_str);
}

fn start() -> Result<Fixture, String> {
	let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
	let runtime: Runtime = Builder::new_multi_thread()
		.worker_threads(WORKER_THREADS)
		.enable_all()
		.build()
		.map_err(|e| format!("fuzz runtime: {e}"))?;
	let (state, raw, backends, redirect) = runtime.block_on(build())?;
	let egress: Egress = runtime.block_on(spawn_gateway())?;
	let health: SocketAddr = runtime.block_on(spawn_health())?;
	return Ok(Fixture {
		runtime,
		state,
		raw,
		backends,
		redirect,
		egress,
		health,
	});
}

async fn build() -> Result<(&'static ProxyState, RawStates, Backends, SocketAddr), String> {
	let (server_tls, client_tls) = tls_pair()?;
	let plain: SocketAddr = spawn_echo(bind().await?)?;
	let tls: SocketAddr = spawn_tls_echo(bind().await?, TlsAcceptor::from(server_tls))?;
	let backends: Backends = Backends {
		plain_h1: plain_backend(plain)?,
		tls_h1: tls_backend("tls-h1", tls)?.with_protocol(BackendProtocol::Http1),
		tls_h2: tls_backend("tls-h2", tls)?,
	};
	let state: &'static ProxyState = proxy_state(routing(&backends.plain_h1)?, Arc::clone(&client_tls));
	let raw: RawStates = RawStates {
		h1: proxy_state(routing(&backends.tls_h1)?, Arc::clone(&client_tls)),
		h2: proxy_state(routing(&backends.tls_h2)?, client_tls),
	};
	return Ok((state, raw, backends, spawn_redirect().await?));
}

async fn bind() -> Result<TcpListener, String> {
	return TcpListener::bind(LOOPBACK).await.map_err(|e| format!("bind loopback: {e}"));
}

fn plain_backend(addr: SocketAddr) -> Result<BackendConfig, String> {
	return BackendConfig::new(PLAIN_ID, addr, 1.0, TransportKind::Tcp)
		.map(|backend| return backend.with_scheme(BackendScheme::Http))
		.map_err(|e| format!("plain backend: {e}"));
}

fn tls_backend(id: &str, addr: SocketAddr) -> Result<BackendConfig, String> {
	return BackendConfig::new(id, addr, 1.0, TransportKind::Tcp)
		.and_then(|backend| return backend.with_host(TLS_HOST))
		.map_err(|e| format!("{id} backend: {e}"));
}

/// The reply every echo backend sends: the marker, the method, the path and query, then the body it read.
#[must_use]
pub fn echo_of(method: &Method, path_and_query: &str, body: &[u8]) -> Vec<u8> {
	return [ECHO_MARKER, method.as_str().as_bytes(), b"\n", path_and_query.as_bytes(), b"\n", body].concat();
}

async fn echo(req: Request<Incoming>) -> Response<Body> {
	let (parts, incoming) = req.into_parts();
	let Ok(body) = incoming.collect().await else {
		let mut failed: Response<Body> = Response::new(Body::empty());
		*failed.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
		return failed;
	};
	let path_and_query: &str = request::path_and_query(&parts.uri);
	let reply: Vec<u8> = echo_of(&parts.method, path_and_query, &body.to_bytes());
	return Response::new(Body::from(reply));
}

fn spawn_echo(listener: TcpListener) -> Result<SocketAddr, String> {
	let addr: SocketAddr = listener.local_addr().map_err(|e| format!("echo addr: {e}"))?;
	tokio::spawn(serve_with(listener, |_: &TcpStream, _: SocketAddr| return echo, pending::<()>()));
	return Ok(addr);
}

fn spawn_tls_echo(tcp: TcpListener, acceptor: TlsAcceptor) -> Result<SocketAddr, String> {
	let addr: SocketAddr = tcp.local_addr().map_err(|e| format!("tls echo addr: {e}"))?;
	let listener: TlsListener = TlsListener { tcp, acceptor };
	tokio::spawn(serve_with(listener, |_: &TlsStream<TcpStream>, _: SocketAddr| return echo, pending::<()>()));
	return Ok(addr);
}

// The listener contract over TLS: accept a TCP stream, then finish its handshake.
struct TlsListener {
	tcp: TcpListener,
	acceptor: TlsAcceptor,
}

impl Listener for TlsListener {
	type Io = TlsStream<TcpStream>;

	async fn accept(&mut self) -> (Self::Io, SocketAddr) {
		loop {
			let Ok((stream, peer)) = self.tcp.accept().await else {
				continue;
			};
			if let Ok(tls) = self.acceptor.accept(stream).await {
				return (tls, peer);
			}
		}
	}

	fn local_addr(&self) -> io::Result<SocketAddr> {
		return self.tcp.local_addr();
	}
}

// A self-signed localhost server config and a client config that trusts only that certificate.
fn tls_pair() -> Result<(Arc<ServerConfig>, Arc<ClientConfig>), String> {
	let key: KeyPair = KeyPair::generate().map_err(|e| format!("tls key: {e}"))?;
	let cert: CertificateDer<'static> = CertificateParams::new(vec![TLS_HOST.to_owned()])
		.and_then(|params| return params.self_signed(&key))
		.map(CertificateDer::from)
		.map_err(|e| format!("tls cert: {e}"))?;
	let key_der: PrivateKeyDer<'static> = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
	let mut server: ServerConfig = ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(vec![cert.clone()], key_der)
		.map_err(|e| format!("tls server config: {e}"))?;
	server.alpn_protocols = ALPN.iter().map(|proto| return proto.to_vec()).collect();
	let mut roots: RootCertStore = RootCertStore::empty();
	roots.add(cert).map_err(|e| format!("tls root: {e}"))?;
	let mut client: ClientConfig = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	client.alpn_protocols = ALPN.iter().map(|proto| return proto.to_vec()).collect();
	return Ok((Arc::new(server), Arc::new(client)));
}

fn routing(backend: &BackendConfig) -> Result<ReloadableState, String> {
	let pool_id: ArrayString<MAX_BACKEND_ID_LEN> =
		ArrayString::from(backend.id.as_str()).map_err(|e| format!("pool id: {e}"))?;
	let route: RouteConfig = RouteConfig {
		path_prefix: ArrayString::from(ROUTE_PREFIX).map_err(|e| format!("route prefix: {e}"))?,
		backend_id: Some(pool_id),
		timeout: None,
		is_wakeable: false,
		stickiness: Stickiness::Identity,
		allows_spill_on_exhaustion: false,
		split: Vec::new(),
	};
	let pool: BackendPool = BackendPool::new(vec![backend.clone()]).map_err(|e| format!("backend pool: {e}"))?;
	return Ok(ReloadableState {
		router: Router::new(&[route]),
		backend_pools: AHashMap::from_iter([(pool_id, pool)]),
		acl: AccessControl::new(vec![], vec![]),
	});
}

// The production ProxyState shape, with short timeouts and peers admitted without a name.
fn proxy_state(reloadable: ReloadableState, client_tls: Arc<ClientConfig>) -> &'static ProxyState {
	let timeouts: TimeoutConfig = TimeoutConfig {
		connect: NonZeroDuration::from_secs(FUZZ_TIMEOUT_SECS),
		handshake: NonZeroDuration::from_secs(FUZZ_TIMEOUT_SECS),
		request: NonZeroDuration::from_secs(FUZZ_REQUEST_SECS),
		response_idle: NonZeroDuration::from_secs(FUZZ_TIMEOUT_SECS),
	};
	return Box::leak(Box::new(ProxyState {
		reloadable: watch::channel(reloadable).1,
		revocation: watch::channel(RevocationSet::default()).1,
		tls_connector: TlsConnector::from(Arc::clone(&client_tls)),
		client_tls_config: client_tls,
		health_rx: watch::channel(HealthState::new()).1,
		conn_pool: ConnPool::new(),
		rate_limiter: RateLimit::new(None),
		queues: SnapshotMap::new(),
		labels: LabelInterner::new(),
		default_queue_depth: QUEUE_DEPTH,
		metrics: ProxyMetrics::new(),
		circuit_breakers: CircuitBreakers::new(&CircuitBreakerConfig::default()),
		shutdown: CancellationToken::new(),
		timeouts,
		proxy_config: ProxyConfig::default(),
		retry_config: RetryConfig::default(),
		client_auth: ClientAuthPolicy::Disabled,
		device_id_source: DeviceIdSource::UidOrCn,
		http_authz: HttpAuthz::default(),
	}));
}

// spawn_http_redirect binds its configured address itself, so reserve a free port first.
async fn spawn_redirect() -> Result<SocketAddr, String> {
	let listen: SocketAddr = bind()
		.await?
		.local_addr()
		.map_err(|e| format!("redirect addr: {e}"))?;
	let config: HttpRedirectConfig = HttpRedirectConfig {
		is_enabled: true,
		listen,
		to_host: ArrayString::from(REDIRECT_HOST).map_err(|e| format!("redirect host: {e}"))?,
	};
	spawn_http_redirect(&config, CancellationToken::new())
		.await
		.map_err(|e| format!("redirect listener: {e}"))?;
	return Ok(listen);
}

// spawn_health_endpoint binds its configured address itself, so reserve a free port first, as for the redirect.
// Readiness is Ready, so both probe paths answer 200.
async fn spawn_health() -> Result<SocketAddr, String> {
	let listen: SocketAddr = bind().await?.local_addr().map_err(|e| format!("health addr: {e}"))?;
	let config: HealthEndpointConfig = HealthEndpointConfig { is_enabled: true, listen };
	let readiness: &'static Readiness = leaked_readiness();
	readiness.set_ready();
	spawn_health_endpoint(&config, readiness, CancellationToken::new())
		.await
		.map_err(|e| format!("health endpoint: {e}"))?
		.ok_or("the endpoint is enabled, so it must start")?;
	return Ok(listen);
}

// A TCP echo that returns every byte until EOF, then closes: the far end of an egress tunnel.
fn spawn_raw_echo(listener: TcpListener) -> Result<SocketAddr, String> {
	let addr: SocketAddr = listener.local_addr().map_err(|e| format!("raw echo addr: {e}"))?;
	tokio::spawn(async move {
		while let Ok((mut stream, _)) = listener.accept().await {
			tokio::spawn(async move {
				let (mut read, mut write) = stream.split();
				let _ = copy(&mut read, &mut write).await;
			});
		}
	});
	return Ok(addr);
}

// The egress config the gateway runs: `localhost` on the echo port is allowed. `127.0.0.2` is allowlisted
// but is not an exempt internal range, so the internal-address check alone refuses it.
fn egress_toml(listen: SocketAddr, echo_port: u16) -> String {
	return format!(
		"[egress]\nlisten = \"{listen}\"\nallow_hosts = [\"{EGRESS_HOST}\", \"{EGRESS_INTERNAL_HOST}\"]\n\
		 allow_ports = [{echo_port}]\nallow_private_cidrs = [\"127.0.0.1/32\", \"::1/128\"]\n\
		 connect_timeout = \"{EGRESS_CONNECT_TIMEOUT_SECS}s\"\nidle_timeout = \"2s\"\nmax_tunnels = 1024\n\
		 [access]\nallow = [\"127.0.0.0/8\", \"::1/128\"]\n"
	);
}

// spawn_egress binds its configured address itself, so reserve a free port first, as for the redirect.
async fn spawn_gateway() -> Result<Egress, String> {
	let echo_port: u16 = spawn_raw_echo(bind().await?)?.port();
	// `localhost` resolves to [::1] first and the gateway dials in order. Windows retries a SYN to a closed port
	// for about 2 s, which uses the whole connect timeout, so the echo listens on both loopbacks.
	let v6: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), echo_port);
	spawn_raw_echo(TcpListener::bind(v6).await.map_err(|e| format!("raw echo on {v6}: {e}"))?)?;
	let gateway: SocketAddr = bind().await?.local_addr().map_err(|e| format!("gateway addr: {e}"))?;
	let config: ReductionConfig =
		toml::from_str(&egress_toml(gateway, echo_port)).map_err(|e| format!("egress config: {e}"))?;
	config.validate().map_err(|e| format!("egress config is invalid: {e}"))?;
	let (_config_tx, config_rx): (watch::Sender<ReductionConfig>, watch::Receiver<ReductionConfig>) = watch::channel(config);
	spawn_egress(config_rx, CancellationToken::new())
		.await
		.map_err(|e| format!("egress gateway: {e}"))?
		.ok_or("the config has [egress], so the gateway must start")?;
	return Ok(Egress { gateway, echo_port });
}

#[cfg(test)]
mod tests {
	use rustls::pki_types::ServerName;
	use tokio::io::AsyncWriteExt;
	use tokio_rustls::client::TlsStream as ClientTlsStream;

	use super::*;

	const NOT_TLS: &[u8] = b"GET / HTTP/1.1\r\n\r\n";
	const ALPN_H2: &[u8] = b"h2";

	// A cleartext peer fails the handshake, then a TLS client on the same listener must still complete one.
	// io::Error::other is a function path, not a closure, so no error arm adds an uncovered line.
	async fn handshake_after_a_failed_one(addr: SocketAddr, connector: TlsConnector) -> io::Result<Option<Vec<u8>>> {
		let mut cleartext: TcpStream = TcpStream::connect(addr).await?;
		cleartext.write_all(NOT_TLS).await?;
		cleartext.shutdown().await?;
		let name: ServerName<'static> = ServerName::try_from(TLS_HOST).map_err(io::Error::other)?;
		let tls: ClientTlsStream<TcpStream> = connector.connect(name, TcpStream::connect(addr).await?).await?;
		return Ok(tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec));
	}

	// The listener accepts in order. So the TLS client gets its handshake only after the cleartext peer failed.
	#[test]
	fn a_failed_handshake_leaves_the_tls_echo_accepting() -> io::Result<()> {
		let fixture: &Fixture = get().map_err(io::Error::other)?;
		let connector: TlsConnector = TlsConnector::from(Arc::clone(&fixture.state.client_tls_config));
		let alpn: Option<Vec<u8>> =
			fixture.block_on(handshake_after_a_failed_one(fixture.backends.tls_h1.address, connector))?;
		assert_eq!(alpn.as_deref(), Some(ALPN_H2), "the TLS echo must offer h2 first, as the client does");
		return Ok(());
	}

	#[test]
	fn the_tls_listener_reports_the_address_it_accepts_on() -> io::Result<()> {
		let fixture: &Fixture = get().map_err(io::Error::other)?;
		let (server_tls, _) = tls_pair().map_err(io::Error::other)?;
		let tcp: TcpListener = fixture.block_on(bind()).map_err(io::Error::other)?;
		let bound: SocketAddr = tcp.local_addr()?;
		let listener: TlsListener = TlsListener {
			tcp,
			acceptor: TlsAcceptor::from(server_tls),
		};
		assert_eq!(listener.local_addr()?, bound, "local_addr must be the address the TCP listener bound");
		return Ok(());
	}

	#[test]
	fn the_echo_reply_carries_marker_method_target_and_body() {
		let reply: Vec<u8> = echo_of(&Method::POST, "/api/echo?x=1", b"hello");
		assert_eq!(reply, b"reduction-fuzz-echo\nPOST\n/api/echo?x=1\nhello".to_vec());
	}

	#[test]
	fn the_selector_cycles_through_all_three_backends() -> Result<(), String> {
		let fixture: &Fixture = get()?;
		let ids: Vec<&str> = (0..3).map(|selector: u8| return fixture.backend(selector).id.as_str()).collect();
		assert_eq!(ids, vec![PLAIN_ID, "tls-h1", "tls-h2"]);
		return Ok(());
	}
}
