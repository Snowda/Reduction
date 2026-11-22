// The egress listener: answer CONNECT with a policy check, one vetted dial, and a spliced tunnel.
use std::fmt::Display;
use std::net::SocketAddr;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::time::Duration;

use arrayvec::ArrayVec;
use http::header::ALLOW;
use http::{HeaderValue, Method, Request, Response};
use hyper::body::Incoming;
use hyper::upgrade::{self, OnUpgrade, Upgraded};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::join;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, Span, info, info_span, warn};

use super::authority::Target;
use super::denial::Denial;
use super::internal::InternalGuard;
use super::metrics::EgressMetrics;
use super::policy::{Policy, spawn_policy_reload};
use super::tunnel::{MAX_RESOLVED_ADDRS, dial, resolve, splice};
use super::uplink::Uplink;
use super::uplink_listener::{UplinkListener, bind_uplink_listener};
use super::uplink_tls::TlsWatch;
use crate::body::Body;
use crate::config::{EgressConfig, RateLimitConfig, ReductionConfig};
use crate::error::{ReductionError, Result};
use crate::proxy::relay::RelayStats;
use crate::proxy::server::{HeadLimits, serve_bounded};
use crate::ratelimit::RateLimit;
use crate::transport::listener::Listener;
use crate::transport::quic_listener::QuicListener;

const ALLOWED_METHOD: &str = "CONNECT";
// A client that sends no full CONNECT head in this time loses its connection.
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
// A CONNECT head is a request line and a few headers. 8 KiB is also the least hyper accepts.
const MAX_HEAD_BUF: usize = 8 * 1024;
pub const EGRESS_HEAD_LIMITS: HeadLimits = HeadLimits { timeout: Some(HEAD_TIMEOUT), max_buf: Some(MAX_HEAD_BUF) };

// Where an admitted tunnel goes: a TCP dial from here, or a stream to the remote gateway.
enum Outbound {
	Direct(TcpStream),
	Uplink(TokioIo<Upgraded>),
}

// A target that passed policy, with the tunnel slot it holds from admission to the end of the splice.
struct Admitted {
	target: Target,
	permit: OwnedSemaphorePermit,
}

pub struct Gateway {
	policy: watch::Receiver<Arc<Policy>>,
	rate: RateLimit,
	rate_sweep: Duration,
	tunnels: Arc<Semaphore>,
	connect_timeout: Duration,
	idle_timeout: Duration,
	metrics: EgressMetrics,
	shutdown: CancellationToken,
	// With an uplink the remote gateway resolves and dials. Without one, this gateway does.
	uplink: Option<Uplink>,
}

impl Gateway {
	#[must_use]
	pub fn new(
		config: &EgressConfig,
		rate: &RateLimitConfig,
		policy: watch::Receiver<Arc<Policy>>,
		metrics: EgressMetrics,
		shutdown: CancellationToken,
	) -> Self {
		return Self {
			policy,
			rate: RateLimit::new(rate.requests_per_second),
			rate_sweep: Duration::from_secs(rate.retain_interval_secs.get()),
			tunnels: Arc::new(Semaphore::new(
				usize::try_from(config.max_tunnels.get()).map_or(Semaphore::MAX_PERMITS, |max| max.min(Semaphore::MAX_PERMITS)),
			)),
			connect_timeout: Duration::from_secs(config.connect_timeout_secs.get()),
			idle_timeout: Duration::from_secs(config.idle_timeout_secs.get()),
			metrics,
			shutdown,
			uplink: None,
		};
	}

	#[must_use]
	pub fn with_uplink(self, uplink: Uplink) -> Self {
		return Self { uplink: Some(uplink), ..self };
	}

	// Every check that needs no network, in the order the log reports a refusal. A client outside the ACL
	// spends no rate budget, and the slot comes last, so a refused request never holds one.
	fn admit<B>(&self, policy: &Policy, client: SocketAddr, req: &Request<B>) -> StdResult<Admitted, Denial> {
		if policy.access.check(client.ip()).is_err() {
			return Err(Denial::ClientNotAllowed);
		}
		if self.rate.check(client.ip()).is_err() {
			return Err(Denial::RateLimited);
		}
		if req.method() != Method::CONNECT {
			return Err(Denial::MethodNotAllowed);
		}
		let authority: &str = req.uri().authority().map(|authority| authority.as_str()).ok_or(Denial::Malformed)?;
		let target: Target = Target::parse(authority)?;
		policy.allowlist.check(&target)?;
		let permit: OwnedSemaphorePermit = Arc::clone(&self.tunnels).try_acquire_owned().map_err(|_| Denial::AtCapacity)?;
		return Ok(Admitted { target, permit });
	}

	async fn connect(&self, guard: &InternalGuard, target: &Target) -> StdResult<TcpStream, Denial> {
		let addrs: ArrayVec<SocketAddr, MAX_RESOLVED_ADDRS> = resolve(target, guard).await?;
		return dial(&addrs, self.connect_timeout).await;
	}

	// The handler drops `req` before the first await, so the future holds no borrow of the request body.
	// One request sees one policy, even if a reload lands while it dials.
	pub async fn answer(self: Arc<Self>, client: SocketAddr, mut req: Request<Incoming>) -> Response<Body> {
		let policy: Arc<Policy> = Arc::clone(&self.policy.borrow());
		let admitted: Admitted = match Self::admit(&self, &policy, client, &req) {
			Ok(admitted) => admitted,
			Err(denial) => return self.refuse(denial, client, req.uri()),
		};
		let on_upgrade: OnUpgrade = upgrade::on(&mut req);
		drop(req);
		let outbound: StdResult<Outbound, Denial> = match &self.uplink {
			None => self.connect(&policy.guard, &admitted.target).await.map(Outbound::Direct),
			Some(uplink) => uplink.open(&admitted.target, self.connect_timeout).await.map(Outbound::Uplink),
		};
		return match outbound {
			Ok(Outbound::Direct(stream)) => self.open_tunnel(client, admitted, on_upgrade, stream),
			Ok(Outbound::Uplink(stream)) => self.open_tunnel(client, admitted, on_upgrade, stream),
			Err(denial) => self.refuse(denial, client, &admitted.target),
		};
	}

	fn open_tunnel<U>(self: Arc<Self>, client: SocketAddr, admitted: Admitted, on_upgrade: OnUpgrade, upstream: U) -> Response<Body>
	where
		U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
	{
		let span: Span = info_span!("egress_tunnel", %client, target = %admitted.target);
		span.in_scope(|| info!("egress tunnel open"));
		self.metrics.opened();
		tokio::spawn(self.tunnel(admitted.permit, on_upgrade, upstream).instrument(span));
		return Response::new(Body::empty());
	}

	// The tunnel keeps its slot until the splice ends.
	async fn tunnel<U: AsyncRead + AsyncWrite + Unpin>(self: Arc<Self>, permit: OwnedSemaphorePermit, on_upgrade: OnUpgrade, upstream: U) {
		let stats: Option<RelayStats> = self.relay(on_upgrade, upstream).await;
		self.metrics.closed(stats.as_ref());
		drop(permit);
	}

	async fn relay<U: AsyncRead + AsyncWrite + Unpin>(&self, on_upgrade: OnUpgrade, upstream: U) -> Option<RelayStats> {
		let client_io: Upgraded = match on_upgrade.await {
			Ok(upgraded) => upgraded,
			Err(err) => {
				warn!(error = %err, "egress upgrade failed");
				return None;
			}
		};
		return match splice(client_io, upstream, self.idle_timeout, self.shutdown.child_token()).await {
			Ok(stats) => {
				log_close(&stats);
				Some(stats)
			}
			Err(err) => {
				warn!(error = %err, "egress tunnel failed");
				None
			}
		};
	}

	// The audit record of a refusal, and the reply the client sees: the status and the denial label.
	fn refuse(&self, denial: Denial, client: SocketAddr, requested: &impl Display) -> Response<Body> {
		warn!(%client, requested = %requested, denial = denial.label(), "egress refused");
		self.metrics.denied(denial);
		let mut response: Response<Body> = Response::new(Body::from(denial.label()));
		*response.status_mut() = denial.status();
		if denial == Denial::MethodNotAllowed {
			response.headers_mut().insert(ALLOW, HeaderValue::from_static(ALLOWED_METHOD));
		}
		return response;
	}
}

// The tunnel span carries the client and the target.
fn log_close(stats: &RelayStats) {
	info!(
		bytes_up = stats.bytes_a_to_b,
		bytes_down = stats.bytes_b_to_a,
		duration_ms = u64::try_from(stats.duration.as_millis()).unwrap_or(u64::MAX),
		end = ?stats.end,
		"egress tunnel closed"
	);
}

// On each interval, drop the buckets that are full again, so the limiter keeps only active clients.
async fn sweep_rate_limits(gateway: Arc<Gateway>, shutdown: CancellationToken) {
	loop {
		tokio::select! {
			() = sleep(gateway.rate_sweep) => gateway.rate.retain_recent(),
			() = shutdown.cancelled() => return,
		}
	}
}

// Bind the egress listener and spawn its serve loop and its policy reload. Returns None when `[egress]` is
// absent: no section means no listener, so nothing accepts a CONNECT. Each config `config_rx` sends
// replaces the policy. The listen address, the limits and `[ratelimit]` stay as they were at start.
pub async fn spawn_egress(
	config_rx: watch::Receiver<ReductionConfig>,
	shutdown: &'static CancellationToken,
) -> Result<Option<JoinHandle<Result<()>>>> {
	let Some(egress) = config_rx.borrow().egress.clone() else {
		return Ok(None);
	};
	let rate: RateLimitConfig = config_rx.borrow().ratelimit.clone();
	let (policy_tx, policy_rx): (watch::Sender<Arc<Policy>>, watch::Receiver<Arc<Policy>>) =
		watch::channel(Arc::new(Policy::from_config(&config_rx.borrow())));
	let listener: Option<TcpListener> = match egress.listen {
		Some(listen) => Some(bind_clients(listen, egress.allow_hosts.len()).await?),
		None => None,
	};
	let local: Gateway = Gateway::new(&egress, &rate, policy_rx, EgressMetrics::global(), shutdown.child_token());
	let gateway: Gateway = match &egress.uplink {
		Some(uplink) => local.with_uplink(Uplink::new(uplink)?),
		None => local,
	};
	let bound: Option<UplinkListener> = egress
		.uplink_listener
		.as_ref()
		.map(|config| bind_uplink_listener(config, egress.max_tunnels, shutdown.child_token()))
		.transpose()?;
	let (uplinks, watch): (Option<QuicListener>, Option<TlsWatch>) =
		bound.map(|bound: UplinkListener| return (bound.quic, bound.watch)).unzip();
	let _reload: JoinHandle<()> = spawn_policy_reload(config_rx, policy_tx, shutdown);
	let serve = serve_gateway(listener, uplinks, gateway, EGRESS_HEAD_LIMITS, shutdown);
	// The listener's TLS files stay under watch while the gateway serves.
	return Ok(Some(tokio::spawn(async move {
		let _watch: Option<TlsWatch> = watch;
		return serve.await;
	})));
}

async fn bind_clients(listen: SocketAddr, hosts: usize) -> Result<TcpListener> {
	let listener: TcpListener = TcpListener::bind(listen).await?;
	info!(listen = %listener.local_addr()?, hosts, "egress gateway bound");
	return Ok(listener);
}

// Answer CONNECTs on `listener` and on `uplinks`, each when given, until `shutdown` fires. Then wait for
// open connections to drain. Both share one gateway, so one tunnel cap and one rate limiter.
pub async fn serve_gateway(
	listener: Option<TcpListener>,
	uplinks: Option<QuicListener>,
	gateway: Gateway,
	limits: HeadLimits,
	shutdown: &'static CancellationToken,
) -> Result<()> {
	let gateway: Arc<Gateway> = Arc::new(gateway);
	let _sweep: JoinHandle<()> = tokio::spawn(sweep_rate_limits(Arc::clone(&gateway), shutdown.child_token()));
	let (direct, uplinked): (Result<()>, Result<()>) = join!(
		serve_some(listener, Arc::clone(&gateway), limits, shutdown),
		serve_some(uplinks, gateway, limits, shutdown)
	);
	return direct.and(uplinked);
}

async fn serve_some<L: Listener>(
	listener: Option<L>,
	gateway: Arc<Gateway>,
	limits: HeadLimits,
	shutdown: &'static CancellationToken,
) -> Result<()> {
	return match listener {
		Some(listener) => serve_on(listener, gateway, limits, shutdown).await,
		None => Ok(()),
	};
}

async fn serve_on<L: Listener>(listener: L, gateway: Arc<Gateway>, limits: HeadLimits, shutdown: &'static CancellationToken) -> Result<()> {
	let make_handler = move |_: &L::Io, client: SocketAddr| {
		let gateway: Arc<Gateway> = Arc::clone(&gateway);
		// Path form: taint follows only exact calls, and it matches a method call on a temporary by name.
		return move |req: Request<Incoming>| Gateway::answer(Arc::clone(&gateway), client, req);
	};
	let signal = async move { shutdown.cancelled().await };
	return serve_bounded(listener, make_handler, signal, limits).await.map_err(ReductionError::from);
}

#[cfg(test)]
mod tests {
	use std::num::{NonZeroU16, NonZeroU32};
	use std::str::FromStr;

	use arrayvec::ArrayString;
	use ipnet::IpNet;
	use rcgen::{CertifiedKey, KeyPair, SanType};
	use tempfile::NamedTempFile;
	use tokio::net::UdpSocket;
	use tokio::time::timeout;

	use server_utils::ctx::Ctx;

	use super::*;
	use crate::acl::AccessControl;
	use crate::config::MAX_HOST_LEN;
	use crate::test_support::{LOOPBACK_ANY, LeafFiles, generate_ca, generate_signed_cert, leaf_files, write_pem};
	use crate::tls::certs::build_client_config;
	use crate::egress::metrics::testutil::Recorder;
	use crate::egress::testutil::{
		Ends, LOOPBACK_EXCEPTIONS, PAYLOAD, STEP_TIMEOUT, Started, connect, echo_server, echo_through, egress, launch_with,
		loopback_egress, open_access, policy, send, send_with,
	};

	// Time for a closed tunnel's task to drop its slot and record its close.
	const RELEASE_WAIT: Duration = Duration::from_millis(100);
	// A header twice the egress head buffer: hyper's default buffer takes it, the egress one does not.
	const OVERSIZED_HEADER_LEN: usize = 2 * MAX_HEAD_BUF;

	fn net(raw: &str) -> StdResult<IpNet, String> {
		return IpNet::from_str(raw).map_err(|err| format!("parse '{raw}': {err}"));
	}

	fn per_second(limit: u32) -> RateLimitConfig {
		return RateLimitConfig { requests_per_second: NonZeroU32::new(limit), ..RateLimitConfig::default() };
	}

	async fn launch(config: &EgressConfig, access: AccessControl, rate: &RateLimitConfig, limits: HeadLimits) -> StdResult<Started, String> {
		return launch_with(config, access, rate, limits, Ends::default()).await;
	}

	async fn start(config: &EgressConfig, access: AccessControl) -> StdResult<SocketAddr, String> {
		return Ok(launch(config, access, &RateLimitConfig::default(), EGRESS_HEAD_LIMITS).await?.addr);
	}

	// The same request with and without the loopback exception: only the exception opens the tunnel.
	#[tokio::test]
	async fn the_internal_check_alone_decides_a_loopback_tunnel() -> StdResult<(), String> {
		let echo: SocketAddr = echo_server().await?;
		let authority: String = format!("localhost:{}", echo.port());

		let guarded: SocketAddr = start(&loopback_egress(echo, "")?, open_access()).await?;
		let (refused, _) = connect(guarded, &authority).await?;
		assert_eq!(refused.status, 403, "loopback is internal without an exception: {}", refused.text);

		let open: SocketAddr = start(&loopback_egress(echo, LOOPBACK_EXCEPTIONS)?, open_access()).await?;
		let (head, mut tunnel) = connect(open, &authority).await?;
		assert_eq!(head.status, 200, "the exception admits loopback: {}", head.text);
		assert_eq!(echo_through(&mut tunnel).await?, PAYLOAD, "bytes cross the tunnel unchanged both ways");
		return Ok(());
	}

	#[tokio::test]
	async fn policy_refusals_answer_with_their_status_and_label() -> StdResult<(), String> {
		let config: EgressConfig = egress("allow_hosts = [\"github.com\"]")?;
		let gateway: SocketAddr = start(&config, open_access()).await?;
		let statuses: [u16; 3] = [
			connect(gateway, "gitlab.com:443").await?.0.status,
			connect(gateway, "github.com:22").await?.0.status,
			connect(gateway, "[::1]:443").await?.0.status,
		];
		assert_eq!(statuses, [403, 403, 403], "unlisted host, unlisted port, IPv6 literal");
		let (get, _) = send(gateway, "GET http://github.com/ HTTP/1.1").await?;
		assert_eq!(get.status, 405, "{}", get.text);
		assert!(get.text.to_ascii_lowercase().contains("allow: connect"), "405 names CONNECT: {}", get.text);
		return Ok(());
	}

	#[tokio::test]
	async fn a_client_outside_the_access_list_is_refused_first() -> StdResult<(), String> {
		let config: EgressConfig = egress("allow_hosts = [\"github.com\"]")?;
		let gateway: SocketAddr = start(&config, AccessControl::new(vec![], vec![net("127.0.0.0/8")?])).await?;
		let (head, _) = send(gateway, "GET http://github.com/ HTTP/1.1").await?;
		assert_eq!(head.status, 403, "the ACL runs before the method check: {}", head.text);
		return Ok(());
	}

	// One slot: the gateway refuses a second tunnel while the first is open, and admits it once the first closes.
	#[tokio::test]
	async fn max_tunnels_caps_open_tunnels_and_frees_a_slot_on_close() -> StdResult<(), String> {
		let echo: SocketAddr = echo_server().await?;
		let authority: String = format!("localhost:{}", echo.port());
		let config: EgressConfig = loopback_egress(echo, &format!("{LOOPBACK_EXCEPTIONS}\nmax_tunnels = 1"))?;
		let gateway: SocketAddr = start(&config, open_access()).await?;

		let (first, mut tunnel) = connect(gateway, &authority).await?;
		assert_eq!(first.status, 200, "{}", first.text);
		assert_eq!(echo_through(&mut tunnel).await?, PAYLOAD);
		let (second, _) = connect(gateway, &authority).await?;
		assert_eq!(second.status, 503, "the only slot is taken: {}", second.text);

		drop(tunnel);
		sleep(RELEASE_WAIT).await;
		let (third, _) = connect(gateway, &authority).await?;
		assert_eq!(third.status, 200, "the closed tunnel gave its slot back: {}", third.text);
		return Ok(());
	}

	#[test]
	fn admit_orders_its_checks_and_refuses_without_a_slot() -> StdResult<(), String> {
		let config: EgressConfig = egress("allow_hosts = [\"github.com\"]\nmax_tunnels = 1")?;
		let (_policy_tx, policy_rx): (watch::Sender<Arc<Policy>>, watch::Receiver<Arc<Policy>>) =
			watch::channel(policy(&config, open_access()));
		let gateway: Gateway =
			Gateway::new(&config, &RateLimitConfig::default(), policy_rx, Recorder::new().metrics(), CancellationToken::new());
		let live: Arc<Policy> = Arc::clone(&gateway.policy.borrow());
		let client: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 40000));
		let request = |method: Method, uri: &str| {
			return Request::builder().method(method).uri(uri).body(()).ctx("build");
		};
		let verdict = |req: &Request<()>| return gateway.admit(&live, client, req).map(|admitted| admitted.target);

		assert_eq!(verdict(&request(Method::CONNECT, "/no-authority")?).err(), Some(Denial::Malformed));
		assert_eq!(verdict(&request(Method::POST, "github.com:443")?).err(), Some(Denial::MethodNotAllowed));
		assert_eq!(verdict(&request(Method::CONNECT, "gitlab.com:443")?).err(), Some(Denial::HostNotAllowed));
		assert_eq!(gateway.tunnels.available_permits(), 1, "refusals take no slot");

		let held: Admitted = gateway.admit(&live, client, &request(Method::CONNECT, "GitHub.com:443")?).map_err(|d| format!("{d:?}"))?;
		assert_eq!(held.target.to_string(), "github.com:443");
		assert_eq!(verdict(&request(Method::CONNECT, "github.com:443")?).err(), Some(Denial::AtCapacity));
		drop(held);
		assert_eq!(gateway.tunnels.available_permits(), 1, "dropping the admission frees its slot");
		return Ok(());
	}

	#[tokio::test]
	async fn an_unreachable_target_is_a_gateway_error() -> StdResult<(), String> {
		let dead: TcpListener = TcpListener::bind("127.0.0.1:0").await.ctx("bind")?;
		let dead_addr: SocketAddr = dead.local_addr().ctx("addr")?;
		drop(dead);
		let config: EgressConfig = loopback_egress(dead_addr, LOOPBACK_EXCEPTIONS)?;
		let gateway: SocketAddr = start(&config, open_access()).await?;
		let (head, _) = connect(gateway, &format!("localhost:{}", dead_addr.port())).await?;
		assert_eq!(head.status, 502, "nothing listens behind the vetted address: {}", head.text);
		return Ok(());
	}

	// The same two requests with and without `[ratelimit]`: only the limit turns the second into a 429.
	#[tokio::test]
	async fn the_rate_limit_alone_refuses_a_second_request_in_the_same_second() -> StdResult<(), String> {
		let config: EgressConfig = egress("allow_hosts = [\"github.com\"]")?;
		let limited: SocketAddr = launch(&config, open_access(), &per_second(1), EGRESS_HEAD_LIMITS).await?.addr;
		let open: SocketAddr = start(&config, open_access()).await?;
		let limited_statuses: [u16; 2] =
			[connect(limited, "gitlab.com:443").await?.0.status, connect(limited, "gitlab.com:443").await?.0.status];
		let open_statuses: [u16; 2] = [connect(open, "gitlab.com:443").await?.0.status, connect(open, "gitlab.com:443").await?.0.status];
		assert_eq!(limited_statuses, [403, 429], "one request a second: the second spends no policy check");
		assert_eq!(open_statuses, [403, 403], "without a limit both reach the allowlist");
		return Ok(());
	}

	// A client outside the ACL spends no budget: its refusal stays a 403 however often it asks.
	#[tokio::test]
	async fn a_client_outside_the_access_list_spends_no_rate_budget() -> StdResult<(), String> {
		let config: EgressConfig = egress("allow_hosts = [\"github.com\"]")?;
		let fenced: AccessControl = AccessControl::new(vec![], vec![net("127.0.0.0/8")?]);
		let gateway: SocketAddr = launch(&config, fenced, &per_second(1), EGRESS_HEAD_LIMITS).await?.addr;
		let statuses: [u16; 2] = [connect(gateway, "github.com:443").await?.0.status, connect(gateway, "github.com:443").await?.0.status];
		assert_eq!(statuses, [403, 403], "the ACL refuses before the limiter counts");
		return Ok(());
	}

	// A new policy on the channel changes the next verdict on a gateway that already serves.
	#[tokio::test]
	async fn a_published_policy_applies_to_the_next_request() -> StdResult<(), String> {
		let echo: SocketAddr = echo_server().await?;
		let authority: String = format!("localhost:{}", echo.port());
		let started: Started = launch(&loopback_egress(echo, "")?, open_access(), &RateLimitConfig::default(), EGRESS_HEAD_LIMITS).await?;
		let (before, _) = connect(started.addr, &authority).await?;
		started
			.policy_tx
			.send(policy(&loopback_egress(echo, LOOPBACK_EXCEPTIONS)?, open_access()))
			.map_err(|_| "the gateway dropped its policy receiver".to_owned())?;
		let (after, mut tunnel) = connect(started.addr, &authority).await?;
		assert_eq!([before.status, after.status], [403, 200], "{} / {}", before.text, after.text);
		assert_eq!(echo_through(&mut tunnel).await?, PAYLOAD);
		return Ok(());
	}

	// The same oversized head against the egress bounds and against hyper's defaults.
	#[tokio::test]
	async fn the_head_bound_alone_refuses_an_oversized_connect() -> StdResult<(), String> {
		let config: EgressConfig = egress("allow_hosts = [\"github.com\"]")?;
		let rate: RateLimitConfig = RateLimitConfig::default();
		let bounded: SocketAddr = launch(&config, open_access(), &rate, EGRESS_HEAD_LIMITS).await?.addr;
		let unbounded: SocketAddr = launch(&config, open_access(), &rate, HeadLimits::default()).await?.addr;
		let padding: String = format!("X-Padding: {}\r\n", "a".repeat(OVERSIZED_HEADER_LEN));
		let line: &str = "CONNECT gitlab.com:443 HTTP/1.1";
		let (refused, _) = send_with(bounded, line, &padding).await?;
		let (passed, _) = send_with(unbounded, line, &padding).await?;
		assert_eq!([refused.status, passed.status], [431, 403], "{} / {}", refused.text, passed.text);
		return Ok(());
	}

	// The same proxy config with and without `[egress]`: only the section binds a gateway.
	#[tokio::test]
	async fn only_an_egress_section_spawns_a_gateway() -> StdResult<(), String> {
		let base: &str = "[listen]\naddress = \"127.0.0.1:8443\"\ntransport = \"quic\"\n\n[tls.server.manual]\ncert_path = \"c.crt\"\nkey_path = \"c.key\"\nca_cert_path = \"ca.crt\"\n";
		let parse = |raw: &str| return toml::from_str::<ReductionConfig>(raw).ctx("parse config");
		let shutdown: &'static CancellationToken = Box::leak(Box::new(CancellationToken::new()));
		let (_bare_tx, bare_rx): (watch::Sender<ReductionConfig>, watch::Receiver<ReductionConfig>) = watch::channel(parse(base)?);
		let absent: Option<JoinHandle<Result<()>>> = spawn_egress(bare_rx, shutdown).await.ctx("spawn without egress")?;
		assert!(absent.is_none(), "no [egress] section must bind no listener");

		let with_section: ReductionConfig = parse(&format!("{base}\n[egress]\nlisten = \"127.0.0.1:0\"\nallow_hosts = [\"github.com\"]\n"))?;
		let (_egress_tx, egress_rx): (watch::Sender<ReductionConfig>, watch::Receiver<ReductionConfig>) = watch::channel(with_section);
		let served: JoinHandle<Result<()>> =
			spawn_egress(egress_rx, shutdown).await.ctx("spawn with egress")?.ok_or("[egress] bound no listener")?;
		shutdown.cancel();
		let ended: Result<()> = timeout(STEP_TIMEOUT, served).await.map_err(|_| "the gateway outlived shutdown".to_owned())?.ctx("join")?;
		assert!(ended.is_ok(), "a shutdown drain is a clean end: {ended:?}");
		return Ok(());
	}

	// spawn_egress binds the address in the config, so the test takes a free UDP port first.
	async fn free_udp_port() -> StdResult<SocketAddr, String> {
		let probe: UdpSocket = UdpSocket::bind(LOOPBACK_ANY).await.ctx("bind probe")?;
		return probe.local_addr().ctx("probe addr");
	}

	// A remote with no `listen`: an `[egress]` with only its uplink listener, and the inner TLS that reaches it.
	struct UplinkOnly {
		config: ReductionConfig,
		inner_tls: rustls::ClientConfig,
		quic: SocketAddr,
		_files: [LeafFiles; 2],
		_ca: NamedTempFile,
	}

	async fn uplink_only(echo: SocketAddr) -> StdResult<UplinkOnly, String> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca: CertifiedKey<KeyPair> = generate_ca()?;
		let remote: LeafFiles =
			generate_signed_cert(&ca, "egress-remote", vec![SanType::IpAddress(LOOPBACK_ANY.ip())]).and_then(leaf_files)?;
		let inner: LeafFiles = generate_signed_cert(&ca, "egress-inner", vec![]).and_then(leaf_files)?;
		let ca_file: NamedTempFile = write_pem(&ca.cert.pem())?;
		let (inner_tls, _resolver, _verifier) =
			build_client_config(inner.cert.path(), inner.key.path(), ca_file.path()).ctx("inner TLS")?;
		let quic: SocketAddr = free_udp_port().await?;
		// TOML literal strings, so a Windows path needs no escapes.
		let text: String = format!(
			"[egress]\nallow_hosts = [\"localhost\"]\nallow_ports = [{}]\n{LOOPBACK_EXCEPTIONS}\n\n[egress.uplink_listener]\nlisten = \"{quic}\"\ncert_path = '{}'\nkey_path = '{}'\nca_cert_path = '{}'\n",
			echo.port(),
			remote.cert.path().display(),
			remote.key.path().display(),
			ca_file.path().display(),
		);
		let config: ReductionConfig = toml::from_str(&text).ctx("parse uplink-only config")?;
		return Ok(UplinkOnly { config, inner_tls, quic, _files: [remote, inner], _ca: ca_file });
	}

	// The startup path with no TCP listen: the uplink listener alone carries a tunnel, and the gateway serves on.
	#[tokio::test]
	async fn a_remote_with_no_listen_serves_tunnels_on_its_uplink_listener() -> StdResult<(), String> {
		let echo: SocketAddr = echo_server().await?;
		let remote: UplinkOnly = uplink_only(echo).await?;
		assert!(remote.config.egress.as_ref().is_some_and(|egress| egress.listen.is_none()), "the fixture has no listen");
		remote.config.validate().ctx("an uplink listener alone is a valid gateway")?;
		let shutdown: &'static CancellationToken = Box::leak(Box::new(CancellationToken::new()));
		let (_config_tx, config_rx): (watch::Sender<ReductionConfig>, watch::Receiver<ReductionConfig>) =
			watch::channel(remote.config);
		let served: JoinHandle<Result<()>> =
			spawn_egress(config_rx, shutdown).await.ctx("spawn")?.ok_or("[egress] spawned no gateway")?;

		let name: ArrayString<MAX_HOST_LEN> = ArrayString::from("127.0.0.1").ctx("server name")?;
		let uplink: Uplink = Uplink::with_tls(remote.quic, name, remote.inner_tls).ctx("uplink")?;
		let target: Target = Target { host: ArrayString::from("localhost").ctx("host")?, port: NonZeroU16::new(echo.port()).ok_or("zero port")? };
		let mut tunnel: TokioIo<Upgraded> = uplink.open(&target, STEP_TIMEOUT).await.map_err(|denial| format!("open: {denial:?}"))?;
		assert_eq!(echo_through(&mut tunnel).await?, PAYLOAD, "the remote dials the echo for the uplink");
		assert!(!served.is_finished(), "an absent TCP listener must not end the gateway");

		shutdown.cancel();
		let ended: Result<()> = timeout(STEP_TIMEOUT, served).await.map_err(|_| "the gateway outlived shutdown".to_owned())?.ctx("join")?;
		assert!(ended.is_ok(), "a shutdown drain is a clean end: {ended:?}");
		return Ok(());
	}

	// Refusals count by reason, and a closed tunnel leaves the open count and adds its bytes both ways.
	#[tokio::test]
	async fn metrics_count_refusals_tunnels_and_bytes() -> StdResult<(), String> {
		let echo: SocketAddr = echo_server().await?;
		let authority: String = format!("localhost:{}", echo.port());
		let config: EgressConfig = loopback_egress(echo, LOOPBACK_EXCEPTIONS)?;
		let started: Started = launch(&config, open_access(), &RateLimitConfig::default(), EGRESS_HEAD_LIMITS).await?;
		let recorder: &Recorder = &started.recorder;
		let payload_len: i64 = i64::try_from(PAYLOAD.len()).ctx("payload length")?;

		connect(started.addr, "gitlab.com:443").await?;
		let (head, mut tunnel) = connect(started.addr, &authority).await?;
		assert_eq!(head.status, 200, "{}", head.text);
		assert_eq!(recorder.sum("egress.tunnels.active", None)?, 1, "the tunnel is open");
		echo_through(&mut tunnel).await?;
		drop(tunnel);
		sleep(RELEASE_WAIT).await;

		assert_eq!(recorder.sum("egress.denials", Some(("reason", "host_not_allowed")))?, 1);
		assert_eq!(recorder.sum("egress.tunnels.opened", None)?, 1);
		assert_eq!(recorder.sum("egress.tunnels.active", None)?, 0, "the closed tunnel left the open count");
		assert_eq!(recorder.sum("egress.bytes", Some(("direction", "up")))?, payload_len);
		assert_eq!(recorder.sum("egress.bytes", Some(("direction", "down")))?, payload_len, "the echo sends it all back");
		return Ok(());
	}
}
