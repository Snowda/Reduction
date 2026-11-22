// The inner end of a paired uplink: each admitted tunnel becomes one CONNECT on a QUIC stream to a remote gateway.
use std::fmt::{Display, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::result::Result as StdResult;
use std::str;
use std::sync::Arc;
use std::time::Duration;

use arrayvec::ArrayString;
use bytes::Bytes;
use http::header::HOST;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::upgrade::{self, Upgraded};
use hyper_util::rt::TokioIo;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{Connecting, Connection, Endpoint, IdleTimeout, TransportConfig, ZeroRttAccepted};
use rustls::client::Resumption;
use tokio::sync::{Mutex, MutexGuard, watch};
use tokio::time::timeout;
use tracing::{debug, info};

use super::authority::Target;
use super::denial::Denial;
use super::uplink_tls::{InnerStamp, UplinkTls};
use crate::body::Body;
use crate::config::{MAX_HOST_LEN, UplinkConfig};
use crate::error::{ReductionError, Result};
use crate::tls::certs::build_client_config;
use crate::transport::quic::{QuicStream, StreamType};

// Both ends offer only this protocol, so a data-plane QUIC peer cannot reach the uplink by mistake.
pub const UPLINK_ALPN: &[u8] = b"reduction-egress/1";
// The remote listener's idle limit. The keep-alive under it holds a quiet uplink open while tunnels idle.
const UPLINK_IDLE: Duration = Duration::from_secs(30);
const UPLINK_KEEP_ALIVE: Duration = Duration::from_secs(10);
// The local port of the client socket: the OS picks one.
const ANY_PORT: u16 = 0;
// A refusal body is one denial label. A longer body is not a refusal that a gateway sent.
const MAX_REFUSAL_BODY: usize = 64;
// `host:port` with the longest name and a five-digit port.
const MAX_AUTHORITY_LEN: usize = MAX_HOST_LEN + ":65535".len();
// One remote, so a few tickets cover the reconnects. Each handshake gets new ones.
const TICKET_SESSIONS: usize = 4;

pub struct Uplink {
	endpoint: Endpoint,
	remote: SocketAddr,
	server_name: ArrayString<MAX_HOST_LEN>,
	// Each stamp gets a copy of this config with its own ticket store.
	tls: rustls::ClientConfig,
	transport: Arc<TransportConfig>,
	// Set when the TLS files hot-reload. Without it the first identity and trust serve for good.
	reloads: Option<UplinkTls>,
	// One connection carries every tunnel. The lock makes concurrent first tunnels share one handshake.
	session: Mutex<Session>,
}

// The client config of one stamp. Its tickets come only from handshakes under that stamp, so no
// ticket from before a reload can resume and skip the new identity or CA.
struct Session {
	stamp: Option<InnerStamp>,
	client: quinn::ClientConfig,
	live: Option<Live>,
}

// Open tunnels keep a replaced connection alive. `early` is set when the connection sent 0-RTT data.
struct Live {
	connection: Connection,
	early: Option<watch::Receiver<Option<bool>>>,
}

impl Uplink {
	// A rotated cert, key or CA file applies at the next handshake, and the next tunnel makes one.
	pub fn new(config: &UplinkConfig) -> Result<Self> {
		let (tls, identity, trust) = build_client_config(&config.cert_path, &config.key_path, &config.ca_cert_path)?;
		let reloads: UplinkTls = UplinkTls::watch(identity, trust, &config.ca_cert_path)?;
		return Ok(Self { reloads: Some(reloads), ..Self::with_tls(config.address, config.server_name, tls)? });
	}

	// Call inside a Tokio runtime: the endpoint spawns its driver task.
	pub fn with_tls(remote: SocketAddr, server_name: ArrayString<MAX_HOST_LEN>, mut tls: rustls::ClientConfig) -> Result<Self> {
		tls.alpn_protocols = vec![UPLINK_ALPN.to_vec()];
		tls.enable_early_data = true;
		let transport: Arc<TransportConfig> = Arc::new(transport()?);
		let client: quinn::ClientConfig = client_config(&tls, &transport)?;
		let bind: SocketAddr = if remote.is_ipv4() {
			SocketAddr::from((Ipv4Addr::UNSPECIFIED, ANY_PORT))
		} else {
			SocketAddr::from((Ipv6Addr::UNSPECIFIED, ANY_PORT))
		};
		let endpoint: Endpoint =
			Endpoint::client(bind).map_err(|err| ReductionError::Transport(format!("egress uplink endpoint: {err}")))?;
		info!(%remote, %server_name, "egress uplink configured");
		let session: Session = Session { stamp: None, client, live: None };
		return Ok(Self { endpoint, remote, server_name, tls, transport, reloads: None, session: Mutex::new(session) });
	}

	// `limit` bounds the whole exchange: a handshake if one is needed, the stream, and the remote's verdict.
	pub async fn open(&self, target: &Target, limit: Duration) -> StdResult<TokioIo<Upgraded>, Denial> {
		return match timeout(limit, self.exchange(target)).await {
			Ok(outcome) => outcome,
			Err(_) => {
				debug!(%target, "egress uplink timed out");
				Err(Denial::UplinkUnavailable)
			}
		};
	}

	// The remote never sees a 0-RTT stream that it refused, so that CONNECT can go again in 1-RTT.
	async fn exchange(&self, target: &Target) -> StdResult<TokioIo<Upgraded>, Denial> {
		let (connection, early): (Connection, Option<watch::Receiver<Option<bool>>>) = self.connection().await?;
		let first: StdResult<TokioIo<Upgraded>, Denial> = tunnel_over(&connection, target).await;
		let Some(early) = early else {
			return first;
		};
		if !matches!(first, Err(Denial::UplinkUnavailable)) || is_early_accepted(early).await {
			return first;
		}
		debug!(%target, "egress uplink 0-RTT refused; sending the CONNECT again");
		return tunnel_over(&connection, target).await;
	}

	// The open connection, or a new one when there is none, the last one closed, or a reload changed the TLS files.
	async fn connection(&self) -> StdResult<(Connection, Option<watch::Receiver<Option<bool>>>), Denial> {
		let stamp: Option<InnerStamp> = self.reloads.as_ref().map(UplinkTls::stamp);
		let mut session: MutexGuard<'_, Session> = self.session.lock().await;
		if session.stamp != stamp {
			if session.live.is_some() {
				info!(remote = %self.remote, "egress uplink TLS files reloaded; new tunnels use a new connection");
			}
			session.client = client_config(&self.tls, &self.transport).map_err(unavailable("client config"))?;
			session.stamp = stamp;
			session.live = None;
		}
		if let Some(live) = session.live.as_ref().filter(|live: &&Live| return live.connection.close_reason().is_none()) {
			return Ok((live.connection.clone(), live.early.clone()));
		}
		let connecting: Connecting = self
			.endpoint
			.connect_with(session.client.clone(), self.remote, &self.server_name)
			.map_err(unavailable("connect"))?;
		let live: Live = match connecting.into_0rtt() {
			Ok((connection, accepted)) => {
				debug!(remote = %self.remote, "egress uplink resumed; the first tunnels go in 0-RTT");
				Live { connection, early: Some(watch_early(accepted)) }
			}
			Err(connecting) => {
				let connection: Connection = connecting.await.map_err(unavailable("QUIC handshake"))?;
				debug!(remote = %self.remote, "egress uplink connected");
				Live { connection, early: None }
			}
		};
		let handle: (Connection, Option<watch::Receiver<Option<bool>>>) = (live.connection.clone(), live.early.clone());
		session.live = Some(live);
		return Ok(handle);
	}
}

// A copy of `tls` with an empty ticket store, so it resumes only sessions that it made itself.
fn client_config(tls: &rustls::ClientConfig, transport: &Arc<TransportConfig>) -> Result<quinn::ClientConfig> {
	let mut fresh: rustls::ClientConfig = tls.clone();
	fresh.resumption = Resumption::in_memory_sessions(TICKET_SESSIONS);
	let crypto: QuicClientConfig = QuicClientConfig::try_from(Arc::new(fresh))
		.map_err(|err| ReductionError::Config(format!("egress uplink QUIC crypto: {err}")))?;
	let mut client: quinn::ClientConfig = quinn::ClientConfig::new(Arc::new(crypto));
	client.transport_config(Arc::clone(transport));
	return Ok(client);
}

// The 0-RTT verdict as a value that every tunnel on the connection can read. None until the handshake ends.
fn watch_early(accepted: ZeroRttAccepted) -> watch::Receiver<Option<bool>> {
	let (verdict_tx, verdict_rx): (watch::Sender<Option<bool>>, watch::Receiver<Option<bool>>) = watch::channel(None);
	tokio::spawn(async move {
		let is_accepted: bool = accepted.await;
		debug!(is_accepted, "egress uplink 0-RTT verdict");
		let _ = verdict_tx.send(Some(is_accepted));
	});
	return verdict_rx;
}

// A handshake that fails gives no verdict. That is not a refusal of the 0-RTT data, so no retry follows.
async fn is_early_accepted(mut early: watch::Receiver<Option<bool>>) -> bool {
	return match early.wait_for(Option::is_some).await {
		Ok(verdict) => *verdict != Some(false),
		Err(_) => true,
	};
}

// One CONNECT on a new stream of `connection`, and the upgraded tunnel when the remote admits it.
async fn tunnel_over(connection: &Connection, target: &Target) -> StdResult<TokioIo<Upgraded>, Denial> {
	let (mut send, recv) = connection.open_bi().await.map_err(unavailable("open stream"))?;
	send.write_all(&[StreamType::Http.byte()]).await.map_err(unavailable("write stream type"))?;
	let io: TokioIo<QuicStream> = TokioIo::new(QuicStream::new(send, recv));
	let (mut sender, driver): (http1::SendRequest<Body>, http1::Connection<TokioIo<QuicStream>, Body>) =
		http1::handshake(io).await.map_err(unavailable("HTTP handshake"))?;
	tokio::spawn(async move {
		if let Err(err) = driver.with_upgrades().await {
			debug!(error = %err, "egress uplink stream ended");
		}
	});
	let response: Response<Incoming> = sender.send_request(connect_request(target)?).await.map_err(unavailable("send CONNECT"))?;
	if response.status() != StatusCode::OK {
		return Err(refusal(response).await);
	}
	let upgraded: Upgraded = upgrade::on(response).await.map_err(unavailable("upgrade"))?;
	return Ok(TokioIo::new(upgraded));
}

fn transport() -> Result<TransportConfig> {
	let idle: IdleTimeout =
		IdleTimeout::try_from(UPLINK_IDLE).map_err(|err| ReductionError::Config(format!("egress uplink idle timeout: {err}")))?;
	let mut transport: TransportConfig = TransportConfig::default();
	transport.max_idle_timeout(Some(idle)).keep_alive_interval(Some(UPLINK_KEEP_ALIVE));
	return Ok(transport);
}

// Each failure of the uplink itself is one refusal to the agent. The step goes to the debug log.
fn unavailable<E: Display>(step: &'static str) -> impl FnOnce(E) -> Denial {
	return move |err: E| {
		debug!(step, error = %err, "egress uplink failed");
		return Denial::UplinkUnavailable;
	};
}

fn connect_request(target: &Target) -> StdResult<Request<Body>, Denial> {
	let mut authority: ArrayString<MAX_AUTHORITY_LEN> = ArrayString::new();
	write!(authority, "{target}").map_err(unavailable("format authority"))?;
	return Request::builder()
		.method(Method::CONNECT)
		.uri(authority.as_str())
		.header(HOST, authority.as_str())
		.body(Body::empty())
		.map_err(unavailable("build CONNECT"));
}

// A refusal the remote sent maps back to its Denial. Any other answer is an uplink failure, not a verdict.
async fn refusal(response: Response<Incoming>) -> Denial {
	let status: StatusCode = response.status();
	let body: Bytes = match Limited::new(response.into_body(), MAX_REFUSAL_BODY).collect().await {
		Ok(collected) => collected.to_bytes(),
		Err(err) => {
			debug!(%status, error = %err, "egress uplink refusal body unreadable");
			return Denial::UplinkUnavailable;
		}
	};
	let label: &str = str::from_utf8(&body).unwrap_or_default();
	return Denial::from_reply(status, label).unwrap_or_else(|| {
		debug!(%status, label, "egress uplink answered with no known refusal");
		return Denial::UplinkUnavailable;
	});
}

#[cfg(test)]
mod tests {
	use std::net::{IpAddr, UdpSocket};
	use std::num::NonZeroU16;
	use std::sync::atomic::{AtomicBool, Ordering};
	use std::time::SystemTime;

	use quinn::VarInt;
	use rcgen::{Certificate, CertificateParams, CertifiedKey, DnType, DnValue, Issuer, KeyPair, SanType};
	use tempfile::NamedTempFile;
	use tokio::net::UdpSocket as AsyncUdpSocket;
	use tokio::sync::mpsc;
	use tokio::time::sleep;
	use tokio_util::sync::CancellationToken;

	use server_utils::ctx::Ctx;

	use super::*;
	use crate::config::{EgressConfig, RateLimitConfig, UplinkListenerConfig};
	use crate::egress::listener::EGRESS_HEAD_LIMITS;
	use crate::egress::testutil::{
		Ends, LOOPBACK_EXCEPTIONS, PAYLOAD, STEP_TIMEOUT, Started, WatchedFiles, connect, echo_server, echo_through, egress,
		launch_with, loopback_egress, open_access, until_reloaded,
	};
	use crate::egress::uplink_listener::{UplinkListener, bind_uplink_listener, bind_with_tls};
	use crate::egress::uplink_tls::TlsWatch;
	use crate::test_support::{LOOPBACK_ANY, LeafFiles, generate_ca, generate_signed_cert, leaf_files, write_pem};
	use crate::tls::certs::build_server_config;
	use crate::transport::quic_listener::QuicListener;

	// The remote leaf carries this IP SAN, so the inner names the remote by its address.
	const REMOTE_NAME: &str = "127.0.0.1";
	const REMOTE_IP: [u8; 4] = [127, 0, 0, 1];
	// The application close code a test sends when it closes the uplink connection itself.
	const TEST_CLOSE_CODE: u32 = 0;
	// Time for the remote's tickets to reach the inner after a handshake.
	const TICKET_WAIT: Duration = Duration::from_millis(200);
	// Time for the remote to drop a closed connection. Then a replayed Initial makes a new one.
	const DRAIN_WAIT: Duration = Duration::from_secs(2);
	// Time for a replayed CONNECT to reach the echo. On Windows the refused dial to [::1] alone takes 2 s.
	const REPLAY_WAIT: Duration = Duration::from_secs(5);
	// RFC 9000 17.2: the first bit of a long header. Initial and 0-RTT packets carry one, 1-RTT packets do not.
	const LONG_HEADER: u8 = 0x80;
	const MAX_DATAGRAM: usize = 65_535;
	// A leaf that outlives one handshake and expires before the reconnect. Certificate times have whole seconds.
	const LEAF_LIFE: Duration = Duration::from_secs(2);
	const EXPIRY_MARGIN: Duration = Duration::from_secs(1);

	type TlsPair = (rustls::ServerConfig, rustls::ClientConfig);

	struct Pair {
		inner: Started,
		remote: Started,
	}

	// The remote leaf comes from `server_ca`, the inner leaf from `client_ca`. Both ends trust only `server_ca`.
	fn tls(server_ca: &CertifiedKey<KeyPair>, client_ca: &CertifiedKey<KeyPair>) -> StdResult<TlsPair, String> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let sans: Vec<SanType> = vec![SanType::IpAddress(IpAddr::from(REMOTE_IP))];
		let server: LeafFiles = generate_signed_cert(server_ca, "egress-remote", sans).and_then(leaf_files)?;
		let client: LeafFiles = generate_signed_cert(client_ca, "egress-inner", vec![]).and_then(leaf_files)?;
		let ca_file: NamedTempFile = write_pem(&server_ca.cert.pem())?;
		let (server_tls, _resolver) = build_server_config(server.cert.path(), server.key.path(), ca_file.path()).ctx("server TLS")?;
		let (client_tls, _resolver, _verifier) =
			build_client_config(client.cert.path(), client.key.path(), ca_file.path()).ctx("client TLS")?;
		return Ok((server_tls, client_tls));
	}

	fn trusted_tls() -> StdResult<TlsPair, String> {
		let ca: CertifiedKey<KeyPair> = generate_ca()?;
		return tls(&ca, &ca);
	}

	fn server_name() -> StdResult<ArrayString<MAX_HOST_LEN>, String> {
		return ArrayString::from(REMOTE_NAME).ctx("server name");
	}

	fn target(port: u16) -> StdResult<Target, String> {
		return Ok(Target { host: ArrayString::from("localhost").ctx("host")?, port: NonZeroU16::new(port).ok_or("zero port")? });
	}

	async fn serve(config: &EgressConfig, ends: Ends) -> StdResult<Started, String> {
		return launch_with(config, open_access(), &RateLimitConfig::default(), EGRESS_HEAD_LIMITS, ends).await;
	}

	// A remote gateway on its uplink listener, and the uplink address an inner dials to reach it.
	async fn remote(config: &EgressConfig, server_tls: rustls::ServerConfig) -> StdResult<(Started, SocketAddr), String> {
		let uplinks: QuicListener =
			bind_with_tls(LOOPBACK_ANY, server_tls, config.max_tunnels, CancellationToken::new()).ctx("bind uplink listener")?;
		let quic: SocketAddr = uplinks.local_addr().ctx("uplink listener addr")?;
		let started: Started = serve(config, Ends { uplink: None, uplinks: Some(uplinks) }).await?;
		return Ok((started, quic));
	}

	async fn pair(inner: &EgressConfig, remote_config: &EgressConfig, tls: TlsPair) -> StdResult<Pair, String> {
		let (server_tls, client_tls) = tls;
		let (remote, quic) = remote(remote_config, server_tls).await?;
		let uplink: Uplink = Uplink::with_tls(quic, server_name()?, client_tls).ctx("uplink")?;
		let inner: Started = serve(inner, Ends { uplink: Some(uplink), uplinks: None }).await?;
		return Ok(Pair { inner, remote });
	}

	// The inner has no loopback exception, so only a dial on the remote reaches the echo.
	#[tokio::test]
	async fn a_paired_tunnel_reaches_what_only_the_remote_can_dial() -> StdResult<(), String> {
		let echo: SocketAddr = echo_server().await?;
		let authority: String = format!("localhost:{}", echo.port());
		let inner: EgressConfig = loopback_egress(echo, "")?;

		let alone: Started = serve(&inner, Ends::default()).await?;
		let (refused, _) = connect(alone.addr, &authority).await?;
		assert_eq!(refused.status, 403, "without the uplink the inner dials and refuses loopback: {}", refused.text);

		let paired: Pair = pair(&inner, &loopback_egress(echo, LOOPBACK_EXCEPTIONS)?, trusted_tls()?).await?;
		let (head, mut tunnel) = connect(paired.inner.addr, &authority).await?;
		assert_eq!(head.status, 200, "the remote dials the echo: {}", head.text);
		assert_eq!(echo_through(&mut tunnel).await?, PAYLOAD, "bytes cross both gateways unchanged");
		assert_eq!(paired.remote.recorder.sum("egress.tunnels.opened", None)?, 1, "the remote opened the tunnel");
		assert_eq!(paired.inner.recorder.sum("egress.tunnels.opened", None)?, 1, "the inner opened its end");
		return Ok(());
	}

	// The inner admits more than the remote: what only the inner admits comes back as the remote's own refusal.
	#[tokio::test]
	async fn remote_refusals_reach_the_agent_and_inner_refusals_never_leave() -> StdResult<(), String> {
		let echo: SocketAddr = echo_server().await?;
		let inner: EgressConfig = egress(&format!("allow_hosts = [\"localhost\", \"github.com\"]\nallow_ports = [{}, 443]", echo.port()))?;
		let paired: Pair = pair(&inner, &loopback_egress(echo, LOOPBACK_EXCEPTIONS)?, trusted_tls()?).await?;
		let (inner_rec, remote_rec) = (&paired.inner.recorder, &paired.remote.recorder);

		let (own, _) = connect(paired.inner.addr, "gitlab.com:443").await?;
		assert_eq!(own.status, 403, "{}", own.text);
		assert_eq!(remote_rec.sum("egress.denials", None)?, 0, "the inner's own refusal opens no stream");

		let (host, _) = connect(paired.inner.addr, "github.com:443").await?;
		let (port, _) = connect(paired.inner.addr, "localhost:443").await?;
		assert_eq!([host.status, port.status], [403, 403], "{} / {}", host.text, port.text);
		assert_eq!(remote_rec.sum("egress.denials", Some(("reason", "host_not_allowed")))?, 1, "the remote refused the host");
		assert_eq!(remote_rec.sum("egress.denials", Some(("reason", "port_not_allowed")))?, 1, "the remote refused the port");
		assert_eq!(inner_rec.sum("egress.denials", Some(("reason", "host_not_allowed")))?, 2, "its own refusal and the relayed one");
		assert_eq!(inner_rec.sum("egress.denials", Some(("reason", "port_not_allowed")))?, 1, "the relayed label maps back");
		assert_eq!(inner_rec.sum("egress.denials", Some(("reason", "uplink_unavailable")))?, 0, "a verdict is not a failure");
		return Ok(());
	}

	// The inner trusts the remote, but its own leaf comes from a CA the remote does not trust.
	#[tokio::test]
	async fn an_inner_with_an_untrusted_leaf_gets_no_tunnel() -> StdResult<(), String> {
		let echo: SocketAddr = echo_server().await?;
		let (ca, foreign): (CertifiedKey<KeyPair>, CertifiedKey<KeyPair>) = (generate_ca()?, generate_ca()?);
		let paired: Pair = pair(&loopback_egress(echo, "")?, &loopback_egress(echo, LOOPBACK_EXCEPTIONS)?, tls(&ca, &foreign)?).await?;
		let (head, _) = connect(paired.inner.addr, &format!("localhost:{}", echo.port())).await?;
		assert_eq!(head.status, 502, "the remote refuses the handshake: {}", head.text);
		assert_eq!(paired.inner.recorder.sum("egress.denials", Some(("reason", "uplink_unavailable")))?, 1);
		assert_eq!(paired.remote.recorder.sum("egress.tunnels.opened", None)?, 0, "no CONNECT reached the remote");
		return Ok(());
	}

	// Nothing listens on the uplink port, so the connect limit ends the attempt.
	#[tokio::test]
	async fn an_unreachable_remote_is_uplink_unavailable() -> StdResult<(), String> {
		let echo: SocketAddr = echo_server().await?;
		let dead: UdpSocket = UdpSocket::bind(LOOPBACK_ANY).ctx("bind dead")?;
		let dead_addr: SocketAddr = dead.local_addr().ctx("dead addr")?;
		drop(dead);
		let (_server_tls, client_tls) = trusted_tls()?;
		let uplink: Uplink = Uplink::with_tls(dead_addr, server_name()?, client_tls).ctx("uplink")?;
		let config: EgressConfig = loopback_egress(echo, "connect_timeout_secs = 1")?;
		let inner: Started = serve(&config, Ends { uplink: Some(uplink), uplinks: None }).await?;
		let (head, _) = connect(inner.addr, &format!("localhost:{}", echo.port())).await?;
		assert_eq!(head.status, 502, "{}", head.text);
		assert_eq!(inner.recorder.sum("egress.denials", Some(("reason", "uplink_unavailable")))?, 1);
		return Ok(());
	}

	// Each tunnel is a stream on the one connection. A closed connection gives way to a new one.
	#[tokio::test]
	async fn tunnels_share_one_connection_until_it_closes() -> StdResult<(), String> {
		let echo: SocketAddr = echo_server().await?;
		let (server_tls, client_tls) = trusted_tls()?;
		let (_remote, quic) = remote(&loopback_egress(echo, LOOPBACK_EXCEPTIONS)?, server_tls).await?;
		let uplink: Uplink = Uplink::with_tls(quic, server_name()?, client_tls).ctx("uplink")?;
		let to_echo: Target = target(echo.port())?;
		let open = || async { return uplink.open(&to_echo, STEP_TIMEOUT).await.map_err(|denial| format!("{denial:?}")) };
		let current = || async { return uplink.session.lock().await.live.as_ref().map(|live: &Live| return live.connection.stable_id()) };

		let mut first: TokioIo<Upgraded> = open().await?;
		assert_eq!(echo_through(&mut first).await?, PAYLOAD);
		let first_id: Option<usize> = current().await;
		drop(first);
		let mut second: TokioIo<Upgraded> = open().await?;
		assert_eq!(echo_through(&mut second).await?, PAYLOAD);
		assert!(first_id.is_some() && current().await == first_id, "the second tunnel reuses the live connection");

		if let Some(live) = uplink.session.lock().await.live.as_ref() {
			live.connection.close(VarInt::from_u32(TEST_CLOSE_CODE), b"test");
		}
		let mut third: TokioIo<Upgraded> = open().await?;
		assert_eq!(echo_through(&mut third).await?, PAYLOAD);
		assert!(current().await.is_some_and(|id| Some(id) != first_id), "a closed connection is replaced");
		return Ok(());
	}

	// An uplink built from its config, over files that a test rewrites.
	struct WatchedUplink {
		uplink: Uplink,
		files: WatchedFiles,
	}

	fn watched_uplink(quic: SocketAddr, leaf: &CertifiedKey<KeyPair>, ca: &CertifiedKey<KeyPair>) -> StdResult<WatchedUplink, String> {
		let files: WatchedFiles = WatchedFiles::new(leaf, ca)?;
		let config: UplinkConfig = UplinkConfig {
			address: quic,
			server_name: server_name()?,
			cert_path: files.cert.clone(),
			key_path: files.key.clone(),
			ca_cert_path: files.ca.clone(),
		};
		return Ok(WatchedUplink { uplink: Uplink::new(&config).ctx("watched uplink")?, files });
	}

	fn stamp(uplink: &Uplink) -> StdResult<InnerStamp, String> {
		return uplink.reloads.as_ref().map(UplinkTls::stamp).ok_or_else(|| "an uplink from its config watches its files".to_owned());
	}

	fn inner_leaf(ca: &CertifiedKey<KeyPair>) -> StdResult<CertifiedKey<KeyPair>, String> {
		return generate_signed_cert(ca, "egress-inner", vec![]);
	}

	// A remote that trusts only `ca` for its inners, and an inner over files with a leaf from `ca`.
	async fn watched_pair(echo: SocketAddr, ca: &CertifiedKey<KeyPair>) -> StdResult<(Started, WatchedUplink), String> {
		let (server_tls, _client_tls) = tls(ca, ca)?;
		let (remote, quic) = remote(&loopback_egress(echo, LOOPBACK_EXCEPTIONS)?, server_tls).await?;
		return Ok((remote, watched_uplink(quic, &inner_leaf(ca)?, ca)?));
	}

	// The live connection keeps the identity of its own handshake. After a reload the next tunnel makes a new
	// handshake. Thus an untrusted leaf stops the tunnels, and a trusted one brings them back.
	#[tokio::test]
	async fn a_reloaded_inner_leaf_reaches_the_remote_at_the_next_tunnel() -> StdResult<(), String> {
		let echo: SocketAddr = echo_server().await?;
		let (ca, foreign): (CertifiedKey<KeyPair>, CertifiedKey<KeyPair>) = (generate_ca()?, generate_ca()?);
		let (_remote, inner) = watched_pair(echo, &ca).await?;
		let to_echo: Target = target(echo.port())?;
		let open = async || return inner.uplink.open(&to_echo, STEP_TIMEOUT).await.map(drop);
		open().await.map_err(|denial| format!("the first leaf is trusted: {denial:?}"))?;

		let untrusted: CertifiedKey<KeyPair> = inner_leaf(&foreign)?;
		let first: InnerStamp = stamp(&inner.uplink)?;
		until_reloaded("the untrusted leaf", || inner.files.write_leaf(&untrusted), async || {
			return stamp(&inner.uplink).is_ok_and(|now: InnerStamp| return now != first);
		})
		.await?;
		assert_eq!(open().await, Err(Denial::UplinkUnavailable), "the remote refuses the new handshake");

		let trusted: CertifiedKey<KeyPair> = inner_leaf(&ca)?;
		let refused: InnerStamp = stamp(&inner.uplink)?;
		until_reloaded("the trusted leaf", || inner.files.write_leaf(&trusted), async || {
			return stamp(&inner.uplink).is_ok_and(|now: InnerStamp| return now != refused);
		})
		.await?;
		assert_eq!(open().await, Ok(()), "a trusted leaf opens tunnels again");
		return Ok(());
	}

	// A reloaded CA that did not sign the remote's leaf stops the tunnels at the next handshake.
	#[tokio::test]
	async fn a_reloaded_inner_ca_applies_at_the_next_tunnel() -> StdResult<(), String> {
		let echo: SocketAddr = echo_server().await?;
		let (ca, foreign): (CertifiedKey<KeyPair>, CertifiedKey<KeyPair>) = (generate_ca()?, generate_ca()?);
		let (_remote, inner) = watched_pair(echo, &ca).await?;
		let to_echo: Target = target(echo.port())?;
		let open = async || return inner.uplink.open(&to_echo, STEP_TIMEOUT).await.map(drop);
		open().await.map_err(|denial| format!("the first CA signs the remote: {denial:?}"))?;

		let first: InnerStamp = stamp(&inner.uplink)?;
		until_reloaded("the foreign CA", || inner.files.write_ca(&foreign), async || {
			return stamp(&inner.uplink).is_ok_and(|now: InnerStamp| return now != first);
		})
		.await?;
		assert_eq!(open().await, Err(Denial::UplinkUnavailable), "the remote's leaf no longer verifies");
		return Ok(());
	}

	// With no reload the stamp stays the same, so tunnels keep the one connection.
	#[tokio::test]
	async fn an_unchanged_stamp_keeps_the_live_connection() -> StdResult<(), String> {
		let echo: SocketAddr = echo_server().await?;
		let (_remote, inner) = watched_pair(echo, &generate_ca()?).await?;
		let to_echo: Target = target(echo.port())?;
		let current = || async { return inner.uplink.session.lock().await.live.as_ref().map(|live: &Live| return live.connection.stable_id()) };
		inner.uplink.open(&to_echo, STEP_TIMEOUT).await.map_err(|denial| format!("first: {denial:?}"))?;
		let first: Option<usize> = current().await;
		inner.uplink.open(&to_echo, STEP_TIMEOUT).await.map_err(|denial| format!("second: {denial:?}"))?;
		assert!(first.is_some() && current().await == first, "a watched uplink reuses its connection while no file changes");
		assert!(stamp(&inner.uplink)? == stamp(&inner.uplink)?, "the stamp of unchanged files is stable");
		return Ok(());
	}

	// A remote on its real uplink listener, over files that a test rewrites.
	struct EarlyRemote {
		started: Started,
		quic: SocketAddr,
		files: WatchedFiles,
		_watch: TlsWatch,
	}

	fn remote_leaf(ca: &CertifiedKey<KeyPair>) -> StdResult<CertifiedKey<KeyPair>, String> {
		return generate_signed_cert(ca, "egress-remote", vec![SanType::IpAddress(IpAddr::from(REMOTE_IP))]);
	}

	async fn early_remote(echo: SocketAddr, ca: &CertifiedKey<KeyPair>) -> StdResult<EarlyRemote, String> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let files: WatchedFiles = WatchedFiles::new(&remote_leaf(ca)?, ca)?;
		let config: UplinkListenerConfig = UplinkListenerConfig {
			listen: LOOPBACK_ANY,
			cert_path: files.cert.clone(),
			key_path: files.key.clone(),
			ca_cert_path: files.ca.clone(),
		};
		let gateway: EgressConfig = loopback_egress(echo, LOOPBACK_EXCEPTIONS)?;
		let UplinkListener { quic, watch } = bind_uplink_listener(&config, gateway.max_tunnels, CancellationToken::new()).ctx("bind")?;
		let addr: SocketAddr = quic.local_addr().ctx("uplink listener addr")?;
		let started: Started = serve(&gateway, Ends { uplink: None, uplinks: Some(quic) }).await?;
		return Ok(EarlyRemote { started, quic: addr, files, _watch: watch });
	}

	// The 0-RTT verdict of the live connection. None means that it sent no early data.
	async fn early_verdict(uplink: &Uplink) -> StdResult<Option<bool>, String> {
		let early: Option<watch::Receiver<Option<bool>>> = uplink.session.lock().await.live.as_ref().and_then(|live: &Live| return live.early.clone());
		let Some(mut early) = early else {
			return Ok(None);
		};
		let verdict: Option<bool> = *timeout(STEP_TIMEOUT, early.wait_for(Option::is_some)).await.ctx("0-RTT verdict")?.ctx("verdict channel")?;
		return Ok(verdict);
	}

	async fn close_live(uplink: &Uplink) {
		if let Some(live) = uplink.session.lock().await.live.as_ref() {
			live.connection.close(VarInt::from_u32(TEST_CLOSE_CODE), b"test");
		}
	}

	// One tunnel and its echo, then the 0-RTT verdict of the connection that carried it.
	async fn tunnel_verdict(uplink: &Uplink, to: &Target) -> StdResult<Option<bool>, String> {
		let mut tunnel: TokioIo<Upgraded> = uplink.open(to, STEP_TIMEOUT).await.map_err(|denial| format!("open: {denial:?}"))?;
		if echo_through(&mut tunnel).await? != PAYLOAD {
			return Err("the tunnel changed the bytes".to_owned());
		}
		return early_verdict(uplink).await;
	}

	// A full handshake gives tickets, then a reconnect resumes and sends its CONNECT in 0-RTT.
	#[tokio::test]
	async fn a_reconnect_resumes_and_sends_its_connect_in_0rtt() -> StdResult<(), String> {
		let echo: SocketAddr = echo_server().await?;
		let ca: CertifiedKey<KeyPair> = generate_ca()?;
		let remote: EarlyRemote = early_remote(echo, &ca).await?;
		let (_fixed_server, client_tls) = tls(&ca, &ca)?;
		let uplink: Uplink = Uplink::with_tls(remote.quic, server_name()?, client_tls).ctx("uplink")?;
		let to_echo: Target = target(echo.port())?;
		assert_eq!(tunnel_verdict(&uplink, &to_echo).await?, None, "no ticket yet, so a full handshake");
		sleep(TICKET_WAIT).await;
		close_live(&uplink).await;
		assert_eq!(tunnel_verdict(&uplink, &to_echo).await?, Some(true), "the remote takes the 0-RTT CONNECT");
		assert_eq!(remote.started.recorder.sum("egress.tunnels.opened", None)?, 2, "one tunnel on each connection");
		return Ok(());
	}

	// A UDP relay between an inner and a remote. It keeps a copy of what the inner sends while it records.
	struct Relay {
		addr: SocketAddr,
		is_recording: Arc<AtomicBool>,
		copies: mpsc::UnboundedReceiver<Vec<u8>>,
	}

	async fn relay(remote: SocketAddr) -> StdResult<Relay, String> {
		let front: AsyncUdpSocket = AsyncUdpSocket::bind(LOOPBACK_ANY).await.ctx("bind relay front")?;
		let back: AsyncUdpSocket = AsyncUdpSocket::bind(LOOPBACK_ANY).await.ctx("bind relay back")?;
		let addr: SocketAddr = front.local_addr().ctx("relay addr")?;
		let is_recording: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
		let (copies_tx, copies): (mpsc::UnboundedSender<Vec<u8>>, mpsc::UnboundedReceiver<Vec<u8>>) = mpsc::unbounded_channel();
		let recording: Arc<AtomicBool> = Arc::clone(&is_recording);
		tokio::spawn(async move {
			let mut inner: Option<SocketAddr> = None;
			let (mut up, mut down): (Vec<u8>, Vec<u8>) = (vec![0; MAX_DATAGRAM], vec![0; MAX_DATAGRAM]);
			loop {
				tokio::select! {
					Ok((len, from)) = front.recv_from(&mut up) => {
						inner = Some(from);
						if recording.load(Ordering::SeqCst) {
							let _ = copies_tx.send(up[..len].to_vec());
						}
						let _ = back.send_to(&up[..len], remote).await;
					}
					Ok((len, _)) = back.recv_from(&mut down) => {
						if let Some(inner) = inner {
							let _ = front.send_to(&down[..len], inner).await;
						}
					}
					else => return,
				}
			}
		});
		return Ok(Relay { addr, is_recording, copies });
	}

	// An attacker copies the first flight of a resumed connection and sends it again after that connection ends.
	// rustls took the ticket out on its first use, so the copy gets no early data and opens no tunnel.
	#[tokio::test]
	async fn a_replayed_first_flight_opens_no_second_tunnel() -> StdResult<(), String> {
		let echo: SocketAddr = echo_server().await?;
		let ca: CertifiedKey<KeyPair> = generate_ca()?;
		let remote: EarlyRemote = early_remote(echo, &ca).await?;
		let mut relay: Relay = relay(remote.quic).await?;
		let (_fixed_server, client_tls) = tls(&ca, &ca)?;
		let uplink: Uplink = Uplink::with_tls(relay.addr, server_name()?, client_tls).ctx("uplink")?;
		let to_echo: Target = target(echo.port())?;
		tunnel_verdict(&uplink, &to_echo).await?;
		sleep(TICKET_WAIT).await;
		close_live(&uplink).await;

		relay.is_recording.store(true, Ordering::SeqCst);
		assert_eq!(tunnel_verdict(&uplink, &to_echo).await?, Some(true), "the recorded flight carries a 0-RTT CONNECT");
		relay.is_recording.store(false, Ordering::SeqCst);
		close_live(&uplink).await;
		sleep(DRAIN_WAIT).await;
		assert_eq!(remote.started.recorder.sum("egress.tunnels.opened", None)?, 2, "the two real tunnels");

		let attacker: AsyncUdpSocket = AsyncUdpSocket::bind(LOOPBACK_ANY).await.ctx("bind attacker")?;
		// Only the long-header datagrams: the ClientHello and the 0-RTT CONNECT, not 1-RTT packets of old connections.
		let mut replayed: usize = 0;
		while let Ok(datagram) = relay.copies.try_recv() {
			if datagram.first().is_some_and(|first: &u8| return first & LONG_HEADER != 0) {
				attacker.send_to(&datagram, remote.quic).await.ctx("replay")?;
				replayed += 1;
			}
		}
		assert!(replayed > 0, "the relay recorded the first flight");
		sleep(REPLAY_WAIT).await;
		assert_eq!(remote.started.recorder.sum("egress.tunnels.opened", None)?, 2, "the replay opened no tunnel");
		// Each request past the ACL takes a rate token, then opens a tunnel or counts a denial. Neither moved.
		assert_eq!(remote.started.recorder.sum("egress.denials", None)?, 0, "the replay reached no admission check");
		return Ok(());
	}

	// A reload on the inner gives it an empty ticket store, so the next connection makes a full handshake.
	#[tokio::test]
	async fn an_inner_reload_drops_its_tickets() -> StdResult<(), String> {
		let echo: SocketAddr = echo_server().await?;
		let ca: CertifiedKey<KeyPair> = generate_ca()?;
		let remote: EarlyRemote = early_remote(echo, &ca).await?;
		let inner: WatchedUplink = watched_uplink(remote.quic, &inner_leaf(&ca)?, &ca)?;
		let to_echo: Target = target(echo.port())?;
		assert_eq!(tunnel_verdict(&inner.uplink, &to_echo).await?, None, "no ticket yet");
		sleep(TICKET_WAIT).await;
		close_live(&inner.uplink).await;
		assert_eq!(tunnel_verdict(&inner.uplink, &to_echo).await?, Some(true), "with no reload the ticket resumes");
		sleep(TICKET_WAIT).await;

		let before: InnerStamp = stamp(&inner.uplink)?;
		until_reloaded("the rewritten inner CA", || inner.files.write_ca(&ca), async || {
			return stamp(&inner.uplink).is_ok_and(|now: InnerStamp| return now != before);
		})
		.await?;
		assert_eq!(tunnel_verdict(&inner.uplink, &to_echo).await?, None, "the new stamp has no ticket, so a full handshake");
		return Ok(());
	}

	// A leaf from `ca` that expires `life` from now.
	fn short_lived_leaf(ca: &CertifiedKey<KeyPair>, life: Duration) -> StdResult<LeafFiles, String> {
		let mut params: CertificateParams = CertificateParams::new(vec![]).ctx("leaf params")?;
		params.distinguished_name.push(DnType::CommonName, DnValue::Utf8String("egress-inner".to_owned()));
		params.not_after = (SystemTime::now() + life).into();
		let key: KeyPair = KeyPair::generate().ctx("leaf key")?;
		let issuer: Issuer<'_, &KeyPair> = Issuer::from_ca_cert_der(ca.cert.der(), &ca.signing_key).ctx("issuer")?;
		let cert: Certificate = params.signed_by(&key, &issuer).ctx("sign leaf")?;
		return leaf_files(CertifiedKey { cert, signing_key: key });
	}

	// A resumed handshake checks no cert, so the remote checks the chain from the ticket itself. An expired
	// leaf passes the ticket check and fails that one.
	#[tokio::test]
	async fn a_resumed_inner_whose_leaf_expired_is_refused() -> StdResult<(), String> {
		let echo: SocketAddr = echo_server().await?;
		let ca: CertifiedKey<KeyPair> = generate_ca()?;
		let remote: EarlyRemote = early_remote(echo, &ca).await?;
		let leaf: LeafFiles = short_lived_leaf(&ca, LEAF_LIFE)?;
		let ca_file: NamedTempFile = write_pem(&ca.cert.pem())?;
		let (client_tls, _resolver, _verifier) = build_client_config(leaf.cert.path(), leaf.key.path(), ca_file.path()).ctx("inner TLS")?;
		let uplink: Uplink = Uplink::with_tls(remote.quic, server_name()?, client_tls).ctx("uplink")?;
		let to_echo: Target = target(echo.port())?;
		assert_eq!(tunnel_verdict(&uplink, &to_echo).await?, None, "the leaf is valid at the full handshake");
		sleep(TICKET_WAIT).await;
		close_live(&uplink).await;

		sleep(LEAF_LIFE + EXPIRY_MARGIN).await;
		assert_eq!(uplink.open(&to_echo, STEP_TIMEOUT).await.map(drop), Err(Denial::UplinkUnavailable), "the expired leaf gets no tunnel");
		assert_eq!(remote.started.recorder.sum("egress.tunnels.opened", None)?, 1, "only the tunnel before expiry");
		return Ok(());
	}

	// A reload on the remote empties its ticket store. It refuses the inner's 0-RTT CONNECT, which goes again in 1-RTT.
	#[tokio::test]
	async fn a_remote_reload_refuses_old_tickets_and_the_connect_goes_again() -> StdResult<(), String> {
		let echo: SocketAddr = echo_server().await?;
		let ca: CertifiedKey<KeyPair> = generate_ca()?;
		let remote: EarlyRemote = early_remote(echo, &ca).await?;
		let (_fixed_server, client_tls) = tls(&ca, &ca)?;
		let uplink: Uplink = Uplink::with_tls(remote.quic, server_name()?, client_tls).ctx("uplink")?;
		let to_echo: Target = target(echo.port())?;
		tunnel_verdict(&uplink, &to_echo).await?;
		sleep(TICKET_WAIT).await;

		let rotated: CertifiedKey<KeyPair> = remote_leaf(&ca)?;
		until_reloaded("the remote leaf", || remote.files.write_leaf(&rotated), async || {
			close_live(&uplink).await;
			let verdict: StdResult<Option<bool>, String> = tunnel_verdict(&uplink, &to_echo).await;
			sleep(TICKET_WAIT).await;
			return verdict == Ok(Some(false));
		})
		.await?;
		return Ok(());
	}
}
