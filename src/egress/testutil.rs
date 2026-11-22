// Shared fixtures for the gateway and uplink tests: a served gateway, an echo target, and a raw CONNECT client.
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::time::Duration;

use rcgen::{CertifiedKey, KeyPair};
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::{Instant, sleep, timeout};
use tokio_util::sync::CancellationToken;

use server_utils::ctx::Ctx;

use super::allowlist::Allowlist;
use super::internal::InternalGuard;
use super::listener::{Gateway, serve_gateway};
use super::metrics::testutil::Recorder;
use super::policy::Policy;
use super::uplink::Uplink;
use crate::acl::AccessControl;
use crate::config::{EgressConfig, RateLimitConfig};
use crate::proxy::server::HeadLimits;
use crate::transport::quic_listener::QuicListener;

// Bounds every network step, so a broken gateway fails the test and does not stop it.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(5);
// The longest response head a test reads before it gives up on the terminator.
const MAX_HEAD_LEN: usize = 4096;
const HEAD_END: &[u8] = b"\r\n\r\n";
pub const PAYLOAD: &[u8] = b"through the tunnel";
pub const LOOPBACK_EXCEPTIONS: &str = "allow_private_cidrs = [\"127.0.0.1/32\", \"::1/128\"]";
// A file watcher reloads after a 300 ms debounce. The wait covers many of them on a slow runner.
const RELOAD_WAIT: Duration = Duration::from_secs(15);
const RELOAD_POLL: Duration = Duration::from_millis(400);

pub struct Head {
	pub status: u16,
	pub text: String,
}

pub struct Started {
	pub addr: SocketAddr,
	pub policy_tx: watch::Sender<Arc<Policy>>,
	pub recorder: Recorder,
}

// The paired ends a gateway serves with: an uplink it sends tunnels through, a QUIC listener it answers on.
#[derive(Default)]
pub struct Ends {
	pub uplink: Option<Uplink>,
	pub uplinks: Option<QuicListener>,
}

pub fn egress(extra: &str) -> StdResult<EgressConfig, String> {
	let raw: String = format!("listen = \"127.0.0.1:0\"\n{extra}");
	return toml::from_str(&raw).ctx("parse egress");
}

pub fn loopback_egress(echo: SocketAddr, extra: &str) -> StdResult<EgressConfig, String> {
	return egress(&format!("allow_hosts = [\"localhost\"]\nallow_ports = [{}]\n{extra}", echo.port()));
}

#[must_use]
pub fn open_access() -> AccessControl {
	return AccessControl::new(vec![], vec![]);
}

#[must_use]
pub fn policy(config: &EgressConfig, access: AccessControl) -> Arc<Policy> {
	return Arc::new(Policy {
		access,
		allowlist: Allowlist::from_config(config),
		guard: InternalGuard::new(config.allow_private_cidrs.clone()),
	});
}

pub async fn echo_server() -> StdResult<SocketAddr, String> {
	let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.ctx("bind echo")?;
	let addr: SocketAddr = listener.local_addr().ctx("echo addr")?;
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

pub async fn launch_with(
	config: &EgressConfig,
	access: AccessControl,
	rate: &RateLimitConfig,
	limits: HeadLimits,
	ends: Ends,
) -> StdResult<Started, String> {
	let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.ctx("bind gateway")?;
	let addr: SocketAddr = listener.local_addr().ctx("gateway addr")?;
	let (policy_tx, policy_rx): (watch::Sender<Arc<Policy>>, watch::Receiver<Arc<Policy>>) = watch::channel(policy(config, access));
	let recorder: Recorder = Recorder::new();
	let shutdown: &'static CancellationToken = Box::leak(Box::new(CancellationToken::new()));
	let local: Gateway = Gateway::new(config, rate, policy_rx, recorder.metrics(), shutdown.child_token());
	let gateway: Gateway = match ends.uplink {
		Some(uplink) => local.with_uplink(uplink),
		None => local,
	};
	tokio::spawn(serve_gateway(Some(listener), ends.uplinks, gateway, limits, shutdown));
	return Ok(Started { addr, policy_tx, recorder });
}

// Read one byte at a time up to the blank line. Thus the head never takes a tunnel byte.
pub async fn read_head(stream: &mut TcpStream) -> StdResult<Head, String> {
	let mut head: Vec<u8> = Vec::new();
	while !head.ends_with(HEAD_END) {
		if head.len() >= MAX_HEAD_LEN {
			return Err("response head has no terminator".to_owned());
		}
		let byte: u8 = timeout(STEP_TIMEOUT, stream.read_u8())
			.await
			.map_err(|_| "head read timed out".to_owned())?
			.ctx("head read")?;
		head.push(byte);
	}
	let text: String = String::from_utf8(head).ctx("head utf8")?;
	let status: u16 = text
		.split(' ')
		.nth(1)
		.and_then(|code| code.parse::<u16>().ok())
		.ok_or_else(|| format!("no status in '{text}'"))?;
	return Ok(Head { status, text });
}

// `headers` is zero or more complete `Name: value\r\n` lines.
pub async fn send_with(gateway: SocketAddr, request_line: &str, headers: &str) -> StdResult<(Head, TcpStream), String> {
	let mut stream: TcpStream = TcpStream::connect(gateway).await.ctx("connect gateway")?;
	let request: String = format!("{request_line}\r\nHost: gateway\r\n{headers}\r\n");
	stream.write_all(request.as_bytes()).await.ctx("write request")?;
	let head: Head = read_head(&mut stream).await?;
	return Ok((head, stream));
}

pub async fn send(gateway: SocketAddr, request_line: &str) -> StdResult<(Head, TcpStream), String> {
	return send_with(gateway, request_line, "").await;
}

pub async fn connect(gateway: SocketAddr, authority: &str) -> StdResult<(Head, TcpStream), String> {
	return send(gateway, &format!("CONNECT {authority} HTTP/1.1")).await;
}

pub async fn echo_through<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> StdResult<Vec<u8>, String> {
	stream.write_all(PAYLOAD).await.ctx("write payload")?;
	let mut echoed: Vec<u8> = vec![0; PAYLOAD.len()];
	timeout(STEP_TIMEOUT, stream.read_exact(&mut echoed))
		.await
		.map_err(|_| "echo read timed out".to_owned())?
		.ctx("echo read")?;
	return Ok(echoed);
}

// A leaf and a CA as PEM files in a directory of their own, so a watcher on them sees no other events.
pub struct WatchedFiles {
	_dir: TempDir,
	pub cert: PathBuf,
	pub key: PathBuf,
	pub ca: PathBuf,
}

impl WatchedFiles {
	pub fn new(leaf: &CertifiedKey<KeyPair>, ca: &CertifiedKey<KeyPair>) -> StdResult<Self, String> {
		let dir: TempDir = TempDir::new().ctx("watched dir")?;
		let files: Self = Self {
			cert: dir.path().join("leaf.crt"),
			key: dir.path().join("leaf.key"),
			ca: dir.path().join("ca.crt"),
			_dir: dir,
		};
		files.write_leaf(leaf)?;
		files.write_ca(ca)?;
		return Ok(files);
	}

	pub fn write_leaf(&self, leaf: &CertifiedKey<KeyPair>) -> StdResult<(), String> {
		fs::write(&self.cert, leaf.cert.pem()).ctx("write leaf cert")?;
		return fs::write(&self.key, leaf.signing_key.serialize_pem()).ctx("write leaf key");
	}

	pub fn write_ca(&self, ca: &CertifiedKey<KeyPair>) -> StdResult<(), String> {
		return fs::write(&self.ca, ca.cert.pem()).ctx("write CA");
	}
}

// Repeats `rewrite` until `check` holds: one write can reach the watcher inside the debounce of the last one.
pub async fn until_reloaded(
	what: &str,
	rewrite: impl Fn() -> StdResult<(), String>,
	check: impl AsyncFn() -> bool,
) -> StdResult<(), String> {
	let deadline: Instant = Instant::now() + RELOAD_WAIT;
	while Instant::now() < deadline {
		rewrite()?;
		sleep(RELOAD_POLL).await;
		if check().await {
			return Ok(());
		}
	}
	return Err(format!("{what} did not apply within {RELOAD_WAIT:?}"));
}
