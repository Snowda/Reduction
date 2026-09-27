use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::server::Acceptor;
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;
use tokio_rustls::{LazyConfigAcceptor, StartHandshake};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::error::Result;
use crate::tls::PeerIdentity;

const INITIAL_BACKOFF: Duration = Duration::from_millis(50);
const MAX_BACKOFF: Duration = Duration::from_secs(5);
// Whole-handshake budget for one connection (ClientHello through TLS completion). A peer that
// connects then stalls is dropped after this, so it can't pin a task or hang the accept loop.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
// Backlog of completed handshakes buffered for `accept()` to drain.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 256;
// Exponential factor applied to the accept-failure backoff each retry.
const BACKOFF_MULTIPLIER: u32 = 2;

// Next accept-failure backoff: multiply, saturating at the ceiling.
#[inline]
fn next_backoff(current: Duration) -> Duration {
	return (current * BACKOFF_MULTIPLIER).min(MAX_BACKOFF);
}

// ACME tls-alpn-01 shares the real-traffic port, distinguished only by this ALPN. Such connections
// get a no-client-auth challenge config and are closed before the HTTP layer, so mTLS isn't bypassed.
const ACME_TLS_ALPN_PROTO: &[u8] = b"acme-tls/1";

pub struct TcpListener {
	// Completed real-traffic TLS streams, produced by the background acceptor task.
	stream_rx: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
	local_addr: SocketAddr,
}

impl TcpListener {
	pub async fn bind(
		addr: SocketAddr,
		tls_config: Arc<rustls::ServerConfig>,
		challenge_config: Option<Arc<rustls::ServerConfig>>,
	) -> Result<Self> {
		return Self::bind_with_token(
			addr,
			tls_config,
			challenge_config,
			CancellationToken::new(),
			DEFAULT_CHANNEL_CAPACITY,
		)
		.await;
	}

	pub async fn bind_with_token(
		addr: SocketAddr,
		tls_config: Arc<rustls::ServerConfig>,
		challenge_config: Option<Arc<rustls::ServerConfig>>,
		shutdown: CancellationToken,
		channel_capacity: usize,
	) -> Result<Self> {
		let inner: TokioTcpListener = TokioTcpListener::bind(addr).await?;
		let local_addr: SocketAddr = inner.local_addr()?;

		info!(%addr, acme_challenge = challenge_config.is_some(), "TCP listener bound");

		let (stream_tx, stream_rx) = mpsc::channel(channel_capacity);
		tokio::spawn(accept_connections(
			inner,
			tls_config,
			challenge_config,
			stream_tx,
			shutdown,
		));

		return Ok(Self { stream_rx, local_addr });
	}
}

// Accept TCP connections and hand each handshake to its own task, so a slow client can't stall the
// accept loop. Completed real-traffic streams go to the channel `accept()` drains. Stops on `shutdown`.
// The tokio::select! accept loop inflates cognitive complexity via macro expansion, not branching logic.
#[allow(clippy::cognitive_complexity)]
async fn accept_connections(
	listener: TokioTcpListener,
	tls_config: Arc<rustls::ServerConfig>,
	challenge_config: Option<Arc<rustls::ServerConfig>>,
	stream_tx: mpsc::Sender<(TlsStream<TcpStream>, SocketAddr)>,
	shutdown: CancellationToken,
) {
	let mut backoff: Duration = INITIAL_BACKOFF;

	loop {
		let accepted: io::Result<(TcpStream, SocketAddr)> = tokio::select! {
			result = listener.accept() => result,
			_ = shutdown.cancelled() => {
				info!("shutdown signal received, stopping TCP acceptor");
				break;
			}
		};

		let (tcp_stream, peer_addr) = match accepted {
			Ok(pair) => {
				backoff = INITIAL_BACKOFF;
				pair
			}
			Err(e) => {
				error!(error = %e, backoff_ms = backoff.as_millis(), "TCP accept failed, backing off");
				tokio::time::sleep(backoff).await;
				backoff = next_backoff(backoff);
				continue;
			}
		};

		let tls_config: Arc<rustls::ServerConfig> = Arc::clone(&tls_config);
		let challenge_config: Option<Arc<rustls::ServerConfig>> = challenge_config.clone();
		let tx: mpsc::Sender<(TlsStream<TcpStream>, SocketAddr)> = stream_tx.clone();

		tokio::spawn(run_handshake(tcp_stream, peer_addr, tls_config, challenge_config, tx));
	}

	debug!("TCP acceptor stopping");
}

// One connection's handshake task, run off the accept loop under a timeout: forward a completed
// real-traffic stream to the accept channel, silently drop an ACME probe, and log a timeout.
async fn run_handshake(
	tcp_stream: TcpStream,
	peer_addr: SocketAddr,
	tls_config: Arc<rustls::ServerConfig>,
	challenge_config: Option<Arc<rustls::ServerConfig>>,
	tx: mpsc::Sender<(TlsStream<TcpStream>, SocketAddr)>,
) {
	match timeout(
		HANDSHAKE_TIMEOUT,
		handshake_connection(tcp_stream, peer_addr, &tls_config, challenge_config),
	)
	.await
	{
		Ok(Some(tls_stream)) => {
			let _ = tx.send((tls_stream, peer_addr)).await;
		}
		Ok(None) => {}
		Err(_) => warn!(%peer_addr, "TLS handshake timed out"),
	}
}

// Complete the TLS handshake for one connection, off the accept loop under a caller-imposed timeout.
// Returns the server stream for real traffic, or None for an ACME probe (served then dropped) or failure.
async fn handshake_connection(
	tcp_stream: TcpStream,
	peer_addr: SocketAddr,
	tls_config: &Arc<rustls::ServerConfig>,
	challenge_config: Option<Arc<rustls::ServerConfig>>,
) -> Option<TlsStream<TcpStream>> {
	// Peek the ClientHello before committing to a config: an ACME probe (no client cert) gets the
	// challenge config while real traffic goes through the mandatory-mTLS config.
	let start = match LazyConfigAcceptor::new(Acceptor::default(), tcp_stream).await {
		Ok(start) => start,
		Err(e) => {
			error!(error = %e, "reading TLS ClientHello failed");
			return None;
		}
	};

	if is_acme_probe(&start, &challenge_config) {
		if let Some(challenge_config) = &challenge_config {
			serve_acme_challenge(start, challenge_config, peer_addr).await;
		}
		return None;
	}

	return match start.into_stream(Arc::clone(tls_config)).await {
		Ok(tls_stream) => Some(tls_stream),
		Err(e) => {
			error!(error = %e, "TLS handshake failed");
			None
		}
	};
}

// True when this ClientHello is an ACME tls-alpn-01 probe: a challenge config is present and the offered
// ALPN includes the acme-tls/1 protocol. Such a probe is served with the challenge cert, not the mTLS config.
fn is_acme_probe(start: &StartHandshake<TcpStream>, challenge_config: &Option<Arc<rustls::ServerConfig>>) -> bool {
	if challenge_config.is_none() {
		return false;
	}
	let hello = start.client_hello();
	return hello
		.alpn()
		.into_iter()
		.flatten()
		.any(|proto| proto == ACME_TLS_ALPN_PROTO);
}

// Complete an ACME tls-alpn-01 challenge handshake so the validator can read the challenge cert, then
// drop the stream. It never becomes an HTTP connection, so mandatory mTLS is not bypassed.
async fn serve_acme_challenge(
	start: StartHandshake<TcpStream>,
	challenge_config: &Arc<rustls::ServerConfig>,
	peer_addr: SocketAddr,
) {
	match start.into_stream(Arc::clone(challenge_config)).await {
		Ok(stream) => {
			debug!(%peer_addr, "served tls-alpn-01 challenge");
			drop(stream);
		}
		Err(e) => {
			warn!(error = %e, %peer_addr, "tls-alpn-01 challenge handshake failed");
		}
	}
}

// Build the per-connection ConnectAddr from an accepted TLS stream, extracting the mTLS identity
// once. A leaf with an unparseable CN yields None here and is rejected in the handler, not forwarded.
fn connect_addr_from_stream(remote: SocketAddr, stream: &TlsStream<tokio::net::TcpStream>) -> super::ConnectAddr {
	let identity: Option<PeerIdentity> = match PeerIdentity::from_tls_stream(stream) {
		Ok(id) => Some(id),
		Err(e) => {
			warn!(error = %e, "failed to extract peer identity from TLS stream");
			None
		}
	};
	return super::ConnectAddr(remote, identity);
}

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, TcpListener>> for super::ConnectAddr {
	fn connect_info(target: axum::serve::IncomingStream<'_, TcpListener>) -> Self {
		return connect_addr_from_stream(*target.remote_addr(), target.io());
	}
}

impl axum::serve::Listener for TcpListener {
	type Io = TlsStream<tokio::net::TcpStream>;
	type Addr = SocketAddr;

	async fn accept(&mut self) -> (Self::Io, Self::Addr) {
		match self.stream_rx.recv().await {
			Some(pair) => return pair,
			None => {
				// The acceptor task exited (shutdown fired). Pend rather than yield so axum's
				// graceful-shutdown path — not a bogus connection — drives termination.
				error!("TCP acceptor task stopped, waiting for graceful shutdown");
				return std::future::pending::<(Self::Io, Self::Addr)>().await;
			}
		}
	}

	fn local_addr(&self) -> io::Result<Self::Addr> {
		return Ok(self.local_addr);
	}
}

#[cfg(test)]
mod tests {
	use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
	use rustls::{ClientConfig, RootCertStore, ServerConfig};
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tokio::net::TcpStream;
	use tokio_rustls::{TlsAcceptor, TlsConnector};

	use super::*;
	use crate::config::ClientAuthPolicy;
	use crate::test_support::{generate_ca, generate_localhost_cert, write_pem};
	use crate::tls::certs::{build_client_config, build_server_config, build_server_config_for_policy};

	// No-client-auth stand-in for the ACME challenge config: its presence must not weaken mTLS on
	// the real-traffic path. Cert contents are irrelevant — these tests hit only the real-traffic branch.
	fn dummy_challenge_config() -> Arc<ServerConfig> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ck = generate_ca();
		let cert_der = CertificateDer::from(ck.cert.der().to_vec());
		let key_der = PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der());
		let mut cfg = ServerConfig::builder()
			.with_no_client_auth()
			.with_single_cert(vec![cert_der], PrivateKeyDer::Pkcs8(key_der))
			.unwrap();
		cfg.alpn_protocols = vec![ACME_TLS_ALPN_PROTO.to_vec()];
		return Arc::new(cfg);
	}

	// Bind the real dual-config listener (mandatory mTLS + a challenge config) and drive one accept.
	async fn bind_dual_config_listener(
		ca: &rcgen::CertifiedKey<rcgen::KeyPair>,
	) -> (SocketAddr, tokio::task::JoinHandle<Option<super::super::ConnectAddr>>) {
		let server_leaf = generate_localhost_cert(ca);
		let ca_file = write_pem(&ca.cert.pem());
		let cert_file = write_pem(&server_leaf.cert.pem());
		let key_file = write_pem(&server_leaf.signing_key.serialize_pem());
		let (server_config, _r) = build_server_config(cert_file.path(), key_file.path(), ca_file.path()).unwrap();

		let mut listener = TcpListener::bind(
			"127.0.0.1:0".parse().unwrap(),
			Arc::new(server_config),
			Some(dummy_challenge_config()),
		)
		.await
		.unwrap();
		let addr = axum::serve::Listener::local_addr(&listener).unwrap();

		// Returns the ConnectAddr of the first real (non-challenge) connection accept() yields.
		let handle = tokio::spawn(async move {
			let (io, peer) = axum::serve::Listener::accept(&mut listener).await;
			return Some(super::connect_addr_from_stream(peer, &io));
		});
		return (addr, handle);
	}

	#[tokio::test]
	async fn test_mtls_still_enforced_with_challenge_config_present() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let (addr, _handle) = bind_dual_config_listener(&ca).await;

		// Client trusts the server CA but presents NO client certificate.
		let ca_der = CertificateDer::from(ca.cert.der().to_vec());
		let mut roots = RootCertStore::empty();
		roots.add(ca_der).unwrap();
		let client_config = ClientConfig::builder()
			.with_root_certificates(roots)
			.with_no_client_auth();

		let connector = TlsConnector::from(Arc::new(client_config));
		let tcp = TcpStream::connect(addr).await.unwrap();
		let server_name: ServerName = ServerName::try_from("localhost").unwrap();
		// The server requires a client cert. Under TLS 1.3 connect() may resolve Ok (rejection then
		// surfaces on first read); under TLS 1.2 it errors outright. Either way, no usable session.
		match connector.connect(server_name, tcp).await {
			Err(_) => {}
			Ok(mut stream) => {
				let mut buf = [0u8; 1];
				let read = stream.read(&mut buf).await;
				let rejected = matches!(read, Err(_) | Ok(0));
				assert!(rejected, "mTLS listener served a client with no certificate");
			}
		}
	}

	#[tokio::test]
	async fn test_mtls_client_accepted_through_dual_config_listener() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let (addr, handle) = bind_dual_config_listener(&ca).await;

		// A valid mTLS client (cert CN device-9) must be accepted and surfaced with its identity.
		let client_leaf = {
			let key = rcgen::KeyPair::generate().unwrap();
			let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
			params.distinguished_name.push(
				rcgen::DnType::CommonName,
				rcgen::DnValue::Utf8String("device-9".to_string()),
			);
			let issuer = rcgen::Issuer::from_ca_cert_der(ca.cert.der(), &ca.signing_key).unwrap();
			let cert = params.signed_by(&key, &issuer).unwrap();
			rcgen::CertifiedKey { cert, signing_key: key }
		};
		let ca_file = write_pem(&ca.cert.pem());
		let client_cert_file = write_pem(&client_leaf.cert.pem());
		let client_key_file = write_pem(&client_leaf.signing_key.serialize_pem());
		let (client_config, _r, _v) =
			build_client_config(client_cert_file.path(), client_key_file.path(), ca_file.path()).unwrap();

		let connector = TlsConnector::from(Arc::new(client_config));
		let tcp = TcpStream::connect(addr).await.unwrap();
		let server_name: ServerName = ServerName::try_from("localhost").unwrap();
		let mut tls = connector.connect(server_name, tcp).await.unwrap();
		tls.write_all(b"x").await.unwrap();
		tls.flush().await.unwrap();

		let connect_addr = handle.await.unwrap().expect("accept yielded a connection");
		let identity = connect_addr.1.expect("identity present");
		assert_eq!(identity.common_name.as_str(), "device-9");
	}

	// Public-browser mode (client_auth = disabled): an anonymous client presenting NO client certificate
	// must complete the TLS handshake and be surfaced with a None identity. This is the functional inverse
	// of test_mtls_still_enforced_with_challenge_config_present, where the same certless client is rejected
	// under mandatory mTLS. Together they prove the policy — not ACME, not the CA — decides admission, and
	// that a disabled server requests no client cert (a certless browser succeeds).
	#[tokio::test]
	async fn test_disabled_client_auth_accepts_anonymous_client() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let server_leaf = generate_localhost_cert(&ca);
		let ca_file = write_pem(&ca.cert.pem());
		let cert_file = write_pem(&server_leaf.cert.pem());
		let key_file = write_pem(&server_leaf.signing_key.serialize_pem());

		// Disabled builds a server config with no client-cert verifier.
		let (server_config, _resolver, verifier) = build_server_config_for_policy(
			cert_file.path(),
			key_file.path(),
			ca_file.path(),
			None,
			ClientAuthPolicy::Disabled,
		)
		.unwrap();
		assert!(verifier.is_none(), "disabled policy must not build an inbound verifier");

		let mut listener = TcpListener::bind("127.0.0.1:0".parse().unwrap(), Arc::new(server_config), None)
			.await
			.unwrap();
		let addr = axum::serve::Listener::local_addr(&listener).unwrap();

		let handle = tokio::spawn(async move {
			let (io, peer) = axum::serve::Listener::accept(&mut listener).await;
			return super::connect_addr_from_stream(peer, &io);
		});

		// Anonymous browser: trusts the server CA but presents NO client certificate.
		let ca_der = CertificateDer::from(ca.cert.der().to_vec());
		let mut roots = RootCertStore::empty();
		roots.add(ca_der).unwrap();
		let client_config = ClientConfig::builder()
			.with_root_certificates(roots)
			.with_no_client_auth();
		let connector = TlsConnector::from(Arc::new(client_config));
		let tcp = TcpStream::connect(addr).await.unwrap();
		let server_name: ServerName = ServerName::try_from("localhost").unwrap();
		// The handshake must SUCCEED for a certless client (mandatory mTLS would have rejected it).
		let mut tls = connector.connect(server_name, tcp).await.expect("anonymous handshake must succeed");
		tls.write_all(b"x").await.unwrap();
		tls.flush().await.unwrap();

		let connect_addr = handle.await.unwrap();
		assert!(
			connect_addr.1.is_none(),
			"an anonymous client must be surfaced with no mTLS identity"
		);
	}

	fn make_server_tls_config() -> Arc<rustls::ServerConfig> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let leaf = generate_localhost_cert(&ca);

		let ca_file = write_pem(&ca.cert.pem());
		let cert_file = write_pem(&leaf.cert.pem());
		let key_file = write_pem(&leaf.signing_key.serialize_pem());

		let (config, _resolver) = build_server_config(cert_file.path(), key_file.path(), ca_file.path()).unwrap();
		return Arc::new(config);
	}

	#[tokio::test]
	async fn test_tcp_listener_bind_and_local_addr() {
		let tls_config = make_server_tls_config();
		let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
		let listener = TcpListener::bind(addr, tls_config, None).await.unwrap();
		let local = axum::serve::Listener::local_addr(&listener).unwrap();
		assert_eq!(local.ip(), std::net::IpAddr::from([127, 0, 0, 1]));
		assert_ne!(local.port(), 0);
	}

	#[tokio::test]
	async fn test_tcp_listener_binds_ephemeral_port() {
		let tls_config = make_server_tls_config();
		let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
		let listener = TcpListener::bind(addr, tls_config, None).await.unwrap();
		let local = axum::serve::Listener::local_addr(&listener).unwrap();
		assert!(local.port() > 0);
	}

	#[tokio::test]
	async fn test_tcp_listener_two_listeners_different_ports() {
		let tls_config = make_server_tls_config();
		let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
		let listener1 = TcpListener::bind(addr, tls_config.clone(), None).await.unwrap();
		let listener2 = TcpListener::bind(addr, tls_config, None).await.unwrap();
		let port1 = axum::serve::Listener::local_addr(&listener1).unwrap().port();
		let port2 = axum::serve::Listener::local_addr(&listener2).unwrap().port();
		assert_ne!(port1, port2);
	}

	#[test]
	fn test_next_backoff_doubles_until_ceiling() {
		// Drives the actual accept-loop progression: each step multiplies by BACKOFF_MULTIPLIER,
		// the growth stays strictly increasing until it clamps, and it never exceeds MAX_BACKOFF.
		let mut backoff: Duration = INITIAL_BACKOFF;
		let next: Duration = next_backoff(backoff);
		assert_eq!(next, INITIAL_BACKOFF * BACKOFF_MULTIPLIER);

		let mut saturated = false;
		for _ in 0..20 {
			let stepped: Duration = next_backoff(backoff);
			assert!(stepped <= MAX_BACKOFF);
			assert!(stepped >= backoff);
			if stepped == MAX_BACKOFF {
				saturated = true;
			}
			backoff = stepped;
		}
		assert!(saturated, "backoff must reach the ceiling within 20 retries");
		// Once at the ceiling it is a fixed point.
		assert_eq!(next_backoff(MAX_BACKOFF), MAX_BACKOFF);
	}

	#[test]
	fn test_connect_addr_deref() {
		let addr = super::super::ConnectAddr("10.0.0.1:5000".parse().unwrap(), None);
		// The explicit deref is the behavior under test, so auto-deref must not be substituted here.
		#[allow(clippy::explicit_auto_deref)]
		let socket_addr: &SocketAddr = &*addr;
		assert_eq!(socket_addr.port(), 5000);
	}

	fn signed_client_cert(
		ca: &rcgen::CertifiedKey<rcgen::KeyPair>,
		cn: Option<&str>,
	) -> rcgen::CertifiedKey<rcgen::KeyPair> {
		let key = rcgen::KeyPair::generate().unwrap();
		let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
		params.distinguished_name = rcgen::DistinguishedName::new();
		match cn {
			Some(name) => params
				.distinguished_name
				.push(rcgen::DnType::CommonName, rcgen::DnValue::Utf8String(name.to_string())),
			// Only an Organization: the leaf genuinely has no CN, driving the None extraction branch.
			None => params.distinguished_name.push(
				rcgen::DnType::OrganizationName,
				rcgen::DnValue::Utf8String("Acme Org".to_string()),
			),
		}
		let issuer = rcgen::Issuer::from_ca_cert_der(ca.cert.der(), &ca.signing_key).unwrap();
		let cert = params.signed_by(&key, &issuer).unwrap();
		return rcgen::CertifiedKey { cert, signing_key: key };
	}

	// Drive a real mTLS handshake and return the ConnectAddr the server builds for the accepted
	// stream, so connect_addr_from_stream is exercised end-to-end for a client cert with `client_cn`.
	async fn connect_addr_for_client_cn(client_cn: Option<&str>) -> super::super::ConnectAddr {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let server_leaf = generate_localhost_cert(&ca);
		let client_leaf = signed_client_cert(&ca, client_cn);

		let ca_file = write_pem(&ca.cert.pem());
		let server_cert_file = write_pem(&server_leaf.cert.pem());
		let server_key_file = write_pem(&server_leaf.signing_key.serialize_pem());
		let client_cert_file = write_pem(&client_leaf.cert.pem());
		let client_key_file = write_pem(&client_leaf.signing_key.serialize_pem());

		let (server_config, _r1) =
			build_server_config(server_cert_file.path(), server_key_file.path(), ca_file.path()).unwrap();
		let (client_config, _r2, _v2) =
			build_client_config(client_cert_file.path(), client_key_file.path(), ca_file.path()).unwrap();

		let listener = TokioTcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
			.await
			.unwrap();
		let addr: SocketAddr = listener.local_addr().unwrap();
		let acceptor = TlsAcceptor::from(Arc::new(server_config));

		let server = tokio::spawn(async move {
			let (tcp, peer) = listener.accept().await.unwrap();
			let mut tls = acceptor.accept(tcp).await.unwrap();
			let connect_addr = super::connect_addr_from_stream(peer, &tls);
			let mut buf = [0u8; 1];
			let _ = tls.read(&mut buf).await;
			return connect_addr;
		});

		let connector = TlsConnector::from(Arc::new(client_config));
		let tcp = TcpStream::connect(addr).await.unwrap();
		let server_name: ServerName = ServerName::try_from("localhost").unwrap();
		let mut tls = connector.connect(server_name, tcp).await.unwrap();
		tls.write_all(b"x").await.unwrap();
		tls.flush().await.unwrap();

		return server.await.unwrap();
	}

	#[tokio::test]
	async fn test_connect_addr_from_stream_extracts_identity() {
		let connect_addr = connect_addr_for_client_cn(Some("device-42")).await;
		let identity = connect_addr.1.expect("identity present for CN cert");
		assert_eq!(identity.common_name.as_str(), "device-42");
	}

	#[tokio::test]
	async fn test_connect_addr_from_stream_none_when_cn_missing() {
		let connect_addr = connect_addr_for_client_cn(None).await;
		assert!(connect_addr.1.is_none());
	}

	#[tokio::test]
	async fn test_slow_client_does_not_block_accept() {
		// A client that connects then never sends a ClientHello must not hold up a later healthy
		// client. Under the old inline-handshake loop the silent connection blocked accept() forever.
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let server_leaf = generate_localhost_cert(&ca);
		let client_leaf = signed_client_cert(&ca, Some("device-live"));

		let ca_file = write_pem(&ca.cert.pem());
		let server_cert_file = write_pem(&server_leaf.cert.pem());
		let server_key_file = write_pem(&server_leaf.signing_key.serialize_pem());
		let client_cert_file = write_pem(&client_leaf.cert.pem());
		let client_key_file = write_pem(&client_leaf.signing_key.serialize_pem());

		let (server_config, _r1) =
			build_server_config(server_cert_file.path(), server_key_file.path(), ca_file.path()).unwrap();
		let (client_config, _r2, _v2) =
			build_client_config(client_cert_file.path(), client_key_file.path(), ca_file.path()).unwrap();

		let mut listener = TcpListener::bind("127.0.0.1:0".parse().unwrap(), Arc::new(server_config), None)
			.await
			.unwrap();
		let addr = axum::serve::Listener::local_addr(&listener).unwrap();

		// Silent client: connects, then sends nothing. Held open for the duration of the test.
		let _silent = TcpStream::connect(addr).await.unwrap();
		tokio::time::sleep(Duration::from_millis(50)).await;

		// Healthy mTLS client connects afterwards and completes its handshake.
		let connector = TlsConnector::from(Arc::new(client_config));
		let server_name: ServerName = ServerName::try_from("localhost").unwrap();
		let live = tokio::spawn(async move {
			let tcp = TcpStream::connect(addr).await.unwrap();
			let mut tls = connector.connect(server_name, tcp).await.unwrap();
			tls.write_all(b"x").await.unwrap();
			tls.flush().await.unwrap();
			tokio::time::sleep(Duration::from_millis(200)).await;
		});

		let (io, peer) = tokio::time::timeout(Duration::from_secs(5), axum::serve::Listener::accept(&mut listener))
			.await
			.expect("accept blocked on the silent client");
		let identity = connect_addr_from_stream(peer, &io)
			.1
			.expect("identity present for live client");
		assert_eq!(identity.common_name.as_str(), "device-live");
		live.await.unwrap();
	}
}
