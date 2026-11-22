// The remote end of a paired uplink: a QUIC listener with mTLS whose streams each carry one CONNECT.
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use tracing::info;

use super::uplink::UPLINK_ALPN;
use super::uplink_tls::TlsWatch;
use crate::config::UplinkListenerConfig;
use crate::error::Result;
use crate::tls::certs::{build_server_config_reloadable, refuse_resumption};
use crate::transport::quic_listener::{EarlyData, QuicListener, Reloading, ZeroRtt, build_quic_server_config_with_streams};

// Streams that wait for the gateway to accept them. The tunnel cap, not this queue, bounds open tunnels.
const ACCEPT_QUEUE: usize = 256;

// The listener and the watchers of its TLS files. A rotated file applies at the next handshake.
pub struct UplinkListener {
	pub quic: QuicListener,
	pub watch: TlsWatch,
}

pub fn bind_uplink_listener(
	config: &UplinkListenerConfig,
	max_tunnels: NonZeroU32,
	shutdown: CancellationToken,
) -> Result<UplinkListener> {
	let (mut tls, identity, trust) =
		build_server_config_reloadable(&config.cert_path, &config.key_path, &config.ca_cert_path, None)?;
	let watch: TlsWatch = TlsWatch::listener(Arc::clone(&identity), Arc::clone(&trust), &config.ca_cert_path)?;
	tls.alpn_protocols = vec![UPLINK_ALPN.to_vec()];
	let early: EarlyData = EarlyData::new(tls, Reloading { identity, trust }, max_tunnels.get(), ZeroRtt::Accept);
	let listener: QuicListener = QuicListener::bind_early(config.listen, early, shutdown, ACCEPT_QUEUE)?;
	return Ok(UplinkListener { quic: http_only(listener)?, watch });
}

// A listener over a fixed TLS config: no reload, so no tickets and no 0-RTT.
pub fn bind_with_tls(
	listen: SocketAddr,
	mut tls: rustls::ServerConfig,
	max_tunnels: NonZeroU32,
	shutdown: CancellationToken,
) -> Result<QuicListener> {
	tls.alpn_protocols = vec![UPLINK_ALPN.to_vec()];
	refuse_resumption(&mut tls);
	let quic: quinn::ServerConfig = build_quic_server_config_with_streams(Arc::new(tls), max_tunnels.get())?;
	return http_only(QuicListener::bind_with_token(listen, quic, shutdown, ACCEPT_QUEUE)?);
}

// Only HTTP streams reach the gateway. A raw stream has no use on an uplink, so the listener drops it.
fn http_only(mut listener: QuicListener) -> Result<QuicListener> {
	drop(listener.take_raw_stream_receiver());
	info!(listen = %listener.local_addr()?, "egress uplink listener bound");
	return Ok(listener);
}

#[cfg(test)]
mod tests {
	use std::num::NonZeroU16;
	use std::path::PathBuf;
	use std::result::Result as StdResult;

	use arrayvec::ArrayString;
	use rcgen::{CertifiedKey, KeyPair, SanType};
	use tempfile::NamedTempFile;

	use server_utils::ctx::Ctx;

	use super::*;
	use crate::config::{EgressConfig, MAX_HOST_LEN, RateLimitConfig};
	use crate::egress::authority::Target;
	use crate::egress::listener::EGRESS_HEAD_LIMITS;
	use crate::egress::testutil::{
		Ends, LOOPBACK_EXCEPTIONS, STEP_TIMEOUT, Started, WatchedFiles, echo_server, launch_with, loopback_egress, open_access,
		until_reloaded,
	};
	use crate::egress::uplink::Uplink;
	use crate::test_support::{LOOPBACK_ANY, LeafFiles, Pki, generate_ca, generate_signed_cert, leaf_files, pki, write_pem};
	use crate::tls::certs::build_client_config;

	// The remote leaf carries the loopback IP SAN, so the inner names the remote by its address.
	const REMOTE_NAME: &str = "127.0.0.1";

	fn config(pki: &Pki, cert_path: PathBuf) -> UplinkListenerConfig {
		return UplinkListenerConfig {
			listen: LOOPBACK_ANY,
			cert_path,
			key_path: pki.server.key.path().to_path_buf(),
			ca_cert_path: pki.ca_file.path().to_path_buf(),
		};
	}

	// The same table with its real leaf binds a port. When the leaf file does not exist, it fails before any bind.
	#[tokio::test]
	async fn a_listener_binds_from_its_files_and_refuses_an_absent_leaf() -> StdResult<(), String> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let pki: Pki = pki("egress-inner")?;
		let good: UplinkListenerConfig = config(&pki, pki.server.cert.path().to_path_buf());
		let listener: UplinkListener = bind_uplink_listener(&good, NonZeroU32::MIN, CancellationToken::new()).ctx("bind")?;
		assert_ne!(listener.quic.local_addr().ctx("addr")?.port(), 0, "the OS gave the listener a port");

		let missing: UplinkListenerConfig = config(&pki, pki.ca_file.path().with_extension("absent"));
		assert!(bind_uplink_listener(&missing, NonZeroU32::MIN, CancellationToken::new()).is_err(), "a missing leaf is a startup error");
		return Ok(());
	}

	// A remote that serves on an uplink listener over watched files, with its uplink address.
	struct WatchedRemote {
		_remote: Started,
		_watch: TlsWatch,
		files: WatchedFiles,
		quic: SocketAddr,
	}

	async fn watched_remote(echo: SocketAddr, leaf: &CertifiedKey<KeyPair>, ca: &CertifiedKey<KeyPair>) -> StdResult<WatchedRemote, String> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let files: WatchedFiles = WatchedFiles::new(leaf, ca)?;
		let config: UplinkListenerConfig = UplinkListenerConfig {
			listen: LOOPBACK_ANY,
			cert_path: files.cert.clone(),
			key_path: files.key.clone(),
			ca_cert_path: files.ca.clone(),
		};
		let gateway: EgressConfig = loopback_egress(echo, LOOPBACK_EXCEPTIONS)?;
		let UplinkListener { quic, watch } = bind_uplink_listener(&config, gateway.max_tunnels, CancellationToken::new()).ctx("bind")?;
		let addr: SocketAddr = quic.local_addr().ctx("uplink listener addr")?;
		let ends: Ends = Ends { uplink: None, uplinks: Some(quic) };
		let remote: Started = launch_with(&gateway, open_access(), &RateLimitConfig::default(), EGRESS_HEAD_LIMITS, ends).await?;
		return Ok(WatchedRemote { _remote: remote, _watch: watch, files, quic: addr });
	}

	fn remote_leaf(ca: &CertifiedKey<KeyPair>) -> StdResult<CertifiedKey<KeyPair>, String> {
		return generate_signed_cert(ca, "egress-remote", vec![SanType::IpAddress(LOOPBACK_ANY.ip())]);
	}

	// An inner TLS config with a leaf from `leaf_ca` that trusts `remote_ca`. The config keeps no file open.
	fn inner_tls(leaf_ca: &CertifiedKey<KeyPair>, remote_ca: &CertifiedKey<KeyPair>) -> StdResult<rustls::ClientConfig, String> {
		let leaf: LeafFiles = generate_signed_cert(leaf_ca, "egress-inner", vec![]).and_then(leaf_files)?;
		let ca_file: NamedTempFile = write_pem(&remote_ca.cert.pem())?;
		let (tls, _identity, _trust) = build_client_config(leaf.cert.path(), leaf.key.path(), ca_file.path()).ctx("inner TLS")?;
		return Ok(tls);
	}

	// Each probe is a new uplink, so it makes a new handshake and reads the listener's current files.
	async fn is_tunnel_open(remote: &WatchedRemote, tls: &rustls::ClientConfig, echo: SocketAddr) -> StdResult<bool, String> {
		let name: ArrayString<MAX_HOST_LEN> = ArrayString::from(REMOTE_NAME).ctx("server name")?;
		let uplink: Uplink = Uplink::with_tls(remote.quic, name, tls.clone()).ctx("probe uplink")?;
		let target: Target = Target { host: ArrayString::from("localhost").ctx("host")?, port: NonZeroU16::new(echo.port()).ok_or("zero port")? };
		return Ok(uplink.open(&target, STEP_TIMEOUT).await.is_ok());
	}

	// The remote's first CA did not sign the inner's leaf. After the CA file reloads, the same inner gets a tunnel.
	#[tokio::test]
	async fn a_reloaded_listener_ca_admits_the_inner_it_now_signs() -> StdResult<(), String> {
		let echo: SocketAddr = echo_server().await?;
		let (ca, inner_ca): (CertifiedKey<KeyPair>, CertifiedKey<KeyPair>) = (generate_ca()?, generate_ca()?);
		let remote: WatchedRemote = watched_remote(echo, &remote_leaf(&ca)?, &ca).await?;
		let inner: rustls::ClientConfig = inner_tls(&inner_ca, &ca)?;
		assert!(!is_tunnel_open(&remote, &inner, echo).await?, "the first CA does not sign the inner's leaf");
		until_reloaded("the listener CA", || remote.files.write_ca(&inner_ca), async || {
			return is_tunnel_open(&remote, &inner, echo).await.unwrap_or(false);
		})
		.await?;
		return Ok(());
	}

	// The remote's leaf reloads to one that the inner's CA did not sign, so the next handshake fails.
	#[tokio::test]
	async fn a_reloaded_listener_leaf_serves_the_next_handshake() -> StdResult<(), String> {
		let echo: SocketAddr = echo_server().await?;
		let (ca, foreign): (CertifiedKey<KeyPair>, CertifiedKey<KeyPair>) = (generate_ca()?, generate_ca()?);
		let remote: WatchedRemote = watched_remote(echo, &remote_leaf(&ca)?, &ca).await?;
		let inner: rustls::ClientConfig = inner_tls(&ca, &ca)?;
		assert!(is_tunnel_open(&remote, &inner, echo).await?, "the first leaf is trusted");
		let untrusted: CertifiedKey<KeyPair> = remote_leaf(&foreign)?;
		until_reloaded("the listener leaf", || remote.files.write_leaf(&untrusted), async || {
			return is_tunnel_open(&remote, &inner, echo).await.is_ok_and(|is_open: bool| return !is_open);
		})
		.await?;
		return Ok(());
	}
}
