use std::path::{Path, PathBuf};
use std::sync::Arc;

use reduction::config::{self, ReductionConfig, ServerTlsConfig};
use reduction::error::{ReductionError, Result};
use reduction::metrics::{self, ProxyMetrics};
use reduction::tls;
use tokio::sync::watch;
use tokio_rustls::TlsConnector;
#[cfg(feature = "acme")]
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

// Inbound TLS server config plus hot-reload watchers, held by the caller for the process lifetime.
struct ServerTls {
	config: Arc<rustls::ServerConfig>,
	// tls-alpn-01 challenge config selected per-ClientHello under ACME; None for manual certs.
	challenge_config: Option<Arc<rustls::ServerConfig>>,
	_cert_watcher: Option<tls::CertWatcher>,
	_trust_watcher: Option<tls::TrustWatcher>,
	// The ACME renewal task's stop signal, bridged to the shutdown token by the caller.
	#[cfg(feature = "acme")]
	acme_shutdown_tx: Option<watch::Sender<()>>,
}

// Build the inbound TLS server config and hot-reload watchers, dispatching to the manual or ACME helper.
async fn build_server_tls(
	config: &ReductionConfig,
	client_cert_resolver: Option<Arc<tls::ReloadingCertResolver>>,
) -> Result<ServerTls> {
	let policy: config::ClientAuthPolicy = config.listen.client_auth;
	return match &config.tls.server {
		ServerTlsConfig::Manual(identity) => build_manual_server_tls(identity, policy, client_cert_resolver),
		#[cfg(feature = "acme")]
		ServerTlsConfig::Acme(acme_config) => build_acme_server_tls(acme_config, policy).await,
	};
}

// Inbound-trust hot-reload watcher for a server whose policy produced a verifier; `None` watches nothing.
fn build_server_trust_watcher(
	verifier: Option<Arc<tls::ReloadingClientVerifier>>,
	trigger_paths: &[PathBuf],
) -> Result<Option<tls::TrustWatcher>> {
	let Some(verifier) = verifier else {
		warn!("inbound client-cert verification DISABLED: anonymous clients accepted (public-browser mode)");
		return Ok(None);
	};
	let watcher: tls::TrustWatcher =
		tls::TrustWatcher::new(verifier, trigger_paths, tls::TRUST_SIDE_SERVER, ProxyMetrics::new())?;
	info!(files = trigger_paths.len(), "inbound CA trust-anchor hot-reload enabled");
	return Ok(Some(watcher));
}

// Manual-cert inbound TLS: a reloadable server-cert resolver, plus a CA/CRL trust watcher unless Disabled.
fn build_manual_server_tls(
	identity: &config::TlsIdentity,
	policy: config::ClientAuthPolicy,
	client_cert_resolver: Option<Arc<tls::ReloadingCertResolver>>,
) -> Result<ServerTls> {
	let crl_path: Option<&std::path::Path> = identity.crl_path.as_deref();
	let (cfg, server_cert_resolver, verifier) = tls::build_server_config_for_policy(
		&identity.cert_path,
		&identity.key_path,
		&identity.ca_cert_path,
		crl_path,
		policy,
	)?;
	// Co-watch the client identity only when one was loaded; a plaintext-backend deployment has none.
	let cert_watcher: tls::CertWatcher = match client_cert_resolver {
		Some(client) => tls::CertWatcher::new(server_cert_resolver, client)?,
		None => tls::CertWatcher::new_server_only(server_cert_resolver)?,
	};
	// Trigger files: the CA bundle always, plus the CRL when configured (deduplicated in the watcher).
	let mut trust_paths: Vec<PathBuf> = vec![identity.ca_cert_path.clone()];
	if let Some(crl) = crl_path {
		trust_paths.push(crl.to_path_buf());
	}
	let trust_watcher: Option<tls::TrustWatcher> = build_server_trust_watcher(verifier, &trust_paths)?;
	return Ok(ServerTls {
		config: Arc::new(cfg),
		challenge_config: None,
		_cert_watcher: Some(cert_watcher),
		_trust_watcher: trust_watcher,
		#[cfg(feature = "acme")]
		acme_shutdown_tx: None,
	});
}

// ACME inbound TLS: the server cert is provisioned by a renewal task (spawned here) and tls-alpn-01 is
// answered on a separate challenge config. Inbound client-cert verification hot-reloads as the manual path.
#[cfg(feature = "acme")]
async fn build_acme_server_tls(acme_config: &config::AcmeTlsConfig, policy: config::ClientAuthPolicy) -> Result<ServerTls> {
	let resolver = Arc::new(tls::AcmeCertResolver::new());
	let (cfg, verifier) =
		tls::build_acme_server_config_for_policy(acme_config.ca_cert_path.as_deref(), resolver.clone(), policy)?;
	let challenge_config: Option<Arc<rustls::ServerConfig>> =
		Some(Arc::new(tls::build_acme_challenge_config(resolver.clone())));
	// The CA is a trigger file exactly when a verifier was built (ca_cert_path present); empty otherwise.
	let trust_paths: Vec<PathBuf> = acme_config.ca_cert_path.iter().cloned().collect();
	let trust_watcher: Option<tls::TrustWatcher> = build_server_trust_watcher(verifier, &trust_paths)?;

	let (shutdown_tx, shutdown_rx) = watch::channel(());
	let task = tls::AcmeRenewalTask::new(acme_config.clone(), resolver, shutdown_rx, ProxyMetrics::new());
	task.provision_initial_cert().await?;
	tokio::spawn(async move {
		task.run().await;
	});
	return Ok(ServerTls {
		config: Arc::new(cfg),
		challenge_config,
		_cert_watcher: None,
		_trust_watcher: trust_watcher,
		acme_shutdown_tx: Some(shutdown_tx),
	});
}

// Metrics, config hot-reload, and all TLS (client + server configs with watchers), held for the process lifetime.
pub struct TlsSetup {
	pub proxy_metrics: ProxyMetrics,
	pub config_rx: watch::Receiver<ReductionConfig>,
	pub client_tls_config: Arc<rustls::ClientConfig>,
	pub tls_connector: TlsConnector,
	pub server_tls_config: Arc<rustls::ServerConfig>,
	pub acme_challenge_config: Option<Arc<rustls::ServerConfig>>,
	pub _config_watcher: config::watcher::ConfigWatcher,
	// None when no backend needs a client identity (plaintext-backend mode): there is no backend CA to watch.
	pub _client_trust_watcher: Option<tls::TrustWatcher>,
	pub _cert_watcher: Option<tls::CertWatcher>,
	pub _trust_watcher: Option<tls::TrustWatcher>,
	#[cfg(feature = "acme")]
	pub acme_shutdown_tx: Option<watch::Sender<()>>,
}

pub async fn build_tls_setup(config_path: &Path, config: &ReductionConfig) -> Result<TlsSetup> {
	metrics::init_metrics(&config.metrics)?;
	let proxy_metrics: ProxyMetrics = ProxyMetrics::new();

	let (config_tx, config_rx): (watch::Sender<ReductionConfig>, watch::Receiver<ReductionConfig>) =
		watch::channel(config.clone());
	let _config_watcher: config::watcher::ConfigWatcher = config::watcher::ConfigWatcher::new(config_path, config_tx)?;

	let ClientTls {
		config: client_tls_config,
		connector: tls_connector,
		cert_resolver: client_cert_resolver,
		trust_watcher: _client_trust_watcher,
	} = build_client_tls(config)?;

	let ServerTls {
		config: server_tls_config,
		challenge_config: acme_challenge_config,
		_cert_watcher,
		_trust_watcher,
		#[cfg(feature = "acme")]
		acme_shutdown_tx,
	} = build_server_tls(config, client_cert_resolver).await?;

	return Ok(TlsSetup {
		proxy_metrics,
		config_rx,
		client_tls_config,
		tls_connector,
		server_tls_config,
		acme_challenge_config,
		_config_watcher,
		_client_trust_watcher,
		_cert_watcher,
		_trust_watcher,
		#[cfg(feature = "acme")]
		acme_shutdown_tx,
	});
}

// Backend-facing client TLS: the mTLS ClientConfig, connector, client-identity cert resolver, and backend-CA watcher.
struct ClientTls {
	config: Arc<rustls::ClientConfig>,
	connector: TlsConnector,
	cert_resolver: Option<Arc<tls::ReloadingCertResolver>>,
	trust_watcher: Option<tls::TrustWatcher>,
}

// A no-file, no-trust ClientConfig standing in when every backend is cleartext HTTP/1.1: ProxyState still
// carries a connector, but the plaintext dial path never uses it and no mTLS material is loaded.
fn empty_client_config() -> Arc<rustls::ClientConfig> {
	return Arc::new(
		rustls::ClientConfig::builder()
			.with_root_certificates(rustls::RootCertStore::empty())
			.with_no_client_auth(),
	);
}

// Build the backend-facing client TLS. When any backend handshakes upstream (quic/https), load the
// [tls.client] identity, its reloadable mTLS ClientConfig + connector, and the backend-CA trust watcher.
// When every backend is cleartext (tcp + http), load nothing — an empty connector stands in.
fn build_client_tls(config: &ReductionConfig) -> Result<ClientTls> {
	if !config.needs_client_tls() {
		let empty: Arc<rustls::ClientConfig> = empty_client_config();
		let connector: TlsConnector = TlsConnector::from(empty.clone());
		info!("no backend needs a TLS client identity; [tls.client] not loaded (plaintext-backend mode)");
		return Ok(ClientTls { config: empty, connector, cert_resolver: None, trust_watcher: None });
	}

	let identity: &config::TlsIdentity = config.tls.client.as_ref().ok_or_else(|| {
		ReductionError::Config(
			"a backend requires a TLS client identity but [tls.client] is absent (should be rejected at validation)".to_owned(),
		)
	})?;

	let (client_tls_config, client_cert_resolver, client_trust_verifier) =
		tls::build_client_config(&identity.cert_path, &identity.key_path, &identity.ca_cert_path)?;
	let client_tls_config: Arc<rustls::ClientConfig> = Arc::new(client_tls_config);

	// Hot-reload the trust anchors that verify backend server certs (tls.client.ca_cert_path): the
	// verifier's inner roots swap in place, so a backend-CA rotation takes effect on the next handshake.
	let trust_watcher: tls::TrustWatcher = tls::TrustWatcher::new(
		client_trust_verifier,
		std::slice::from_ref(&identity.ca_cert_path),
		tls::TRUST_SIDE_CLIENT,
		ProxyMetrics::new(),
	)?;
	info!(ca = %identity.ca_cert_path.display(), "backend CA trust-anchor hot-reload enabled");

	let connector: TlsConnector = TlsConnector::from(client_tls_config.clone());
	return Ok(ClientTls {
		config: client_tls_config,
		connector,
		cert_resolver: Some(client_cert_resolver),
		trust_watcher: Some(trust_watcher),
	});
}

// Bridge the process-wide shutdown token to the ACME renewal task's watch channel, so ctrl-c / SIGTERM
// stops cert renewal alongside every other long-lived task.
#[cfg(feature = "acme")]
pub fn bridge_acme_shutdown(shutdown_token: &CancellationToken, acme_shutdown_tx: Option<watch::Sender<()>>) {
	let Some(acme_shutdown_tx) = acme_shutdown_tx else {
		return;
	};
	let acme_cancel: CancellationToken = shutdown_token.clone();
	tokio::spawn(async move {
		acme_cancel.cancelled().await;
		// A failed send only means the renewal task already exited on its own.
		acme_shutdown_tx.send(()).ok();
	});
}

#[cfg(test)]
mod client_tls_tests {
	use reduction::config::ReductionConfig;
	use reduction::error::Result;

	use super::{ClientTls, build_client_tls};

	// Public-style config: tcp listener, one cleartext-http backend, and NO [tls.client].
	const PLAINTEXT_CONFIG: &str = r#"
[listen]
address = "127.0.0.1:8443"
transport = "tcp"
client_auth = "disabled"

[tls.server.manual]
cert_path = "certs/server.crt"
key_path = "certs/server.key"
ca_cert_path = "certs/ca.crt"

[[backends]]
id = "blog"
address = "127.0.0.1:8080"
weight = 1.0
transport = "tcp"
scheme = "http"

[[routes]]
path_prefix = "/"
backend_id = "blog"
"#;

	// A pure plaintext-backend deployment must build client TLS WITHOUT loading any identity (no cert
	// resolver, no backend-CA watcher) — asserting the no-load branch, not merely that the config parses.
	#[test]
	fn build_client_tls_loads_nothing_for_plaintext_backends() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let parsed: std::result::Result<ReductionConfig, toml::de::Error> = toml::from_str(PLAINTEXT_CONFIG);
		assert!(parsed.is_ok(), "plaintext config parses");
		let Ok(config) = parsed else { return };
		assert!(!config.needs_client_tls());
		let built: Result<ClientTls> = build_client_tls(&config);
		assert!(built.is_ok(), "plaintext client TLS builds");
		let Ok(client_tls) = built else { return };
		assert!(client_tls.cert_resolver.is_none(), "no client identity must be loaded");
		assert!(client_tls.trust_watcher.is_none(), "no backend-CA watcher without an identity");
	}
}
