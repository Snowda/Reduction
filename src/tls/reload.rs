use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
#[cfg(feature = "proxy")]
use std::time::Duration;

#[cfg(feature = "proxy")]
use notify::{Event, RecommendedWatcher};
#[cfg(feature = "proxy")]
use opentelemetry::KeyValue;
use rustls::SignatureScheme;
use rustls::client::ResolvesClientCert;
use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
// error! appears only in the proxy-gated fs-watcher reload closures below.
#[cfg(feature = "proxy")]
use tracing::error;
use tracing::info;

use crate::error::{ReductionError, Result};
#[cfg(feature = "proxy")]
use crate::fs_watch::{WatchSetupFailure, spawn_trailing_edge_watcher};
use crate::tls::certs::{load_certs, load_private_key};

// The two hot-reloadable mTLS verifiers live in submodules; re-exported so `crate::tls::reload::X` stays stable.
mod client_verifier;
mod server_verifier;
#[cfg(test)]
mod testutil;

pub use client_verifier::ReloadingClientVerifier;
pub use server_verifier::ReloadingServerVerifier;

// A CertifiedKey that is hot-swappable in place. One type serves both rustls roles — it implements
// ResolvesServerCert and ResolvesClientCert — because the reload machinery is identical for each;
// every instance watches a single cert/key pair and is handed to rustls in exactly one role. Reloads
// swap the key behind an RwLock, so live listeners and the connection pool pick up a rotated cert on
// the next handshake. The Arc handed to rustls stays the same object across reloads.
pub struct ReloadingCertResolver {
	inner: RwLock<Arc<CertifiedKey>>,
	cert_path: PathBuf,
	key_path: PathBuf,
}

impl ReloadingCertResolver {
	pub fn new(cert_path: &Path, key_path: &Path) -> Result<Self> {
		let certified_key: CertifiedKey = build_certified_key(cert_path, key_path)?;
		return Ok(Self {
			inner: RwLock::new(Arc::new(certified_key)),
			cert_path: cert_path.to_path_buf(),
			key_path: key_path.to_path_buf(),
		});
	}

	pub fn reload(&self) -> Result<()> {
		let new_key: CertifiedKey = build_certified_key(&self.cert_path, &self.key_path)?;
		let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
		*guard = Arc::new(new_key);
		// The role (server/client) is logged by the watcher; the path here identifies which cert.
		info!(cert = %self.cert_path.display(), "certificate reloaded");
		return Ok(());
	}

	pub fn current(&self) -> Arc<CertifiedKey> {
		let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
		return Arc::clone(&guard);
	}
}

impl fmt::Debug for ReloadingCertResolver {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		return f
			.debug_struct("ReloadingCertResolver")
			.field("cert_path", &self.cert_path)
			.field("key_path", &self.key_path)
			.finish();
	}
}

impl ResolvesServerCert for ReloadingCertResolver {
	fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
		return Some(self.current());
	}
}

impl ResolvesClientCert for ReloadingCertResolver {
	fn resolve(&self, _root_hint_subjects: &[&[u8]], _sigschemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
		return Some(self.current());
	}

	fn has_certs(&self) -> bool {
		return true;
	}
}

// Load PEM-encoded X.509 CRLs from a file. An empty file yields an empty list (no revocations); a
// malformed file is an error the caller maps to last-known-good.

// Trust material that re-reads its backing file(s) and hot-swaps in place. Both verifier sides implement
// it so one generic TrustWatcher drives either — server (inbound client-cert) and client (outbound server-cert).
pub trait Reloadable: Send + Sync {
	fn reload(&self) -> Result<()>;
}


// Build a server-cert verifier from disk. An empty/missing/garbage bundle errors (load_ca_certs rejects
// empty), so a reload reading nothing keeps the previous roots — never an empty trust store.

fn build_certified_key(cert_path: &Path, key_path: &Path) -> Result<CertifiedKey> {
	let certs: Vec<CertificateDer<'static>> = load_certs(cert_path)?;
	let key = load_private_key(key_path)?;

	let provider = rustls::crypto::CryptoProvider::get_default()
		.ok_or_else(|| ReductionError::Config("no default crypto provider installed".to_owned()))?;

	let certified_key = CertifiedKey::from_der(certs, key, provider)
		.map_err(|e| ReductionError::Config(format!("failed to build certified key: {e}")))?;

	return Ok(certified_key);
}

// The fs-watcher is proxy-side: it drags the notify dependency, and lean clients reload certs
// via their own renewal flow rather than watching files. The resolvers above stay core.
#[cfg(feature = "proxy")]
const CERT_RELOAD_DEBOUNCE_MS: u64 = 300;

#[cfg(feature = "proxy")]
pub struct CertWatcher {
	_watcher: RecommendedWatcher,
}

#[cfg(feature = "proxy")]
impl CertWatcher {
	// cognitive_complexity is attributed here to the file-event closure passed to the watcher; its body
	// (two path-affinity checks, each reloading the matching side) is over-counted by the nested `.any()`
	// closures and reload-result match arms, not genuine branching.
	pub fn new(
		server_resolver: Arc<ReloadingCertResolver>,
		client_resolver: Arc<ReloadingCertResolver>,
	) -> Result<Self> {
		return Self::with_optional_client(server_resolver, Some(client_resolver));
	}

	// Server-cert-only watcher: no backend-facing client identity to co-watch (public/plaintext-backend
	// deployment). Used when the manual server path runs without a [tls.client] identity.
	pub fn new_server_only(server_resolver: Arc<ReloadingCertResolver>) -> Result<Self> {
		return Self::with_optional_client(server_resolver, None);
	}

	// The winning event of a debounce burst decides which side(s) to reload; a reload re-reads the settled
	// file and keeps the previous key on failure (last-known-good). The client side is watched only when a
	// client resolver is present.
	#[allow(clippy::cognitive_complexity)]
	fn with_optional_client(
		server_resolver: Arc<ReloadingCertResolver>,
		client_resolver: Option<Arc<ReloadingCertResolver>>,
	) -> Result<Self> {
		let debounce: Duration = Duration::from_millis(CERT_RELOAD_DEBOUNCE_MS);
		let server_cert_path: PathBuf = server_resolver.cert_path.clone();
		let server_key_path: PathBuf = server_resolver.key_path.clone();
		let client_paths: Option<(PathBuf, PathBuf)> = client_resolver
			.as_ref()
			.map(|r| (r.cert_path.clone(), r.key_path.clone()));
		let mut trigger_paths: Vec<PathBuf> = vec![server_cert_path.clone(), server_key_path.clone()];
		if let Some((cert, key)) = &client_paths {
			trigger_paths.push(cert.clone());
			trigger_paths.push(key.clone());
		}

		let watcher: RecommendedWatcher = spawn_trailing_edge_watcher(
			&trigger_paths,
			debounce,
			"cert",
			WatchSetupFailure::Warn,
			move |event: &Event| {
				let affected_server: bool = event
					.paths
					.iter()
					.any(|p| p == &server_cert_path || p == &server_key_path);
				let affected_client: bool = client_paths
					.as_ref()
					.is_some_and(|(cert, key)| event.paths.iter().any(|p| p == cert || p == key));
				if affected_server {
					match server_resolver.reload() {
						Ok(()) => info!("server certificate hot-reloaded"),
						Err(e) => error!(error = %e, "failed to reload server certificate, keeping previous"),
					}
				}
				if let (true, Some(client_resolver)) = (affected_client, client_resolver.as_ref()) {
					match client_resolver.reload() {
						Ok(()) => info!("client certificate hot-reloaded"),
						Err(e) => error!(error = %e, "failed to reload client certificate, keeping previous"),
					}
				}
			},
		)?;

		info!("watching certificate files for hot-reload");

		return Ok(Self { _watcher: watcher });
	}
}

// Values for the `side` metric attribute distinguishing the two trust stores a proxy reloads: the
// server side verifies inbound client certs (`tls.server.ca_cert_path`), the client side verifies the
// backend server certs this proxy dials (`tls.client.ca_cert_path`). One counter pair covers both,
// tagged by this attribute — cleaner than two near-identical counter pairs.
#[cfg(feature = "proxy")]
pub const TRUST_SIDE_SERVER: &str = "server";
#[cfg(feature = "proxy")]
pub const TRUST_SIDE_CLIENT: &str = "client";
#[cfg(feature = "proxy")]
const TRUST_SIDE_ATTR: &str = "side";

// Watches one or more trust files (a CA bundle, and — on the server side — an optional CRL), reloading
// the wrapped verifier in place when any of them changes. Generic over `Reloadable` so the same
// machinery drives either verifier side. Same notify + debounce pattern as CertWatcher. A failed
// reload keeps the previous trust material (last-known-good) and increments `ca_bundle_load_errors`; a
// success increments `ca_bundle_reloads`; both carry the `side` attribute. Each trigger file's parent
// directory is watched (files are often replaced by rename, which fires no event on the file node
// itself) and events are filtered to the exact trigger paths.
#[cfg(feature = "proxy")]
pub struct TrustWatcher {
	_watcher: RecommendedWatcher,
}

#[cfg(feature = "proxy")]
impl TrustWatcher {
	pub fn new<R: Reloadable + 'static>(
		reloadable: Arc<R>,
		trigger_paths: &[PathBuf],
		side: &'static str,
		metrics: crate::metrics::ProxyMetrics,
	) -> Result<Self> {
		let debounce: Duration = Duration::from_millis(CERT_RELOAD_DEBOUNCE_MS);
		let watcher: RecommendedWatcher = spawn_trailing_edge_watcher(
			trigger_paths,
			debounce,
			"trust",
			WatchSetupFailure::Warn,
			move |_event: &Event| match reloadable.reload() {
				Ok(()) => {
					metrics
						.ca_bundle_reloads
						.add(1, &[KeyValue::new(TRUST_SIDE_ATTR, side)]);
					info!(side, "trust anchors hot-reloaded");
				}
				Err(e) => {
					metrics
						.ca_bundle_load_errors
						.add(1, &[KeyValue::new(TRUST_SIDE_ATTR, side)]);
					error!(error = %e, side, "failed to reload trust anchors, keeping previous");
				}
			},
		)?;
		info!(side, files = trigger_paths.len(), "watching trust files for hot-reload");
		return Ok(Self { _watcher: watcher });
	}
}

#[cfg(test)]
mod tests {
	#[cfg(feature = "proxy")]
	use std::thread;

	#[cfg(feature = "proxy")]
	use tempfile::TempDir;

	use super::testutil::{crl_ca, crl_leaf, make_crl_pem, server_verifier_accepts, verifier_accepts};
	use super::*;
	use crate::test_support::{generate_ca, generate_localhost_cert, write_pem};

	// Poll interval must exceed CERT_RELOAD_DEBOUNCE_MS so repeated writes aren't all debounced away.
	#[cfg(feature = "proxy")]
	const RELOAD_POLL_INTERVAL_MS: u64 = 500;
	#[cfg(feature = "proxy")]
	const RELOAD_MAX_ATTEMPTS: u32 = 20;
	#[cfg(feature = "proxy")]
	const FAILED_RELOAD_SETTLE_MS: u64 = 1000;

	// Signs a fresh cert for an EXISTING key so tests can swap the cert file without touching the
	// key file — one fs event, and the on-disk pair never goes through a mismatched state.
	#[cfg(feature = "proxy")]
	fn generate_cert_pem_for_key(ca: &rcgen::CertifiedKey<rcgen::KeyPair>, key: &rcgen::KeyPair) -> String {
		let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
		params.distinguished_name.push(
			rcgen::DnType::CommonName,
			rcgen::DnValue::Utf8String("localhost".to_string()),
		);
		let issuer = rcgen::Issuer::from_ca_cert_der(ca.cert.der(), &ca.signing_key).unwrap();
		let cert = params.signed_by(key, &issuer).unwrap();
		return cert.pem();
	}

	#[cfg(feature = "proxy")]
	struct WatcherFixture {
		_dir: TempDir,
		server_cert_path: PathBuf,
		server_key_path: PathBuf,
		client_cert_path: PathBuf,
		server_resolver: Arc<ReloadingCertResolver>,
		client_resolver: Arc<ReloadingCertResolver>,
		ca: rcgen::CertifiedKey<rcgen::KeyPair>,
		server_key: rcgen::KeyPair,
		client_key: rcgen::KeyPair,
	}

	// Dedicated TempDir per test: watching the shared OS temp dir would let unrelated fs events
	// consume the watcher's debounce window.
	#[cfg(feature = "proxy")]
	fn watcher_fixture() -> WatcherFixture {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let server_key = rcgen::KeyPair::generate().unwrap();
		let client_key = rcgen::KeyPair::generate().unwrap();

		let dir = tempfile::tempdir().unwrap();
		let server_cert_path = dir.path().join("server-cert.pem");
		let server_key_path = dir.path().join("server-key.pem");
		let client_cert_path = dir.path().join("client-cert.pem");
		let client_key_path = dir.path().join("client-key.pem");

		std::fs::write(&server_cert_path, generate_cert_pem_for_key(&ca, &server_key)).unwrap();
		std::fs::write(&server_key_path, server_key.serialize_pem()).unwrap();
		std::fs::write(&client_cert_path, generate_cert_pem_for_key(&ca, &client_key)).unwrap();
		std::fs::write(&client_key_path, client_key.serialize_pem()).unwrap();

		let server_resolver = Arc::new(ReloadingCertResolver::new(&server_cert_path, &server_key_path).unwrap());
		let client_resolver = Arc::new(ReloadingCertResolver::new(&client_cert_path, &client_key_path).unwrap());

		return WatcherFixture {
			_dir: dir,
			server_cert_path,
			server_key_path,
			client_cert_path,
			server_resolver,
			client_resolver,
			ca,
			server_key,
			client_key,
		};
	}

	// Rewrites until the watcher picks the change up: a single write can race the debounce or be
	// read mid-write, so retrying beats one write + one long sleep for flake resistance.
	#[cfg(feature = "proxy")]
	fn write_until<F: Fn() -> bool>(path: &Path, pem: &str, reloaded: F) -> bool {
		for _ in 0..RELOAD_MAX_ATTEMPTS {
			std::fs::write(path, pem).unwrap();
			thread::sleep(Duration::from_millis(RELOAD_POLL_INTERVAL_MS));
			if reloaded() {
				return true;
			}
		}
		return false;
	}

	#[test]
	fn test_server_resolver_new_and_resolve() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let leaf = generate_localhost_cert(&ca);

		let cert_file = write_pem(&leaf.cert.pem());
		let key_file = write_pem(&leaf.signing_key.serialize_pem());

		let resolver = ReloadingCertResolver::new(cert_file.path(), key_file.path()).unwrap();
		let key = resolver.current();
		assert!(!key.cert.is_empty());
	}

	#[test]
	fn test_server_resolver_reload_with_new_cert() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let leaf1 = generate_localhost_cert(&ca);
		let leaf2 = generate_localhost_cert(&ca);

		let cert_file = write_pem(&leaf1.cert.pem());
		let key_file = write_pem(&leaf1.signing_key.serialize_pem());

		let resolver = ReloadingCertResolver::new(cert_file.path(), key_file.path()).unwrap();
		let key_before = resolver.current();

		std::fs::write(cert_file.path(), leaf2.cert.pem()).unwrap();
		std::fs::write(key_file.path(), leaf2.signing_key.serialize_pem()).unwrap();

		resolver.reload().unwrap();
		let key_after = resolver.current();

		assert_ne!(key_before.cert, key_after.cert);
	}

	#[test]
	fn test_server_resolver_reload_invalid_keeps_old() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let leaf = generate_localhost_cert(&ca);

		let cert_file = write_pem(&leaf.cert.pem());
		let key_file = write_pem(&leaf.signing_key.serialize_pem());

		let resolver = ReloadingCertResolver::new(cert_file.path(), key_file.path()).unwrap();
		let key_before = resolver.current();

		std::fs::write(cert_file.path(), "garbage").unwrap();

		let result = resolver.reload();
		assert!(result.is_err());

		let key_after = resolver.current();
		assert_eq!(key_before.cert, key_after.cert);
	}

	#[test]
	fn test_client_resolver_new_and_resolve() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let leaf = generate_localhost_cert(&ca);

		let cert_file = write_pem(&leaf.cert.pem());
		let key_file = write_pem(&leaf.signing_key.serialize_pem());

		let resolver = ReloadingCertResolver::new(cert_file.path(), key_file.path()).unwrap();
		assert!(resolver.has_certs());

		// The type implements both resolver traits, so name the client-cert one explicitly.
		let key = ResolvesClientCert::resolve(&resolver, &[], &[]);
		assert!(key.is_some());
	}

	#[test]
	fn test_client_resolver_reload() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let ca = generate_ca();
		let leaf1 = generate_localhost_cert(&ca);
		let leaf2 = generate_localhost_cert(&ca);

		let cert_file = write_pem(&leaf1.cert.pem());
		let key_file = write_pem(&leaf1.signing_key.serialize_pem());

		let resolver = ReloadingCertResolver::new(cert_file.path(), key_file.path()).unwrap();

		std::fs::write(cert_file.path(), leaf2.cert.pem()).unwrap();
		std::fs::write(key_file.path(), leaf2.signing_key.serialize_pem()).unwrap();

		resolver.reload().unwrap();
		let key = resolver.current();
		assert!(!key.cert.is_empty());
	}

	#[test]
	#[cfg(feature = "proxy")]
	fn test_cert_watcher_new_succeeds() {
		let fixture = watcher_fixture();
		let watcher = CertWatcher::new(
			Arc::clone(&fixture.server_resolver),
			Arc::clone(&fixture.client_resolver),
		);
		assert!(watcher.is_ok());
	}

	#[test]
	#[cfg(feature = "proxy")]
	fn test_cert_watcher_hot_reloads_server_cert() {
		let fixture = watcher_fixture();
		let key_before = fixture.server_resolver.current();
		let _watcher = CertWatcher::new(
			Arc::clone(&fixture.server_resolver),
			Arc::clone(&fixture.client_resolver),
		)
		.unwrap();

		let new_cert_pem = generate_cert_pem_for_key(&fixture.ca, &fixture.server_key);
		let reloaded = write_until(&fixture.server_cert_path, &new_cert_pem, || {
			fixture.server_resolver.current().cert != key_before.cert
		});
		assert!(reloaded, "server resolver never picked up the new cert");
	}

	#[test]
	#[cfg(feature = "proxy")]
	fn test_cert_watcher_hot_reloads_client_cert() {
		let fixture = watcher_fixture();
		let key_before = fixture.client_resolver.current();
		let _watcher = CertWatcher::new(
			Arc::clone(&fixture.server_resolver),
			Arc::clone(&fixture.client_resolver),
		)
		.unwrap();

		let new_cert_pem = generate_cert_pem_for_key(&fixture.ca, &fixture.client_key);
		let reloaded = write_until(&fixture.client_cert_path, &new_cert_pem, || {
			fixture.client_resolver.current().cert != key_before.cert
		});
		assert!(reloaded, "client resolver never picked up the new cert");
	}

	#[test]
	#[cfg(feature = "proxy")]
	fn test_cert_watcher_invalid_cert_keeps_previous_then_recovers() {
		let fixture = watcher_fixture();
		let key_before = fixture.server_resolver.current();
		let _watcher = CertWatcher::new(
			Arc::clone(&fixture.server_resolver),
			Arc::clone(&fixture.client_resolver),
		)
		.unwrap();

		std::fs::write(&fixture.server_cert_path, "not a certificate").unwrap();
		thread::sleep(Duration::from_millis(FAILED_RELOAD_SETTLE_MS));
		assert_eq!(
			fixture.server_resolver.current().cert,
			key_before.cert,
			"invalid cert write must not replace the served key"
		);

		// The watcher must survive the failed reload and accept the next valid cert.
		let new_cert_pem = generate_cert_pem_for_key(&fixture.ca, &fixture.server_key);
		let reloaded = write_until(&fixture.server_cert_path, &new_cert_pem, || {
			fixture.server_resolver.current().cert != key_before.cert
		});
		assert!(reloaded, "watcher did not recover after a failed reload");
	}

	// A genuine two-file rotation — a brand-new key AND its matching cert, both files replaced — is
	// the case the other watcher tests avoid (generate_cert_pem_for_key reuses the existing key, so
	// only the cert file changes). The trailing-edge debounce re-reads both settled files, and
	// build_certified_key's from_der rejects any transient new-cert/old-key mismatch, so the resolver
	// only ever installs a self-consistent pair and converges on the new one.
	#[test]
	#[cfg(feature = "proxy")]
	fn test_cert_watcher_two_file_rotation_serves_matched_pair() {
		let fixture = watcher_fixture();
		let cert_before: Vec<CertificateDer<'static>> = fixture.server_resolver.current().cert.clone();
		let _watcher = CertWatcher::new(
			Arc::clone(&fixture.server_resolver),
			Arc::clone(&fixture.client_resolver),
		)
		.unwrap();

		let new_key: rcgen::KeyPair = rcgen::KeyPair::generate().unwrap();
		let new_cert_pem: String = generate_cert_pem_for_key(&fixture.ca, &new_key);
		let new_key_pem: String = new_key.serialize_pem();

		let mut rotated: bool = false;
		for _ in 0..RELOAD_MAX_ATTEMPTS {
			std::fs::write(&fixture.server_cert_path, &new_cert_pem).unwrap();
			std::fs::write(&fixture.server_key_path, &new_key_pem).unwrap();
			thread::sleep(Duration::from_millis(RELOAD_POLL_INTERVAL_MS));
			let served: Arc<CertifiedKey> = fixture.server_resolver.current();
			if served.cert != cert_before {
				// The resolver installs only pairs from_der accepted, so a served new cert already
				// implies a matching key; assert the invariant to make that guarantee explicit.
				assert!(served.keys_match().is_ok(), "rotated pair must be self-consistent");
				rotated = true;
				break;
			}
		}
		assert!(rotated, "server resolver never rotated to the new cert+key pair");
	}

	// ── CRL client verifier (handshake-level revocation) ──

	// A CA that may sign CRLs (CrlSign key usage) so rcgen's signed_by accepts it as the issuer.
	#[test]
	#[cfg(feature = "proxy")]
	fn test_trust_watcher_hot_reloads_crl() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let _ = crate::metrics::init_metrics(&crate::config::MetricsConfig { otlp_endpoint: None });
		let ca = crl_ca();
		let leaf = crl_leaf(&ca, "device-1", 1);

		let dir = tempfile::tempdir().unwrap();
		let ca_path = dir.path().join("ca.pem");
		let crl_path = dir.path().join("revoked.crl.pem");
		std::fs::write(&ca_path, ca.cert.pem()).unwrap();
		std::fs::write(&crl_path, make_crl_pem(&ca, &[])).unwrap(); // empty CRL initially

		let verifier = ReloadingClientVerifier::new(&ca_path, Some(&crl_path)).unwrap();
		assert!(verifier_accepts(&verifier, &leaf), "leaf accepted before revocation");

		let _watcher = TrustWatcher::new(
			Arc::clone(&verifier),
			&[ca_path, crl_path.clone()],
			TRUST_SIDE_SERVER,
			crate::metrics::ProxyMetrics::new(),
		)
		.unwrap();

		// Overwrite with a CRL revoking the leaf; the watcher must swap it in without a restart.
		let revoking = make_crl_pem(&ca, &[1]);
		let mut rejected = false;
		for _ in 0..RELOAD_MAX_ATTEMPTS {
			std::fs::write(&crl_path, &revoking).unwrap();
			thread::sleep(Duration::from_millis(RELOAD_POLL_INTERVAL_MS));
			if !verifier_accepts(&verifier, &leaf) {
				rejected = true;
				break;
			}
		}
		assert!(rejected, "trust watcher never applied the CRL revocation");
	}

	#[test]
	#[cfg(feature = "proxy")]
	fn test_trust_watcher_hot_reloads_ca_bundle() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let _ = crate::metrics::init_metrics(&crate::config::MetricsConfig { otlp_endpoint: None });
		let ca_old = crl_ca();
		let ca_new = crl_ca();
		let new_leaf = crl_leaf(&ca_new, "device-new", 1);

		let dir = tempfile::tempdir().unwrap();
		let ca_path = dir.path().join("ca.pem");
		std::fs::write(&ca_path, ca_old.cert.pem()).unwrap();

		let verifier = ReloadingClientVerifier::new(&ca_path, None).unwrap();
		assert!(
			!verifier_accepts(&verifier, &new_leaf),
			"new-CA leaf rejected before rotation"
		);

		let _watcher = TrustWatcher::new(
			Arc::clone(&verifier),
			std::slice::from_ref(&ca_path),
			TRUST_SIDE_SERVER,
			crate::metrics::ProxyMetrics::new(),
		)
		.unwrap();

		// Rotate the CA bundle on disk; the watcher must swap the trust anchors in with no restart.
		let mut accepted = false;
		for _ in 0..RELOAD_MAX_ATTEMPTS {
			std::fs::write(&ca_path, ca_new.cert.pem()).unwrap();
			thread::sleep(Duration::from_millis(RELOAD_POLL_INTERVAL_MS));
			if verifier_accepts(&verifier, &new_leaf) {
				accepted = true;
				break;
			}
		}
		assert!(accepted, "trust watcher never applied the CA rotation");
	}

	#[test]
	#[cfg(feature = "proxy")]
	fn test_trust_watcher_hot_reloads_server_ca_bundle() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let _ = crate::metrics::init_metrics(&crate::config::MetricsConfig { otlp_endpoint: None });
		let ca_old = generate_ca();
		let ca_new = generate_ca();
		let new_leaf = generate_localhost_cert(&ca_new);

		let dir = tempfile::tempdir().unwrap();
		let ca_path = dir.path().join("ca.pem");
		std::fs::write(&ca_path, ca_old.cert.pem()).unwrap();

		let verifier = ReloadingServerVerifier::new(&ca_path).unwrap();
		assert!(
			!server_verifier_accepts(&verifier, &new_leaf),
			"new-CA server leaf rejected before rotation"
		);

		// The generic watcher drives the server-cert verifier (client side) exactly as it does the
		// client-cert verifier (server side) — same file, no restart, TRUST_SIDE_CLIENT metric tag.
		let _watcher = TrustWatcher::new(
			Arc::clone(&verifier),
			std::slice::from_ref(&ca_path),
			TRUST_SIDE_CLIENT,
			crate::metrics::ProxyMetrics::new(),
		)
		.unwrap();

		let mut accepted = false;
		for _ in 0..RELOAD_MAX_ATTEMPTS {
			std::fs::write(&ca_path, ca_new.cert.pem()).unwrap();
			thread::sleep(Duration::from_millis(RELOAD_POLL_INTERVAL_MS));
			if server_verifier_accepts(&verifier, &new_leaf) {
				accepted = true;
				break;
			}
		}
		assert!(accepted, "trust watcher never applied the backend CA rotation");
	}
}
