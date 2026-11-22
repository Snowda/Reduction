use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(feature = "proxy")]
use std::time::Duration;

#[cfg(feature = "proxy")]
use notify::{Event, RecommendedWatcher};
use rustls::SignatureScheme;
use rustls::client::ResolvesClientCert;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use solo::lease::{Lease, Leased};
// error! appears only in the proxy-gated fs-watcher reload closures below.
#[cfg(feature = "proxy")]
use tracing::error;
use tracing::info;

use crate::config::KeySource;
use crate::error::{ReductionError, Result};
#[cfg(feature = "proxy")]
use crate::fs_watch::{RELOAD_DEBOUNCE, WatchSetupFailure, spawn_trailing_edge_watcher};
use crate::lease::LEASES;
use crate::tls::load::{load_certs, load_key};

// The two hot-reloadable mTLS verifiers live in submodules. They are re-exported so `crate::tls::reload::X` stays stable.
mod client_verifier;
mod server_verifier;
mod stamp;
#[cfg(test)]
mod testutil;
#[cfg(feature = "proxy")]
mod trust_watcher;

pub use client_verifier::ReloadingClientVerifier;
pub use server_verifier::ReloadingServerVerifier;
pub use stamp::Stamp;
#[cfg(feature = "proxy")]
pub use trust_watcher::{TrustSide, TrustWatcher};

// A CertifiedKey that is hot-swappable in place. One type serves both rustls roles (it implements
// ResolvesServerCert and ResolvesClientCert), because the reload machinery is the same for each.
// Each instance watches one cert/key pair, and rustls gets it in exactly one role. A reload stores the
// key into a Leased. Live listeners and the connection pool then use a rotated cert on the next
// handshake, with no lock. The Arc that rustls holds stays the same object across reloads.
pub struct ReloadingCertResolver {
	inner: Leased<Arc<CertifiedKey>>,
	cert_path: PathBuf,
	key: KeySource,
}

impl ReloadingCertResolver {
	pub fn new(cert_path: &Path, key_path: &Path) -> Result<Self> {
		return Self::with_key(cert_path, KeySource::File(key_path.to_path_buf()));
	}

	pub fn with_key(cert_path: &Path, key: KeySource) -> Result<Self> {
		let certified_key: CertifiedKey = build_certified_key(cert_path, &key)?;
		return Ok(Self {
			inner: Leased::from_pointee(certified_key, LEASES),
			cert_path: cert_path.to_path_buf(),
			key,
		});
	}

	// The files whose change reloads this pair: the cert, and the key when it is a file.
	#[must_use]
	pub fn watched_paths(&self) -> Vec<PathBuf> {
		let mut paths: Vec<PathBuf> = vec![self.cert_path.clone()];
		paths.extend(self.key.path().map(Path::to_path_buf));
		return paths;
	}

	#[must_use]
	pub fn is_watching(&self, path: &Path) -> bool {
		return path == self.cert_path || self.key.path() == Some(path);
	}

	pub fn reload(&self) -> Result<()> {
		let new_key: CertifiedKey = build_certified_key(&self.cert_path, &self.key)?;
		self.inner.store(Arc::new(new_key));
		// The watcher logs the role (server/client). The path here identifies which cert.
		info!(cert = %self.cert_path.display(), "certificate reloaded");
		return Ok(());
	}

	pub fn current(&self) -> Arc<CertifiedKey> {
		return Lease::into_inner(self.inner.lease());
	}
}

impl fmt::Debug for ReloadingCertResolver {
	// An env key shows only the variable's name, never its value.
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let mut shown: fmt::DebugStruct<'_, '_> = f.debug_struct("ReloadingCertResolver");
		shown.field("cert_path", &self.cert_path);
		match &self.key {
			KeySource::File(path) => shown.field("key_path", path),
			KeySource::Env(var) => shown.field("key_env", var),
		};
		return shown.finish();
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

// Trust material that re-reads its file(s) and hot-swaps in place. Both verifier sides implement it, so
// one generic TrustWatcher drives either: server (inbound client-cert) and client (outbound server-cert).
pub trait Reloadable: Send + Sync {
	fn reload(&self) -> Result<()>;
}

fn build_certified_key(cert_path: &Path, key: &KeySource) -> Result<CertifiedKey> {
	let certs: Vec<CertificateDer<'static>> = load_certs(cert_path)?.into_vec();
	let key: PrivateKeyDer<'static> = load_key(key)?;

	let provider: &Arc<CryptoProvider> = rustls::crypto::CryptoProvider::get_default()
		.ok_or_else(|| ReductionError::Config("no default crypto provider installed".to_owned()))?;

	let certified_key: CertifiedKey = CertifiedKey::from_der(certs, key, provider)
		.map_err(|e| ReductionError::Config(format!("failed to build certified key: {e}")))?;

	return Ok(certified_key);
}

// The fs-watcher is proxy-side: it pulls in the notify dependency. Lean clients reload certs through
// their own renewal flow and do not watch files. The resolvers above stay core.
#[cfg(feature = "proxy")]
const SERVER_SIDE: &str = "server";
#[cfg(feature = "proxy")]
const CLIENT_SIDE: &str = "client";

#[cfg(feature = "proxy")]
pub struct CertWatcher {
	_watcher: RecommendedWatcher,
}

#[cfg(feature = "proxy")]
impl CertWatcher {
	pub fn new(
		server_resolver: Arc<ReloadingCertResolver>,
		client_resolver: Arc<ReloadingCertResolver>,
	) -> Result<Self> {
		return Self::watching(vec![(server_resolver, SERVER_SIDE), (client_resolver, CLIENT_SIDE)]);
	}

	// Server-cert-only watcher: there is no client identity toward the backends (public/plaintext-backend
	// deployment). The manual server path uses it when it runs without a [tls.client] identity.
	pub fn new_server_only(server_resolver: Arc<ReloadingCertResolver>) -> Result<Self> {
		return Self::watching(vec![(server_resolver, SERVER_SIDE)]);
	}

	// Client-cert-only watcher: an identity that this process presents and never serves, such as the egress uplink.
	pub fn new_client_only(client_resolver: Arc<ReloadingCertResolver>) -> Result<Self> {
		return Self::watching(vec![(client_resolver, CLIENT_SIDE)]);
	}

	// The last event of a debounce burst decides which side(s) to reload. A reload re-reads the settled
	// file and keeps the previous key on failure (last-known-good). The sides reload in the given order.
	fn watching(sides: Vec<(Arc<ReloadingCertResolver>, &'static str)>) -> Result<Self> {
		let debounce: Duration = RELOAD_DEBOUNCE;
		// An env-held key has no file, so only its cert is watched.
		let trigger_paths: Vec<PathBuf> =
			sides.iter().flat_map(|(resolver, _)| return resolver.watched_paths()).collect();

		let watcher: RecommendedWatcher = spawn_trailing_edge_watcher(
			&trigger_paths,
			debounce,
			"cert",
			WatchSetupFailure::Warn,
			move |event: &Event| {
				sides
					.iter()
					.filter(|(resolver, _)| return event.paths.iter().any(|p| return resolver.is_watching(p)))
					.for_each(|(resolver, side)| reload_and_log(resolver, side));
			},
		)?;

		info!("watching certificate files for hot-reload");

		return Ok(Self { _watcher: watcher });
	}
}

// Reload one side's settled cert/key. On failure, the previous key stays in service (last-known-good).
#[cfg(feature = "proxy")]
fn reload_and_log(resolver: &ReloadingCertResolver, side: &str) {
	match resolver.reload() {
		Ok(()) => info!("{side} certificate hot-reloaded"),
		Err(e) => error!(error = %e, "failed to reload {side} certificate, keeping previous"),
	}
}

#[cfg(test)]
mod tests {
	use std::result::Result;
	#[cfg(feature = "proxy")]
	use std::thread;

	#[cfg(feature = "proxy")]
	use rcgen::{CertificateParams, Issuer, KeyPair};
	use rustls::{ClientConfig, ServerConfig};
	#[cfg(feature = "proxy")]
	use tempfile::TempDir;

	#[cfg(feature = "proxy")]
	use super::testutil::write_until;
	use super::testutil::{Ca, ca_and_leaves, write_file};
	use super::*;
	#[cfg(feature = "proxy")]
	use crate::test_support::generate_ca;
	use crate::test_support::handshake::{Observed, handshake, served_epoch, trusting};
	use crate::test_support::{LeafFiles, leaf_files};

	#[cfg(feature = "proxy")]
	const FAILED_RELOAD_SETTLE_MS: u64 = 1000;

	// A fresh cert for a key that is already on disk. A test can then swap the cert file and leave the
	// key file as it is. That gives one fs event, and the on-disk pair never has a mismatched state.
	#[cfg(feature = "proxy")]
	fn generate_cert_pem_for_key(ca: &Ca, key: &rcgen::KeyPair) -> Result<String, String> {
		let mut params: CertificateParams = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
			.map_err(|err| format!("rcgen::CertificateParams::new: {err:?}"))?;
		params.distinguished_name.push(
			rcgen::DnType::CommonName,
			rcgen::DnValue::Utf8String("localhost".to_owned()),
		);
		let issuer: Issuer<'_, &KeyPair> = rcgen::Issuer::from_ca_cert_der(ca.cert.der(), &ca.signing_key)
			.map_err(|err| format!("rcgen::Issuer::from_ca_cert_der: {err:?}"))?;
		return match params.signed_by(key, &issuer) {
			Ok(cert) => Ok(cert.pem()),
			Err(err) => Err(format!("params.signed_by: {err:?}")),
		};
	}

	// `leaf` written to PEM files, and a resolver loaded from them. Later rewrites use the same files.
	fn leaf_resolver(leaf: Ca) -> Result<(ReloadingCertResolver, LeafFiles), String> {
		let files: LeafFiles = leaf_files(leaf)?;
		return match ReloadingCertResolver::new(files.cert.path(), files.key.path()) {
			Ok(resolver) => Ok((resolver, files)),
			Err(err) => Err(format!("ReloadingCertResolver::new: {err:?}")),
		};
	}

	// Overwrite the cert and key files with `leaf`'s pair.
	fn rewrite_pair(files: &LeafFiles, leaf: &Ca) -> Result<(), String> {
		return write_file(files.cert.path(), &leaf.cert.pem())
			.and_then(|()| write_file(files.key.path(), &leaf.signing_key.serialize_pem()));
	}

	#[cfg(feature = "proxy")]
	struct WatcherFixture {
		_dir: TempDir,
		server_cert_path: PathBuf,
		server_key_path: PathBuf,
		client_cert_path: PathBuf,
		server_resolver: Arc<ReloadingCertResolver>,
		client_resolver: Arc<ReloadingCertResolver>,
		ca: Ca,
		server_key: rcgen::KeyPair,
		client_key: rcgen::KeyPair,
	}

	// Write a cert for `key` (signed by `ca`) and the key itself into `dir`.
	// The names are `<name>-cert.pem` and `<name>-key.pem`. Then load a resolver from them.
	#[cfg(feature = "proxy")]
	fn watched_pair(
		dir: &Path,
		name: &str,
		ca: &Ca,
		key: &rcgen::KeyPair,
	) -> Result<(PathBuf, PathBuf, Arc<ReloadingCertResolver>), String> {
		let cert_path: PathBuf = dir.join(format!("{name}-cert.pem"));
		let key_path: PathBuf = dir.join(format!("{name}-key.pem"));
		let written: Result<(), String> = generate_cert_pem_for_key(ca, key)
			.and_then(|cert_pem| write_file(&cert_path, &cert_pem))
			.and_then(|()| write_file(&key_path, &key.serialize_pem()));
		written?;
		return match ReloadingCertResolver::new(&cert_path, &key_path) {
			Ok(resolver) => Ok((cert_path, key_path, Arc::new(resolver))),
			Err(err) => Err(format!("{name} resolver: {err:?}")),
		};
	}

	// Dedicated TempDir per test. If the watcher watched the shared OS temp dir, unrelated fs events
	// can use up its debounce window.
	#[cfg(feature = "proxy")]
	fn watcher_fixture() -> Result<WatcherFixture, String> {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		let (ca, server_key, client_key) = match (generate_ca(), rcgen::KeyPair::generate(), rcgen::KeyPair::generate())
		{
			(Ok(ca), Ok(server_key), Ok(client_key)) => (ca, server_key, client_key),
			(ca, server_key, client_key) => {
				return Err(format!(
					"CA/keys: {:?} {:?} {:?}",
					ca.err(),
					server_key.err(),
					client_key.err()
				));
			}
		};
		let dir: TempDir = tempfile::tempdir().map_err(|err| format!("tempfile::tempdir(): {err:?}"))?;
		let (server_cert_path, server_key_path, server_resolver) =
			watched_pair(dir.path(), "server", &ca, &server_key)?;
		let (client_cert_path, _client_key_path, client_resolver) =
			watched_pair(dir.path(), "client", &ca, &client_key)?;
		return Ok(WatcherFixture {
			_dir: dir,
			server_cert_path,
			server_key_path,
			client_cert_path,
			server_resolver,
			client_resolver,
			ca,
			server_key,
			client_key,
		});
	}

	#[cfg(feature = "proxy")]
	fn start_cert_watcher(fixture: &WatcherFixture) -> Result<CertWatcher, String> {
		return match CertWatcher::new(
			Arc::clone(&fixture.server_resolver),
			Arc::clone(&fixture.client_resolver),
		) {
			Ok(watcher) => Ok(watcher),
			Err(err) => Err(format!("CertWatcher::new: {err:?}")),
		};
	}

	// A new cert for `key` written to `cert_path` until `resolver` serves something other than `before`.
	#[cfg(feature = "proxy")]
	fn rotate_cert_until_served(
		fixture: &WatcherFixture,
		cert_path: &Path,
		key: &rcgen::KeyPair,
		resolver: &ReloadingCertResolver,
	) -> Result<bool, String> {
		let before: Arc<CertifiedKey> = resolver.current();
		let new_cert_pem: String = generate_cert_pem_for_key(&fixture.ca, key)?;
		return write_until(&[(cert_path, &new_cert_pem)], || resolver.current().cert != before.cert);
	}

	#[test]
	fn test_server_resolver_new_and_resolve() -> Result<(), String> {
		let (_ca, [leaf]) = ca_and_leaves::<1>()?;
		let (resolver, _files) = leaf_resolver(leaf)?;
		let key: Arc<CertifiedKey> = resolver.current();
		assert!(!key.cert.is_empty());
		return Ok(());
	}

	#[test]
	fn test_server_resolver_reload_with_new_cert() -> Result<(), String> {
		let (_ca, [leaf1, leaf2]) = ca_and_leaves::<2>()?;
		let (resolver, files) = leaf_resolver(leaf1)?;
		let key_before: Arc<CertifiedKey> = resolver.current();
		rewrite_pair(&files, &leaf2)?;
		resolver.reload().map_err(|err| format!("resolver.reload(): {err:?}"))?;
		let key_after: Arc<CertifiedKey> = resolver.current();
		assert_ne!(key_before.cert, key_after.cert);
		return Ok(());
	}

	// The live server of served_after_rotation, built once over a ReloadingCertResolver of `old_leaf`.
	fn live_server(old_leaf: Ca) -> Result<(Arc<ServerConfig>, Arc<ReloadingCertResolver>, LeafFiles), String> {
		let (resolver, files) = leaf_resolver(old_leaf)?;
		let resolver: Arc<ReloadingCertResolver> = Arc::new(resolver);
		let live_resolver: Arc<ReloadingCertResolver> = Arc::clone(&resolver);
		let server: Arc<ServerConfig> = Arc::new(
			ServerConfig::builder()
				.with_no_client_auth()
				.with_cert_resolver(live_resolver),
		);
		return Ok((server, resolver, files));
	}

	// The certificate the server presents in one full handshake.
	fn served(
		server: &Arc<ServerConfig>,
		client: &Arc<rustls::ClientConfig>,
	) -> Result<CertificateDer<'static>, String> {
		return match handshake(Arc::clone(server), Arc::clone(client)) {
			Ok(Ok(value)) => Ok(value),
			Ok(Err(err)) => Err(format!("handshake: {err:?}")),
			Err(err) => Err(format!("handshake harness: {err}")),
		};
	}

	// Rotates the cert pair on disk under a ServerConfig built once, then handshakes again. `apply_reload` is
	// the swap switch: off leaves the Leased untouched, on stores the freshly loaded key.
	fn served_after_rotation(apply_reload: bool) -> Result<Observed, String> {
		let (ca, [old_leaf, new_leaf]) = ca_and_leaves::<2>()?;
		let (server, resolver, files) = live_server(old_leaf)?;
		let client: Arc<ClientConfig> = trusting(&ca)?;
		let old_files: &LeafFiles = &files;
		let before: CertificateDer<'static> = served(&server, &client)?;
		assert_eq!(
			served_epoch(&before, &old_files.leaf, &new_leaf),
			Observed::Old,
			"the original cert is served before rotation"
		);

		rewrite_pair(old_files, &new_leaf)?;
		if apply_reload && let Err(err) = resolver.reload() {
			return Err(format!("resolver.reload(): {err:?}"));
		}
		return match served(&server, &client) {
			Ok(after) => Ok(served_epoch(&after, &old_files.leaf, &new_leaf)),
			Err(err) => Err(format!("after rotation: {err}")),
		};
	}

	#[test]
	fn test_handshake_serves_rotated_cert_only_after_reload() -> Result<(), String> {
		let without_swap: Observed = served_after_rotation(false)?;
		let with_swap: Observed = served_after_rotation(true)?;
		assert_eq!(
			without_swap,
			Observed::Old,
			"no store: the live config keeps serving the old cert"
		);
		assert_eq!(
			with_swap,
			Observed::New,
			"after store: the same live config serves the new cert"
		);
		assert_ne!(
			without_swap, with_swap,
			"the swap is the only difference between the two runs"
		);
		return Ok(());
	}

	#[test]
	fn test_server_resolver_reload_invalid_keeps_old() -> Result<(), String> {
		let (_ca, [leaf]) = ca_and_leaves::<1>()?;
		let (resolver, files) = leaf_resolver(leaf)?;
		let key_before: Arc<CertifiedKey> = resolver.current();
		write_file(files.cert.path(), "garbage")?;
		let result: Result<(), ReductionError> = resolver.reload();
		assert!(result.is_err());
		let key_after: Arc<CertifiedKey> = resolver.current();
		assert_eq!(key_before.cert, key_after.cert);
		return Ok(());
	}

	#[test]
	fn test_client_resolver_new_and_resolve() -> Result<(), String> {
		let (_ca, [leaf]) = ca_and_leaves::<1>()?;
		let (resolver, _files) = leaf_resolver(leaf)?;
		assert!(resolver.has_certs());
		// The type implements both resolver traits, so name the client-cert one explicitly.
		let key: Option<Arc<CertifiedKey>> = ResolvesClientCert::resolve(&resolver, &[], &[]);
		assert!(key.is_some());
		return Ok(());
	}

	#[test]
	fn test_client_resolver_reload() -> Result<(), String> {
		let (_ca, [leaf1, leaf2]) = ca_and_leaves::<2>()?;
		let (resolver, files) = leaf_resolver(leaf1)?;
		rewrite_pair(&files, &leaf2)?;
		resolver.reload().map_err(|err| format!("resolver.reload(): {err:?}"))?;
		let key: Arc<CertifiedKey> = resolver.current();
		assert!(!key.cert.is_empty());
		return Ok(());
	}

	#[test]
	fn test_resolver_debug_names_the_paths_and_never_the_key() -> Result<(), String> {
		let (_ca, [leaf]) = ca_and_leaves::<1>()?;
		let key_pem: String = leaf.signing_key.serialize_pem();
		let (resolver, files) = leaf_resolver(leaf)?;
		let shown: String = format!("{resolver:?}");
		assert_eq!(
			shown,
			format!(
				"ReloadingCertResolver {{ cert_path: {:?}, key_path: {:?} }}",
				files.cert.path(),
				files.key.path()
			)
		);
		assert!(!shown.contains(key_pem.trim()), "the private key never reaches Debug output");
		return Ok(());
	}

	#[test]
	#[cfg(feature = "proxy")]
	fn test_server_only_cert_watcher_hot_reloads_the_server_cert() -> Result<(), String> {
		let fixture: WatcherFixture = watcher_fixture()?;
		let _watcher: CertWatcher = CertWatcher::new_server_only(Arc::clone(&fixture.server_resolver))
			.map_err(|err| format!("CertWatcher::new_server_only: {err:?}"))?;
		let reloaded: bool = rotate_cert_until_served(
			&fixture,
			&fixture.server_cert_path,
			&fixture.server_key,
			&fixture.server_resolver,
		)?;
		assert!(reloaded, "a server-only watcher still reloads the server cert");
		return Ok(());
	}

	#[test]
	#[cfg(feature = "proxy")]
	fn test_a_resolver_watches_its_own_cert_and_key_only() -> Result<(), String> {
		let fixture: WatcherFixture = watcher_fixture()?;
		let server: &ReloadingCertResolver = &fixture.server_resolver;
		assert!(server.is_watching(&fixture.server_cert_path));
		assert!(server.is_watching(&fixture.server_key_path));
		assert!(!server.is_watching(&fixture.client_cert_path), "the client's cert must not reload the server side");
		assert!(
			server.watched_paths().iter().all(|path: &PathBuf| server.is_watching(path)),
			"every trigger file the watcher registers maps back to this resolver"
		);
		return Ok(());
	}

	#[test]
	#[cfg(feature = "proxy")]
	fn test_cert_watcher_new_succeeds() -> Result<(), String> {
		let fixture: WatcherFixture = watcher_fixture()?;
		assert!(start_cert_watcher(&fixture).is_ok());
		return Ok(());
	}

	#[test]
	#[cfg(feature = "proxy")]
	fn test_cert_watcher_hot_reloads_server_cert() -> Result<(), String> {
		let fixture: WatcherFixture = watcher_fixture()?;
		let _watcher: CertWatcher = start_cert_watcher(&fixture)?;
		let reloaded: bool = rotate_cert_until_served(
			&fixture,
			&fixture.server_cert_path,
			&fixture.server_key,
			&fixture.server_resolver,
		)?;
		assert!(reloaded, "server resolver never picked up the new cert");
		return Ok(());
	}

	#[test]
	#[cfg(feature = "proxy")]
	fn test_cert_watcher_hot_reloads_client_cert() -> Result<(), String> {
		let fixture: WatcherFixture = watcher_fixture()?;
		let _watcher: CertWatcher = start_cert_watcher(&fixture)?;
		let reloaded: bool = rotate_cert_until_served(
			&fixture,
			&fixture.client_cert_path,
			&fixture.client_key,
			&fixture.client_resolver,
		)?;
		assert!(reloaded, "client resolver never picked up the new cert");
		return Ok(());
	}

	#[test]
	#[cfg(feature = "proxy")]
	fn test_cert_watcher_invalid_cert_keeps_previous_then_recovers() -> Result<(), String> {
		let fixture: WatcherFixture = watcher_fixture()?;
		let key_before: Arc<CertifiedKey> = fixture.server_resolver.current();
		let _watcher: CertWatcher = start_cert_watcher(&fixture)?;
		write_file(&fixture.server_cert_path, "not a certificate")?;
		thread::sleep(Duration::from_millis(FAILED_RELOAD_SETTLE_MS));
		assert_eq!(
			fixture.server_resolver.current().cert,
			key_before.cert,
			"invalid cert write must not replace the served key"
		);

		// The watcher must survive the failed reload and accept the next valid cert.
		let reloaded: bool = rotate_cert_until_served(
			&fixture,
			&fixture.server_cert_path,
			&fixture.server_key,
			&fixture.server_resolver,
		)?;
		assert!(reloaded, "watcher did not recover after a failed reload");
		return Ok(());
	}

	// A true two-file rotation: a brand-new key AND its cert, both files replaced. The other watcher
	// tests avoid this case, because generate_cert_pem_for_key reuses the current key and only the cert
	// file changes. The debounce re-reads both settled files at the end of the burst. The from_der in
	// build_certified_key rejects a transient new-cert/old-key mismatch. Thus the resolver installs
	// only a self-consistent pair, and it ends on the new one.
	#[test]
	#[cfg(feature = "proxy")]
	fn test_cert_watcher_two_file_rotation_serves_matched_pair() -> Result<(), String> {
		let fixture: WatcherFixture = watcher_fixture()?;
		let cert_before: Arc<CertifiedKey> = fixture.server_resolver.current();
		let _watcher: CertWatcher = start_cert_watcher(&fixture)?;
		let (new_cert_pem, new_key_pem) = match rcgen::KeyPair::generate() {
			Ok(new_key) => match generate_cert_pem_for_key(&fixture.ca, &new_key) {
				Ok(cert_pem) => (cert_pem, new_key.serialize_pem()),
				Err(err) => return Err(format!("generate_cert_pem_for_key: {err}")),
			},
			Err(err) => return Err(format!("rcgen::KeyPair::generate(): {err:?}")),
		};
		let writes: [(&Path, &str); 2] = [
			(&fixture.server_cert_path, &new_cert_pem),
			(&fixture.server_key_path, &new_key_pem),
		];
		let rotated: bool = write_until(&writes, || fixture.server_resolver.current().cert != cert_before.cert)?;
		assert!(rotated, "server resolver never rotated to the new cert+key pair");
		// The resolver installs only pairs that from_der accepted. Thus a served new cert implies a key
		// that agrees with it. The assert makes that guarantee explicit.
		let served: Arc<CertifiedKey> = fixture.server_resolver.current();
		assert!(served.keys_match().is_ok(), "rotated pair must be self-consistent");
		return Ok(());
	}
}
