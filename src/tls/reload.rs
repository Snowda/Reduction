use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rustls::client::ResolvesClientCert;
use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::SignatureScheme;
use tracing::{error, info, warn};

use crate::error::{ReductionError, Result};
use crate::tls::certs::{load_certs, load_private_key};

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
        info!(cert = %self.cert_path.display(), "server certificate reloaded");
        return Ok(());
    }

    pub fn current(&self) -> Arc<CertifiedKey> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        return Arc::clone(&guard);
    }
}

impl fmt::Debug for ReloadingCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReloadingCertResolver")
            .field("cert_path", &self.cert_path)
            .field("key_path", &self.key_path)
            .finish()
    }
}

impl ResolvesServerCert for ReloadingCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        return Some(self.current());
    }
}

pub struct ReloadingClientCertResolver {
    inner: RwLock<Arc<CertifiedKey>>,
    cert_path: PathBuf,
    key_path: PathBuf,
}

impl ReloadingClientCertResolver {
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
        info!(cert = %self.cert_path.display(), "client certificate reloaded");
        return Ok(());
    }

    pub fn current(&self) -> Arc<CertifiedKey> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        return Arc::clone(&guard);
    }
}

impl fmt::Debug for ReloadingClientCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReloadingClientCertResolver")
            .field("cert_path", &self.cert_path)
            .field("key_path", &self.key_path)
            .finish()
    }
}

impl ResolvesClientCert for ReloadingClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        return Some(self.current());
    }

    fn has_certs(&self) -> bool {
        return true;
    }
}

fn build_certified_key(cert_path: &Path, key_path: &Path) -> Result<CertifiedKey> {
    let certs: Vec<CertificateDer<'static>> = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let provider = rustls::crypto::CryptoProvider::get_default()
        .ok_or_else(|| ReductionError::Config("no default crypto provider installed".to_string()))?;

    let certified_key = CertifiedKey::from_der(certs, key, provider)
        .map_err(|e| ReductionError::Config(format!("failed to build certified key: {e}")))?;

    return Ok(certified_key);
}

pub struct CertWatcher {
    _watcher: RecommendedWatcher,
}

impl CertWatcher {
    pub fn new(
        server_resolver: Arc<ReloadingCertResolver>,
        client_resolver: Arc<ReloadingClientCertResolver>,
    ) -> Result<Self> {
        let debounce_duration: Duration = Duration::from_millis(300);
        let last_reload: Arc<RwLock<Instant>> =
            Arc::new(RwLock::new(Instant::now() - debounce_duration));

        let server_cert_path: PathBuf = server_resolver.cert_path.clone();
        let server_key_path: PathBuf = server_resolver.key_path.clone();
        let client_cert_path: PathBuf = client_resolver.cert_path.clone();
        let client_key_path: PathBuf = client_resolver.key_path.clone();

        let paths_to_watch: Vec<PathBuf> = vec![
            server_cert_path.clone(),
            server_key_path.clone(),
            client_cert_path.clone(),
            client_key_path.clone(),
        ];

        let mut watcher: RecommendedWatcher = notify::recommended_watcher(
            move |result: std::result::Result<Event, notify::Error>| {
                match result {
                    Ok(event) => {
                        if !matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                            return;
                        }

                        let mut last = last_reload.write().unwrap_or_else(|e| e.into_inner());
                        if last.elapsed() < debounce_duration {
                            return;
                        }
                        *last = Instant::now();
                        drop(last);

                        let affected_server: bool = event.paths.iter().any(|p| {
                            p == &server_cert_path || p == &server_key_path
                        });
                        let affected_client: bool = event.paths.iter().any(|p| {
                            p == &client_cert_path || p == &client_key_path
                        });

                        if affected_server {
                            match server_resolver.reload() {
                                Ok(()) => info!("server certificate hot-reloaded"),
                                Err(e) => error!(error = %e, "failed to reload server certificate, keeping previous"),
                            }
                        }

                        if affected_client {
                            match client_resolver.reload() {
                                Ok(()) => info!("client certificate hot-reloaded"),
                                Err(e) => error!(error = %e, "failed to reload client certificate, keeping previous"),
                            }
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "cert watcher error");
                    }
                }
            },
        )
        .map_err(|e| ReductionError::Config(format!("cert watcher init: {e}")))?;

        for path in &paths_to_watch {
            if let Some(parent) = path.parent() {
                if let Err(e) = watcher.watch(parent, RecursiveMode::NonRecursive) {
                    warn!(path = %parent.display(), error = %e, "failed to watch cert directory, will retry on next event");
                }
            } else {
                warn!(path = %path.display(), "cannot watch cert file without parent directory");
            }
        }

        info!("watching certificate files for hot-reload");

        return Ok(Self { _watcher: watcher });
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use tempfile::NamedTempFile;

    fn generate_ca() -> rcgen::CertifiedKey {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String("Test CA".to_string()),
        );
        let cert = params.self_signed(&key).unwrap();
        return rcgen::CertifiedKey { cert, key_pair: key };
    }

    fn generate_signed_cert(ca: &rcgen::CertifiedKey) -> rcgen::CertifiedKey {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String("localhost".to_string()),
        );
        let cert = params.signed_by(&key, &ca.cert, &ca.key_pair).unwrap();
        return rcgen::CertifiedKey { cert, key_pair: key };
    }

    fn write_pem(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        return f;
    }

    #[test]
    fn test_server_resolver_new_and_resolve() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = generate_ca();
        let leaf = generate_signed_cert(&ca);

        let cert_file = write_pem(&leaf.cert.pem());
        let key_file = write_pem(&leaf.key_pair.serialize_pem());

        let resolver = ReloadingCertResolver::new(cert_file.path(), key_file.path()).unwrap();
        let key = resolver.current();
        assert!(!key.cert.is_empty());
    }

    #[test]
    fn test_server_resolver_reload_with_new_cert() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = generate_ca();
        let leaf1 = generate_signed_cert(&ca);
        let leaf2 = generate_signed_cert(&ca);

        let cert_file = write_pem(&leaf1.cert.pem());
        let key_file = write_pem(&leaf1.key_pair.serialize_pem());

        let resolver = ReloadingCertResolver::new(cert_file.path(), key_file.path()).unwrap();
        let key_before = resolver.current();

        std::fs::write(cert_file.path(), leaf2.cert.pem()).unwrap();
        std::fs::write(key_file.path(), leaf2.key_pair.serialize_pem()).unwrap();

        resolver.reload().unwrap();
        let key_after = resolver.current();

        assert_ne!(key_before.cert, key_after.cert);
    }

    #[test]
    fn test_server_resolver_reload_invalid_keeps_old() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = generate_ca();
        let leaf = generate_signed_cert(&ca);

        let cert_file = write_pem(&leaf.cert.pem());
        let key_file = write_pem(&leaf.key_pair.serialize_pem());

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
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = generate_ca();
        let leaf = generate_signed_cert(&ca);

        let cert_file = write_pem(&leaf.cert.pem());
        let key_file = write_pem(&leaf.key_pair.serialize_pem());

        let resolver = ReloadingClientCertResolver::new(cert_file.path(), key_file.path()).unwrap();
        assert!(resolver.has_certs());

        let key = resolver.resolve(&[], &[]);
        assert!(key.is_some());
    }

    #[test]
    fn test_client_resolver_reload() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = generate_ca();
        let leaf1 = generate_signed_cert(&ca);
        let leaf2 = generate_signed_cert(&ca);

        let cert_file = write_pem(&leaf1.cert.pem());
        let key_file = write_pem(&leaf1.key_pair.serialize_pem());

        let resolver = ReloadingClientCertResolver::new(cert_file.path(), key_file.path()).unwrap();

        std::fs::write(cert_file.path(), leaf2.cert.pem()).unwrap();
        std::fs::write(key_file.path(), leaf2.key_pair.serialize_pem()).unwrap();

        resolver.reload().unwrap();
        let key = resolver.current();
        assert!(!key.cert.is_empty());
    }
}
