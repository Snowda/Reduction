use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::watch;
use tracing::{error, info, warn};

use super::ReductionConfig;
use crate::error::Result;
use crate::fs_util::load_or_recover;

const CONFIG_RELOAD_DEBOUNCE_MS: u64 = 300;

pub struct ConfigWatcher {
    _watcher: RecommendedWatcher,
}

impl ConfigWatcher {
    pub fn new(
        config_path: &Path,
        config_tx: watch::Sender<ReductionConfig>,
    ) -> Result<Self> {
        let path_clone: PathBuf = config_path.to_path_buf();
        let debounce_duration: Duration = Duration::from_millis(CONFIG_RELOAD_DEBOUNCE_MS);
        let last_reload: Arc<RwLock<Instant>> =
            Arc::new(RwLock::new(Instant::now() - debounce_duration));

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

                        info!("config file changed, reloading");
                        match reload_config(&path_clone, &config_tx) {
                            Ok(()) => info!("config reloaded successfully"),
                            Err(e) => error!(error = %e, "failed to reload config"),
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "config watcher error");
                    }
                }
            },
        )
        .map_err(|e| crate::error::ReductionError::Config(format!("watcher init: {e}")))?;

        watcher
            .watch(config_path, RecursiveMode::NonRecursive)
            .map_err(|e| crate::error::ReductionError::Config(format!("watch: {e}")))?;

        info!(path = %config_path.display(), "watching config file for changes");

        return Ok(Self { _watcher: watcher });
    }
}

fn reload_config(
    path: &Path,
    config_tx: &watch::Sender<ReductionConfig>,
) -> Result<()> {
    let new_config: ReductionConfig = load_or_recover(path, |s| toml::from_str(s))?;

    let old_config: watch::Ref<'_, ReductionConfig> = config_tx.borrow();
    if old_config.listen.address != new_config.listen.address {
        warn!("listen address changed - requires restart to take effect");
    }
    if old_config.listen.transport != new_config.listen.transport {
        warn!("transport kind changed - requires restart to take effect");
    }
    if old_config.tls.server != new_config.tls.server {
        warn!("server TLS identity paths changed in config - certificate files are hot-reloaded via file watcher, but changing paths requires restart");
    }
    if old_config.tls.client != new_config.tls.client {
        warn!("client TLS identity paths changed in config - certificate files are hot-reloaded via file watcher, but changing paths requires restart");
    }
    drop(old_config);

    config_tx.send(new_config)
        .map_err(|_| crate::error::ReductionError::Config("all config receivers dropped".to_owned()))?;

    return Ok(());
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use arrayvec::ArrayString;

    use super::*;
    use crate::config::{
        AccessControlConfig, BackendConfig, BalancerConfig, CacheConfig, CircuitBreakerConfig,
        CompressionConfig, HealthConfig, ListenConfig, MetricsConfig, ProxyConfig,
        RateLimitConfig, RetryConfig, RouteConfig, ServerTlsConfig, TimeoutConfig,
        TlsConfig, TlsIdentity, TracingConfig, TransportKind, TunnelConfig,
    };

    fn test_config() -> ReductionConfig {
        return ReductionConfig {
            listen: ListenConfig {
                address: "127.0.0.1:8443".parse().unwrap(),
                transport: TransportKind::Tcp,
            },
            tls: TlsConfig {
                server: ServerTlsConfig::Manual(TlsIdentity {
                    cert_path: "certs/server.crt".into(),
                    key_path: "certs/server.key".into(),
                    ca_cert_path: "certs/ca.crt".into(),
                }),
                client: TlsIdentity {
                    cert_path: "certs/client.crt".into(),
                    key_path: "certs/client.key".into(),
                    ca_cert_path: "certs/ca.crt".into(),
                },
            },
            backends: vec![BackendConfig::new(
                "api",
                "10.0.0.1:8080".parse().unwrap(),
                1.0,
                TransportKind::Tcp,
            ).unwrap()],
            routes: vec![RouteConfig {
                path_prefix: ArrayString::from("/api").unwrap(),
                backend_id: ArrayString::from("api").unwrap(),
                timeout_secs: None,
            }],
            balancer: BalancerConfig::default(),
            proxy: ProxyConfig::default(),
            compression: CompressionConfig::default(),
            health: HealthConfig::default(),
            access: AccessControlConfig::default(),
            ratelimit: RateLimitConfig::default(),
            metrics: MetricsConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            timeouts: TimeoutConfig::default(),
            retry: RetryConfig::default(),
            tracing: TracingConfig::default(),
            tunnel: TunnelConfig::default(),
            cache: CacheConfig::default(),
        };
    }

    #[test]
    fn test_reload_config_updates_shared_state() {
        let dir: tempfile::TempDir = tempfile::tempdir().unwrap();
        let config_path: PathBuf = dir.path().join("config.toml");

        let config: ReductionConfig = test_config();
        let toml_str: String = toml::to_string(&config).unwrap();
        let mut file: std::fs::File = std::fs::File::create(&config_path).unwrap();
        file.write_all(toml_str.as_bytes()).unwrap();

        let (tx, rx): (watch::Sender<ReductionConfig>, watch::Receiver<ReductionConfig>) =
            watch::channel(config);

        let mut updated: ReductionConfig = test_config();
        updated.backends[0].weight = 5.0;
        let updated_toml: String = toml::to_string(&updated).unwrap();
        std::fs::write(&config_path, updated_toml).unwrap();

        reload_config(&config_path, &tx).unwrap();

        assert_eq!(rx.borrow().backends[0].weight, 5.0);
    }

    #[test]
    fn test_reload_config_quarantines_corrupt_file() {
        let dir: tempfile::TempDir = tempfile::tempdir().unwrap();
        let config_path: PathBuf = dir.path().join("config.toml");

        let config: ReductionConfig = test_config();
        let toml_str: String = toml::to_string(&config).unwrap();
        std::fs::write(&config_path, &toml_str).unwrap();

        let (tx, _rx): (watch::Sender<ReductionConfig>, watch::Receiver<ReductionConfig>) =
            watch::channel(config);

        std::fs::write(&config_path, "this is not valid toml {{{").unwrap();

        let result = reload_config(&config_path, &tx);
        assert!(result.is_err());

        assert!(!config_path.exists(), "corrupt file should be quarantined");

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 1);
        let name: String = entries[0].file_name().to_string_lossy().to_string();
        assert!(name.starts_with("config.toml.corrupt."), "got: {name}");
    }
}
