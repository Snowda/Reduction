use std::path::PathBuf;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::watch;
use tracing::{error, info, warn};

use super::ReductionConfig;
use crate::error::{ReductionError, Result};

pub struct ConfigWatcher {
    _watcher: RecommendedWatcher,
}

impl ConfigWatcher {
    pub fn new(
        config_path: PathBuf,
        config_tx: watch::Sender<ReductionConfig>,
    ) -> Result<Self> {
        let path_clone: PathBuf = config_path.clone();

        let mut watcher: RecommendedWatcher = notify::recommended_watcher(
            move |result: std::result::Result<Event, notify::Error>| {
                match result {
                    Ok(event) => {
                        if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                            info!("config file changed, reloading");
                            match reload_config(&path_clone, &config_tx) {
                                Ok(()) => info!("config reloaded successfully"),
                                Err(e) => error!(error = %e, "failed to reload config"),
                            }
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "config watcher error");
                    }
                }
            },
        )
        .map_err(|e| ReductionError::Config(format!("watcher init: {e}")))?;

        watcher
            .watch(config_path.as_ref(), RecursiveMode::NonRecursive)
            .map_err(|e| ReductionError::Config(format!("watch: {e}")))?;

        info!(path = %config_path.display(), "watching config file for changes");

        return Ok(Self { _watcher: watcher });
    }
}

fn reload_config(
    path: &PathBuf,
    config_tx: &watch::Sender<ReductionConfig>,
) -> Result<()> {
    let contents: String = std::fs::read_to_string(path)
        .map_err(|e| ReductionError::Config(format!("read: {e}")))?;

    let new_config: ReductionConfig = toml::from_str(&contents)?;

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
        .map_err(|_| ReductionError::Config("all config receivers dropped".to_string()))?;

    return Ok(());
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::config::{
        AccessControlConfig, BackendConfig, BalancerConfig, CircuitBreakerConfig,
        CompressionConfig, HealthConfig, ListenConfig, MetricsConfig, ProxyConfig,
        RateLimitConfig, RetryConfig, RouteConfig, TimeoutConfig, TlsConfig, TlsIdentity, TracingConfig, TransportKind,
    };

    fn test_config() -> ReductionConfig {
        return ReductionConfig {
            listen: ListenConfig {
                address: "127.0.0.1:8443".parse().unwrap(),
                transport: TransportKind::Tcp,
            },
            tls: TlsConfig {
                server: TlsIdentity {
                    cert_path: "certs/server.crt".into(),
                    key_path: "certs/server.key".into(),
                    ca_cert_path: "certs/ca.crt".into(),
                },
                client: TlsIdentity {
                    cert_path: "certs/client.crt".into(),
                    key_path: "certs/client.key".into(),
                    ca_cert_path: "certs/ca.crt".into(),
                },
            },
            backends: vec![BackendConfig::new(
                "api".to_string(),
                "10.0.0.1:8080".parse().unwrap(),
                1.0,
                TransportKind::Tcp,
            )],
            routes: vec![RouteConfig {
                path_prefix: "/api".to_string(),
                backend_id: "api".to_string(),
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
}
