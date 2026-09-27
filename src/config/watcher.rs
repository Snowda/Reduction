use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::time::Duration;

use notify::{Event, RecommendedWatcher};
use tokio::sync::watch;
use tracing::{error, info, warn};

use super::ReductionConfig;
use crate::error::Result;
use crate::fs_util::load_or_recover;
use crate::fs_watch::{WatchSetupFailure, spawn_trailing_edge_watcher};

const CONFIG_RELOAD_DEBOUNCE_MS: u64 = 300;

pub struct ConfigWatcher {
	_watcher: RecommendedWatcher,
}

impl ConfigWatcher {
	pub fn new(config_path: &Path, config_tx: watch::Sender<ReductionConfig>) -> Result<Self> {
		let debounce: Duration = Duration::from_millis(CONFIG_RELOAD_DEBOUNCE_MS);
		let reload_path = config_path.to_path_buf();
		let watcher: RecommendedWatcher = spawn_trailing_edge_watcher(
			&[config_path.to_path_buf()],
			debounce,
			"config",
			WatchSetupFailure::Fatal,
			move |_event: &Event| {
				info!("config file changed, reloading");
				match reload_config(&reload_path, &config_tx) {
					Ok(()) => info!("config reloaded successfully"),
					Err(e) => error!(error = %e, "failed to reload config"),
				}
			},
		)?;

		info!(path = %config_path.display(), "watching config file for changes");

		return Ok(Self { _watcher: watcher });
	}
}

// Sections read exactly once at startup: a reload that changes one publishes cleanly but has no
// runtime effect until restart. Kept as a pure diff (returning the changed section names) so the
// reload contract is unit-testable, and so "config reloaded successfully" is never the whole story
// when part of the change was silently inert. What DOES hot-reload: routes, backends, access,
// balancer (except queue_depth), and the contents of the TLS/revocation files at their startup paths.
fn restart_required_sections(old: &ReductionConfig, new: &ReductionConfig) -> Vec<&'static str> {
	let mut changed: Vec<&'static str> = Vec::new();
	if old.listen.address != new.listen.address {
		changed.push("listen.address");
	}
	if old.listen.transport != new.listen.transport {
		changed.push("listen.transport");
	}
	// Identity/CA *paths* are startup-fixed; the files at those paths hot-reload via the watchers.
	if old.tls.server != new.tls.server {
		changed.push("tls.server (paths; file contents hot-reload)");
	}
	if old.tls.client != new.tls.client {
		changed.push("tls.client (paths; file contents hot-reload)");
	}
	if old.timeouts != new.timeouts {
		changed.push("timeouts");
	}
	if old.proxy != new.proxy {
		changed.push("proxy");
	}
	if old.compression != new.compression {
		changed.push("compression");
	}
	if old.health != new.health {
		changed.push("health");
	}
	if old.ratelimit != new.ratelimit {
		changed.push("ratelimit");
	}
	if old.metrics != new.metrics {
		changed.push("metrics");
	}
	if old.circuit_breaker != new.circuit_breaker {
		changed.push("circuit_breaker");
	}
	if old.retry != new.retry {
		changed.push("retry");
	}
	if old.tracing != new.tracing {
		changed.push("tracing");
	}
	if old.tunnel != new.tunnel {
		changed.push("tunnel (revocation file contents hot-reload)");
	}
	if old.cache != new.cache {
		changed.push("cache");
	}
	if old.balancer.queue_depth != new.balancer.queue_depth {
		changed.push("balancer.queue_depth");
	}
	if old.raw_relay_authz != new.raw_relay_authz {
		changed.push("raw_relay_authz");
	}
	return changed;
}

fn reload_config(path: &Path, config_tx: &watch::Sender<ReductionConfig>) -> Result<()> {
	let new_config: ReductionConfig = load_or_recover(path, |s| toml::from_str(s))?;
	// Semantic validation after the parse (so a cross-field violation rejects the reload and keeps
	// the previous config, without load_or_recover's quarantine treating the file as corrupt).
	new_config.validate()?;

	let old_config: watch::Ref<'_, ReductionConfig> = config_tx.borrow();
	let inert: Vec<&'static str> = restart_required_sections(&old_config, &new_config);
	drop(old_config);
	inert.iter().for_each(|section| {
		warn!(
			section,
			"config section changed on reload but is fixed at startup - restart required to take effect"
		);
	});

	config_tx
		.send(new_config)
		.map_err(|_| crate::error::ReductionError::Config("all config receivers dropped".to_owned()))?;

	return Ok(());
}

#[cfg(test)]
mod tests {
	use std::io::Write;
	use std::num::NonZeroU64;

	use arrayvec::ArrayString;

	use super::*;
	use crate::config::{
		AccessControlConfig, BackendConfig, BalancerConfig, CacheConfig, CircuitBreakerConfig, ClientAuthPolicy,
		CompressionConfig, HealthConfig, HealthEndpointConfig, HttpRedirectConfig, ListenConfig, MetricsConfig,
		ProxyConfig, RateLimitConfig, RawRelayAuthzEntry, RetryConfig, RouteConfig, ServerTlsConfig, TimeoutConfig,
		TlsConfig, TlsIdentity, TracingConfig, TransportKind, TunnelConfig,
	};

	fn test_config() -> ReductionConfig {
		return ReductionConfig {
			listen: ListenConfig {
				address: "127.0.0.1:8443".parse().unwrap(),
				transport: TransportKind::Tcp,
				client_auth: ClientAuthPolicy::Required,
			},
			tls: TlsConfig {
				server: ServerTlsConfig::Manual(TlsIdentity {
					cert_path: "certs/server.crt".into(),
					key_path: "certs/server.key".into(),
					ca_cert_path: "certs/ca.crt".into(),
					crl_path: None,
				}),
				client: Some(TlsIdentity {
					cert_path: "certs/client.crt".into(),
					key_path: "certs/client.key".into(),
					ca_cert_path: "certs/ca.crt".into(),
					crl_path: None,
				}),
			},
			backends: vec![
				BackendConfig::new("api", "10.0.0.1:8080".parse().unwrap(), 1.0, TransportKind::Tcp).unwrap(),
			],
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
			raw_relay_authz: Vec::new(),
			ingress: Vec::new(),
			http_redirect: HttpRedirectConfig::default(),
			health_endpoint: HealthEndpointConfig::default(),
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

		let (tx, rx): (watch::Sender<ReductionConfig>, watch::Receiver<ReductionConfig>) = watch::channel(config);

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

		let (tx, _rx): (watch::Sender<ReductionConfig>, watch::Receiver<ReductionConfig>) = watch::channel(config);

		std::fs::write(&config_path, "this is not valid toml {{{").unwrap();

		let result = reload_config(&config_path, &tx);
		assert!(result.is_err());

		assert!(!config_path.exists(), "corrupt file should be quarantined");

		let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().filter_map(|e| e.ok()).collect();
		assert_eq!(entries.len(), 1);
		let name: String = entries[0].file_name().to_string_lossy().to_string();
		assert!(name.starts_with("config.toml.corrupt."), "got: {name}");
	}

	// Every restart-required field differs between the old (in-channel) config and the new (on-disk)
	// one, exercising all four "changed - requires restart" warn branches in a single reload. The
	// reload still succeeds and publishes the new config; the warnings are advisory only.
	#[test]
	fn test_reload_config_warns_on_restart_required_field_changes() {
		let dir: tempfile::TempDir = tempfile::tempdir().unwrap();
		let config_path: PathBuf = dir.path().join("config.toml");

		let old: ReductionConfig = test_config();
		let (tx, rx): (watch::Sender<ReductionConfig>, watch::Receiver<ReductionConfig>) = watch::channel(old);

		let mut updated: ReductionConfig = test_config();
		updated.listen.address = "127.0.0.1:9999".parse().unwrap();
		updated.listen.transport = TransportKind::Quic;
		updated.tls.server = ServerTlsConfig::Manual(TlsIdentity {
			cert_path: "certs/new-server.crt".into(),
			key_path: "certs/new-server.key".into(),
			ca_cert_path: "certs/new-ca.crt".into(),
			crl_path: None,
		});
		updated.tls.client = Some(TlsIdentity {
			cert_path: "certs/new-client.crt".into(),
			key_path: "certs/new-client.key".into(),
			ca_cert_path: "certs/new-ca.crt".into(),
			crl_path: None,
		});
		std::fs::write(&config_path, toml::to_string(&updated).unwrap()).unwrap();

		reload_config(&config_path, &tx).unwrap();

		// The reload succeeds despite the warnings, and the new values are published.
		assert_eq!(rx.borrow().listen.transport, TransportKind::Quic);
		assert_eq!(rx.borrow().listen.address, "127.0.0.1:9999".parse().unwrap());
	}

	#[test]
	fn test_restart_required_sections_empty_when_unchanged() {
		let a: ReductionConfig = test_config();
		let b: ReductionConfig = test_config();
		assert!(restart_required_sections(&a, &b).is_empty());
	}

	// Every startup-frozen section must be flagged when it changes; a section missing from the diff
	// means an operator edit that "reloads successfully" while silently doing nothing.
	#[test]
	fn test_restart_required_sections_flags_every_frozen_section() {
		let old: ReductionConfig = test_config();
		let mut new: ReductionConfig = test_config();
		new.listen.address = "127.0.0.1:9999".parse().unwrap();
		new.listen.transport = TransportKind::Quic;
		new.tls.server = ServerTlsConfig::Manual(TlsIdentity {
			cert_path: "certs/other-server.crt".into(),
			key_path: "certs/other-server.key".into(),
			ca_cert_path: "certs/other-ca.crt".into(),
			crl_path: None,
		});
		new.tls.client = Some(TlsIdentity {
			cert_path: "certs/other-client.crt".into(),
			key_path: "certs/other-client.key".into(),
			ca_cert_path: "certs/other-ca.crt".into(),
			crl_path: None,
		});
		new.timeouts.request_secs = NonZeroU64::new(99).unwrap();
		new.proxy.max_idle_quic_per_host = 99;
		new.compression.level = 9;
		new.health.staleness_ttl_secs = 999;
		new.ratelimit.requests_per_second = 42;
		new.metrics.otlp_endpoint = Some("http://localhost:4318".to_owned());
		new.circuit_breaker.recovery_timeout_secs = 999;
		new.retry.max_retries = 9;
		new.tracing.sample_ratio = 0.5;
		new.tunnel.registration_timeout_secs = 99;
		new.cache.enabled = !new.cache.enabled;
		new.balancer.queue_depth = 42;
		new.raw_relay_authz = vec![RawRelayAuthzEntry {
			backend_id: ArrayString::from("api").unwrap(),
			allowed_cns: Vec::new(),
			allowed_spkis: Vec::new(),
		}];

		let sections: Vec<&'static str> = restart_required_sections(&old, &new);
		let expected: [&str; 14] = [
			"listen.address",
			"listen.transport",
			"timeouts",
			"proxy",
			"compression",
			"health",
			"ratelimit",
			"metrics",
			"circuit_breaker",
			"retry",
			"tracing",
			"cache",
			"balancer.queue_depth",
			"raw_relay_authz",
		];
		expected.iter().for_each(|name| {
			assert!(sections.contains(name), "frozen section not flagged: {name}");
		});
		assert!(
			sections.iter().any(|s| s.starts_with("tls.server")),
			"tls.server not flagged"
		);
		assert!(
			sections.iter().any(|s| s.starts_with("tls.client")),
			"tls.client not flagged"
		);
		assert!(sections.iter().any(|s| s.starts_with("tunnel")), "tunnel not flagged");
	}

	// Hot-reloadable parts (routes, backends, most of balancer) must NOT trip restart warnings.
	#[test]
	fn test_restart_required_sections_ignores_hot_reloadable_changes() {
		let old: ReductionConfig = test_config();
		let mut new: ReductionConfig = test_config();
		new.backends[0].weight = 9.0;
		new.routes[0].path_prefix = ArrayString::from("/v2").unwrap();
		new.balancer.drain_timeout_secs = 5;
		assert!(restart_required_sections(&old, &new).is_empty());
	}

	// A reload whose new config parses but violates a cross-field invariant must be rejected —
	// keeping the previous config in force — and must NOT quarantine the file (it isn't corrupt).
	#[test]
	fn test_reload_config_rejects_semantic_violation_and_keeps_previous() {
		let dir: tempfile::TempDir = tempfile::tempdir().unwrap();
		let config_path: PathBuf = dir.path().join("config.toml");

		let config: ReductionConfig = test_config();
		let (tx, rx): (watch::Sender<ReductionConfig>, watch::Receiver<ReductionConfig>) = watch::channel(config);

		let mut invalid: ReductionConfig = test_config();
		invalid.retry.base_delay_ms = 100;
		invalid.retry.max_delay_ms = 50;
		std::fs::write(&config_path, toml::to_string(&invalid).unwrap()).unwrap();

		let result = reload_config(&config_path, &tx);
		assert!(result.is_err(), "base_delay_ms > max_delay_ms must fail the reload");
		assert!(
			config_path.exists(),
			"a semantically invalid config must not be quarantined"
		);
		assert_eq!(
			rx.borrow().retry.base_delay_ms,
			test_config().retry.base_delay_ms,
			"the previous config must remain published",
		);
	}

	#[test]
	fn test_reload_config_errs_when_all_receivers_dropped() {
		let dir: tempfile::TempDir = tempfile::tempdir().unwrap();
		let config_path: PathBuf = dir.path().join("config.toml");

		let config: ReductionConfig = test_config();
		std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();

		let (tx, rx): (watch::Sender<ReductionConfig>, watch::Receiver<ReductionConfig>) = watch::channel(config);
		drop(rx); // no receivers left → send must fail

		let err = reload_config(&config_path, &tx).unwrap_err();
		assert!(format!("{err}").contains("all config receivers dropped"));
	}

	#[test]
	fn test_config_watcher_new_errors_on_unwatchable_path() {
		// A path under a non-existent directory cannot be watched; construction must surface the error
		// rather than silently no-op.
		let dir: tempfile::TempDir = tempfile::tempdir().unwrap();
		let bad_path: PathBuf = dir.path().join("no-such-dir").join("config.toml");
		let (tx, _rx) = watch::channel(test_config());
		let result = ConfigWatcher::new(&bad_path, tx);
		assert!(result.is_err(), "watching a path with no parent directory must fail");
	}

	// Poll a predicate until it holds or the attempt budget runs out. Retrying beats one write + one
	// long sleep: a single write can land inside the debounce window or be read mid-write.
	fn poll_until<F: FnMut() -> bool>(mut done: F) -> bool {
		for _ in 0..40 {
			if done() {
				return true;
			}
			std::thread::sleep(Duration::from_millis(100));
		}
		return false;
	}

	#[test]
	fn test_config_watcher_hot_reloads_on_file_change() {
		let dir: tempfile::TempDir = tempfile::tempdir().unwrap();
		let config_path: PathBuf = dir.path().join("config.toml");

		let config: ReductionConfig = test_config();
		std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();

		let (tx, rx): (watch::Sender<ReductionConfig>, watch::Receiver<ReductionConfig>) = watch::channel(config);
		let _watcher: ConfigWatcher = ConfigWatcher::new(&config_path, tx).unwrap();

		// One settled write: the trailing-edge watcher reloads once the debounce quiet period elapses,
		// so we poll the channel read-only rather than rewriting (repeated writes inside the debounce
		// window would keep superseding the pending reload). Exercises new() + the notify callback.
		let mut updated: ReductionConfig = test_config();
		updated.backends[0].weight = 7.0;
		std::fs::write(&config_path, toml::to_string(&updated).unwrap()).unwrap();

		let reloaded = poll_until(|| (rx.borrow().backends[0].weight - 7.0).abs() < f64::EPSILON);
		assert!(reloaded, "config watcher never applied the on-disk change");
	}
}
