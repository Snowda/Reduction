use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arrayvec::ArrayString;
use reduction::acl::AccessControl;
use reduction::balancer::BackendPool;
use reduction::config::{self, ReductionConfig};
use reduction::error::Result;
use reduction::proxy::{ProxyState, ReloadableState, Router};
use reduction::tunnel::revocation::RevocationSet;
use reduction::tunnel::revocation_reload;
use tokio::sync::watch;
use tokio::time::sleep;
use tracing::{error, info};

pub fn build_backend_pools(config: &ReductionConfig) -> Result<HashMap<ArrayString<256>, BackendPool>> {
	let mut pools: HashMap<ArrayString<256>, BackendPool> = HashMap::new();

	for route in &config.routes {
		if pools.contains_key(&route.backend_id) {
			continue;
		}

		let backends: Vec<config::BackendConfig> = config
			.backends
			.iter()
			.filter(|b| b.pool.as_str() == route.backend_id.as_str())
			.cloned()
			.collect();

		if !backends.is_empty() {
			let pool: BackendPool = BackendPool::with_max(backends, config.balancer.max_backends)?;
			pools.insert(route.backend_id, pool);
		}
	}

	return Ok(pools);
}

pub fn spawn_config_reload_task(
	mut config_rx: watch::Receiver<ReductionConfig>,
	reloadable_tx: watch::Sender<ReloadableState>,
	revocation_tx: watch::Sender<RevocationSet>,
	proxy_state: Arc<ProxyState>,
	// The revocation path fixed at startup (what RevocationWatcher watches); the re-read below pins to it too,
	// since honoring a reloaded path while the watcher stayed on the old one would split enforcement. Path changes need a restart.
	startup_revocation_path: Option<PathBuf>,
) {
	tokio::spawn(async move {
		// Baseline of the routing-relevant config, refreshed after each applied reload that changes it.
		// Lets the response-cache flush fire only on a real route/backend edit.
		let mut prev_routes: Vec<config::RouteConfig> = config_rx.borrow().routes.clone();
		let mut prev_backends: Vec<config::BackendConfig> = config_rx.borrow().backends.clone();
		while config_rx.changed().await.is_ok() {
			let config: ReductionConfig = config_rx.borrow_and_update().clone();
			let flow: ControlFlow<()> = apply_config_reload(
				config,
				&reloadable_tx,
				&revocation_tx,
				&proxy_state,
				&startup_revocation_path,
				&mut prev_routes,
				&mut prev_backends,
			)
			.await;
			if flow.is_break() {
				return;
			}
		}
	});
}

// Apply one config reload: re-read the revocation file, rebuild backend pools + ACL + router, publish the new
// reloadable state, flush the cache on a routing change, and drain removed backends. Break stops the reload task
// (all receivers dropped); Continue waits for the next change. cognitive_complexity is the build/publish sequence, not branching.
#[allow(clippy::too_many_arguments, clippy::cognitive_complexity)]
async fn apply_config_reload(
	config: ReductionConfig,
	reloadable_tx: &watch::Sender<ReloadableState>,
	revocation_tx: &watch::Sender<RevocationSet>,
	proxy_state: &Arc<ProxyState>,
	startup_revocation_path: &Option<PathBuf>,
	prev_routes: &mut Vec<config::RouteConfig>,
	prev_backends: &mut Vec<config::BackendConfig>,
) -> ControlFlow<()> {
	// Re-read the revocation file alongside the ordinary config reload: a config-file save is a second
	// refresh trigger besides the notify watcher. Only republish on a clean parse — a bad read (missing
	// or corrupt) keeps the previous denylist rather than fail-open un-revoking.
	if let Some(path) = startup_revocation_path {
		match revocation_reload::load_revocation_file(path) {
			Ok(set) => {
				revocation_tx.send(set).ok();
			}
			Err(e) => {
				proxy_state.metrics.revocation_load_errors.add(1, &[]);
				error!(error = %e, "revocation re-read on config reload failed; keeping previous denylist");
			}
		}
	}

	let backend_pools: HashMap<ArrayString<256>, BackendPool> = match build_backend_pools(&config) {
		Ok(pools) => pools,
		Err(e) => {
			error!(error = %e, "failed to rebuild backend pools, keeping current config");
			return ControlFlow::Continue(());
		}
	};
	let new_state: ReloadableState = ReloadableState {
		router: Router::new(&config.routes),
		backend_pools,
		acl: AccessControl::new(config.access.allow.clone(), config.access.deny.clone()),
	};

	let old_state: ReloadableState = reloadable_tx.borrow().clone();
	let (removed_addrs, removed_backend_ids) = diff_removed_backends(&old_state, &new_state);

	if reloadable_tx.send(new_state).is_err() {
		info!("all proxy state receivers dropped, stopping config reload");
		return ControlFlow::Break(());
	}
	// Flush the response cache only when routing actually changed: the key carries no route generation, so an
	// entry cached against the old routing table would otherwise serve until its TTL for a path that now routes
	// elsewhere. A reload touching only unrelated sections (timeouts, TLS, balancer) leaves the cache warm.
	let routing_changed: bool = config.routes != *prev_routes || config.backends != *prev_backends;
	if routing_changed {
		proxy_state.response_cache.clear();
		*prev_routes = config.routes.clone();
		*prev_backends = config.backends.clone();
	}
	info!(routing_changed, "proxy state rebuilt from updated config");

	for id in &removed_backend_ids {
		proxy_state.queues.remove(id);
		proxy_state.circuit_breakers.remove_backend(id);
	}
	if !removed_backend_ids.is_empty() {
		info!(backends = ?removed_backend_ids, "cleaned up state for removed backends");
	}

	if !removed_addrs.is_empty() {
		let drain_timeout: u64 = config.balancer.drain_timeout_secs;
		info!(backends = ?removed_addrs, timeout_secs = drain_timeout, "draining removed backends");
		spawn_backend_drain(
			removed_addrs,
			drain_timeout,
			Arc::clone(proxy_state),
			reloadable_tx.subscribe(),
		);
	}

	proxy_state
		.conn_pool
		.warm_up(
			&config.backends,
			&proxy_state.tls_connector,
			&proxy_state.client_tls_config,
			Duration::from_secs(config.timeouts.connect_secs.get()),
			Duration::from_secs(config.timeouts.handshake_secs.get()),
		)
		.await;
	info!(
		count = config.backends.len(),
		"connection pool pre-warmed after config reload"
	);

	return ControlFlow::Continue(());
}

// Collect every backend address across all pools of a reloadable state into a set.
fn backend_addresses(state: &ReloadableState) -> HashSet<SocketAddr> {
	let mut addrs: HashSet<SocketAddr> = HashSet::new();
	state.backend_pools.values().for_each(|p| {
		p.backends.iter().for_each(|b| {
			addrs.insert(b.address);
		})
	});
	return addrs;
}

// Diff the live backend set against the rebuilt one: addresses no longer present anywhere (to drain)
// and pool ids that disappeared (to clean up per-backend queues/circuit state).
fn diff_removed_backends(old: &ReloadableState, new: &ReloadableState) -> (Vec<SocketAddr>, Vec<ArrayString<256>>) {
	let new_addrs: HashSet<SocketAddr> = backend_addresses(new);
	let removed_addrs: Vec<SocketAddr> = backend_addresses(old)
		.into_iter()
		.filter(|addr| !new_addrs.contains(addr))
		.collect();
	let removed_backend_ids: Vec<ArrayString<256>> = old
		.backend_pools
		.keys()
		.filter(|id| !new.backend_pools.contains_key(*id))
		.copied()
		.collect();
	return (removed_addrs, removed_backend_ids);
}

// After a grace period, evict idle connections to addresses removed by a reload — but only those still
// absent from the current state, so a backend re-added during the grace window keeps its connections.
fn spawn_backend_drain(
	removed_addrs: Vec<SocketAddr>,
	drain_timeout_secs: u64,
	proxy_state: Arc<ProxyState>,
	reloadable_rx: watch::Receiver<ReloadableState>,
) {
	tokio::spawn(async move {
		sleep(Duration::from_secs(drain_timeout_secs)).await;
		let current: ReloadableState = reloadable_rx.borrow().clone();
		let still_active: HashSet<SocketAddr> = backend_addresses(&current);
		let to_evict: Vec<SocketAddr> = removed_addrs
			.into_iter()
			.filter(|addr| !still_active.contains(addr))
			.collect();
		if !to_evict.is_empty() {
			proxy_state.conn_pool.drain_backends(&to_evict);
			info!(backends = ?to_evict, "drain complete, idle connections evicted");
		}
	});
}
