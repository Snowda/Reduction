use std::sync::Arc;
use std::time::Duration;

use reduction::acl::AccessControl;
use reduction::circuit::CircuitBreakers;
use reduction::config::{self, IngressProtocol, ReductionConfig};
use reduction::error::Result;
use reduction::health::HealthState;
use reduction::ingress::tcp::{self, TcpIngressParams};
use reduction::ingress::udp::{self, UdpIngressParams};
use reduction::metrics::ProxyMetrics;
use reduction::proxy::{ConnPool, ProxyState, ReloadableState};
use reduction::tunnel::registry::TunnelRegistry;
use reduction::tunnel::revocation::RevocationSet;
use reduction::tunnel::revocation_reload::{self, RevocationWatcher};
use tokio::sync::watch;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::config_reload::spawn_config_reload_task;

// Entries removed by a sweep, from the map size before and after retain_recent(). Concurrent check() inserts
// can grow the map between the two len() reads, so `after` may exceed `before`; saturating avoids a usize underflow.
#[must_use]
const fn swept_count(before: usize, after: usize) -> usize {
	return before.saturating_sub(after);
}

// Periodically drop fully-replenished per-IP entries from the rate limiter's keyed store so its
// memory stays bounded by the active source-IP set. governor never reclaims these itself, so
// without this sweep the map would grow one entry per distinct client IP for the process lifetime.
fn spawn_ratelimit_gc(proxy_state: Arc<ProxyState>, interval: Duration, shutdown: CancellationToken) {
	tokio::spawn(async move {
		loop {
			tokio::select! {
				_ = sleep(interval) => {
					let before: usize = proxy_state.rate_limiter.len();
					proxy_state.rate_limiter.retain_recent();
					let after: usize = proxy_state.rate_limiter.len();
					let pruned: usize = swept_count(before, after);
					if pruned > 0 {
						debug!(pruned, remaining = after, "rate limiter state swept");
					}
				}
				_ = shutdown.cancelled() => {
					info!("rate limiter GC stopping");
					break;
				}
			}
		}
	});
}

// Watch the revocation channel and, on each update, sweep the tunnel registry: terminate every live
// session the new set denies and record how many were cut off. Runs until the channel closes.
fn spawn_revocation_sweep(
	mut revocation_rx: watch::Receiver<RevocationSet>,
	registry: Arc<TunnelRegistry>,
	metrics: ProxyMetrics,
) {
	tokio::spawn(async move {
		while revocation_rx.changed().await.is_ok() {
			let revoked: usize = {
				let set: watch::Ref<'_, RevocationSet> = revocation_rx.borrow_and_update();
				registry.revoke_matching(&set)
			};
			if revoked > 0 {
				metrics
					.tunnel_sessions_revoked
					.add(u64::try_from(revoked).unwrap_or(u64::MAX), &[]);
				info!(count = revoked, "revocation update terminated live tunnel sessions");
			}
		}
		info!("revocation channel closed, stopping revocation sweep");
	});
}

// Spawn a UDP ingress listener for every `[[ingress]]` entry (presence of any enables the mode). Each
// gets its own connection pool + circuit breaker (ingress backends have independent stream state from
// the HTTP path) but shares the health and config watch channels so selection and tunable hot-reload
// track live state. TCP ingress is Phase 3; a tcp entry is logged and skipped for now.
async fn spawn_ingress_listeners(
	config: &ReductionConfig,
	client_tls_config: &Arc<rustls::ClientConfig>,
	health_rx: &watch::Receiver<HealthState>,
	config_rx: &watch::Receiver<ReductionConfig>,
	tunnel_registry: Option<Arc<TunnelRegistry>>,
	shutdown: &CancellationToken,
) -> Result<()> {
	if config.ingress.is_empty() {
		return Ok(());
	}

	let mut ingress_pool: ConnPool = ConnPool::new().with_pool_config(
		config.proxy.h2_connections_per_backend.get(),
		config.proxy.max_idle_quic_per_host,
		config.proxy.h2_stream_window,
		config.proxy.h2_conn_window,
	);
	if let Some(registry) = tunnel_registry {
		ingress_pool = ingress_pool.with_tunnel_registry(registry);
	}
	let ingress_pool: Arc<ConnPool> = Arc::new(ingress_pool);
	let circuit: Arc<CircuitBreakers> = Arc::new(CircuitBreakers::new(&config.circuit_breaker));
	let connect_timeout: Duration = Duration::from_secs(config.timeouts.connect_secs.get());

	for entry in &config.ingress {
		match entry.protocol {
			IngressProtocol::Udp => {
				let backends: Vec<config::BackendConfig> = config
					.backends
					.iter()
					.filter(|b| entry.backend_ids.iter().any(|id| id.as_str() == b.id.as_str()))
					.cloned()
					.collect();
				let params: UdpIngressParams = UdpIngressParams {
					config: entry.clone(),
					backends,
					acl: AccessControl::new(config.access.allow.clone(), config.access.deny.clone()),
					requests_per_second: config.ratelimit.requests_per_second,
					conn_pool: Arc::clone(&ingress_pool),
					client_tls_config: Arc::clone(client_tls_config),
					health_rx: health_rx.clone(),
					config_rx: config_rx.clone(),
					circuit: Arc::clone(&circuit),
					retry: config.retry.clone(),
					connect_timeout,
					max_backends: config.balancer.max_backends,
					shutdown: shutdown.clone(),
				};
				udp::spawn_udp_ingress(&params)?;
				info!(ingress = %entry.id, listen = %entry.listen, "udp ingress listener spawned");
			}
			IngressProtocol::Tcp => {
				let backends: Vec<config::BackendConfig> = config
					.backends
					.iter()
					.filter(|b| entry.backend_ids.iter().any(|id| id.as_str() == b.id.as_str()))
					.cloned()
					.collect();
				let params: TcpIngressParams = TcpIngressParams {
					config: entry.clone(),
					backends,
					acl: AccessControl::new(config.access.allow.clone(), config.access.deny.clone()),
					requests_per_second: config.ratelimit.requests_per_second,
					conn_pool: Arc::clone(&ingress_pool),
					client_tls_config: Arc::clone(client_tls_config),
					health_rx: health_rx.clone(),
					circuit: Arc::clone(&circuit),
					connect_timeout,
					max_backends: config.balancer.max_backends,
					shutdown: shutdown.clone(),
				};
				tcp::spawn_tcp_ingress(params).await?;
				info!(ingress = %entry.id, listen = %entry.listen, "tcp ingress listener spawned");
			}
		}
	}
	return Ok(());
}

// Seed the revocation denylist from `tunnel.revocation_path` (publishing the initial set) and start a
// notify watcher that keeps it current. Returns the watcher (held by the caller); a watcher that fails
// to start leaves the startup set enforced but not refreshed — surfaced loudly rather than fatal.
pub fn setup_revocation_watcher(
	config: &ReductionConfig,
	proxy_metrics: &ProxyMetrics,
	revocation_tx: &watch::Sender<RevocationSet>,
) -> Result<Option<RevocationWatcher>> {
	let path = match &config.tunnel.revocation_path {
		Some(path) => path,
		None => return Ok(None),
	};
	let initial: RevocationSet = revocation_reload::load_initial(path, proxy_metrics)?;
	revocation_tx.send(initial).ok();
	return match RevocationWatcher::new(path, revocation_tx.clone(), ProxyMetrics::new()) {
		Ok(watcher) => Ok(Some(watcher)),
		Err(e) => {
			error!(error = %e, "failed to start revocation watcher; denylist will not hot-reload");
			Ok(None)
		}
	};
}

// The channel senders and TLS config the background tasks consume, bundled to keep the spawn helper's
// argument count in check.
pub struct BackgroundCtx {
	pub config_rx: watch::Receiver<ReductionConfig>,
	pub reloadable_tx: watch::Sender<ReloadableState>,
	pub reload_revocation_tx: watch::Sender<RevocationSet>,
	pub revocation_rx: watch::Receiver<RevocationSet>,
	pub server_tls_config: Arc<rustls::ServerConfig>,
	pub health_tx: watch::Sender<HealthState>,
}

// Spawn every long-lived background task (config hot-reload, rate-limiter GC, ingress listeners, tunnel
// listener) and pre-warm the connection pool. The listeners fail fast if a bind fails; everything else
// runs until the shutdown token fires.
pub async fn spawn_background_tasks(
	config: &ReductionConfig,
	proxy_state: &Arc<ProxyState>,
	tunnel_registry: &Arc<TunnelRegistry>,
	shutdown_token: &CancellationToken,
	ctx: BackgroundCtx,
) -> Result<()> {
	// Clone the config receiver for ingress before the reload task takes ownership of the original, so
	// ingress workers see the same hot-reload stream.
	let ingress_config_rx: watch::Receiver<ReductionConfig> = ctx.config_rx.clone();

	spawn_config_reload_task(
		ctx.config_rx,
		ctx.reloadable_tx,
		ctx.reload_revocation_tx,
		Arc::clone(proxy_state),
		config.tunnel.revocation_path.clone(),
	);

	spawn_ratelimit_gc(
		Arc::clone(proxy_state),
		Duration::from_secs(config.ratelimit.retain_interval_secs.get()),
		shutdown_token.clone(),
	);

	spawn_ingress_listeners(
		config,
		&proxy_state.client_tls_config,
		&proxy_state.health_rx,
		&ingress_config_rx,
		config.tunnel.enabled.then(|| Arc::clone(tunnel_registry)),
		shutdown_token,
	)
	.await?;

	// Optional cleartext port-80 → HTTPS redirect listener. Binds fail-fast (like ingress) so a
	// privileged-port failure surfaces at startup; a no-op when disabled.
	reduction::redirect::spawn_http_redirect(&config.http_redirect, shutdown_token.clone()).await?;

	spawn_tunnel_listener(config, tunnel_registry, &ctx.server_tls_config, shutdown_token, &ctx.revocation_rx, ctx.health_tx);

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
	info!(count = config.backends.len(), "connection pool pre-warmed on startup");
	return Ok(());
}

// Spawn the tunnel listener and its revocation sweep when tunneling is enabled and an address is set.
// A no-op when tunneling is off; an enabled-but-unaddressed config is warned about, not fatal.
fn spawn_tunnel_listener(
	config: &ReductionConfig,
	tunnel_registry: &Arc<TunnelRegistry>,
	server_tls_config: &Arc<rustls::ServerConfig>,
	shutdown_token: &CancellationToken,
	revocation_rx: &watch::Receiver<RevocationSet>,
	health_tx: watch::Sender<HealthState>,
) {
	if !config.tunnel.enabled {
		return;
	}
	let Some(tunnel_addr) = config.tunnel.listen_address else {
		warn!("tunnel enabled but no listen_address configured");
		return;
	};
	let tunnel_reg: Arc<TunnelRegistry> = Arc::clone(tunnel_registry);
	let tunnel_shutdown: CancellationToken = shutdown_token.clone();
	let tunnel_tls: Arc<rustls::ServerConfig> = Arc::clone(server_tls_config);
	let tunnel_config = config.tunnel.clone();
	let tunnel_metrics: ProxyMetrics = ProxyMetrics::new();
	let tunnel_revocation: watch::Receiver<RevocationSet> = revocation_rx.clone();
	// F4 flag: only honor control-plane Health frames when explicitly enabled. Off ⇒ the plain entry
	// point, byte-identical to Phase 1 (health_tx dropped, health frames ignored).
	let control_plane_health: bool = config.tunnel.control_plane_health;
	tokio::spawn(async move {
		let result: Result<()> = if control_plane_health {
			reduction::tunnel::listener::run_tunnel_listener_with_health(
				tunnel_addr,
				tunnel_tls,
				tunnel_reg,
				tunnel_shutdown,
				tunnel_config,
				tunnel_metrics,
				tunnel_revocation,
				health_tx,
			)
			.await
		} else {
			reduction::tunnel::listener::run_tunnel_listener(
				tunnel_addr,
				tunnel_tls,
				tunnel_reg,
				tunnel_shutdown,
				tunnel_config,
				tunnel_metrics,
				tunnel_revocation,
			)
			.await
		};
		if let Err(e) = result {
			error!(error = %e, "tunnel listener failed");
		}
	});
	info!(%tunnel_addr, control_plane_health, "tunnel listener spawned");

	// Sweep live sessions on every revocation-set update: registration-time denial alone would leave an
	// already-connected clone tunnel alive until it happened to reconnect.
	spawn_revocation_sweep(revocation_rx.clone(), Arc::clone(tunnel_registry), ProxyMetrics::new());
}

#[cfg(test)]
mod tests {
	use super::swept_count;

	// Normal case: retain_recent() shrank the map, so the swept count is the difference.
	#[test]
	fn swept_count_reports_the_shrink() {
		assert_eq!(swept_count(5, 3), 2);
	}

	// Regression: a concurrent check() insert grew the map between the two len() reads, so
	// after > before. The count must saturate to 0 rather than underflow usize — the old
	// `before - after` panicked here in debug builds, killing the GC task the sweep protects.
	#[test]
	fn swept_count_saturates_when_concurrent_inserts_outpace_pruning() {
		assert_eq!(swept_count(3, 5), 0);
	}

	// Boundary: no net change sweeps nothing.
	#[test]
	fn swept_count_is_zero_when_unchanged() {
		assert_eq!(swept_count(4, 4), 0);
	}
}
