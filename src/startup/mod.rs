use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use reduction::config::ReductionConfig;
use reduction::error::Result;
use reduction::proxy::{ProxyState, RawRelayAuthz};
use reduction::tunnel::registry::TunnelRegistry;
use reduction::tunnel::revocation::RevocationSet;
use reduction::tunnel::revocation_reload::RevocationWatcher;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::info;

pub mod background;
pub mod balancing;
pub mod serve;
pub mod tls;

use background::{BackgroundCtx, setup_revocation_watcher, spawn_background_tasks};
use balancing::{Balancing, ProxyStateInputs, build_balancing, build_proxy_state};
use serve::{ShutdownOutcome, drain_connections, serve_transport};
use tls::{TlsSetup, build_tls_setup};

// The process startup wiring: build every long-lived subsystem, spawn the background tasks, then serve
// until shutdown. Branchy sub-units are extracted into their own functions so this driver stays linear.
pub async fn run(config_path: PathBuf, config: ReductionConfig) -> Result<()> {
	let TlsSetup {
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
	} = build_tls_setup(&config_path, &config).await?;

	let Balancing {
		reloadable_tx,
		reloadable_rx,
		configured_backend_ids,
		health_rx,
		health_tx,
		rate_limiter,
		circuit_breakers,
	} = build_balancing(&config)?;

	let shutdown_token: CancellationToken = CancellationToken::new();

	#[cfg(feature = "acme")]
	tls::bridge_acme_shutdown(&shutdown_token, acme_shutdown_tx);

	let tunnel_registry: Arc<TunnelRegistry> =
		Arc::new(TunnelRegistry::new(config.tunnel.max_sessions_per_backend.get()));

	// Revocation denylist, hot-swapped over its own watch channel; seeded from `tunnel.revocation_path`.
	let (revocation_tx, revocation_rx): (watch::Sender<RevocationSet>, watch::Receiver<RevocationSet>) =
		watch::channel(RevocationSet::default());
	let _revocation_watcher: Option<RevocationWatcher> =
		setup_revocation_watcher(&config, &proxy_metrics, &revocation_tx)?;
	// Held for the process lifetime so the config-reload re-read path can republish the denylist.
	let reload_revocation_tx: watch::Sender<RevocationSet> = revocation_tx;

	let proxy_state: Arc<ProxyState> = build_proxy_state(
		&config,
		&tunnel_registry,
		&revocation_rx,
		&shutdown_token,
		ProxyStateInputs {
			proxy_metrics,
			tls_connector,
			client_tls_config,
			reloadable_rx,
			health_rx,
			rate_limiter,
			circuit_breakers,
		},
	);

	spawn_background_tasks(
		&config,
		&proxy_state,
		&tunnel_registry,
		&shutdown_token,
		BackgroundCtx {
			config_rx,
			reloadable_tx,
			reload_revocation_tx,
			revocation_rx,
			server_tls_config: Arc::clone(&server_tls_config),
			health_tx,
		},
	)
	.await?;

	// Non-public readiness/liveness endpoint. Bound now (fail-fast); flipped to ready just before serving
	// — by which point TLS is built (under ACME the initial cert is provisioned) and every background task
	// is spawned. Its own task flips it to draining when shutdown fires so a load balancer drains us.
	let readiness: reduction::health_endpoint::Readiness = reduction::health_endpoint::Readiness::new();
	reduction::health_endpoint::spawn_health_endpoint(&config.health_endpoint, readiness.clone(), shutdown_token.clone())
		.await?;

	let drain_registry: Arc<TunnelRegistry> = Arc::clone(&tunnel_registry);
	let drain_state: Arc<ProxyState> = Arc::clone(&proxy_state);
	// Per-backend raw-relay allowlist (validated here so a malformed policy fails fast at startup rather
	// than silently denying at request time). Only the QUIC transport spawns the raw relay handler.
	let raw_relay_authz: Arc<RawRelayAuthz> =
		Arc::new(RawRelayAuthz::new(&config.raw_relay_authz, &configured_backend_ids)?);
	info!(
		backends = raw_relay_authz.len(),
		"raw-relay per-device authorization configured"
	);
	let drain_timeout: Duration = Duration::from_secs(config.balancer.drain_timeout_secs);

	// Everything is wired and the cert is present: announce readiness so probes flip to 200.
	readiness.set_ready();
	info!("proxy ready to serve");

	let outcome: ShutdownOutcome = serve_transport(
		&config,
		proxy_state,
		server_tls_config,
		acme_challenge_config,
		&shutdown_token,
		drain_timeout,
		raw_relay_authz,
	)
	.await?;

	drain_registry.shutdown_all().await;
	// If the bounded graceful shutdown already timed out, in-flight connections are hung; force the
	// pool closed immediately rather than waiting out a second full drain window.
	let residual_drain: Duration = match outcome {
		ShutdownOutcome::ForcedTimeout => Duration::ZERO,
		ShutdownOutcome::Graceful => drain_timeout,
	};
	drain_connections(drain_state, residual_drain).await;
	return Ok(());
}
