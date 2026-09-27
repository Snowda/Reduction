use std::sync::Arc;
use std::time::Duration;

use axum::routing::any;
use reduction::config::{ReductionConfig, TransportKind};
use reduction::error::{ReductionError, Result};
use reduction::proxy::{ProxyState, RawRelayAuthz, proxy_handler};
use reduction::transport;
use tokio::signal;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
#[cfg(unix)]
use tracing::error;
use tracing::{info, warn};

// Build the axum app and serve it over the configured transport until shutdown. TCP and QUIC both wrap
// the listener in a bounded graceful shutdown; only QUIC also spawns the raw-stream relay handler.
// Returns whether shutdown completed gracefully or was cut off by the drain timeout.
pub async fn serve_transport(
	config: &ReductionConfig,
	proxy_state: Arc<ProxyState>,
	server_tls_config: Arc<rustls::ServerConfig>,
	acme_challenge_config: Option<Arc<rustls::ServerConfig>>,
	shutdown_token: &CancellationToken,
	drain_timeout: Duration,
	raw_relay_authz: Arc<RawRelayAuthz>,
) -> Result<ShutdownOutcome> {
	// Held for the raw relay (QUIC only); cloned before proxy_state is moved into the app's state.
	let raw_relay_state: Arc<ProxyState> = Arc::clone(&proxy_state);

	let app = axum::Router::new()
		.fallback(any(proxy_handler))
		.layer(axum::extract::DefaultBodyLimit::max(
			usize::try_from(config.proxy.max_request_body_bytes).unwrap_or(usize::MAX),
		))
		.with_state(proxy_state)
		.into_make_service_with_connect_info::<transport::ConnectAddr>();

	info!("reduction proxy starting on {}", config.listen.address);

	let outcome: ShutdownOutcome = match config.listen.transport {
		TransportKind::Tcp => {
			let listener: transport::tcp::TcpListener = transport::tcp::TcpListener::bind_with_token(
				config.listen.address,
				server_tls_config,
				acme_challenge_config,
				shutdown_token.clone(),
				transport::tcp::DEFAULT_CHANNEL_CAPACITY,
			)
			.await?;
			let serve = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal(shutdown_token.clone()));
			serve_bounded(serve, shutdown_token, drain_timeout).await?
		}
		TransportKind::Quic => {
			let quic_config: quinn::ServerConfig = transport::quic::build_quic_server_config(server_tls_config)?;
			let mut listener: transport::quic::QuicListener = transport::quic::QuicListener::bind_with_token(
				config.listen.address,
				quic_config,
				shutdown_token.clone(),
				usize::try_from(config.proxy.quic_channel_capacity.get()).unwrap_or(usize::MAX),
			)?;

			if let Some(raw_rx) = listener.take_raw_stream_receiver() {
				let raw_state: Arc<ProxyState> = raw_relay_state;
				let raw_authz: Arc<RawRelayAuthz> = raw_relay_authz;
				let raw_shutdown: CancellationToken = shutdown_token.clone();
				tokio::spawn(async move {
					reduction::proxy::raw_relay::run_raw_relay_handler(raw_rx, raw_state, raw_authz, raw_shutdown)
						.await;
				});
				info!("raw QUIC stream relay handler spawned");
			}

			let serve = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal(shutdown_token.clone()));
			serve_bounded(serve, shutdown_token, drain_timeout).await?
		}
	};
	return Ok(outcome);
}

// Whether the bounded graceful shutdown completed on its own or was cut off by the drain timeout.
#[derive(Clone, Copy)]
pub enum ShutdownOutcome {
	Graceful,
	ForcedTimeout,
}

// Drives the axum server through graceful shutdown, but bounds the in-flight drain by `drain_timeout`
// measured from the moment the shutdown signal fires. axum's own graceful shutdown waits for in-flight
// connections with no internal timeout, so without this a single hung connection would block shutdown
// forever and the configured drain timeout could never take effect.
async fn serve_bounded<F>(
	serve: F,
	shutdown_token: &CancellationToken,
	drain_timeout: Duration,
) -> Result<ShutdownOutcome>
where
	F: IntoFuture<Output = std::io::Result<()>>,
{
	let serve = serve.into_future();
	tokio::pin!(serve);
	tokio::select! {
		result = &mut serve => {
			result.map_err(ReductionError::from)?;
			return Ok(ShutdownOutcome::Graceful);
		}
		_ = force_deadline(shutdown_token, drain_timeout) => {
			warn!(
				timeout_secs = drain_timeout.as_secs(),
				"graceful shutdown exceeded drain timeout; abandoning in-flight connections",
			);
			return Ok(ShutdownOutcome::ForcedTimeout);
		}
	}
}

// Resolves once the shutdown signal has fired and the drain grace period has then elapsed.
async fn force_deadline(shutdown_token: &CancellationToken, drain_timeout: Duration) {
	shutdown_token.cancelled().await;
	sleep(drain_timeout).await;
}

async fn shutdown_signal(token: CancellationToken) {
	let ctrl_c = signal::ctrl_c();

	#[cfg(unix)]
	let terminate = async {
		match signal::unix::signal(signal::unix::SignalKind::terminate()) {
			Ok(mut stream) => {
				stream.recv().await;
			}
			Err(e) => {
				// If the handler can't be installed, fall back to ctrl-c only rather than panicking.
				error!(error = %e, "failed to install SIGTERM handler; SIGTERM shutdown disabled");
				std::future::pending::<()>().await;
			}
		}
	};

	#[cfg(not(unix))]
	let terminate = std::future::pending::<()>();

	tokio::select! {
		_ = ctrl_c => info!("received ctrl-c, starting graceful shutdown"),
		_ = terminate => info!("received SIGTERM, starting graceful shutdown"),
	}

	token.cancel();
}

// This function is a trivial poll loop; the cognitive_complexity clippy reports here is the preceding
// shutdown_signal's tokio::select! macro expansion, which clippy attributes to the following item's span.
#[allow(clippy::cognitive_complexity)]
pub async fn drain_connections(state: Arc<ProxyState>, drain_timeout: Duration) {
	info!(timeout_secs = drain_timeout.as_secs(), "draining in-flight connections");

	const DRAIN_POLL_INTERVAL_MS: u64 = 250;
	let poll_interval: Duration = Duration::from_millis(DRAIN_POLL_INTERVAL_MS);
	let deadline: tokio::time::Instant = tokio::time::Instant::now() + drain_timeout;

	loop {
		let active: i64 = state.metrics.active_connection_count();
		if active <= 0 {
			info!("all connections drained");
			break;
		}
		if tokio::time::Instant::now() >= deadline {
			warn!(
				active,
				"drain timeout reached, forcing shutdown with in-flight connections"
			);
			break;
		}
		sleep(poll_interval).await;
	}

	state.conn_pool.drain();
	info!("connection pool closed");
}
