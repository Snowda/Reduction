use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::body::Body;
use axum::extract::State;
use axum::http::{Response, StatusCode};
use axum::routing::get;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::config::HealthEndpointConfig;
use crate::error::Result;

// Lifecycle states the readiness probe reflects. Starting: wiring not finished (or ACME cert not yet
// provisioned). Ready: serving. Draining: shutdown began, so a load balancer should stop routing here
// while in-flight requests finish. A u8 (not a bool) keeps the three states distinguishable in the
// probe body and future transitions, per the project's prefer-enum-over-bool guidance.
const STATE_STARTING: u8 = 0;
const STATE_READY: u8 = 1;
const STATE_DRAINING: u8 = 2;

// Shared readiness flag, flipped by the process lifecycle and read by the /readyz handler. Cloneable
// (Arc); a clone observes the same state. Liveness (/livez) does not consult it — a running process is
// live by definition.
#[derive(Debug, Clone)]
pub struct Readiness {
	state: Arc<AtomicU8>,
}

impl Default for Readiness {
	fn default() -> Self {
		return Self::new();
	}
}

impl Readiness {
	#[must_use]
	pub fn new() -> Self {
		return Self {
			state: Arc::new(AtomicU8::new(STATE_STARTING)),
		};
	}

	// Mark the proxy ready to serve (startup wiring complete and, under ACME, the initial cert present).
	pub fn set_ready(&self) {
		self.state.store(STATE_READY, Ordering::Release);
	}

	// Mark the proxy draining (shutdown began): /readyz flips to 503 so an LB removes it from rotation.
	pub fn set_draining(&self) {
		self.state.store(STATE_DRAINING, Ordering::Release);
	}

	#[must_use]
	pub fn is_ready(&self) -> bool {
		return self.state.load(Ordering::Acquire) == STATE_READY;
	}

	// Human-readable label for the probe body / logs.
	#[must_use]
	pub fn label(&self) -> &'static str {
		return match self.state.load(Ordering::Acquire) {
			STATE_READY => "ready",
			STATE_DRAINING => "draining",
			_ => "starting",
		};
	}
}

fn text_response(status: StatusCode, body: &'static str) -> Response<Body> {
	let mut response: Response<Body> = Response::new(Body::from(body));
	*response.status_mut() = status;
	return response;
}

// Liveness: the process is up and the endpoint is serving. Always 200 — it never consults readiness,
// so an orchestrator can distinguish "process dead" (connection refused) from "not ready" (/readyz 503).
async fn livez() -> Response<Body> {
	return text_response(StatusCode::OK, "alive");
}

// Readiness: 200 only while READY; 503 while STARTING or DRAINING, so traffic is withheld until the
// proxy can serve and withdrawn again the moment shutdown begins.
async fn readyz(State(readiness): State<Readiness>) -> Response<Body> {
	if readiness.is_ready() {
		return text_response(StatusCode::OK, "ready");
	}
	return match readiness.label() {
		"draining" => text_response(StatusCode::SERVICE_UNAVAILABLE, "draining"),
		_ => text_response(StatusCode::SERVICE_UNAVAILABLE, "starting"),
	};
}

// Bind the non-public health endpoint and spawn its serve loop plus a task that flips readiness to
// draining when shutdown fires. Binding is synchronous (fail fast at startup); a no-op when disabled.
pub async fn spawn_health_endpoint(
	config: &HealthEndpointConfig,
	readiness: Readiness,
	shutdown: CancellationToken,
) -> Result<()> {
	if !config.enabled {
		return Ok(());
	}

	let listener: TcpListener = TcpListener::bind(config.listen).await?;
	let local_addr = listener.local_addr()?;

	let app = axum::Router::new()
		.route("/livez", get(livez))
		.route("/readyz", get(readyz))
		.with_state(readiness.clone());

	info!(listen = %local_addr, "health endpoint bound (/livez, /readyz)");

	// Flip to draining as soon as shutdown begins so /readyz sheds traffic during the drain window.
	let drain_readiness: Readiness = readiness;
	let drain_shutdown: CancellationToken = shutdown.clone();
	tokio::spawn(async move {
		drain_shutdown.cancelled().await;
		drain_readiness.set_draining();
		info!("health endpoint readiness set to draining");
	});

	tokio::spawn(async move {
		let serve = axum::serve(listener, app).with_graceful_shutdown(async move {
			shutdown.cancelled().await;
		});
		if let Err(e) = serve.await {
			error!(error = %e, "health endpoint serve loop failed");
		}
	});

	return Ok(());
}

#[cfg(test)]
mod tests {
	use std::net::SocketAddr;
	use std::time::Duration;

	use http_body_util::BodyExt;
	use hyper::client::conn::http1;
	use hyper::Request;
	use hyper_util::rt::TokioIo;
	use tokio::net::TcpStream;

	use super::*;

	#[test]
	fn readiness_transitions() {
		let r = Readiness::new();
		assert!(!r.is_ready(), "starts not-ready");
		assert_eq!(r.label(), "starting");
		r.set_ready();
		assert!(r.is_ready());
		assert_eq!(r.label(), "ready");
		r.set_draining();
		assert!(!r.is_ready(), "draining is not ready");
		assert_eq!(r.label(), "draining");
	}

	#[test]
	fn readiness_clone_shares_state() {
		let r = Readiness::new();
		let clone = r.clone();
		r.set_ready();
		assert!(clone.is_ready(), "a clone observes the same state");
	}

	#[tokio::test]
	async fn readyz_reflects_readiness_and_livez_is_always_ok() {
		let readiness = Readiness::new();
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let addr: SocketAddr = listener.local_addr().unwrap();
		let app = axum::Router::new()
			.route("/livez", get(livez))
			.route("/readyz", get(readyz))
			.with_state(readiness.clone());
		tokio::spawn(async move {
			let _ = axum::serve(listener, app).await;
		});
		tokio::time::sleep(Duration::from_millis(50)).await;

		// Before ready: /livez 200, /readyz 503.
		assert_eq!(probe(addr, "/livez").await, StatusCode::OK);
		assert_eq!(probe(addr, "/readyz").await, StatusCode::SERVICE_UNAVAILABLE);

		// After ready: /readyz flips to 200.
		readiness.set_ready();
		assert_eq!(probe(addr, "/readyz").await, StatusCode::OK);

		// Draining: /readyz back to 503 while /livez stays 200.
		readiness.set_draining();
		assert_eq!(probe(addr, "/readyz").await, StatusCode::SERVICE_UNAVAILABLE);
		assert_eq!(probe(addr, "/livez").await, StatusCode::OK);
	}

	async fn probe(addr: SocketAddr, path: &str) -> StatusCode {
		let stream = TcpStream::connect(addr).await.unwrap();
		let (mut sender, conn) = http1::handshake::<_, Body>(TokioIo::new(stream)).await.unwrap();
		tokio::spawn(async move {
			let _ = conn.await;
		});
		let req = Request::builder().uri(path).body(Body::empty()).unwrap();
		let resp = sender.send_request(req).await.unwrap();
		let status = resp.status();
		let _ = resp.into_body().collect().await;
		return status;
	}

	// ── spawn_health_endpoint end-to-end ──

	async fn free_port() -> SocketAddr {
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let addr = listener.local_addr().unwrap();
		drop(listener);
		return addr;
	}

	#[tokio::test]
	async fn spawn_disabled_is_a_noop() {
		let config = crate::config::HealthEndpointConfig::default();
		assert!(!config.enabled);
		let result = spawn_health_endpoint(&config, Readiness::new(), CancellationToken::new()).await;
		assert!(result.is_ok(), "a disabled health endpoint must be a successful no-op");
	}

	#[tokio::test]
	async fn spawn_enabled_serves_probes_and_flips_to_draining_on_shutdown() {
		let addr = free_port().await;
		let config = crate::config::HealthEndpointConfig {
			enabled: true,
			listen: addr,
		};
		let readiness = Readiness::new();
		let shutdown = CancellationToken::new();
		spawn_health_endpoint(&config, readiness.clone(), shutdown.clone())
			.await
			.unwrap();
		tokio::time::sleep(Duration::from_millis(50)).await;

		// Before ready: /livez 200, /readyz 503; after set_ready, /readyz 200.
		assert_eq!(probe(addr, "/livez").await, StatusCode::OK);
		assert_eq!(probe(addr, "/readyz").await, StatusCode::SERVICE_UNAVAILABLE);
		readiness.set_ready();
		assert_eq!(probe(addr, "/readyz").await, StatusCode::OK);

		// Shutdown must drive the drain-flip task: readiness (a shared clone) becomes draining.
		shutdown.cancel();
		let mut drained = false;
		for _ in 0..40 {
			if readiness.label() == "draining" {
				drained = true;
				break;
			}
			tokio::time::sleep(Duration::from_millis(25)).await;
		}
		assert!(drained, "shutdown must flip readiness to draining");
	}
}
