use std::net::SocketAddr;
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode};
use tokio::net::TcpStream;
use tokio::time::Instant as TokioInstant;
use tokio::time::{sleep_until, timeout};
use tracing::{info, warn};

use crate::config::{BackendConfig, TransportKind};
use crate::proxy::handler::{error_response, record_completion};

use super::{AttemptOutcome, RequestCtx};

// F1 park: each connect probe's timeout and the gap between probes; the wake deadline bounds the total.
const PROBE_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const PROBE_INTERVAL: Duration = Duration::from_millis(200);

// F1: park a request to a cold `wakeable` backend until it is reachable or the wake deadline passes. It
// dispatches a `Wake` to the control plane, then waits for readiness. On readiness it retries (`Continue`);
// on timeout it returns `503` + `Retry-After` (not `502`: the backend is starting, not broken).
pub async fn park_for_wake(ctx: &RequestCtx<'_>, backend: &BackendConfig) -> AttemptOutcome {
	let wake_secs: u64 = ctx.state.proxy_config.wake_timeout_secs.get();
	let deadline: TokioInstant = TokioInstant::now() + Duration::from_secs(wake_secs);
	info!(backend = backend.id.as_str(), wake_secs, "cold wakeable backend: parking request for a wake");
	if let Some(registry) = ctx.state.conn_pool.tunnel_registry() {
		registry.dispatch_wake(backend.id.as_str(), wake_secs.saturating_mul(1000)).await;
	}
	if await_reachable_or_refused(ctx, backend, deadline).await {
		info!(backend = backend.id.as_str(), "parked request released: backend is reachable");
		return AttemptOutcome::Continue;
	}
	warn!(backend = backend.id.as_str(), wake_secs, "wake not satisfied; returning 503");
	record_completion(ctx.state, ctx.start, StatusCode::SERVICE_UNAVAILABLE, ctx.backend_id.as_str());
	return AttemptOutcome::Return(wake_timeout_response(wake_secs));
}

// Wait for the woken backend to become reachable, or for a control-plane refusal to abort the park first.
async fn await_reachable_or_refused(ctx: &RequestCtx<'_>, backend: &BackendConfig, deadline: TokioInstant) -> bool {
	let Some(registry) = ctx.state.conn_pool.tunnel_registry() else {
		return backend_became_reachable(ctx, backend, deadline).await;
	};
	return tokio::select! {
		became = backend_became_reachable(ctx, backend, deadline) => became,
		() = registry.await_refusal(backend.id.as_str()) => {
			warn!(backend = backend.id.as_str(), "wake refused by the control plane");
			false
		}
	};
}

// Whether the woken backend is reachable before `deadline` (direct by TCP connect, tunnel by session).
async fn backend_became_reachable(ctx: &RequestCtx<'_>, backend: &BackendConfig, deadline: TokioInstant) -> bool {
	return match backend.transport {
		TransportKind::Tcp => wait_for_reachable_tcp(backend.address, deadline).await,
		TransportKind::Quic => match ctx.state.conn_pool.tunnel_registry() {
			Some(registry) => registry.wait_for_session(backend.id.as_str(), deadline).await,
			None => false,
		},
	};
}

// Poll `addr` until a TCP connection succeeds (the woken direct backend is up) or `deadline` passes.
async fn wait_for_reachable_tcp(addr: SocketAddr, deadline: TokioInstant) -> bool {
	loop {
		if timeout(PROBE_CONNECT_TIMEOUT, TcpStream::connect(addr)).await.is_ok_and(|r| r.is_ok()) {
			return true;
		}
		let now: TokioInstant = TokioInstant::now();
		if now >= deadline {
			return false;
		}
		let next: TokioInstant = (now + PROBE_INTERVAL).min(deadline);
		sleep_until(next).await;
	}
}

// A `503 Service Unavailable` + `Retry-After` for a wake that did not complete in time.
fn wake_timeout_response(wake_secs: u64) -> Response<Body> {
	let mut response: Response<Body> = error_response(StatusCode::SERVICE_UNAVAILABLE, "backend waking; retry shortly");
	if let Ok(value) = HeaderValue::try_from(wake_secs.to_string()) {
		response.headers_mut().insert("Retry-After", value);
	}
	return response;
}

#[cfg(test)]
mod tests {
	use std::net::SocketAddr;
	use std::time::Duration;

	use axum::http::StatusCode;
	use tokio::time::Instant as TokioInstant;

	use super::{wait_for_reachable_tcp, wake_timeout_response};

	// The park's reachability probe: a live address releases at once; a dead one times out at the deadline.
	#[tokio::test]
	async fn wait_for_reachable_tcp_true_when_listening_false_on_timeout() {
		let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let live: SocketAddr = listener.local_addr().unwrap();
		let soon: TokioInstant = TokioInstant::now() + Duration::from_secs(5);
		assert!(wait_for_reachable_tcp(live, soon).await, "a listening address is reachable");

		let dead: std::net::TcpListener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let dead_addr: SocketAddr = dead.local_addr().unwrap();
		drop(dead);
		let deadline: TokioInstant = TokioInstant::now() + Duration::from_millis(150);
		assert!(!wait_for_reachable_tcp(dead_addr, deadline).await, "a dead address times out to false");
	}

	// F1: a wake that never completes is a 503 + Retry-After (backend starting), not a 502 (broken).
	#[test]
	fn wake_timeout_response_is_503_with_retry_after() {
		let response = wake_timeout_response(30);
		assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
		assert_eq!(response.headers().get("Retry-After").and_then(|v| v.to_str().ok()), Some("30"));
	}
}
