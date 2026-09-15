use super::{
	Arc, ArrayString, ArrayVec, Body, BodyExt, BackendConfig, BackendPool, Bytes, CacheDirectives, CacheKeyRef,
	CircuitState, ConnPermitGuard, Duration, HalfOpenGuard, Instant, IpAddr, KeyValue, MAX_BACKENDS, Parts,
	PeerIdentity, ProxyState, ReductionError, Request, Response, Result, StatusCode, backend_label, backoff_delay,
	error, error_response, forward_request, from_ref, info, is_cacheable_status, is_retryable_status, mark_failed,
	maybe_compress, record_completion, response_is_encoded, response_permits_shared_caching, select_backend_excluding,
	vary_permits_caching, warn, HeaderValue,
};
use std::net::SocketAddr;

use tokio::net::TcpStream;
use tokio::time::sleep_until;
use tokio::time::timeout;
use tokio::time::Instant as TokioInstant;

use crate::config::TransportKind;

// F1 park: each connect probe's timeout, and the gap between probes, while a direct wakeable backend
// starts. The wake deadline bounds the total.
const PROBE_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const PROBE_INTERVAL: Duration = Duration::from_millis(200);

pub struct RequestCtx<'a> {
	pub state: &'a Arc<ProxyState>,
	pub pool: &'a BackendPool,
	pub client_ip: IpAddr,
	pub client_identity: Option<PeerIdentity>,
	pub backend_id: ArrayString<256>,
	pub cache_identity: &'a str,
	pub start: Instant,
	pub max_attempts: u32,
	pub is_cacheable_method: bool,
	pub request_has_cookie: bool,
	pub accepts_zstd: bool,
}

// The request body prepared for replay: a buffered copy (retryable) or a one-shot streaming body, plus the request parts cloned per attempt.
pub struct ReplayBody {
	pub body_bytes: Option<Bytes>,
	pub streaming_body: Option<Body>,
	pub req_parts: Parts,
}

// State across retry attempts: tried backends + the last retryable response/error for budget exhaustion.
pub struct RetryState {
	pub failed_backends: ArrayVec<ArrayString<256>, MAX_BACKENDS>,
	pub last_response: Option<Response<Body>>,
	pub last_error_msg: Option<String>,
}

// A backend selected and gated for one attempt, carrying its per-attempt guards (connection permit, half-open probe).
struct Selected {
	backend: BackendConfig,
	sel_label: KeyValue,
	conn: ConnPermitGuard,
	half_open: Option<HalfOpenGuard>,
}

// How one attempt ended: retry next, stop, return a response, or stream a success (caller bundles its guards).
pub enum AttemptOutcome {
	Continue,
	Break,
	Return(Response<Body>),
	Stream {
		response: Response<Body>,
		conn: ConnPermitGuard,
		half_open: Option<HalfOpenGuard>,
	},
}

// Loop control for a skipped attempt (tiny enum so select_and_gate's Result Err stays small).
enum Skip {
	Break,
	Continue,
}

// Select a backend (preferring untried), acquire its connection permit, and gate on the circuit breaker.
// `Err(Skip)` carries loop control: Break (no backend) or Continue (permit exhausted / circuit open).
fn select_and_gate(ctx: &RequestCtx<'_>, attempt: u32, retry: &mut RetryState) -> std::result::Result<Selected, Skip> {
	// Prefer a backend not yet tried this request; fall back to re-selecting among all of them so a
	// retry still fires for single-backend pools and exhausted multi-backend pools.
	let selection: Result<BackendConfig> =
		select_backend_excluding(ctx.pool, ctx.client_ip, &ctx.state.health_rx, &ctx.state.conn_pool, &retry.failed_backends)
			.or_else(|_| select_backend_excluding(ctx.pool, ctx.client_ip, &ctx.state.health_rx, &ctx.state.conn_pool, &[]));
	let backend: BackendConfig = match selection {
		Ok(b) => b,
		Err(e) => {
			warn!(attempt, error = %e, "no backend available");
			retry.last_error_msg = Some(format!("{e}"));
			return Err(Skip::Break);
		}
	};
	let sel_label: KeyValue = backend_label(&ctx.state.labels, &backend.id);
	ctx.state.metrics.backend_selections.add(1, from_ref(&sel_label));
	let sel_attr: [KeyValue; 1] = [sel_label.clone()];

	// Per-attempt connection permit — released when this attempt ends, or, on the winning attempt, moved
	// into the response body so it is held until the body finishes streaming.
	let conn: ConnPermitGuard = match ctx.state.conn_pool.try_acquire_conn_permit(&backend) {
		Ok(permit) => {
			ctx.state.metrics.backend_active_connections.add(1, &sel_attr);
			ConnPermitGuard {
				counter: ctx.state.metrics.backend_active_connections.clone(),
				backend_kv: sel_label.clone(),
				_permit: permit,
			}
		}
		Err(_) => {
			ctx.state.metrics.backend_conn_limit_rejected.add(1, &sel_attr);
			warn!(
				backend = backend.id.as_str(),
				max = backend.max_connections,
				"connection limit reached, trying another backend"
			);
			retry.last_error_msg = Some("backend connection limit reached".into());
			mark_failed(&mut retry.failed_backends, backend.id);
			return Err(Skip::Continue);
		}
	};

	// Per-attempt circuit-breaker gate; an open circuit skips this backend, not the request.
	let half_open: Option<HalfOpenGuard>;
	match ctx.state.circuit_breakers.check(backend.id.as_str()) {
		(CircuitState::Open, _) => {
			ctx.state.metrics.circuit_open_total.add(1, &sel_attr);
			warn!(backend = backend.id.as_str(), "circuit breaker open, trying another backend");
			retry.last_error_msg = Some("circuit open".into());
			mark_failed(&mut retry.failed_backends, backend.id);
			return Err(Skip::Continue);
		}
		(CircuitState::HalfOpen, guard) => {
			half_open = guard;
			ctx.state.metrics.circuit_half_open_probes.add(1, &sel_attr);
		}
		(CircuitState::Closed, _) => {
			half_open = None;
		}
	}

	return Ok(Selected { backend, sel_label, conn, half_open });
}

// Rebuild the request for one attempt: a buffered body clones; a streaming body consumed once yields None (stop retrying).
fn build_retry_req(replay: &mut ReplayBody, backend: &BackendConfig, attempt: u32) -> Option<Request<Body>> {
	return match &replay.body_bytes {
		Some(bytes) => Some(Request::from_parts(replay.req_parts.clone(), Body::from(bytes.clone()))),
		None => match replay.streaming_body.take() {
			Some(body) => Some(Request::from_parts(replay.req_parts.clone(), body)),
			None => {
				warn!(
					backend = backend.id.as_str(),
					attempt, "streaming body already consumed; cannot retry"
				);
				None
			}
		},
	};
}

// Run one attempt end to end: select+gate a backend, rebuild the request, forward it, interpret the result.
pub async fn run_attempt(ctx: &RequestCtx<'_>, attempt: u32, remaining: Duration, replay: &mut ReplayBody, retry: &mut RetryState) -> AttemptOutcome {
	let selected: Selected = match select_and_gate(ctx, attempt, retry) {
		Ok(s) => s,
		Err(Skip::Break) => return AttemptOutcome::Break,
		Err(Skip::Continue) => return AttemptOutcome::Continue,
	};
	let retry_req: Request<Body> = match build_retry_req(replay, &selected.backend, attempt) {
		Some(r) => r,
		None => return AttemptOutcome::Break,
	};
	info!(backend = selected.backend.id.as_str(), attempt, "forwarding request");
	let result: Result<Response<Body>> = forward_request(
		retry_req,
		&selected.backend,
		ctx.state,
		remaining,
		ctx.client_identity.as_ref(),
		ctx.client_ip,
	)
	.await;
	// Pass only the request parts (not the whole ReplayBody, whose streaming `Body` is !Sync) so the
	// forward-handling future stays Send across its awaits.
	return handle_response(ctx, attempt, selected, result, &replay.req_parts, retry).await;
}

// A transport-level forward failure: record it, then retry with backoff or return 502 on the final attempt.
async fn handle_forward_error(
	ctx: &RequestCtx<'_>,
	attempt: u32,
	backend: &BackendConfig,
	sel_label: KeyValue,
	e: ReductionError,
	retry: &mut RetryState,
) -> AttemptOutcome {
	// F1/F2: a transport miss on a wakeable backend is a cold start, not a failure. Park the request
	// for a wake (F1) rather than counting a breaker failure (F2), so it releases the moment the woken
	// backend is reachable — one round trip, no client retry. Every other error counts.
	if backend.wakeable && e.is_transport_miss() {
		return park_for_wake(ctx, backend).await;
	}
	ctx.state.circuit_breakers.record_failure(backend.id.as_str());
	ctx.state.metrics.retry_attempts.add(
		1,
		&[sel_label, KeyValue::new("attempt", i64::from(attempt + 1)), KeyValue::new("outcome", "error")],
	);
	if attempt + 1 < ctx.max_attempts {
		warn!(backend = backend.id.as_str(), attempt, error = %e, "forward failed, will retry");
		mark_failed(&mut retry.failed_backends, backend.id);
		tokio::time::sleep(backoff_delay(attempt, &ctx.state.retry_config)).await;
		retry.last_error_msg = Some(format!("{e}"));
		return AttemptOutcome::Continue;
	}
	error!(backend = backend.id.as_str(), error = %e, "failed to forward request after all attempts");
	record_completion(ctx.state, ctx.start, StatusCode::BAD_GATEWAY, ctx.backend_id.as_str());
	return AttemptOutcome::Return(error_response(StatusCode::BAD_GATEWAY, "backend error"));
}

// F1: park a request to a cold `wakeable` backend until the backend is reachable or the wake deadline
// passes. It dispatches a `Wake` to the control plane (so Moist starts the backend), then waits for
// readiness — a tunnel backend by its session registering, a direct backend by its address accepting
// a connection. On readiness it retries (`Continue` → the next attempt forwards — one round trip); on
// timeout it returns `503` + `Retry-After` (not `502`: the backend is starting, not broken).
async fn park_for_wake(ctx: &RequestCtx<'_>, backend: &BackendConfig) -> AttemptOutcome {
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

// Wait for the woken backend to become reachable, or — with a control channel — for a refusal to
// abort the park first (returning false so the caller 503s at once instead of at the deadline).
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

// Whether the woken backend is reachable before `deadline`: a direct backend by its address accepting
// a connection, a tunnel backend by its session registering.
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

// Interpret a forward result: a transport error or retryable status retries (or returns on the final attempt);
// a cacheable success is stored and returned buffered; any other success streams with its guards moved into the body.
async fn handle_response(
	ctx: &RequestCtx<'_>,
	attempt: u32,
	selected: Selected,
	result: Result<Response<Body>>,
	req_parts: &Parts,
	retry: &mut RetryState,
) -> AttemptOutcome {
	let Selected { backend, sel_label, conn, half_open } = selected;

	let response: Response<Body> = match result {
		Ok(response) => response,
		Err(e) => return handle_forward_error(ctx, attempt, &backend, sel_label, e, retry).await,
	};

	let status: StatusCode = response.status();
	if is_retryable_status(status) {
		ctx.state.circuit_breakers.record_failure(backend.id.as_str());
		ctx.state.metrics.retry_attempts.add(
			1,
			&[
				sel_label,
				KeyValue::new("attempt", i64::from(attempt + 1)),
				KeyValue::new("outcome", "retryable_status"),
			],
		);
		if attempt + 1 < ctx.max_attempts {
			warn!(
				backend = backend.id.as_str(),
				attempt,
				status = status.as_u16(),
				"retryable status, will retry"
			);
			mark_failed(&mut retry.failed_backends, backend.id);
			tokio::time::sleep(backoff_delay(attempt, &ctx.state.retry_config)).await;
			retry.last_response = Some(response);
			return AttemptOutcome::Continue;
		}
		// Final attempt — fall through and return this response.
	}

	if status.is_server_error() {
		ctx.state.circuit_breakers.record_failure(backend.id.as_str());
	} else {
		ctx.state.circuit_breakers.record_success(backend.id.as_str());
	}

	let cache_directives: CacheDirectives = CacheDirectives::from_response(&response);
	if should_cache_response(ctx, &response, status, &cache_directives) {
		return store_and_respond(ctx, response, status, &cache_directives, req_parts).await;
	}

	record_completion(ctx.state, ctx.start, status, ctx.backend_id.as_str());
	let response: Response<Body> = maybe_compress(response, ctx.accepts_zstd, &cache_directives, &ctx.state.compression_config);
	// Winning attempt: hand the per-attempt guards back so the caller bundles them with the
	// request-level guards into the streaming body.
	return AttemptOutcome::Stream { response, conn, half_open };
}

// Whether a forward-success response may be stored in the shared cache. A backend-encoded body is keyed
// without an encoding dimension (its Content-Encoding is the backend's — the proxy adds zstd only after
// this store site), so an encoded body is refused rather than replayed to a client that never asked for it.
fn should_cache_response(ctx: &RequestCtx<'_>, response: &Response<Body>, status: StatusCode, directives: &CacheDirectives) -> bool {
	return ctx.state.cache_config.enabled
		&& ctx.is_cacheable_method
		&& is_cacheable_status(status)
		&& !response_is_encoded(response)
		&& vary_permits_caching(response.headers())
		&& response_permits_shared_caching(ctx.request_has_cookie, directives);
}

// Buffer a cacheable response, store it under the request's cache key, and return it (compressed if the
// client accepts zstd). A failure to buffer the body surfaces as a 502 rather than a corrupt cache entry.
async fn store_and_respond(
	ctx: &RequestCtx<'_>,
	response: Response<Body>,
	status: StatusCode,
	directives: &CacheDirectives,
	req_parts: &Parts,
) -> AttemptOutcome {
	let (parts, body) = response.into_parts();
	let body_bytes: Bytes = match body.collect().await {
		Ok(collected) => collected.to_bytes(),
		Err(e) => {
			warn!(error = %e, "failed to buffer response for caching");
			record_completion(ctx.state, ctx.start, status, ctx.backend_id.as_str());
			return AttemptOutcome::Return(error_response(StatusCode::BAD_GATEWAY, "failed to read response"));
		}
	};

	// Method and path for the cache key are read from the still-live request parts and borrowed as &str.
	// The path expression matches the get site so a put stores under the exact key a later get looks up.
	let cache_path: &str = req_parts
		.uri
		.path_and_query()
		.map(|pq| pq.as_str())
		.unwrap_or(req_parts.uri.path());
	let key: CacheKeyRef<'_> = CacheKeyRef {
		method: req_parts.method.as_str(),
		path: cache_path,
		identity: ctx.cache_identity,
	};
	ctx.state
		.response_cache
		.put(key, status, &parts.headers, body_bytes.clone(), directives);

	let response: Response<Body> = Response::from_parts(parts, Body::from(body_bytes));
	record_completion(ctx.state, ctx.start, status, ctx.backend_id.as_str());
	return AttemptOutcome::Return(maybe_compress(response, ctx.accepts_zstd, directives, &ctx.state.compression_config));
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;
	use std::net::{IpAddr, Ipv4Addr, SocketAddr};

	use super::TokioInstant;
	use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
	use std::pin::Pin;
	use std::sync::Arc;
	use std::task::{Context, Poll};

	use arrayvec::{ArrayString, ArrayVec};
	use axum::body::Body;
	use axum::http::request::Parts;
	use axum::http::{Request, Response, StatusCode};
	use bytes::Bytes;
	use http_body::{Body as HttpBody, Frame};
	use http_body_util::BodyExt;

	use super::{
		AttemptOutcome, ConnPermitGuard, Duration, Instant, KeyValue, ReplayBody, RequestCtx, RetryState, Selected,
		Skip, backend_label, build_retry_req, handle_forward_error, handle_response, run_attempt, select_and_gate,
		should_cache_response, store_and_respond, wake_timeout_response,
	};
	use crate::acl::AccessControl;
	use crate::balancer::BackendPool;
	use crate::cache::CacheKeyRef;
	use crate::cache_control::CacheDirectives;
	use crate::circuit::CircuitState;
	use crate::config::{
		BackendConfig, CacheConfig, CircuitBreakerConfig, RetryConfig, TimeoutConfig, TransportKind,
	};
	use crate::error::ReductionError;
	use crate::proxy::handler::{ProxyState, ReloadableState, TestProxyStateParams};
	use crate::proxy::router::Router;
	use crate::tunnel::revocation::RevocationSet;

	// An arbitrary loopback address for backends and clients; nothing ever connects to it because these
	// tests stop short of the network forward, so the port need not be reachable.
	const TEST_ADDR: &str = "127.0.0.1:9";
	// Fast, jitter-free retry so the backoff sleeps in the retry paths cost ~1ms, not the production 200ms.
	const FAST_BASE_DELAY_MS: u64 = 1;

	fn install_crypto() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
	}

	// A ClientConfig with an empty trust store — never used for a handshake here, only stored in ProxyState.
	fn client_config() -> Arc<rustls::ClientConfig> {
		return Arc::new(
			rustls::ClientConfig::builder()
				.with_root_certificates(rustls::RootCertStore::empty())
				.with_no_client_auth(),
		);
	}

	fn fast_retry() -> RetryConfig {
		return RetryConfig {
			max_retries: 2,
			base_delay_ms: FAST_BASE_DELAY_MS,
			max_delay_ms: FAST_BASE_DELAY_MS,
			jitter_ms: 0,
		};
	}

	// A circuit breaker that opens on the first failure and stays open (long recovery), so `check` is
	// forced to Open synchronously by a single record_failure.
	fn cb_opens_immediately() -> CircuitBreakerConfig {
		return CircuitBreakerConfig {
			failure_threshold: NonZeroU32::new(1).unwrap(),
			recovery_timeout_secs: 60,
			half_open_max_requests: NonZeroU32::new(1).unwrap(),
		};
	}

	// Opens on the first failure but with a zero recovery window, so the very next `check` transitions to
	// half-open without any real elapsed time.
	fn cb_half_opens_immediately() -> CircuitBreakerConfig {
		return CircuitBreakerConfig {
			failure_threshold: NonZeroU32::new(1).unwrap(),
			recovery_timeout_secs: 0,
			half_open_max_requests: NonZeroU32::new(1).unwrap(),
		};
	}

	fn cache_off() -> CacheConfig {
		return CacheConfig {
			enabled: false,
			..CacheConfig::default()
		};
	}

	fn cache_on() -> CacheConfig {
		return CacheConfig {
			enabled: true,
			max_entries: NonZeroUsize::new(100).unwrap(),
			max_entry_bytes: NonZeroUsize::new(1024 * 1024).unwrap(),
			default_ttl_secs: NonZeroU64::new(300).unwrap(),
		};
	}

	fn make_state(cb: CircuitBreakerConfig, retry: RetryConfig, cache: CacheConfig) -> Arc<ProxyState> {
		install_crypto();
		let reloadable: ReloadableState = ReloadableState {
			router: Router::new(&[]),
			backend_pools: HashMap::new(),
			acl: AccessControl::new(vec![], vec![]),
		};
		return ProxyState::for_test(TestProxyStateParams {
			circuit_breaker_config: cb,
			retry_config: retry,
			cache_config: cache,
			..TestProxyStateParams::new(reloadable, RevocationSet::default(), client_config(), TimeoutConfig::default())
		});
	}

	fn make_backend(id: &str) -> BackendConfig {
		return BackendConfig::new(id, TEST_ADDR.parse().unwrap(), 1.0, TransportKind::Tcp).unwrap();
	}

	fn make_backend_capped(id: &str, max_connections: u32) -> BackendConfig {
		return make_backend(id).with_max_connections(max_connections).unwrap();
	}

	// Owns the borrowed-by-RequestCtx locals so a test can hand out a fresh ctx without lifetime juggling.
	struct Fixture {
		state: Arc<ProxyState>,
		pool: BackendPool,
		cache_identity: String,
	}

	impl Fixture {
		fn new(state: Arc<ProxyState>, backends: Vec<BackendConfig>) -> Self {
			return Self {
				state,
				pool: BackendPool::new(backends).unwrap(),
				cache_identity: String::new(),
			};
		}

		fn ctx(&self, max_attempts: u32, is_cacheable_method: bool, request_has_cookie: bool, accepts_zstd: bool) -> RequestCtx<'_> {
			return RequestCtx {
				state: &self.state,
				pool: &self.pool,
				client_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
				client_identity: None,
				backend_id: ArrayString::from("svc").unwrap(),
				cache_identity: &self.cache_identity,
				start: Instant::now(),
				max_attempts,
				is_cacheable_method,
				request_has_cookie,
				accepts_zstd,
			};
		}
	}

	fn empty_retry() -> RetryState {
		return RetryState {
			failed_backends: ArrayVec::new(),
			last_response: None,
			last_error_msg: None,
		};
	}

	// Build a Selected with a real connection permit, mirroring select_and_gate's own construction, so
	// handle_response can be driven without a live network selection.
	fn make_selected(state: &Arc<ProxyState>, backend: BackendConfig) -> Selected {
		let sel_label: KeyValue = backend_label(&state.labels, &backend.id);
		let permit = state.conn_pool.try_acquire_conn_permit(&backend).unwrap();
		let conn: ConnPermitGuard = ConnPermitGuard {
			counter: state.metrics.backend_active_connections.clone(),
			backend_kv: sel_label.clone(),
			_permit: permit,
		};
		return Selected { backend, sel_label, conn, half_open: None };
	}

	fn parts_for(method: &str, uri: &str) -> Parts {
		let req: Request<Body> = Request::builder().method(method).uri(uri).body(Body::empty()).unwrap();
		return req.into_parts().0;
	}

	fn response_with(status: StatusCode, cache_control: Option<&str>, body: &str) -> Response<Body> {
		let mut builder = Response::builder().status(status);
		if let Some(cc) = cache_control {
			builder = builder.header("cache-control", cc);
		}
		return builder.body(Body::from(body.to_owned())).unwrap();
	}

	// A response body that fails on the first frame poll, so store_and_respond's `collect().await` errors.
	struct ErrBody;

	impl HttpBody for ErrBody {
		type Data = Bytes;
		type Error = std::io::Error;

		fn poll_frame(
			self: Pin<&mut Self>,
			_cx: &mut Context<'_>,
		) -> Poll<Option<std::result::Result<Frame<Bytes>, std::io::Error>>> {
			return Poll::Ready(Some(Err(std::io::Error::other("boom"))));
		}
	}

	// --- build_retry_req -------------------------------------------------------------------------

	#[test]
	fn build_retry_req_clones_buffered_body_and_leaves_it_reusable() {
		let backend: BackendConfig = make_backend("b1");
		let mut replay: ReplayBody = ReplayBody {
			body_bytes: Some(Bytes::from_static(b"payload")),
			streaming_body: None,
			req_parts: parts_for("GET", "/x"),
		};

		let first: Option<Request<Body>> = build_retry_req(&mut replay, &backend, 0);
		let second: Option<Request<Body>> = build_retry_req(&mut replay, &backend, 1);

		// A buffered body clones, so both attempts get a request and the buffer survives.
		assert!(first.is_some());
		assert!(second.is_some(), "a buffered body must be replayable across attempts");
		assert!(replay.body_bytes.is_some());
	}

	#[test]
	fn build_retry_req_consumes_streaming_body_once_then_refuses() {
		let backend: BackendConfig = make_backend("b1");
		let mut replay: ReplayBody = ReplayBody {
			body_bytes: None,
			streaming_body: Some(Body::from("streamed")),
			req_parts: parts_for("POST", "/x"),
		};

		let first: Option<Request<Body>> = build_retry_req(&mut replay, &backend, 0);
		let second: Option<Request<Body>> = build_retry_req(&mut replay, &backend, 1);

		assert!(first.is_some(), "the first attempt takes the one-shot streaming body");
		assert!(second.is_none(), "a consumed streaming body cannot be replayed");
		assert!(replay.streaming_body.is_none());
	}

	#[test]
	fn build_retry_req_none_when_no_body_available() {
		let backend: BackendConfig = make_backend("b1");
		let mut replay: ReplayBody = ReplayBody {
			body_bytes: None,
			streaming_body: None,
			req_parts: parts_for("GET", "/x"),
		};

		assert!(build_retry_req(&mut replay, &backend, 0).is_none());
	}

	// --- select_and_gate -------------------------------------------------------------------------

	#[test]
	fn select_and_gate_breaks_when_no_backend_available() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let fx: Fixture = Fixture::new(state, vec![]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let mut retry: RetryState = empty_retry();

		let outcome = select_and_gate(&ctx, 0, &mut retry);

		assert!(matches!(outcome, Err(Skip::Break)), "an empty pool must Break the retry loop");
		assert!(retry.last_error_msg.is_some(), "the no-backend error is recorded for the final response");
	}

	#[test]
	fn select_and_gate_returns_selected_for_healthy_closed_backend() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let mut retry: RetryState = empty_retry();

		let outcome = select_and_gate(&ctx, 0, &mut retry);

		match outcome {
			Ok(selected) => {
				assert_eq!(selected.backend.id.as_str(), "b1");
				assert!(selected.half_open.is_none(), "a closed circuit carries no half-open probe");
			}
			_ => panic!("a healthy closed backend must be selected"),
		}
	}

	#[test]
	fn select_and_gate_breaks_when_only_backend_fully_pressured() {
		// Holding the only permit drives the backend's connection pressure to 1.0, which the balancer
		// scores as ineligible (weight 0) — so selection returns nothing and the loop Breaks. This is
		// the deterministic single-threaded outcome; the connection-limit `Continue` branch (the
		// try_acquire_conn_permit Err arm) is only reachable when a permit is taken between selection and
		// acquire, a TOCTOU race exercised concurrently by the `h2_pool_caps_and_evicts_dead_connections`
		// integration test, not here.
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let backend: BackendConfig = make_backend_capped("b1", 1);
		let _held = state.conn_pool.try_acquire_conn_permit(&backend).unwrap();
		let fx: Fixture = Fixture::new(state, vec![backend]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let mut retry: RetryState = empty_retry();

		let outcome = select_and_gate(&ctx, 0, &mut retry);

		assert!(matches!(outcome, Err(Skip::Break)), "a fully-pressured sole backend leaves nothing to select");
	}

	#[test]
	fn select_and_gate_continues_when_circuit_open() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		// Trip the breaker for b1 so check() reports Open.
		state.circuit_breakers.record_failure("b1");
		assert_eq!(state.circuit_breakers.state("b1"), CircuitState::Open, "precondition: breaker is open");
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let mut retry: RetryState = empty_retry();

		let outcome = select_and_gate(&ctx, 0, &mut retry);

		assert!(matches!(outcome, Err(Skip::Continue)), "an open circuit must Continue past the backend");
		assert!(retry.failed_backends.iter().any(|id| id.as_str() == "b1"));
	}

	#[test]
	fn select_and_gate_probes_half_open_backend() {
		let state: Arc<ProxyState> = make_state(cb_half_opens_immediately(), fast_retry(), cache_off());
		// Open the breaker; with a zero recovery window the next check transitions to half-open.
		state.circuit_breakers.record_failure("b1");
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let mut retry: RetryState = empty_retry();

		let outcome = select_and_gate(&ctx, 0, &mut retry);

		match outcome {
			Ok(selected) => assert!(selected.half_open.is_some(), "a half-open probe carries its guard"),
			_ => panic!("a half-open backend must be selected as a probe"),
		}
	}

	// --- should_cache_response -------------------------------------------------------------------

	#[test]
	fn should_cache_response_true_for_public_ok_get() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_on());
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let resp: Response<Body> = response_with(StatusCode::OK, Some("public, max-age=300"), "ok");
		let directives: CacheDirectives = CacheDirectives::from_response(&resp);

		assert!(should_cache_response(&ctx, &resp, StatusCode::OK, &directives));
	}

	#[test]
	fn should_cache_response_false_when_cache_disabled() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let resp: Response<Body> = response_with(StatusCode::OK, Some("public"), "ok");
		let directives: CacheDirectives = CacheDirectives::from_response(&resp);

		assert!(!should_cache_response(&ctx, &resp, StatusCode::OK, &directives), "disabled cache never stores");
	}

	#[test]
	fn should_cache_response_false_for_non_cacheable_method() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_on());
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, false, false, false);
		let resp: Response<Body> = response_with(StatusCode::OK, Some("public"), "ok");
		let directives: CacheDirectives = CacheDirectives::from_response(&resp);

		assert!(!should_cache_response(&ctx, &resp, StatusCode::OK, &directives));
	}

	#[test]
	fn should_cache_response_false_for_non_ok_status() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_on());
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let resp: Response<Body> = response_with(StatusCode::NO_CONTENT, Some("public"), "");
		let directives: CacheDirectives = CacheDirectives::from_response(&resp);

		assert!(!should_cache_response(&ctx, &resp, StatusCode::NO_CONTENT, &directives));
	}

	#[test]
	fn should_cache_response_false_for_encoded_body() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_on());
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let resp: Response<Body> = Response::builder()
			.status(StatusCode::OK)
			.header("cache-control", "public")
			.header("content-encoding", "gzip")
			.body(Body::from("x"))
			.unwrap();
		let directives: CacheDirectives = CacheDirectives::from_response(&resp);

		assert!(!should_cache_response(&ctx, &resp, StatusCode::OK, &directives), "a backend-encoded body is never shared-cached");
	}

	#[test]
	fn should_cache_response_false_when_request_has_cookie() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_on());
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, true, false);
		let resp: Response<Body> = response_with(StatusCode::OK, Some("public"), "ok");
		let directives: CacheDirectives = CacheDirectives::from_response(&resp);

		assert!(!should_cache_response(&ctx, &resp, StatusCode::OK, &directives), "a cookie-bearing request never caches");
	}

	// --- store_and_respond -----------------------------------------------------------------------

	#[tokio::test]
	async fn store_and_respond_populates_cache_and_returns_body() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_on());
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let resp: Response<Body> = response_with(StatusCode::OK, Some("public, max-age=300"), "cached-body");
		let directives: CacheDirectives = CacheDirectives::from_response(&resp);
		let parts: Parts = parts_for("GET", "/foo");

		let outcome: AttemptOutcome = store_and_respond(&ctx, resp, StatusCode::OK, &directives, &parts).await;

		match outcome {
			AttemptOutcome::Return(response) => {
				assert_eq!(response.status(), StatusCode::OK);
				let bytes: Bytes = response.into_body().collect().await.unwrap().to_bytes();
				assert_eq!(&bytes[..], b"cached-body", "the returned body is the stored body");
			}
			_ => panic!("a cacheable success must Return a buffered response"),
		}

		// The entry must be retrievable under the exact key store_and_respond wrote.
		let key: CacheKeyRef<'_> = CacheKeyRef { method: "GET", path: "/foo", identity: "" };
		assert!(fx.state.response_cache.get(key).is_some(), "the response must be stored in the cache");
	}

	#[tokio::test]
	async fn store_and_respond_returns_502_when_body_unreadable() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_on());
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let resp: Response<Body> = Response::builder()
			.status(StatusCode::OK)
			.header("cache-control", "public")
			.body(Body::new(ErrBody))
			.unwrap();
		let directives: CacheDirectives = CacheDirectives::from_response(&resp);
		let parts: Parts = parts_for("GET", "/foo");

		let outcome: AttemptOutcome = store_and_respond(&ctx, resp, StatusCode::OK, &directives, &parts).await;

		match outcome {
			AttemptOutcome::Return(response) => assert_eq!(response.status(), StatusCode::BAD_GATEWAY),
			_ => panic!("an unreadable body must surface as a 502, not a corrupt cache entry"),
		}
		let key: CacheKeyRef<'_> = CacheKeyRef { method: "GET", path: "/foo", identity: "" };
		assert!(fx.state.response_cache.get(key).is_none(), "a failed buffer must not leave a cache entry");
	}

	// --- handle_response -------------------------------------------------------------------------

	#[tokio::test]
	async fn handle_response_forward_error_retries_before_final_attempt() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let fx: Fixture = Fixture::new(state.clone(), vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let selected: Selected = make_selected(&state, make_backend("b1"));
		let parts: Parts = parts_for("GET", "/x");
		let mut retry: RetryState = empty_retry();

		let outcome: AttemptOutcome =
			handle_response(&ctx, 0, selected, Err(ReductionError::BackendUnavailable), &parts, &mut retry).await;

		assert!(matches!(outcome, AttemptOutcome::Continue), "a non-final forward error retries");
		assert!(retry.failed_backends.iter().any(|id| id.as_str() == "b1"));
		assert!(retry.last_error_msg.is_some());
	}

	#[tokio::test]
	async fn handle_response_forward_error_returns_502_on_final_attempt() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let fx: Fixture = Fixture::new(state.clone(), vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(1, true, false, false);
		let selected: Selected = make_selected(&state, make_backend("b1"));
		let parts: Parts = parts_for("GET", "/x");
		let mut retry: RetryState = empty_retry();

		let outcome: AttemptOutcome =
			handle_response(&ctx, 0, selected, Err(ReductionError::BackendUnavailable), &parts, &mut retry).await;

		match outcome {
			AttemptOutcome::Return(response) => assert_eq!(response.status(), StatusCode::BAD_GATEWAY),
			_ => panic!("the final forward error must Return a 502"),
		}
	}

	#[tokio::test]
	async fn handle_response_retryable_status_retries_before_final_attempt() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let fx: Fixture = Fixture::new(state.clone(), vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let selected: Selected = make_selected(&state, make_backend("b1"));
		let resp: Response<Body> = response_with(StatusCode::SERVICE_UNAVAILABLE, None, "down");
		let parts: Parts = parts_for("GET", "/x");
		let mut retry: RetryState = empty_retry();

		let outcome: AttemptOutcome = handle_response(&ctx, 0, selected, Ok(resp), &parts, &mut retry).await;

		assert!(matches!(outcome, AttemptOutcome::Continue), "a retryable 503 before the final attempt retries");
		match retry.last_response {
			Some(r) => assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE, "the 503 is captured for budget exhaustion"),
			None => panic!("the retryable response must be captured"),
		}
	}

	#[tokio::test]
	async fn handle_response_retryable_status_streams_on_final_attempt() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let fx: Fixture = Fixture::new(state.clone(), vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(1, true, false, false);
		let selected: Selected = make_selected(&state, make_backend("b1"));
		let resp: Response<Body> = response_with(StatusCode::SERVICE_UNAVAILABLE, None, "down");
		let parts: Parts = parts_for("GET", "/x");
		let mut retry: RetryState = empty_retry();

		let outcome: AttemptOutcome = handle_response(&ctx, 0, selected, Ok(resp), &parts, &mut retry).await;

		match outcome {
			AttemptOutcome::Stream { response, .. } => assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE),
			_ => panic!("the final retryable attempt streams its response back"),
		}
	}

	#[tokio::test]
	async fn handle_response_success_streams_and_records_circuit_success() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let fx: Fixture = Fixture::new(state.clone(), vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let selected: Selected = make_selected(&state, make_backend("b1"));
		let resp: Response<Body> = response_with(StatusCode::OK, None, "hello");
		let parts: Parts = parts_for("GET", "/x");
		let mut retry: RetryState = empty_retry();

		let outcome: AttemptOutcome = handle_response(&ctx, 0, selected, Ok(resp), &parts, &mut retry).await;

		match outcome {
			AttemptOutcome::Stream { response, .. } => assert_eq!(response.status(), StatusCode::OK),
			_ => panic!("a non-cacheable success streams"),
		}
		assert_eq!(state.circuit_breakers.state("b1"), CircuitState::Closed, "a 2xx records success and keeps the circuit closed");
	}

	#[tokio::test]
	async fn handle_response_server_error_streams_and_records_circuit_failure() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let fx: Fixture = Fixture::new(state.clone(), vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let selected: Selected = make_selected(&state, make_backend("b1"));
		// 500 is a server error but not retryable, so it streams back while recording a circuit failure.
		let resp: Response<Body> = response_with(StatusCode::INTERNAL_SERVER_ERROR, None, "boom");
		let parts: Parts = parts_for("GET", "/x");
		let mut retry: RetryState = empty_retry();

		let outcome: AttemptOutcome = handle_response(&ctx, 0, selected, Ok(resp), &parts, &mut retry).await;

		match outcome {
			AttemptOutcome::Stream { response, .. } => assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR),
			_ => panic!("a non-retryable 500 streams back"),
		}
		assert_eq!(state.circuit_breakers.state("b1"), CircuitState::Open, "a 5xx records a failure, tripping the one-shot breaker");
	}

	// A `wakeable` backend whose address currently accepts connections (a live stand-in for a woken
	// service), so `park_for_wake`'s reachability probe releases at once.
	fn wakeable_backend_at(id: &str, addr: SocketAddr) -> BackendConfig {
		return BackendConfig::new(id, addr, 1.0, TransportKind::Tcp).unwrap().with_wakeable(true);
	}

	// F1/F2 `with`: a transport miss (the real cold-start error — connect refused → `Forward`) on a
	// wakeable backend PARKS. With the backend reachable the park releases (`Continue`) and the breaker
	// stays closed — the woken service is routable, uncharged.
	#[tokio::test]
	async fn wakeable_transport_miss_parks_and_releases_when_reachable() {
		let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let addr: SocketAddr = listener.local_addr().unwrap();
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let backend: BackendConfig = wakeable_backend_at("b1", addr);
		let fx: Fixture = Fixture::new(state.clone(), vec![backend.clone()]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let sel: KeyValue = backend_label(&state.labels, &backend.id);
		let mut retry: RetryState = empty_retry();

		let outcome = handle_forward_error(&ctx, 0, &backend, sel, ReductionError::Forward("connect refused".to_owned()), &mut retry).await;

		assert!(matches!(outcome, AttemptOutcome::Continue), "a reachable woken backend releases the park to retry");
		assert_eq!(state.circuit_breakers.state("b1"), CircuitState::Closed, "a wakeable cold miss must not trip the breaker (F2)");
	}

	// F1/F2 `without`: the same `Forward` miss on a NON-wakeable backend is a real failure — it records
	// against the breaker (and never parks).
	#[tokio::test]
	async fn non_wakeable_transport_miss_opens_the_breaker() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let backend: BackendConfig = make_backend("b1"); // wakeable = false → Phase 1 behavior
		let fx: Fixture = Fixture::new(state.clone(), vec![backend.clone()]);
		let ctx: RequestCtx<'_> = fx.ctx(1, true, false, false);
		let sel: KeyValue = backend_label(&state.labels, &backend.id);
		let mut retry: RetryState = empty_retry();

		let _ = handle_forward_error(&ctx, 0, &backend, sel, ReductionError::Forward("connect refused".to_owned()), &mut retry).await;

		assert_eq!(state.circuit_breakers.state("b1"), CircuitState::Open, "without the flag, a cold miss trips the breaker");
	}

	// The park's reachability probe: a live address releases at once; a dead one times out at the deadline.
	#[tokio::test]
	async fn wait_for_reachable_tcp_true_when_listening_false_on_timeout() {
		let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let live: SocketAddr = listener.local_addr().unwrap();
		let soon: TokioInstant = TokioInstant::now() + Duration::from_secs(5);
		assert!(super::wait_for_reachable_tcp(live, soon).await, "a listening address is reachable");

		let dead: std::net::TcpListener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let dead_addr: SocketAddr = dead.local_addr().unwrap();
		drop(dead);
		let deadline: TokioInstant = TokioInstant::now() + Duration::from_millis(150);
		assert!(!super::wait_for_reachable_tcp(dead_addr, deadline).await, "a dead address times out to false");
	}

	// F1: a wake that never completes is a 503 + Retry-After (backend starting), not a 502 (broken).
	#[test]
	fn wake_timeout_response_is_503_with_retry_after() {
		let response = wake_timeout_response(30);
		assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
		assert_eq!(response.headers().get("Retry-After").and_then(|v| v.to_str().ok()), Some("30"));
	}

	#[tokio::test]
	async fn handle_response_cacheable_success_returns_and_caches() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_on());
		let fx: Fixture = Fixture::new(state.clone(), vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let selected: Selected = make_selected(&state, make_backend("b1"));
		let resp: Response<Body> = response_with(StatusCode::OK, Some("public, max-age=300"), "cacheme");
		let parts: Parts = parts_for("GET", "/foo");
		let mut retry: RetryState = empty_retry();

		let outcome: AttemptOutcome = handle_response(&ctx, 0, selected, Ok(resp), &parts, &mut retry).await;

		assert!(matches!(outcome, AttemptOutcome::Return(_)), "a cacheable success Returns a buffered response");
		let key: CacheKeyRef<'_> = CacheKeyRef { method: "GET", path: "/foo", identity: "" };
		assert!(state.response_cache.get(key).is_some(), "the cacheable success is stored");
	}

	// --- run_attempt -----------------------------------------------------------------------------

	#[tokio::test]
	async fn run_attempt_breaks_when_no_backend() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let fx: Fixture = Fixture::new(state, vec![]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let mut replay: ReplayBody = ReplayBody {
			body_bytes: Some(Bytes::from_static(b"x")),
			streaming_body: None,
			req_parts: parts_for("GET", "/x"),
		};
		let mut retry: RetryState = empty_retry();

		let outcome: AttemptOutcome =
			run_attempt(&ctx, 0, Duration::from_secs(5), &mut replay, &mut retry).await;

		assert!(matches!(outcome, AttemptOutcome::Break), "no backend Breaks the loop before any forward");
	}

	#[tokio::test]
	async fn run_attempt_continues_when_circuit_open() {
		// An open circuit gates the backend, so run_attempt Continues to the next attempt without ever
		// forwarding — the deterministic path through select_and_gate's Skip::Continue.
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		state.circuit_breakers.record_failure("b1");
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let mut replay: ReplayBody = ReplayBody {
			body_bytes: Some(Bytes::from_static(b"x")),
			streaming_body: None,
			req_parts: parts_for("GET", "/x"),
		};
		let mut retry: RetryState = empty_retry();

		let outcome: AttemptOutcome =
			run_attempt(&ctx, 0, Duration::from_secs(5), &mut replay, &mut retry).await;

		assert!(matches!(outcome, AttemptOutcome::Continue), "a gated backend Continues without forwarding");
	}

	#[tokio::test]
	async fn run_attempt_breaks_when_streaming_body_already_consumed() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		// Backend selectable and gated open, but no body to replay -> build_retry_req returns None -> Break.
		let mut replay: ReplayBody = ReplayBody {
			body_bytes: None,
			streaming_body: None,
			req_parts: parts_for("GET", "/x"),
		};
		let mut retry: RetryState = empty_retry();

		let outcome: AttemptOutcome =
			run_attempt(&ctx, 0, Duration::from_secs(5), &mut replay, &mut retry).await;

		assert!(matches!(outcome, AttemptOutcome::Break), "an unreplayable body Breaks before forwarding");
	}
}

// A shutdown rejection (503, ready to return), or the request-entry timestamp and the connection's
// proven client IP / mTLS identity for the pipeline downstream.
