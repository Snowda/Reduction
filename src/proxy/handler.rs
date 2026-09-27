use std::collections::HashMap;
use std::net::IpAddr;
use std::slice::from_ref;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arrayvec::{ArrayString, ArrayVec};
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, COOKIE, HOST, RANGE, VARY};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::Method;
use hyper::body::Incoming;
use opentelemetry::{KeyValue, StringValue, global};
use tokio::sync::{OwnedSemaphorePermit, watch};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::acl::AccessControl;
use crate::balancer::{BackendPool, MAX_BACKENDS, RequestQueue};
use crate::cache::{CacheKeyRef, ResponseCache};
use crate::cache_control::CacheDirectives;
use crate::circuit::{CircuitBreakers, CircuitState, HalfOpenGuard};
#[cfg(any(test, feature = "integration_tests"))]
use crate::config::CircuitBreakerConfig;
use crate::config::{
	BackendConfig, CacheConfig, ClientAuthPolicy, CompressionConfig, ProxyConfig, RetryConfig, TimeoutConfig,
};
use crate::error::{ReductionError, Result};
use crate::health::HealthState;
use crate::metrics::{ActiveConnectionGuard, ProxyMetrics};
use crate::proxy::compress_body::CompressedBody;
use crate::proxy::guarded_body::GuardedBody;
use crate::proxy::pool::{ConnPool, HttpSender};
use crate::proxy::router::{RouteMatch, Router};
use crate::ratelimit::RateLimit;
use crate::tls::{PeerIdentity, SPKI_HEX_LEN};
use crate::transport::ConnectAddr;
use crate::tunnel::revocation::RevocationSet;
use crate::{compression, retry};

// Header rewriting (identity/forwarded injection, hop-by-hop stripping) lives in a submodule.
mod headers;
// The per-attempt retry loop (select → gate → forward → interpret) lives in a submodule.
mod attempt;
// Request-body preparation for replay (decompress, buffer, cap checks) lives in a submodule.
mod body;

// Caching/compression and retry-policy decision helpers live in a submodule.
mod policy;
// Response-cache lookup and per-request cache negotiation live in a submodule.
mod cache;
// Shared proxy state (hot-swappable ReloadableState, the per-request ProxyState) lives in a submodule.
mod state;
// Backend selection, metric-label interning, and route resolution live in a submodule.
mod selection;

use attempt::{AttemptOutcome, ReplayBody, RequestCtx, RetryState, run_attempt};
use cache::{CacheDecision, CacheNegotiation, negotiate_cache};
use body::{PreparedBody, compress_response, prepare_replay_body};
use headers::{HeaderExtractor, HeaderInjector, apply_forwarded_headers, apply_identity_headers, strip_hop_by_hop_headers};
use policy::{
	backoff_delay, is_cacheable_status, is_retryable_status, maybe_compress, response_is_encoded,
	response_permits_shared_caching, retries_permitted, vary_permits_caching,
};
use selection::{
	ResolvedRoute, backend_label, completion_backend_label, mark_failed, resolve_backend_pool, select_backend_excluding,
};
pub use state::{ProxyState, ReloadableState};
#[cfg(any(test, feature = "integration_tests"))]
pub use state::TestProxyStateParams;

// Retry-After value (seconds) advertised to clients while the proxy is draining for shutdown.
const SHUTDOWN_RETRY_AFTER_SECS: &str = "5";

// mTLS peer identity headers injected per request (backends authorize the device); trustworthy only on a private path, client values stripped.
const HEADER_CLIENT_ID: &str = "x-reduction-client-id";
const HEADER_CLIENT_SPKI: &str = "x-reduction-client-spki";

// Client-IP forwarding headers, set (not appended) from the proven peer address; client chains are stripped (mTLS edge).
const HEADER_X_FORWARDED_FOR: &str = "x-forwarded-for";
const HEADER_X_REAL_IP: &str = "x-real-ip";


// Client opt-in to retry a non-idempotent request: a non-empty value asserts the backend deduplicates replays (Idempotency-Key).
const HEADER_IDEMPOTENCY_KEY: &str = "idempotency-key";

// Metric attribute on requests_rejected distinguishing why a request was refused before forwarding.
const REJECT_REASON_KEY: &str = "reason";
const REJECT_REASON_REVOKED: &str = "revoked";
const REJECT_REASON_NO_IDENTITY: &str = "no_identity";

// HTTP status codes treated as transient, so the request is safe to retry against another backend.
// Seconds-to-milliseconds conversion factor for latency metrics.
const SECS_TO_MILLIS: f64 = 1000.0;
const STATUS_TOO_MANY_REQUESTS: u16 = 429;
const STATUS_BAD_GATEWAY: u16 = 502;
const STATUS_SERVICE_UNAVAILABLE: u16 = 503;

#[cold]
fn error_response(status: StatusCode, message: &str) -> Response<Body> {
	// Build without the fallible `Response::builder` so a status code can never produce a panic.
	let mut response: Response<Body> = Response::new(Body::from(String::from(message)));
	*response.status_mut() = status;
	return response;
}

// Pre-routing admission gates (ACL, per-IP rate limit, parseable mTLS identity, revocation): returns the
// rejection response or None. Gated before routing/cache so a denied/unnameable/revoked peer reaches neither
// a backend nor a cache entry (a None identity can't be named, so it's rejected, not forwarded anonymously).
fn reject_before_routing(
	state: &Arc<ProxyState>,
	client_ip: IpAddr,
	client_identity: Option<&PeerIdentity>,
) -> Option<Response<Body>> {
	if state.reloadable.borrow().acl.check(client_ip).is_err() {
		return Some(error_response(StatusCode::FORBIDDEN, "access denied"));
	}
	if state.rate_limiter.check(client_ip).is_err() {
		state.metrics.rate_limit_rejections.add(1, &[]);
		return Some(error_response(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
	}
	// A nameless peer is refused only under mandatory mTLS. In public-browser mode (client_auth =
	// disabled/optional) an anonymous browser is admitted and forwarded with no identity headers — the
	// TLS layer already declined to request or require a client cert, so this gate must match it.
	if client_identity.is_none() && !state.client_auth.allows_anonymous() {
		state
			.metrics
			.requests_rejected
			.add(1, &[KeyValue::new(REJECT_REASON_KEY, REJECT_REASON_NO_IDENTITY)]);
		return Some(error_response(StatusCode::FORBIDDEN, "client identity required"));
	}
	if let Some(identity) = client_identity
		&& state.revocation.borrow().is_revoked(identity)
	{
		state
			.metrics
			.requests_rejected
			.add(1, &[KeyValue::new(REJECT_REASON_KEY, REJECT_REASON_REVOKED)]);
		return Some(error_response(StatusCode::FORBIDDEN, "revoked"));
	}
	return None;
}


// The request entry point: admit, serve from cache, route+queue, prepare the replay body, drive the retry
// loop. Per-attempt guards are created here or handed back by `run_attempt` and moved into the streaming body.
#[tracing::instrument(skip_all, fields(
    http.method = %req.method(),
    http.target = %req.uri().path(),
    http.status_code = tracing::field::Empty,
    proxy.backend = tracing::field::Empty,
))]
pub async fn proxy_handler(State(state): State<Arc<ProxyState>>, req: Request<Body>) -> Response<Body> {
	let (start, client_ip, client_identity): (Instant, IpAddr, Option<PeerIdentity>) = match admit_client(&state, &req) {
		ClientAdmission::Reject(response) => return response,
		ClientAdmission::Proceed { start, client_ip, client_identity } => (start, client_ip, client_identity),
	};

	// Active-connection gauge held for the whole request: drops (−1) when the handler returns on a buffered path,
	// or moves into the response body's guard bundle to drop at true end-of-body. Metrics-owned so the drain loop tracks it.
	let active_conn: ActiveConnectionGuard = state.metrics.connection_guard();

	if let Some(response) = reject_before_routing(&state, client_ip, client_identity.as_ref()) {
		return response;
	}

	let CacheNegotiation {
		is_cacheable_method,
		accepts_zstd,
		request_is_zstd,
		request_has_cookie,
		cache_identity_hex,
	} = match negotiate_cache(&state, &req, client_identity.as_ref()) {
		CacheDecision::Hit(response) => return response,
		CacheDecision::Miss(negotiation) => negotiation,
	};
	// The SPKI hex lives in its stack ArrayString for the whole request; the cache key borrows &str.
	let cache_identity: &str = cache_identity_hex.as_deref().unwrap_or("");

	let RouteInfo {
		backend_id,
		pool,
		request_timeout,
		response_idle_timeout,
		queue_permit,
		queue_guard,
	} = match route_and_admit(&state, req.uri().path(), start) {
		Ok(info) => info,
		Err(response) => return *response,
	};

	// Selection, connection permit, and circuit gating are per-attempt (inside the retry loop below) so a
	// retry re-selects a different healthy member instead of hammering the one that just failed.

	let (mut replay, max_attempts): (ReplayBody, u32) =
		match prepare_replay_body(req, &state, request_is_zstd, &backend_id, start).await {
			PreparedBody::Ready(replay, max_attempts) => (replay, max_attempts),
			PreparedBody::Respond(response) => return response,
		};

	let deadline: Instant = start + request_timeout;
	let connect_budget: Duration = Duration::from_secs(state.timeouts.connect_secs.get());

	let ctx: RequestCtx<'_> = RequestCtx {
		state: &state,
		pool: &pool,
		client_ip,
		client_identity,
		backend_id,
		cache_identity,
		start,
		max_attempts,
		is_cacheable_method,
		request_has_cookie,
		accepts_zstd,
	};
	let mut retry: RetryState = RetryState {
		failed_backends: ArrayVec::new(),
		last_response: None,
		last_error_msg: None,
	};

	for attempt in 0..max_attempts {
		let now: Instant = Instant::now();
		let remaining: Duration = match deadline.checked_duration_since(now) {
			Some(d) if d > connect_budget => d,
			_ => {
				warn!(attempt, "retry budget exhausted");
				break;
			}
		};
		match run_attempt(&ctx, attempt, remaining, &mut replay, &mut retry).await {
			AttemptOutcome::Continue => continue,
			AttemptOutcome::Break => break,
			AttemptOutcome::Return(response) => return response,
			AttemptOutcome::Stream { response, conn, half_open } => {
				// Winning attempt: move every accounting guard into the streaming body so they are held until the body finishes.
				let guards: ResponseGuards = ResponseGuards {
					active_conn,
					queue_depth: queue_guard,
					queue_permit,
					conn: Some(conn),
					half_open,
				};
				return guard_streaming_body(response, guards, response_idle_timeout);
			}
		}
	}

	// Exhausted retries (budget, open circuits, or no untried backend) — return the last retryable response if
	// captured, else 502. Its per-attempt permit/probe already released; the still-live outer guards move into the body.
	if let Some(response) = retry.last_response {
		let status: StatusCode = response.status();
		record_completion(&state, start, status, backend_id.as_str());
		let guards: ResponseGuards = ResponseGuards {
			active_conn,
			queue_depth: queue_guard,
			queue_permit,
			conn: None,
			half_open: None,
		};
		return guard_streaming_body(response, guards, response_idle_timeout);
	}
	let msg: String = retry.last_error_msg.unwrap_or_else(|| "backend error".into());
	error!(backend = backend_id.as_str(), error = %msg, "all retry attempts exhausted");
	record_completion(&state, start, StatusCode::BAD_GATEWAY, backend_id.as_str());
	return error_response(StatusCode::BAD_GATEWAY, "backend error");
}

// Immutable per-request context threaded through the retry loop, built once so each helper takes one borrow instead of a dozen args.
enum ClientAdmission {
	Reject(Response<Body>),
	Proceed {
		start: Instant,
		client_ip: IpAddr,
		client_identity: Option<PeerIdentity>,
	},
}

// Join the caller's W3C trace, capture the request-entry timestamp and the connection's proven client
// identity, and reject immediately with a 503 (Retry-After) when the proxy is draining for shutdown.
fn admit_client(state: &Arc<ProxyState>, req: &Request<Body>) -> ClientAdmission {
	// Join the caller's trace if traceparent is present, otherwise start a new root trace.
	let parent_cx = global::get_text_map_propagator(|propagator| propagator.extract(&HeaderExtractor(req.headers())));
	let _ = tracing::Span::current().set_parent(parent_cx);

	let start: Instant = Instant::now();

	let connect_addr: Option<ConnectAddr> = req.extensions().get::<ConnectInfo<ConnectAddr>>().map(|ci| ci.0);
	let client_ip: IpAddr = connect_addr
		.map(|ca| ca.0.ip())
		.unwrap_or_else(|| IpAddr::from([127, 0, 0, 1]));
	// Handshake-proven mTLS identity for this connection; propagated to the backend as headers.
	let client_identity: Option<PeerIdentity> = connect_addr.and_then(|ca| ca.1);

	if state.shutdown.is_cancelled() {
		let mut response: Response<Body> = error_response(StatusCode::SERVICE_UNAVAILABLE, "server is shutting down");
		response
			.headers_mut()
			.insert("Retry-After", HeaderValue::from_static(SHUTDOWN_RETRY_AFTER_SECS));
		return ClientAdmission::Reject(response);
	}

	return ClientAdmission::Proceed { start, client_ip, client_identity };
}


// The resolved route plus the request-level admission guards. Returned by `route_and_admit` so the
// prologue's routing and queue-admission branches live in one place instead of inline in the handler.
struct RouteInfo {
	backend_id: ArrayString<256>,
	pool: BackendPool,
	request_timeout: Duration,
	response_idle_timeout: Duration,
	queue_permit: OwnedSemaphorePermit,
	queue_guard: QueueDepthGuard,
}

// Resolve the path to a backend pool and take its queue-admission permit. `Err` is a ready early response
// (404/503), boxed so the common Ok path stays small; both error paths record completion first.
fn route_and_admit(state: &Arc<ProxyState>, path: &str, start: Instant) -> std::result::Result<RouteInfo, Box<Response<Body>>> {
	let resolved: ResolvedRoute = match resolve_backend_pool(&state.reloadable, path) {
		Ok(result) => result,
		Err(response) => {
			record_completion(state, start, StatusCode::NOT_FOUND, "");
			return Err(Box::new(response));
		}
	};
	let backend_id: ArrayString<256> = resolved.backend_id;
	let pool: BackendPool = resolved.pool;
	let request_timeout: Duration =
		Duration::from_secs(resolved.timeout_secs.unwrap_or(state.timeouts.request_secs.get()));
	// Idle timeout for the streaming response body: the request_timeout above only bounds time-to-
	// headers, so this is what keeps a stalled body from holding the guards indefinitely.
	let response_idle_timeout: Duration = Duration::from_secs(state.timeouts.response_idle_secs.get());

	// Interned label for the resolved route/pool id; consumed by the queue-depth guard below.
	let route_label: KeyValue = backend_label(&state.labels, &backend_id);

	let queue_depth: u32 = state.default_queue_depth;
	let queue: Arc<RequestQueue> = state
		.queues
		.entry(backend_id)
		.or_insert_with(|| Arc::new(RequestQueue::new(queue_depth)))
		.clone();

	// Owned permit so it can be moved into the response body and released at true end-of-body, not at
	// handler return; a streaming body that outlived a borrowed permit would defeat the connection cap.
	let queue_permit: OwnedSemaphorePermit = match queue.try_acquire_owned() {
		Ok(guard) => guard,
		Err(e) => {
			error!(backend = backend_id.as_str(), error = %e, "queue full");
			record_completion(state, start, StatusCode::SERVICE_UNAVAILABLE, backend_id.as_str());
			return Err(Box::new(error_response(StatusCode::SERVICE_UNAVAILABLE, &format!("{e}"))));
		}
	};
	// Gauge is now live for the whole request; the guard drops it when the response body ends (or on an
	// early-return exit path).
	let queue_guard: QueueDepthGuard = QueueDepthGuard::new(state.metrics.queue_depth.clone(), route_label);

	return Ok(RouteInfo {
		backend_id,
		pool,
		request_timeout,
		response_idle_timeout,
		queue_permit,
		queue_guard,
	});
}

// Either the replay body + retry-attempt count, or a ready-to-return early response. An enum rather
// than `Result<_, Response>` because a `Response<Body>` Err variant is large (`result_large_err`).
struct ConnPermitGuard {
	counter: opentelemetry::metrics::UpDownCounter<i64>,
	backend_kv: KeyValue,
	_permit: OwnedSemaphorePermit,
}

impl Drop for ConnPermitGuard {
	fn drop(&mut self) {
		self.counter.add(-1, from_ref(&self.backend_kv));
	}
}

// RAII guard for the queue-depth gauge: +1 on construction, −1 on drop, so no early-return path can leak the gauge.
struct QueueDepthGuard {
	counter: opentelemetry::metrics::UpDownCounter<i64>,
	backend_kv: KeyValue,
}

impl QueueDepthGuard {
	fn new(counter: opentelemetry::metrics::UpDownCounter<i64>, backend_kv: KeyValue) -> Self {
		counter.add(1, from_ref(&backend_kv));
		return Self { counter, backend_kv };
	}
}

impl Drop for QueueDepthGuard {
	fn drop(&mut self) {
		self.counter.add(-1, from_ref(&self.backend_kv));
	}
}

// Per-request accounting (conn gauge, queue gauge+slot, connection permit, half-open probe) bundled so a
// streaming body owns them and releases each at true end-of-body. Fields exist only to be dropped (RAII).
#[allow(dead_code)]
struct ResponseGuards {
	active_conn: ActiveConnectionGuard,
	queue_depth: QueueDepthGuard,
	queue_permit: OwnedSemaphorePermit,
	conn: Option<ConnPermitGuard>,
	half_open: Option<HalfOpenGuard>,
}

// Wrap a streaming response body so it owns `guards` (released only at body end) and aborts if the backend
// stalls past `idle_timeout` between frames. Applied after compression so the guards cover the whole pipeline.
fn guard_streaming_body(response: Response<Body>, guards: ResponseGuards, idle_timeout: Duration) -> Response<Body> {
	let (parts, body) = response.into_parts();
	let guarded: GuardedBody<Body, ResponseGuards> = GuardedBody::new(body, guards, idle_timeout);
	return Response::from_parts(parts, Body::new(guarded));
}

fn record_completion(state: &ProxyState, start: Instant, status: StatusCode, backend_str: &str) {
	let duration_ms: f64 = start.elapsed().as_secs_f64() * SECS_TO_MILLIS;
	let attrs: [KeyValue; 2] = [
		KeyValue::new("status", i64::from(status.as_u16())),
		completion_backend_label(&state.labels, backend_str),
	];
	state.metrics.requests_total.add(1, &attrs);
	state.metrics.request_duration_ms.record(duration_ms, &attrs);
	// Active-connection gauge is decremented by ActiveConnGuard on handler return, not here.

	// Populate deferred span fields for OTel trace export
	let span = tracing::Span::current();
	span.record("http.status_code", status.as_u16());
	span.record("proxy.backend", backend_str);
}

// Execute one outbound attempt against `backend`: acquire a pooled connection, rewrite headers (host,
// forwarded, identity, trace injection), send, and cap the response body at the configured limit.
#[tracing::instrument(skip_all, fields(backend = backend.id.as_str()))]
async fn forward_request(
	req: Request<Body>,
	backend: &BackendConfig,
	state: &Arc<ProxyState>,
	request_timeout: Duration,
	identity: Option<&PeerIdentity>,
	client_ip: IpAddr,
) -> Result<Response<Body>> {
	let connect_timeout: Duration = Duration::from_secs(state.timeouts.connect_secs.get());
	let handshake_timeout: Duration = Duration::from_secs(state.timeouts.handshake_secs.get());
	let mut sender: HttpSender = state
		.conn_pool
		.acquire(
			backend,
			&state.tls_connector,
			&state.client_tls_config,
			connect_timeout,
			handshake_timeout,
		)
		.await?;

	let (mut parts, body) = req.into_parts();
	strip_hop_by_hop_headers(&mut parts.headers);
	parts.headers.insert(
		HOST,
		HeaderValue::from_str(&backend.host)
			.map_err(|e| ReductionError::Forward(format!("invalid host header: {e}")))?,
	);
	apply_forwarded_headers(&mut parts.headers, client_ip)?;
	apply_identity_headers(&mut parts.headers, identity)?;

	// Inject current trace context into outbound headers so the
	// backend can continue the distributed trace.
	global::get_text_map_propagator(|propagator| {
		let cx = tracing::Span::current().context();
		propagator.inject_context(&cx, &mut HeaderInjector(&mut parts.headers));
	});

	let backend_req: Request<Body> = Request::from_parts(parts, body);

	let response: Response<Incoming> = timeout(request_timeout, sender.send_request(backend_req))
		.await
		.map_err(|_| ReductionError::Forward("send request: timed out".into()))?
		.map_err(|e| ReductionError::Forward(format!("send request: {e}")))?;

	// The spawned connection driver owns the stream, so the per-request `sender` can drop here without truncating the in-flight body.
	let (mut parts, incoming_body) = response.into_parts();
	strip_hop_by_hop_headers(&mut parts.headers);
	let limited_body: Limited<Incoming> = Limited::new(
		incoming_body,
		usize::try_from(state.proxy_config.max_response_body_bytes).unwrap_or(usize::MAX),
	);

	return Ok(Response::from_parts(parts, Body::new(limited_body)));
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::config::{RouteConfig, TimeoutConfig, TransportKind};
	use crate::proxy::router::Router;

	#[test]
	fn test_error_response_status_and_body() {
		let resp = error_response(StatusCode::BAD_GATEWAY, "backend error");
		assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
	}

	#[test]
	fn test_error_response_not_found() {
		let resp = error_response(StatusCode::NOT_FOUND, "missing");
		assert_eq!(resp.status(), StatusCode::NOT_FOUND);
	}

	#[test]
	fn test_error_response_too_many_requests() {
		let resp = error_response(StatusCode::TOO_MANY_REQUESTS, "rate limited");
		assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
	}

	#[test]
	fn test_error_response_service_unavailable() {
		let resp = error_response(StatusCode::SERVICE_UNAVAILABLE, "queue full");
		assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
	}

	#[test]
	fn test_is_retryable_status_404_not_retryable() {
		assert!(!is_retryable_status(StatusCode::NOT_FOUND));
	}

	#[test]
	fn test_is_retryable_status_500_not_retryable() {
		// 500 is a definite server error, not transient — we only retry 502/503/429
		assert!(!is_retryable_status(StatusCode::INTERNAL_SERVER_ERROR));
	}

	// --- request-pipeline helpers ----------------------------------------------------------------

	fn install_crypto() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
	}

	fn client_config() -> Arc<rustls::ClientConfig> {
		return Arc::new(
			rustls::ClientConfig::builder()
				.with_root_certificates(rustls::RootCertStore::empty())
				.with_no_client_auth(),
		);
	}

	fn build_state(reloadable: ReloadableState, revocation: RevocationSet) -> Arc<ProxyState> {
		install_crypto();
		return ProxyState::for_test(TestProxyStateParams::new(
			reloadable,
			revocation,
			client_config(),
			TimeoutConfig::default(),
		));
	}

	fn build_state_with_policy(
		reloadable: ReloadableState,
		revocation: RevocationSet,
		client_auth: ClientAuthPolicy,
	) -> Arc<ProxyState> {
		install_crypto();
		return ProxyState::for_test(TestProxyStateParams {
			client_auth,
			..TestProxyStateParams::new(reloadable, revocation, client_config(), TimeoutConfig::default())
		});
	}

	fn permissive_reloadable() -> ReloadableState {
		return ReloadableState {
			router: Router::new(&[]),
			backend_pools: HashMap::new(),
			acl: AccessControl::new(vec![], vec![]),
		};
	}

	fn deny_reloadable(cidr: &str) -> ReloadableState {
		return ReloadableState {
			router: Router::new(&[]),
			backend_pools: HashMap::new(),
			acl: AccessControl::new(vec![], vec![cidr.parse().unwrap()]),
		};
	}

	fn routed_reloadable() -> ReloadableState {
		let backend: BackendConfig =
			BackendConfig::new("api", "127.0.0.1:8080".parse().unwrap(), 1.0, TransportKind::Tcp).unwrap();
		let route: RouteConfig = RouteConfig {
			path_prefix: ArrayString::from("/api").unwrap(),
			backend_id: ArrayString::from("api").unwrap(),
			timeout_secs: None,
		};
		let mut pools: HashMap<ArrayString<256>, BackendPool> = HashMap::new();
		pools.insert(ArrayString::from("api").unwrap(), BackendPool::new(vec![backend]).unwrap());
		return ReloadableState {
			router: Router::new(&[route]),
			backend_pools: pools,
			acl: AccessControl::new(vec![], vec![]),
		};
	}

	// A PeerIdentity from its public fields; `byte` fills the SPKI so spki_hex() is deterministic and distinct.
	fn identity_with_spki(byte: u8) -> PeerIdentity {
		return PeerIdentity {
			common_name: ArrayString::from("dev").unwrap(),
			spki_sha256: [byte; 32],
		};
	}

	// --- reject_before_routing -------------------------------------------------------------------

	#[test]
	fn reject_before_routing_denies_acl_blocked_ip() {
		let state: Arc<ProxyState> = build_state(deny_reloadable("10.0.0.0/8"), RevocationSet::default());
		let ip: IpAddr = "10.0.0.1".parse().unwrap();
		let id: PeerIdentity = identity_with_spki(1);

		let rejection: Option<Response<Body>> = reject_before_routing(&state, ip, Some(&id));

		match rejection {
			Some(response) => assert_eq!(response.status(), StatusCode::FORBIDDEN),
			None => panic!("an ACL-blocked IP must be rejected"),
		}
	}

	#[test]
	fn reject_before_routing_rejects_missing_identity() {
		let state: Arc<ProxyState> = build_state(permissive_reloadable(), RevocationSet::default());
		let ip: IpAddr = "10.0.0.1".parse().unwrap();

		let rejection: Option<Response<Body>> = reject_before_routing(&state, ip, None);

		match rejection {
			Some(response) => assert_eq!(response.status(), StatusCode::FORBIDDEN, "an unnameable peer is refused"),
			None => panic!("a request with no identity must be rejected"),
		}
	}

	#[test]
	fn reject_before_routing_admits_anonymous_under_disabled_policy() {
		// Public-browser mode: a request with no mTLS identity must be admitted (None returned), the
		// application-layer inverse of the TLS layer no longer requesting a client cert. Contrast with
		// reject_before_routing_rejects_missing_identity, which uses the default Required policy.
		let state: Arc<ProxyState> =
			build_state_with_policy(permissive_reloadable(), RevocationSet::default(), ClientAuthPolicy::Disabled);
		let ip: IpAddr = "10.0.0.1".parse().unwrap();

		let rejection: Option<Response<Body>> = reject_before_routing(&state, ip, None);
		assert!(rejection.is_none(), "an anonymous request must be admitted under the disabled policy");
	}

	#[test]
	fn reject_before_routing_admits_anonymous_under_optional_policy() {
		let state: Arc<ProxyState> =
			build_state_with_policy(permissive_reloadable(), RevocationSet::default(), ClientAuthPolicy::Optional);
		let ip: IpAddr = "10.0.0.1".parse().unwrap();

		let rejection: Option<Response<Body>> = reject_before_routing(&state, ip, None);
		assert!(rejection.is_none(), "an anonymous request must be admitted under the optional policy");
	}

	#[test]
	fn reject_before_routing_still_revokes_named_peer_under_disabled_policy() {
		// Even in public-browser mode a PRESENTED-and-revoked identity is still refused: disabling
		// mandatory auth relaxes the nameless-peer gate only, not revocation of an authenticated one.
		let id: PeerIdentity = identity_with_spki(9);
		let toml: String = format!("[[revoked]]\nspki = \"{}\"\nreason = \"clone\"\n", id.spki_hex());
		let revocation: RevocationSet = RevocationSet::parse(&toml).unwrap();
		let state: Arc<ProxyState> =
			build_state_with_policy(permissive_reloadable(), revocation, ClientAuthPolicy::Disabled);
		let ip: IpAddr = "10.0.0.1".parse().unwrap();

		let rejection: Option<Response<Body>> = reject_before_routing(&state, ip, Some(&id));
		match rejection {
			Some(response) => assert_eq!(response.status(), StatusCode::FORBIDDEN, "a revoked named peer is still refused"),
			None => panic!("a revoked identity must be rejected even under the disabled policy"),
		}
	}

	#[test]
	fn reject_before_routing_rejects_revoked_identity() {
		let id: PeerIdentity = identity_with_spki(2);
		let toml: String = format!("[[revoked]]\nspki = \"{}\"\nreason = \"clone\"\n", id.spki_hex());
		let revocation: RevocationSet = RevocationSet::parse(&toml).unwrap();
		let state: Arc<ProxyState> = build_state(permissive_reloadable(), revocation);
		let ip: IpAddr = "10.0.0.1".parse().unwrap();

		let rejection: Option<Response<Body>> = reject_before_routing(&state, ip, Some(&id));

		match rejection {
			Some(response) => assert_eq!(response.status(), StatusCode::FORBIDDEN),
			None => panic!("a revoked identity must be rejected"),
		}
	}

	#[test]
	fn reject_before_routing_admits_allowed_named_unrevoked_peer() {
		let state: Arc<ProxyState> = build_state(permissive_reloadable(), RevocationSet::default());
		let ip: IpAddr = "10.0.0.1".parse().unwrap();
		let id: PeerIdentity = identity_with_spki(3);

		assert!(reject_before_routing(&state, ip, Some(&id)).is_none(), "a clean peer passes admission");
	}

	// --- admit_client ----------------------------------------------------------------------------

	#[test]
	fn admit_client_rejects_while_shutting_down() {
		let state: Arc<ProxyState> = build_state(permissive_reloadable(), RevocationSet::default());
		state.shutdown.cancel();
		let req: Request<Body> = Request::builder().uri("/x").body(Body::empty()).unwrap();

		match admit_client(&state, &req) {
			ClientAdmission::Reject(response) => {
				assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
				assert!(response.headers().contains_key("Retry-After"), "a draining server sets Retry-After");
			}
			ClientAdmission::Proceed { .. } => panic!("a shutting-down server must reject"),
		}
	}

	#[test]
	fn admit_client_extracts_ip_and_identity_from_connect_info() {
		let state: Arc<ProxyState> = build_state(permissive_reloadable(), RevocationSet::default());
		let mut req: Request<Body> = Request::builder().uri("/x").body(Body::empty()).unwrap();
		req.extensions_mut()
			.insert(ConnectInfo(ConnectAddr("198.51.100.7:40000".parse().unwrap(), Some(identity_with_spki(4)))));

		match admit_client(&state, &req) {
			ClientAdmission::Proceed { client_ip, client_identity, .. } => {
				assert_eq!(client_ip, "198.51.100.7".parse::<IpAddr>().unwrap());
				assert!(client_identity.is_some(), "the handshake identity is carried through");
			}
			ClientAdmission::Reject(_) => panic!("a normal request must proceed"),
		}
	}

	#[test]
	fn admit_client_defaults_ip_when_connect_info_absent() {
		let state: Arc<ProxyState> = build_state(permissive_reloadable(), RevocationSet::default());
		let req: Request<Body> = Request::builder().uri("/x").body(Body::empty()).unwrap();

		match admit_client(&state, &req) {
			ClientAdmission::Proceed { client_ip, client_identity, .. } => {
				assert_eq!(client_ip, IpAddr::from([127, 0, 0, 1]), "a missing ConnectInfo falls back to loopback");
				assert!(client_identity.is_none());
			}
			ClientAdmission::Reject(_) => panic!("no ConnectInfo is not itself a rejection here"),
		}
	}

	// --- route_and_admit -------------------------------------------------------------------------

	#[test]
	fn route_and_admit_errors_404_for_unrouted_path() {
		let state: Arc<ProxyState> = build_state(permissive_reloadable(), RevocationSet::default());

		let result = route_and_admit(&state, "/nowhere", Instant::now());

		match result {
			Err(response) => assert_eq!(response.status(), StatusCode::NOT_FOUND),
			Ok(_) => panic!("an unrouted path must 404"),
		}
	}

	#[test]
	fn route_and_admit_resolves_route_and_takes_queue_permit() {
		let state: Arc<ProxyState> = build_state(routed_reloadable(), RevocationSet::default());

		let result = route_and_admit(&state, "/api/thing", Instant::now());

		match result {
			Ok(info) => {
				assert_eq!(info.backend_id.as_str(), "api");
				assert_eq!(info.pool.backends.len(), 1);
			}
			Err(_) => panic!("a routed path must resolve"),
		}
	}

	#[test]
	fn route_and_admit_errors_503_when_queue_full() {
		let state: Arc<ProxyState> = build_state(routed_reloadable(), RevocationSet::default());
		// Pre-install a depth-1 queue for the route and hold its only permit, so admission finds it full.
		let queue: Arc<RequestQueue> = Arc::new(RequestQueue::new(1));
		state.queues.insert(ArrayString::from("api").unwrap(), queue.clone());
		let _held: OwnedSemaphorePermit = queue.try_acquire_owned().unwrap();

		let result = route_and_admit(&state, "/api/thing", Instant::now());

		match result {
			Err(response) => assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE),
			Ok(_) => panic!("a full queue must reject with 503"),
		}
	}

	// --- record_completion & guard_streaming_body ------------------------------------------------

	#[test]
	fn record_completion_runs_for_named_and_empty_backend() {
		let state: Arc<ProxyState> = build_state(permissive_reloadable(), RevocationSet::default());
		// Both label paths (interned id and the empty "" reject path) must record without panicking.
		record_completion(&state, Instant::now(), StatusCode::OK, "api");
		record_completion(&state, Instant::now(), StatusCode::BAD_GATEWAY, "");
	}

	#[tokio::test]
	async fn guard_streaming_body_preserves_response_and_body() {
		let state: Arc<ProxyState> = build_state(permissive_reloadable(), RevocationSet::default());
		let queue: RequestQueue = RequestQueue::new(1);
		let permit: OwnedSemaphorePermit = queue.try_acquire_owned().unwrap();
		let label: KeyValue = backend_label(&state.labels, &ArrayString::from("api").unwrap());
		let guards: ResponseGuards = ResponseGuards {
			active_conn: state.metrics.connection_guard(),
			queue_depth: QueueDepthGuard::new(state.metrics.queue_depth.clone(), label),
			queue_permit: permit,
			conn: None,
			half_open: None,
		};
		let response: Response<Body> = Response::builder().status(StatusCode::OK).body(Body::from("streamed")).unwrap();

		let guarded: Response<Body> = guard_streaming_body(response, guards, Duration::from_secs(30));

		assert_eq!(guarded.status(), StatusCode::OK);
		let bytes: Bytes = guarded.into_body().collect().await.unwrap().to_bytes();
		assert_eq!(&bytes[..], b"streamed", "the guarded body streams through unchanged");
	}
}
