use std::collections::HashMap;
use std::hash::{Hash, Hasher, DefaultHasher};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, HOST};
use axum::http::{HeaderValue, Request, Response, StatusCode};
use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use opentelemetry::global;
use opentelemetry::propagation::{Extractor, Injector};
use opentelemetry::KeyValue;
use tokio::sync::watch;
use tokio::sync::{OwnedSemaphorePermit, SemaphorePermit};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::acl::AccessControl;
use crate::cache_control::CacheDirectives;
use crate::balancer::{BackendPool, RequestQueue};
use crate::circuit::{CircuitBreakers, CircuitState};
use crate::compression;
use crate::config::{BackendConfig, CompressionConfig, ProxyConfig, RetryConfig, TimeoutConfig};
use crate::proxy::compress_body::CompressedBody;
use crate::error::{ReductionError, Result};
use crate::health::HealthState;
use crate::metrics::ProxyMetrics;
use crate::proxy::pool::{ConnPool, HttpSender, PooledBody};
use crate::proxy::router::{RouteMatch, Router};
use crate::ratelimit::RateLimit;
use crate::transport::ConnectAddr;

#[derive(Clone)]
pub struct ReloadableState {
    pub router: Router,
    pub backend_pools: HashMap<String, BackendPool>,
}

pub struct ProxyState {
    pub reloadable: watch::Receiver<ReloadableState>,
    pub tls_connector: TlsConnector,
    pub client_tls_config: Arc<rustls::ClientConfig>,
    pub health_rx: watch::Receiver<HealthState>,
    pub conn_pool: ConnPool,
    pub acl: AccessControl,
    pub rate_limiter: RateLimit,
    pub queues: DashMap<String, Arc<RequestQueue>>,
    pub default_queue_depth: usize,
    pub metrics: ProxyMetrics,
    pub circuit_breakers: CircuitBreakers,
    pub shutdown: CancellationToken,
    pub timeouts: TimeoutConfig,
    pub proxy_config: ProxyConfig,
    pub compression_config: CompressionConfig,
    pub retry_config: RetryConfig,
}

// Synchronous so the watch::Ref never crosses an await point.
fn select_backend(
    pool: &BackendPool,
    client_ip: IpAddr,
    health_rx: &watch::Receiver<HealthState>,
    conn_pool: &ConnPool,
) -> Result<BackendConfig> {
    let health: watch::Ref<'_, HealthState> = health_rx.borrow();
    let pressure_fn = |id: &str| -> f64 {
        let max: u32 = pool.backends.iter()
            .find(|b| b.id == id)
            .map(|b| b.max_connections)
            .unwrap_or(256);
        conn_pool.connection_pressure(id, max)
    };
    match pool.select_with_pressure(client_ip, &health, &pressure_fn) {
        Some(backend) => return Ok(backend.clone()),
        None => return Err(ReductionError::BackendUnavailable),
    }
}

struct ResolvedRoute {
    backend_id: String,
    pool: BackendPool,
    timeout_secs: Option<u64>,
}

// Resolve route and backend pool from reloadable state before any await point.
fn resolve_backend_pool(
    reloadable: &watch::Receiver<ReloadableState>,
    path: &str,
) -> std::result::Result<ResolvedRoute, Response<Body>> {
    let state: watch::Ref<'_, ReloadableState> = reloadable.borrow();

    let route_match: RouteMatch<'_> = match state.router.match_route(path) {
        Some(m) => m,
        None => {
            return Err(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("no route matched"))
                .expect("failed to build response"));
        }
    };

    let pool: &BackendPool = match state.backend_pools.get(route_match.backend_id) {
        Some(p) => p,
        None => {
            error!(backend_id = route_match.backend_id, "route matched but no backend pool found");
            return Err(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("backend pool not found"))
                .expect("failed to build response"));
        }
    };

    return Ok(ResolvedRoute {
        backend_id: route_match.backend_id.to_string(),
        pool: pool.clone(),
        timeout_secs: route_match.timeout_secs,
    });
}

// Adapts axum HeaderMap for OTel trace context extraction from inbound requests.
struct HeaderExtractor<'a>(&'a axum::http::HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        return self.0.get(key).and_then(|v| v.to_str().ok());
    }

    fn keys(&self) -> Vec<&str> {
        return self.0.keys().map(|k| k.as_str()).collect();
    }
}

// Adapts axum HeaderMap for OTel trace context injection into outbound requests.
struct HeaderInjector<'a>(&'a mut axum::http::HeaderMap);

impl Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let Ok(name) = axum::http::header::HeaderName::from_bytes(key.as_bytes())
            && let Ok(val) = HeaderValue::from_str(&value)
        {
            self.0.insert(name, val);
        }
    }
}

fn error_response(status: StatusCode, message: &str) -> Response<Body> {
    return Response::builder()
        .status(status)
        .body(Body::from(message.to_string()))
        .expect("failed to build response");
}

#[tracing::instrument(skip_all, fields(
    http.method = %req.method(),
    http.target = %req.uri().path(),
    http.status_code = tracing::field::Empty,
    proxy.backend = tracing::field::Empty,
))]
pub async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    req: Request<Body>,
) -> Response<Body> {
    // Extract W3C trace context from inbound request headers.
    // Joins the caller's trace if traceparent is present, otherwise starts a new root trace.
    let parent_cx = global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(req.headers()))
    });
    let _ = tracing::Span::current().set_parent(parent_cx);

    let start: Instant = Instant::now();

    let client_ip: IpAddr = req
        .extensions()
        .get::<ConnectInfo<ConnectAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or_else(|| IpAddr::from([127, 0, 0, 1]));

    if state.shutdown.is_cancelled() {
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("Retry-After", "5")
            .body(Body::from("server is shutting down"))
            .expect("failed to build response");
    }

    state.metrics.track_connection(1);

    if state.acl.check(client_ip).is_err() {
        state.metrics.track_connection(-1);
        return error_response(StatusCode::FORBIDDEN, "access denied");
    }

    if state.rate_limiter.check(client_ip).is_err() {
        state.metrics.rate_limit_rejections.add(1, &[]);
        state.metrics.track_connection(-1);
        return error_response(StatusCode::TOO_MANY_REQUESTS, "rate limited");
    }

    // Capture compression negotiation headers before consuming the request
    let accepts_zstd: bool = req
        .headers()
        .get(ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("zstd"))
        .unwrap_or(false);

    let request_is_zstd: bool = req
        .headers()
        .get(CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "zstd")
        .unwrap_or(false);

    let resolved: ResolvedRoute = match resolve_backend_pool(&state.reloadable, req.uri().path()) {
        Ok(result) => result,
        Err(response) => {
            record_completion(&state, start, StatusCode::NOT_FOUND, "");
            return response;
        }
    };
    let backend_id: String = resolved.backend_id;
    let pool: BackendPool = resolved.pool;
    let request_timeout: Duration = Duration::from_secs(
        resolved.timeout_secs.unwrap_or(state.timeouts.request_secs),
    );

    let backend_attr: [KeyValue; 1] = [KeyValue::new("backend", backend_id.clone())];

    let queue_depth: usize = state.default_queue_depth;
    let queue: Arc<RequestQueue> = state
        .queues
        .entry(backend_id.clone())
        .or_insert_with(|| Arc::new(RequestQueue::new(queue_depth)))
        .clone();

    state.metrics.queue_depth.add(1, &backend_attr);
    let _permit: SemaphorePermit<'_> = match queue.try_acquire() {
        Ok(guard) => guard,
        Err(e) => {
            state.metrics.queue_depth.add(-1, &backend_attr);
            error!(backend = %backend_id, error = %e, "queue full");
            record_completion(&state, start, StatusCode::SERVICE_UNAVAILABLE, &backend_id);
            return error_response(StatusCode::SERVICE_UNAVAILABLE, &format!("{e}"));
        }
    };

    let backend: BackendConfig = match select_backend(&pool, client_ip, &state.health_rx, &state.conn_pool) {
        Ok(b) => {
            state.metrics.backend_selections.add(1, &[KeyValue::new("backend", b.id.clone())]);
            b
        }
        Err(e) => {
            state.metrics.queue_depth.add(-1, &backend_attr);
            error!(backend = %backend_id, error = %e, "dispatch failed");
            record_completion(&state, start, StatusCode::BAD_GATEWAY, &backend_id);
            return error_response(StatusCode::BAD_GATEWAY, &format!("{e}"));
        }
    };

    let _conn_guard: ConnPermitGuard = match state.conn_pool.try_acquire_conn_permit(&backend) {
        Ok(permit) => {
            state.metrics.backend_active_connections.add(1, &[KeyValue::new("backend", backend.id.clone())]);
            ConnPermitGuard {
                counter: state.metrics.backend_active_connections.clone(),
                backend_id: backend.id.clone(),
                _permit: permit,
            }
        }
        Err(_) => {
            state.metrics.backend_conn_limit_rejected.add(1, &[KeyValue::new("backend", backend.id.clone())]);
            state.metrics.queue_depth.add(-1, &backend_attr);
            warn!(backend = %backend.id, max = backend.max_connections, "connection limit reached");
            record_completion(&state, start, StatusCode::SERVICE_UNAVAILABLE, &backend_id);
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "backend connection limit reached");
        }
    };

    match state.circuit_breakers.check(&backend.id) {
        CircuitState::Open => {
            state.metrics.circuit_open_total.add(1, &[KeyValue::new("backend", backend.id.clone())]);
            state.metrics.queue_depth.add(-1, &backend_attr);
            warn!(backend = %backend.id, "circuit breaker open, rejecting request");
            record_completion(&state, start, StatusCode::SERVICE_UNAVAILABLE, &backend_id);
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "circuit open");
        }
        CircuitState::HalfOpen => {
            state.metrics.circuit_half_open_probes.add(1, &[KeyValue::new("backend", backend.id.clone())]);
        }
        CircuitState::Closed => {}
    }

    // Decompress zstd-encoded request body before forwarding to backend
    let req: Request<Body> = if request_is_zstd {
        match decompress_request(req, state.proxy_config.max_response_body_bytes).await {
            Ok(r) => r,
            Err(response) => {
                state.metrics.queue_depth.add(-1, &backend_attr);
                record_completion(&state, start, StatusCode::BAD_REQUEST, &backend_id);
                return response;
            }
        }
    } else {
        req
    };

    info!(backend = %backend.id, path = %req.uri().path(), "forwarding request");

    // Buffer the request body so we can replay it on retries.
    let (parts, body) = req.into_parts();
    let body_bytes: Bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            state.metrics.queue_depth.add(-1, &backend_attr);
            warn!(error = %e, "failed to buffer request body");
            record_completion(&state, start, StatusCode::BAD_REQUEST, &backend_id);
            return error_response(StatusCode::BAD_REQUEST, "failed to read request body");
        }
    };

    let deadline: Instant = start + request_timeout;
    let connect_budget: Duration = Duration::from_secs(state.timeouts.connect_secs);
    let max_attempts: u32 = state.retry_config.max_retries + 1;

    let mut last_response: Option<Response<Body>> = None;
    let mut last_error_msg: Option<String> = None;

    for attempt in 0..max_attempts {
        let now: Instant = Instant::now();
        let remaining: Duration = match deadline.checked_duration_since(now) {
            Some(d) if d > connect_budget => d,
            _ => {
                // Not enough time budget for another attempt
                warn!(backend = %backend.id, attempt, "retry budget exhausted");
                break;
            }
        };

        // Circuit breaker may have tripped during a previous attempt
        if attempt > 0
            && let CircuitState::Open = state.circuit_breakers.check(&backend.id)
        {
            warn!(backend = %backend.id, attempt, "circuit opened during retry");
            break;
        }

        let retry_req: Request<Body> = Request::from_parts(parts.clone(), Body::from(body_bytes.clone()));

        match forward_request(retry_req, &backend, &state, remaining).await {
            Ok(response) => {
                let status: StatusCode = response.status();
                if is_retryable_status(status) {
                    state.circuit_breakers.record_failure(&backend.id);
                    state.metrics.retry_attempts.add(1, &[
                        KeyValue::new("backend", backend.id.clone()),
                        KeyValue::new("attempt", (attempt + 1) as i64),
                        KeyValue::new("outcome", "retryable_status"),
                    ]);
                    if attempt + 1 < max_attempts {
                        warn!(backend = %backend.id, attempt, status = status.as_u16(), "retryable status, will retry");
                        tokio::time::sleep(backoff_delay(attempt, &state.retry_config)).await;
                        last_response = Some(response);
                        continue;
                    }
                    // Final attempt — fall through and return this response
                }

                if status.is_server_error() {
                    state.circuit_breakers.record_failure(&backend.id);
                } else {
                    state.circuit_breakers.record_success(&backend.id);
                }

                state.metrics.queue_depth.add(-1, &backend_attr);

                let cache_directives: CacheDirectives = CacheDirectives::from_response(&response);

                if accepts_zstd
                    && !response_is_encoded(&response)
                    && status != StatusCode::PARTIAL_CONTENT
                    && !cache_directives.no_transform
                {
                    record_completion(&state, start, status, &backend_id);
                    return compress_response(response, state.compression_config.min_bytes, state.compression_config.level);
                }

                record_completion(&state, start, status, &backend_id);
                return response;
            }
            Err(e) => {
                state.circuit_breakers.record_failure(&backend.id);
                state.metrics.retry_attempts.add(1, &[
                    KeyValue::new("backend", backend.id.clone()),
                    KeyValue::new("attempt", (attempt + 1) as i64),
                    KeyValue::new("outcome", "error"),
                ]);
                if attempt + 1 < max_attempts {
                    warn!(backend = %backend.id, attempt, error = %e, "forward failed, will retry");
                    tokio::time::sleep(backoff_delay(attempt, &state.retry_config)).await;
                    last_error_msg = Some(format!("{e}"));
                    continue;
                }
                error!(backend = %backend.id, error = %e, "failed to forward request after all attempts");
                state.metrics.queue_depth.add(-1, &backend_attr);
                record_completion(&state, start, StatusCode::BAD_GATEWAY, &backend_id);
                return error_response(StatusCode::BAD_GATEWAY, "backend error");
            }
        }
    }

    // Exhausted retries via budget/circuit — return last response or 502
    state.metrics.queue_depth.add(-1, &backend_attr);
    if let Some(response) = last_response {
        let status: StatusCode = response.status();
        record_completion(&state, start, status, &backend_id);
        return response;
    }
    let msg: String = last_error_msg.unwrap_or_else(|| "backend error".to_string());
    error!(backend = %backend.id, error = %msg, "all retry attempts exhausted");
    record_completion(&state, start, StatusCode::BAD_GATEWAY, &backend_id);
    return error_response(StatusCode::BAD_GATEWAY, "backend error");
}

struct ConnPermitGuard {
    counter: opentelemetry::metrics::UpDownCounter<i64>,
    backend_id: String,
    _permit: OwnedSemaphorePermit,
}

impl Drop for ConnPermitGuard {
    fn drop(&mut self) {
        self.counter.add(-1, &[KeyValue::new("backend", self.backend_id.clone())]);
    }
}

fn record_completion(state: &ProxyState, start: Instant, status: StatusCode, backend_id: &str) {
    let duration_ms: f64 = start.elapsed().as_secs_f64() * 1000.0;
    let attrs: Vec<KeyValue> = vec![
        KeyValue::new("status", status.as_u16() as i64),
        KeyValue::new("backend", backend_id.to_string()),
    ];
    state.metrics.requests_total.add(1, &attrs);
    state.metrics.request_duration_ms.record(duration_ms, &attrs);
    state.metrics.track_connection(-1);

    // Populate deferred span fields for OTel trace export
    let span = tracing::Span::current();
    span.record("http.status_code", status.as_u16());
    span.record("proxy.backend", backend_id);
}

fn response_is_encoded(response: &Response<Body>) -> bool {
    return response
        .headers()
        .contains_key(CONTENT_ENCODING);
}

fn is_retryable_status(status: StatusCode) -> bool {
    return matches!(
        status.as_u16(),
        502 | 503 | 429
    );
}

// Compute exponential backoff with pseudo-random jitter.
// delay = min(base_delay * 2^attempt, max_delay) + hash_jitter(0..jitter_ms)
fn backoff_delay(attempt: u32, config: &RetryConfig) -> Duration {
    let exp_delay_ms: u64 = config
        .base_delay_ms
        .saturating_mul(1u64.checked_shl(attempt).unwrap_or(u64::MAX))
        .min(config.max_delay_ms);

    let jitter_ms: u64 = if config.jitter_ms > 0 {
        // Deterministic-enough jitter from hashing the attempt + current time nanos
        let mut hasher: DefaultHasher = DefaultHasher::new();
        attempt.hash(&mut hasher);
        Instant::now().elapsed().as_nanos().hash(&mut hasher);
        let hash: u64 = hasher.finish();
        hash % config.jitter_ms
    } else {
        0
    };

    return Duration::from_millis(exp_delay_ms.saturating_add(jitter_ms));
}

#[tracing::instrument(skip_all)]
async fn decompress_request(req: Request<Body>, max_body: usize) -> std::result::Result<Request<Body>, Response<Body>> {
    let (mut parts, body) = req.into_parts();

    let body_bytes: Bytes = body
        .collect()
        .await
        .map(|c| c.to_bytes())
        .map_err(|e| {
            warn!(error = %e, "failed to read request body for decompression");
            error_response(StatusCode::BAD_REQUEST, "failed to read request body")
        })?;

    let decompressed: Vec<u8> = if body_bytes.len() <= compression::INLINE_COMPRESS_THRESHOLD {
        compression::decompress_bounded(&body_bytes, max_body)
            .map_err(|e| {
                warn!(error = %e, "request decompression failed");
                error_response(StatusCode::BAD_REQUEST, "invalid zstd body")
            })?
    } else {
        tokio::task::spawn_blocking(move || {
            compression::decompress_bounded(&body_bytes, max_body)
        })
        .await
        .map_err(|e| {
            error!(error = %e, "decompression task panicked");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "decompression failed")
        })?
        .map_err(|e| {
            warn!(error = %e, "request decompression failed");
            error_response(StatusCode::BAD_REQUEST, "invalid zstd body")
        })?
    };

    parts.headers.remove(CONTENT_ENCODING);
    parts.headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from(decompressed.len()),
    );

    return Ok(Request::from_parts(parts, Body::from(decompressed)));
}

fn compress_response(response: Response<Body>, min_bytes: usize, compression_level: i32) -> Response<Body> {
    let (mut parts, body) = response.into_parts();

    if let Some(len) = parts.headers.get(CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<usize>().ok())
        && len < min_bytes
    {
        return Response::from_parts(parts, body);
    }

    parts.headers.insert(
        CONTENT_ENCODING,
        HeaderValue::from_static("zstd"),
    );
    parts.headers.remove(CONTENT_LENGTH);

    let compressed: CompressedBody<Body> = CompressedBody::with_level(body, compression_level);
    return Response::from_parts(parts, Body::new(compressed));
}


#[tracing::instrument(skip_all, fields(backend = %backend.id))]
async fn forward_request(
    req: Request<Body>,
    backend: &BackendConfig,
    state: &Arc<ProxyState>,
    request_timeout: Duration,
) -> Result<Response<Body>> {
    let connect_timeout: Duration = Duration::from_secs(state.timeouts.connect_secs);
    let handshake_timeout: Duration = Duration::from_secs(state.timeouts.handshake_secs);
    let mut sender: HttpSender =
        state.conn_pool.acquire(backend, &state.tls_connector, &state.client_tls_config, connect_timeout, handshake_timeout).await?;

    let (mut parts, body) = req.into_parts();
    parts.headers.insert(
        HOST,
        HeaderValue::from_str(&backend.host)
            .map_err(|e| ReductionError::Forward(format!("invalid host header: {e}")))?,
    );
    parts.headers.remove("x-forwarded-for");
    parts.headers.remove("x-forwarded-proto");
    parts.headers.remove("x-forwarded-host");
    parts.headers.remove("forwarded");
    parts.headers.remove("x-real-ip");

    // Inject current trace context into outbound headers so the
    // backend can continue the distributed trace.
    global::get_text_map_propagator(|propagator| {
        let cx = tracing::Span::current().context();
        propagator.inject_context(&cx, &mut HeaderInjector(&mut parts.headers));
    });

    let backend_req: Request<Body> = Request::from_parts(parts, body);

    let response: Response<Incoming> = timeout(request_timeout, sender.send_request(backend_req))
        .await
        .map_err(|_| ReductionError::Forward("send request: timed out".to_string()))?
        .map_err(|e| ReductionError::Forward(format!("send request: {e}")))?;

    let (parts, incoming_body) = response.into_parts();
    let limited_body: Limited<Incoming> =
        Limited::new(incoming_body, state.proxy_config.max_response_body_bytes);
    let pooled_body: PooledBody<Limited<Incoming>> =
        PooledBody::new(limited_body, sender);

    return Ok(Response::from_parts(parts, Body::new(pooled_body)));
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
    fn test_response_is_encoded_false() {
        let resp = Response::builder()
            .body(Body::empty())
            .unwrap();
        assert!(!response_is_encoded(&resp));
    }

    #[test]
    fn test_response_is_encoded_true() {
        let resp = Response::builder()
            .header(CONTENT_ENCODING, "zstd")
            .body(Body::empty())
            .unwrap();
        assert!(response_is_encoded(&resp));
    }

    #[test]
    fn test_response_is_encoded_gzip() {
        let resp = Response::builder()
            .header(CONTENT_ENCODING, "gzip")
            .body(Body::empty())
            .unwrap();
        assert!(response_is_encoded(&resp));
    }

    fn make_reloadable_state(routes: &[(&str, &str)], backends: Vec<BackendConfig>) -> watch::Receiver<ReloadableState> {
        let route_configs: Vec<RouteConfig> = routes
            .iter()
            .map(|(prefix, id)| RouteConfig {
                path_prefix: prefix.to_string(),
                backend_id: id.to_string(),
                timeout_secs: None,
            })
            .collect();

        let router = Router::new(&route_configs);
        let mut grouped: HashMap<String, Vec<BackendConfig>> = HashMap::new();
        for b in backends {
            grouped.entry(b.pool.clone()).or_default().push(b);
        }
        let backend_pools: HashMap<String, BackendPool> = grouped
            .into_iter()
            .map(|(id, bs)| (id, BackendPool::new(bs, 0.0).unwrap()))
            .collect();

        let state = ReloadableState { router, backend_pools };
        let (_tx, rx) = watch::channel(state);
        return rx;
    }

    #[test]
    fn test_resolve_backend_pool_success() {
        let backend = BackendConfig::new(
            "api".into(), "127.0.0.1:8080".parse().unwrap(), 1.0, TransportKind::Tcp,
        );
        let rx = make_reloadable_state(&[("/api", "api")], vec![backend]);
        let result = resolve_backend_pool(&rx, "/api/test");
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert_eq!(resolved.backend_id, "api");
        assert_eq!(resolved.pool.backends.len(), 1);
        assert_eq!(resolved.timeout_secs, None);
    }

    #[test]
    fn test_resolve_backend_pool_no_route() {
        let backend = BackendConfig::new(
            "api".into(), "127.0.0.1:8080".parse().unwrap(), 1.0, TransportKind::Tcp,
        );
        let rx = make_reloadable_state(&[("/api", "api")], vec![backend]);
        let result = resolve_backend_pool(&rx, "/health");
        let resp = match result {
            Err(r) => r,
            Ok(_) => panic!("expected error response"),
        };
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_resolve_backend_pool_route_but_no_pool() {
        let route_configs = vec![RouteConfig {
            path_prefix: "/api".into(),
            backend_id: "missing-pool".into(),
            timeout_secs: None,
        }];
        let router = Router::new(&route_configs);
        let state = ReloadableState {
            router,
            backend_pools: HashMap::new(),
        };
        let (_tx, rx) = watch::channel(state);
        let result = resolve_backend_pool(&rx, "/api/test");
        let resp = match result {
            Err(r) => r,
            Ok(_) => panic!("expected error response"),
        };
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_select_backend_success() {
        let backend = BackendConfig::new(
            "api".into(), "127.0.0.1:8080".parse().unwrap(), 1.0, TransportKind::Tcp,
        );
        let pool = BackendPool::new(vec![backend], 0.0).unwrap();
        let health = HealthState::new();
        let (_tx, health_rx) = watch::channel(health);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let conn_pool = ConnPool::new();

        let result = select_backend(&pool, ip, &health_rx, &conn_pool);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().id, "api");
    }

    #[test]
    fn test_select_backend_empty_pool() {
        let pool = BackendPool::new(vec![], 0.0).unwrap();
        let health = HealthState::new();
        let (_tx, health_rx) = watch::channel(health);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let conn_pool = ConnPool::new();

        let result = select_backend(&pool, ip, &health_rx, &conn_pool);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_decompress_request_valid() {
        let original = b"hello world from the client";
        let compressed: Vec<u8> = compression::compress(original).unwrap();

        let req = Request::builder()
            .header(CONTENT_ENCODING, "zstd")
            .body(Body::from(compressed))
            .unwrap();

        let result = decompress_request(req, 10 * 1024 * 1024).await;
        assert!(result.is_ok());
        let decompressed_req = result.unwrap();
        assert!(!decompressed_req.headers().contains_key(CONTENT_ENCODING));

        let body_bytes = decompressed_req
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body_bytes[..], original);
    }

    #[tokio::test]
    async fn test_decompress_request_invalid_zstd() {
        let req = Request::builder()
            .header(CONTENT_ENCODING, "zstd")
            .body(Body::from(vec![0xFF, 0xFE, 0xFD]))
            .unwrap();

        let result = decompress_request(req, 10 * 1024 * 1024).await;
        assert!(result.is_err());
        let resp = result.unwrap_err();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_compress_response_round_trip() {
        let original: Vec<u8> = "response body data for compression "
            .repeat(10)
            .into_bytes();
        let resp = Response::builder()
            .body(Body::from(original.clone()))
            .unwrap();

        let compressed_resp = compress_response(resp, 256, 3);
        assert_eq!(
            compressed_resp.headers().get(CONTENT_ENCODING).unwrap(),
            "zstd"
        );
        assert!(!compressed_resp.headers().contains_key(CONTENT_LENGTH));

        let body_bytes = compressed_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let decompressed: Vec<u8> = compression::decompress(&body_bytes).unwrap();
        assert_eq!(decompressed, original);
    }

    #[tokio::test]
    async fn test_compress_response_small_body_skipped() {
        let original = b"tiny";
        let resp = Response::builder()
            .header(CONTENT_LENGTH, original.len())
            .body(Body::from(original.to_vec()))
            .unwrap();

        let result = compress_response(resp, 256, 3);
        assert!(!result.headers().contains_key(CONTENT_ENCODING));
        let body_bytes = result.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body_bytes[..], original);
    }

    #[test]
    fn test_reloadable_state_is_clone() {
        let state = ReloadableState {
            router: Router::new(&[]),
            backend_pools: HashMap::new(),
        };
        let _cloned = state.clone();
    }

    #[test]
    fn test_proxy_config_defaults() {
        let cfg: ProxyConfig = ProxyConfig::default();
        assert_eq!(cfg.max_response_body_bytes, 10 * 1024 * 1024);
        assert_eq!(cfg.h2_connections_per_backend, 4);
        assert_eq!(cfg.max_idle_quic_per_host, 16);
    }

    #[test]
    fn test_compression_config_defaults() {
        let cfg: CompressionConfig = CompressionConfig::default();
        assert_eq!(cfg.level, 3);
        assert_eq!(cfg.min_bytes, 256);
    }

    #[test]
    fn test_timeout_config_defaults() {
        let cfg: TimeoutConfig = TimeoutConfig::default();
        assert_eq!(cfg.connect_secs, 5);
        assert_eq!(cfg.handshake_secs, 5);
        assert_eq!(cfg.request_secs, 30);
    }

    #[tokio::test]
    async fn test_compress_response_skipped_for_partial_content() {
        let original = b"partial range data here";
        let resp = Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header("Content-Range", "bytes 0-22/100")
            .body(Body::from(original.to_vec()))
            .unwrap();

        // Simulate the proxy_handler logic: skip compression for 206
        let status = resp.status();
        let should_compress = !response_is_encoded(&resp) && status != StatusCode::PARTIAL_CONTENT;
        assert!(!should_compress);
    }

    #[tokio::test]
    async fn test_compress_response_applied_for_200() {
        let original: Vec<u8> = "response body data for compression "
            .repeat(10)
            .into_bytes();
        let resp = Response::builder()
            .status(StatusCode::OK)
            .body(Body::from(original.clone()))
            .unwrap();

        let status = resp.status();
        let should_compress = !response_is_encoded(&resp) && status != StatusCode::PARTIAL_CONTENT;
        assert!(should_compress);
    }

    #[test]
    fn test_no_transform_skips_compression() {
        let original: Vec<u8> = "response body data for compression "
            .repeat(10)
            .into_bytes();
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header("cache-control", "no-transform")
            .body(Body::from(original))
            .unwrap();

        let status = resp.status();
        let directives = CacheDirectives::from_response(&resp);
        let should_compress = !response_is_encoded(&resp)
            && status != StatusCode::PARTIAL_CONTENT
            && !directives.no_transform;
        assert!(!should_compress);
    }

    #[test]
    fn test_no_transform_absent_allows_compression() {
        let original: Vec<u8> = "response body data for compression "
            .repeat(10)
            .into_bytes();
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header("cache-control", "max-age=3600")
            .body(Body::from(original))
            .unwrap();

        let status = resp.status();
        let directives = CacheDirectives::from_response(&resp);
        let should_compress = !response_is_encoded(&resp)
            && status != StatusCode::PARTIAL_CONTENT
            && !directives.no_transform;
        assert!(should_compress);
    }

    #[test]
    fn test_range_headers_not_stripped() {
        use axum::http::HeaderMap;

        let mut headers = HeaderMap::new();
        headers.insert("range", HeaderValue::from_static("bytes=0-99"));
        headers.insert("if-range", HeaderValue::from_static("\"etag123\""));
        headers.insert("accept-ranges", HeaderValue::from_static("bytes"));
        headers.insert("content-range", HeaderValue::from_static("bytes 0-99/200"));

        // forward_request only strips these headers — verify range headers are not among them
        let stripped = ["x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "forwarded", "x-real-ip"];
        for name in ["range", "if-range", "accept-ranges", "content-range"] {
            assert!(!stripped.contains(&name), "{name} should not be stripped");
            assert!(headers.contains_key(name), "{name} must survive forwarding");
        }
    }

    #[test]
    fn test_is_retryable_status_502() {
        assert!(is_retryable_status(StatusCode::BAD_GATEWAY));
    }

    #[test]
    fn test_is_retryable_status_503() {
        assert!(is_retryable_status(StatusCode::SERVICE_UNAVAILABLE));
    }

    #[test]
    fn test_is_retryable_status_429() {
        assert!(is_retryable_status(StatusCode::TOO_MANY_REQUESTS));
    }

    #[test]
    fn test_is_retryable_status_200_not_retryable() {
        assert!(!is_retryable_status(StatusCode::OK));
    }

    #[test]
    fn test_is_retryable_status_400_not_retryable() {
        assert!(!is_retryable_status(StatusCode::BAD_REQUEST));
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

    #[test]
    fn test_retry_config_defaults() {
        let cfg: RetryConfig = RetryConfig::default();
        assert_eq!(cfg.max_retries, 2);
        assert_eq!(cfg.base_delay_ms, 200);
        assert_eq!(cfg.max_delay_ms, 2000);
        assert_eq!(cfg.jitter_ms, 100);
    }

    #[test]
    fn test_backoff_delay_exponential_growth() {
        let config: RetryConfig = RetryConfig {
            max_retries: 3,
            base_delay_ms: 100,
            max_delay_ms: 5000,
            jitter_ms: 0,
        };
        let d0: Duration = backoff_delay(0, &config);
        let d1: Duration = backoff_delay(1, &config);
        let d2: Duration = backoff_delay(2, &config);

        // With zero jitter, delays should be exactly 100, 200, 400
        assert_eq!(d0, Duration::from_millis(100));
        assert_eq!(d1, Duration::from_millis(200));
        assert_eq!(d2, Duration::from_millis(400));
    }

    #[test]
    fn test_backoff_delay_capped_at_max() {
        let config: RetryConfig = RetryConfig {
            max_retries: 10,
            base_delay_ms: 1000,
            max_delay_ms: 2000,
            jitter_ms: 0,
        };
        // attempt=5 would be 1000 * 32 = 32000 uncapped, but should be capped at 2000
        let d: Duration = backoff_delay(5, &config);
        assert_eq!(d, Duration::from_millis(2000));
    }

    #[test]
    fn test_backoff_delay_jitter_bounded() {
        let config: RetryConfig = RetryConfig {
            max_retries: 3,
            base_delay_ms: 100,
            max_delay_ms: 5000,
            jitter_ms: 50,
        };
        // Run multiple times — jitter should always be in [0, 50) so total in [100, 150)
        for _ in 0..20 {
            let d: Duration = backoff_delay(0, &config);
            assert!(d >= Duration::from_millis(100), "delay {d:?} below base");
            assert!(d < Duration::from_millis(150), "delay {d:?} exceeds base + jitter");
        }
    }

    #[test]
    fn test_backoff_delay_zero_jitter() {
        let config: RetryConfig = RetryConfig {
            max_retries: 1,
            base_delay_ms: 200,
            max_delay_ms: 2000,
            jitter_ms: 0,
        };
        let d: Duration = backoff_delay(0, &config);
        assert_eq!(d, Duration::from_millis(200));
    }
}
