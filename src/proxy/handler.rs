use std::collections::HashMap;
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
use hyper::client::conn::http1;
use opentelemetry::KeyValue;
use tokio::sync::watch;
use tokio::sync::SemaphorePermit;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::{error, info, warn};

use crate::balancer::{BackendPool, RequestQueue};
use crate::compression;
use crate::config::BackendConfig;
use crate::error::{ReductionError, Result};
use crate::health::HealthState;
use crate::metrics::ProxyMetrics;
use crate::proxy::pool::{ConnPool, PooledBody};
use crate::proxy::router::Router;
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
    pub rate_limiter: RateLimit,
    pub queues: DashMap<String, Arc<RequestQueue>>,
    pub default_queue_depth: usize,
    pub metrics: ProxyMetrics,
}

// Synchronous so the watch::Ref never crosses an await point.
fn select_backend(
    pool: &BackendPool,
    client_ip: IpAddr,
    health_rx: &watch::Receiver<HealthState>,
) -> Result<BackendConfig> {
    let health: watch::Ref<'_, HealthState> = health_rx.borrow();
    match pool.select(client_ip, &health) {
        Some(backend) => return Ok(backend.clone()),
        None => return Err(ReductionError::BackendUnavailable),
    }
}

// Resolve route and backend pool from reloadable state before any await point.
fn resolve_backend_pool(
    reloadable: &watch::Receiver<ReloadableState>,
    path: &str,
) -> std::result::Result<(String, BackendPool), Response<Body>> {
    let state: watch::Ref<'_, ReloadableState> = reloadable.borrow();

    let backend_id: &str = match state.router.match_route(path) {
        Some(id) => id,
        None => {
            return Err(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("no route matched"))
                .expect("failed to build response"));
        }
    };

    let pool: &BackendPool = match state.backend_pools.get(backend_id) {
        Some(p) => p,
        None => {
            error!(backend_id, "route matched but no backend pool found");
            return Err(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("backend pool not found"))
                .expect("failed to build response"));
        }
    };

    return Ok((backend_id.to_string(), pool.clone()));
}

fn error_response(status: StatusCode, message: &str) -> Response<Body> {
    return Response::builder()
        .status(status)
        .body(Body::from(message.to_string()))
        .expect("failed to build response");
}

pub async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    req: Request<Body>,
) -> Response<Body> {
    let start: Instant = Instant::now();
    let path: String = req.uri().path().to_string();

    let client_ip: IpAddr = req
        .extensions()
        .get::<ConnectInfo<ConnectAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or_else(|| IpAddr::from([127, 0, 0, 1]));

    state.metrics.active_connections.add(1, &[]);

    if state.rate_limiter.check(client_ip).is_err() {
        state.metrics.rate_limit_rejections.add(1, &[]);
        state.metrics.active_connections.add(-1, &[]);
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

    let (backend_id, pool): (String, BackendPool) = match resolve_backend_pool(&state.reloadable, &path) {
        Ok(result) => result,
        Err(response) => {
            record_completion(&state, start, StatusCode::NOT_FOUND, "");
            return response;
        }
    };

    let queue_depth: usize = state.default_queue_depth;
    let queue: Arc<RequestQueue> = state
        .queues
        .entry(backend_id.clone())
        .or_insert_with(|| Arc::new(RequestQueue::new(queue_depth)))
        .clone();

    state.metrics.queue_depth.add(1, &[KeyValue::new("backend", backend_id.clone())]);
    let _permit: SemaphorePermit<'_> = match queue.try_acquire() {
        Ok(guard) => guard,
        Err(e) => {
            state.metrics.queue_depth.add(-1, &[KeyValue::new("backend", backend_id.clone())]);
            error!(backend_id, error = %e, "queue full");
            record_completion(&state, start, StatusCode::SERVICE_UNAVAILABLE, &backend_id);
            return error_response(StatusCode::SERVICE_UNAVAILABLE, &format!("{e}"));
        }
    };

    let backend: BackendConfig = match select_backend(&pool, client_ip, &state.health_rx) {
        Ok(b) => {
            state.metrics.backend_selections.add(1, &[KeyValue::new("backend", b.id.clone())]);
            b
        }
        Err(e) => {
            state.metrics.queue_depth.add(-1, &[KeyValue::new("backend", backend_id.clone())]);
            error!(backend_id, error = %e, "dispatch failed");
            record_completion(&state, start, StatusCode::BAD_GATEWAY, &backend_id);
            return error_response(StatusCode::BAD_GATEWAY, &format!("{e}"));
        }
    };

    // Decompress zstd-encoded request body before forwarding to backend
    let req: Request<Body> = if request_is_zstd {
        match decompress_request(req).await {
            Ok(r) => r,
            Err(response) => {
                state.metrics.queue_depth.add(-1, &[KeyValue::new("backend", backend_id.clone())]);
                record_completion(&state, start, StatusCode::BAD_REQUEST, &backend_id);
                return response;
            }
        }
    } else {
        req
    };

    info!(backend = %backend.id, path, "forwarding request");

    let response: Response<Body> = match forward_request(req, &backend, &state).await {
        Ok(response) => response,
        Err(e) => {
            state.metrics.queue_depth.add(-1, &[KeyValue::new("backend", backend_id.clone())]);
            error!(backend = %backend.id, error = %e, "failed to forward request");
            record_completion(&state, start, StatusCode::BAD_GATEWAY, &backend_id);
            return error_response(StatusCode::BAD_GATEWAY, "backend error");
        }
    };

    let status: StatusCode = response.status();
    state.metrics.queue_depth.add(-1, &[KeyValue::new("backend", backend_id.clone())]);

    // Compress response if client accepts zstd and response isn't already encoded
    if accepts_zstd && !response_is_encoded(&response) {
        return match compress_response(response).await {
            Ok(r) => {
                record_completion(&state, start, status, &backend_id);
                r
            }
            Err(e) => {
                warn!(error = %e, "response compression failed, returning uncompressed");
                record_completion(&state, start, StatusCode::BAD_GATEWAY, &backend_id);
                error_response(StatusCode::BAD_GATEWAY, "compression error")
            }
        };
    }

    record_completion(&state, start, status, &backend_id);
    return response;
}

fn record_completion(state: &ProxyState, start: Instant, status: StatusCode, backend_id: &str) {
    let duration_ms: f64 = start.elapsed().as_secs_f64() * 1000.0;
    let attrs: Vec<KeyValue> = vec![
        KeyValue::new("status", status.as_u16() as i64),
        KeyValue::new("backend", backend_id.to_string()),
    ];
    state.metrics.requests_total.add(1, &attrs);
    state.metrics.request_duration_ms.record(duration_ms, &attrs);
    state.metrics.active_connections.add(-1, &[]);
}

fn response_is_encoded(response: &Response<Body>) -> bool {
    return response
        .headers()
        .contains_key(CONTENT_ENCODING);
}

async fn decompress_request(req: Request<Body>) -> std::result::Result<Request<Body>, Response<Body>> {
    let (mut parts, body) = req.into_parts();

    let body_bytes: Bytes = body
        .collect()
        .await
        .map(|c| c.to_bytes())
        .map_err(|e| {
            warn!(error = %e, "failed to read request body for decompression");
            error_response(StatusCode::BAD_REQUEST, "failed to read request body")
        })?;

    let decompressed: Vec<u8> =
        compression::decompress_bounded(&body_bytes, MAX_RESPONSE_BODY).map_err(|e| {
            warn!(error = %e, "request decompression failed");
            error_response(StatusCode::BAD_REQUEST, "invalid zstd body")
        })?;

    parts.headers.remove(CONTENT_ENCODING);
    parts.headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from(decompressed.len()),
    );

    return Ok(Request::from_parts(parts, Body::from(decompressed)));
}

async fn compress_response(
    response: Response<Body>,
) -> Result<Response<Body>> {
    let (mut parts, body) = response.into_parts();

    let body_bytes: Bytes = body
        .collect()
        .await
        .map(|c| c.to_bytes())
        .map_err(|e| ReductionError::Forward(format!("read response body: {e}")))?;

    if body_bytes.is_empty() {
        return Ok(Response::from_parts(parts, Body::empty()));
    }

    let compressed: Vec<u8> = compression::compress(&body_bytes)?;

    parts.headers.insert(
        CONTENT_ENCODING,
        HeaderValue::from_static("zstd"),
    );
    parts.headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from(compressed.len()),
    );

    return Ok(Response::from_parts(parts, Body::from(compressed)));
}

pub const MAX_RESPONSE_BODY: usize = 10 * 1024 * 1024;
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);


async fn forward_request(
    req: Request<Body>,
    backend: &BackendConfig,
    state: &Arc<ProxyState>,
) -> Result<Response<Body>> {
    let mut sender: http1::SendRequest<Body> =
        state.conn_pool.acquire(backend, &state.tls_connector, &state.client_tls_config).await?;

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

    let backend_req: Request<Body> = Request::from_parts(parts, body);

    let response: Response<Incoming> = timeout(REQUEST_TIMEOUT, sender.send_request(backend_req))
        .await
        .map_err(|_| ReductionError::Forward("send request: timed out".to_string()))?
        .map_err(|e| ReductionError::Forward(format!("send request: {e}")))?;

    let (parts, incoming_body) = response.into_parts();
    let limited_body: Limited<Incoming> =
        Limited::new(incoming_body, MAX_RESPONSE_BODY);
    let pooled_body: PooledBody<Limited<Incoming>> =
        PooledBody::new(limited_body, Arc::clone(state), backend.address, sender, backend.transport);

    return Ok(Response::from_parts(parts, Body::new(pooled_body)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RouteConfig, TransportKind};
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
        let (id, pool) = result.unwrap();
        assert_eq!(id, "api");
        assert_eq!(pool.backends.len(), 1);
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

        let result = select_backend(&pool, ip, &health_rx);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().id, "api");
    }

    #[test]
    fn test_select_backend_empty_pool() {
        let pool = BackendPool::new(vec![], 0.0).unwrap();
        let health = HealthState::new();
        let (_tx, health_rx) = watch::channel(health);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let result = select_backend(&pool, ip, &health_rx);
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

        let result = decompress_request(req).await;
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

        let result = decompress_request(req).await;
        assert!(result.is_err());
        let resp = result.unwrap_err();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_compress_response_round_trip() {
        let original = b"response body data for compression";
        let resp = Response::builder()
            .body(Body::from(original.to_vec()))
            .unwrap();

        let compressed_resp = compress_response(resp).await.unwrap();
        assert_eq!(
            compressed_resp.headers().get(CONTENT_ENCODING).unwrap(),
            "zstd"
        );

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
    async fn test_compress_response_empty_body() {
        let resp = Response::builder()
            .body(Body::empty())
            .unwrap();

        let result = compress_response(resp).await.unwrap();
        assert!(!result.headers().contains_key(CONTENT_ENCODING));
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
    fn test_max_response_body_constant() {
        assert_eq!(MAX_RESPONSE_BODY, 10 * 1024 * 1024);
    }

    #[test]
    fn test_connect_timeout_constant() {
        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(5));
    }

    #[test]
    fn test_request_timeout_constant() {
        assert_eq!(REQUEST_TIMEOUT, Duration::from_secs(30));
    }
}
