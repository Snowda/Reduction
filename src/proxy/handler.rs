use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::{error, info};

use crate::balancer::{BackendPool, RequestQueue};
use crate::config::BackendConfig;
use crate::health::HealthState;
use crate::proxy::router::Router;

static REQUEST_QUEUE: OnceLock<RequestQueue> = OnceLock::new();

pub fn init_request_queue(queue: RequestQueue) -> crate::error::Result<()> {
    REQUEST_QUEUE
        .set(queue)
        .map_err(|_| crate::error::ReductionError::Config("request queue already initialized".to_string()))
}

fn request_queue() -> &'static RequestQueue {
    return REQUEST_QUEUE
        .get()
        .expect("request queue not initialized");
}

#[derive(Clone)]
pub struct ReloadableState {
    pub router: Router,
    pub backend_pools: HashMap<String, BackendPool>,
}

#[derive(Clone)]
pub struct ProxyState {
    pub reloadable: watch::Receiver<ReloadableState>,
    pub tls_connector: TlsConnector,
    pub health_rx: watch::Receiver<HealthState>,
}

// Synchronous so the watch::Ref never crosses an await point.
fn select_backend(
    pool: &BackendPool,
    client_ip: IpAddr,
    health_rx: &watch::Receiver<HealthState>,
) -> crate::error::Result<BackendConfig> {
    let health = health_rx.borrow();
    match pool.select(client_ip, &health) {
        Some(backend) => return Ok(backend.clone()),
        None => return Err(crate::error::ReductionError::BackendUnavailable),
    }
}

// Resolve route and backend pool from reloadable state before any await point.
fn resolve_backend_pool(
    reloadable: &watch::Receiver<ReloadableState>,
    path: &str,
) -> Result<(String, BackendPool), Response<Body>> {
    let state = reloadable.borrow();

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

pub async fn proxy_handler(
    State(state): State<ProxyState>,
    req: Request<Body>,
) -> Response<Body> {
    let path: &str = req.uri().path();

    let client_ip: IpAddr = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or_else(|| IpAddr::from([127, 0, 0, 1]));

    let (backend_id, pool) = match resolve_backend_pool(&state.reloadable, path) {
        Ok(result) => result,
        Err(response) => return response,
    };

    let queue: &RequestQueue = request_queue();

    let _permit = match queue.try_acquire() {
        Ok(guard) => guard,
        Err(e) => {
            error!(backend_id, error = %e, "queue full");
            return Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Body::from(format!("{e}")))
                .expect("failed to build response");
        }
    };

    let backend: BackendConfig = match select_backend(&pool, client_ip, &state.health_rx) {
        Ok(b) => b,
        Err(e) => {
            error!(backend_id, error = %e, "dispatch failed");
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(format!("{e}")))
                .expect("failed to build response");
        }
    };

    info!(backend = %backend.id, path, "forwarding request");

    match forward_request(req, &backend, &state.tls_connector).await {
        Ok(response) => response,
        Err(e) => {
            error!(backend = %backend.id, error = %e, "failed to forward request");
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("backend error"))
                .expect("failed to build response");
        }
    }
}

const MAX_RESPONSE_BODY: usize = 10 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

fn timeout_err(phase: &str) -> crate::error::ReductionError {
    return crate::error::ReductionError::Forward(format!("{phase}: timed out"));
}

async fn forward_request(
    req: Request<Body>,
    backend: &BackendConfig,
    tls_connector: &TlsConnector,
) -> crate::error::Result<Response<Body>> {
    let tcp_stream: TcpStream = timeout(CONNECT_TIMEOUT, TcpStream::connect(backend.address))
        .await
        .map_err(|_| timeout_err("connect"))?
        .map_err(|e| crate::error::ReductionError::Forward(format!("connect {}: {e}", backend.address)))?;

    let server_name: rustls::pki_types::ServerName<'static> =
        rustls::pki_types::ServerName::try_from(backend.host.as_str())
            .map_err(|e| crate::error::ReductionError::Forward(format!("invalid server name: {e}")))?
            .to_owned();

    let tls_stream = timeout(HANDSHAKE_TIMEOUT, tls_connector.connect(server_name, tcp_stream))
        .await
        .map_err(|_| timeout_err("tls handshake"))?
        .map_err(|e| crate::error::ReductionError::Forward(format!("tls handshake: {e}")))?;

    let io = TokioIo::new(tls_stream);

    let (mut sender, conn) = timeout(HANDSHAKE_TIMEOUT, http1::handshake(io))
        .await
        .map_err(|_| timeout_err("http handshake"))?
        .map_err(|e| crate::error::ReductionError::Forward(format!("http handshake: {e}")))?;

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            error!(error = %e, "backend connection driver error");
        }
    });

    let (mut parts, body) = req.into_parts();
    parts.headers.insert(
        axum::http::header::HOST,
        axum::http::HeaderValue::from_str(&backend.host)
            .map_err(|e| crate::error::ReductionError::Forward(format!("invalid host header: {e}")))?,
    );

    let backend_req: Request<Body> = Request::from_parts(parts, body);

    let response = timeout(REQUEST_TIMEOUT, sender.send_request(backend_req))
        .await
        .map_err(|_| timeout_err("send request"))?
        .map_err(|e| crate::error::ReductionError::Forward(format!("send request: {e}")))?;

    let (parts, incoming_body) = response.into_parts();
    let limited_body = http_body_util::Limited::new(incoming_body, MAX_RESPONSE_BODY);
    let bytes = timeout(RESPONSE_TIMEOUT, limited_body.collect())
        .await
        .map_err(|_| timeout_err("read response body"))?
        .map_err(|e| crate::error::ReductionError::Forward(format!("read response body: {e}")))?
        .to_bytes();

    return Ok(Response::from_parts(parts, Body::from(bytes)));
}
