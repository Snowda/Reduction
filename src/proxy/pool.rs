use std::collections::VecDeque;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, Response};
use bytes::Bytes;
use dashmap::DashMap;
use dashmap::mapref::one::{Ref as MapRef, RefMut as MapRefMut};
use http_body::Frame;
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use pin_project_lite::pin_project;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{Connecting, Connection, Endpoint};
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, MutexGuard, OnceCell, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tracing::{debug, error, warn};

use crate::config::{BackendConfig, TransportKind};
use crate::error::{ReductionError, Result};
use crate::transport::quic::QuicStream;

const MAX_IDLE_PER_HOST: usize = 16;
const READY_TIMEOUT: Duration = Duration::from_millis(50);
const H2_STREAM_WINDOW: u32 = 2 * 1024 * 1024;
const H2_CONN_WINDOW: u32 = 4 * 1024 * 1024;
const H2_CONNS_PER_BACKEND: usize = 4;

pub enum HttpSender {
    H1(http1::SendRequest<Body>),
    H2(http2::SendRequest<Body>),
}

impl HttpSender {
    pub async fn send_request(
        &mut self,
        req: Request<Body>,
    ) -> std::result::Result<Response<Incoming>, hyper::Error> {
        return match self {
            HttpSender::H1(s) => s.send_request(req).await,
            HttpSender::H2(s) => s.send_request(req).await,
        };
    }
}

pub struct ConnPool {
    tcp_h2: DashMap<SocketAddr, Vec<http2::SendRequest<Body>>>,
    tcp_h2_rr: AtomicUsize,
    quic_idle: DashMap<SocketAddr, Mutex<VecDeque<Connection>>>,
    quic_endpoint: OnceCell<Endpoint>,
    conn_limits: DashMap<String, Arc<Semaphore>>,
    h2_conns_per_backend: usize,
    max_idle_quic_per_host: usize,
}

impl ConnPool {
    pub fn new() -> Self {
        return Self {
            tcp_h2: DashMap::new(),
            tcp_h2_rr: AtomicUsize::new(0),
            quic_idle: DashMap::new(),
            quic_endpoint: OnceCell::new(),
            conn_limits: DashMap::new(),
            h2_conns_per_backend: H2_CONNS_PER_BACKEND,
            max_idle_quic_per_host: MAX_IDLE_PER_HOST,
        };
    }

    pub fn with_pool_config(mut self, h2_conns: usize, max_idle_quic: usize) -> Self {
        self.h2_conns_per_backend = h2_conns;
        self.max_idle_quic_per_host = max_idle_quic;
        return self;
    }

    pub fn try_acquire_conn_permit(
        &self,
        backend: &BackendConfig,
    ) -> std::result::Result<OwnedSemaphorePermit, ReductionError> {
        let sem: Arc<Semaphore> = self
            .conn_limits
            .entry(backend.id.clone())
            .or_insert_with(|| Arc::new(Semaphore::new(backend.max_connections as usize)))
            .clone();
        return sem.try_acquire_owned().map_err(|_| {
            ReductionError::BackendUnavailable
        });
    }

    pub fn connection_pressure(&self, backend_id: &str, max_connections: u32) -> f64 {
        let max: usize = max_connections as usize;
        if max == 0 {
            return 1.0;
        }
        let available: usize = self
            .conn_limits
            .get(backend_id)
            .map(|sem| sem.available_permits())
            .unwrap_or(max);
        let in_use: usize = max.saturating_sub(available);
        return in_use as f64 / max as f64;
    }

    fn take_quic(&self, addr: &SocketAddr) -> Option<Connection> {
        let entry: MapRef<'_, SocketAddr, Mutex<VecDeque<Connection>>> =
            self.quic_idle.get(addr)?;
        let mut queue: MutexGuard<'_, VecDeque<Connection>> =
            entry.try_lock().ok()?;
        while let Some(conn) = queue.pop_front() {
            if conn.close_reason().is_none() {
                return Some(conn);
            }
        }
        return None;
    }

    fn put_quic(&self, addr: SocketAddr, conn: Connection) {
        if conn.close_reason().is_some() {
            return;
        }
        let entry: MapRefMut<'_, SocketAddr, Mutex<VecDeque<Connection>>> =
            self.quic_idle.entry(addr).or_insert_with(|| Mutex::new(VecDeque::new()));
        let Ok(mut queue) = entry.try_lock() else {
            return;
        };
        if queue.len() < self.max_idle_quic_per_host {
            queue.push_back(conn);
        }
    }

    #[tracing::instrument(skip_all, fields(backend = %backend.id))]
    pub async fn acquire(
        &self,
        backend: &BackendConfig,
        tls_connector: &TlsConnector,
        client_tls_config: &Arc<rustls::ClientConfig>,
        connect_timeout: Duration,
        handshake_timeout: Duration,
    ) -> Result<HttpSender> {
        return match backend.transport {
            TransportKind::Tcp => self.acquire_tcp(backend, tls_connector, connect_timeout, handshake_timeout).await,
            TransportKind::Quic => self.acquire_quic(backend, client_tls_config, connect_timeout, handshake_timeout).await,
        };
    }

    async fn acquire_tcp(
        &self,
        backend: &BackendConfig,
        tls_connector: &TlsConnector,
        connect_timeout: Duration,
        handshake_timeout: Duration,
    ) -> Result<HttpSender> {
        if let Some(entry) = self.tcp_h2.get(&backend.address) {
            let senders: &Vec<http2::SendRequest<Body>> = entry.value();
            if !senders.is_empty() {
                let idx: usize = self.tcp_h2_rr.fetch_add(1, Ordering::Relaxed) % senders.len();
                let mut sender: http2::SendRequest<Body> = senders[idx].clone();
                drop(entry);
                match timeout(READY_TIMEOUT, sender.ready()).await {
                    Ok(Ok(_)) => {
                        debug!(backend = %backend.id, idx, "reusing pooled HTTP/2 connection");
                        return Ok(HttpSender::H2(sender));
                    }
                    _ => {
                        debug!(backend = %backend.id, "pooled HTTP/2 connection not ready, reconnecting");
                    }
                }
            } else {
                drop(entry);
            }
        }
        return self.connect_tcp_h2(backend, tls_connector, connect_timeout, handshake_timeout).await;
    }

    async fn acquire_quic(
        &self,
        backend: &BackendConfig,
        client_tls_config: &Arc<rustls::ClientConfig>,
        connect_timeout: Duration,
        handshake_timeout: Duration,
    ) -> Result<HttpSender> {
        let conn: Connection = if let Some(conn) = self.take_quic(&backend.address) {
            debug!(backend = %backend.id, "reusing pooled QUIC connection");
            conn
        } else {
            self.connect_quic(backend, client_tls_config, connect_timeout).await?
        };

        let (send, recv) = timeout(handshake_timeout, conn.open_bi())
            .await
            .map_err(|_| ReductionError::Forward("QUIC stream open: timed out".to_string()))?
            .map_err(|e| ReductionError::Forward(format!("QUIC stream open: {e}")))?;

        // Return the connection to the pool immediately — QUIC multiplexes streams
        self.put_quic(backend.address, conn);

        let stream: QuicStream = QuicStream::new(send, recv);
        let io: TokioIo<QuicStream> = TokioIo::new(stream);

        let (sender, conn_driver): (http1::SendRequest<Body>, _) =
            timeout(handshake_timeout, http1::handshake(io))
                .await
                .map_err(|_| ReductionError::Forward("http handshake: timed out".to_string()))?
                .map_err(|e| ReductionError::Forward(format!("http handshake: {e}")))?;

        tokio::spawn(async move {
            if let Err(e) = conn_driver.await {
                debug!(error = %e, "QUIC stream HTTP driver ended");
            }
        });

        return Ok(HttpSender::H1(sender));
    }

    async fn connect_tcp_h2(
        &self,
        backend: &BackendConfig,
        tls_connector: &TlsConnector,
        connect_timeout: Duration,
        handshake_timeout: Duration,
    ) -> Result<HttpSender> {
        let tcp_stream: TcpStream =
            timeout(connect_timeout, TcpStream::connect(backend.address))
                .await
                .map_err(|_| ReductionError::Forward("connect: timed out".to_string()))?
                .map_err(|e| {
                    ReductionError::Forward(format!("connect {}: {e}", backend.address))
                })?;

        let server_name: ServerName<'static> =
            ServerName::try_from(backend.host.as_str())
                .map_err(|e| ReductionError::Forward(format!("invalid server name: {e}")))?
                .to_owned();

        let tls_stream: TlsStream<TcpStream> =
            timeout(handshake_timeout, tls_connector.connect(server_name, tcp_stream))
                .await
                .map_err(|_| ReductionError::Forward("tls handshake: timed out".to_string()))?
                .map_err(|e| ReductionError::Forward(format!("tls handshake: {e}")))?;

        let io: TokioIo<TlsStream<TcpStream>> = TokioIo::new(tls_stream);

        let (sender, conn) =
            timeout(
                handshake_timeout,
                http2::Builder::new(TokioExecutor::new())
                    .initial_stream_window_size(H2_STREAM_WINDOW)
                    .initial_connection_window_size(H2_CONN_WINDOW)
                    .handshake(io),
            )
                .await
                .map_err(|_| ReductionError::Forward("http2 handshake: timed out".to_string()))?
                .map_err(|e| ReductionError::Forward(format!("http2 handshake: {e}")))?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                error!(error = %e, "HTTP/2 connection driver error");
            }
        });

        self.tcp_h2
            .entry(backend.address)
            .or_insert_with(Vec::new)
            .push(sender.clone());

        return Ok(HttpSender::H2(sender));
    }

    async fn get_or_init_quic_endpoint(
        &self,
        client_tls_config: &Arc<rustls::ClientConfig>,
    ) -> Result<&Endpoint> {
        return self
            .quic_endpoint
            .get_or_try_init(|| async {
                let quic_crypto: QuicClientConfig =
                    QuicClientConfig::try_from(client_tls_config.clone()).map_err(|e| {
                        ReductionError::Forward(format!("QUIC client crypto: {e}"))
                    })?;

                let mut client_config: quinn::ClientConfig =
                    quinn::ClientConfig::new(Arc::new(quic_crypto));
                client_config.transport_config(Arc::new(quinn::TransportConfig::default()));

                let mut endpoint: Endpoint =
                    Endpoint::client("0.0.0.0:0".parse().unwrap())
                        .map_err(|e| ReductionError::Forward(format!("QUIC endpoint: {e}")))?;
                endpoint.set_default_client_config(client_config);

                debug!("shared QUIC client endpoint initialized");
                return Ok(endpoint);
            })
            .await;
    }

    async fn connect_quic(
        &self,
        backend: &BackendConfig,
        client_tls_config: &Arc<rustls::ClientConfig>,
        connect_timeout: Duration,
    ) -> Result<Connection> {
        let endpoint: &Endpoint = self.get_or_init_quic_endpoint(client_tls_config).await?;

        let connecting: Connecting = endpoint
            .connect(backend.address, &backend.host)
            .map_err(|e| ReductionError::Forward(format!("QUIC connect: {e}")))?;

        let connection: Connection = timeout(connect_timeout, connecting)
            .await
            .map_err(|_| ReductionError::Forward("QUIC handshake: timed out".to_string()))?
            .map_err(|e| ReductionError::Forward(format!("QUIC handshake: {e}")))?;

        debug!(backend = %backend.id, "QUIC connection established");
        return Ok(connection);
    }

    pub fn drain_backends(&self, addrs: &[SocketAddr]) {
        for addr in addrs {
            self.tcp_h2.remove(addr);
            if let Some((_, mutex)) = self.quic_idle.remove(addr) {
                if let Ok(mut queue) = mutex.try_lock() {
                    for conn in queue.drain(..) {
                        conn.close(0u32.into(), b"draining");
                    }
                }
            }
        }
    }

    pub fn drain(&self) {
        self.tcp_h2.clear();

        for entry in self.quic_idle.iter() {
            if let Ok(mut queue) = entry.try_lock() {
                for conn in queue.drain(..) {
                    conn.close(0u32.into(), b"shutdown");
                }
            }
        }
        self.quic_idle.clear();

        if let Some(endpoint) = self.quic_endpoint.get() {
            endpoint.close(0u32.into(), b"shutdown");
        }
    }

    pub async fn warm_up(
        &self,
        backends: &[BackendConfig],
        tls_connector: &TlsConnector,
        client_tls_config: &Arc<rustls::ClientConfig>,
        connect_timeout: Duration,
        handshake_timeout: Duration,
    ) {
        for backend in backends {
            match backend.transport {
                TransportKind::Tcp => {
                    let existing: usize = self.tcp_h2.get(&backend.address)
                        .map(|e| e.value().len())
                        .unwrap_or(0);
                    for i in existing..self.h2_conns_per_backend {
                        match self.connect_tcp_h2(backend, tls_connector, connect_timeout, handshake_timeout).await {
                            Ok(_sender) => {
                                debug!(backend = %backend.id, conn = i, "pre-warmed H2 connection");
                            }
                            Err(e) => {
                                warn!(backend = %backend.id, conn = i, error = %e, "failed to pre-warm H2 connection");
                                break;
                            }
                        }
                    }
                }
                TransportKind::Quic => {
                    match self.acquire(backend, tls_connector, client_tls_config, connect_timeout, handshake_timeout).await {
                        Ok(_sender) => {
                            debug!(backend = %backend.id, "pre-warmed QUIC connection");
                        }
                        Err(e) => {
                            warn!(backend = %backend.id, error = %e, "failed to pre-warm QUIC connection");
                        }
                    }
                }
            }
        }
    }
}

struct ReturnHandle {
    sender: Option<HttpSender>,
}

impl Drop for ReturnHandle {
    fn drop(&mut self) {
        // H2 senders are clones — dropping returns nothing to the pool.
        // QUIC H1 senders are per-stream — no pooling needed.
    }
}

pin_project! {
    pub struct PooledBody<B> {
        #[pin]
        inner: B,
        return_handle: ReturnHandle,
    }
}

impl<B> PooledBody<B> {
    pub fn new(inner: B, sender: HttpSender) -> Self {
        return Self {
            inner,
            return_handle: ReturnHandle {
                sender: Some(sender),
            },
        };
    }
}

impl<B> http_body::Body for PooledBody<B>
where
    B: http_body::Body<Data = Bytes>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        match this.inner.poll_frame(cx) {
            Poll::Ready(None) => {
                return Poll::Ready(None);
            }
            Poll::Ready(Some(Err(e))) => {
                // Error — discard the sender.
                this.return_handle.sender.take();
                return Poll::Ready(Some(Err(e)));
            }
            other => return other,
        }
    }

    fn is_end_stream(&self) -> bool {
        return self.inner.is_end_stream();
    }

    fn size_hint(&self) -> http_body::SizeHint {
        return self.inner.size_hint();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use bytes::Bytes;
    use dashmap::DashMap;
    use http_body::{Body as _, Frame};
    use http_body_util::BodyExt;
    use tokio::sync::watch;

    use crate::circuit::CircuitBreakers;
    use crate::config::{CircuitBreakerConfig, CompressionConfig, ProxyConfig, RetryConfig, TimeoutConfig};
    use crate::health::HealthState;
    use crate::metrics::ProxyMetrics;
    use crate::acl::AccessControl;
    use crate::proxy::handler::{ProxyState, ReloadableState};
    use crate::proxy::router::Router;
    use crate::ratelimit::RateLimit;

    use tokio_util::sync::CancellationToken;

    use super::*;

    fn make_test_state() -> Arc<ProxyState> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client_config: Arc<rustls::ClientConfig> = Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_no_client_auth(),
        );
        let tls_connector: TlsConnector = TlsConnector::from(client_config.clone());
        let initial_reloadable = ReloadableState {
            router: Router::new(&[]),
            backend_pools: HashMap::new(),
        };
        let (_, reloadable_rx) = watch::channel(initial_reloadable);
        let (_, health_rx) = watch::channel(HealthState::new());
        return Arc::new(ProxyState {
            reloadable: reloadable_rx,
            tls_connector,
            client_tls_config: client_config,
            health_rx,
            conn_pool: ConnPool::new(),
            acl: AccessControl::new(vec![], vec![]),
            rate_limiter: RateLimit::new(u32::MAX).unwrap(),
            queues: DashMap::new(),
            default_queue_depth: 1000,
            metrics: ProxyMetrics::new(),
            circuit_breakers: CircuitBreakers::new(&CircuitBreakerConfig::default()),
            shutdown: CancellationToken::new(),
            timeouts: TimeoutConfig::default(),
            proxy_config: ProxyConfig::default(),
            compression_config: CompressionConfig::default(),
            retry_config: RetryConfig::default(),
        });
    }

    #[tokio::test]
    async fn test_pool_acquire_no_idle_fails_without_backend() {
        let state = make_test_state();
        let backend: BackendConfig = BackendConfig::new(
            "test".into(),
            "127.0.0.1:1".parse().unwrap(),
            1.0,
            TransportKind::Tcp,
        );
        let connect_timeout: Duration = Duration::from_secs(state.timeouts.connect_secs);
        let handshake_timeout: Duration = Duration::from_secs(state.timeouts.handshake_secs);
        let result: Result<HttpSender> =
            state.conn_pool.acquire(&backend, &state.tls_connector, &state.client_tls_config, connect_timeout, handshake_timeout).await;
        assert!(result.is_err());
    }

    #[derive(Debug)]
    struct NoVerify;

    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self, _: &rustls::pki_types::CertificateDer<'_>,
            _: &[rustls::pki_types::CertificateDer<'_>], _: &ServerName<'_>,
            _: &[u8], _: rustls::pki_types::UnixTime,
        ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }

        fn verify_tls12_signature(
            &self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            return Ok(rustls::client::danger::HandshakeSignatureValid::assertion());
        }

        fn verify_tls13_signature(
            &self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            return Ok(rustls::client::danger::HandshakeSignatureValid::assertion());
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            return vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA256,
            ];
        }
    }

    #[test]
    fn test_take_quic_nonexistent_addr() {
        let pool = ConnPool::new();
        let addr: SocketAddr = "10.0.0.1:9090".parse().unwrap();
        assert!(pool.take_quic(&addr).is_none());
    }

    #[test]
    fn test_pool_tcp_h2_map_starts_empty() {
        let pool = ConnPool::new();
        assert!(pool.tcp_h2.is_empty());
    }

    #[test]
    fn test_pool_quic_idle_map_starts_empty() {
        let pool = ConnPool::new();
        assert!(pool.quic_idle.is_empty());
    }

    #[test]
    fn test_pool_default_constants() {
        let pool = ConnPool::new();
        assert_eq!(pool.h2_conns_per_backend, 4);
        assert_eq!(pool.max_idle_quic_per_host, 16);
    }

    #[test]
    fn test_pool_with_custom_config() {
        let pool = ConnPool::new().with_pool_config(8, 32);
        assert_eq!(pool.h2_conns_per_backend, 8);
        assert_eq!(pool.max_idle_quic_per_host, 32);
    }

    #[test]
    fn test_ready_timeout_constant() {
        assert_eq!(READY_TIMEOUT, Duration::from_millis(50));
    }

    struct MockBody {
        data: Option<Bytes>,
    }

    impl MockBody {
        fn new(data: &[u8]) -> Self {
            return Self { data: Some(Bytes::copy_from_slice(data)) };
        }

        fn empty() -> Self {
            return Self { data: None };
        }
    }

    impl http_body::Body for MockBody {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
            if let Some(data) = self.data.take() {
                return Poll::Ready(Some(Ok(Frame::data(data))));
            }
            return Poll::Ready(None);
        }

        fn is_end_stream(&self) -> bool {
            return self.data.is_none();
        }

        fn size_hint(&self) -> http_body::SizeHint {
            let mut hint = http_body::SizeHint::new();
            if let Some(ref data) = self.data {
                hint.set_exact(data.len() as u64);
            } else {
                hint.set_exact(0);
            }
            return hint;
        }
    }

    #[test]
    fn test_pooled_body_is_end_stream_delegates() {
        let inner = MockBody::empty();
        let body = PooledBody {
            inner,
            return_handle: ReturnHandle { sender: None },
        };
        assert!(body.is_end_stream());
    }

    #[test]
    fn test_pooled_body_is_end_stream_false_with_data() {
        let inner = MockBody::new(b"hello");
        let body = PooledBody {
            inner,
            return_handle: ReturnHandle { sender: None },
        };
        assert!(!body.is_end_stream());
    }

    #[test]
    fn test_pooled_body_size_hint_delegates() {
        let inner = MockBody::new(b"hello");
        let body = PooledBody {
            inner,
            return_handle: ReturnHandle { sender: None },
        };
        assert_eq!(body.size_hint().exact(), Some(5));
    }

    #[test]
    fn test_pooled_body_size_hint_empty() {
        let inner = MockBody::empty();
        let body = PooledBody {
            inner,
            return_handle: ReturnHandle { sender: None },
        };
        assert_eq!(body.size_hint().exact(), Some(0));
    }

    #[tokio::test]
    async fn test_pooled_body_poll_frame_reads_data() {
        let inner = MockBody::new(b"test data");
        let mut body = PooledBody {
            inner,
            return_handle: ReturnHandle { sender: None },
        };

        let frame = body.frame().await;
        assert!(frame.is_some());
        let frame = frame.unwrap().unwrap();
        assert!(frame.is_data());
        assert_eq!(frame.into_data().unwrap(), Bytes::from("test data"));

        let frame = body.frame().await;
        assert!(frame.is_none());
    }

    struct ErrorBody;

    impl http_body::Body for ErrorBody {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
            return Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "mock error",
            ))));
        }

        fn is_end_stream(&self) -> bool {
            return false;
        }

        fn size_hint(&self) -> http_body::SizeHint {
            return http_body::SizeHint::default();
        }
    }

    #[tokio::test]
    async fn test_pooled_body_error_discards_sender() {
        let inner = ErrorBody;
        let mut body = PooledBody {
            inner,
            return_handle: ReturnHandle { sender: None },
        };

        let frame = body.frame().await;
        assert!(frame.is_some());
        let result = frame.unwrap();
        assert!(result.is_err());
        assert!(body.return_handle.sender.is_none());
    }

    #[tokio::test]
    async fn test_pool_acquire_quic_no_idle_fails_without_backend() {
        let state = make_test_state();
        let backend = BackendConfig::new(
            "test".into(),
            "127.0.0.1:1".parse().unwrap(),
            1.0,
            TransportKind::Quic,
        );
        let connect_timeout: Duration = Duration::from_secs(state.timeouts.connect_secs);
        let handshake_timeout: Duration = Duration::from_secs(state.timeouts.handshake_secs);
        let result: Result<HttpSender> = state.conn_pool.acquire(&backend, &state.tls_connector, &state.client_tls_config, connect_timeout, handshake_timeout).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_drain_clears_tcp_pool() {
        let pool = ConnPool::new();
        pool.tcp_h2.insert("127.0.0.1:8080".parse().unwrap(), Vec::new());
        assert!(!pool.tcp_h2.is_empty());
        pool.drain();
        assert!(pool.tcp_h2.is_empty());
        assert!(pool.quic_idle.is_empty());
    }

    #[test]
    fn test_drain_on_empty_pool() {
        let pool = ConnPool::new();
        pool.drain();
        assert!(pool.tcp_h2.is_empty());
        assert!(pool.quic_idle.is_empty());
    }

    #[test]
    fn test_drain_backends_removes_only_specified_addrs() {
        let pool = ConnPool::new();
        let addr_a: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:9090".parse().unwrap();
        let addr_c: SocketAddr = "127.0.0.1:7070".parse().unwrap();
        pool.tcp_h2.insert(addr_a, Vec::new());
        pool.tcp_h2.insert(addr_b, Vec::new());
        pool.tcp_h2.insert(addr_c, Vec::new());

        pool.drain_backends(&[addr_a, addr_c]);

        assert!(!pool.tcp_h2.contains_key(&addr_a));
        assert!(pool.tcp_h2.contains_key(&addr_b));
        assert!(!pool.tcp_h2.contains_key(&addr_c));
    }

    #[test]
    fn test_drain_backends_noop_for_unknown_addrs() {
        let pool = ConnPool::new();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        pool.tcp_h2.insert(addr, Vec::new());

        let unknown: SocketAddr = "10.0.0.1:443".parse().unwrap();
        pool.drain_backends(&[unknown]);

        assert!(pool.tcp_h2.contains_key(&addr));
    }

    #[test]
    fn test_drain_backends_empty_slice_is_noop() {
        let pool = ConnPool::new();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        pool.tcp_h2.insert(addr, Vec::new());

        pool.drain_backends(&[]);

        assert!(pool.tcp_h2.contains_key(&addr));
    }

    #[test]
    fn test_conn_permit_acquire_succeeds() {
        let pool = ConnPool::new();
        let backend = BackendConfig::new(
            "test".into(),
            "127.0.0.1:8080".parse().unwrap(),
            1.0,
            TransportKind::Tcp,
        ).with_max_connections(2);

        let _p1 = pool.try_acquire_conn_permit(&backend).unwrap();
        let _p2 = pool.try_acquire_conn_permit(&backend).unwrap();
    }

    #[test]
    fn test_conn_permit_exhausted() {
        let pool = ConnPool::new();
        let backend = BackendConfig::new(
            "test".into(),
            "127.0.0.1:8080".parse().unwrap(),
            1.0,
            TransportKind::Tcp,
        ).with_max_connections(1);

        let _p1 = pool.try_acquire_conn_permit(&backend).unwrap();
        let result = pool.try_acquire_conn_permit(&backend);
        assert!(result.is_err());
    }

    #[test]
    fn test_conn_permit_released_on_drop() {
        let pool = ConnPool::new();
        let backend = BackendConfig::new(
            "test".into(),
            "127.0.0.1:8080".parse().unwrap(),
            1.0,
            TransportKind::Tcp,
        ).with_max_connections(1);

        {
            let _p1 = pool.try_acquire_conn_permit(&backend).unwrap();
        }
        let _p2 = pool.try_acquire_conn_permit(&backend).unwrap();
    }

    #[test]
    fn test_connection_pressure_zero_when_idle() {
        let pool = ConnPool::new();
        let pressure: f64 = pool.connection_pressure("test", 256);
        assert_eq!(pressure, 0.0);
    }

    #[test]
    fn test_connection_pressure_increases_with_permits() {
        let pool = ConnPool::new();
        let backend = BackendConfig::new(
            "test".into(),
            "127.0.0.1:8080".parse().unwrap(),
            1.0,
            TransportKind::Tcp,
        ).with_max_connections(4);

        let _p1 = pool.try_acquire_conn_permit(&backend).unwrap();
        let pressure: f64 = pool.connection_pressure("test", 4);
        assert!((pressure - 0.25).abs() < f64::EPSILON);

        let _p2 = pool.try_acquire_conn_permit(&backend).unwrap();
        let pressure: f64 = pool.connection_pressure("test", 4);
        assert!((pressure - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_connection_pressure_full() {
        let pool = ConnPool::new();
        let backend = BackendConfig::new(
            "test".into(),
            "127.0.0.1:8080".parse().unwrap(),
            1.0,
            TransportKind::Tcp,
        ).with_max_connections(1);

        let _p1 = pool.try_acquire_conn_permit(&backend).unwrap();
        let pressure: f64 = pool.connection_pressure("test", 1);
        assert!((pressure - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_independent_backend_permits() {
        let pool = ConnPool::new();
        let backend_a = BackendConfig::new(
            "a".into(),
            "127.0.0.1:8080".parse().unwrap(),
            1.0,
            TransportKind::Tcp,
        ).with_max_connections(1);
        let backend_b = BackendConfig::new(
            "b".into(),
            "127.0.0.2:8080".parse().unwrap(),
            1.0,
            TransportKind::Tcp,
        ).with_max_connections(1);

        let _pa = pool.try_acquire_conn_permit(&backend_a).unwrap();
        let _pb = pool.try_acquire_conn_permit(&backend_b).unwrap();

        assert!(pool.try_acquire_conn_permit(&backend_a).is_err());
        assert!(pool.try_acquire_conn_permit(&backend_b).is_err());
    }
}
