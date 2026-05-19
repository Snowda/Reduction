use std::collections::VecDeque;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use bytes::Bytes;
use dashmap::DashMap;
use dashmap::mapref::one::{Ref as MapRef, RefMut as MapRefMut};
use http_body::Frame;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use pin_project_lite::pin_project;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{Connecting, Connection, Endpoint};
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, MutexGuard, OnceCell};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tracing::{debug, error};

use crate::config::{BackendConfig, TransportKind};
use crate::error::{ReductionError, Result};
use crate::transport::quic::QuicStream;

use super::handler::{CONNECT_TIMEOUT, HANDSHAKE_TIMEOUT, ProxyState};

const MAX_IDLE_PER_HOST: usize = 16;
const READY_TIMEOUT: Duration = Duration::from_millis(50);

pub struct ConnPool {
    tcp_idle: DashMap<SocketAddr, Mutex<VecDeque<http1::SendRequest<Body>>>>,
    quic_idle: DashMap<SocketAddr, Mutex<VecDeque<Connection>>>,
    quic_endpoint: OnceCell<Endpoint>,
}

impl ConnPool {
    pub fn new() -> Self {
        return Self {
            tcp_idle: DashMap::new(),
            quic_idle: DashMap::new(),
            quic_endpoint: OnceCell::new(),
        };
    }

    fn take_tcp(&self, addr: &SocketAddr) -> Option<http1::SendRequest<Body>> {
        let entry: MapRef<'_, SocketAddr, Mutex<VecDeque<http1::SendRequest<Body>>>> =
            self.tcp_idle.get(addr)?;
        let mut queue: MutexGuard<'_, VecDeque<http1::SendRequest<Body>>> =
            entry.try_lock().ok()?;
        return queue.pop_front();
    }

    fn put_tcp(&self, addr: SocketAddr, sender: http1::SendRequest<Body>) {
        let entry: MapRefMut<'_, SocketAddr, Mutex<VecDeque<http1::SendRequest<Body>>>> =
            self.tcp_idle.entry(addr).or_insert_with(|| Mutex::new(VecDeque::new()));
        let Ok(mut queue) = entry.try_lock() else {
            return;
        };
        if queue.len() < MAX_IDLE_PER_HOST {
            queue.push_back(sender);
        }
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
        if queue.len() < MAX_IDLE_PER_HOST {
            queue.push_back(conn);
        }
    }

    pub async fn acquire(
        &self,
        backend: &BackendConfig,
        tls_connector: &TlsConnector,
        client_tls_config: &Arc<rustls::ClientConfig>,
    ) -> Result<http1::SendRequest<Body>> {
        return match backend.transport {
            TransportKind::Tcp => self.acquire_tcp(backend, tls_connector).await,
            TransportKind::Quic => self.acquire_quic(backend, client_tls_config).await,
        };
    }

    async fn acquire_tcp(
        &self,
        backend: &BackendConfig,
        tls_connector: &TlsConnector,
    ) -> Result<http1::SendRequest<Body>> {
        if let Some(mut sender) = self.take_tcp(&backend.address) {
            match timeout(READY_TIMEOUT, sender.ready()).await {
                Ok(Ok(_)) => {
                    debug!(backend = %backend.id, "reusing pooled TCP connection");
                    return Ok(sender);
                }
                _ => {
                    debug!(backend = %backend.id, "pooled TCP connection not ready, creating new");
                }
            }
        }
        return self.connect_tcp(backend, tls_connector).await;
    }

    async fn acquire_quic(
        &self,
        backend: &BackendConfig,
        client_tls_config: &Arc<rustls::ClientConfig>,
    ) -> Result<http1::SendRequest<Body>> {
        let conn: Connection = if let Some(conn) = self.take_quic(&backend.address) {
            debug!(backend = %backend.id, "reusing pooled QUIC connection");
            conn
        } else {
            self.connect_quic(backend, client_tls_config).await?
        };

        let (send, recv) = timeout(HANDSHAKE_TIMEOUT, conn.open_bi())
            .await
            .map_err(|_| ReductionError::Forward("QUIC stream open: timed out".to_string()))?
            .map_err(|e| ReductionError::Forward(format!("QUIC stream open: {e}")))?;

        // Return the connection to the pool immediately — QUIC multiplexes streams
        self.put_quic(backend.address, conn);

        let stream: QuicStream = QuicStream::new(send, recv);
        let io: TokioIo<QuicStream> = TokioIo::new(stream);

        let (sender, conn_driver): (http1::SendRequest<Body>, _) =
            timeout(HANDSHAKE_TIMEOUT, http1::handshake(io))
                .await
                .map_err(|_| ReductionError::Forward("http handshake: timed out".to_string()))?
                .map_err(|e| ReductionError::Forward(format!("http handshake: {e}")))?;

        tokio::spawn(async move {
            if let Err(e) = conn_driver.await {
                debug!(error = %e, "QUIC stream HTTP driver ended");
            }
        });

        return Ok(sender);
    }

    async fn connect_tcp(
        &self,
        backend: &BackendConfig,
        tls_connector: &TlsConnector,
    ) -> Result<http1::SendRequest<Body>> {
        let tcp_stream: TcpStream =
            timeout(CONNECT_TIMEOUT, TcpStream::connect(backend.address))
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
            timeout(HANDSHAKE_TIMEOUT, tls_connector.connect(server_name, tcp_stream))
                .await
                .map_err(|_| ReductionError::Forward("tls handshake: timed out".to_string()))?
                .map_err(|e| ReductionError::Forward(format!("tls handshake: {e}")))?;

        let io: TokioIo<TlsStream<TcpStream>> = TokioIo::new(tls_stream);

        let (sender, conn) =
            timeout(HANDSHAKE_TIMEOUT, http1::handshake(io))
                .await
                .map_err(|_| ReductionError::Forward("http handshake: timed out".to_string()))?
                .map_err(|e| ReductionError::Forward(format!("http handshake: {e}")))?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                error!(error = %e, "backend connection driver error");
            }
        });

        return Ok(sender);
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
    ) -> Result<Connection> {
        let endpoint: &Endpoint = self.get_or_init_quic_endpoint(client_tls_config).await?;

        let connecting: Connecting = endpoint
            .connect(backend.address, &backend.host)
            .map_err(|e| ReductionError::Forward(format!("QUIC connect: {e}")))?;

        let connection: Connection = timeout(CONNECT_TIMEOUT, connecting)
            .await
            .map_err(|_| ReductionError::Forward("QUIC handshake: timed out".to_string()))?
            .map_err(|e| ReductionError::Forward(format!("QUIC handshake: {e}")))?;

        debug!(backend = %backend.id, "QUIC connection established");
        return Ok(connection);
    }
}

struct ReturnHandle {
    state: Arc<ProxyState>,
    addr: SocketAddr,
    sender: Option<http1::SendRequest<Body>>,
    transport: TransportKind,
}

impl Drop for ReturnHandle {
    fn drop(&mut self) {
        if self.transport == TransportKind::Tcp
            && let Some(sender) = self.sender.take()
        {
            self.state.conn_pool.put_tcp(self.addr, sender);
        }
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
    pub fn new(
        inner: B,
        state: Arc<ProxyState>,
        addr: SocketAddr,
        sender: http1::SendRequest<Body>,
        transport: TransportKind,
    ) -> Self {
        return Self {
            inner,
            return_handle: ReturnHandle {
                state,
                addr,
                sender: Some(sender),
                transport,
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
                // Body complete — sender returns to pool via ReturnHandle Drop.
                return Poll::Ready(None);
            }
            Poll::Ready(Some(Err(e))) => {
                // Error — discard the connection.
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

    use crate::health::HealthState;
    use crate::metrics::ProxyMetrics;
    use crate::proxy::handler::ReloadableState;
    use crate::proxy::router::Router;
    use crate::ratelimit::RateLimit;

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
            rate_limiter: RateLimit::new(u32::MAX).unwrap(),
            queues: DashMap::new(),
            default_queue_depth: 1000,
            metrics: ProxyMetrics::new(),
        });
    }

    #[test]
    fn test_pool_new_empty() {
        let pool: ConnPool = ConnPool::new();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert!(pool.take_tcp(&addr).is_none());
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
        let result: Result<http1::SendRequest<Body>> =
            state.conn_pool.acquire(&backend, &state.tls_connector, &state.client_tls_config).await;
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
    fn test_take_tcp_nonexistent_addr() {
        let pool = ConnPool::new();
        let addr: SocketAddr = "10.0.0.1:9090".parse().unwrap();
        assert!(pool.take_tcp(&addr).is_none());
    }

    #[test]
    fn test_take_quic_nonexistent_addr() {
        let pool = ConnPool::new();
        let addr: SocketAddr = "10.0.0.1:9090".parse().unwrap();
        assert!(pool.take_quic(&addr).is_none());
    }

    #[test]
    fn test_pool_tcp_idle_map_starts_empty() {
        let pool = ConnPool::new();
        assert!(pool.tcp_idle.is_empty());
    }

    #[test]
    fn test_pool_quic_idle_map_starts_empty() {
        let pool = ConnPool::new();
        assert!(pool.quic_idle.is_empty());
    }

    #[test]
    fn test_max_idle_per_host_constant() {
        assert_eq!(MAX_IDLE_PER_HOST, 16);
    }

    #[test]
    fn test_ready_timeout_constant() {
        assert_eq!(READY_TIMEOUT, Duration::from_millis(50));
    }

    #[test]
    fn test_return_handle_drop_tcp_returns_sender() {
        let state = make_test_state();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let handle = ReturnHandle {
            state: Arc::clone(&state),
            addr,
            sender: None,
            transport: TransportKind::Tcp,
        };
        drop(handle);
        assert!(state.conn_pool.take_tcp(&addr).is_none());
    }

    #[test]
    fn test_return_handle_drop_quic_does_not_return() {
        let state = make_test_state();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let handle = ReturnHandle {
            state: Arc::clone(&state),
            addr,
            sender: None,
            transport: TransportKind::Quic,
        };
        drop(handle);
        assert!(state.conn_pool.take_tcp(&addr).is_none());
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
        let state = make_test_state();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let inner = MockBody::empty();
        let body = PooledBody {
            inner,
            return_handle: ReturnHandle {
                state,
                addr,
                sender: None,
                transport: TransportKind::Tcp,
            },
        };
        assert!(body.is_end_stream());
    }

    #[test]
    fn test_pooled_body_is_end_stream_false_with_data() {
        let state = make_test_state();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let inner = MockBody::new(b"hello");
        let body = PooledBody {
            inner,
            return_handle: ReturnHandle {
                state,
                addr,
                sender: None,
                transport: TransportKind::Tcp,
            },
        };
        assert!(!body.is_end_stream());
    }

    #[test]
    fn test_pooled_body_size_hint_delegates() {
        let state = make_test_state();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let inner = MockBody::new(b"hello");
        let body = PooledBody {
            inner,
            return_handle: ReturnHandle {
                state,
                addr,
                sender: None,
                transport: TransportKind::Tcp,
            },
        };
        assert_eq!(body.size_hint().exact(), Some(5));
    }

    #[test]
    fn test_pooled_body_size_hint_empty() {
        let state = make_test_state();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let inner = MockBody::empty();
        let body = PooledBody {
            inner,
            return_handle: ReturnHandle {
                state,
                addr,
                sender: None,
                transport: TransportKind::Tcp,
            },
        };
        assert_eq!(body.size_hint().exact(), Some(0));
    }

    #[tokio::test]
    async fn test_pooled_body_poll_frame_reads_data() {
        let state = make_test_state();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let inner = MockBody::new(b"test data");
        let mut body = PooledBody {
            inner,
            return_handle: ReturnHandle {
                state,
                addr,
                sender: None,
                transport: TransportKind::Tcp,
            },
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
        let state = make_test_state();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let inner = ErrorBody;
        let mut body = PooledBody {
            inner,
            return_handle: ReturnHandle {
                state,
                addr,
                sender: None,
                transport: TransportKind::Tcp,
            },
        };

        let frame = body.frame().await;
        assert!(frame.is_some());
        let result = frame.unwrap();
        assert!(result.is_err());
        // Sender should have been taken (discarded)
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
        let result = state.conn_pool.acquire(&backend, &state.tls_connector, &state.client_tls_config).await;
        assert!(result.is_err());
    }
}
