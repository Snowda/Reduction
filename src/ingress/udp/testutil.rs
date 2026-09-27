use std::net::SocketAddr;
use std::sync::Arc;

use crate::circuit::CircuitBreakers;
use crate::config::{BackendConfig, CircuitBreakerConfig, RetryConfig, TransportKind};
use crate::ingress::protocol::{Datagram, Peer};

pub fn datagram(payload: &[u8]) -> Datagram {
	let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
	return Datagram {
		peer: Peer::from_socket_addr(addr),
		recv_at_unix_nanos: 0,
		payload: payload.to_vec(),
	};
}

pub fn quic_backend(id: &str) -> BackendConfig {
	return BackendConfig::new(id, "10.0.0.5:9000".parse().unwrap(), 1.0, TransportKind::Quic).unwrap();
}

pub fn empty_client_config() -> Arc<rustls::ClientConfig> {
	let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
	return Arc::new(
		rustls::ClientConfig::builder()
			.with_root_certificates(rustls::RootCertStore::empty())
			.with_no_client_auth(),
	);
}

pub fn breakers() -> Arc<CircuitBreakers> {
	return Arc::new(CircuitBreakers::new(&CircuitBreakerConfig::default()));
}

pub fn fast_retry() -> RetryConfig {
	// Long enough that a cooldown window is observable in a test, no jitter for determinism.
	return RetryConfig {
		max_retries: 3,
		base_delay_ms: 10_000,
		max_delay_ms: 60_000,
		jitter_ms: 0,
	};
}
