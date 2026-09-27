// Relax restriction lints under cfg(test) only: tests use unwrap/panic, exact float asserts, lossy casts.
#![cfg_attr(
	test,
	allow(
		clippy::unwrap_used,
		clippy::expect_used,
		clippy::panic,
		clippy::float_cmp,
		clippy::str_to_string,
		clippy::cast_possible_truncation,
		clippy::cast_sign_loss,
	)
)]

// Always-compiled core a lean client (default-features = false) needs to dial a reverse tunnel; proxy side is feature-gated.
pub mod config;
pub mod error;
pub mod fs_util;
pub mod ingress;
pub mod tls;
pub mod transport;
pub mod tunnel;

// Shared PKI fixtures for unit tests; compiled only under test.
#[cfg(test)]
mod test_support;

#[cfg(feature = "proxy")]
pub mod acl;
#[cfg(feature = "proxy")]
pub mod balancer;
#[cfg(feature = "proxy")]
pub mod cache;
#[cfg(feature = "proxy")]
pub mod cache_control;
#[cfg(feature = "proxy")]
pub mod circuit;
#[cfg(feature = "proxy")]
pub mod compression;
// Shared trailing-edge debounced fs-watcher used by every hot-reload path (config/cert/trust/revocation).
#[cfg(feature = "proxy")]
pub mod fs_watch;
#[cfg(feature = "proxy")]
pub mod health;
// Non-public liveness/readiness HTTP endpoint (proxy-side; uses axum). Independent of the data plane.
#[cfg(feature = "proxy")]
pub mod health_endpoint;
#[cfg(feature = "proxy")]
pub mod metrics;
#[cfg(feature = "proxy")]
pub mod proxy;
#[cfg(feature = "proxy")]
pub mod ratelimit;
// Cleartext port-80 → HTTPS redirect listener. Proxy-side (uses axum) and independent of the main data plane.
#[cfg(feature = "proxy")]
pub mod redirect;
#[cfg(feature = "proxy")]
pub mod retry;
#[cfg(feature = "proxy")]
pub mod tracing_init;
