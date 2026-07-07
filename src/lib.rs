// Test code legitimately uses patterns the production lint gate forbids: unwrap/expect/panic to
// fail a case, exact float assertions on deterministic results (assert_eq!(weight, 1.0)),
// `&str` literals via .to_string(), and lossy casts on small known fixtures. Relax those
// restriction lints under cfg(test) only, so `cargo clippy --all-targets` runs clean while
// application code stays strictly held to the deny-level rules above.
#![cfg_attr(test, allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_cmp,
    clippy::str_to_string,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
))]

pub mod acl;
pub mod balancer;
pub mod cache;
pub mod cache_control;
pub mod circuit;
pub mod compression;
pub mod config;
pub mod error;
pub mod fs_util;
pub mod health;
pub mod metrics;
pub mod proxy;
pub mod ratelimit;
pub mod tls;
pub mod tracing_init;
pub mod transport;
pub mod tunnel;
