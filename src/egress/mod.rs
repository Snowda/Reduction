// Egress gateway: a CONNECT forward proxy that lets agents reach only allowlisted hosts.
pub mod allowlist;
pub mod authority;
pub mod denial;
pub mod internal;
pub mod listener;
pub mod metrics;
pub mod policy;
#[cfg(test)]
pub mod testutil;
pub mod tunnel;
pub mod uplink;
pub mod uplink_listener;
pub mod uplink_tls;

pub use denial::Denial;
pub use listener::{Gateway, spawn_egress};
