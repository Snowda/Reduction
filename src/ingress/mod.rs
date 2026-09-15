// Plaintext UDP/TCP ingress over one QUIC+mTLS raw stream; `protocol` stays in the core for `default-features = false` backends. See PLAN_INGRESS.md.

pub mod protocol;

#[cfg(feature = "proxy")]
pub mod batch;
#[cfg(feature = "proxy")]
pub mod tcp;
#[cfg(feature = "proxy")]
pub mod udp;
