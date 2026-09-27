pub mod quic;
#[cfg(feature = "proxy")]
pub mod quic_listener;
#[cfg(feature = "proxy")]
pub mod tcp;

use std::net::SocketAddr;
use std::ops::Deref;

use crate::tls::PeerIdentity;

// Per-connection info for axum ConnectInfo: peer address + handshake-proven mTLS identity
// (None only when the leaf cert had no parseable CN).
#[derive(Debug, Clone, Copy)]
pub struct ConnectAddr(pub SocketAddr, pub Option<PeerIdentity>);

impl Deref for ConnectAddr {
	type Target = SocketAddr;
	fn deref(&self) -> &Self::Target {
		return &self.0;
	}
}
