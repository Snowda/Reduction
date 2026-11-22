use std::sync::Arc;

use rustls::sign::CertifiedKey;

// The identity and trust of one handshake. It holds the Arcs, so no later reload can reuse their addresses.
pub struct Stamp<V: ?Sized> {
	identity: Arc<CertifiedKey>,
	trust: Arc<V>,
}

impl<V: ?Sized> Stamp<V> {
	#[must_use]
	pub const fn new(identity: Arc<CertifiedKey>, trust: Arc<V>) -> Self {
		return Self { identity, trust };
	}
}

impl<V: ?Sized> PartialEq for Stamp<V> {
	fn eq(&self, other: &Self) -> bool {
		return Arc::ptr_eq(&self.identity, &other.identity) && Arc::ptr_eq(&self.trust, &other.trust);
	}
}
