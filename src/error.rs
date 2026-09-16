use std::io;

#[derive(Debug, thiserror::Error)]
pub enum ReductionError {
	#[error("config: {0}")]
	Config(String),

	#[error("config parse: {0}")]
	ConfigParse(#[from] toml::de::Error),

	#[error("tls: {0}")]
	Tls(#[from] rustls::Error),

	#[error("identity: {0}")]
	Identity(String),

	#[error("io: {0}")]
	Io(#[from] io::Error),

	#[error("transport: {0}")]
	Transport(String),

	#[error("backend unavailable")]
	BackendUnavailable,

	#[error("queue full")]
	QueueFull,

	#[error("rate limited")]
	RateLimited,

	#[error("access denied")]
	AccessDenied,

	#[error("forward: {0}")]
	Forward(String),

	#[error("circuit open for backend {0}")]
	CircuitOpen(String),

	#[error("connect tunnel: {0}")]
	ConnectTunnel(String),

	#[error("tunnel: {0}")]
	Tunnel(String),

	// A miss on a backend with no live tunnel session — distinct from a real Tunnel failure so a
	// scale-to-zero backend's cold start is not charged as a breaker failure (findings F1/F2).
	#[error("no tunnel sessions for backend {0}")]
	NoBackendSession(String),

	#[error("ingress: {0}")]
	Ingress(String),

	#[cfg(feature = "acme")]
	#[error("acme: {0}")]
	Acme(String),
}

impl ReductionError {
	/// True for a miss that means "the backend could not be reached" — no tunnel session, a refused
	/// connect, or an exhausted permit. For a wakeable backend these are all a cold start, not a
	/// failure: the proxy parks the request (F1) and leaves the breaker closed (F2). A cold start most
	/// often surfaces as `Forward` (direct connect refused), since routing to the tunnel path requires
	/// an existing session — so keying only on `NoBackendSession` would miss the common case.
	#[must_use]
	pub const fn is_transport_miss(&self) -> bool {
		return matches!(self, Self::NoBackendSession(_) | Self::BackendUnavailable | Self::Forward(_));
	}
}

pub type Result<T> = std::result::Result<T, ReductionError>;

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_error_display_config() {
		let err: ReductionError = ReductionError::Config("bad path".to_string());
		assert_eq!(format!("{err}"), "config: bad path");
	}

	#[test]
	fn test_error_display_transport() {
		let err: ReductionError = ReductionError::Transport("connection refused".to_string());
		assert_eq!(format!("{err}"), "transport: connection refused");
	}

	#[test]
	fn test_error_display_backend_unavailable() {
		let err: ReductionError = ReductionError::BackendUnavailable;
		assert_eq!(format!("{err}"), "backend unavailable");
	}

	#[test]
	fn test_is_transport_miss_covers_cold_start_errors() {
		// The three ways "couldn't reach the backend" surfaces — all cold-start candidates (F1/F2).
		assert!(ReductionError::Forward("connect refused".to_owned()).is_transport_miss());
		assert!(ReductionError::BackendUnavailable.is_transport_miss());
		assert!(ReductionError::NoBackendSession("api".to_owned()).is_transport_miss());
		// A real failure is not a cold start and must still count.
		assert!(!ReductionError::CircuitOpen("api".to_owned()).is_transport_miss());
		assert!(!ReductionError::Identity("bad cn".to_owned()).is_transport_miss());
		assert!(!ReductionError::Config("x".to_owned()).is_transport_miss());
	}

	#[test]
	fn test_error_display_queue_full() {
		let err: ReductionError = ReductionError::QueueFull;
		assert_eq!(format!("{err}"), "queue full");
	}

	#[test]
	fn test_error_display_rate_limited() {
		let err: ReductionError = ReductionError::RateLimited;
		assert_eq!(format!("{err}"), "rate limited");
	}

	#[test]
	fn test_error_display_access_denied() {
		let err: ReductionError = ReductionError::AccessDenied;
		assert_eq!(format!("{err}"), "access denied");
	}

	#[test]
	fn test_error_display_circuit_open() {
		let err: ReductionError = ReductionError::CircuitOpen("api-1".to_string());
		assert_eq!(format!("{err}"), "circuit open for backend api-1");
	}

	#[test]
	fn test_error_display_identity() {
		let err: ReductionError = ReductionError::Identity("no common name".to_string());
		assert_eq!(format!("{err}"), "identity: no common name");
	}

	#[test]
	fn test_error_display_ingress() {
		let err: ReductionError = ReductionError::Ingress("bind udp".to_string());
		assert_eq!(format!("{err}"), "ingress: bind udp");
	}

	#[test]
	fn test_error_from_io() {
		let io_err: io::Error = io::Error::new(io::ErrorKind::NotFound, "not found");
		let err: ReductionError = ReductionError::from(io_err);
		assert!(format!("{err}").contains("not found"));
	}
}
