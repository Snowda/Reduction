use std::net::SocketAddr;

use arrayvec::ArrayString;
use serde::{Deserialize, Serialize};

// ── Ingress defaults ──

// 0 = one worker per CPU (Linux SO_REUSEPORT); ignored elsewhere. Phase 1 always runs a single
// worker regardless of this value — multi-worker fan-out is Phase 2.
pub const DEFAULT_INGRESS_WORKERS: u32 = 0;
pub const DEFAULT_RECV_BUFFER_BYTES: u32 = 8 * 1024 * 1024;
pub const DEFAULT_MAX_DATAGRAM_BYTES: u32 = 8192;
pub const DEFAULT_BATCH_MAX_DATAGRAMS: u32 = 512;
pub const DEFAULT_BATCH_MAX_BYTES: u32 = 61440;
pub const DEFAULT_LINGER_MS: u64 = 20;
pub const DEFAULT_QUEUE_DEPTH_PER_BACKEND: u32 = 4096;
// Largest possible UDP payload (65 535 − 8 UDP header − 20 IP header); max_datagram_bytes cannot
// exceed this because no UDP datagram can.
pub const MAX_UDP_DATAGRAM_BYTES: u32 = 65_507;

const fn default_ingress_workers() -> u32 {
	return DEFAULT_INGRESS_WORKERS;
}
const fn default_recv_buffer_bytes() -> u32 {
	return DEFAULT_RECV_BUFFER_BYTES;
}
const fn default_max_datagram_bytes() -> u32 {
	return DEFAULT_MAX_DATAGRAM_BYTES;
}
const fn default_batch_max_datagrams() -> u32 {
	return DEFAULT_BATCH_MAX_DATAGRAMS;
}
const fn default_batch_max_bytes() -> u32 {
	return DEFAULT_BATCH_MAX_BYTES;
}
const fn default_linger_ms() -> u64 {
	return DEFAULT_LINGER_MS;
}
const fn default_queue_depth_per_backend() -> u32 {
	return DEFAULT_QUEUE_DEPTH_PER_BACKEND;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IngressProtocol {
	Udp,
	Tcp,
}

// A plaintext datagram/stream ingress listener. Presence of any `[[ingress]]` enables the mode. UDP
// fields drive Phase 1; `max_connections`/`idle_timeout_secs` are TCP-only (Phase 3) and optional.
// `id` is required in Phase 1 (the plan's "default to client cert CN" needs identity plumbing the
// config layer does not have; deferred to a later phase).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressConfig {
	pub id: ArrayString<64>,
	pub protocol: IngressProtocol,
	pub listen: SocketAddr,
	#[serde(default = "default_ingress_workers")]
	pub workers: u32,
	#[serde(default = "default_recv_buffer_bytes")]
	pub recv_buffer_bytes: u32,
	#[serde(default = "default_max_datagram_bytes")]
	pub max_datagram_bytes: u32,
	pub backend_ids: Vec<ArrayString<256>>,
	#[serde(default = "default_batch_max_datagrams")]
	pub batch_max_datagrams: u32,
	#[serde(default = "default_batch_max_bytes")]
	pub batch_max_bytes: u32,
	#[serde(default = "default_linger_ms")]
	pub linger_ms: u64,
	#[serde(default = "default_queue_depth_per_backend")]
	pub queue_depth_per_backend: u32,
	// TCP ingress (Phase 3) only; ignored for UDP.
	#[serde(default)]
	pub max_connections: Option<u32>,
	#[serde(default)]
	pub idle_timeout_secs: Option<u64>,
}

// Whether a listen address sits on a private/internal range. A non-private (routable) ingress listen
// address must be paired with an `[access]` allowlist, since ingress relaxes the mTLS-only rule.
pub const fn is_private_listen_addr(ip: std::net::IpAddr) -> bool {
	return match ip {
		std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
		std::net::IpAddr::V6(v6) => {
			let octets: [u8; 16] = v6.octets();
			// fc00::/7 (unique local) or fe80::/10 (link-local), plus loopback ::1.
			v6.is_loopback() || (octets[0] & 0xfe) == 0xfc || (octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80)
		}
	};
}

#[cfg(test)]
mod tests {
	use super::*;

	// ── IngressConfig ──

	#[test]
	fn ingress_config_parses_with_field_defaults() {
		let parsed: IngressConfig = toml::from_str(
			"id = \"site-dublin-udp\"\nprotocol = \"udp\"\nlisten = \"10.20.0.1:5000\"\nbackend_ids = [\"ingest-a\"]",
		)
		.unwrap();
		assert_eq!(parsed.id.as_str(), "site-dublin-udp");
		assert_eq!(parsed.protocol, IngressProtocol::Udp);
		assert_eq!(parsed.listen, "10.20.0.1:5000".parse().unwrap());
		assert_eq!(parsed.workers, DEFAULT_INGRESS_WORKERS);
		assert_eq!(parsed.recv_buffer_bytes, DEFAULT_RECV_BUFFER_BYTES);
		assert_eq!(parsed.max_datagram_bytes, DEFAULT_MAX_DATAGRAM_BYTES);
		assert_eq!(parsed.batch_max_datagrams, DEFAULT_BATCH_MAX_DATAGRAMS);
		assert_eq!(parsed.batch_max_bytes, DEFAULT_BATCH_MAX_BYTES);
		assert_eq!(parsed.linger_ms, DEFAULT_LINGER_MS);
		assert_eq!(parsed.queue_depth_per_backend, DEFAULT_QUEUE_DEPTH_PER_BACKEND);
		assert!(parsed.max_connections.is_none());
		assert!(parsed.idle_timeout_secs.is_none());
	}

	#[test]
	fn ingress_config_rejects_unknown_field() {
		let toml_str: &str =
			"id = \"x\"\nprotocol = \"udp\"\nlisten = \"10.0.0.1:5000\"\nbackend_ids = [\"a\"]\nlingerr_ms = 5";
		assert!(
			toml::from_str::<IngressConfig>(toml_str).is_err(),
			"a misspelled ingress field must not silently default"
		);
	}

	#[test]
	fn ingress_config_parses_tcp_only_fields() {
		let parsed: IngressConfig = toml::from_str(
			"id = \"site-tcp\"\nprotocol = \"tcp\"\nlisten = \"10.20.0.1:5001\"\nbackend_ids = [\"ingest-a\"]\nmax_connections = 10000\nidle_timeout_secs = 300",
		)
		.unwrap();
		assert_eq!(parsed.protocol, IngressProtocol::Tcp);
		assert_eq!(parsed.max_connections, Some(10000));
		assert_eq!(parsed.idle_timeout_secs, Some(300));
	}

	#[test]
	fn is_private_listen_addr_classifies_ranges() {
		use std::net::IpAddr;
		assert!(is_private_listen_addr("10.20.0.1".parse::<IpAddr>().unwrap()));
		assert!(is_private_listen_addr("192.168.1.1".parse::<IpAddr>().unwrap()));
		assert!(is_private_listen_addr("172.16.0.1".parse::<IpAddr>().unwrap()));
		assert!(is_private_listen_addr("127.0.0.1".parse::<IpAddr>().unwrap()));
		assert!(is_private_listen_addr("fd00::1".parse::<IpAddr>().unwrap()));
		assert!(is_private_listen_addr("fe80::1".parse::<IpAddr>().unwrap()));
		assert!(is_private_listen_addr("::1".parse::<IpAddr>().unwrap()));
		assert!(!is_private_listen_addr("8.8.8.8".parse::<IpAddr>().unwrap()));
		assert!(!is_private_listen_addr(
			"2001:4860:4860::8888".parse::<IpAddr>().unwrap()
		));
	}
}
