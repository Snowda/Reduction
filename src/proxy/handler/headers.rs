use std::net::IpAddr;

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use opentelemetry::propagation::{Extractor, Injector};

use super::{HEADER_CLIENT_ID, HEADER_CLIENT_SPKI, HEADER_X_FORWARDED_FOR, HEADER_X_REAL_IP};
use crate::error::{ReductionError, Result};
use crate::tls::PeerIdentity;

// RFC 9110 §7.6.1 connection-specific fields: they describe one HTTP transport hop and must not be relayed.
// `Connection` may also nominate arbitrary field names, removed by strip_hop_by_hop_headers below.
const HOP_BY_HOP_HEADERS: [&str; 10] = [
	"connection",
	"keep-alive",
	"proxy-authenticate",
	"proxy-authorization",
	"proxy-connection",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
	"http2-settings",
];

// Strip any client-supplied identity headers (anti-spoof, unconditional so a forgery never survives), then
// inject the handshake-proven values. Insert (not append) guarantees a single value. Shared by pool and tunnel paths.
pub fn apply_identity_headers(headers: &mut axum::http::HeaderMap, identity: Option<&PeerIdentity>) -> Result<()> {
	headers.remove(HEADER_CLIENT_ID);
	headers.remove(HEADER_CLIENT_SPKI);

	let Some(identity) = identity else {
		return Ok(());
	};

	let cn: HeaderValue = HeaderValue::from_str(identity.common_name.as_str())
		.map_err(|e| ReductionError::Forward(format!("invalid client-id header: {e}")))?;
	let spki: HeaderValue = HeaderValue::from_str(identity.spki_hex().as_str())
		.map_err(|e| ReductionError::Forward(format!("invalid client-spki header: {e}")))?;
	headers.insert(HEADER_CLIENT_ID, cn);
	headers.insert(HEADER_CLIENT_SPKI, spki);
	return Ok(());
}

// Strip any client-supplied forwarding metadata (anti-spoof), then set X-Forwarded-For / X-Real-IP to the
// real peer IP. X-Forwarded-Proto/-Host and Forwarded are dropped unreplaced (Reduction doesn't vouch for them).
pub fn apply_forwarded_headers(headers: &mut axum::http::HeaderMap, client_ip: IpAddr) -> Result<()> {
	headers.remove(HEADER_X_FORWARDED_FOR);
	headers.remove("x-forwarded-proto");
	headers.remove("x-forwarded-host");
	headers.remove("forwarded");
	headers.remove(HEADER_X_REAL_IP);

	let ip: HeaderValue = HeaderValue::from_str(&client_ip.to_string())
		.map_err(|e| ReductionError::Forward(format!("invalid client-ip header: {e}")))?;
	headers.insert(HEADER_X_FORWARDED_FOR, ip.clone());
	headers.insert(HEADER_X_REAL_IP, ip);
	return Ok(());
}

// Remove fields bound to the current HTTP connection. Besides the fixed RFC set, each `Connection` value can
// nominate comma-separated field names (e.g. `Connection: keep-alive, x-debug`); gather those before removing
// Connection itself, so neither requests nor responses smuggle connection-local state across the boundary.
pub fn strip_hop_by_hop_headers(headers: &mut HeaderMap) {
	let connection_nominated: Vec<HeaderName> = headers
		.get_all("connection")
		.iter()
		.filter_map(|value| value.to_str().ok())
		.flat_map(|value| value.split(','))
		.filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
		.collect();

	for name in HOP_BY_HOP_HEADERS {
		headers.remove(name);
	}
	for name in connection_nominated {
		headers.remove(name);
	}
}

// Adapts axum HeaderMap for OTel trace context extraction from inbound requests.
pub struct HeaderExtractor<'a>(pub &'a axum::http::HeaderMap);

impl Extractor for HeaderExtractor<'_> {
	fn get(&self, key: &str) -> Option<&str> {
		return self.0.get(key).and_then(|v| v.to_str().ok());
	}

	fn keys(&self) -> Vec<&str> {
		return self.0.keys().map(|k| k.as_str()).collect();
	}
}

// Adapts axum HeaderMap for OTel trace context injection into outbound requests.
pub struct HeaderInjector<'a>(pub &'a mut axum::http::HeaderMap);

impl Injector for HeaderInjector<'_> {
	fn set(&mut self, key: &str, value: String) {
		if let Ok(name) = HeaderName::from_bytes(key.as_bytes())
			&& let Ok(val) = HeaderValue::from_str(&value)
		{
			self.0.insert(name, val);
		}
	}
}

#[cfg(test)]
mod tests {
	use axum::http::header::CONTENT_LENGTH;

	use super::*;

	// Build a real PeerIdentity from an rcgen leaf with the given CN, exercising the same parse path
	// production uses (no hand-constructed identity).
	fn identity_with_cn(cn: &str) -> PeerIdentity {
		let key = rcgen::KeyPair::generate().unwrap();
		let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
		params
			.distinguished_name
			.push(rcgen::DnType::CommonName, rcgen::DnValue::Utf8String(cn.to_string()));
		let cert = params.self_signed(&key).unwrap();
		return PeerIdentity::from_leaf_der(cert.der()).unwrap();
	}

	#[test]
	fn test_apply_identity_headers_injects_cn_and_spki() {
		let identity = identity_with_cn("device-42");
		let mut headers = axum::http::HeaderMap::new();
		apply_identity_headers(&mut headers, Some(&identity)).unwrap();
		assert_eq!(headers.get(HEADER_CLIENT_ID).unwrap(), "device-42");
		// Independent hex oracle: encode the raw SPKI bytes ourselves and compare.
		let expected_hex: String = identity.spki_sha256.iter().map(|b| format!("{b:02x}")).collect();
		assert_eq!(headers.get(HEADER_CLIENT_SPKI).unwrap(), expected_hex.as_str());
	}

	#[test]
	fn test_apply_identity_headers_replaces_forged_values() {
		let identity = identity_with_cn("device-42");
		let mut headers = axum::http::HeaderMap::new();
		headers.insert(HEADER_CLIENT_ID, HeaderValue::from_static("attacker"));
		headers.insert(HEADER_CLIENT_SPKI, HeaderValue::from_static("deadbeef"));
		apply_identity_headers(&mut headers, Some(&identity)).unwrap();
		assert_eq!(headers.get(HEADER_CLIENT_ID).unwrap(), "device-42");
		assert_ne!(headers.get(HEADER_CLIENT_SPKI).unwrap(), "deadbeef");
	}

	#[test]
	fn test_apply_identity_headers_no_duplicates() {
		let identity = identity_with_cn("device-42");
		let mut headers = axum::http::HeaderMap::new();
		// A client that appends the header twice must not end up with three values after injection.
		headers.append(HEADER_CLIENT_ID, HeaderValue::from_static("forged-a"));
		headers.append(HEADER_CLIENT_ID, HeaderValue::from_static("forged-b"));
		apply_identity_headers(&mut headers, Some(&identity)).unwrap();
		assert_eq!(headers.get_all(HEADER_CLIENT_ID).iter().count(), 1);
		assert_eq!(headers.get_all(HEADER_CLIENT_SPKI).iter().count(), 1);
	}

	#[test]
	fn test_apply_identity_headers_none_strips_forged() {
		let mut headers = axum::http::HeaderMap::new();
		headers.insert(HEADER_CLIENT_ID, HeaderValue::from_static("attacker"));
		headers.insert(HEADER_CLIENT_SPKI, HeaderValue::from_static("deadbeef"));
		apply_identity_headers(&mut headers, None).unwrap();
		assert!(headers.get(HEADER_CLIENT_ID).is_none());
		assert!(headers.get(HEADER_CLIENT_SPKI).is_none());
	}

	#[test]
	fn test_apply_forwarded_headers_sets_client_ip() {
		let mut headers = axum::http::HeaderMap::new();
		let ip: IpAddr = "203.0.113.7".parse().unwrap();
		apply_forwarded_headers(&mut headers, ip).unwrap();
		assert_eq!(headers.get(HEADER_X_FORWARDED_FOR).unwrap(), "203.0.113.7");
		assert_eq!(headers.get(HEADER_X_REAL_IP).unwrap(), "203.0.113.7");
	}

	#[test]
	fn test_apply_forwarded_headers_replaces_spoofed() {
		let mut headers = axum::http::HeaderMap::new();
		// A client that pre-sets a forged chain must not have it survive.
		headers.append(HEADER_X_FORWARDED_FOR, HeaderValue::from_static("1.2.3.4"));
		headers.append(HEADER_X_FORWARDED_FOR, HeaderValue::from_static("5.6.7.8"));
		headers.insert(HEADER_X_REAL_IP, HeaderValue::from_static("9.9.9.9"));
		let ip: IpAddr = "10.0.0.1".parse().unwrap();
		apply_forwarded_headers(&mut headers, ip).unwrap();
		assert_eq!(headers.get_all(HEADER_X_FORWARDED_FOR).iter().count(), 1);
		assert_eq!(headers.get(HEADER_X_FORWARDED_FOR).unwrap(), "10.0.0.1");
		assert_eq!(headers.get(HEADER_X_REAL_IP).unwrap(), "10.0.0.1");
	}

	#[test]
	fn test_apply_forwarded_headers_strips_proto_host_forwarded() {
		let mut headers = axum::http::HeaderMap::new();
		headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));
		headers.insert("x-forwarded-host", HeaderValue::from_static("evil.example"));
		headers.insert("forwarded", HeaderValue::from_static("for=1.2.3.4"));
		apply_forwarded_headers(&mut headers, "10.0.0.1".parse().unwrap()).unwrap();
		// Dropped without a proxy-vouched replacement.
		assert!(headers.get("x-forwarded-proto").is_none());
		assert!(headers.get("x-forwarded-host").is_none());
		assert!(headers.get("forwarded").is_none());
	}

	#[test]
	fn test_apply_forwarded_headers_ipv6() {
		let mut headers = axum::http::HeaderMap::new();
		let ip: IpAddr = "2001:db8::1".parse().unwrap();
		apply_forwarded_headers(&mut headers, ip).unwrap();
		assert_eq!(headers.get(HEADER_X_FORWARDED_FOR).unwrap(), "2001:db8::1");
	}

	#[test]
	fn test_strip_hop_by_hop_headers_removes_standard_and_nominated_fields() {
		let mut headers = HeaderMap::new();
		headers.insert(
			"connection",
			HeaderValue::from_static("keep-alive, x-debug, content-length"),
		);
		headers.append("connection", HeaderValue::from_static("x-another-hop"));
		headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
		headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
		headers.insert("x-debug", HeaderValue::from_static("private"));
		headers.insert("x-another-hop", HeaderValue::from_static("also-private"));
		headers.insert(CONTENT_LENGTH, HeaderValue::from_static("42"));
		headers.insert("range", HeaderValue::from_static("bytes=0-41"));
		headers.insert("x-app", HeaderValue::from_static("preserve"));

		strip_hop_by_hop_headers(&mut headers);

		for name in [
			"connection",
			"keep-alive",
			"transfer-encoding",
			"x-debug",
			"x-another-hop",
			"content-length",
		] {
			assert!(!headers.contains_key(name), "{name} must not cross a proxy hop");
		}
		assert_eq!(headers.get("range").unwrap(), "bytes=0-41");
		assert_eq!(headers.get("x-app").unwrap(), "preserve");
	}

	#[test]
	fn test_trusted_headers_are_rebuilt_after_connection_sanitization() {
		let mut headers = HeaderMap::new();
		headers.insert(
			"connection",
			HeaderValue::from_static("x-forwarded-for, x-real-ip, x-reduction-client-id"),
		);
		headers.insert(HEADER_X_FORWARDED_FOR, HeaderValue::from_static("spoofed"));
		headers.insert(HEADER_X_REAL_IP, HeaderValue::from_static("spoofed"));
		headers.insert(HEADER_CLIENT_ID, HeaderValue::from_static("spoofed"));

		strip_hop_by_hop_headers(&mut headers);
		let identity = identity_with_cn("device-1");
		apply_forwarded_headers(&mut headers, "203.0.113.8".parse().unwrap()).unwrap();
		apply_identity_headers(&mut headers, Some(&identity)).unwrap();

		assert_eq!(headers.get(HEADER_X_FORWARDED_FOR).unwrap(), "203.0.113.8");
		assert_eq!(headers.get(HEADER_X_REAL_IP).unwrap(), "203.0.113.8");
		assert_eq!(headers.get(HEADER_CLIENT_ID).unwrap(), "device-1");
	}

	#[test]
	fn test_apply_identity_headers_distinct_devices_distinct_spki() {
		let a = identity_with_cn("device-a");
		let b = identity_with_cn("device-b");
		let mut ha = axum::http::HeaderMap::new();
		let mut hb = axum::http::HeaderMap::new();
		apply_identity_headers(&mut ha, Some(&a)).unwrap();
		apply_identity_headers(&mut hb, Some(&b)).unwrap();
		assert_ne!(ha.get(HEADER_CLIENT_SPKI).unwrap(), hb.get(HEADER_CLIENT_SPKI).unwrap());
	}
}
