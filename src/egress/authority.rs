// The `host:port` a CONNECT names, parsed into a normalized name and a non-zero port.
use std::fmt;
use std::num::NonZeroU16;

use arrayvec::ArrayString;

use super::denial::Denial;
use crate::config::{MAX_HOST_LEN, normalize_host};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
	pub host: ArrayString<MAX_HOST_LEN>,
	pub port: NonZeroU16,
}

impl Target {
	// RFC 9110 §9.3.6: a CONNECT target is `host:port` with the port present. An IPv6 literal is a
	// well-formed target that no allowlist entry can name, so it is refused as a host, not as malformed.
	pub fn parse(authority: &str) -> Result<Self, Denial> {
		if authority.contains('@') {
			return Err(Denial::Malformed);
		}
		let Some((host, port)) = authority.rsplit_once(':') else {
			return Err(Denial::Malformed);
		};
		let port: NonZeroU16 = port.parse::<NonZeroU16>().map_err(|_| Denial::Malformed)?;
		if host.starts_with('[') && host.ends_with(']') {
			return Err(Denial::HostNotAllowed);
		}
		let host: ArrayString<MAX_HOST_LEN> = normalize_host(host).ok_or(Denial::Malformed)?;
		return Ok(Self { host, port });
	}
}

impl fmt::Display for Target {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		return write!(f, "{}:{}", self.host, self.port);
	}
}

#[cfg(test)]
mod tests {
	use std::result::Result;

	use super::*;

	fn target(authority: &str) -> Result<Target, String> {
		return Target::parse(authority).map_err(|denial| format!("parse '{authority}': {denial:?}"));
	}

	#[test]
	fn host_and_port_parse_and_normalize() -> Result<(), String> {
		let parsed: Target = target("API.Anthropic.com.:443")?;
		assert_eq!(parsed.host.as_str(), "api.anthropic.com");
		assert_eq!(parsed.port.get(), 443);
		assert_eq!(parsed.to_string(), "api.anthropic.com:443");
		assert_eq!(target("10.0.0.1:8443")?.host.as_str(), "10.0.0.1", "an IPv4 literal is a valid target name");
		assert_eq!(target("xn--bcher-kva.example:443")?.host.as_str(), "xn--bcher-kva.example");
		return Ok(());
	}

	#[test]
	fn malformed_authorities_are_bad_requests() {
		let malformed: [&str; 10] = [
			"github.com",
			"github.com:",
			"github.com:0",
			"github.com:65536",
			"github.com:https",
			":443",
			"user@github.com:443",
			"git hub.com:443",
			"bücher.example:443",
			"a..b:443",
		];
		malformed
			.iter()
			.for_each(|raw| assert_eq!(Target::parse(raw), Err(Denial::Malformed), "'{raw}' must be malformed"));
	}

	#[test]
	fn ipv6_literals_are_refused_as_hosts() {
		assert_eq!(Target::parse("[::1]:443"), Err(Denial::HostNotAllowed));
		assert_eq!(Target::parse("[2001:db8::1]:443"), Err(Denial::HostNotAllowed));
		assert_eq!(Target::parse("[::1]"), Err(Denial::Malformed), "the port is still required");
	}

	#[test]
	fn an_overlong_name_is_malformed() {
		let long: String = format!("{}:443", ["a"; MAX_HOST_LEN].join("."));
		assert_eq!(Target::parse(&long), Err(Denial::Malformed));
	}
}
