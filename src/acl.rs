use std::net::{IpAddr, Ipv4Addr};

use ipnet::{IpNet, Ipv4Net};
use tracing::warn;

use crate::error::{ReductionError, Result};

// Number of leading bits in the IPv4-mapped IPv6 block ::ffff:0:0/96. A V6 CIDR whose network
// address is IPv4-mapped and whose prefix covers this block denotes an IPv4 range.
const IPV4_MAPPED_PREFIX_BITS: u8 = 96;

// Fold an IPv4-mapped IPv6 CIDR (::ffff:a.b.c.d/N, N >= 96) to its native IPv4 form a.b.c.d/(N-96),
// so a rule written in mapped notation matches the canonicalized peer addresses check() compares
// against. Non-mapped nets (any V4, or a real V6 range) pass through unchanged.
const fn canonicalize_net(net: IpNet) -> IpNet {
	let IpNet::V6(v6) = net else {
		return net;
	};
	let prefix: u8 = v6.prefix_len();
	if prefix < IPV4_MAPPED_PREFIX_BITS {
		return net;
	}
	let mapped: Ipv4Addr = match v6.addr().to_ipv4_mapped() {
		Some(addr) => addr,
		None => return net,
	};
	return match Ipv4Net::new(mapped, prefix - IPV4_MAPPED_PREFIX_BITS) {
		Ok(v4) => IpNet::V4(v4),
		Err(_) => net,
	};
}

#[derive(Clone)]
pub struct AccessControl {
	allow: Vec<IpNet>,
	deny: Vec<IpNet>,
}

impl AccessControl {
	#[must_use]
	pub fn new(allow: Vec<IpNet>, deny: Vec<IpNet>) -> Self {
		let allow: Vec<IpNet> = allow.into_iter().map(canonicalize_net).collect();
		let deny: Vec<IpNet> = deny.into_iter().map(canonicalize_net).collect();
		return Self { allow, deny };
	}

	pub fn check(&self, ip: IpAddr) -> Result<()> {
		// A dual-stack [::] listener surfaces IPv4 peers as IPv4-mapped IPv6 (::ffff:a.b.c.d).
		// IpNet::contains matches only within a family, so an IPv4 CIDR would never see the mapped
		// form: deny would fail open and allow would reject everyone. Fold it back to IPv4 first.
		let ip: IpAddr = ip.to_canonical();
		// Deny takes precedence; an allow list, when present, then makes membership mandatory.
		if self.is_denied(ip) {
			warn!(%ip, "access denied: in deny list");
			return Err(ReductionError::AccessDenied);
		}
		if !self.allow.is_empty() && !self.is_allowed(ip) {
			warn!(%ip, "access denied: not in allow list");
			return Err(ReductionError::AccessDenied);
		}
		return Ok(());
	}

	#[inline]
	fn is_allowed(&self, ip: IpAddr) -> bool {
		return self.allow.iter().any(|net| net.contains(&ip));
	}

	#[inline]
	fn is_denied(&self, ip: IpAddr) -> bool {
		return self.deny.iter().any(|net| net.contains(&ip));
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn parse_net(s: &str) -> IpNet {
		return s.parse().unwrap();
	}

	#[test]
	fn test_disabled_allows_everything() {
		let acl: AccessControl = AccessControl::new(vec![], vec![]);
		assert!(acl.check("10.0.0.1".parse().unwrap()).is_ok());
		assert!(acl.check("192.168.1.1".parse().unwrap()).is_ok());
	}

	#[test]
	fn test_allowlist_permits_matching_ip() {
		let acl: AccessControl = AccessControl::new(vec![parse_net("10.0.0.0/24")], vec![]);
		assert!(acl.check("10.0.0.1".parse().unwrap()).is_ok());
		assert!(acl.check("10.0.0.254".parse().unwrap()).is_ok());
	}

	#[test]
	fn test_allowlist_rejects_non_matching_ip() {
		let acl: AccessControl = AccessControl::new(vec![parse_net("10.0.0.0/24")], vec![]);
		assert!(acl.check("192.168.1.1".parse().unwrap()).is_err());
	}

	#[test]
	fn test_denylist_blocks_matching_ip() {
		let acl: AccessControl = AccessControl::new(vec![], vec![parse_net("10.0.0.0/24")]);
		assert!(acl.check("10.0.0.1".parse().unwrap()).is_err());
	}

	#[test]
	fn test_denylist_allows_non_matching_ip() {
		let acl: AccessControl = AccessControl::new(vec![], vec![parse_net("10.0.0.0/24")]);
		assert!(acl.check("192.168.1.1".parse().unwrap()).is_ok());
	}

	#[test]
	fn test_both_deny_takes_precedence() {
		let acl: AccessControl = AccessControl::new(vec![parse_net("10.0.0.0/16")], vec![parse_net("10.0.1.0/24")]);
		// In allow range but also in deny range — deny wins
		assert!(acl.check("10.0.1.5".parse().unwrap()).is_err());
		// In allow range, not in deny range — allowed
		assert!(acl.check("10.0.0.5".parse().unwrap()).is_ok());
	}

	#[test]
	fn test_both_rejects_unlisted() {
		let acl: AccessControl = AccessControl::new(vec![parse_net("10.0.0.0/24")], vec![parse_net("192.168.0.0/16")]);
		// Not in either list — default-deny
		assert!(acl.check("172.16.0.1".parse().unwrap()).is_err());
	}

	#[test]
	fn test_single_host_cidr() {
		let acl: AccessControl = AccessControl::new(vec![parse_net("10.0.0.1/32")], vec![]);
		assert!(acl.check("10.0.0.1".parse().unwrap()).is_ok());
		assert!(acl.check("10.0.0.2".parse().unwrap()).is_err());
	}

	#[test]
	fn test_ipv6_allowlist() {
		let acl: AccessControl = AccessControl::new(vec![parse_net("fd00::/64")], vec![]);
		assert!(acl.check("fd00::1".parse().unwrap()).is_ok());
		assert!(acl.check("fe80::1".parse().unwrap()).is_err());
	}

	#[test]
	fn test_mixed_ipv4_ipv6() {
		let acl: AccessControl = AccessControl::new(vec![parse_net("10.0.0.0/8"), parse_net("fd00::/64")], vec![]);
		assert!(acl.check("10.1.2.3".parse().unwrap()).is_ok());
		assert!(acl.check("fd00::1".parse().unwrap()).is_ok());
		assert!(acl.check("192.168.1.1".parse().unwrap()).is_err());
	}

	#[test]
	fn test_multiple_allow_ranges() {
		let acl: AccessControl = AccessControl::new(vec![parse_net("10.0.0.0/24"), parse_net("172.16.0.0/12")], vec![]);
		assert!(acl.check("10.0.0.5".parse().unwrap()).is_ok());
		assert!(acl.check("172.20.1.1".parse().unwrap()).is_ok());
		assert!(acl.check("192.168.1.1".parse().unwrap()).is_err());
	}

	#[test]
	fn test_denylist_blocks_ipv4_mapped_ipv6() {
		// Regression: on a [::] listener a 10.x peer arrives as ::ffff:10.0.0.1. Before canonicalizing
		// this fell open (V4 CIDR never matched the mapped V6 form). It must be denied, same as bare.
		let acl: AccessControl = AccessControl::new(vec![], vec![parse_net("10.0.0.0/8")]);
		let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
		let bare: IpAddr = "10.0.0.1".parse().unwrap();
		assert!(acl.check(mapped).is_err(), "mapped IPv4 must hit the deny CIDR");
		assert_eq!(acl.check(mapped).is_err(), acl.check(bare).is_err());
	}

	#[test]
	fn test_allowlist_admits_ipv4_mapped_ipv6() {
		// Mirror: the mapped form must pass an IPv4 allow CIDR, not be default-denied as unmatched.
		let acl: AccessControl = AccessControl::new(vec![parse_net("10.0.0.0/8")], vec![]);
		let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
		let bare: IpAddr = "10.0.0.1".parse().unwrap();
		assert!(acl.check(mapped).is_ok(), "mapped IPv4 must satisfy the allow CIDR");
		assert_eq!(acl.check(mapped).is_ok(), acl.check(bare).is_ok());
	}

	#[test]
	fn test_canonicalize_net_folds_mapped_v6_to_v4() {
		// ::ffff:10.0.0.0/104 is the IPv4 range 10.0.0.0/8 in mapped notation (104 - 96 = 8).
		assert_eq!(
			canonicalize_net(parse_net("::ffff:10.0.0.0/104")),
			parse_net("10.0.0.0/8")
		);
		// Native V4 and a real V6 range are left untouched.
		assert_eq!(canonicalize_net(parse_net("10.0.0.0/8")), parse_net("10.0.0.0/8"));
		assert_eq!(canonicalize_net(parse_net("fd00::/64")), parse_net("fd00::/64"));
	}

	#[test]
	fn test_config_cidr_in_mapped_notation_matches_bare_v4() {
		// A deny rule written as mapped V6 must block a bare IPv4 peer. A bare V4 peer is unchanged by
		// peer-side canonicalization, so this passes only if new() folded the CIDR to native V4.
		let acl: AccessControl = AccessControl::new(vec![], vec![parse_net("::ffff:10.0.0.0/104")]);
		assert!(acl.check("10.0.0.1".parse().unwrap()).is_err());
		assert!(acl.check("11.0.0.1".parse().unwrap()).is_ok());
	}
}
