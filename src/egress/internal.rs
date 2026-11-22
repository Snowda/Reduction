// Addresses a tunnel must never reach: the gateway's own host and network, and every range that is
// not public unicast. The check runs on resolved addresses, so a public name cannot pivot inward.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

const V4_BITS: u32 = 32;
const V6_BITS: u32 = 128;
// The embedded IPv4 address sits in the low 32 bits of a NAT64 (64:ff9b::/96) or IPv4-compatible address.
const LOW_V4_SHIFT: u32 = 0;
// A 6to4 address (2002::/16) carries its IPv4 address in bits 16..48.
const SIX_TO_FOUR_V4_SHIFT: u32 = 80;

#[derive(Debug, Clone, Copy)]
struct V4Range {
	net: Ipv4Addr,
	prefix: u32,
}

#[derive(Debug, Clone, Copy)]
struct V6Range {
	net: Ipv6Addr,
	prefix: u32,
}

const fn v4(a: u8, b: u8, c: u8, d: u8, prefix: u32) -> V4Range {
	return V4Range { net: Ipv4Addr::new(a, b, c, d), prefix };
}

const fn v6(segments: [u16; 8], prefix: u32) -> V6Range {
	let [a, b, c, d, e, f, g, h]: [u16; 8] = segments;
	return V6Range { net: Ipv6Addr::new(a, b, c, d, e, f, g, h), prefix };
}

// IANA special-purpose IPv4 ranges (RFC 6890 and successors) that are not globally reachable unicast.
const DENIED_V4: [V4Range; 15] = [
	v4(0, 0, 0, 0, 8),
	v4(10, 0, 0, 0, 8),
	v4(100, 64, 0, 0, 10),
	v4(127, 0, 0, 0, 8),
	v4(169, 254, 0, 0, 16),
	v4(172, 16, 0, 0, 12),
	v4(192, 0, 0, 0, 24),
	v4(192, 0, 2, 0, 24),
	v4(192, 88, 99, 0, 24),
	v4(192, 168, 0, 0, 16),
	v4(198, 18, 0, 0, 15),
	v4(198, 51, 100, 0, 24),
	v4(203, 0, 113, 0, 24),
	v4(224, 0, 0, 0, 4),
	v4(240, 0, 0, 0, 4),
];

// IPv6 counterparts: unspecified, loopback, local-use NAT64, discard, documentation, ULA, link-local,
// site-local and multicast.
const DENIED_V6: [V6Range; 9] = [
	v6([0, 0, 0, 0, 0, 0, 0, 0], 128),
	v6([0, 0, 0, 0, 0, 0, 0, 1], 128),
	v6([0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48),
	v6([0x100, 0, 0, 0, 0, 0, 0, 0], 64),
	v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32),
	v6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
	v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
	v6([0xfec0, 0, 0, 0, 0, 0, 0, 0], 10),
	v6([0xff00, 0, 0, 0, 0, 0, 0, 0], 8),
];

// IPv6 ranges that embed an IPv4 address: the embedded address is checked against DENIED_V4.
// IPv4-mapped (::ffff:0:0/96) is not here: `to_canonical` folds it to IPv4 first.
const EMBEDDING_V6: [(V6Range, u32); 3] = [
	(v6([0, 0, 0, 0, 0, 0, 0, 0], 96), LOW_V4_SHIFT),
	(v6([0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 96), LOW_V4_SHIFT),
	(v6([0x2002, 0, 0, 0, 0, 0, 0, 0], 16), SIX_TO_FOUR_V4_SHIFT),
];

// A /0 shifts by the full width. `checked_shr` gives None there, and both sides become 0, so a /0 matches all.
#[inline]
fn is_in_prefix_u32(ip: u32, net: u32, prefix: u32) -> bool {
	let shift: u32 = V4_BITS - prefix;
	return ip.checked_shr(shift).unwrap_or(0) == net.checked_shr(shift).unwrap_or(0);
}

#[inline]
fn is_in_prefix_u128(ip: u128, net: u128, prefix: u32) -> bool {
	let shift: u32 = V6_BITS - prefix;
	return ip.checked_shr(shift).unwrap_or(0) == net.checked_shr(shift).unwrap_or(0);
}

fn is_internal_v4(ip: Ipv4Addr) -> bool {
	let bits: u32 = ip.to_bits();
	return DENIED_V4.iter().any(|range| is_in_prefix_u32(bits, range.net.to_bits(), range.prefix));
}

fn is_internal_v6(ip: Ipv6Addr) -> bool {
	let bits: u128 = ip.to_bits();
	if DENIED_V6.iter().any(|range| is_in_prefix_u128(bits, range.net.to_bits(), range.prefix)) {
		return true;
	}
	return EMBEDDING_V6.iter().any(|(range, shift)| {
		// The mask keeps the 32 bits at `shift`, so the conversion cannot fail.
		let embedded: u32 = u32::try_from((bits >> shift) & u128::from(u32::MAX)).unwrap_or(0);
		return is_in_prefix_u128(bits, range.net.to_bits(), range.prefix) && is_internal_v4(Ipv4Addr::from_bits(embedded));
	});
}

// True for any address a tunnel must not reach unless an operator exception covers it.
#[must_use]
pub fn is_internal(ip: IpAddr) -> bool {
	return match ip.to_canonical() {
		IpAddr::V4(v4_addr) => is_internal_v4(v4_addr),
		IpAddr::V6(v6_addr) => is_internal_v6(v6_addr),
	};
}

// The internal-range refusal plus the operator's `allow_private_cidrs` exceptions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InternalGuard {
	exceptions: Vec<IpNet>,
}

impl InternalGuard {
	#[must_use]
	pub const fn new(exceptions: Vec<IpNet>) -> Self {
		return Self { exceptions };
	}

	#[must_use]
	pub fn admits(&self, ip: IpAddr) -> bool {
		let ip: IpAddr = ip.to_canonical();
		return !is_internal(ip) || self.exceptions.iter().any(|net| net.contains(&ip));
	}
}

#[cfg(test)]
mod tests {
	use std::result::Result;
	use std::str::FromStr;

	use super::*;

	fn ip(raw: &str) -> Result<IpAddr, String> {
		return IpAddr::from_str(raw).map_err(|err| format!("parse '{raw}': {err}"));
	}

	fn net(raw: &str) -> Result<IpNet, String> {
		return IpNet::from_str(raw).map_err(|err| format!("parse '{raw}': {err}"));
	}

	#[test]
	fn internal_ranges_are_refused() -> Result<(), String> {
		let internal: [&str; 27] = [
			"0.0.0.0",
			"10.1.2.3",
			"100.64.0.1",
			"100.127.255.255",
			"127.0.0.1",
			"127.255.255.254",
			"169.254.169.254",
			"172.16.0.1",
			"172.31.255.255",
			"192.0.0.8",
			"192.0.2.1",
			"192.168.1.1",
			"198.18.0.1",
			"198.51.100.7",
			"203.0.113.9",
			"224.0.0.1",
			"255.255.255.255",
			"::",
			"::1",
			"fd00::1",
			"fe80::1",
			"ff02::1",
			"2001:db8::1",
			"::ffff:127.0.0.1",
			"::ffff:10.0.0.1",
			"64:ff9b::a00:1",
			"2002:c0a8:101::1",
		];
		internal.iter().try_for_each(|raw| {
			assert!(is_internal(ip(raw)?), "{raw} must be internal");
			return Ok::<(), String>(());
		})?;
		return Ok(());
	}

	// The edges just outside each range stay public, so the prefixes are not wider than written.
	#[test]
	fn public_addresses_pass() -> Result<(), String> {
		let public: [&str; 12] = [
			"1.1.1.1",
			"8.8.8.8",
			"100.63.255.255",
			"100.128.0.0",
			"172.15.255.255",
			"172.32.0.0",
			"192.169.0.0",
			"198.20.0.0",
			"223.255.255.255",
			"2606:4700::1111",
			"::ffff:1.1.1.1",
			"64:ff9b::808:808",
		];
		public.iter().try_for_each(|raw| {
			assert!(!is_internal(ip(raw)?), "{raw} must be public");
			return Ok::<(), String>(());
		})?;
		return Ok(());
	}

	#[test]
	fn an_exception_admits_only_its_own_range() -> Result<(), String> {
		let guard: InternalGuard = InternalGuard::new(vec![net("10.1.2.3/32")?]);
		assert!(guard.admits(ip("10.1.2.3")?), "the excepted address passes");
		assert!(guard.admits(ip("::ffff:10.1.2.3")?), "its IPv4-mapped form passes too");
		assert!(!guard.admits(ip("10.1.2.4")?), "a neighbour stays refused");
		assert!(!guard.admits(ip("127.0.0.1")?));
		assert!(guard.admits(ip("1.1.1.1")?), "public addresses need no exception");
		assert!(!InternalGuard::default().admits(ip("10.1.2.3")?), "no exceptions by default");
		return Ok(());
	}

	#[test]
	fn a_zero_prefix_matches_every_address() {
		assert!(is_in_prefix_u32(u32::MAX, 0, 0));
		assert!(is_in_prefix_u128(u128::MAX, 0, 0));
		assert!(!is_in_prefix_u32(u32::MAX, 0, 1));
	}
}
