use std::net::IpAddr;
use std::num::NonZeroU32;

use governor::clock::DefaultClock;
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter};

use crate::error::{ReductionError, Result};

type KeyedLimiter = RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>;

pub struct RateLimit {
	limiter: KeyedLimiter,
}

impl RateLimit {
	pub fn new(requests_per_second: u32) -> Result<Self> {
		let rps: NonZeroU32 = NonZeroU32::new(requests_per_second)
			.ok_or_else(|| ReductionError::Config("rate limit must be > 0".to_owned()))?;

		let quota: Quota = Quota::per_second(rps);
		let limiter: KeyedLimiter = RateLimiter::dashmap(quota);

		return Ok(Self { limiter });
	}

	// Consults governor's lock-free token bucket directly — the only arbiter. An earlier per-IP allow
	// cache let a burst bypass the limit entirely.
	#[tracing::instrument(skip_all)]
	pub fn check(&self, key: IpAddr) -> Result<()> {
		// Fold IPv4-mapped IPv6 (::ffff:a.b.c.d) back to IPv4 so one host keys one bucket across listener families.
		let key: IpAddr = key.to_canonical();
		return match self.limiter.check_key(&key) {
			Ok(_) => Ok(()),
			Err(_) => Err(ReductionError::RateLimited),
		};
	}

	// Drop keyed entries that have fully replenished (now indistinguishable from never-seen). governor's
	// DashMap store never reclaims them itself; this sweep bounds the map to the active IP set. Safe under check().
	pub fn retain_recent(&self) {
		self.limiter.retain_recent();
	}

	// Keyed entry count. Diagnostic: drives the GC sweep's before/after log and lets tests assert shrink.
	#[must_use]
	pub fn len(&self) -> usize {
		return self.limiter.len();
	}

	#[must_use]
	pub fn is_empty(&self) -> bool {
		return self.limiter.len() == 0;
	}
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use tokio::time::sleep;

	use super::*;

	#[test]
	fn test_rate_limit_allows_within_quota() {
		let limiter: RateLimit = RateLimit::new(10).unwrap();
		let ip: IpAddr = "10.0.0.1".parse().unwrap();
		let result: Result<()> = limiter.check(ip);
		assert!(result.is_ok());
	}

	#[test]
	fn test_distinct_ips_each_create_an_entry() {
		let limiter: RateLimit = RateLimit::new(1000).unwrap();
		assert!(limiter.is_empty());
		for octet in 1..=30u8 {
			let _ = limiter.check(IpAddr::from([10, 0, 0, octet]));
		}
		assert_eq!(limiter.len(), 30, "each distinct source IP holds its own keyed entry");
	}

	#[tokio::test]
	async fn test_retain_recent_prunes_replenished_entries() {
		// Once an entry's quota has fully replenished it is indistinguishable from a never-seen key and
		// the sweep must drop it; without retain_recent the map would stay at 30.
		let limiter: RateLimit = RateLimit::new(1000).unwrap();
		for octet in 1..=30u8 {
			let _ = limiter.check(IpAddr::from([10, 0, 0, octet]));
		}
		assert_eq!(limiter.len(), 30, "precondition: entries populated");

		// At 1000 rps a single consumed cell replenishes in ~1ms; 100ms is a wide margin.
		sleep(Duration::from_millis(100)).await;
		limiter.retain_recent();

		assert_eq!(
			limiter.len(),
			0,
			"fully-replenished entries must be swept, bounding the map"
		);
	}

	#[tokio::test]
	async fn test_retain_recent_keeps_active_entry() {
		// Surgical: an entry still holding depleted state (a very slow quota just consumed) survives
		// the sweep, so GC never drops a limiter that is still actively throttling a client.
		let limiter: RateLimit = RateLimit::new(1).unwrap();
		let ip: IpAddr = IpAddr::from([10, 0, 0, 1]);
		assert!(limiter.check(ip).is_ok());
		assert!(limiter.check(ip).is_err(), "second immediate request is throttled");

		// No wait: the 1 rps quota has not replenished, so the entry is still meaningful and kept.
		limiter.retain_recent();
		assert_eq!(limiter.len(), 1, "an entry still throttling a client must not be swept");
	}

	#[test]
	fn test_rate_limit_different_keys_independent() {
		let limiter: RateLimit = RateLimit::new(1).unwrap();
		let ip1: IpAddr = "10.0.0.1".parse().unwrap();
		let ip2: IpAddr = "10.0.0.2".parse().unwrap();

		assert!(limiter.check(ip1).is_ok());
		assert!(limiter.check(ip2).is_ok());
	}

	#[test]
	fn test_rate_limit_immediate_burst_rejected() {
		// Regression: a burst inside the old 10ms allow-cache window bypassed the limiter
		// entirely. At 1 rps the second immediate request must be rejected, not cached-allowed.
		let limiter: RateLimit = RateLimit::new(1).unwrap();
		let ip: IpAddr = "10.0.0.1".parse().unwrap();

		assert!(limiter.check(ip).is_ok());
		assert!(limiter.check(ip).is_err());
	}

	#[test]
	fn test_ipv4_mapped_ipv6_shares_bucket_with_bare_ipv4() {
		// Regression: ::ffff:10.0.0.1 and 10.0.0.1 must key the same bucket. Before canonicalizing
		// they were distinct keys, so one host got two buckets (double quota) across listener families.
		let limiter: RateLimit = RateLimit::new(1).unwrap();
		let bare: IpAddr = "10.0.0.1".parse().unwrap();
		let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();

		assert!(limiter.check(bare).is_ok());
		assert!(
			limiter.check(mapped).is_err(),
			"mapped form must draw on the same depleted bucket"
		);
		assert_eq!(limiter.len(), 1, "one host must hold exactly one keyed entry");
	}

	#[test]
	fn test_rate_limit_zero_rps_errors() {
		let result: Result<RateLimit> = RateLimit::new(0);
		assert!(result.is_err());
	}

	#[test]
	fn test_rate_limit_exceeds_quota() {
		let limiter: RateLimit = RateLimit::new(1).unwrap();
		let ip: IpAddr = "10.0.0.1".parse().unwrap();

		assert!(limiter.check(ip).is_ok());
		assert!(limiter.check(ip).is_err());
	}

	#[test]
	fn test_high_rate_limit_allows_many() {
		let limiter: RateLimit = RateLimit::new(u32::MAX).unwrap();
		let ip: IpAddr = "10.0.0.1".parse().unwrap();

		for _ in 0..100 {
			assert!(limiter.check(ip).is_ok());
		}
	}
}
