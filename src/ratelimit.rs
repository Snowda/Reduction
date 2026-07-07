use std::net::IpAddr;
use std::num::NonZeroU32;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use governor::clock::DefaultClock;
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter};

use crate::error::{ReductionError, Result};

type KeyedLimiter = RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>;

const CACHE_WINDOW: Duration = Duration::from_millis(10);

pub struct RateLimit {
    limiter: KeyedLimiter,
    allow_cache: DashMap<IpAddr, Instant>,
}

impl RateLimit {
    pub fn new(requests_per_second: u32) -> Result<Self> {
        let rps: NonZeroU32 = NonZeroU32::new(requests_per_second).ok_or_else(|| {
            ReductionError::Config("rate limit must be > 0".to_owned())
        })?;

        let quota: Quota = Quota::per_second(rps);
        let limiter: KeyedLimiter = RateLimiter::dashmap(quota);

        return Ok(Self {
            limiter,
            allow_cache: DashMap::new(),
        });
    }

    #[tracing::instrument(skip_all)]
    pub fn check(&self, key: IpAddr) -> Result<()> {
        if let Some(entry) = self.allow_cache.get(&key) {
            if entry.value().elapsed() < CACHE_WINDOW {
                return Ok(());
            }
        }

        match self.limiter.check_key(&key) {
            Ok(_) => {
                self.allow_cache.insert(key, Instant::now());
                return Ok(());
            }
            Err(_) => return Err(ReductionError::RateLimited),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_allows_within_quota() {
        let limiter: RateLimit = RateLimit::new(10).unwrap();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let result: Result<()> = limiter.check(ip);
        assert!(result.is_ok());
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
    fn test_rate_limit_zero_rps_errors() {
        let result: Result<RateLimit> = RateLimit::new(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_rate_limit_exceeds_quota() {
        let limiter: RateLimit = RateLimit::new(1).unwrap();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(limiter.check(ip).is_ok());
        // Invalidate the cache so the second check reaches governor
        limiter.allow_cache.remove(&ip);
        assert!(limiter.check(ip).is_err());
    }

    #[test]
    fn test_cache_allows_repeat_calls() {
        let limiter: RateLimit = RateLimit::new(1).unwrap();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(limiter.check(ip).is_ok());
        // Second call within cache window should be allowed via cache
        assert!(limiter.check(ip).is_ok());
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
