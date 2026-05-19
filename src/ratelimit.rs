use std::num::NonZeroU32;

use governor::clock::DefaultClock;
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter};

use crate::error::{ReductionError, Result};

pub type KeyedLimiter = RateLimiter<String, DashMapStateStore<String>, DefaultClock>;

pub struct RateLimit {
    limiter: KeyedLimiter,
}

impl RateLimit {
    pub fn new(requests_per_second: u32) -> Result<Self> {
        let rps: NonZeroU32 = NonZeroU32::new(requests_per_second).ok_or_else(|| {
            ReductionError::Config("rate limit must be > 0".to_string())
        })?;

        let quota: Quota = Quota::per_second(rps);
        let limiter: KeyedLimiter = RateLimiter::dashmap(quota);

        return Ok(Self { limiter });
    }

    pub fn check(&self, key: &str) -> Result<()> {
        match self.limiter.check_key(&key.to_string()) {
            Ok(_) => return Ok(()),
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
        let result: Result<()> = limiter.check("client-1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_rate_limit_different_keys_independent() {
        let limiter: RateLimit = RateLimit::new(1).unwrap();

        assert!(limiter.check("client-1").is_ok());
        assert!(limiter.check("client-2").is_ok());
    }

    #[test]
    fn test_rate_limit_zero_rps_errors() {
        let result = RateLimit::new(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_rate_limit_exceeds_quota() {
        let limiter: RateLimit = RateLimit::new(1).unwrap();

        // First should succeed
        assert!(limiter.check("client-1").is_ok());
        // Second should be rate limited (1 per second)
        assert!(limiter.check("client-1").is_err());
    }
}
