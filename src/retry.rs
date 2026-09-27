use std::time::Duration;

use crate::config::RetryConfig;

// Exponential backoff with pseudo-random jitter: min(base_delay * 2^attempt, max_delay) +
// rand(0..jitter). Shared by the proxy forward-retry loop and the ingress backend-stream reconnect
// loop so both pace retries identically and jitter decorrelates concurrent retriers (no thundering
// herd when a shared backend fails).
#[must_use]
pub fn backoff_delay(attempt: u32, config: &RetryConfig) -> Duration {
	let exp_delay_ms: u64 = config
		.base_delay_ms
		.saturating_mul(1u64.checked_shl(attempt).unwrap_or(u64::MAX))
		.min(config.max_delay_ms);

	let jitter_ms: u64 = if config.jitter_ms > 0 {
		// random_range yields [0, jitter_ms).
		rand::random_range(0..config.jitter_ms)
	} else {
		0
	};

	return Duration::from_millis(exp_delay_ms.saturating_add(jitter_ms));
}

#[cfg(test)]
mod tests {
	use super::*;

	fn config(base_delay_ms: u64, max_delay_ms: u64, jitter_ms: u64) -> RetryConfig {
		return RetryConfig {
			max_retries: 3,
			base_delay_ms,
			max_delay_ms,
			jitter_ms,
		};
	}

	#[test]
	fn test_backoff_grows_exponentially_without_jitter() {
		let cfg: RetryConfig = config(100, 5000, 0);
		assert_eq!(backoff_delay(0, &cfg), Duration::from_millis(100));
		assert_eq!(backoff_delay(1, &cfg), Duration::from_millis(200));
		assert_eq!(backoff_delay(2, &cfg), Duration::from_millis(400));
	}

	#[test]
	fn test_backoff_capped_at_max() {
		let cfg: RetryConfig = config(1000, 2000, 0);
		// 1000 * 2^5 = 32000 uncapped, must clamp to 2000.
		assert_eq!(backoff_delay(5, &cfg), Duration::from_millis(2000));
	}

	#[test]
	fn test_backoff_jitter_is_bounded() {
		let cfg: RetryConfig = config(100, 5000, 50);
		for _ in 0..32 {
			let d: Duration = backoff_delay(0, &cfg);
			assert!(d >= Duration::from_millis(100), "delay {d:?} below base");
			assert!(d < Duration::from_millis(150), "delay {d:?} exceeds base + jitter");
		}
	}

	#[test]
	fn test_backoff_high_attempt_does_not_overflow() {
		// A huge attempt must saturate, not panic on the shift.
		let cfg: RetryConfig = config(200, 2000, 0);
		assert_eq!(backoff_delay(u32::MAX, &cfg), Duration::from_millis(2000));
	}
}
