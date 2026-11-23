// Exponential backoff: each step doubles the delay from `initial`, and no step goes past `max`.
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
	pub initial: Duration,
	pub max: Duration,
}

impl Backoff {
	#[must_use]
	pub const fn new(initial: Duration, max: Duration) -> Self {
		return Self { initial, max };
	}

	// The delay that follows `current`.
	#[must_use]
	pub fn next(self, current: Duration) -> Duration {
		return current.saturating_mul(2).min(self.max);
	}

	// The delay before retry `n`, counted from 0: `initial` doubled `n` times.
	#[must_use]
	pub fn nth(self, n: u32) -> Duration {
		let factor: u32 = 1_u32.checked_shl(n).unwrap_or(u32::MAX);
		return self.initial.saturating_mul(factor).min(self.max);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const STEPS: Backoff = Backoff::new(Duration::from_millis(50), Duration::from_secs(5));

	#[test]
	fn next_doubles_until_the_max_and_stays_there() {
		assert_eq!(STEPS.next(Duration::from_millis(50)), Duration::from_millis(100));
		assert_eq!(STEPS.next(Duration::from_secs(3)), Duration::from_secs(5), "a double past the max stops at it");
		assert_eq!(STEPS.next(STEPS.max), STEPS.max);
		assert_eq!(STEPS.next(Duration::MAX), STEPS.max, "no overflow");
	}

	#[test]
	fn nth_is_initial_times_two_to_the_n_capped_at_the_max() {
		let doubled: Vec<Duration> = (0..8).map(|n: u32| return STEPS.nth(n)).collect();
		let expected: Vec<Duration> = [50, 100, 200, 400, 800, 1600, 3200, 5000].map(Duration::from_millis).to_vec();
		assert_eq!(doubled, expected);
		assert_eq!(STEPS.nth(31), STEPS.max);
		assert_eq!(STEPS.nth(32), STEPS.max, "a shift past the width saturates");
		assert_eq!(STEPS.nth(u32::MAX), STEPS.max);
	}

	#[test]
	fn nth_agrees_with_repeated_next() {
		let mut current: Duration = STEPS.initial;
		(0..12).for_each(|n: u32| {
			assert_eq!(STEPS.nth(n), current, "step {n}");
			current = STEPS.next(current);
		});
	}
}
