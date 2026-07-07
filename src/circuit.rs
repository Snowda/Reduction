use std::fmt::{self, Debug, Formatter};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arrayvec::ArrayString;
use dashmap::DashMap;
use parking_lot::Mutex;
use tracing::{info, warn};

use crate::config::CircuitBreakerConfig;

const STATE_CLOSED: u8 = 0;
const STATE_OPEN: u8 = 1;
const STATE_HALF_OPEN: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

impl From<u8> for CircuitState {
    #[inline]
    fn from(v: u8) -> Self {
        return match v {
            STATE_OPEN => CircuitState::Open,
            STATE_HALF_OPEN => CircuitState::HalfOpen,
            _ => CircuitState::Closed,
        };
    }
}

struct BackendBreaker {
    state: AtomicU8,
    consecutive_failures: AtomicU32,
    half_open_inflight: AtomicU32,
    opened_at: Mutex<Option<Instant>>,
}

impl BackendBreaker {
    fn new() -> Self {
        return Self {
            state: AtomicU8::new(STATE_CLOSED),
            consecutive_failures: AtomicU32::new(0),
            half_open_inflight: AtomicU32::new(0),
            opened_at: Mutex::new(None),
        };
    }
}

/// RAII guard that decrements `half_open_inflight` when dropped,
/// unless the circuit has already transitioned out of HalfOpen.
pub struct HalfOpenGuard {
    breaker: Arc<BackendBreaker>,
}

impl Debug for HalfOpenGuard {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        return f.debug_struct("HalfOpenGuard").finish();
    }
}

impl Drop for HalfOpenGuard {
    fn drop(&mut self) {
        let current: CircuitState = CircuitState::from(self.breaker.state.load(Ordering::Acquire));
        if current == CircuitState::HalfOpen {
            self.breaker.half_open_inflight.fetch_sub(1, Ordering::Release);
        }
    }
}

pub struct CircuitBreakers {
    breakers: DashMap<ArrayString<256>, Arc<BackendBreaker>>,
    failure_threshold: NonZeroU32,
    recovery_timeout: Duration,
    half_open_max_requests: NonZeroU32,
}

impl CircuitBreakers {
    #[must_use]
    pub fn new(config: &CircuitBreakerConfig) -> Self {
        return Self {
            breakers: DashMap::new(),
            failure_threshold: config.failure_threshold,
            recovery_timeout: Duration::from_secs(config.recovery_timeout_secs),
            half_open_max_requests: config.half_open_max_requests,
        };
    }

    pub fn check(&self, backend_id: &str) -> (CircuitState, Option<HalfOpenGuard>) {
        let key: ArrayString<256> = match ArrayString::from(backend_id) {
            Ok(k) => k,
            Err(_) => return (CircuitState::Open, None),
        };
        let breaker: Arc<BackendBreaker> = self.breakers.entry(key)
            .or_insert_with(|| Arc::new(BackendBreaker::new()))
            .clone();

        let current: CircuitState = CircuitState::from(breaker.state.load(Ordering::Acquire));

        return match current {
            CircuitState::Closed => (CircuitState::Closed, None),
            CircuitState::Open => {
                let should_transition: bool = {
                    let opened_at = breaker.opened_at.lock();
                    opened_at
                        .map(|t| t.elapsed() >= self.recovery_timeout)
                        .unwrap_or(false)
                };
                if should_transition {
                    breaker.half_open_inflight.store(1, Ordering::Release);
                    breaker.state.store(STATE_HALF_OPEN, Ordering::Release);
                    info!(backend = %backend_id, "circuit breaker transitioning to half-open");
                    let guard: HalfOpenGuard = HalfOpenGuard { breaker };
                    (CircuitState::HalfOpen, Some(guard))
                } else {
                    (CircuitState::Open, None)
                }
            }
            CircuitState::HalfOpen => {
                let inflight: u32 = breaker.half_open_inflight.fetch_add(1, Ordering::AcqRel);
                if inflight >= self.half_open_max_requests.get() {
                    breaker.half_open_inflight.fetch_sub(1, Ordering::Release);
                    (CircuitState::Open, None)
                } else {
                    let guard: HalfOpenGuard = HalfOpenGuard { breaker };
                    (CircuitState::HalfOpen, Some(guard))
                }
            }
        };
    }

    pub fn record_success(&self, backend_id: &str) {
        let Some(breaker) = self.breakers.get(backend_id) else {
            return;
        };

        let current: CircuitState = CircuitState::from(breaker.state.load(Ordering::Acquire));

        match current {
            CircuitState::HalfOpen => {
                breaker.consecutive_failures.store(0, Ordering::Release);
                breaker.half_open_inflight.store(0, Ordering::Release);
                breaker.state.store(STATE_CLOSED, Ordering::Release);
                *breaker.opened_at.lock() = None;
                info!(backend = %backend_id, "circuit breaker closed after successful probe");
            }
            CircuitState::Closed => {
                breaker.consecutive_failures.store(0, Ordering::Release);
            }
            CircuitState::Open => {}
        }
    }

    pub fn record_failure(&self, backend_id: &str) {
        let key: ArrayString<256> = match ArrayString::from(backend_id) {
            Ok(k) => k,
            Err(_) => return,
        };
        let breaker: Arc<BackendBreaker> = self.breakers.entry(key)
            .or_insert_with(|| Arc::new(BackendBreaker::new()))
            .clone();

        let current: CircuitState = CircuitState::from(breaker.state.load(Ordering::Acquire));

        match current {
            CircuitState::Closed => {
                let failures: u32 = breaker.consecutive_failures.fetch_add(1, Ordering::AcqRel) + 1;
                if failures >= self.failure_threshold.get() {
                    breaker.state.store(STATE_OPEN, Ordering::Release);
                    *breaker.opened_at.lock() = Some(Instant::now());
                    warn!(
                        backend = %backend_id,
                        failures = failures,
                        "circuit breaker opened after consecutive failures"
                    );
                }
            }
            CircuitState::HalfOpen => {
                breaker.half_open_inflight.store(0, Ordering::Release);
                breaker.state.store(STATE_OPEN, Ordering::Release);
                *breaker.opened_at.lock() = Some(Instant::now());
                warn!(backend = %backend_id, "circuit breaker re-opened after half-open failure");
            }
            CircuitState::Open => {}
        }
    }

    #[must_use]
    pub fn state(&self, backend_id: &str) -> CircuitState {
        return self.breakers.get(backend_id)
            .map(|b| CircuitState::from(b.state.load(Ordering::Acquire)))
            .unwrap_or(CircuitState::Closed);
    }

    pub fn remove_backend(&self, backend_id: &str) {
        self.breakers.remove(backend_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CircuitBreakerConfig {
        return CircuitBreakerConfig {
            failure_threshold: NonZeroU32::new(3).unwrap(),
            recovery_timeout_secs: 60,
            half_open_max_requests: NonZeroU32::new(2).unwrap(),
        };
    }

    fn check_state(cb: &CircuitBreakers, id: &str) -> CircuitState {
        let (state, _guard) = cb.check(id);
        return state;
    }

    #[test]
    fn test_starts_closed() {
        let cb: CircuitBreakers = CircuitBreakers::new(&test_config());
        assert_eq!(cb.state("backend-1"), CircuitState::Closed);
        assert_eq!(check_state(&cb, "backend-1"), CircuitState::Closed);
    }

    #[test]
    fn test_opens_after_threshold() {
        let cb: CircuitBreakers = CircuitBreakers::new(&test_config());
        cb.check("b1");
        cb.record_failure("b1");
        cb.record_failure("b1");
        assert_eq!(cb.state("b1"), CircuitState::Closed);
        cb.record_failure("b1");
        assert_eq!(cb.state("b1"), CircuitState::Open);
    }

    #[test]
    fn test_success_resets_failure_count() {
        let cb: CircuitBreakers = CircuitBreakers::new(&test_config());
        cb.check("b1");
        cb.record_failure("b1");
        cb.record_failure("b1");
        cb.record_success("b1");
        cb.record_failure("b1");
        cb.record_failure("b1");
        assert_eq!(cb.state("b1"), CircuitState::Closed);
    }

    #[test]
    fn test_open_blocks_requests() {
        let cb: CircuitBreakers = CircuitBreakers::new(&test_config());
        for _ in 0..3 {
            cb.record_failure("b1");
        }
        assert_eq!(check_state(&cb, "b1"), CircuitState::Open);
    }

    #[test]
    fn test_half_open_after_recovery_timeout() {
        let config: CircuitBreakerConfig = CircuitBreakerConfig {
            failure_threshold: NonZeroU32::new(1).unwrap(),
            recovery_timeout_secs: 0,
            half_open_max_requests: NonZeroU32::new(2).unwrap(),
        };
        let cb: CircuitBreakers = CircuitBreakers::new(&config);
        cb.record_failure("b1");
        assert_eq!(cb.state("b1"), CircuitState::Open);

        // recovery_timeout is 0s so it should immediately transition
        let (state, guard) = cb.check("b1");
        assert_eq!(state, CircuitState::HalfOpen);
        assert!(guard.is_some());
    }

    #[test]
    fn test_half_open_limits_probes() {
        let config: CircuitBreakerConfig = CircuitBreakerConfig {
            failure_threshold: NonZeroU32::new(1).unwrap(),
            recovery_timeout_secs: 0,
            half_open_max_requests: NonZeroU32::new(2).unwrap(),
        };
        let cb: CircuitBreakers = CircuitBreakers::new(&config);
        cb.record_failure("b1");

        let (_s1, _g1) = cb.check("b1");
        assert_eq!(_s1, CircuitState::HalfOpen);
        let (_s2, _g2) = cb.check("b1");
        assert_eq!(_s2, CircuitState::HalfOpen);
        // Third probe should be rejected (returns Open)
        assert_eq!(check_state(&cb, "b1"), CircuitState::Open);
    }

    #[test]
    fn test_half_open_success_closes() {
        let config: CircuitBreakerConfig = CircuitBreakerConfig {
            failure_threshold: NonZeroU32::new(1).unwrap(),
            recovery_timeout_secs: 0,
            half_open_max_requests: NonZeroU32::new(2).unwrap(),
        };
        let cb: CircuitBreakers = CircuitBreakers::new(&config);
        cb.record_failure("b1");
        cb.check("b1"); // transitions to half-open
        cb.record_success("b1");
        assert_eq!(cb.state("b1"), CircuitState::Closed);
    }

    #[test]
    fn test_half_open_failure_reopens() {
        let config: CircuitBreakerConfig = CircuitBreakerConfig {
            failure_threshold: NonZeroU32::new(1).unwrap(),
            recovery_timeout_secs: 0,
            half_open_max_requests: NonZeroU32::new(2).unwrap(),
        };
        let cb: CircuitBreakers = CircuitBreakers::new(&config);
        cb.record_failure("b1");
        cb.check("b1"); // transitions to half-open
        cb.record_failure("b1");
        assert_eq!(cb.state("b1"), CircuitState::Open);
    }

    #[test]
    fn test_half_open_guard_decrements_on_drop() {
        let config: CircuitBreakerConfig = CircuitBreakerConfig {
            failure_threshold: NonZeroU32::new(1).unwrap(),
            recovery_timeout_secs: 0,
            half_open_max_requests: NonZeroU32::new(3).unwrap(),
        };
        let cb: CircuitBreakers = CircuitBreakers::new(&config);
        cb.record_failure("b1");

        let (_s1, guard1) = cb.check("b1"); // inflight=1
        assert_eq!(_s1, CircuitState::HalfOpen);
        let (_s2, _g2) = cb.check("b1"); // inflight=2
        assert_eq!(_s2, CircuitState::HalfOpen);

        // Drop guard1 — should decrement inflight back to 1
        drop(guard1);

        // Now a third check should succeed (inflight was 2, dropped to 1, now goes to 2 again)
        let (_s3, _g3) = cb.check("b1");
        assert_eq!(_s3, CircuitState::HalfOpen);
    }

    #[test]
    fn test_guard_no_decrement_after_state_transition() {
        let config: CircuitBreakerConfig = CircuitBreakerConfig {
            failure_threshold: NonZeroU32::new(1).unwrap(),
            recovery_timeout_secs: 0,
            half_open_max_requests: NonZeroU32::new(2).unwrap(),
        };
        let cb: CircuitBreakers = CircuitBreakers::new(&config);
        cb.record_failure("b1");

        let (_state, guard) = cb.check("b1"); // half-open, inflight=1
        cb.record_success("b1"); // transitions to Closed, resets inflight to 0

        // Dropping guard after transition to Closed should NOT decrement
        drop(guard);

        // State should remain Closed (not corrupted by guard drop)
        assert_eq!(cb.state("b1"), CircuitState::Closed);
    }

    #[test]
    fn test_remove_backend() {
        let cb: CircuitBreakers = CircuitBreakers::new(&test_config());
        cb.check("b1");
        cb.record_failure("b1");
        assert_eq!(cb.state("b1"), CircuitState::Closed);
        cb.remove_backend("b1");
        // After removal, state resets to default (Closed, no entry)
        assert_eq!(cb.state("b1"), CircuitState::Closed);
    }

    #[test]
    fn test_independent_backends() {
        let cb: CircuitBreakers = CircuitBreakers::new(&test_config());
        for _ in 0..3 {
            cb.record_failure("b1");
        }
        assert_eq!(cb.state("b1"), CircuitState::Open);
        assert_eq!(cb.state("b2"), CircuitState::Closed);
        assert_eq!(check_state(&cb, "b2"), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_state_from_u8() {
        assert_eq!(CircuitState::from(STATE_CLOSED), CircuitState::Closed);
        assert_eq!(CircuitState::from(STATE_OPEN), CircuitState::Open);
        assert_eq!(CircuitState::from(STATE_HALF_OPEN), CircuitState::HalfOpen);
        assert_eq!(CircuitState::from(255), CircuitState::Closed);
    }
}
