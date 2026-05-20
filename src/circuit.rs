use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::time::{Duration, Instant};

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

pub struct CircuitBreakers {
    breakers: DashMap<String, BackendBreaker>,
    failure_threshold: u32,
    recovery_timeout: Duration,
    half_open_max_requests: u32,
}

impl CircuitBreakers {
    pub fn new(config: &CircuitBreakerConfig) -> Self {
        return Self {
            breakers: DashMap::new(),
            failure_threshold: config.failure_threshold,
            recovery_timeout: Duration::from_secs(config.recovery_timeout_secs),
            half_open_max_requests: config.half_open_max_requests,
        };
    }

    pub fn check(&self, backend_id: &str) -> CircuitState {
        let breaker = self.breakers.entry(backend_id.to_string())
            .or_insert_with(BackendBreaker::new);

        let current: CircuitState = CircuitState::from(breaker.state.load(Ordering::Acquire));

        return match current {
            CircuitState::Closed => CircuitState::Closed,
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
                    CircuitState::HalfOpen
                } else {
                    CircuitState::Open
                }
            }
            CircuitState::HalfOpen => {
                let inflight: u32 = breaker.half_open_inflight.fetch_add(1, Ordering::AcqRel);
                if inflight >= self.half_open_max_requests {
                    breaker.half_open_inflight.fetch_sub(1, Ordering::Release);
                    CircuitState::Open
                } else {
                    CircuitState::HalfOpen
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
        let breaker = self.breakers.entry(backend_id.to_string())
            .or_insert_with(BackendBreaker::new);

        let current: CircuitState = CircuitState::from(breaker.state.load(Ordering::Acquire));

        match current {
            CircuitState::Closed => {
                let failures: u32 = breaker.consecutive_failures.fetch_add(1, Ordering::AcqRel) + 1;
                if failures >= self.failure_threshold {
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
                breaker.state.store(STATE_OPEN, Ordering::Release);
                *breaker.opened_at.lock() = Some(Instant::now());
                warn!(backend = %backend_id, "circuit breaker re-opened after half-open failure");
            }
            CircuitState::Open => {}
        }
    }

    pub fn state(&self, backend_id: &str) -> CircuitState {
        return self.breakers.get(backend_id)
            .map(|b| CircuitState::from(b.state.load(Ordering::Acquire)))
            .unwrap_or(CircuitState::Closed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CircuitBreakerConfig {
        return CircuitBreakerConfig {
            failure_threshold: 3,
            recovery_timeout_secs: 60,
            half_open_max_requests: 2,
        };
    }

    #[test]
    fn test_starts_closed() {
        let cb: CircuitBreakers = CircuitBreakers::new(&test_config());
        assert_eq!(cb.state("backend-1"), CircuitState::Closed);
        assert_eq!(cb.check("backend-1"), CircuitState::Closed);
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
        assert_eq!(cb.check("b1"), CircuitState::Open);
    }

    #[test]
    fn test_half_open_after_recovery_timeout() {
        let config: CircuitBreakerConfig = CircuitBreakerConfig {
            failure_threshold: 1,
            recovery_timeout_secs: 0,
            half_open_max_requests: 2,
        };
        let cb: CircuitBreakers = CircuitBreakers::new(&config);
        cb.record_failure("b1");
        assert_eq!(cb.state("b1"), CircuitState::Open);

        // recovery_timeout is 0s so it should immediately transition
        let state: CircuitState = cb.check("b1");
        assert_eq!(state, CircuitState::HalfOpen);
    }

    #[test]
    fn test_half_open_limits_probes() {
        let config: CircuitBreakerConfig = CircuitBreakerConfig {
            failure_threshold: 1,
            recovery_timeout_secs: 0,
            half_open_max_requests: 2,
        };
        let cb: CircuitBreakers = CircuitBreakers::new(&config);
        cb.record_failure("b1");

        assert_eq!(cb.check("b1"), CircuitState::HalfOpen);
        assert_eq!(cb.check("b1"), CircuitState::HalfOpen);
        // Third probe should be rejected (returns Open)
        assert_eq!(cb.check("b1"), CircuitState::Open);
    }

    #[test]
    fn test_half_open_success_closes() {
        let config: CircuitBreakerConfig = CircuitBreakerConfig {
            failure_threshold: 1,
            recovery_timeout_secs: 0,
            half_open_max_requests: 2,
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
            failure_threshold: 1,
            recovery_timeout_secs: 0,
            half_open_max_requests: 2,
        };
        let cb: CircuitBreakers = CircuitBreakers::new(&config);
        cb.record_failure("b1");
        cb.check("b1"); // transitions to half-open
        cb.record_failure("b1");
        assert_eq!(cb.state("b1"), CircuitState::Open);
    }

    #[test]
    fn test_independent_backends() {
        let cb: CircuitBreakers = CircuitBreakers::new(&test_config());
        for _ in 0..3 {
            cb.record_failure("b1");
        }
        assert_eq!(cb.state("b1"), CircuitState::Open);
        assert_eq!(cb.state("b2"), CircuitState::Closed);
        assert_eq!(cb.check("b2"), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_state_from_u8() {
        assert_eq!(CircuitState::from(STATE_CLOSED), CircuitState::Closed);
        assert_eq!(CircuitState::from(STATE_OPEN), CircuitState::Open);
        assert_eq!(CircuitState::from(STATE_HALF_OPEN), CircuitState::HalfOpen);
        assert_eq!(CircuitState::from(255), CircuitState::Closed);
    }
}
