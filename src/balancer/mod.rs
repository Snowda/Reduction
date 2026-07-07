pub mod jitter;
pub mod queue;
pub mod rendezvous;

use std::net::IpAddr;
use std::sync::Arc;

use arrayvec::ArrayVec;

use crate::config::{BackendConfig, DEFAULT_MAX_BACKENDS, HARD_MAX_BACKENDS};
use crate::error::{ReductionError, Result};
use crate::health::HealthState;

pub use queue::RequestQueue;

// const context has no infallible u32->usize conversion; the value (256) fits trivially.
#[allow(clippy::as_conversions)]
pub const MAX_BACKENDS: usize = HARD_MAX_BACKENDS as usize;

#[derive(Debug, Clone)]
pub struct BackendPool {
    pub backends: Arc<[BackendConfig]>,
    pub jitter_factor: f64,
}

impl BackendPool {
    pub fn new(backends: Vec<BackendConfig>, jitter_factor: f64) -> Result<Self> {
        return Self::with_max(backends, jitter_factor, DEFAULT_MAX_BACKENDS);
    }

    pub fn with_max(backends: Vec<BackendConfig>, jitter_factor: f64, max_backends: u32) -> Result<Self> {
        if backends.len() > usize::try_from(max_backends).unwrap_or(usize::MAX) {
            return Err(ReductionError::Config(format!(
                "backend count {} exceeds maximum {max_backends}",
                backends.len(),
            )));
        }
        if backends.len() > MAX_BACKENDS {
            return Err(ReductionError::Config(format!(
                "backend count {} exceeds hard limit {MAX_BACKENDS}",
                backends.len(),
            )));
        }
        return Ok(Self {
            backends: Arc::from(backends),
            jitter_factor,
        });
    }

    #[must_use]
    #[tracing::instrument(skip_all)]
    pub fn select(
        &self,
        client_ip: IpAddr,
        health: &HealthState,
    ) -> Option<&BackendConfig> {
        return self.select_with_pressure(client_ip, health, &|_| 0.0);
    }

    #[must_use]
    #[tracing::instrument(skip_all)]
    pub fn select_with_pressure<F>(
        &self,
        client_ip: IpAddr,
        health: &HealthState,
        pressure_fn: &F,
    ) -> Option<&BackendConfig>
    where
        F: Fn(&str) -> f64,
    {
        if self.backends.is_empty() {
            return None;
        }

        let ids: ArrayVec<&str, MAX_BACKENDS> = self.backends.iter().map(|b| b.id.as_str()).collect();
        let base_weights: ArrayVec<f64, MAX_BACKENDS> = self.backends.iter().map(|b| b.weight).collect();

        let health_weights: ArrayVec<f64, MAX_BACKENDS> = base_weights
            .iter()
            .zip(ids.iter())
            .map(|(w, id)| w * health.weight_factor(id))
            .collect();

        let pressure_weights: ArrayVec<f64, MAX_BACKENDS> = health_weights
            .iter()
            .zip(ids.iter())
            .map(|(w, id)| {
                let pressure: f64 = pressure_fn(id).clamp(0.0, 1.0);
                w * (1.0 - pressure)
            })
            .collect();

        let jittered_weights: ArrayVec<f64, MAX_BACKENDS> =
            jitter::apply_jitter(client_ip, &ids, &pressure_weights, self.jitter_factor);

        let index: Option<usize> = rendezvous::select_backend(client_ip, &ids, &jittered_weights);

        return index.map(|i| &self.backends[i]);
    }
}

#[cfg(test)]
mod tests {
    use arrayvec::ArrayString;

    use super::*;
    use crate::config::{HARD_MAX_BACKENDS, TransportKind};
    use crate::health::state::{Availability, BackendHealth, HealthBroadcast};

    fn make_backends(count: usize) -> Vec<BackendConfig> {
        return (0..count)
            .map(|i| {
                let a: usize = (i / 256) % 256;
                let b: usize = i % 256;
                BackendConfig::new(
                    &format!("backend-{i}"),
                    format!("10.0.{a}.{b}:8080").parse().unwrap(),
                    1.0,
                    TransportKind::Tcp,
                ).unwrap()
            })
            .collect();
    }

    #[test]
    fn test_pool_select_deterministic() {
        let pool: BackendPool = BackendPool::new(make_backends(3), 0.05).unwrap();
        let health: HealthState = HealthState::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        let first: Option<&BackendConfig> = pool.select(ip, &health);
        let second: Option<&BackendConfig> = pool.select(ip, &health);

        assert_eq!(first.map(|b| &b.id), second.map(|b| &b.id));
    }

    #[test]
    fn test_pool_empty_backends() {
        let pool: BackendPool = BackendPool::new(vec![], 0.0).unwrap();
        let health: HealthState = HealthState::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(pool.select(ip, &health).is_none());
    }

    #[test]
    fn test_pool_distributes_across_backends() {
        let pool: BackendPool = BackendPool::new(make_backends(3), 0.05).unwrap();
        let health: HealthState = HealthState::new();
        let mut counts: std::collections::HashMap<ArrayString<256>, usize> =
            std::collections::HashMap::new();

        for i in 0..200u8 {
            let ip: IpAddr = format!("10.0.{}.{}", i / 50, i % 50).parse().unwrap();
            if let Some(b) = pool.select(ip, &health) {
                *counts.entry(b.id).or_insert(0) += 1;
            }
        }

        for (_, count) in &counts {
            assert!(*count > 0, "at least one backend got zero traffic");
        }
    }

    #[test]
    fn test_pool_respects_health_unavailable() {
        let mut health: HealthState = HealthState::new();
        health.update(HealthBroadcast {
            entries: vec![
                BackendHealth {
                    backend_id: ArrayString::from("backend-0").unwrap(),
                    load: 0.0,
                    latency_ms: 10,
                    availability: Availability::Offline,
                },
                BackendHealth {
                    backend_id: ArrayString::from("backend-1").unwrap(),
                    load: 0.1,
                    latency_ms: 10,
                    availability: Availability::Online,
                },
            ],
        });

        let pool: BackendPool = BackendPool::new(make_backends(2), 0.0).unwrap();

        for i in 0..50u8 {
            let ip: IpAddr = format!("10.0.0.{i}").parse().unwrap();
            let selected: &BackendConfig = pool.select(ip, &health).unwrap();
            assert_eq!(selected.id.as_str(), "backend-1");
        }
    }

    #[test]
    fn test_pool_is_clone() {
        let pool: BackendPool = BackendPool::new(make_backends(2), 0.05).unwrap();
        let cloned: BackendPool = pool.clone();
        assert_eq!(cloned.backends.len(), 2);
        assert_eq!(cloned.jitter_factor, 0.05);
    }

    #[test]
    fn test_pool_rejects_too_many_backends_default() {
        let result = BackendPool::new(make_backends(65), 0.05);
        assert!(result.is_err());
        let err: String = format!("{}", result.unwrap_err());
        assert!(err.contains("exceeds maximum"), "expected exceeds maximum, got: {err}");
    }

    #[test]
    fn test_pool_accepts_default_max_backends() {
        let result = BackendPool::new(make_backends(64), 0.05);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().backends.len(), 64);
    }

    #[test]
    fn test_pool_with_max_custom_limit() {
        let result = BackendPool::with_max(make_backends(100), 0.05, 100);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().backends.len(), 100);
    }

    #[test]
    fn test_pool_with_max_rejects_over_custom_limit() {
        let result = BackendPool::with_max(make_backends(101), 0.05, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_pool_rejects_over_hard_limit() {
        let result = BackendPool::with_max(make_backends(MAX_BACKENDS + 1), 0.05, HARD_MAX_BACKENDS + 1);
        assert!(result.is_err());
        let err: String = format!("{}", result.unwrap_err());
        assert!(err.contains("hard limit"), "expected hard limit error, got: {err}");
    }

    #[test]
    fn test_pressure_steers_away_from_loaded_backend() {
        let pool: BackendPool = BackendPool::new(make_backends(2), 0.0).unwrap();
        let health: HealthState = HealthState::new();

        let pressure_fn = |id: &str| -> f64 {
            if id == "backend-0" { 0.95 } else { 0.0 }
        };

        let mut backend_1_count: usize = 0;
        for i in 0..100u8 {
            let ip: IpAddr = format!("10.0.0.{i}").parse().unwrap();
            if let Some(b) = pool.select_with_pressure(ip, &health, &pressure_fn) {
                if b.id.as_str() == "backend-1" {
                    backend_1_count += 1;
                }
            }
        }
        assert!(backend_1_count > 80, "expected backend-1 to receive majority of traffic, got {backend_1_count}/100");
    }

    #[test]
    fn test_zero_pressure_matches_select() {
        let pool: BackendPool = BackendPool::new(make_backends(3), 0.0).unwrap();
        let health: HealthState = HealthState::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        let normal: Option<&BackendConfig> = pool.select(ip, &health);
        let with_zero: Option<&BackendConfig> = pool.select_with_pressure(ip, &health, &|_| 0.0);

        assert_eq!(normal.map(|b| &b.id), with_zero.map(|b| &b.id));
    }
}
