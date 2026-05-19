pub mod jitter;
pub mod queue;
pub mod rendezvous;

use std::net::IpAddr;

use arrayvec::ArrayVec;

use crate::config::BackendConfig;
use crate::health::HealthState;

pub use queue::RequestQueue;

pub const MAX_BACKENDS: usize = 32;

#[derive(Clone)]
pub struct BackendPool {
    pub backends: Vec<BackendConfig>,
    pub jitter_factor: f64,
}

impl BackendPool {
    pub fn new(backends: Vec<BackendConfig>, jitter_factor: f64) -> Self {
        assert!(
            backends.len() <= MAX_BACKENDS,
            "backend count {} exceeds maximum {MAX_BACKENDS}",
            backends.len(),
        );
        return Self {
            backends,
            jitter_factor,
        };
    }

    pub fn select(
        &self,
        client_ip: IpAddr,
        health: &HealthState,
    ) -> Option<&BackendConfig> {
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

        let jittered_weights: ArrayVec<f64, MAX_BACKENDS> =
            jitter::apply_jitter(client_ip, &ids, &health_weights, self.jitter_factor);

        let index: Option<usize> = rendezvous::select_backend(client_ip, &ids, &jittered_weights);

        return index.map(|i| &self.backends[i]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TransportKind;

    fn make_backends(count: usize) -> Vec<BackendConfig> {
        return (0..count)
            .map(|i| BackendConfig::new(
                format!("backend-{i}"),
                format!("10.0.0.{i}:8080").parse().unwrap(),
                1.0,
                TransportKind::Tcp,
            ))
            .collect();
    }

    #[test]
    fn test_pool_select_deterministic() {
        let pool: BackendPool = BackendPool::new(make_backends(3), 0.05);
        let health: HealthState = HealthState::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        let first: Option<&BackendConfig> = pool.select(ip, &health);
        let second: Option<&BackendConfig> = pool.select(ip, &health);

        assert_eq!(first.map(|b| &b.id), second.map(|b| &b.id));
    }

    #[test]
    fn test_pool_empty_backends() {
        let pool: BackendPool = BackendPool::new(vec![], 0.0);
        let health: HealthState = HealthState::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(pool.select(ip, &health).is_none());
    }

    #[test]
    fn test_pool_distributes_across_backends() {
        let pool: BackendPool = BackendPool::new(make_backends(3), 0.05);
        let health: HealthState = HealthState::new();
        let mut counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        for i in 0..200u8 {
            let ip: IpAddr = format!("10.0.{}.{}", i / 50, i % 50).parse().unwrap();
            if let Some(b) = pool.select(ip, &health) {
                *counts.entry(b.id.clone()).or_insert(0) += 1;
            }
        }

        for (_, count) in &counts {
            assert!(*count > 0, "at least one backend got zero traffic");
        }
    }

    #[test]
    fn test_pool_respects_health_unavailable() {
        use crate::health::state::{BackendHealth, HealthBroadcast};

        let mut health: HealthState = HealthState::new();
        health.update(HealthBroadcast {
            entries: vec![
                BackendHealth {
                    backend_id: "backend-0".to_string(),
                    load: 0.0,
                    latency_ms: 10,
                    available: false,
                },
                BackendHealth {
                    backend_id: "backend-1".to_string(),
                    load: 0.1,
                    latency_ms: 10,
                    available: true,
                },
            ],
        });

        let pool: BackendPool = BackendPool::new(make_backends(2), 0.0);

        for i in 0..50u8 {
            let ip: IpAddr = format!("10.0.0.{i}").parse().unwrap();
            let selected: &BackendConfig = pool.select(ip, &health).unwrap();
            assert_eq!(selected.id, "backend-1");
        }
    }

    #[test]
    fn test_pool_is_clone() {
        let pool: BackendPool = BackendPool::new(make_backends(2), 0.05);
        let cloned: BackendPool = pool.clone();
        assert_eq!(cloned.backends.len(), 2);
        assert_eq!(cloned.jitter_factor, 0.05);
    }
}
