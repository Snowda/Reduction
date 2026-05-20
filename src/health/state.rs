use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use bitcode::{Decode, Encode};
use lru::LruCache;

use crate::balancer::MAX_BACKENDS;

const DEFAULT_STALENESS_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Encode, Decode)]
pub struct BackendHealth {
    pub backend_id: String,
    pub load: f64,
    pub latency_ms: u32,
    pub available: bool,
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct HealthBroadcast {
    pub entries: Vec<BackendHealth>,
}

#[derive(Debug)]
pub struct HealthState {
    entries: LruCache<String, (BackendHealth, Instant)>,
    staleness_ttl: Duration,
}

impl HealthState {
    pub fn new() -> Self {
        return Self {
            entries: LruCache::new(
                NonZeroUsize::new(MAX_BACKENDS).expect("MAX_BACKENDS must be > 0"),
            ),
            staleness_ttl: DEFAULT_STALENESS_TTL,
        };
    }

    pub fn with_config(capacity: usize, staleness_ttl: Duration) -> Self {
        let cap: usize = capacity.min(MAX_BACKENDS).max(1);
        return Self {
            entries: LruCache::new(
                NonZeroUsize::new(cap).expect("capacity must be > 0"),
            ),
            staleness_ttl,
        };
    }

    pub fn with_staleness_ttl(mut self, ttl: Duration) -> Self {
        self.staleness_ttl = ttl;
        return self;
    }

    pub fn update(&mut self, broadcast: HealthBroadcast) {
        let now: Instant = Instant::now();
        for entry in broadcast.entries {
            self.entries.push(entry.backend_id.clone(), (entry, now));
        }
    }

    pub fn is_valid(&self, backend_id: &str) -> bool {
        match self.entries.peek(backend_id) {
            None => return false,
            Some((_, received_at)) => {
                return received_at.elapsed() < self.staleness_ttl;
            }
        }
    }

    pub fn weight_factor(&self, backend_id: &str) -> f64 {
        if !self.is_valid(backend_id) {
            return 1.0;
        }

        match self.entries.peek(backend_id) {
            None => return 1.0,
            Some((health, _)) => {
                if !health.available {
                    return 0.0;
                }

                let load_factor: f64 = 1.0 - health.load.clamp(0.0, 1.0);

                let latency_factor: f64 = if health.latency_ms > 500 {
                    500.0 / (health.latency_ms as f64)
                } else {
                    1.0
                };

                return load_factor * latency_factor;
            }
        }
    }

    pub fn get(&self, backend_id: &str) -> Option<&BackendHealth> {
        return self.entries.peek(backend_id).map(|(h, _)| h);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_broadcast(entries: Vec<BackendHealth>) -> HealthBroadcast {
        return HealthBroadcast { entries };
    }

    fn healthy_backend(id: &str) -> BackendHealth {
        return BackendHealth {
            backend_id: id.to_string(),
            load: 0.3,
            latency_ms: 50,
            available: true,
        };
    }

    #[test]
    fn test_update_and_get() {
        let mut state: HealthState = HealthState::new();
        state.update(make_broadcast(vec![healthy_backend("api")]));

        let health: &BackendHealth = state.get("api").unwrap();
        assert_eq!(health.backend_id, "api");
        assert!(health.available);
    }

    #[test]
    fn test_is_valid_fresh_data() {
        let mut state: HealthState = HealthState::new();
        state.update(make_broadcast(vec![healthy_backend("api")]));

        assert!(state.is_valid("api"));
    }

    #[test]
    fn test_is_valid_unknown_backend() {
        let state: HealthState = HealthState::new();
        assert!(!state.is_valid("unknown"));
    }

    #[test]
    fn test_weight_factor_healthy() {
        let mut state: HealthState = HealthState::new();
        state.update(make_broadcast(vec![healthy_backend("api")]));

        let factor: f64 = state.weight_factor("api");
        assert!(factor > 0.5);
        assert!(factor <= 1.0);
    }

    #[test]
    fn test_weight_factor_unavailable() {
        let mut state: HealthState = HealthState::new();
        state.update(make_broadcast(vec![BackendHealth {
            backend_id: "api".to_string(),
            load: 0.0,
            latency_ms: 10,
            available: false,
        }]));

        let factor: f64 = state.weight_factor("api");
        assert_eq!(factor, 0.0);
    }

    #[test]
    fn test_weight_factor_high_load() {
        let mut state: HealthState = HealthState::new();
        state.update(make_broadcast(vec![BackendHealth {
            backend_id: "api".to_string(),
            load: 0.9,
            latency_ms: 50,
            available: true,
        }]));

        let factor: f64 = state.weight_factor("api");
        assert!(factor < 0.2);
    }

    #[test]
    fn test_weight_factor_high_latency() {
        let mut state: HealthState = HealthState::new();
        state.update(make_broadcast(vec![BackendHealth {
            backend_id: "api".to_string(),
            load: 0.0,
            latency_ms: 1000,
            available: true,
        }]));

        let factor: f64 = state.weight_factor("api");
        assert!(factor < 1.0);
        assert!(factor > 0.0);
    }

    #[test]
    fn test_weight_factor_unknown_backend() {
        let state: HealthState = HealthState::new();
        let factor: f64 = state.weight_factor("unknown");
        assert_eq!(factor, 1.0);
    }

    #[test]
    fn test_broadcast_round_trip() {
        let original: HealthBroadcast = make_broadcast(vec![
            healthy_backend("api-1"),
            healthy_backend("api-2"),
        ]);

        let encoded: Vec<u8> = bitcode::encode(&original);
        let decoded: HealthBroadcast = bitcode::decode(&encoded).unwrap();

        assert_eq!(decoded.entries.len(), 2);
        assert_eq!(decoded.entries[0].backend_id, "api-1");
        assert_eq!(decoded.entries[1].backend_id, "api-2");
    }

    #[test]
    fn test_staleness_ttl_custom() {
        let state: HealthState = HealthState::new()
            .with_staleness_ttl(Duration::from_secs(60));

        assert!(!state.is_valid("api"));
    }

    #[test]
    fn test_lru_evicts_oldest_at_capacity() {
        let cap: usize = 16;
        let mut state: HealthState = HealthState::with_config(cap, Duration::from_secs(300));

        for i in 0..cap {
            state.update(make_broadcast(vec![healthy_backend(&format!("b-{i}"))]));
        }

        assert!(state.get("b-0").is_some());

        state.update(make_broadcast(vec![healthy_backend("overflow")]));

        assert!(state.get("b-0").is_none(), "oldest entry should be evicted");
        assert!(state.get("overflow").is_some());
        assert!(state.get(&format!("b-{}", cap - 1)).is_some());
    }

    #[test]
    fn test_lru_update_existing_does_not_evict() {
        let cap: usize = 16;
        let mut state: HealthState = HealthState::with_config(cap, Duration::from_secs(300));

        for i in 0..cap {
            state.update(make_broadcast(vec![healthy_backend(&format!("b-{i}"))]));
        }

        state.update(make_broadcast(vec![healthy_backend("b-0")]));

        assert!(state.get("b-0").is_some());
        assert!(state.get(&format!("b-{}", cap - 1)).is_some());
    }
}
