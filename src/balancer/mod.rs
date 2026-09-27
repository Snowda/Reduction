pub mod queue;
pub mod rendezvous;

use std::net::IpAddr;
use std::sync::Arc;

use arrayvec::{ArrayString, ArrayVec};
pub use queue::RequestQueue;

use crate::config::{BackendConfig, DEFAULT_MAX_BACKENDS, HARD_MAX_BACKENDS};
use crate::error::{ReductionError, Result};
use crate::health::HealthState;

// const context has no infallible u32->usize conversion; the value (256) fits trivially.
#[allow(clippy::as_conversions)]
pub const MAX_BACKENDS: usize = HARD_MAX_BACKENDS as usize;

#[derive(Debug, Clone)]
pub struct BackendPool {
	pub backends: Arc<[BackendConfig]>,
}

impl BackendPool {
	pub fn new(backends: Vec<BackendConfig>) -> Result<Self> {
		return Self::with_max(backends, DEFAULT_MAX_BACKENDS);
	}

	pub fn with_max(backends: Vec<BackendConfig>, max_backends: u32) -> Result<Self> {
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
		});
	}

	#[must_use]
	#[tracing::instrument(skip_all)]
	pub fn select(&self, client_ip: IpAddr, health: &HealthState) -> Option<&BackendConfig> {
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
		F: Fn(&BackendConfig) -> f64,
	{
		return self.select_with_pressure_excluding(client_ip, health, pressure_fn, &[]);
	}

	// Like `select_with_pressure` but skips any backend id in `excluded`. None = every backend excluded
	// or the pool is empty (out of untried backends, not a leftover pick); empty `excluded` is identical.
	#[must_use]
	#[tracing::instrument(skip_all)]
	pub fn select_with_pressure_excluding<F>(
		&self,
		client_ip: IpAddr,
		health: &HealthState,
		pressure_fn: &F,
		excluded: &[ArrayString<256>],
	) -> Option<&BackendConfig>
	where
		F: Fn(&BackendConfig) -> f64,
	{
		if self.backends.is_empty() {
			return None;
		}

		let ids: ArrayVec<&str, MAX_BACKENDS> = self.backends.iter().map(|b| b.id.as_str()).collect();
		let weights: ArrayVec<f64, MAX_BACKENDS> = self.scored_weights(health, pressure_fn, &ids);

		// Highest rendezvous score among eligible, non-excluded backends wins; ties keep the earlier
		// index, matching `rendezvous::select_backend`. A non-positive effective weight (backend
		// offline, or fully connection-pressured) is ineligible — when every candidate is ineligible
		// or excluded, best_index stays None and the caller surfaces "no backend available" (503)
		// rather than latching onto a dead backend.
		let mut best_index: Option<usize> = None;
		let mut best_score: f64 = f64::NEG_INFINITY;
		for (i, id) in ids.iter().enumerate() {
			if weights[i] <= 0.0 || excluded.iter().any(|e| e.as_str() == *id) {
				continue;
			}
			let score: f64 = rendezvous::rendezvous_score(client_ip, id, weights[i]);
			if best_index.is_none() || score > best_score {
				best_score = score;
				best_index = Some(i);
			}
		}

		return best_index.map(|i| &self.backends[i]);
	}

	// Base weight × health factor × (1 − connection pressure) — the per-backend weight the rendezvous
	// score is computed from. A backend that is offline (health factor 0) or fully pressured yields 0,
	// which `select_with_pressure_excluding` treats as ineligible.
	fn scored_weights<F>(&self, health: &HealthState, pressure_fn: &F, ids: &[&str]) -> ArrayVec<f64, MAX_BACKENDS>
	where
		F: Fn(&BackendConfig) -> f64,
	{
		return self
			.backends
			.iter()
			.zip(ids.iter())
			.map(|(b, id)| {
				let health_weight: f64 = b.weight * health.weight_factor(id);
				let pressure: f64 = pressure_fn(b).clamp(0.0, 1.0);
				health_weight * (1.0 - pressure)
			})
			.collect();
	}
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;

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
				)
				.unwrap()
			})
			.collect();
	}

	#[test]
	fn test_pool_select_deterministic() {
		let pool: BackendPool = BackendPool::new(make_backends(3)).unwrap();
		let health: HealthState = HealthState::new();
		let ip: IpAddr = "192.168.1.1".parse().unwrap();

		let first: Option<&BackendConfig> = pool.select(ip, &health);
		let second: Option<&BackendConfig> = pool.select(ip, &health);

		assert_eq!(first.map(|b| &b.id), second.map(|b| &b.id));
	}

	#[test]
	fn test_pool_empty_backends() {
		let pool: BackendPool = BackendPool::new(vec![]).unwrap();
		let health: HealthState = HealthState::new();
		let ip: IpAddr = "10.0.0.1".parse().unwrap();

		assert!(pool.select(ip, &health).is_none());
	}

	#[test]
	fn test_pool_distributes_across_backends() {
		let pool: BackendPool = BackendPool::new(make_backends(3)).unwrap();
		let health: HealthState = HealthState::new();
		let mut counts: HashMap<ArrayString<256>, usize> = HashMap::new();

		for i in 0..200u8 {
			let ip: IpAddr = format!("10.0.{}.{}", i / 50, i % 50).parse().unwrap();
			if let Some(b) = pool.select(ip, &health) {
				*counts.entry(b.id).or_insert(0) += 1;
			}
		}

		for count in counts.values() {
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

		let pool: BackendPool = BackendPool::new(make_backends(2)).unwrap();

		for i in 0..50u8 {
			let ip: IpAddr = format!("10.0.0.{i}").parse().unwrap();
			let selected: &BackendConfig = pool.select(ip, &health).unwrap();
			assert_eq!(selected.id.as_str(), "backend-1");
		}
	}

	#[test]
	fn test_pool_all_offline_returns_none() {
		// Every backend offline drives all effective weights to 0; the pool must return None (→ 503)
		// rather than latching onto backends[0].
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
					load: 0.0,
					latency_ms: 10,
					availability: Availability::Offline,
				},
			],
		});

		let pool: BackendPool = BackendPool::new(make_backends(2)).unwrap();
		for i in 0..50u8 {
			let ip: IpAddr = format!("10.0.0.{i}").parse().unwrap();
			assert!(
				pool.select(ip, &health).is_none(),
				"all-offline pool selected a backend for ip {i}"
			);
		}
	}

	#[test]
	fn test_pool_full_pressure_on_all_returns_none() {
		// Full connection pressure on every backend zeroes all weights → no selection.
		let pool: BackendPool = BackendPool::new(make_backends(3)).unwrap();
		let health: HealthState = HealthState::new();
		let ip: IpAddr = "10.0.0.7".parse().unwrap();
		assert!(pool.select_with_pressure(ip, &health, &|_| 1.0).is_none());
	}

	#[test]
	fn test_pool_is_clone() {
		let pool: BackendPool = BackendPool::new(make_backends(2)).unwrap();
		let cloned: BackendPool = pool.clone();
		// Compare the clone against the still-live original so the clone is the behavior under test.
		assert_eq!(cloned.backends.len(), pool.backends.len());
	}

	#[test]
	fn test_pool_rejects_too_many_backends_default() {
		let result = BackendPool::new(make_backends(65));
		assert!(result.is_err());
		let err: String = format!("{}", result.unwrap_err());
		assert!(err.contains("exceeds maximum"), "expected exceeds maximum, got: {err}");
	}

	#[test]
	fn test_pool_accepts_default_max_backends() {
		let result = BackendPool::new(make_backends(64));
		assert!(result.is_ok());
		assert_eq!(result.unwrap().backends.len(), 64);
	}

	#[test]
	fn test_pool_with_max_custom_limit() {
		let result = BackendPool::with_max(make_backends(100), 100);
		assert!(result.is_ok());
		assert_eq!(result.unwrap().backends.len(), 100);
	}

	#[test]
	fn test_pool_with_max_rejects_over_custom_limit() {
		let result = BackendPool::with_max(make_backends(101), 100);
		assert!(result.is_err());
	}

	#[test]
	fn test_pool_rejects_over_hard_limit() {
		let result = BackendPool::with_max(make_backends(MAX_BACKENDS + 1), HARD_MAX_BACKENDS + 1);
		assert!(result.is_err());
		let err: String = format!("{}", result.unwrap_err());
		assert!(err.contains("hard limit"), "expected hard limit error, got: {err}");
	}

	#[test]
	fn test_pressure_steers_away_from_loaded_backend() {
		let pool: BackendPool = BackendPool::new(make_backends(2)).unwrap();
		let health: HealthState = HealthState::new();

		let pressure_fn = |b: &BackendConfig| -> f64 { if b.id.as_str() == "backend-0" { 0.95 } else { 0.0 } };

		let mut backend_1_count: usize = 0;
		for i in 0..100u8 {
			let ip: IpAddr = format!("10.0.0.{i}").parse().unwrap();
			if let Some(b) = pool.select_with_pressure(ip, &health, &pressure_fn)
				&& b.id.as_str() == "backend-1"
			{
				backend_1_count += 1;
			}
		}
		assert!(
			backend_1_count > 80,
			"expected backend-1 to receive majority of traffic, got {backend_1_count}/100"
		);
	}

	#[test]
	fn test_exclude_empty_matches_select_with_pressure() {
		let pool: BackendPool = BackendPool::new(make_backends(4)).unwrap();
		let health: HealthState = HealthState::new();
		for i in 0..64u8 {
			let ip: IpAddr = format!("10.0.0.{i}").parse().unwrap();
			let base: Option<&BackendConfig> = pool.select_with_pressure(ip, &health, &|_| 0.0);
			let excl: Option<&BackendConfig> = pool.select_with_pressure_excluding(ip, &health, &|_| 0.0, &[]);
			assert_eq!(base.map(|b| b.id), excl.map(|b| b.id), "ip {i} diverged");
		}
	}

	#[test]
	fn test_exclude_steers_to_other_backend() {
		let pool: BackendPool = BackendPool::new(make_backends(3)).unwrap();
		let health: HealthState = HealthState::new();
		let ip: IpAddr = "192.168.1.1".parse().unwrap();

		let chosen: ArrayString<256> = pool.select_with_pressure(ip, &health, &|_| 0.0).unwrap().id;
		let after: ArrayString<256> = pool
			.select_with_pressure_excluding(ip, &health, &|_| 0.0, &[chosen])
			.unwrap()
			.id;
		assert_ne!(after, chosen, "excluded backend was reselected");
	}

	#[test]
	fn test_exclude_all_returns_none() {
		let pool: BackendPool = BackendPool::new(make_backends(2)).unwrap();
		let health: HealthState = HealthState::new();
		let ip: IpAddr = "10.0.0.5".parse().unwrap();

		let all: Vec<ArrayString<256>> = pool.backends.iter().map(|b| b.id).collect();
		assert!(
			pool.select_with_pressure_excluding(ip, &health, &|_| 0.0, &all)
				.is_none()
		);
	}

	#[test]
	fn test_zero_pressure_matches_select() {
		let pool: BackendPool = BackendPool::new(make_backends(3)).unwrap();
		let health: HealthState = HealthState::new();
		let ip: IpAddr = "192.168.1.1".parse().unwrap();

		let normal: Option<&BackendConfig> = pool.select(ip, &health);
		let with_zero: Option<&BackendConfig> = pool.select_with_pressure(ip, &health, &|_| 0.0);

		assert_eq!(normal.map(|b| &b.id), with_zero.map(|b| &b.id));
	}
}
