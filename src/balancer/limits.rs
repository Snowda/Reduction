// Pool construction: a backend list is accepted only within the configured cap and the MAX_BACKENDS hard limit.
use std::sync::Arc;

use super::{BackendPool, MAX_BACKENDS};
use crate::config::{BackendConfig, DEFAULT_MAX_BACKENDS, PoolAffinity};
use crate::error::{ReductionError, Result};

impl BackendPool {
	pub fn new(backends: Vec<BackendConfig>) -> Result<Self> {
		return Self::with_max(backends, DEFAULT_MAX_BACKENDS);
	}

	pub fn with_max(backends: Vec<BackendConfig>, max_backends: u32) -> Result<Self> {
		if backends.len() > usize::try_from(max_backends).unwrap_or(usize::MAX) {
			return Err(ReductionError::Config(format!(
				"backend count {} exceeds maximum {max_backends}",
				backends.len(),
			).into()));
		}
		if backends.len() > MAX_BACKENDS {
			return Err(ReductionError::Config(format!(
				"backend count {} exceeds hard limit {MAX_BACKENDS}",
				backends.len(),
			).into()));
		}
		return Ok(Self {
			backends: Arc::from(backends),
			affinity: PoolAffinity::default(),
		});
	}
}

#[cfg(test)]
mod tests {
	use std::result::Result;

	use super::*;
	use crate::balancer::testutil::make_backends;
	use crate::config::HARD_MAX_BACKENDS;

	#[test]
	fn test_pool_rejects_too_many_backends_default() -> Result<(), String> {
		let result = BackendPool::new(make_backends(65)?);
		assert!(result.is_err());
		let err: String = format!(
			"{}",
			match result {
				Ok(value) => return Err(format!("result: expected Err, got Ok({value:?})")),
				Err(err) => err,
			}
		);
		assert!(err.contains("exceeds maximum"), "expected exceeds maximum, got: {err}");
		return Ok(());
	}

	#[test]
	fn test_pool_accepts_default_max_backends() -> Result<(), String> {
		let result = BackendPool::new(make_backends(64)?);
		assert!(result.is_ok());
		assert_eq!(
			(result.map_err(|err| format!("result: {err:?}"))?)
			.backends
			.len(),
			64
		);
		return Ok(());
	}

	#[test]
	fn test_pool_with_max_custom_limit() -> Result<(), String> {
		let result = BackendPool::with_max(
			make_backends(100)?,
			100,
		);
		assert!(result.is_ok());
		assert_eq!(
			(result.map_err(|err| format!("result: {err:?}"))?)
			.backends
			.len(),
			100
		);
		return Ok(());
	}

	#[test]
	fn test_pool_with_max_rejects_over_custom_limit() -> Result<(), String> {
		let result = BackendPool::with_max(
			make_backends(101)?,
			100,
		);
		assert!(result.is_err());
		return Ok(());
	}

	#[test]
	fn test_pool_rejects_over_hard_limit() -> Result<(), String> {
		let result = BackendPool::with_max(
			make_backends(MAX_BACKENDS + 1)?,
			HARD_MAX_BACKENDS + 1,
		);
		assert!(result.is_err());
		let err: String = format!(
			"{}",
			match result {
				Ok(value) => return Err(format!("result: expected Err, got Ok({value:?})")),
				Err(err) => err,
			}
		);
		assert!(err.contains("hard limit"), "expected hard limit error, got: {err}");
		return Ok(());
	}

	// MAX_BACKENDS is written out (a const cannot convert u32 -> usize without `as`); keep it equal to the config cap.
	#[test]
	fn max_backends_matches_hard_limit() -> Result<(), String> {
		let hard_limit: usize = usize::try_from(HARD_MAX_BACKENDS)
			.map_err(|err| format!("HARD_MAX_BACKENDS as usize: {err}"))?;
		assert_eq!(MAX_BACKENDS, hard_limit);
		return Ok(());
	}
}
