use std::sync::Arc;

use crate::error::{ReductionError, Result};
use crate::gate::{AdmissionGate, GatePermit, OwnedGatePermit};

#[derive(Debug)]
pub struct RequestQueue {
	// Held behind an Arc so a permit can outlive the borrow of the queue — the proxied response body
	// owns its permit and releases it at true end-of-body, long after the handler has returned.
	gate: Arc<AdmissionGate>,
	max_depth: u32,
}

impl RequestQueue {
	#[must_use]
	pub fn new(max_depth: u32) -> Self {
		return Self {
			gate: Arc::new(AdmissionGate::new(max_depth)),
			max_depth,
		};
	}

	pub fn try_acquire(&self) -> Result<GatePermit<&AdmissionGate>> {
		return self.gate.try_acquire().ok_or(ReductionError::QueueFull);
	}

	// Owned counterpart to try_acquire: the returned permit carries no borrow of the queue, so it can
	// be moved into a streaming response body and released only when that body finishes.
	pub fn try_acquire_owned(&self) -> Result<OwnedGatePermit> {
		return self.gate.try_acquire_owned().ok_or(ReductionError::QueueFull);
	}

	#[must_use]
	pub fn depth(&self) -> u32 {
		return self.gate.in_use();
	}

	#[must_use]
	pub const fn max_depth(&self) -> u32 {
		return self.max_depth;
	}

	#[must_use]
	pub fn is_full(&self) -> bool {
		return self.gate.is_full();
	}
}

#[cfg(test)]
mod tests {
	use std::result::Result;

	use super::*;

	#[test]
	fn test_queue_acquire_and_release() -> Result<(), String> {
		let queue: RequestQueue = RequestQueue::new(2);
		assert_eq!(queue.depth(), 0);
		assert!(!queue.is_full());

		let _g1: GatePermit<&AdmissionGate> = match queue.try_acquire() {
			Ok(value) => value,
			Err(err) => return Err(format!("queue.try_acquire(): {err:?}")),
		};
		assert_eq!(queue.depth(), 1);

		let _g2: GatePermit<&AdmissionGate> = match queue.try_acquire() {
			Ok(value) => value,
			Err(err) => return Err(format!("queue.try_acquire(): {err:?}")),
		};
		assert_eq!(queue.depth(), 2);
		assert!(queue.is_full());

		assert!(queue.try_acquire().is_err());
		return Ok(());
	}

	#[test]
	fn test_queue_release_on_drop() -> Result<(), String> {
		let queue: RequestQueue = RequestQueue::new(1);

		{
			let _permit: GatePermit<&AdmissionGate> = match queue.try_acquire() {
				Ok(value) => value,
				Err(err) => return Err(format!("queue.try_acquire(): {err:?}")),
			};
			assert_eq!(queue.depth(), 1);
		}

		assert_eq!(queue.depth(), 0);
		let _permit = match queue.try_acquire() {
			Ok(value) => value,
			Err(err) => return Err(format!("queue.try_acquire(): {err:?}")),
		};
		assert_eq!(queue.depth(), 1);
		return Ok(());
	}

	#[test]
	fn test_queue_max_depth() {
		let queue: RequestQueue = RequestQueue::new(100);
		assert_eq!(queue.max_depth(), 100);
	}

	#[test]
	fn test_queue_depth_one() -> Result<(), String> {
		let queue: RequestQueue = RequestQueue::new(1);
		let _permit = match queue.try_acquire() {
			Ok(value) => value,
			Err(err) => return Err(format!("queue.try_acquire(): {err:?}")),
		};
		assert!(queue.is_full());
		assert!(queue.try_acquire().is_err());
		return Ok(());
	}

	#[test]
	fn test_queue_acquire_owned_counts_against_depth() -> Result<(), String> {
		let queue: RequestQueue = RequestQueue::new(1);
		let permit: OwnedGatePermit = match queue.try_acquire_owned() {
			Ok(value) => value,
			Err(err) => return Err(format!("queue.try_acquire_owned(): {err:?}")),
		};
		assert_eq!(queue.depth(), 1);
		assert!(queue.is_full());
		// The single slot is taken, so both the borrowed and owned acquires must fail.
		assert!(queue.try_acquire().is_err());
		assert!(queue.try_acquire_owned().is_err());
		drop(permit);
		assert_eq!(queue.depth(), 0);
		assert!(queue.try_acquire_owned().is_ok());
		return Ok(());
	}

	#[test]
	fn test_queue_owned_permit_outlives_queue_borrow() -> Result<(), String> {
		// The owned permit carries no borrow of the queue, so it can be returned from a scope that
		// only briefly borrowed the queue — the property the streaming response body relies on.
		let queue: RequestQueue = RequestQueue::new(2);
		let permit: OwnedGatePermit = {
			match queue.try_acquire_owned() {
				Ok(value) => value,
				Err(err) => return Err(format!("queue.try_acquire_owned(): {err:?}")),
			}
		};
		assert_eq!(queue.depth(), 1);
		drop(permit);
		assert_eq!(queue.depth(), 0);
		return Ok(());
	}
}
