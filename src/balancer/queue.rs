use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore, SemaphorePermit};

use crate::error::{ReductionError, Result};

#[derive(Debug)]
pub struct RequestQueue {
	// Held behind an Arc so a permit can outlive the borrow of the queue — the proxied response body
	// owns its permit and releases it at true end-of-body, long after the handler has returned.
	semaphore: Arc<Semaphore>,
	max_depth: u32,
}

impl RequestQueue {
	#[must_use]
	pub fn new(max_depth: u32) -> Self {
		return Self {
			semaphore: Arc::new(Semaphore::new(usize::try_from(max_depth).unwrap_or(usize::MAX))),
			max_depth,
		};
	}

	pub fn try_acquire(&self) -> Result<SemaphorePermit<'_>> {
		match self.semaphore.try_acquire() {
			Ok(permit) => return Ok(permit),
			Err(_) => return Err(ReductionError::QueueFull),
		}
	}

	// Owned counterpart to try_acquire: the returned permit carries no borrow of the queue, so it can
	// be moved into a streaming response body and released only when that body finishes.
	pub fn try_acquire_owned(&self) -> Result<OwnedSemaphorePermit> {
		match Arc::clone(&self.semaphore).try_acquire_owned() {
			Ok(permit) => return Ok(permit),
			Err(_) => return Err(ReductionError::QueueFull),
		}
	}

	#[must_use]
	pub fn depth(&self) -> u32 {
		// available_permits <= max_depth (u32); the fallback is unreachable but avoids a panic.
		let available: u32 = u32::try_from(self.semaphore.available_permits()).unwrap_or(self.max_depth);
		return self.max_depth.saturating_sub(available);
	}

	#[must_use]
	pub const fn max_depth(&self) -> u32 {
		return self.max_depth;
	}

	#[must_use]
	pub fn is_full(&self) -> bool {
		return self.semaphore.available_permits() == 0;
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_queue_acquire_and_release() {
		let queue: RequestQueue = RequestQueue::new(2);
		assert_eq!(queue.depth(), 0);
		assert!(!queue.is_full());

		let _g1: SemaphorePermit<'_> = queue.try_acquire().unwrap();
		assert_eq!(queue.depth(), 1);

		let _g2: SemaphorePermit<'_> = queue.try_acquire().unwrap();
		assert_eq!(queue.depth(), 2);
		assert!(queue.is_full());

		assert!(queue.try_acquire().is_err());
	}

	#[test]
	fn test_queue_release_on_drop() {
		let queue: RequestQueue = RequestQueue::new(1);

		{
			let _permit: SemaphorePermit<'_> = queue.try_acquire().unwrap();
			assert_eq!(queue.depth(), 1);
		}

		assert_eq!(queue.depth(), 0);
		let _permit = queue.try_acquire().unwrap();
		assert_eq!(queue.depth(), 1);
	}

	#[test]
	fn test_queue_max_depth() {
		let queue: RequestQueue = RequestQueue::new(100);
		assert_eq!(queue.max_depth(), 100);
	}

	#[test]
	fn test_queue_depth_one() {
		let queue: RequestQueue = RequestQueue::new(1);
		let _permit = queue.try_acquire().unwrap();
		assert!(queue.is_full());
		assert!(queue.try_acquire().is_err());
	}

	#[test]
	fn test_queue_acquire_owned_counts_against_depth() {
		let queue: RequestQueue = RequestQueue::new(1);
		let permit: OwnedSemaphorePermit = queue.try_acquire_owned().unwrap();
		assert_eq!(queue.depth(), 1);
		assert!(queue.is_full());
		// The single slot is taken, so both the borrowed and owned acquires must fail.
		assert!(queue.try_acquire().is_err());
		assert!(queue.try_acquire_owned().is_err());
		drop(permit);
		assert_eq!(queue.depth(), 0);
		assert!(queue.try_acquire_owned().is_ok());
	}

	#[test]
	fn test_queue_owned_permit_outlives_queue_borrow() {
		// The owned permit carries no borrow of the queue, so it can be returned from a scope that
		// only briefly borrowed the queue — the property the streaming response body relies on.
		let queue: RequestQueue = RequestQueue::new(2);
		let permit: OwnedSemaphorePermit = { queue.try_acquire_owned().unwrap() };
		assert_eq!(queue.depth(), 1);
		drop(permit);
		assert_eq!(queue.depth(), 0);
	}
}
