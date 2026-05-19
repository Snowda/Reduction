use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Semaphore;

use crate::error::{ReductionError, Result};

#[derive(Debug)]
pub struct RequestQueue {
    semaphore: Semaphore,
    max_depth: usize,
    current_depth: AtomicUsize,
}

impl RequestQueue {
    pub fn new(max_depth: usize) -> Self {
        return Self {
            semaphore: Semaphore::new(max_depth),
            max_depth,
            current_depth: AtomicUsize::new(0),
        };
    }

    // Try to acquire a slot in the queue. Returns a guard that releases the slot on drop.
    pub fn try_acquire(&self) -> Result<QueueGuard<'_>> {
        match self.semaphore.try_acquire() {
            Ok(permit) => {
                self.current_depth.fetch_add(1, Ordering::Relaxed);
                return Ok(QueueGuard {
                    _permit: permit,
                    depth_counter: &self.current_depth,
                });
            }
            Err(_) => {
                return Err(ReductionError::QueueFull);
            }
        }
    }

    pub fn depth(&self) -> usize {
        return self.current_depth.load(Ordering::Relaxed);
    }

    pub fn max_depth(&self) -> usize {
        return self.max_depth;
    }

    pub fn is_full(&self) -> bool {
        return self.depth() >= self.max_depth;
    }
}

pub struct QueueGuard<'a> {
    _permit: tokio::sync::SemaphorePermit<'a>,
    depth_counter: &'a AtomicUsize,
}

impl<'a> Drop for QueueGuard<'a> {
    fn drop(&mut self) {
        self.depth_counter.fetch_sub(1, Ordering::Relaxed);
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

        let _g1: QueueGuard<'_> = queue.try_acquire().unwrap();
        assert_eq!(queue.depth(), 1);

        let _g2: QueueGuard<'_> = queue.try_acquire().unwrap();
        assert_eq!(queue.depth(), 2);
        assert!(queue.is_full());

        // Third should fail
        let result: Result<QueueGuard<'_>> = queue.try_acquire();
        assert!(result.is_err());
    }

    #[test]
    fn test_queue_release_on_drop() {
        let queue: RequestQueue = RequestQueue::new(1);

        {
            let _guard: QueueGuard<'_> = queue.try_acquire().unwrap();
            assert_eq!(queue.depth(), 1);
        }

        assert_eq!(queue.depth(), 0);
        // Can acquire again after drop
        let _guard: QueueGuard<'_> = queue.try_acquire().unwrap();
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
        let _guard: QueueGuard<'_> = queue.try_acquire().unwrap();
        assert!(queue.is_full());
        assert!(queue.try_acquire().is_err());
    }
}
