use tokio::sync::{Semaphore, SemaphorePermit};

use crate::error::{ReductionError, Result};

#[derive(Debug)]
pub struct RequestQueue {
    semaphore: Semaphore,
    max_depth: u32,
}

impl RequestQueue {
    pub fn new(max_depth: u32) -> Self {
        return Self {
            semaphore: Semaphore::new(max_depth as usize),
            max_depth,
        };
    }

    pub fn try_acquire(&self) -> Result<SemaphorePermit<'_>> {
        match self.semaphore.try_acquire() {
            Ok(permit) => return Ok(permit),
            Err(_) => return Err(ReductionError::QueueFull),
        }
    }

    pub fn depth(&self) -> u32 {
        // Safe: available_permits <= max_depth (u32), so subtraction fits in u32
        return self.max_depth - self.semaphore.available_permits() as u32;
    }

    pub fn max_depth(&self) -> u32 {
        return self.max_depth;
    }

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
}
