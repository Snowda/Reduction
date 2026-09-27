use std::time::{Duration, Instant};

use crate::ingress::protocol::Datagram;

// Why a batch flushed, for drop/relay accounting and tests. Each trigger is independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FlushReason {
	// Reached batch_max_datagrams.
	Count,
	// Reached batch_max_bytes of accumulated payload.
	Bytes,
	// The oldest datagram has waited linger without the batch filling.
	Linger,
}

// Caps that govern when an in-flight batch is handed off. Copy — plain configuration data.
#[derive(Debug, Clone, Copy)]
pub struct BatchLimits {
	pub max_datagrams: u32,
	// Ceiling on accumulated opaque payload bytes (not the encoded frame size; the frame cap is
	// enforced separately at encode time). Sized so one encoded frame stays under MAX_ENVELOPE_FRAME.
	pub max_bytes: u32,
	pub linger: Duration,
}

// An in-flight batch for one backend. Pure accumulator: decides *when* to flush and hands back the
// datagrams, never touching the network. The recv loop owns one per backend, single-threaded.
pub struct Batch {
	datagrams: Vec<Datagram>,
	payload_bytes: usize,
	// When the first datagram of the current batch arrived — the clock the linger deadline runs from.
	opened_at: Option<Instant>,
}

impl Batch {
	#[must_use]
	pub const fn new() -> Self {
		return Self {
			datagrams: Vec::new(),
			payload_bytes: 0,
			opened_at: None,
		};
	}

	#[must_use]
	pub const fn is_empty(&self) -> bool {
		return self.datagrams.is_empty();
	}

	#[must_use]
	pub const fn len(&self) -> usize {
		return self.datagrams.len();
	}

	#[must_use]
	pub const fn payload_bytes(&self) -> usize {
		return self.payload_bytes;
	}

	// Append a datagram, stamping the open time on the first one so linger is measured from arrival.
	pub fn push(&mut self, now: Instant, datagram: Datagram) {
		if self.datagrams.is_empty() {
			self.opened_at = Some(now);
		}
		self.payload_bytes = self.payload_bytes.saturating_add(datagram.payload.len());
		self.datagrams.push(datagram);
	}

	// Count/bytes triggers, checked right after a push. Count is checked before bytes so a batch that
	// hits both reports the count trigger; either way the batch is handed off.
	#[must_use]
	pub fn fill_flush(&self, limits: &BatchLimits) -> Option<FlushReason> {
		if self.datagrams.is_empty() {
			return None;
		}
		if self.datagrams.len() >= usize::try_from(limits.max_datagrams).unwrap_or(usize::MAX) {
			return Some(FlushReason::Count);
		}
		if self.payload_bytes >= usize::try_from(limits.max_bytes).unwrap_or(usize::MAX) {
			return Some(FlushReason::Bytes);
		}
		return None;
	}

	// True once the oldest datagram has waited at least `linger`; time is passed in so the caller controls the clock.
	#[must_use]
	pub fn linger_expired(&self, limits: &BatchLimits, now: Instant) -> bool {
		return match self.opened_at {
			Some(opened) => now.duration_since(opened) >= limits.linger,
			None => false,
		};
	}

	// Deadline for the current batch's linger, if buffered — lets the driver arm a timer instead of polling.
	#[must_use]
	pub fn linger_deadline(&self, limits: &BatchLimits) -> Option<Instant> {
		return self.opened_at.map(|opened| opened + limits.linger);
	}

	// Drain the batch and reset it, returning the accumulated datagrams for hand-off (empty yields empty Vec).
	#[must_use]
	pub fn take(&mut self) -> Vec<Datagram> {
		self.payload_bytes = 0;
		self.opened_at = None;
		return std::mem::take(&mut self.datagrams);
	}
}

impl Default for Batch {
	fn default() -> Self {
		return Self::new();
	}
}

#[cfg(test)]
mod tests {
	use std::net::SocketAddr;

	use super::*;
	use crate::ingress::protocol::Peer;

	const TEST_LINGER: Duration = Duration::from_millis(20);

	fn limits(max_datagrams: u32, max_bytes: u32) -> BatchLimits {
		return BatchLimits {
			max_datagrams,
			max_bytes,
			linger: TEST_LINGER,
		};
	}

	fn datagram(payload: &[u8]) -> Datagram {
		let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
		return Datagram {
			peer: Peer::from_socket_addr(addr),
			recv_at_unix_nanos: 0,
			payload: payload.to_vec(),
		};
	}

	#[test]
	fn test_empty_batch_never_flushes() {
		let batch: Batch = Batch::new();
		let lim: BatchLimits = limits(1, 1);
		assert!(batch.is_empty());
		assert_eq!(batch.fill_flush(&lim), None);
		assert!(!batch.linger_expired(&lim, Instant::now()));
		assert!(batch.linger_deadline(&lim).is_none());
	}

	#[test]
	fn test_flush_on_count_independent_of_bytes() {
		// max_bytes is set huge so only the count trigger can fire.
		let lim: BatchLimits = limits(3, u32::MAX);
		let mut batch: Batch = Batch::new();
		let now: Instant = Instant::now();
		batch.push(now, datagram(b"a"));
		batch.push(now, datagram(b"b"));
		assert_eq!(batch.fill_flush(&lim), None, "two of three must not flush");
		batch.push(now, datagram(b"c"));
		assert_eq!(batch.fill_flush(&lim), Some(FlushReason::Count));
	}

	#[test]
	fn test_flush_on_bytes_independent_of_count() {
		// max_datagrams huge so only the bytes trigger can fire; three 4-byte payloads reach 12 bytes.
		let lim: BatchLimits = limits(u32::MAX, 12);
		let mut batch: Batch = Batch::new();
		let now: Instant = Instant::now();
		batch.push(now, datagram(b"aaaa"));
		batch.push(now, datagram(b"bbbb"));
		assert_eq!(batch.fill_flush(&lim), None, "8 of 12 bytes must not flush");
		batch.push(now, datagram(b"cccc"));
		assert_eq!(batch.fill_flush(&lim), Some(FlushReason::Bytes));
	}

	#[test]
	fn test_flush_on_linger_independent_of_count_and_bytes() {
		// Caps set high so neither count nor bytes can fire; only elapsed time flushes.
		let lim: BatchLimits = limits(u32::MAX, u32::MAX);
		let mut batch: Batch = Batch::new();
		let opened: Instant = Instant::now();
		batch.push(opened, datagram(b"x"));
		assert_eq!(
			batch.fill_flush(&lim),
			None,
			"one datagram under caps must not fill-flush"
		);
		assert!(
			!batch.linger_expired(&lim, opened),
			"linger cannot expire at the open instant"
		);
		assert!(
			batch.linger_expired(&lim, opened + TEST_LINGER),
			"linger must expire once the interval has elapsed"
		);
		assert_eq!(batch.linger_deadline(&lim), Some(opened + TEST_LINGER));
	}

	#[test]
	fn test_take_drains_and_resets() {
		let lim: BatchLimits = limits(10, 1024);
		let mut batch: Batch = Batch::new();
		let now: Instant = Instant::now();
		batch.push(now, datagram(b"one"));
		batch.push(now, datagram(b"two"));
		assert_eq!(batch.len(), 2);
		assert_eq!(batch.payload_bytes(), 6);

		let drained: Vec<Datagram> = batch.take();
		assert_eq!(drained.len(), 2, "take must return every buffered datagram");
		assert!(batch.is_empty(), "batch must be empty after take");
		assert_eq!(batch.payload_bytes(), 0, "byte accounting must reset after take");
		assert!(
			batch.linger_deadline(&lim).is_none(),
			"linger clock must reset after take"
		);
	}
}
