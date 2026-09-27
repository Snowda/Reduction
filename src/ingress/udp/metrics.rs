use std::sync::atomic::{AtomicU64, Ordering};

use opentelemetry::metrics::{Counter, Histogram, Meter, UpDownCounter};
use opentelemetry::{KeyValue, global};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DropReason {
	Acl,
	RateLimit,
	Oversize,
	NoBackend,
	Backpressure,
	CircuitOpen,
	Protocol,
}

impl DropReason {
	#[must_use]
	pub const fn as_str(&self) -> &'static str {
		return match self {
			Self::Acl => "acl",
			Self::RateLimit => "rate_limit",
			Self::Oversize => "oversize",
			Self::NoBackend => "no_backend",
			Self::Backpressure => "backpressure",
			Self::CircuitOpen => "circuit_open",
			Self::Protocol => "protocol",
		};
	}
}

// OTel instruments for one ingress listener, all carrying the `ingress_id` attribute (plus `reason`
// on drops and `backend` on per-backend gauges). Built from the global meter, which is a no-op until
// init_metrics runs — so constructing this in tests or before export is configured is harmless.
struct IngressInstruments {
	received: Counter<u64>,
	relayed: Counter<u64>,
	dropped: Counter<u64>,
	batches_sent: Counter<u64>,
	batch_datagrams: Histogram<u64>,
	queue_depth: UpDownCounter<i64>,
	stream_reconnects: Counter<u64>,
}

impl IngressInstruments {
	fn new() -> Self {
		let meter: Meter = global::meter("reduction");
		return Self {
			received: meter
				.u64_counter("proxy.ingress.received")
				.with_description("Datagrams received by an ingress listener")
				.build(),
			relayed: meter
				.u64_counter("proxy.ingress.relayed")
				.with_description("Datagrams relayed to a backend over a QUIC stream")
				.build(),
			dropped: meter
				.u64_counter("proxy.ingress.dropped")
				.with_description("Datagrams dropped by an ingress listener, by reason")
				.build(),
			batches_sent: meter
				.u64_counter("proxy.ingress.batches_sent")
				.with_description("Envelope batch frames written to a backend")
				.build(),
			batch_datagrams: meter
				.u64_histogram("proxy.ingress.batch_datagrams")
				.with_description("Datagrams per relayed batch")
				.build(),
			queue_depth: meter
				.i64_up_down_counter("proxy.ingress.queue_depth")
				.with_description("Batches queued to a backend writer, by backend")
				.build(),
			stream_reconnects: meter
				.u64_counter("proxy.ingress.stream_reconnects")
				.with_description("Backend stream re-establishments, by backend")
				.build(),
		};
	}
}

// Per-ingress accounting. The atomics are the tested source of truth for the invariant
// `received == relayed + Σ dropped` (at quiescence); each mutator also emits the matching OTel signal
// so the two never diverge. Shared (Arc) across every worker of one ingress, so per-worker counts sum
// automatically.
pub struct IngressCounters {
	received: AtomicU64,
	relayed: AtomicU64,
	dropped_acl: AtomicU64,
	dropped_rate_limit: AtomicU64,
	dropped_oversize: AtomicU64,
	dropped_no_backend: AtomicU64,
	dropped_backpressure: AtomicU64,
	dropped_circuit_open: AtomicU64,
	dropped_protocol: AtomicU64,
	instruments: IngressInstruments,
	ingress_attrs: [KeyValue; 1],
}

impl IngressCounters {
	#[must_use]
	pub fn new(ingress_id: &str) -> Self {
		return Self {
			received: AtomicU64::new(0),
			relayed: AtomicU64::new(0),
			dropped_acl: AtomicU64::new(0),
			dropped_rate_limit: AtomicU64::new(0),
			dropped_oversize: AtomicU64::new(0),
			dropped_no_backend: AtomicU64::new(0),
			dropped_backpressure: AtomicU64::new(0),
			dropped_circuit_open: AtomicU64::new(0),
			dropped_protocol: AtomicU64::new(0),
			instruments: IngressInstruments::new(),
			ingress_attrs: [KeyValue::new("ingress_id", ingress_id.to_owned())],
		};
	}

	pub fn record_received(&self) {
		self.received.fetch_add(1, Ordering::Relaxed);
		self.instruments.received.add(1, &self.ingress_attrs);
	}

	pub fn record_relayed(&self, count: u64) {
		self.relayed.fetch_add(count, Ordering::Relaxed);
		self.instruments.relayed.add(count, &self.ingress_attrs);
	}

	pub fn record_drop(&self, reason: DropReason, count: u64) {
		self.drop_atomic(reason).fetch_add(count, Ordering::Relaxed);
		let attrs: [KeyValue; 2] = [self.ingress_attrs[0].clone(), KeyValue::new("reason", reason.as_str())];
		self.instruments.dropped.add(count, &attrs);
	}

	// One batch frame left for a backend: bump the batch counter and record its datagram count into
	// the size histogram. Relayed datagrams are counted separately via record_relayed.
	pub fn record_batch_sent(&self, datagrams: u64) {
		self.instruments.batches_sent.add(1, &self.ingress_attrs);
		self.instruments.batch_datagrams.record(datagrams, &self.ingress_attrs);
	}

	pub fn record_stream_reconnect(&self, backend_id: &str) {
		let attrs: [KeyValue; 2] = [
			self.ingress_attrs[0].clone(),
			KeyValue::new("backend", backend_id.to_owned()),
		];
		self.instruments.stream_reconnects.add(1, &attrs);
	}

	// In-flight batches queued to a backend writer: +1 on enqueue, −1 when the writer dequeues.
	pub fn queue_depth_add(&self, backend_id: &str, delta: i64) {
		let attrs: [KeyValue; 2] = [
			self.ingress_attrs[0].clone(),
			KeyValue::new("backend", backend_id.to_owned()),
		];
		self.instruments.queue_depth.add(delta, &attrs);
	}

	const fn drop_atomic(&self, reason: DropReason) -> &AtomicU64 {
		return match reason {
			DropReason::Acl => &self.dropped_acl,
			DropReason::RateLimit => &self.dropped_rate_limit,
			DropReason::Oversize => &self.dropped_oversize,
			DropReason::NoBackend => &self.dropped_no_backend,
			DropReason::Backpressure => &self.dropped_backpressure,
			DropReason::CircuitOpen => &self.dropped_circuit_open,
			DropReason::Protocol => &self.dropped_protocol,
		};
	}

	#[must_use]
	pub fn received(&self) -> u64 {
		return self.received.load(Ordering::Relaxed);
	}

	#[must_use]
	pub fn relayed(&self) -> u64 {
		return self.relayed.load(Ordering::Relaxed);
	}

	#[must_use]
	pub fn dropped(&self, reason: DropReason) -> u64 {
		return self.drop_atomic(reason).load(Ordering::Relaxed);
	}

	// Sum of every drop reason. `received == relayed + total_dropped()` once the pipeline has drained
	// (no batches still in flight) — the accounting-closes invariant.
	#[must_use]
	pub fn total_dropped(&self) -> u64 {
		return self.dropped(DropReason::Acl)
			+ self.dropped(DropReason::RateLimit)
			+ self.dropped(DropReason::Oversize)
			+ self.dropped(DropReason::NoBackend)
			+ self.dropped(DropReason::Backpressure)
			+ self.dropped(DropReason::CircuitOpen)
			+ self.dropped(DropReason::Protocol);
	}
}

// The admission gate for one datagram: ACL, then per-IP rate limit, then size cap — the plan's order.
// Returns the drop reason instead of an opaque error so the caller counts by reason. The size cap

#[cfg(test)]
mod tests {
	use super::*;

	// ── DropReason / counters ──

	#[test]
	fn test_drop_reason_labels_are_stable() {
		assert_eq!(DropReason::Acl.as_str(), "acl");
		assert_eq!(DropReason::RateLimit.as_str(), "rate_limit");
		assert_eq!(DropReason::Oversize.as_str(), "oversize");
		assert_eq!(DropReason::NoBackend.as_str(), "no_backend");
		assert_eq!(DropReason::Backpressure.as_str(), "backpressure");
		assert_eq!(DropReason::CircuitOpen.as_str(), "circuit_open");
		assert_eq!(DropReason::Protocol.as_str(), "protocol");
	}

	#[test]
	fn test_counters_track_received_relayed_and_each_drop() {
		let counters: IngressCounters = IngressCounters::new("test");
		counters.record_received();
		counters.record_received();
		counters.record_relayed(5);
		counters.record_drop(DropReason::Acl, 1);
		counters.record_drop(DropReason::Backpressure, 3);
		assert_eq!(counters.received(), 2);
		assert_eq!(counters.relayed(), 5);
		assert_eq!(counters.dropped(DropReason::Acl), 1);
		assert_eq!(counters.dropped(DropReason::Backpressure), 3);
		assert_eq!(counters.dropped(DropReason::Oversize), 0, "untouched reasons stay zero");
	}

	// The accounting-closes invariant at the counter level: received equals relayed plus every drop.
	#[test]
	fn test_accounting_invariant_closes() {
		let counters: IngressCounters = IngressCounters::new("test");
		for _ in 0..10 {
			counters.record_received();
		}
		counters.record_relayed(6);
		counters.record_drop(DropReason::Acl, 1);
		counters.record_drop(DropReason::Oversize, 1);
		counters.record_drop(DropReason::Backpressure, 2);
		assert_eq!(counters.total_dropped(), 4);
		assert_eq!(
			counters.received(),
			counters.relayed() + counters.total_dropped(),
			"received must equal relayed + Σ dropped"
		);
	}

	#[test]
	fn test_counters_metric_helpers_do_not_panic() {
		// The OTel emission path (no-op meter in tests) must run cleanly for every helper.
		let counters: IngressCounters = IngressCounters::new("test");
		counters.record_batch_sent(7);
		counters.record_stream_reconnect("ingest-a");
		counters.queue_depth_add("ingest-a", 1);
		counters.queue_depth_add("ingest-a", -1);
	}

}
