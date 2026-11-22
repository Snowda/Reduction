// The egress gateway's OTel instruments: open and total tunnels, refusals by reason, and bytes relayed.
use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry::metrics::{Counter, Meter, UpDownCounter};

use super::denial::Denial;
use crate::proxy::relay::RelayStats;

const METER_NAME: &str = "reduction";
const TUNNELS_ACTIVE: &str = "egress.tunnels.active";
const TUNNELS_OPENED: &str = "egress.tunnels.opened";
const DENIALS: &str = "egress.denials";
const BYTES: &str = "egress.bytes";
const REASON_KEY: &str = "reason";
const DIRECTION_KEY: &str = "direction";
// Client to target, and target to client.
const UP: &str = "up";
const DOWN: &str = "down";

#[derive(Clone)]
pub struct EgressMetrics {
	tunnels_active: UpDownCounter<i64>,
	tunnels_opened: Counter<u64>,
	denials: Counter<u64>,
	bytes: Counter<u64>,
}

impl EgressMetrics {
	#[must_use]
	pub fn new(meter: &Meter) -> Self {
		return Self {
			tunnels_active: meter.i64_up_down_counter(TUNNELS_ACTIVE).with_description("Egress tunnels open now").build(),
			tunnels_opened: meter.u64_counter(TUNNELS_OPENED).with_description("Egress tunnels opened since start").build(),
			denials: meter.u64_counter(DENIALS).with_description("Refused CONNECT requests, by reason").build(),
			bytes: meter.u64_counter(BYTES).with_description("Bytes relayed through egress tunnels, by direction").build(),
		};
	}

	// The instruments on the global meter provider that `init_metrics` installs.
	#[must_use]
	pub fn global() -> Self {
		return Self::new(&global::meter(METER_NAME));
	}

	pub fn denied(&self, denial: Denial) {
		self.denials.add(1, &[KeyValue::new(REASON_KEY, denial.label())]);
	}

	pub fn opened(&self) {
		self.tunnels_opened.add(1, &[]);
		self.tunnels_active.add(1, &[]);
	}

	// A tunnel whose upgrade or splice failed has no stats: it closes with no bytes counted.
	pub fn closed(&self, stats: Option<&RelayStats>) {
		self.tunnels_active.add(-1, &[]);
		if let Some(stats) = stats {
			self.bytes.add(stats.bytes_a_to_b, &[KeyValue::new(DIRECTION_KEY, UP)]);
			self.bytes.add(stats.bytes_b_to_a, &[KeyValue::new(DIRECTION_KEY, DOWN)]);
		}
	}
}

#[cfg(test)]
pub mod testutil {
	use opentelemetry::metrics::MeterProvider;
	use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
	use opentelemetry_sdk::metrics::{InMemoryMetricExporter, SdkMeterProvider};

	use super::*;

	// An exporter that keeps what it collects, so a test reads back each sum it recorded.
	pub struct Recorder {
		provider: SdkMeterProvider,
		exporter: InMemoryMetricExporter,
	}

	impl Default for Recorder {
		fn default() -> Self {
			return Self::new();
		}
	}

	impl Recorder {
		#[must_use]
		pub fn new() -> Self {
			let exporter: InMemoryMetricExporter = InMemoryMetricExporter::default();
			let provider: SdkMeterProvider = SdkMeterProvider::builder().with_periodic_exporter(exporter.clone()).build();
			return Self { provider, exporter };
		}

		#[must_use]
		pub fn metrics(&self) -> EgressMetrics {
			return EgressMetrics::new(&self.provider.meter(METER_NAME));
		}

		// The cumulative sum of `name` over data points that carry `attr`, or all of them when `attr` is None.
		pub fn sum(&self, name: &str, attr: Option<(&str, &str)>) -> Result<i64, String> {
			self.provider.force_flush().map_err(|err| format!("flush: {err}"))?;
			let exported: Vec<ResourceMetrics> = self.exporter.get_finished_metrics().map_err(|err| format!("export: {err}"))?;
			let Some(latest) = exported.last() else {
				return Ok(0);
			};
			let total: i64 = latest
				.scope_metrics()
				.flat_map(|scope| scope.metrics())
				.filter(|metric| metric.name() == name)
				.map(|metric| {
					return match metric.data() {
						AggregatedMetrics::U64(MetricData::Sum(sum)) => sum
							.data_points()
							.filter(|point| has_attr(point.attributes(), attr))
							.map(|point| i64::try_from(point.value()).unwrap_or(i64::MAX))
							.sum::<i64>(),
						AggregatedMetrics::I64(MetricData::Sum(sum)) => {
							sum.data_points().filter(|point| has_attr(point.attributes(), attr)).map(|point| point.value()).sum::<i64>()
						}
						_ => 0,
					};
				})
				.sum();
			return Ok(total);
		}
	}

	fn has_attr<'a>(mut attrs: impl Iterator<Item = &'a KeyValue>, attr: Option<(&str, &str)>) -> bool {
		return attr.is_none_or(|(key, value)| attrs.any(|kv| kv.key.as_str() == key && kv.value.as_str() == value));
	}
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use super::testutil::Recorder;
	use super::*;
	use crate::proxy::relay::RelayEnd;

	const UP_BYTES: u64 = 120;
	const DOWN_BYTES: u64 = 4500;

	#[test]
	fn each_event_moves_its_own_instrument() -> Result<(), String> {
		let recorder: Recorder = Recorder::new();
		let metrics: EgressMetrics = recorder.metrics();
		metrics.denied(Denial::HostNotAllowed);
		metrics.denied(Denial::HostNotAllowed);
		metrics.denied(Denial::RateLimited);
		metrics.opened();
		metrics.opened();
		let stats: RelayStats =
			RelayStats { bytes_a_to_b: UP_BYTES, bytes_b_to_a: DOWN_BYTES, duration: Duration::ZERO, end: RelayEnd::Completed };
		metrics.closed(Some(&stats));

		assert_eq!(recorder.sum(DENIALS, Some((REASON_KEY, "host_not_allowed")))?, 2);
		assert_eq!(recorder.sum(DENIALS, Some((REASON_KEY, "rate_limited")))?, 1);
		assert_eq!(recorder.sum(TUNNELS_OPENED, None)?, 2);
		assert_eq!(recorder.sum(TUNNELS_ACTIVE, None)?, 1, "two opened, one closed");
		assert_eq!(u64::try_from(recorder.sum(BYTES, Some((DIRECTION_KEY, UP)))?).ok(), Some(UP_BYTES));
		assert_eq!(u64::try_from(recorder.sum(BYTES, Some((DIRECTION_KEY, DOWN)))?).ok(), Some(DOWN_BYTES));
		return Ok(());
	}

	#[test]
	fn a_failed_tunnel_closes_without_bytes() -> Result<(), String> {
		let recorder: Recorder = Recorder::new();
		let metrics: EgressMetrics = recorder.metrics();
		metrics.opened();
		metrics.closed(None);
		assert_eq!(recorder.sum(TUNNELS_ACTIVE, None)?, 0);
		assert_eq!(recorder.sum(BYTES, None)?, 0);
		return Ok(());
	}
}
