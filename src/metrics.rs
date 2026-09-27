use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram, Meter, UpDownCounter};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use tracing::info;

use crate::config::MetricsConfig;
use crate::error::{ReductionError, Result};

pub struct ProxyMetrics {
	pub requests_total: Counter<u64>,
	pub request_duration_ms: Histogram<f64>,
	pub active_connections: UpDownCounter<i64>,
	pub queue_depth: UpDownCounter<i64>,
	pub rate_limit_rejections: Counter<u64>,
	pub backend_selections: Counter<u64>,
	pub circuit_open_total: Counter<u64>,
	pub circuit_half_open_probes: Counter<u64>,
	pub backend_active_connections: UpDownCounter<i64>,
	pub backend_conn_limit_rejected: Counter<u64>,
	pub retry_attempts: Counter<u64>,
	pub tunnel_sessions_active: UpDownCounter<i64>,
	pub tunnel_streams_opened: Counter<u64>,
	pub tunnel_heartbeat_timeouts: Counter<u64>,
	pub tunnel_registration_rejected: Counter<u64>,
	pub tunnel_accepts_rate_limited: Counter<u64>,
	pub tunnel_duplicate_sessions: Counter<u64>,
	pub tunnel_sessions_revoked: Counter<u64>,
	pub revocation_load_errors: Counter<u64>,
	pub ca_bundle_load_errors: Counter<u64>,
	pub ca_bundle_reloads: Counter<u64>,
	pub requests_rejected: Counter<u64>,
	pub raw_relay_active: UpDownCounter<i64>,
	pub raw_relay_bytes_relayed: Counter<u64>,
	pub raw_relay_errors: Counter<u64>,
	pub raw_relay_rejected: Counter<u64>,
	pub cache_hits: Counter<u64>,
	pub cache_misses: Counter<u64>,
	// ACME certificate lifecycle (only incremented on the acme-feature path; harmless catalog entries
	// otherwise). Successful provision/renewals vs failed attempts — pair them for renewal-health alerting.
	pub acme_renewals_total: Counter<u64>,
	pub acme_renewal_failures_total: Counter<u64>,
	// Shared with ActiveConnectionGuard (Arc) so guards created from this instance move the same
	// count that active_connection_count() reports — the graceful-drain loop polls it at shutdown.
	active_count: Arc<AtomicI64>,
}

impl Default for ProxyMetrics {
	fn default() -> Self {
		return Self::new();
	}
}

impl ProxyMetrics {
	// A flat registry of ~30 OTel instruments (name + description each): no branching, just
	// definitions co-located with the struct fields they populate — splitting it would scatter the
	// audit surface without cutting real complexity.
	#[must_use]
	#[allow(clippy::too_many_lines)]
	pub fn new() -> Self {
		let meter: Meter = global::meter("reduction");

		// One-line builders per instrument kind: every metric below is a name + description, so these
		// collapse the otherwise-identical four-line builder chains. `&'static str` params keep the
		// literal descriptions satisfying `with_description`'s `Into<Cow<'static, str>>` bound.
		let counter = |name: &'static str, desc: &'static str| -> Counter<u64> {
			return meter.u64_counter(name).with_description(desc).build();
		};
		let updown = |name: &'static str, desc: &'static str| -> UpDownCounter<i64> {
			return meter.i64_up_down_counter(name).with_description(desc).build();
		};
		let histogram = |name: &'static str, desc: &'static str| -> Histogram<f64> {
			return meter.f64_histogram(name).with_description(desc).build();
		};

		let requests_total: Counter<u64> = counter("proxy.requests.total", "Total number of proxied requests");
		let request_duration_ms: Histogram<f64> =
			histogram("proxy.request.duration_ms", "Request duration in milliseconds");
		let active_connections: UpDownCounter<i64> = updown("proxy.connections.active", "Number of active connections");
		let queue_depth: UpDownCounter<i64> = updown("proxy.queue.depth", "Current request queue depth");
		let rate_limit_rejections: Counter<u64> =
			counter("proxy.rate_limit.rejections", "Number of rate-limited requests");
		let backend_selections: Counter<u64> =
			counter("proxy.backend.selections", "Number of backend selections by backend ID");
		let circuit_open_total: Counter<u64> = counter(
			"proxy.circuit.open_total",
			"Number of requests rejected by open circuit breaker",
		);
		let circuit_half_open_probes: Counter<u64> = counter(
			"proxy.circuit.half_open_probes",
			"Number of half-open probe requests allowed through",
		);
		let backend_active_connections: UpDownCounter<i64> = updown(
			"proxy.backend.active_connections",
			"Current in-flight connections per backend",
		);
		let backend_conn_limit_rejected: Counter<u64> = counter(
			"proxy.backend.conn_limit_rejected",
			"Requests rejected because a backend hit its connection limit",
		);
		let retry_attempts: Counter<u64> = counter(
			"proxy.retry.attempts",
			"Number of retry attempts by backend and outcome",
		);
		let tunnel_sessions_active: UpDownCounter<i64> =
			updown("proxy.tunnel.sessions_active", "Active reverse tunnel sessions");
		let tunnel_streams_opened: Counter<u64> =
			counter("proxy.tunnel.streams_opened", "Streams opened over reverse tunnels");
		let tunnel_heartbeat_timeouts: Counter<u64> = counter(
			"proxy.tunnel.heartbeat_timeouts",
			"Tunnel sessions lost to heartbeat timeout",
		);
		let tunnel_registration_rejected: Counter<u64> = counter(
			"proxy.tunnel.registration_rejected",
			"Tunnel registration attempts rejected",
		);
		// Incoming tunnel connections dropped at accept() by the per-source-IP accept-rate limiter,
		// before any QUIC handshake — cheap rejection of a connection flood.
		let tunnel_accepts_rate_limited: Counter<u64> = counter(
			"proxy.tunnel.accepts_rate_limited",
			"Incoming tunnel connections dropped at accept by the per-IP rate limiter",
		);
		// Two concurrent sessions for one backend_id means two holders of the same identity key —
		// a clone/compromise signal for single-device backends (fleet clone detection).
		let tunnel_duplicate_sessions: Counter<u64> = counter(
			"proxy.tunnel.duplicate_sessions",
			"Registrations creating a concurrent duplicate session for a backend",
		);
		// Live tunnel sessions torn down because a revocation-set update matched their identity —
		// the enforcement half of clone detection (a flagged clone is cut off, not just counted).
		let tunnel_sessions_revoked: Counter<u64> = counter(
			"proxy.tunnel.sessions_revoked",
			"Live tunnel sessions terminated by a revocation-set update",
		);
		// HTTP requests refused before routing, by reason (currently a revoked client identity).
		let requests_rejected: Counter<u64> = counter(
			"proxy.requests.rejected",
			"Requests rejected before forwarding, by reason",
		);
		// A revocation file was present but could not be parsed on load/reload. The previous denylist
		// stays in force (last-known-good); this counter makes the staleness visible.
		let revocation_load_errors: Counter<u64> = counter(
			"proxy.revocation.load_errors",
			"Revocation file loads that failed to parse (previous set kept)",
		);
		// Failed CA-bundle reload (empty/missing/unparseable); previous roots kept (last-known-good) —
		// an empty store would reject the whole fleet. `side`: server = inbound client-cert, client = backend.
		let ca_bundle_load_errors: Counter<u64> = counter(
			"proxy.ca_bundle.load_errors",
			"CA trust-bundle reloads that failed to load (previous roots kept); by side",
		);
		// Successful CA-bundle reloads (roots/CRLs swapped in). Pair with ca_bundle_load_errors for
		// staleness alerting (errors rising while this stays flat); same `side` attribute.
		let ca_bundle_reloads: Counter<u64> = counter(
			"proxy.ca_bundle.reloads",
			"Successful CA trust-bundle reloads (roots/CRLs swapped in); by side",
		);
		let raw_relay_active: UpDownCounter<i64> = updown("proxy.raw_relay.active", "Active raw QUIC stream relays");
		let raw_relay_bytes_relayed: Counter<u64> = counter(
			"proxy.raw_relay.bytes_relayed",
			"Bytes relayed through raw QUIC streams",
		);
		let raw_relay_errors: Counter<u64> = counter("proxy.raw_relay.errors", "Errors in raw QUIC stream relay");
		// Raw relay streams refused by an admission check (ACL, rate limit, or missing mTLS
		// identity) before any backend connection was opened. The `reason` attribute distinguishes.
		let raw_relay_rejected: Counter<u64> = counter(
			"proxy.raw_relay.rejected",
			"Raw QUIC stream relays rejected by an admission check",
		);
		let cache_hits: Counter<u64> = counter("proxy.cache.hits", "Response cache hits");
		let cache_misses: Counter<u64> = counter("proxy.cache.misses", "Response cache misses");
		let acme_renewals_total: Counter<u64> = counter(
			"proxy.acme.renewals_total",
			"ACME certificates successfully provisioned or renewed",
		);
		let acme_renewal_failures_total: Counter<u64> = counter(
			"proxy.acme.renewal_failures_total",
			"ACME provision/renewal attempts that failed",
		);

		return Self {
			requests_total,
			request_duration_ms,
			active_connections,
			queue_depth,
			rate_limit_rejections,
			backend_selections,
			circuit_open_total,
			circuit_half_open_probes,
			backend_active_connections,
			backend_conn_limit_rejected,
			retry_attempts,
			tunnel_sessions_active,
			tunnel_streams_opened,
			tunnel_heartbeat_timeouts,
			tunnel_registration_rejected,
			tunnel_accepts_rate_limited,
			tunnel_duplicate_sessions,
			tunnel_sessions_revoked,
			revocation_load_errors,
			ca_bundle_load_errors,
			ca_bundle_reloads,
			requests_rejected,
			raw_relay_active,
			raw_relay_bytes_relayed,
			raw_relay_errors,
			raw_relay_rejected,
			cache_hits,
			cache_misses,
			acme_renewals_total,
			acme_renewal_failures_total,
			active_count: Arc::new(AtomicI64::new(0)),
		};
	}

	pub fn track_connection(&self, delta: i64) {
		self.active_connections.add(delta, &[]);
		self.active_count.fetch_add(delta, Ordering::Relaxed);
	}

	#[must_use]
	pub fn active_connection_count(&self) -> i64 {
		return self.active_count.load(Ordering::Relaxed);
	}

	// RAII counterpart to track_connection: +1 now, -1 on drop, so every exit path of a request
	// decrements exactly once and the drain loop's active_connection_count() stays truthful.
	#[must_use]
	pub fn connection_guard(&self) -> ActiveConnectionGuard {
		self.track_connection(1);
		return ActiveConnectionGuard {
			counter: self.active_connections.clone(),
			count: Arc::clone(&self.active_count),
		};
	}
}

pub struct ActiveConnectionGuard {
	counter: UpDownCounter<i64>,
	count: Arc<AtomicI64>,
}

impl Drop for ActiveConnectionGuard {
	fn drop(&mut self) {
		self.counter.add(-1, &[]);
		self.count.fetch_add(-1, Ordering::Relaxed);
	}
}

pub fn init_metrics(config: &MetricsConfig) -> Result<()> {
	let mut builder: opentelemetry_sdk::metrics::MeterProviderBuilder = SdkMeterProvider::builder();

	if let Some(endpoint) = &config.otlp_endpoint {
		let exporter: opentelemetry_otlp::MetricExporter = opentelemetry_otlp::MetricExporter::builder()
			.with_http()
			.with_endpoint(endpoint)
			.build()
			.map_err(|e| ReductionError::Config(format!("OTLP exporter: {e}")))?;

		let reader: PeriodicReader<opentelemetry_otlp::MetricExporter> = PeriodicReader::builder(exporter).build();
		builder = builder.with_reader(reader);

		info!(%endpoint, "OTLP metrics exporter configured");
	}

	let provider: SdkMeterProvider = builder.build();
	global::set_meter_provider(provider);

	info!("OTel metrics initialized");

	return Ok(());
}

#[cfg(test)]
mod tests {
	use super::*;

	fn no_export_config() -> MetricsConfig {
		return MetricsConfig { otlp_endpoint: None };
	}

	#[test]
	fn test_init_metrics() {
		let result: Result<()> = init_metrics(&no_export_config());
		assert!(result.is_ok());
	}

	#[test]
	fn test_proxy_metrics_creation() {
		let _ = init_metrics(&no_export_config());
		let metrics: ProxyMetrics = ProxyMetrics::new();

		metrics.requests_total.add(1, &[]);
		metrics.request_duration_ms.record(42.5, &[]);
		metrics.active_connections.add(1, &[]);
		metrics.queue_depth.add(1, &[]);
		metrics.rate_limit_rejections.add(1, &[]);
		metrics.backend_selections.add(1, &[]);
	}

	// The drain loop at shutdown polls active_connection_count(); the guard must move that same
	// count (not only the OTel instrument), or drain sees a permanent zero and exits early.
	#[test]
	fn test_connection_guard_moves_the_drain_count() {
		let _ = init_metrics(&no_export_config());
		let metrics: ProxyMetrics = ProxyMetrics::new();

		assert_eq!(metrics.active_connection_count(), 0);
		let guard: ActiveConnectionGuard = metrics.connection_guard();
		let second: ActiveConnectionGuard = metrics.connection_guard();
		assert_eq!(metrics.active_connection_count(), 2);
		drop(guard);
		assert_eq!(metrics.active_connection_count(), 1);
		drop(second);
		assert_eq!(metrics.active_connection_count(), 0);
	}

	#[test]
	fn test_track_connection_increments_and_decrements() {
		let _ = init_metrics(&no_export_config());
		let metrics: ProxyMetrics = ProxyMetrics::new();

		assert_eq!(metrics.active_connection_count(), 0);
		metrics.track_connection(1);
		assert_eq!(metrics.active_connection_count(), 1);
		metrics.track_connection(1);
		assert_eq!(metrics.active_connection_count(), 2);
		metrics.track_connection(-1);
		assert_eq!(metrics.active_connection_count(), 1);
		metrics.track_connection(-1);
		assert_eq!(metrics.active_connection_count(), 0);
	}
}
