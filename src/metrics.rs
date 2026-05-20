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
    active_count: AtomicI64,
}

impl ProxyMetrics {
    pub fn new() -> Self {
        let meter: Meter = global::meter("reduction");

        let requests_total: Counter<u64> = meter
            .u64_counter("proxy.requests.total")
            .with_description("Total number of proxied requests")
            .build();

        let request_duration_ms: Histogram<f64> = meter
            .f64_histogram("proxy.request.duration_ms")
            .with_description("Request duration in milliseconds")
            .build();

        let active_connections: UpDownCounter<i64> = meter
            .i64_up_down_counter("proxy.connections.active")
            .with_description("Number of active connections")
            .build();

        let queue_depth: UpDownCounter<i64> = meter
            .i64_up_down_counter("proxy.queue.depth")
            .with_description("Current request queue depth")
            .build();

        let rate_limit_rejections: Counter<u64> = meter
            .u64_counter("proxy.rate_limit.rejections")
            .with_description("Number of rate-limited requests")
            .build();

        let backend_selections: Counter<u64> = meter
            .u64_counter("proxy.backend.selections")
            .with_description("Number of backend selections by backend ID")
            .build();

        let circuit_open_total: Counter<u64> = meter
            .u64_counter("proxy.circuit.open_total")
            .with_description("Number of requests rejected by open circuit breaker")
            .build();

        let circuit_half_open_probes: Counter<u64> = meter
            .u64_counter("proxy.circuit.half_open_probes")
            .with_description("Number of half-open probe requests allowed through")
            .build();

        let backend_active_connections: UpDownCounter<i64> = meter
            .i64_up_down_counter("proxy.backend.active_connections")
            .with_description("Current in-flight connections per backend")
            .build();

        let backend_conn_limit_rejected: Counter<u64> = meter
            .u64_counter("proxy.backend.conn_limit_rejected")
            .with_description("Requests rejected because a backend hit its connection limit")
            .build();

        let retry_attempts: Counter<u64> = meter
            .u64_counter("proxy.retry.attempts")
            .with_description("Number of retry attempts by backend and outcome")
            .build();

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
            active_count: AtomicI64::new(0),
        };
    }

    pub fn track_connection(&self, delta: i64) {
        self.active_connections.add(delta, &[]);
        self.active_count.fetch_add(delta, Ordering::Relaxed);
    }

    pub fn active_connection_count(&self) -> i64 {
        return self.active_count.load(Ordering::Relaxed);
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

        let reader: PeriodicReader<opentelemetry_otlp::MetricExporter> =
            PeriodicReader::builder(exporter).build();
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
