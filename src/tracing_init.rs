use opentelemetry::global;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use tracing::info;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::TracingConfig;
use crate::error::{ReductionError, Result};

// Init the tracing subscriber with optional OTLP export. Returns the provider handle when
// export is enabled, for graceful shutdown.
pub fn init_tracing(config: &TracingConfig) -> Result<Option<SdkTracerProvider>> {
	// Always set the W3C propagator so trace context flows regardless of whether spans export.
	global::set_text_map_propagator(TraceContextPropagator::new());

	let filter: EnvFilter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

	let provider: Option<SdkTracerProvider> = if let Some(endpoint) = &config.otlp_endpoint {
		let exporter = opentelemetry_otlp::SpanExporter::builder()
			.with_http()
			.with_endpoint(endpoint)
			.build()
			.map_err(|e| ReductionError::Config(format!("OTLP trace exporter: {e}")))?;

		let sampler: Sampler = if (config.sample_ratio - 1.0).abs() < f64::EPSILON {
			Sampler::AlwaysOn
		} else {
			Sampler::TraceIdRatioBased(config.sample_ratio)
		};

		let provider: SdkTracerProvider = SdkTracerProvider::builder()
			.with_batch_exporter(exporter)
			.with_sampler(sampler)
			.build();

		let otel_layer = OpenTelemetryLayer::new(provider.tracer("reduction"));

		tracing_subscriber::registry()
			.with(filter)
			.with(tracing_subscriber::fmt::layer())
			.with(otel_layer)
			.init();

		info!(%endpoint, sample_ratio = config.sample_ratio, "OTLP trace exporter configured");
		Some(provider)
	} else {
		// No export endpoint — structured logging only, no OTel layer.
		tracing_subscriber::registry()
			.with(filter)
			.with(tracing_subscriber::fmt::layer())
			.init();
		None
	};

	return Ok(provider);
}

pub fn shutdown_tracing(provider: Option<SdkTracerProvider>) {
	if let Some(provider) = provider
		&& let Err(e) = provider.shutdown()
	{
		tracing::error!("failed to shutdown tracer provider: {e}");
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_tracing_config_default_sample_ratio() {
		let config: TracingConfig = TracingConfig::default();
		assert!((config.sample_ratio - 1.0).abs() < f64::EPSILON);
		assert!(config.otlp_endpoint.is_none());
	}

	#[test]
	fn test_shutdown_tracing_none_is_noop() {
		// No provider (export disabled) — shutdown must be a clean no-op.
		shutdown_tracing(None);
	}

	#[test]
	fn test_shutdown_tracing_some_shuts_down_provider() {
		// Build a provider directly (no global subscriber) and shut it down: exercises the Some branch.
		let provider: SdkTracerProvider = SdkTracerProvider::builder().build();
		shutdown_tracing(Some(provider));
	}

	// init_tracing installs a PROCESS-GLOBAL subscriber via `.init()`, which panics if called twice, so
	// only one branch is unit-testable per test binary; this drives the export-enabled path. The
	// export-disabled and ratio-sampler arms are covered by running the binary, not unit tests.
	#[tokio::test]
	async fn test_init_tracing_with_endpoint_returns_provider() {
		let config: TracingConfig = TracingConfig {
			otlp_endpoint: Some("http://127.0.0.1:4318".to_owned()),
			sample_ratio: 1.0,
		};
		let provider: Option<SdkTracerProvider> = init_tracing(&config).unwrap();
		assert!(
			provider.is_some(),
			"an OTLP endpoint must yield a provider handle for shutdown"
		);
		shutdown_tracing(provider);
	}
}
