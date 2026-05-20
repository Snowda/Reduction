use opentelemetry::global;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use tracing::info;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use crate::config::TracingConfig;
use crate::error::{ReductionError, Result};

// Initialize the tracing subscriber with optional OTLP trace export.
// Always sets the W3C TraceContextPropagator so inbound context extraction
// works even without an export endpoint configured.
// Returns the SdkTracerProvider handle when export is enabled, for graceful shutdown.
pub fn init_tracing(config: &TracingConfig) -> Result<Option<SdkTracerProvider>> {
    // W3C propagator is always active so trace context flows through
    // the proxy regardless of whether spans are exported.
    global::set_text_map_propagator(TraceContextPropagator::new());

    let filter: EnvFilter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

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
        eprintln!("failed to shutdown tracer provider: {e}");
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
}
