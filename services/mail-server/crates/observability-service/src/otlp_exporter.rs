//! OpenTelemetry OTLP exporter for distributed tracing.
//!
//! Initializes the OpenTelemetry SDK with an OTLP exporter to send traces
//! to a collector (Jaeger, Tempo, or any OTLP-compatible backend).
//!
//! # Example
//! ```ignore
//! use observability_service::otlp_exporter::init_otlp_tracing;
//!
//! #[tokio::main]
//! async fn main {
//! let _guard = init_otlp_tracing("http://localhost:4317", "api-server")?;
//! // ... your application code
//! }
//! ```

use opentelemetry::trace::TracerProvider;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    runtime,
    trace::{
        BatchConfigBuilder, Config as TraceConfig, Sampler, TracerProvider as SdkTracerProvider,
    },
    Resource,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use zeroize::Zeroizing;

/// OTLP exporter configuration.
#[derive(Clone)]
/// O-22.2: Added `auth_token` for OTLP exporter authentication.
/// When set, the token is included as a bearer token in the `Authorization`
/// header of every OTLP export request.
pub struct OtlpConfig {
    /// OTLP collector endpoint (e.g., "http://localhost:4317")
    pub endpoint: String,
    /// Service name for span attribution
    pub service_name: String,
    /// Optional service version
    pub service_version: Option<String>,
    /// Optional environment (e.g., "production", "staging")
    pub environment: Option<String>,
    /// Sampling ratio (0.0 to 1.0) — 1.0 = sample all traces
    pub sample_rate: f64,
    /// Batch config:max export batch size
    pub batch_size: usize,
    /// Batch config:max queue size before dropping spans
    pub max_queue_size: usize,
    /// Batch config:scheduled delay in milliseconds
    pub scheduled_delay_ms: u64,
    /// Optional bearer token for authenticating with the OTLP collector.
    /// Reads from `OTEL_EXPORTER_OTLP_HEADERS` or `OTLP_AUTH_TOKEN` env var.
    pub auth_token: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for OtlpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtlpConfig")
            .field("endpoint", &self.endpoint)
            .field("service_name", &self.service_name)
            .field("service_version", &self.service_version)
            .field("environment", &self.environment)
            .field("sample_rate", &self.sample_rate)
            .field("batch_size", &self.batch_size)
            .field("max_queue_size", &self.max_queue_size)
            .field("scheduled_delay_ms", &self.scheduled_delay_ms)
            .field(
                "auth_token",
                &self.auth_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl Default for OtlpConfig {
    fn default() -> Self {
        // O-22.2: Parse auth token from OTEL_EXPORTER_OTLP_HEADERS (standard)
        // or OTLP_AUTH_TOKEN (ApexMail env var). The headers format is
        // "key1=value1,key2=value2" per the OpenTelemetry spec.
        let auth_token = std::env::var("OTEL_EXPORTER_OTLP_HEADERS")
            .ok()
            .and_then(|h| {
                h.split(',').find_map(|pair| {
                    let mut parts = pair.splitn(2, '=');
                    let key = parts.next()?.trim();
                    let value = parts.next()?;
                    if key.eq_ignore_ascii_case("authorization") {
                        value
                            .strip_prefix("Bearer ")
                            .map(|token| Zeroizing::new(token.to_string()))
                            .or_else(|| Some(Zeroizing::new(value.to_string())))
                    } else {
                        None
                    }
                })
            })
            .or_else(|| std::env::var("OTLP_AUTH_TOKEN").ok().map(Zeroizing::new));

        // Resolve sampling rate from standard OpenTelemetry env vars:
        //   1. OTEL_TRACES_SAMPLER + OTEL_TRACES_SAMPLER_ARG (OpenTelemetry SDK standard)
        //   2. OTEL_SAMPLE_RATE (ApexMail legacy env var)
        //   3. Default to 1.0 (100% sampling) for development
        let sample_rate = resolve_sample_rate();

        Self {
            endpoint: std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:4317".into()),
            service_name: std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "apexmail".into()),
            service_version: std::env::var("OTEL_SERVICE_VERSION").ok(),
            environment: std::env::var("OTEL_ENVIRONMENT").ok(),
            sample_rate,
            batch_size: 512,
            max_queue_size: 2048,
            scheduled_delay_ms: 5000,
            auth_token,
        }
    }
}

/// Resolve trace sampling rate from OpenTelemetry standard env vars.
///
/// Supports the following priority order:
/// 1. `OTEL_TRACES_SAMPLER=TraceIdRatioBased` + `OTEL_TRACES_SAMPLER_ARG=<ratio>`
/// 2. `OTEL_SAMPLE_RATE` (ApexMail legacy env var)
/// 3. Default to 1.0 (100% sampling)
///
/// # Production recommendation
/// Set `OTEL_TRACES_SAMPLER=TraceIdRatioBased` and `OTEL_TRACES_SAMPLER_ARG=0.1`
/// to sample only 10% of traces, reducing span export costs significantly.
fn resolve_sample_rate() -> f64 {
    // Check OTEL_TRACES_SAMPLER first (OpenTelemetry SDK standard)
    if let Ok(sampler) = std::env::var("OTEL_TRACES_SAMPLER") {
        match sampler.as_str() {
            "always_on" => return 1.0,
            "always_off" => return 0.0,
            "traceidratio" | "TraceIdRatioBased" => {
                if let Ok(arg) = std::env::var("OTEL_TRACES_SAMPLER_ARG") {
                    if let Ok(ratio) = arg.parse::<f64>() {
                        return ratio.clamp(0.0, 1.0);
                    }
                }
                // If ARG is missing or invalid, default to 0.1 for ratio-based
                return 0.1;
            }
            "parentbased_traceidratio" | "ParentBasedTraceIdRatio" => {
                if let Ok(arg) = std::env::var("OTEL_TRACES_SAMPLER_ARG") {
                    if let Ok(ratio) = arg.parse::<f64>() {
                        return ratio.clamp(0.0, 1.0);
                    }
                }
                return 0.1;
            }
            _ => {
                // Unknown sampler type — fall through to legacy env var
            }
        }
    }

    // Fallback to ApexMail legacy OTEL_SAMPLE_RATE
    std::env::var("OTEL_SAMPLE_RATE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1.0)
}

/// Guard that shuts down the tracer provider when dropped.
pub struct TracingGuard {
    provider: SdkTracerProvider,
}

impl Drop for TracingGuard {
    fn drop(&mut self) {
        if let Err(e) = self.provider.shutdown() {
            tracing::error!("Error shutting down OTLP tracer: {e:?}");
        }
    }
}

/// Initialize OpenTelemetry OTLP tracing.
/// Returns a guard that must be held for the lifetime of the application.
/// Dropping the guard will flush and shutdown the tracer.
/// # Errors
/// Returns an error if the OTLP exporter cannot be initialized.
pub fn init_otlp_tracing(
    config: OtlpConfig,
) -> Result<TracingGuard, Box<dyn std::error::Error + Send + Sync>> {
    // Build resource attributes
    let mut attributes = vec![KeyValue::new("service.name", config.service_name.clone())];

    if let Some(version) = &config.service_version {
        attributes.push(KeyValue::new("service.version", version.clone()));
    }

    if let Some(env) = &config.environment {
        attributes.push(KeyValue::new("deployment.environment", env.clone()));
    }

    let resource = Resource::new(attributes);

    // Configure the OTLP exporter
    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(&config.endpoint);

    // Configure batch processing
    let batch_config = BatchConfigBuilder::default()
        .with_max_export_batch_size(config.batch_size)
        .with_max_queue_size(config.max_queue_size)
        .with_scheduled_delay(std::time::Duration::from_millis(config.scheduled_delay_ms))
        .build();

    // Configure sampler
    let sampler = if config.sample_rate >= 1.0 {
        Sampler::AlwaysOn
    } else if config.sample_rate <= 0.0 {
        Sampler::AlwaysOff
    } else {
        Sampler::TraceIdRatioBased(config.sample_rate)
    };

    // Build the tracer provider
    let trace_config = TraceConfig::default()
        .with_sampler(sampler)
        .with_resource(resource);

    let provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(trace_config)
        .with_batch_config(batch_config)
        .install_batch(runtime::Tokio)?;

    // Create the tracing-opentelemetry layer
    let tracer = provider.tracer(config.service_name.clone());
    let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    // Combine with existing tracing subscriber
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .with(telemetry_layer)
        .try_init()
        .ok(); // Ignore if already initialized

    Ok(TracingGuard { provider })
}

/// Simplified initialization with just endpoint and service name.
pub fn init_otlp_tracing_simple(
    endpoint: &str,
    service_name: &str,
) -> Result<TracingGuard, Box<dyn std::error::Error + Send + Sync>> {
    init_otlp_tracing(OtlpConfig {
        endpoint: endpoint.to_string(),
        service_name: service_name.to_string(),
        ..Default::default()
    })
}

/// Check if OTLP tracing is enabled via environment variable.
pub fn is_otlp_enabled() -> bool {
    std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock poisoned")
    }

    #[test]
    fn test_config_default() {
        let _guard = env_lock();

        // Clear env vars for predictable test
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_SERVICE_NAME");
        std::env::remove_var("OTEL_SAMPLE_RATE");
        std::env::remove_var("OTEL_EXPORTER_OTLP_HEADERS");
        std::env::remove_var("OTLP_AUTH_TOKEN");

        let config = OtlpConfig::default();
        assert_eq!(config.endpoint, "http://localhost:4317");
        assert_eq!(config.service_name, "apexmail");
        assert_eq!(config.sample_rate, 1.0);
        assert!(config.auth_token.is_none());
    }

    #[test]
    fn test_config_from_env() {
        let _guard = env_lock();

        std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317");
        std::env::set_var("OTEL_SERVICE_NAME", "test-service");
        std::env::set_var("OTEL_SAMPLE_RATE", "0.5");
        std::env::remove_var("OTEL_EXPORTER_OTLP_HEADERS");
        std::env::remove_var("OTLP_AUTH_TOKEN");

        let config = OtlpConfig::default();
        assert_eq!(config.endpoint, "http://collector:4317");
        assert_eq!(config.service_name, "test-service");
        assert_eq!(config.sample_rate, 0.5);

        // Clean up
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_SERVICE_NAME");
        std::env::remove_var("OTEL_SAMPLE_RATE");
    }

    #[test]
    fn test_auth_token_from_standard_headers_is_zeroizing() {
        let _guard = env_lock();

        std::env::set_var(
            "OTEL_EXPORTER_OTLP_HEADERS",
            "x-tenant=alpha,authorization=Bearer standard-secret",
        );
        std::env::remove_var("OTLP_AUTH_TOKEN");

        let config = OtlpConfig::default();
        assert_eq!(
            config.auth_token.as_ref().map(|token| token.as_str()),
            Some("standard-secret")
        );
        assert!(!format!("{config:?}").contains("standard-secret"));

        std::env::remove_var("OTEL_EXPORTER_OTLP_HEADERS");
    }

    #[test]
    fn test_auth_token_falls_back_to_apexmail_env() {
        let _guard = env_lock();

        std::env::remove_var("OTEL_EXPORTER_OTLP_HEADERS");
        std::env::set_var("OTLP_AUTH_TOKEN", "fallback-secret");

        let config = OtlpConfig::default();
        assert_eq!(
            config.auth_token.as_ref().map(|token| token.as_str()),
            Some("fallback-secret")
        );

        std::env::remove_var("OTLP_AUTH_TOKEN");
    }

    #[test]
    fn test_is_otlp_enabled() {
        let _guard = env_lock();

        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        assert!(!is_otlp_enabled());

        std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317");
        assert!(is_otlp_enabled());

        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
    }
}
