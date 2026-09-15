//! Common types, traits, and utilities shared across all processors.

pub mod backpressure;
pub mod circuit_breaker;
pub mod config;
pub mod error;
pub mod pool;

pub use backpressure::{Backpressure, BackpressureConfig};
pub use circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitState};
pub use config::{
    AnalyticsConfig, DkimConfig, EmailConfig, IpRateLimitConfig, ProcessorConfig,
    ReplyHandlerConfig, SesConfig, SmtpConfig, TrackingConfig, TransportType, WarmupConfig,
    WebhookConfig,
};
pub use error::{ProcessorError, ProcessorResult};
pub use pool::{create_db_pool, create_redis_pool, DbPool, RedisPool};

/// Deterministic environment for the AWS SDK clients the processor's tests
/// construct (`EmailProcessor::new` builds the SES transport).
///
/// Two failure modes this closes (both observed as flaky 15s failures under
/// parallel nextest load): the default provider chain probing EC2 metadata,
/// and the SDK's rustls trust store being built from macOS native roots,
/// which reads the keychain through the Security framework and can come back
/// empty under load — aborting client construction with
/// `TrustStore configured to enable native roots but no valid root
/// certificates parsed!`. Pointing `AWS_CA_BUNDLE` at the system PEM bundle
/// reads a plain file instead. Test-only: the worker binary runs on Linux
/// with native roots. Only set when the variable is absent — an explicit
/// choice (or CI's own CA configuration) wins.
#[cfg(test)]
pub(crate) fn ensure_aws_test_env() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
        std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        // rustls-native-certs (the AWS SDK's rustls trust source) honours
        // SSL_CERT_FILE: without it every test process re-reads the macOS
        // keychain through the Security framework, which under parallel load
        // intermittently yields zero parseable roots and aborts SDK client
        // construction ("no valid root certificates parsed"). A plain PEM
        // file is deterministic.
        if std::env::var_os("SSL_CERT_FILE").is_none() {
            for candidate in [
                "/etc/ssl/cert.pem",
                "/etc/ssl/certs/ca-certificates.crt",
                "/etc/pki/tls/certs/ca-bundle.crt",
            ] {
                if std::path::Path::new(candidate).is_file() {
                    std::env::set_var("SSL_CERT_FILE", candidate);
                    break;
                }
            }
        }
        if std::env::var_os("AWS_CA_BUNDLE").is_none() {
            for candidate in [
                "/etc/ssl/cert.pem",
                "/etc/ssl/certs/ca-certificates.crt",
                "/etc/pki/tls/certs/ca-bundle.crt",
            ] {
                if std::path::Path::new(candidate).is_file() {
                    std::env::set_var("AWS_CA_BUNDLE", candidate);
                    break;
                }
            }
        }
    });
}
