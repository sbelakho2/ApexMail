//! HTTP client wrapper for external service calls with correlation ID propagation.

use reqwest::Client;
use std::time::Duration;

/// Build a pre-configured HTTP client.
/// #237:Returns Result instead of panicking on build failure
pub fn build_http_client(timeout_secs: u64) -> Result<Client, reqwest::Error> {
    Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .pool_max_idle_per_host(20)
        .connect_timeout(Duration::from_secs(5))
        .user_agent("ApexMail/1.0")
        .build()
}

/// Build an HTTP client that propagates the `x-correlation-id` header.
///
/// This is essential for distributed tracing across service boundaries (OBS-08).
/// The correlation ID is set as a default header on every outgoing request,
/// enabling end-to-end trace correlation across ApexMail services.
///
/// Call this in service entry points (API server, tracking, MTA, etc.) so that
/// all outbound HTTP calls carry the correlation context.
pub fn build_http_client_with_correlation(
    timeout_secs: u64,
    correlation_id: Option<&str>,
) -> Result<Client, reqwest::Error> {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .pool_max_idle_per_host(20)
        .connect_timeout(Duration::from_secs(5))
        .user_agent("ApexMail/1.0");

    // Propagate x-correlation-id if provided
    if let Some(cid) = correlation_id {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Ok(val) = reqwest::header::HeaderValue::from_str(cid) {
            headers.insert("x-correlation-id", val);
        }
        builder = builder.default_headers(headers);
    }

    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_client() {
        let client = build_http_client(30).expect("test client should build");
        drop(client);
    }

    #[test]
    fn test_build_client_with_correlation() {
        let client = build_http_client_with_correlation(30, Some("corr-test-123"))
            .expect("test client should build");
        drop(client);
    }

    #[test]
    fn test_build_client_without_correlation() {
        let client =
            build_http_client_with_correlation(30, None).expect("test client should build");
        drop(client);
    }
}
