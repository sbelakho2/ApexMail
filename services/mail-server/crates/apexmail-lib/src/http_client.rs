//! HTTP client wrapper for external service calls.

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_client() {
        let client = build_http_client(30).expect("test client should build");
        drop(client); // just verifying construction does not panic
    }
}
