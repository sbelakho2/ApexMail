//! Mailstore Service
//!
//! Provides message storage and retrieval functionality.

use anyhow::{anyhow, bail, Result};
use clap::Parser;
use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};
use mail_proto::{InternalServiceToken, MailstoreServiceServer};
use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tonic::transport::Server;
use tracing::info;
use tracing_subscriber::EnvFilter;

use mailstore_core::{MailstoreServiceImpl, MessageStorage};

#[derive(Parser)]
#[command(name = "mailstore")]
#[command(about = "Mailstore Service - Message storage and retrieval")]
struct Cli {
    /// gRPC listen address. Defaults to loopback so the service is not
    /// exposed by accident; container deployments override this with
    /// MAILSTORE_BIND_ADDR=0.0.0.0:50051 (see docker-compose).
    #[arg(short, long, env = "MAILSTORE_BIND_ADDR", default_value = "127.0.0.1:50051")]
    listen: String,

    /// Database URL
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// O‑4.3:Path to a 0600 secret file containing the master encryption key.
    /// If provided, message body content is encrypted at rest using AES‑256‑GCM.
    #[arg(long, env = "ENCRYPTION_KEY_FILE")]
    encryption_key_file: Option<PathBuf>,
}

/// Shared-token gRPC authentication.
///
/// When `INTERNAL_SERVICE_TOKEN` is set, every request must present
/// `authorization: Bearer <INTERNAL_SERVICE_TOKEN>` or it is rejected with
/// UNAUTHENTICATED. The token may only be omitted for loopback local
/// development; startup rejects an externally reachable tokenless server.
#[derive(Clone)]
struct SharedTokenInterceptor {
    expected: Option<InternalServiceToken>,
}

impl SharedTokenInterceptor {
    fn from_env() -> Result<Self> {
        Ok(Self {
            expected: InternalServiceToken::from_env().map_err(|error| anyhow!(error))?,
        })
    }

    fn is_enabled(&self) -> bool {
        self.expected.is_some()
    }

    #[cfg(test)]
    fn with_token(token: &str) -> Self {
        Self {
            expected: Some(
                InternalServiceToken::new(token.to_owned())
                    .expect("test token must satisfy production validation"),
            ),
        }
    }
}

impl tonic::service::Interceptor for SharedTokenInterceptor {
    fn call(
        &mut self,
        request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        if !self.is_enabled() {
            return Ok(request);
        }
        let authorized = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().strip_prefix("Bearer "))
            .zip(self.expected.as_ref())
            .is_some_and(|(provided, expected)| {
                constant_time_eq(provided.as_bytes(), expected.as_str().as_bytes())
            });
        if authorized {
            Ok(request)
        } else {
            Err(tonic::Status::unauthenticated(
                "missing or invalid internal service token",
            ))
        }
    }
}

/// Length-safe constant-time byte comparison (avoids a new dependency on
/// `subtle`; the length check itself leaks only the token length).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b)
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Only loopback binds may opt out of internal service authentication. Docker
/// bridge and wildcard addresses are network-reachable and must always carry
/// a validated token.
fn validate_bind_security(
    address: std::net::SocketAddr,
    interceptor: &SharedTokenInterceptor,
) -> Result<()> {
    if !address.ip().is_loopback() && !interceptor.is_enabled() {
        bail!(
            "INTERNAL_SERVICE_TOKEN is required when MAILSTORE_BIND_ADDR ({address}) is not loopback"
        );
    }
    Ok(())
}

fn init_tracing(log_level: &str) -> Option<TracingGuard> {
    if is_otlp_enabled() {
        let config = OtlpConfig {
            service_name: "mailstore".to_string(),
            ..OtlpConfig::default()
        };
        match init_otlp_tracing(config) {
            Ok(guard) => return Some(guard),
            Err(e) => tracing::warn!("OTLP tracing disabled: {e}"),
        }
    }
    // Fallback: structured JSON logging
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();
    None
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let _guard = init_tracing(&cli.log_level);

    let addr: std::net::SocketAddr = cli.listen.parse()?;
    let interceptor = SharedTokenInterceptor::from_env()?;
    validate_bind_security(addr, &interceptor)?;

    info!("Starting Mailstore Service");
    info!("Listen address: {addr}");

    // Connect to database
    let pool = sqlx::PgPool::connect(&cli.database_url).await?;
    info!("Connected to database");

    // Create storage with optional encryption at rest
    let storage = if let Some(path) = cli.encryption_key_file.as_deref() {
        let key = load_encryption_key_from_file(path)?;
        info!("Encryption at rest enabled");
        Arc::new(MessageStorage::with_encryption(pool, key))
    } else {
        Arc::new(MessageStorage::new(pool))
    };
    storage.initialize().await?;

    // Create gRPC service
    let service = MailstoreServiceImpl::new(storage);

    // Start gRPC server
    info!("Starting gRPC server on {}", addr);

    if interceptor.is_enabled() {
        info!("gRPC shared-token authentication enabled (INTERNAL_SERVICE_TOKEN)");
    }

    // Message limits raised to 64 MiB so large messages (e.g. 5 MB APPENDs or
    // inbound SMTP deliveries) round-trip without hitting the 4 MiB default.
    let service = MailstoreServiceServer::new(service)
        .max_decoding_message_size(64 * 1024 * 1024)
        .max_encoding_message_size(64 * 1024 * 1024);

    Server::builder()
        .layer(tonic::service::interceptor(interceptor))
        .add_service(service)
        .serve_with_shutdown(addr, async {
            tokio::signal::ctrl_c().await.ok();
            info!("Shutdown signal received");
        })
        .await?;

    info!("Mailstore Service stopped");
    Ok(())
}

fn load_encryption_key_from_file(path: &Path) -> Result<Vec<u8>> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| anyhow!("failed to inspect encryption key file: {error}"))?;
    if !metadata.is_file() {
        bail!("encryption key file must be a regular file");
    }
    validate_encryption_key_file_mode(&metadata)?;

    let mut key = std::fs::read(path)
        .map_err(|error| anyhow!("failed to read encryption key file: {error}"))?;
    trim_trailing_line_endings(&mut key);
    if key.len() < 32 {
        bail!("encryption key file must contain at least 32 bytes");
    }

    Ok(key)
}

#[cfg(unix)]
fn validate_encryption_key_file_mode(metadata: &Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        bail!("encryption key file permissions must be 0600");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_encryption_key_file_mode(_metadata: &Metadata) -> Result<()> {
    Ok(())
}

fn trim_trailing_line_endings(bytes: &mut Vec<u8>) {
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::service::Interceptor;

    #[test]
    fn constant_time_eq_compares_bytes() {
        assert!(constant_time_eq(b"token", b"token"));
        assert!(!constant_time_eq(b"token", b"tokeN"));
        assert!(!constant_time_eq(b"token", b"token2"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn shared_token_interceptor_accepts_only_the_configured_bearer_token() {
        let token = "a".repeat(mail_proto::MIN_INTERNAL_SERVICE_TOKEN_LENGTH);
        let mut interceptor = SharedTokenInterceptor::with_token(&token);

        let mut authorized_request = tonic::Request::new(());
        authorized_request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        assert!(interceptor.call(authorized_request).is_ok());

        assert!(interceptor.call(tonic::Request::new(())).is_err());

        let mut invalid_request = tonic::Request::new(());
        invalid_request
            .metadata_mut()
            .insert("authorization", "Bearer wrong-token".parse().unwrap());
        assert!(interceptor.call(invalid_request).is_err());
    }

    #[test]
    fn tokenless_mailstore_is_limited_to_loopback() {
        let no_token = SharedTokenInterceptor { expected: None };
        assert!(validate_bind_security("127.0.0.1:50051".parse().unwrap(), &no_token).is_ok());
        assert!(validate_bind_security("[::1]:50051".parse().unwrap(), &no_token).is_ok());
        assert!(validate_bind_security("0.0.0.0:50051".parse().unwrap(), &no_token).is_err());
        assert!(validate_bind_security("10.0.0.7:50051".parse().unwrap(), &no_token).is_err());
    }

    #[test]
    fn configured_token_allows_non_loopback_mailstore_bind() {
        let token = "a".repeat(mail_proto::MIN_INTERNAL_SERVICE_TOKEN_LENGTH);
        let interceptor = SharedTokenInterceptor::with_token(&token);
        assert!(validate_bind_security("0.0.0.0:50051".parse().unwrap(), &interceptor).is_ok());
    }

    #[test]
    fn trim_trailing_line_endings_only_removes_crlf_suffix() {
        let mut key = b"0123456789abcdef0123456789abcdef\r\n".to_vec();
        trim_trailing_line_endings(&mut key);

        assert_eq!(key, b"0123456789abcdef0123456789abcdef");
    }

    #[cfg(unix)]
    #[test]
    fn load_encryption_key_rejects_group_readable_file() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "apexmail-mailstore-test-key-{}-bad",
            std::process::id()
        ));
        std::fs::write(&path, b"0123456789abcdef0123456789abcdef").expect("write test key");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .expect("set test key mode");

        let error = load_encryption_key_from_file(&path).expect_err("mode must be rejected");
        let _ = std::fs::remove_file(&path);

        assert!(error.to_string().contains("0600"));
    }

    #[cfg(unix)]
    #[test]
    fn load_encryption_key_accepts_0600_file() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "apexmail-mailstore-test-key-{}-good",
            std::process::id()
        ));
        std::fs::write(&path, b"0123456789abcdef0123456789abcdef\n").expect("write test key");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("set test key mode");

        let key = load_encryption_key_from_file(&path).expect("load 0600 key");
        let _ = std::fs::remove_file(&path);

        assert_eq!(key, b"0123456789abcdef0123456789abcdef");
    }
}
