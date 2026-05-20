//! Mailstore Service
//!
//! Provides message storage and retrieval functionality.

use anyhow::{anyhow, bail, Result};
use clap::Parser;
use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};
use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tonic::transport::Server;
use tracing::info;
use tracing_subscriber::EnvFilter;

use mail_proto::MailstoreServiceServer;
use mailstore_core::{MailstoreServiceImpl, MessageStorage};

#[derive(Parser)]
#[command(name = "mailstore")]
#[command(about = "Mailstore Service - Message storage and retrieval")]
struct Cli {
    /// gRPC listen address
    #[arg(short, long, default_value = "0.0.0.0:50051")]
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

    info!("Starting Mailstore Service");
    info!("Listen address: {}", cli.listen);

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
    let addr = cli.listen.parse()?;
    info!("Starting gRPC server on {}", addr);

    Server::builder()
        .add_service(MailstoreServiceServer::new(service))
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
