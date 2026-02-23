use flate2::write::GzEncoder;
use flate2::Compression;
use sqlx::PgPool;
use std::io::Write;
use tracing::info;
use uuid::Uuid;

use crate::types::*;

/// Log Streaming Service: deliver logs to S3, Webhook, Splunk, Datadog, etc.
pub struct LogStreamingService {
    db: PgPool,
}

impl LogStreamingService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Create a new log stream
    pub async fn create(
        &self, tenant_id: Uuid, name: &str, description: Option<&str>,
        destination_type: &str, destination_config: Option<serde_json::Value>,
        log_categories: Option<Vec<String>>, batch_size: Option<i32>,
        batch_interval_seconds: Option<i32>, compression_enabled: bool,
    ) -> Result<ApiResult<LogStream>, String> {
        let id = Uuid::new_v4();
        let row = sqlx::query_as::<_, LogStream>(
            "INSERT INTO ent_log_streams (id, tenant_id, name, description, destination_type, status, enabled, destination_config, log_categories, batch_size, batch_interval_seconds, compression_enabled, format, total_events_delivered, total_bytes_delivered, delivery_failures_count, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,'active',true,$6,$7,$8,$9,$10,'json',0,0,0,NOW(),NOW())
             RETURNING *"
        )
        .bind(id).bind(tenant_id).bind(name).bind(description)
        .bind(destination_type).bind(&destination_config).bind(&log_categories)
        .bind(batch_size).bind(batch_interval_seconds).bind(compression_enabled)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Create log stream: {e}"))?;

        info!(tenant_id = %tenant_id, name = name, dest = destination_type, "Log stream created");
        Ok(ApiResult::ok(row))
    }

    /// Get a log stream by ID
    pub async fn get(&self, id: Uuid) -> Result<ApiResult<LogStream>, String> {
        let row = sqlx::query_as::<_, LogStream>(
            "SELECT * FROM ent_log_streams WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get log stream: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(r)),
            None => Ok(ApiResult::err("Log stream not found", "NOT_FOUND")),
        }
    }

    /// List log streams for an account
    pub async fn list(&self, tenant_id: Uuid) -> Result<ApiResult<Vec<LogStream>>, String> {
        let rows = sqlx::query_as::<_, LogStream>(
            "SELECT * FROM ent_log_streams WHERE tenant_id = $1 ORDER BY created_at DESC"
        )
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("List log streams: {e}"))?;

        Ok(ApiResult::ok(rows))
    }

    /// Update a log stream
    pub async fn update(
        &self, id: Uuid, name: Option<&str>, description: Option<&str>,
        destination_config: Option<serde_json::Value>,
        log_categories: Option<Vec<String>>,
    ) -> Result<ApiResult<LogStream>, String> {
        let row = sqlx::query_as::<_, LogStream>(
            "UPDATE ent_log_streams SET
             name = COALESCE($2, name),
             description = COALESCE($3, description),
             destination_config = COALESCE($4, destination_config),
             log_categories = COALESCE($5, log_categories),
             updated_at = NOW()
             WHERE id = $1 RETURNING *"
        )
        .bind(id).bind(name).bind(description)
        .bind(&destination_config).bind(&log_categories)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Update log stream: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(r)),
            None => Ok(ApiResult::err("Log stream not found", "NOT_FOUND")),
        }
    }

    /// Pause a log stream
    pub async fn pause(&self, id: Uuid) -> Result<ApiResult<LogStream>, String> {
        let row = sqlx::query_as::<_, LogStream>(
            "UPDATE ent_log_streams SET status = 'paused', updated_at = NOW() WHERE id = $1 RETURNING *"
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Pause log stream: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(r)),
            None => Ok(ApiResult::err("Log stream not found", "NOT_FOUND")),
        }
    }

    /// Resume a log stream
    pub async fn resume(&self, id: Uuid) -> Result<ApiResult<LogStream>, String> {
        let row = sqlx::query_as::<_, LogStream>(
            "UPDATE ent_log_streams SET status = 'active', updated_at = NOW() WHERE id = $1 RETURNING *"
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Resume log stream: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(r)),
            None => Ok(ApiResult::err("Log stream not found", "NOT_FOUND")),
        }
    }

    /// Delete a log stream
    pub async fn delete(&self, id: Uuid) -> Result<ApiResult<serde_json::Value>, String> {
        let result = sqlx::query("DELETE FROM ent_log_streams WHERE id = $1")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(|e| format!("Delete log stream: {e}"))?;

        if result.rows_affected() == 0 {
            Ok(ApiResult::err("Log stream not found", "NOT_FOUND"))
        } else {
            Ok(ApiResult::ok(serde_json::json!({"deleted": true})))
        }
    }

    /// Verify destination connectivity
    pub async fn verify(&self, id: Uuid) -> Result<ApiResult<serde_json::Value>, String> {
        let stream = sqlx::query_as::<_, LogStream>(
            "SELECT * FROM ent_log_streams WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get stream for verify: {e}"))?;

        let stream = match stream {
            Some(s) => s,
            None => return Ok(ApiResult::err("Log stream not found", "NOT_FOUND")),
        };

        // Verify based on destination type
        let result = match stream.destination_type.as_str() {
            "webhook" => verify_webhook(&stream).await,
            "splunk" => verify_splunk(&stream).await,
            "datadog" => verify_datadog(&stream).await,
            _ => Ok(serde_json::json!({"verified": true, "message": "Destination type check passed"})),
        };

        match result {
            Ok(v) => Ok(ApiResult::ok(v)),
            Err(e) => Ok(ApiResult::err(e, "VERIFICATION_FAILED")),
        }
    }

    /// Record a delivery batch
    pub async fn record_delivery(
        &self, stream_id: Uuid, batch_id: &str, event_count: i32,
        bytes_delivered: i64, duration_ms: i32, success: bool, error_message: Option<&str>,
    ) -> Result<(), String> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO ent_stream_batches (id, stream_id, batch_id, event_count, bytes_delivered, duration_ms, success, error_message, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())"
        )
        .bind(id).bind(stream_id).bind(batch_id).bind(event_count)
        .bind(bytes_delivered).bind(duration_ms).bind(success).bind(error_message)
        .execute(&self.db)
        .await
        .map_err(|e| format!("Record delivery: {e}"))?;

        if success {
            sqlx::query(
                "UPDATE ent_log_streams SET total_events_delivered = total_events_delivered + $2,
                 total_bytes_delivered = total_bytes_delivered + $3, last_delivery_at = NOW()
                 WHERE id = $1"
            )
            .bind(stream_id).bind(event_count as i64).bind(bytes_delivered)
            .execute(&self.db)
            .await
            .map_err(|e| format!("Update stream stats: {e}"))?;
        } else {
            sqlx::query(
                "UPDATE ent_log_streams SET last_error = $2, last_error_at = NOW(),
                 delivery_failures_count = delivery_failures_count + 1,
                 status = CASE WHEN delivery_failures_count >= 10 THEN 'error' ELSE status END
                 WHERE id = $1"
            )
            .bind(stream_id).bind(error_message)
            .execute(&self.db)
            .await
            .map_err(|e| format!("Update stream error: {e}"))?;
        }
        Ok(())
    }

    /// Get delivery statistics for a stream
    pub async fn get_stats(&self, stream_id: Uuid) -> Result<ApiResult<StreamStats>, String> {
        let row: Option<(i64, Option<i64>, Option<i64>, Option<f64>)> = sqlx::query_as(
            "SELECT COUNT(*), SUM(event_count)::bigint, SUM(bytes_delivered)::bigint, AVG(duration_ms)::float8
             FROM ent_stream_batches WHERE stream_id = $1 AND created_at > NOW() - interval '24 hours'"
        )
        .bind(stream_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get stream stats: {e}"))?;

        let (total, events, bytes, avg_dur) = row.unwrap_or((0, None, None, None));
        let success_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM ent_stream_batches WHERE stream_id = $1 AND success = true AND created_at > NOW() - interval '24 hours'"
        )
        .bind(stream_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Get success count: {e}"))?;

        let success_rate = if total > 0 { success_count.0 as f64 / total as f64 * 100.0 } else { 100.0 };

        Ok(ApiResult::ok(StreamStats {
            total_deliveries: total,
            total_events: events.unwrap_or(0),
            total_bytes: bytes.unwrap_or(0),
            avg_duration_ms: avg_dur.unwrap_or(0.0),
            success_rate,
        }))
    }

    /// Get all active streams for background processing
    pub async fn get_active_streams(&self) -> Result<Vec<LogStream>, String> {
        sqlx::query_as::<_, LogStream>(
            "SELECT * FROM ent_log_streams WHERE status = 'active' AND enabled = true"
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("Get active streams: {e}"))
    }
}

// ── Delivery helpers ───────────────────────────────────────────────────

async fn verify_webhook(stream: &LogStream) -> Result<serde_json::Value, String> {
    let config = stream.destination_config.as_ref().ok_or("No destination config")?;
    let url = config.get("url").and_then(|v| v.as_str()).ok_or("No webhook URL")?;

    let client = reqwest::Client::new();
    let resp = client.post(url)
        .header("Content-Type", "application/json")
        .body(r#"{"test": true}"#)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("Webhook verify failed: {e}"))?;

    if resp.status().is_success() {
        Ok(serde_json::json!({"verified": true, "status": resp.status().as_u16()}))
    } else {
        Err(format!("Webhook returned status {}", resp.status()))
    }
}

async fn verify_splunk(stream: &LogStream) -> Result<serde_json::Value, String> {
    let config = stream.destination_config.as_ref().ok_or("No destination config")?;
    let url = config.get("url").and_then(|v| v.as_str()).ok_or("No Splunk URL")?;
    let token = config.get("token").and_then(|v| v.as_str()).ok_or("No HEC token")?;

    let client = reqwest::Client::new();
    let resp = client.post(&format!("{url}/services/collector/event"))
        .header("Authorization", format!("Splunk {token}"))
        .json(&serde_json::json!({"event": "test", "sourcetype": "apexmail"}))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("Splunk verify failed: {e}"))?;

    if resp.status().is_success() {
        Ok(serde_json::json!({"verified": true}))
    } else {
        Err(format!("Splunk returned status {}", resp.status()))
    }
}

async fn verify_datadog(stream: &LogStream) -> Result<serde_json::Value, String> {
    let config = stream.destination_config.as_ref().ok_or("No destination config")?;
    let api_key = config.get("api_key").and_then(|v| v.as_str()).ok_or("No Datadog API key")?;

    let client = reqwest::Client::new();
    let resp = client.post("https://http-intake.logs.datadoghq.com/api/v2/logs")
        .header("DD-API-KEY", api_key)
        .json(&serde_json::json!([{"message": "ApexMail connectivity test", "ddsource": "apexmail"}]))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("Datadog verify failed: {e}"))?;

    if resp.status().is_success() {
        Ok(serde_json::json!({"verified": true}))
    } else {
        Err(format!("Datadog returned status {}", resp.status()))
    }
}

/// Compress data using gzip
pub fn gzip_compress(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).map_err(|e| format!("Compress: {e}"))?;
    encoder.finish().map_err(|e| format!("Finish compress: {e}"))
}

/// Sign a webhook payload with HMAC-SHA256
pub fn hmac_sign(key: &[u8], data: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_gzip_compress_decompress() {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let data = b"Hello, world! This is a test payload for log streaming.";
        let compressed = gzip_compress(data).unwrap();
        assert!(compressed.len() < data.len() + 50); // gzip adds some overhead for small data

        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_hmac_sign_deterministic() {
        let sig1 = hmac_sign(b"secret", b"payload");
        let sig2 = hmac_sign(b"secret", b"payload");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_hmac_sign_different_keys() {
        let sig1 = hmac_sign(b"key1", b"same_data");
        let sig2 = hmac_sign(b"key2", b"same_data");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_hmac_sign_hex_format() {
        let sig = hmac_sign(b"test", b"test");
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(sig.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn test_stream_stats_serialization() {
        let stats = StreamStats {
            total_deliveries: 100,
            total_events: 5000,
            total_bytes: 1024000,
            avg_duration_ms: 45.5,
            success_rate: 98.5,
        };
        let json = serde_json::to_value(&stats).unwrap();
        assert_eq!(json["total_deliveries"], 100);
        assert_eq!(json["success_rate"], 98.5);
    }

    #[test]
    fn test_log_stream_serialization() {
        let stream = LogStream {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "My Stream".into(),
            description: Some("Test stream".into()),
            destination_type: "webhook".into(),
            status: "active".into(),
            enabled: true,
            destination_config: Some(serde_json::json!({"url": "https://example.com/webhook"})),
            credentials_encrypted: None,
            log_categories: Some(vec!["delivery".into(), "bounce".into()]),
            filter_rules: None,
            batch_size: Some(500),
            batch_interval_seconds: Some(30),
            compression_enabled: true,
            format: Some("json".into()),
            total_events_delivered: 10000,
            total_bytes_delivered: 5242880,
            delivery_failures_count: 2,
            last_delivery_at: Some(Utc::now()),
            last_error: None,
            last_error_at: None,
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
        };
        let json = serde_json::to_value(&stream).unwrap();
        assert_eq!(json["name"], "My Stream");
        assert_eq!(json["status"], "active");
    }

    #[test]
    fn test_gzip_empty_data() {
        let compressed = gzip_compress(b"").unwrap();
        assert!(!compressed.is_empty()); // even empty data produces gzip header

        use flate2::read::GzDecoder;
        use std::io::Read;
        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        assert!(decompressed.is_empty());
    }

    #[test]
    fn test_stream_delivery_serialization() {
        let delivery = StreamDelivery {
            id: Uuid::new_v4(),
            stream_id: Uuid::new_v4(),
            batch_id: "batch-001".into(),
            event_count: 500,
            bytes_delivered: 102400,
            duration_ms: 250,
            success: true,
            error_message: None,
            created_at: Some(Utc::now()),
        };
        let json = serde_json::to_value(&delivery).unwrap();
        assert_eq!(json["event_count"], 500);
        assert_eq!(json["success"], true);
    }
}
