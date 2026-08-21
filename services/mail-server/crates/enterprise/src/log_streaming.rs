use flate2::write::GzEncoder;
use flate2::Compression;
use sqlx::PgPool;
use std::io::Write;
use tracing::info;
use uuid::Uuid;

use crate::types::*;

/// Log Streaming Service:deliver logs to S3, Webhook, Splunk, Datadog, etc.
pub struct LogStreamingService {
    db: PgPool,
    /// Fix H-2: encryptor used to protect destination-config secrets at
    /// rest, bound to the owning tenant via AAD. `None` disables at-rest
    /// protection (legacy construction path).
    secret_encryptor: Option<crate::field_encryption::FieldEncryptor>,
}

/// Destination-config keys whose values are credentials and must be
/// encrypted at rest and masked in responses (fix H-2).
pub const SECRET_CONFIG_FIELDS: &[&str] = &[
    "token",
    "api_key",
    "secret",
    "password",
    "secret_key",
    "access_key",
    "client_secret",
    "shared_key",
];

const LOG_STREAM_SECRET_PURPOSE: &str = "enterprise/log-streaming/destination-secrets";

fn stream_secret_aad(tenant_id: &str) -> Vec<u8> {
    format!("{LOG_STREAM_SECRET_PURPOSE}/tenant:{tenant_id}").into_bytes()
}

/// Replace secret values with a mask that keeps only the last 4 characters.
pub fn mask_destination_config(config: &serde_json::Value) -> serde_json::Value {
    let mut masked = config.clone();
    let Some(obj) = masked.as_object_mut() else {
        return masked;
    };
    for field in SECRET_CONFIG_FIELDS {
        if let Some(value) = obj.get_mut(*field) {
            if let Some(secret) = value.as_str() {
                let tail: String = secret.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
                *value = serde_json::json!(format!("****{tail}"));
            }
        }
    }
    masked
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct LogStreamDbRow {
    id: Uuid,
    tenant_id: String,
    name: String,
    description: Option<String>,
    destination_type: String,
    status: String,
    enabled: bool,
    destination_config: Option<serde_json::Value>,
    credentials_encrypted: Option<String>,
    log_categories: Option<Vec<String>>,
    filter_rules: Option<serde_json::Value>,
    batch_size: Option<i32>,
    batch_interval_seconds: Option<i32>,
    compression_enabled: bool,
    format: Option<String>,
    total_events_delivered: i64,
    total_bytes_delivered: i64,
    delivery_failures_count: i32,
    last_delivery_at: Option<chrono::DateTime<chrono::Utc>>,
    last_error: Option<String>,
    last_error_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: Option<chrono::DateTime<chrono::Utc>>,
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<LogStreamDbRow> for LogStream {
    fn from(row: LogStreamDbRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            name: row.name,
            description: row.description,
            destination_type: row.destination_type,
            status: row.status,
            enabled: row.enabled,
            destination_config: row.destination_config,
            credentials_encrypted: row.credentials_encrypted,
            log_categories: row.log_categories,
            filter_rules: row.filter_rules,
            batch_size: row.batch_size,
            batch_interval_seconds: row.batch_interval_seconds,
            compression_enabled: row.compression_enabled,
            format: row.format,
            total_events_delivered: row.total_events_delivered,
            total_bytes_delivered: row.total_bytes_delivered,
            delivery_failures_count: row.delivery_failures_count,
            last_delivery_at: row.last_delivery_at,
            last_error: row.last_error,
            last_error_at: row.last_error_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// Mask secret fields of a stream's destination config before returning it
/// to a client (fix H-2: list/get responses must not echo secrets).
fn mask_stream(mut stream: LogStream) -> LogStream {
    if let Some(config) = stream.destination_config.take() {
        stream.destination_config = Some(mask_destination_config(&config));
    }
    stream
}

impl LogStreamingService {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            secret_encryptor: None,
        }
    }

    /// Construct with at-rest secret protection for destination configs
    /// (fix H-2). `secret` derives a purpose-bound KEK via
    /// `field_encryption::derive_kek_from_secret`.
    pub fn with_secret_key(db: PgPool, secret: &str) -> Self {
        let secret_encryptor =
            crate::field_encryption::encryptor_from_secret(secret, LOG_STREAM_SECRET_PURPOSE)
                .ok();
        if secret_encryptor.is_none() {
            tracing::error!(
                "Failed to derive log-stream destination secret encryptor — secrets will NOT be encrypted at rest"
            );
        }
        Self {
            db,
            secret_encryptor,
        }
    }

    /// Encrypt secret fields of a destination config (tenant-bound AAD).
    fn encrypt_config_secrets(
        &self,
        tenant_id: &str,
        config: &mut serde_json::Value,
    ) -> Result<(), String> {
        let Some(encryptor) = &self.secret_encryptor else {
            return Ok(());
        };
        let aad = stream_secret_aad(tenant_id);
        let Some(obj) = config.as_object_mut() else {
            return Ok(());
        };
        for field in SECRET_CONFIG_FIELDS {
            if let Some(value) = obj.get_mut(*field) {
                if let Some(secret) = value.as_str() {
                    if secret.is_empty()
                        || crate::field_encryption::FieldEncryptor::is_encrypted(secret)
                    {
                        continue;
                    }
                    let encrypted = encryptor
                        .encrypt_with_aad(secret, &aad)
                        .map_err(|e| format!("Encrypt destination secret: {e}"))?;
                    *value = serde_json::json!(encrypted);
                }
            }
        }
        Ok(())
    }

    /// Decrypt secret fields of a destination config (tenant-bound AAD).
    /// Values that were stored in plaintext (legacy) pass through.
    fn decrypt_config_secrets(
        &self,
        tenant_id: &str,
        config: &mut serde_json::Value,
    ) -> Result<(), String> {
        let Some(encryptor) = &self.secret_encryptor else {
            return Ok(());
        };
        let aad = stream_secret_aad(tenant_id);
        let Some(obj) = config.as_object_mut() else {
            return Ok(());
        };
        for field in SECRET_CONFIG_FIELDS {
            if let Some(value) = obj.get_mut(*field) {
                if let Some(secret) = value.as_str() {
                    if crate::field_encryption::FieldEncryptor::is_encrypted(secret) {
                        let decrypted = encryptor
                            .decrypt_with_aad(secret, &aad)
                            .map_err(|e| format!("Decrypt destination secret: {e}"))?;
                        *value = serde_json::json!(decrypted);
                    }
                }
            }
        }
        Ok(())
    }

    /// Create a new log stream
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        tenant_id: String,
        name: &str,
        description: Option<&str>,
        destination_type: &str,
        destination_config: Option<serde_json::Value>,
        log_categories: Option<Vec<String>>,
        batch_size: Option<i32>,
        batch_interval_seconds: Option<i32>,
        compression_enabled: bool,
    ) -> Result<ApiResult<LogStream>, String> {
        // Fix H-2: secrets in the destination config are encrypted at rest,
        // bound to the owning tenant.
        let mut destination_config = destination_config;
        if let Some(config) = destination_config.as_mut() {
            self.encrypt_config_secrets(&tenant_id, config)?;
        }
        let id = Uuid::new_v4();
        let row = sqlx::query_as::<_, LogStreamDbRow>(
            "INSERT INTO ent_log_streams (id, tenant_id, name, description, destination_type, status, enabled, destination_config, log_categories, batch_size, batch_interval_seconds, compression_enabled, format, total_events_delivered, total_bytes_delivered, delivery_failures_count, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,'active',true,$6,$7,$8,$9,$10,'json',0,0,0,NOW(),NOW())
             RETURNING *"
        )
        .bind(id).bind(&tenant_id).bind(name).bind(description)
        .bind(destination_config).bind(&log_categories)
        .bind(batch_size).bind(batch_interval_seconds).bind(compression_enabled)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Create log stream: {e}"))?;

        info!(tenant_id = %tenant_id, name = name, dest = destination_type, "Log stream created");
        Ok(ApiResult::ok(mask_stream(row.into())))
    }

    /// Get a log stream by ID
    pub async fn get(&self, id: Uuid) -> Result<ApiResult<LogStream>, String> {
        let row =
            sqlx::query_as::<_, LogStreamDbRow>("SELECT * FROM ent_log_streams WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| format!("Get log stream: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(mask_stream(r.into()))),
            None => Ok(ApiResult::err("Log stream not found", "NOT_FOUND")),
        }
    }

    /// List log streams for an account
    pub async fn list(&self, tenant_id: String) -> Result<ApiResult<Vec<LogStream>>, String> {
        let rows = sqlx::query_as::<_, LogStreamDbRow>(
            "SELECT * FROM ent_log_streams WHERE tenant_id = $1 ORDER BY created_at DESC",
        )
        .bind(&tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("List log streams: {e}"))?;

        Ok(ApiResult::ok(
            rows.into_iter().map(|r| mask_stream(r.into())).collect(),
        ))
    }

    /// Update a log stream
    pub async fn update(
        &self,
        id: Uuid,
        name: Option<&str>,
        description: Option<&str>,
        destination_config: Option<serde_json::Value>,
        log_categories: Option<Vec<String>>,
    ) -> Result<ApiResult<LogStream>, String> {
        // Fix H-2: encrypt secrets of the replacement config with the
        // stream's owning tenant binding.
        let mut destination_config = destination_config;
        if let Some(config) = destination_config.as_mut() {
            let owner: Option<String> = sqlx::query_scalar(
                "SELECT tenant_id FROM ent_log_streams WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(&self.db)
            .await
            .map_err(|e| format!("Load stream tenant: {e}"))?;
            match owner {
                Some(tenant_id) => self.encrypt_config_secrets(&tenant_id, config)?,
                None => return Ok(ApiResult::err("Log stream not found", "NOT_FOUND")),
            }
        }
        let row = sqlx::query_as::<_, LogStreamDbRow>(
            "UPDATE ent_log_streams SET
             name = COALESCE($2, name),
             description = COALESCE($3, description),
             destination_config = COALESCE($4, destination_config),
             log_categories = COALESCE($5, log_categories),
             updated_at = NOW()
             WHERE id = $1 RETURNING *",
        )
        .bind(id)
        .bind(name)
        .bind(description)
        .bind(&destination_config)
        .bind(&log_categories)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Update log stream: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(mask_stream(r.into()))),
            None => Ok(ApiResult::err("Log stream not found", "NOT_FOUND")),
        }
    }

    /// Pause a log stream
    pub async fn pause(&self, id: Uuid) -> Result<ApiResult<LogStream>, String> {
        let row = sqlx::query_as::<_, LogStreamDbRow>(
            "UPDATE ent_log_streams SET status = 'paused', updated_at = NOW() WHERE id = $1 RETURNING *"
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Pause log stream: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(r.into())),
            None => Ok(ApiResult::err("Log stream not found", "NOT_FOUND")),
        }
    }

    /// Resume a log stream
    pub async fn resume(&self, id: Uuid) -> Result<ApiResult<LogStream>, String> {
        let row = sqlx::query_as::<_, LogStreamDbRow>(
            "UPDATE ent_log_streams SET status = 'active', updated_at = NOW() WHERE id = $1 RETURNING *"
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Resume log stream: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(r.into())),
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
        let stream =
            sqlx::query_as::<_, LogStreamDbRow>("SELECT * FROM ent_log_streams WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| format!("Get stream for verify: {e}"))?;

        let mut stream = match stream {
            Some(s) => LogStream::from(s),
            None => return Ok(ApiResult::err("Log stream not found", "NOT_FOUND")),
        };

        // Fix H-2: decrypt the at-rest secrets with the owning tenant binding
        // for the outbound verification request.
        if let Some(config) = stream.destination_config.as_mut() {
            if let Err(e) = self.decrypt_config_secrets(&stream.tenant_id, config) {
                return Ok(ApiResult::err(e, "SECRET_DECRYPT_FAILED"));
            }
        }

        // Verify based on destination type
        let result = match stream.destination_type.as_str() {
            "webhook" => verify_webhook(&stream).await,
            "splunk" => verify_splunk(&stream).await,
            "datadog" => verify_datadog(&stream).await,
            // Fix F: unknown destination types must NOT auto-verify.
            other => Ok(serde_json::json!({
                "verified": false,
                "reason": format!("unsupported destination type '{other}'"),
            })),
        };

        match result {
            Ok(v) => Ok(ApiResult::ok(v)),
            Err(e) => Ok(ApiResult::err(e, "VERIFICATION_FAILED")),
        }
    }

    /// Record a delivery batch
    #[allow(clippy::too_many_arguments)]
    pub async fn record_delivery(
        &self,
        stream_id: Uuid,
        batch_id: &str,
        event_count: i32,
        bytes_delivered: i64,
        duration_ms: i32,
        success: bool,
        error_message: Option<&str>,
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
                 WHERE id = $1",
            )
            .bind(stream_id)
            .bind(event_count as i64)
            .bind(bytes_delivered)
            .execute(&self.db)
            .await
            .map_err(|e| format!("Update stream stats: {e}"))?;
        } else {
            // #274:Fixed race condition - increment first, then check the NEW value
            // Using a single atomic update that increments and evaluates in one operation
            sqlx::query(
                "UPDATE ent_log_streams SET 
                 last_error = $2, 
                 last_error_at = NOW(),
                 delivery_failures_count = delivery_failures_count + 1,
                 status = CASE WHEN delivery_failures_count + 1 >= 10 THEN 'error' ELSE status END
                 WHERE id = $1",
            )
            .bind(stream_id)
            .bind(error_message)
            .execute(&self.db)
            .await
            .map_err(|e| format!("Update stream error: {e}"))?;
        }
        Ok(())
    }

    /// Get delivery statistics for a stream
    pub async fn get_stats(&self, stream_id: Uuid) -> Result<ApiResult<StreamStats>, String> {
        #[allow(clippy::type_complexity)]
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

        let success_rate = if total > 0 {
            success_count.0 as f64 / total as f64 * 100.0
        } else {
            100.0
        };

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
        let rows = sqlx::query_as::<_, LogStreamDbRow>(
            "SELECT * FROM ent_log_streams WHERE status = 'active' AND enabled = true",
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("Get active streams: {e}"))?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// One pass of the background delivery loop (fix H-1).
    ///
    /// Pulls active streams (bounded batch) and delivers a bounded heartbeat
    /// event batch to each verified destination through the SSRF-guarded,
    /// address-pinned client — wiring `get_active_streams`, `record_delivery`
    /// and `hmac_sign` into a live best-effort delivery path. Delivery errors
    /// are recorded per-stream and never abort the cycle.
    pub async fn run_delivery_cycle(&self) -> Result<u64, String> {
        const MAX_STREAMS_PER_CYCLE: usize = 50;
        let streams = self.get_active_streams().await?;
        let mut delivered = 0u64;

        for stream in streams.into_iter().take(MAX_STREAMS_PER_CYCLE) {
            let mut stream = stream;
            if let Some(config) = stream.destination_config.as_mut() {
                if let Err(e) = self.decrypt_config_secrets(&stream.tenant_id, config) {
                    tracing::warn!(stream_id = %stream.id, error = %e, "delivery: secret decrypt failed");
                    let _ = self
                        .record_delivery(
                            stream.id,
                            &format!("hb-{}", Uuid::new_v4()),
                            0,
                            0,
                            0,
                            false,
                            Some(&e),
                        )
                        .await;
                    continue;
                }
            }

            let started = std::time::Instant::now();
            let outcome = deliver_heartbeat(&stream).await;
            let duration_ms = started.elapsed().as_millis().min(i32::MAX as u128) as i32;
            let batch_id = format!("hb-{}", Uuid::new_v4());

            match outcome {
                Ok(bytes) => {
                    delivered += 1;
                    if let Err(e) = self
                        .record_delivery(stream.id, &batch_id, 1, bytes as i64, duration_ms, true, None)
                        .await
                    {
                        tracing::warn!(stream_id = %stream.id, error = %e, "delivery: record failed");
                    }
                }
                Err(e) => {
                    tracing::warn!(stream_id = %stream.id, error = %e, "delivery: heartbeat failed");
                    if let Err(record_err) = self
                        .record_delivery(stream.id, &batch_id, 0, 0, duration_ms, false, Some(&e))
                        .await
                    {
                        tracing::warn!(stream_id = %stream.id, error = %record_err, "delivery: record failed");
                    }
                }
            }
        }

        Ok(delivered)
    }
}

/// Deliver a single-event heartbeat batch to a stream's destination using
/// the SSRF-guarded, address-pinned client (fix H-1 / F).
async fn deliver_heartbeat(stream: &LogStream) -> Result<usize, String> {
    let config = stream
        .destination_config
        .as_ref()
        .ok_or("No destination config")?;

    let payload = serde_json::json!([{
        "ts": chrono::Utc::now().to_rfc3339(),
        "service": "enterprise",
        "type": "heartbeat",
        "stream_id": stream.id.to_string(),
    }]);
    let body = serde_json::to_vec(&payload).map_err(|e| format!("Encode heartbeat: {e}"))?;

    match stream.destination_type.as_str() {
        "webhook" => {
            let url = config
                .get("url")
                .and_then(|v| v.as_str())
                .ok_or("No webhook URL")?;
            let dest = ssrf_guard_url(url).await?;
            let mut request = pinned_client(&dest.host, dest.addr)?
                .post(dest.url)
                .header("Content-Type", "application/json");
            // H-1: HMAC-sign the payload when a shared secret is configured.
            if let Some(secret) = config.get("secret").and_then(|v| v.as_str()) {
                let signature = hmac_sign(secret.as_bytes(), &body)?;
                request = request.header("X-ApexMail-Signature", format!("sha256={signature}"));
            }
            let resp = request
                .body(body.clone())
                .send()
                .await
                .map_err(|e| format!("Webhook delivery failed: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("Webhook returned status {}", resp.status()));
            }
            Ok(body.len())
        }
        "splunk" => {
            let url = config
                .get("url")
                .and_then(|v| v.as_str())
                .ok_or("No Splunk URL")?;
            let token = config
                .get("token")
                .and_then(|v| v.as_str())
                .ok_or("No HEC token")?;
            let mut base = ssrf_guard_url(url).await?;
            base.url.set_path("/services/collector/event");
            base.url.set_query(None);
            let resp = pinned_client(&base.host, base.addr)?
                .post(base.url)
                .header("Authorization", format!("Splunk {token}"))
                .body(body.clone())
                .send()
                .await
                .map_err(|e| format!("Splunk delivery failed: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("Splunk returned status {}", resp.status()));
            }
            Ok(body.len())
        }
        "datadog" => {
            let api_key = config
                .get("api_key")
                .and_then(|v| v.as_str())
                .ok_or("No Datadog API key")?;
            let dest =
                ssrf_guard_url("https://http-intake.logs.datadoghq.com/api/v2/logs").await?;
            let resp = pinned_client(&dest.host, dest.addr)?
                .post(dest.url)
                .header("DD-API-KEY", api_key)
                .body(body.clone())
                .send()
                .await
                .map_err(|e| format!("Datadog delivery failed: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("Datadog returned status {}", resp.status()));
            }
            Ok(body.len())
        }
        other => Err(format!(
            "unsupported destination type '{other}' — no delivery path configured"
        )),
    }
}

// ── Delivery helpers ───────────────────────────────────────────────────

// ── SSRF guard (fix F) ───────────────────────────────────────────────────────

fn is_private_or_reserved_v4(v4: &std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_loopback() // 127/8
        || v4.is_private() // 10/8, 172.16/12, 192.168/16
        || v4.is_link_local() // 169.254/16 (AWS/GCP metadata)
        || v4.is_unspecified() // 0.0.0.0
        || v4.is_broadcast() // 255.255.255.255
        || v4.is_documentation() // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || o[0] == 0 // "this" network
        || o[0] >= 240 // reserved for future use
        // 100.64/10 — CGNAT shared address space
        || (o[0] == 100 && o[1] >= 64 && o[1] <= 127)
        // 192.0.0/24 — IETF protocol assignments
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        // 198.18/15 — benchmarking
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
}

/// Pure IP classification: is this address private, reserved, loopback,
/// link-local, or otherwise unsuitable as an outbound destination?
///
/// Unit-testable without DNS — tests feed addresses directly.
pub fn is_private_or_reserved_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_private_or_reserved_v4(&v4),
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback() // ::1
                || v6.is_unspecified() // ::
                || v6.is_multicast()
                // fe80::/10 — link-local
                || (s[0] & 0xffc0) == 0xfe80
                // fc00::/7 — unique local addresses
                || (s[0] & 0xfe00) == 0xfc00
                // IPv4-mapped (::ffff:a.b.c.d) — re-check the embedded v4
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|embedded| is_private_or_reserved_v4(&embedded))
        }
    }
}

/// Addresses explicitly allow-listed via `LOG_STREAMING_SSRF_ALLOWLIST`
/// (comma-separated IPs) — an escape hatch for internal test destinations.
static SSRF_ALLOWLIST: std::sync::LazyLock<Vec<std::net::IpAddr>> = std::sync::LazyLock::new(|| {
    std::env::var("LOG_STREAMING_SSRF_ALLOWLIST")
        .unwrap_or_default()
        .split(',')
        .filter_map(|entry| entry.trim().parse().ok())
        .collect()
});

/// Cached per-destination clients whose DNS is pinned to the validated
/// address (fix F: closes the DNS-rebinding TOCTOU between validation and
/// the actual request). Bounded cache — evicted wholesale when it grows past
/// a small cap.
static PINNED_CLIENTS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<(String, std::net::SocketAddr), reqwest::Client>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Build (or fetch from the bounded cache) an HTTP client whose DNS for
/// `host` is pinned to the validated `addr`.
pub fn pinned_client(host: &str, addr: std::net::SocketAddr) -> Result<reqwest::Client, String> {
    let key = (host.to_string(), addr);
    {
        let cache = PINNED_CLIENTS
            .lock()
            .map_err(|_| "pinned client cache poisoned")?;
        if let Some(client) = cache.get(&key) {
            return Ok(client.clone());
        }
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .resolve(host, addr)
        .build()
        .map_err(|e| format!("Build pinned client for {host}: {e}"))?;

    let mut cache = PINNED_CLIENTS
        .lock()
        .map_err(|_| "pinned client cache poisoned")?;
    if cache.len() >= 64 {
        cache.clear();
    }
    cache.insert(key, client.clone());
    Ok(client)
}

/// A destination URL that passed the resolving SSRF guard.
pub struct GuardedDestination {
    /// Original URL string (post-parse).
    pub url: reqwest::Url,
    /// Hostname to pin in the outgoing request.
    pub host: String,
    /// The resolved, validated address to pin the outgoing request to.
    pub addr: std::net::SocketAddr,
}

/// Resolving SSRF guard for outbound destination URLs (fix F).
///
/// The previous check matched hostname *strings* ("10.", "localhost", …)
/// without DNS resolution, so `https://evil.com` → 10.0.0.5 or a DNS rebinding
/// answer sailed through, and the Splunk verifier did not even call it. This
/// guard:
///   1. requires HTTPS,
///   2. resolves the hostname (or parses a literal IP),
///   3. rejects the URL when ANY resolved address is private/reserved
///      (unless explicitly allow-listed via env),
///   4. returns the resolved address so the caller can pin it for the actual
///      request (pinned client) — closing DNS-rebinding TOCTOU.
pub async fn ssrf_guard_url(url: &str) -> Result<GuardedDestination, String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("Invalid URL: {e}"))?;
    if parsed.scheme() != "https" {
        return Err("Destination URL must use HTTPS".into());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "No host in URL".to_string())?
        .to_string();
    let port = parsed.port_or_known_default().ok_or("No port")?;

    // Literal IP or DNS resolution.
    let ips: Vec<std::net::IpAddr> = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        vec![ip]
    } else {
        tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|e| format!("DNS resolution failed for {host}: {e}"))?
            .map(|socket_addr| socket_addr.ip())
            .collect()
    };
    if ips.is_empty() {
        return Err(format!("DNS resolution returned no addresses for {host}"));
    }

    let allowlist = &*SSRF_ALLOWLIST;
    for ip in &ips {
        if is_private_or_reserved_ip(*ip) && !allowlist.contains(ip) {
            return Err(format!(
                "Destination {host} resolves to a blocked private/reserved address ({ip})"
            ));
        }
    }

    let addr = std::net::SocketAddr::new(ips[0], port);
    Ok(GuardedDestination {
        url: parsed,
        host,
        addr,
    })
}

async fn verify_webhook(stream: &LogStream) -> Result<serde_json::Value, String> {
    let config = stream
        .destination_config
        .as_ref()
        .ok_or("No destination config")?;
    let url = config
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or("No webhook URL")?;

    // Fix F: resolving SSRF guard with a pinned address.
    let dest = ssrf_guard_url(url).await?;

    let resp = pinned_client(&dest.host, dest.addr)?
        .post(dest.url)
        .header("Content-Type", "application/json")
        .body(r#"{"test": true}"#)
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
    let config = stream
        .destination_config
        .as_ref()
        .ok_or("No destination config")?;
    let url = config
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or("No Splunk URL")?;
    let token = config
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or("No HEC token")?;

    // Fix F: the Splunk verifier previously never called the SSRF guard at
    // all — route it through the same resolving guard and pin the address.
    let mut base = ssrf_guard_url(url).await?;
    base.url.set_path("/services/collector/event");
    base.url.set_query(None);

    let resp = pinned_client(&base.host, base.addr)?
        .post(base.url)
        .header("Authorization", format!("Splunk {token}"))
        .json(&serde_json::json!({"event": "test", "sourcetype": "apexmail"}))
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
    let config = stream
        .destination_config
        .as_ref()
        .ok_or("No destination config")?;
    let api_key = config
        .get("api_key")
        .and_then(|v| v.as_str())
        .ok_or("No Datadog API key")?;

    // Datadog's intake host is fixed and public — still route it through the
    // guard for uniformity (fix F: all destinations verified alike).
    let dest = ssrf_guard_url("https://http-intake.logs.datadoghq.com/api/v2/logs").await?;

    let resp = pinned_client(&dest.host, dest.addr)?
        .post(dest.url)
        .header("DD-API-KEY", api_key)
        .json(
            &serde_json::json!([{"message": "ApexMail connectivity test", "ddsource": "apexmail"}]),
        )
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
    encoder
        .write_all(data)
        .map_err(|e| format!("Compress: {e}"))?;
    encoder
        .finish()
        .map_err(|e| format!("Finish compress: {e}"))
}

/// Sign a webhook payload with HMAC-SHA256
/// #271:Returns Result instead of panicking on invalid key
pub fn hmac_sign(key: &[u8], data: &[u8]) -> Result<String, String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).map_err(|e| format!("Invalid HMAC key: {e}"))?;
    mac.update(data);
    Ok(hex::encode(mac.finalize().into_bytes()))
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
        let sig1 = hmac_sign(b"secret", b"payload").unwrap();
        let sig2 = hmac_sign(b"secret", b"payload").unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_hmac_sign_different_keys() {
        let sig1 = hmac_sign(b"key1", b"same_data").unwrap();
        let sig2 = hmac_sign(b"key2", b"same_data").unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_hmac_sign_hex_format() {
        let sig = hmac_sign(b"test", b"test").unwrap();
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
            tenant_id: Uuid::new_v4().to_string(),
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
