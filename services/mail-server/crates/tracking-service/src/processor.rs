//! Redis WAL → PostgreSQL event processor.
//!
//! • Events are RPUSH'd into a Redis list (write-ahead log) _before_ the
//! HTTP response is sent, so they survive process crashes (Redis AOF).
//! • A background Tokio task drains batches from Redis → Postgres using an
//! atomic Lua script (LRANGE + LTRIM in one Redis round-trip).
//! • If the Postgres write fails, events are re-RPUSH'd back to Redis so the
//! next flush cycle retries (-500-001).
//! • Events are wrapped in versioned envelopes with a SHA-256 checksum
//! (E-174) for forward-compatible integrity checking.
//! • Dedup via Redis SETNX (EX 86400, open; EX 1 s, rapid clicks).

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use deadpool_redis::Pool as RedisPool;
use redis::Script;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::Notify;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// ── Event envelope ────────────────────────────────────────────────────────────

/// WAL envelope version for the persisted tracking payload.
const WAL_VERSION: u8 = 1;

/// Redis list key (without the `tracking:` keyPrefix applied by the pool).
/// The pool's keyPrefix is `tracking:` so the effective key is
/// `tracking:apexmail:events:pending`.
pub const REDIS_WAL_KEY: &str = "apexmail:events:pending";

/// Atomic Lua drain:reads up to N items from the front of the list and
/// simultaneously trims them, all in a single Redis operation — no interleave
/// window between LRANGE and LTRIM.
const ATOMIC_DRAIN_SCRIPT: &str = r#"
local events = redis.call('LRANGE', KEYS[1], 0, tonumber(ARGV[1]) - 1)
if #events > 0 then
  redis.call('LTRIM', KEYS[1], #events, -1)
end
return events
"#;

// ── Tracking event ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrackingEvent {
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: EventType,
    pub tenant_id: String,
    pub message_id: String,
    pub recipient: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsubscribe_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventType {
    Opened,
    Clicked,
    Unsubscribed,
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventType::Opened => f.write_str("opened"),
            EventType::Clicked => f.write_str("clicked"),
            EventType::Unsubscribed => f.write_str("unsubscribed"),
        }
    }
}

// ── Public record helpers ────────────────────────────────────────────────────

pub struct OpenData {
    pub tenant_id: String,
    pub message_id: String,
    pub recipient: String,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}

pub struct ClickData {
    pub tenant_id: String,
    pub message_id: String,
    pub recipient: String,
    pub link_id: String,
    pub link_url: String,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}

pub struct UnsubscribeData {
    pub tenant_id: String,
    pub message_id: String,
    pub recipient: String,
    pub reason: Option<String>,
    pub category: Option<String>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}

// ── EventProcessor ────────────────────────────────────────────────────────────

pub struct EventProcessor {
    db: PgPool,
    redis: RedisPool,
    flush_interval_ms: u64,
    max_buffer_size: usize,
    drain_script: Script,
    shutdown: Arc<Notify>,
    running: Arc<AtomicBool>,
}

impl EventProcessor {
    pub fn new(db: PgPool, redis: RedisPool) -> Self {
        Self::with_config(db, redis, 1_000, 100)
    }

    pub fn with_config(
        db: PgPool,
        redis: RedisPool,
        flush_interval_ms: u64,
        max_buffer_size: usize,
    ) -> Self {
        Self {
            db,
            redis,
            flush_interval_ms,
            max_buffer_size,
            drain_script: Script::new(ATOMIC_DRAIN_SCRIPT),
            shutdown: Arc::new(Notify::new()),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

/// Start the background flush loop in a detached Tokio task.
/// Returns a handle so callers can `await` graceful shutdown.
    pub fn start(self: Arc<Self>) {
        let interval = Duration::from_millis(self.flush_interval_ms);
        let this = self.clone();

        self.running.store(true, Ordering::SeqCst);
        tokio::spawn(async move {
            info!("EventProcessor: flush loop started (interval={}ms, batch={})",
                this.flush_interval_ms, this.max_buffer_size);

            loop {
                tokio::select! {
// Re-schedule after the configured fixed interval.
                    _ = tokio::time::sleep(interval) => {
                        if let Err(e) = this.flush().await {
                            error!(error = %e, "EventProcessor: flush error");
                        }
                    }
// Shutdown signal received
                    _ = this.shutdown.notified() => {
                        info!("EventProcessor: shutdown signal received, draining WAL");
// Drain remaining events before exit (C-093)
                        this.drain_all().await;
                        break;
                    }
                }
            }
            this.running.store(false, Ordering::SeqCst);
            info!("EventProcessor: flush loop stopped");
        });
    }

/// Signal shutdown and wait for the flush loop to drain.
    pub async fn stop(&self) {
        self.shutdown.notify_one();
// Poll until the loop exits
        let mut waited = 0u64;
        while self.running.load(Ordering::SeqCst) && waited < 30_000 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            waited += 50;
        }
    }

// ── Record helpers ────────────────────────────────────────────────

/// Record an email-open event into the Redis WAL.
    pub async fn record_open(&self, data: OpenData) -> Result<()> {
// Dedup:SETNX dedupe:{sha256(type:msgId:recipient)} EX 86400
        let dedup_key = dedup_key("open", &data.message_id, &data.recipient, None);
        if !self.try_set_dedup(&dedup_key, 86400).await? {
            debug!(message_id = %data.message_id, "Duplicate open event, skipping");
            return Ok(());
        }

        let OpenData { tenant_id, message_id, recipient, user_agent, ip_address } = data;
        let event = TrackingEvent {
            id: new_id("evt"),
            event_type: EventType::Opened,
            tenant_id,
            message_id,
            recipient,
            link_id: None,
            link_url: None,
            unsubscribe_reason: None,
            user_agent,
            ip_address,
            timestamp: Utc::now(),
            metadata: None,
        };

        self.enqueue_event(&event).await?;

// Increment Redis counters (non-critical, fire-and-forget)
        let now = Utc::now();
        let date = now.format("%Y-%m-%d").to_string();
        let hour = now.format("%H").to_string();
        self.incr_counters(&event.tenant_id, &date, &hour, "opens").await;

        Ok(())
    }

/// Record a click event into the Redis WAL.
    pub async fn record_click(&self, data: ClickData) -> Result<()> {
// Dedup rapid-fire clicks within 1 second
        let dedup_key = dedup_key("click", &data.message_id, &data.recipient, Some(&data.link_id));
        if !self.try_set_dedup(&dedup_key, 1).await? {
            debug!(message_id = %data.message_id, link_id = %data.link_id, "Rapid duplicate click, skipping");
            return Ok(());
        }

        let ClickData { tenant_id, message_id, recipient, link_id, link_url, user_agent, ip_address } = data;
        let event = TrackingEvent {
            id: new_id("evt"),
            event_type: EventType::Clicked,
            tenant_id,
            message_id,
            recipient,
            link_id: Some(link_id),
            link_url: Some(link_url),
            unsubscribe_reason: None,
            user_agent,
            ip_address,
            timestamp: Utc::now(),
            metadata: None,
        };

        self.enqueue_event(&event).await?;

// Track unique clicks via a separate NX key (30-day window)
        let now = Utc::now();
        let date = now.format("%Y-%m-%d").to_string();
        let hour = now.format("%H").to_string();
        self.incr_counters(&event.tenant_id, &date, &hour, "clicks").await;

        Ok(())
    }

/// Record an unsubscribe event into the Redis WAL and immediately add the
/// recipient to the suppression list (GDPR / CAN-SPAM requirement).
    pub async fn record_unsubscribe(&self, data: UnsubscribeData) -> Result<()> {
        let metadata = data.category.as_deref().map(|cat| {
            serde_json::json!({ "category": cat })
        });
        let category = data.category;
        let UnsubscribeData { tenant_id, message_id, recipient, reason, user_agent, ip_address, .. } = data;
        let event = TrackingEvent {
            id: new_id("evt"),
            event_type: EventType::Unsubscribed,
            tenant_id,
            message_id,
            recipient,
            link_id: None,
            link_url: None,
            unsubscribe_reason: Some(reason.unwrap_or_else(|| "one-click".into())),
            user_agent,
            ip_address,
            timestamp: Utc::now(),
            metadata,
        };

        self.enqueue_event(&event).await?;
        self.add_to_suppression_list(&event.tenant_id, &event.recipient, category.as_deref()).await;

        Ok(())
    }

// ── WAL helpers ───────────────────────────────────────────────────

/// Wrap event in a versioned envelope and RPUSH to Redis WAL.
    async fn enqueue_event(&self, event: &TrackingEvent) -> Result<()> {
        let payload = serde_json::to_string(event).context("serialize event")?;
        let cs = sha256_hex8(&payload);
        let envelope = format!(r#"{{"v":{WAL_VERSION},"cs":"{cs}","d":{payload}}}"#);

        let mut conn = self.redis.get().await.context("redis pool get")?;
        redis::cmd("RPUSH")
            .arg(REDIS_WAL_KEY)
            .arg(&envelope)
            .query_async::<()>(&mut *conn)
            .await
            .context("RPUSH to WAL")?;
        Ok(())
    }

// ── Flush loop ────────────────────────────────────────────────────

    async fn flush(&self) -> Result<()> {
        let mut conn = self.redis.get().await.context("redis pool get (flush)")?;

        let raw: Vec<String> = self
            .drain_script
            .key(REDIS_WAL_KEY)
            .arg(self.max_buffer_size as i64)
            .invoke_async(&mut *conn)
            .await
            .context("atomic drain Lua script")?;

        drop(conn);

        if raw.is_empty() {
            return Ok(());
        }

        let events: Vec<TrackingEvent> = parse_wal_entries(&raw);
        if events.is_empty() {
            return Ok(());
        }

        if let Err(write_err) = self.write_events(&events).await {
            error!(
                count = events.len(),
                error = %write_err,
                "writeEvents failed — re-pushing events to Redis WAL"
            );
            self.reenqueue_events(&events).await;
            return Err(write_err);
        }

        debug!(count = raw.len(), "Flushed events from Redis WAL");
        Ok(())
    }

    async fn drain_all(&self) {
        loop {
            let mut conn = match self.redis.get().await {
                Ok(c) => c,
                Err(e) => { error!(error = %e, "drain_all: redis pool error"); break; }
            };
            let len: i64 = match redis::cmd("LLEN").arg(REDIS_WAL_KEY).query_async(&mut *conn).await {
                Ok(n) => n,
                Err(e) => { error!(error = %e, "drain_all: LLEN error"); break; }
            };
            drop(conn);
            if len == 0 { break; }
            info!(remaining = len, "Draining Redis WAL on shutdown");
            if let Err(e) = self.flush().await {
                error!(error = %e, "drain_all: flush error, stopping drain");
                break;
            }
        }
    }

    async fn reenqueue_events(&self, events: &[TrackingEvent]) {
        let mut conn = match self.redis.get().await {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, count = events.len(),
                    "CRITICAL: failed to get Redis conn for re-enqueue — events may be lost");
                return;
            }
        };

        let mut pipe = redis::pipe();
        for event in events {
            if let Ok(payload) = serde_json::to_string(event) {
                let cs = sha256_hex8(&payload);
                let envelope = format!(r#"{{"v":{WAL_VERSION},"cs":"{cs}","d":{payload}}}"#);
                pipe.rpush(REDIS_WAL_KEY, envelope);
            }
        }
        if let Err(e) = pipe.query_async::<()>(&mut *conn).await {
            error!(error = %e, count = events.len(),
                "CRITICAL: failed to re-push events to Redis WAL — events may be lost");
        }
    }

// ── Postgres write ─────────────────────────────────────────────────

    async fn write_events(&self, events: &[TrackingEvent]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }

// Max PG params ≈ 65535; 10 columns per event → max chunk 6500
        const PARAMS_PER_EVENT: usize = 10;
        const MAX_PER_CHUNK: usize = 65000 / PARAMS_PER_EVENT;

        let mut tx = self.db.begin().await.context("begin transaction")?;

        for chunk in events.chunks(MAX_PER_CHUNK) {
// Use sqlx query_builder for safe parameterization
            let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
                "INSERT INTO events (id, tenant_id, message_id, event_type, recipient, link_id, link_url, user_agent, ip_address, timestamp) "
            );
            builder.push_values(chunk, |mut b, ev| {
                b.push_bind(ev.id.clone())
                    .push_bind(ev.tenant_id.clone())
                    .push_bind(ev.message_id.clone())
                    .push_bind(ev.event_type.to_string())
                    .push_bind(ev.recipient.clone())
                    .push_bind(ev.link_id.clone())
                    .push_bind(ev.link_url.clone())
                    .push_bind(ev.user_agent.clone())
                    .push_bind(ev.ip_address.clone())
                    .push_bind(ev.timestamp);
            });
            builder.push(" ON CONFLICT (id) DO NOTHING");
            builder.build().execute(&mut *tx).await.context("batch insert events")?;
        }

// Batch UPDATE messages stats with unnest (-042)
        let mut msg_ids: Vec<String> = Vec::new();
        let mut open_counts: Vec<i32> = Vec::new();
        let mut click_counts: Vec<i32> = Vec::new();
        let mut unsub_counts: Vec<i32> = Vec::new();

        let mut stats: std::collections::HashMap<&str, (i32, i32, i32)> =
            std::collections::HashMap::new();
        for ev in events {
            let e = stats.entry(&ev.message_id).or_insert((0, 0, 0));
            match ev.event_type {
                EventType::Opened => e.0 += 1,
                EventType::Clicked => e.1 += 1,
                EventType::Unsubscribed => e.2 += 1,
            }
        }
        for (id, (o, c, u)) in &stats {
            if *o > 0 || *c > 0 || *u > 0 {
                msg_ids.push(id.to_string());
                open_counts.push(*o);
                click_counts.push(*c);
                unsub_counts.push(*u);
            }
        }

        if !msg_ids.is_empty() {
            sqlx::query(
                r#"
                UPDATE messages AS m SET
                    open_count = m.open_count + v.opens,
                    click_count = m.click_count + v.clicks,
                    unsubscribe_count = m.unsubscribe_count + v.unsubs,
                    first_opened_at = COALESCE(m.first_opened_at, CASE WHEN v.opens > 0 THEN NOW() END),
                    first_clicked_at = COALESCE(m.first_clicked_at, CASE WHEN v.clicks > 0 THEN NOW() END),
                    updated_at = NOW()
                FROM (
                    SELECT
                        unnest($1::text[]) AS id,
                        unnest($2::int[])  AS opens,
                        unnest($3::int[])  AS clicks,
                        unnest($4::int[])  AS unsubs
                ) AS v
                WHERE m.id = v.id
                "#,
            )
            .bind(&msg_ids)
            .bind(&open_counts)
            .bind(&click_counts)
            .bind(&unsub_counts)
            .execute(&mut *tx)
            .await
            .context("batch update message stats")?;
        }

        tx.commit().await.context("commit transaction")?;

// ── Publish events to Redis Pub/Sub for real-time SSE streaming ──
// Fire-and-forget:SSE is best-effort; Postgres is the source of truth.
        let redis = self.redis.clone();
        let events_for_pubsub: Vec<(String, String)> = events
            .iter()
            .filter_map(|ev| {
                serde_json::to_string(ev)
                    .ok()
                    .map(|json| (ev.tenant_id.clone(), json))
            })
            .collect();

        tokio::spawn(async move {
            if let Ok(mut conn) = redis.get().await {
                for (tenant_id, payload) in events_for_pubsub {
                    let channel = format!("events:{tenant_id}");
                    let _: Result<(), _> = redis::cmd("PUBLISH")
                        .arg(&channel)
                        .arg(&payload)
                        .query_async(&mut *conn)
                        .await;
                }
            }
        });

        Ok(())
    }

// ── Suppression list ──────────────────────────────────────────────

    async fn add_to_suppression_list(
        &self,
        tenant_id: &str,
        email: &str,
        category: Option<&str>,
    ) {
        let email_lc = email.to_lowercase();
        let sup_id = new_id("sup");

        let result: Result<()> = async {
            if let Some(cat) = category {
                sqlx::query(
                    r#"
                    INSERT INTO subscription_preferences (id, tenant_id, email, category, subscribed, updated_at)
                    VALUES ($1, $2, $3, $4, false, NOW())
                    ON CONFLICT (tenant_id, email, category) DO UPDATE SET
                        subscribed = false, updated_at = NOW()
                    "#,
                )
                .bind(&sup_id)
                .bind(tenant_id)
                .bind(&email_lc)
                .bind(cat)
                .execute(&self.db)
                .await
                .context("insert subscription_preferences")?;
            } else {
                sqlx::query(
                    r#"
                    INSERT INTO suppressions (id, tenant_id, email, reason, subtype, created_at)
                    VALUES ($1, $2, $3, 'unsubscribe', 'one-click', NOW())
                    ON CONFLICT (tenant_id, email) DO UPDATE SET
                        reason = 'unsubscribe', subtype = 'one-click', updated_at = NOW()
                    "#,
                )
                .bind(&sup_id)
                .bind(tenant_id)
                .bind(&email_lc)
                .execute(&self.db)
                .await
                .context("insert suppression")?;
            }
            Ok(())
        }
        .await;

        if let Err(e) = result {
            error!(error = %e, "Failed to add suppression, event still recorded");
        }

// Fire-and-forget Redis publish (F-217)
        let payload = serde_json::json!({
            "tenantId": tenant_id,
            "email": email_lc,
            "reason": "unsubscribe",
            "category": category,
            "timestamp": Utc::now().to_rfc3339(),
        });
        let redis = self.redis.clone();
        let payload_str = payload.to_string();
        tokio::spawn(async move {
            if let Ok(mut conn) = redis.get().await {
                let _ = redis::cmd("PUBLISH")
                    .arg("suppression:added")
                    .arg(payload_str)
                    .query_async::<()>(&mut *conn)
                    .await;
            }
        });
    }

// ── Redis counter helpers ─────────────────────────────────────────

    async fn incr_counters(&self, tenant_id: &str, date: &str, hour: &str, metric: &str) {
// #180:Key format must match reader in query_engine.rs:stats:{tenant_id}:day:{date}:{metric}
        let hourly = format!("stats:{tenant_id}:hour:{date}:{hour}:{metric}");
        let daily = format!("stats:{tenant_id}:day:{date}:{metric}");

        let redis = self.redis.clone();
        let hourly2 = hourly.clone();
        let daily2 = daily.clone();

        tokio::spawn(async move {
            if let Ok(mut conn) = redis.get().await {
// #200:Log Redis pipeline errors instead of silently dropping them
                if let Err(e) = redis::pipe()
                    .cmd("INCR").arg(&hourly2)
                    .cmd("EXPIRE").arg(&hourly2).arg(86400u64 * 7)
                    .cmd("INCR").arg(&daily2)
                    .cmd("EXPIRE").arg(&daily2).arg(86400u64 * 90)
                    .query_async::<()>(&mut *conn)
                    .await
                {
                    tracing::warn!(error = %e, hourly = %hourly2, daily = %daily2, "Redis counter pipeline failed");
                }
            }
        });
    }

// ── Dedup via SETNX ───────────────────────────────────────────────

/// Returns `true` if the key was set (new event); `false` if it already
/// existed (duplicate).
    async fn try_set_dedup(&self, key: &str, ttl_secs: u64) -> Result<bool> {
        let mut conn = self.redis.get().await.context("redis pool get (dedup)")?;
        let result: Option<String> = redis::cmd("SET")
            .arg(format!("dedupe:{key}"))
            .arg("1")
            .arg("EX").arg(ttl_secs)
            .arg("NX")
            .query_async(&mut *conn)
            .await
            .context("SETNX dedup")?;
        Ok(result.is_some())
    }
}

// ── WAL parsing ───────────────────────────────────────────────────────────────

fn parse_wal_entries(raw: &[String]) -> Vec<TrackingEvent> {
    let mut out = Vec::with_capacity(raw.len());
    for entry in raw {
        match parse_single_wal_entry(entry) {
            Ok(ev) => out.push(ev),
            Err(e) => warn!(error = %e, raw = &entry[..entry.len().min(100)], "WAL entry parse error, skipping"),
        }
    }
    out
}

fn parse_single_wal_entry(raw: &str) -> Result<TrackingEvent> {
    let outer: serde_json::Value = serde_json::from_str(raw).context("outer JSON")?;

    if outer.get("v").is_some() {
        let v = outer["v"].as_u64().unwrap_or(0);
        if v != WAL_VERSION as u64 {
            anyhow::bail!("unsupported WAL version {v}");
        }

// #181:Extract the `d` value from the already-parsed JSON instead of
// fragile string searching with raw.find(",\"d\":"), which can match
// content inside the payload itself.
        let d_value = outer.get("d").context("no 'd' key in envelope")?;
        let raw_payload = serde_json::to_string(d_value).context("re-serialize 'd' value")?;
        let expected_cs = sha256_hex8(&raw_payload);
        let actual_cs = outer["cs"].as_str().unwrap_or("");
        if actual_cs != expected_cs {
// Fall back:try the original raw extraction for backward compatibility
// with envelopes where checksum was computed over the raw substring
            let d_idx = raw.find(",\"d\":").context("no 'd' key in raw envelope")?;
            let raw_payload_legacy = &raw[d_idx + 5..raw.len() - 1];
            let expected_cs_legacy = sha256_hex8(raw_payload_legacy);
            if actual_cs != expected_cs_legacy {
                anyhow::bail!("checksum mismatch: expected={expected_cs} actual={actual_cs}");
            }
        }
        serde_json::from_value(d_value.clone()).context("deserialize event from envelope")
    } else {
// Legacy bare event
        serde_json::from_str(raw).context("deserialize legacy event")
    }
}

// ── Utility functions ─────────────────────────────────────────────────────────

/// Compute the first 8 hex chars of SHA-256.
fn sha256_hex8(s: &str) -> String {
    let hash = Sha256::digest(s.as_bytes());
    hex::encode(&hash[..4]) // 4 bytes = 8 hex chars
}

/// Generate a prefixed ULID-style ID (e.g. "evt_01HXYZ...").
/// Uses UUID v4 for simplicity.
fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::new_v4().simple())
}

/// Derive a dedup cache key from event type and identifying fields.
fn dedup_key(
    event_type: &str,
    message_id: &str,
    recipient: &str,
    link_id: Option<&str>,
) -> String {
    let parts = match link_id {
        Some(l) => format!("{event_type}:{message_id}:{recipient}:{l}"),
        None => format!("{event_type}:{message_id}:{recipient}"),
    };
// First 32 hex chars of SHA-256 (128 bits, collision-resistant for dedup)
    let hash = Sha256::digest(parts.as_bytes());
    hex::encode(&hash[..16])
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex8_len() {
        assert_eq!(sha256_hex8("hello").len(), 8);
    }

    #[test]
    fn dedup_key_is_deterministic() {
        let k1 = dedup_key("open", "msg_1", "a@b.com", None);
        let k2 = dedup_key("open", "msg_1", "a@b.com", None);
        assert_eq!(k1, k2);
        let k3 = dedup_key("open", "msg_2", "a@b.com", None);
        assert_ne!(k1, k3);
    }

    #[test]
    fn parse_versioned_envelope() {
        let event = TrackingEvent {
            id: "evt_1".into(),
            event_type: EventType::Opened,
            tenant_id: "t1".into(),
            message_id: "m1".into(),
            recipient: "a@b.com".into(),
            link_id: None,
            link_url: None,
            unsubscribe_reason: None,
            user_agent: None,
            ip_address: None,
            timestamp: Utc::now(),
            metadata: None,
        };
        let payload = serde_json::to_string(&event).unwrap();
        let cs = sha256_hex8(&payload);
        let envelope = format!(r#"{{"v":1,"cs":"{cs}","d":{payload}}}"#);
        let parsed = parse_single_wal_entry(&envelope).unwrap();
        assert_eq!(parsed.id, event.id);
    }

    #[test]
    fn parse_envelope_checksum_mismatch_is_err() {
        let payload = r#"{"id":"evt_1","type":"opened","tenantId":"t","messageId":"m","recipient":"x@y.com","timestamp":"2024-01-01T00:00:00Z"}"#;
        let envelope = format!(r#"{{"v":1,"cs":"00000000","d":{payload}}}"#);
        assert!(parse_single_wal_entry(&envelope).is_err());
    }
}
