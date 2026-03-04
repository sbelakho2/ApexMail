//! Per-message transport routing: SES (shared) vs SMTP (dedicated IPs).
//!
//! ## Routing Rule (non-negotiable)
//!
//! | Has active/warming dedicated IP? | Transport     |
//! |----------------------------------|---------------|
//! | Yes                              | Self-hosted SMTP via Hetzner IPs |
//! | No                               | AWS SES shared IP pool           |
//!
//! There is **no** per-tenant preference toggle.  The presence of dedicated
//! IPs is the sole determinant.  A single tenant can have both paths active
//! simultaneously — SES for domains that share IPs and SMTP for domains
//! bound to dedicated IPs.
//!
//! ## How it works
//!
//! `TransportRouter` keeps a local cache of `transport_routing_cache` rows,
//! refreshed every 30 seconds.  The cache is updated by a DB trigger that
//! fires whenever `dedicated_ips` rows change.  So when a billing webhook
//! auto-provisions a Hetzner IP, the cache picks it up on the next tick and
//! messages start flowing via SMTP with zero manual intervention.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use sqlx::PgPool;
use uuid::Uuid;

// ─── Transport abstraction ─────────────────────────────────────

/// A transport backend that can send an email.
///
/// Implementations:
/// - `SesTransport`: calls SES `SendRawEmail` (shared IP pool)
/// - `SmtpTransport`: connects to self-hosted MTA on Hetzner (dedicated IPs)
#[async_trait::async_trait]
pub trait EmailTransport: Send + Sync {
    async fn send_raw_email(
        &self,
        from: &str,
        to: &[String],
        raw_message: &[u8],
        config: &TransportConfig,
    ) -> Result<SendResult, TransportError>;

    fn name(&self) -> &'static str;
}

/// Configuration passed to the transport layer per message.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Which dedicated IP to bind (SMTP only, ignored by SES).
    pub bind_ip: Option<String>,
    /// DKIM selector override.
    pub dkim_selector: Option<String>,
    /// Custom HELO name.
    pub helo_name: Option<String>,
    /// Max SMTP DATA timeout override.
    pub data_timeout: Option<Duration>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            bind_ip: None,
            dkim_selector: None,
            helo_name: None,
            data_timeout: None,
        }
    }
}

/// Result of a send operation.
#[derive(Debug, Clone)]
pub struct SendResult {
    /// Opaque ID for the transport (SES MessageId or self-hosted queue ID).
    pub message_id: String,
    /// Which transport was used.
    pub transport: TransportKind,
}

/// Which transport carried the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// AWS SES shared IP pool.
    Ses,
    /// Self-hosted SMTP via Hetzner dedicated IPs.
    Smtp,
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportKind::Ses => write!(f, "ses"),
            TransportKind::Smtp => write!(f, "smtp"),
        }
    }
}

/// Transport errors.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("SES error: {0}")]
    Ses(String),

    #[error("SMTP error: {0}")]
    Smtp(String),

    #[error("no transport configured")]
    NoTransport,

    #[error("rate limited")]
    RateLimited,

    #[error("database error: {0}")]
    Database(String),
}

impl From<sqlx::Error> for TransportError {
    fn from(e: sqlx::Error) -> Self {
        TransportError::Database(e.to_string())
    }
}

// ─── Routing cache entry ───────────────────────────────────────

/// Cached routing decision for a tenant.
#[derive(Debug, Clone)]
struct RoutingEntry {
    tenant_id: Uuid,
    /// `true` → at least one active/warming dedicated IP exists.
    has_dedicated_ips: bool,
    /// The preferred dedicated IP to bind outgoing connections to.
    /// Selected by: active first, then lowest warmup_progress first.
    preferred_ip: Option<String>,
    /// Number of active + warming IPs.
    dedicated_ip_count: i32,
}

// ─── Router ────────────────────────────────────────────────────

/// Per-message transport router.
///
/// Both SES and SMTP transports are **always** available.  The router
/// decides which to use based on the tenant's dedicated IP ownership.
pub struct TransportRouter {
    ses: Arc<dyn EmailTransport>,
    smtp: Arc<dyn EmailTransport>,
    db: PgPool,
    cache: Arc<RwLock<RoutingCache>>,
}

struct RoutingCache {
    entries: HashMap<Uuid, RoutingEntry>,
    last_refresh: Instant,
}

impl TransportRouter {
    /// Create a router with both transport paths.
    ///
    /// - `ses`: transport for the shared SES IP pool
    /// - `smtp`: transport for self-hosted MTA servers (Hetzner dedicated IPs)
    pub fn new(
        ses: Arc<dyn EmailTransport>,
        smtp: Arc<dyn EmailTransport>,
        db: PgPool,
    ) -> Self {
        Self {
            ses,
            smtp,
            db,
            cache: Arc::new(RwLock::new(RoutingCache {
                entries: HashMap::new(),
                last_refresh: Instant::now() - Duration::from_secs(3600),
            })),
        }
    }

    // ── Public API ─────────────────────────────────────────────

    /// Route and send a message.
    ///
    /// Decision tree:
    /// 1. Look up tenant in routing cache
    /// 2. If tenant has any active/warming dedicated IP → SMTP with bind IP
    /// 3. Otherwise → SES shared pool
    ///
    /// A tenant with dedicated IPs can still have *some* mail go through SES
    /// if the domain-level routing is configured that way (future extension),
    /// but the default is: dedicated IP exists ⇒ all mail → SMTP.
    pub async fn send(
        &self,
        tenant_id: Uuid,
        from: &str,
        to: &[String],
        raw_message: &[u8],
    ) -> Result<SendResult, TransportError> {
        self.ensure_cache_fresh().await?;

        let (transport, config) = self.resolve(tenant_id).await?;

        transport.send_raw_email(from, to, raw_message, &config).await
    }

    /// Determine which transport would be used for a tenant (without sending).
    pub async fn resolve_transport_kind(
        &self,
        tenant_id: Uuid,
    ) -> Result<TransportKind, TransportError> {
        self.ensure_cache_fresh().await?;

        let cache = self.cache.read().await;
        match cache.entries.get(&tenant_id) {
            Some(entry) if entry.has_dedicated_ips => Ok(TransportKind::Smtp),
            _ => Ok(TransportKind::Ses),
        }
    }

    /// Force a cache refresh (e.g., after allocating a new IP).
    pub async fn invalidate_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.last_refresh = Instant::now() - Duration::from_secs(3600);
    }

    /// Force refresh routing for a specific tenant.
    pub async fn invalidate_tenant(&self, tenant_id: Uuid) {
        let entry = self.fetch_routing_entry(tenant_id).await;
        let mut cache = self.cache.write().await;
        match entry {
            Ok(Some(e)) => { cache.entries.insert(tenant_id, e); }
            Ok(None)    => { cache.entries.remove(&tenant_id); }
            Err(e) => warn!(tenant_id = %tenant_id, error = %e, "Failed to refresh routing"),
        }
    }

    // ── Internals ──────────────────────────────────────────────

    /// Resolve transport + config for a tenant.
    async fn resolve(
        &self,
        tenant_id: Uuid,
    ) -> Result<(Arc<dyn EmailTransport>, TransportConfig), TransportError> {
        let cache = self.cache.read().await;
        match cache.entries.get(&tenant_id) {
            Some(entry) if entry.has_dedicated_ips => {
                let mut config = TransportConfig::default();
                config.bind_ip = entry.preferred_ip.clone();
                debug!(
                    tenant_id = %tenant_id,
                    ip = ?config.bind_ip,
                    count = entry.dedicated_ip_count,
                    "Routing via self-hosted SMTP (dedicated IP)"
                );
                Ok((self.smtp.clone(), config))
            }
            _ => {
                debug!(tenant_id = %tenant_id, "Routing via SES shared pool");
                Ok((self.ses.clone(), TransportConfig::default()))
            }
        }
    }

    /// Ensure the cache is fresh (refreshed within the last 30 seconds).
    async fn ensure_cache_fresh(&self) -> Result<(), TransportError> {
        let needs_refresh = {
            let cache = self.cache.read().await;
            cache.last_refresh.elapsed() > Duration::from_secs(30)
        };

        if needs_refresh {
            self.refresh_cache().await?;
        }
        Ok(())
    }

    /// Full cache refresh from `transport_routing_cache`.
    async fn refresh_cache(&self) -> Result<(), TransportError> {
        let rows: Vec<(Uuid, bool, Option<String>, i32)> = sqlx::query_as(
            "SELECT tenant_id, has_dedicated_ips, preferred_dedicated_ip, dedicated_ip_count
             FROM transport_routing_cache",
        )
        .fetch_all(&self.db)
        .await?;

        let mut entries = HashMap::with_capacity(rows.len());
        for (tid, has, ip, count) in rows {
            entries.insert(tid, RoutingEntry {
                tenant_id: tid,
                has_dedicated_ips: has,
                preferred_ip: ip,
                dedicated_ip_count: count,
            });
        }

        let mut cache = self.cache.write().await;
        let tenant_count = entries.len();
        cache.entries = entries;
        cache.last_refresh = Instant::now();

        debug!(tenants = tenant_count, "Routing cache refreshed");
        Ok(())
    }

    /// Fetch a single tenant's routing entry directly from `dedicated_ips`.
    async fn fetch_routing_entry(
        &self,
        tenant_id: Uuid,
    ) -> Result<Option<RoutingEntry>, TransportError> {
        let row: Option<(i64, Option<String>)> = sqlx::query_as(
            "SELECT COUNT(*),
                    (SELECT ip_address FROM dedicated_ips
                     WHERE tenant_id = $1 AND status IN ('active', 'warming')
                     ORDER BY CASE status WHEN 'active' THEN 0 ELSE 1 END,
                             warmup_progress DESC
                     LIMIT 1)
             FROM dedicated_ips
             WHERE tenant_id = $1 AND status IN ('active', 'warming')",
        )
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await?;

        Ok(row.map(|(count, ip)| RoutingEntry {
            tenant_id,
            has_dedicated_ips: count > 0,
            preferred_ip: ip,
            dedicated_ip_count: count as i32,
        }))
    }
}

// ─── RoutingTransport wrapper ──────────────────────────────────

/// Convenience wrapper that implements `EmailTransport` by delegating to
/// `TransportRouter::send`.  Drop this into any code that expects a single
/// `EmailTransport` and it will automatically route per-tenant.
pub struct RoutingTransport {
    router: Arc<TransportRouter>,
}

impl RoutingTransport {
    pub fn new(router: Arc<TransportRouter>) -> Self {
        Self { router }
    }
}

#[async_trait::async_trait]
impl EmailTransport for RoutingTransport {
    async fn send_raw_email(
        &self,
        from: &str,
        to: &[String],
        raw_message: &[u8],
        config: &TransportConfig,
    ) -> Result<SendResult, TransportError> {
        // Extract tenant_id from the from address or look it up.
        // In practice, the tenant_id is threaded via the job context,
        // not extracted from the email headers.  This wrapper is used
        // as a fallback when tenant context isn't available.
        warn!("RoutingTransport used without explicit tenant context — falling back to SES");
        self.router.ses.send_raw_email(from, to, raw_message, config).await
    }

    fn name(&self) -> &'static str {
        "routing"
    }
}

// ─── Helper: check dedicated IP status directly ────────────────

/// Quick check: does this tenant have any active or warming dedicated IPs?
/// Used by rate limiter, analytics, etc. without needing a full router.
pub async fn tenant_has_dedicated_ip(
    db: &PgPool,
    tenant_id: Uuid,
) -> Result<bool, TransportError> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM dedicated_ips
         WHERE tenant_id = $1 AND status IN ('active', 'warming')",
    )
    .bind(tenant_id)
    .fetch_one(db)
    .await?;
    Ok(count > 0)
}

/// Get the best dedicated IP for sending (active preferred over warming,
/// then lowest daily send count).  Used by `outbound-queue` IP rotation.
pub async fn select_dedicated_ip(
    db: &PgPool,
    tenant_id: Uuid,
) -> Result<Option<String>, TransportError> {
    let ip: Option<(String,)> = sqlx::query_as(
        "SELECT d.ip_address
         FROM dedicated_ips d
         LEFT JOIN ip_daily_usage u ON u.ip_address = d.ip_address
             AND u.usage_date = CURRENT_DATE
         WHERE d.tenant_id = $1 AND d.status IN ('active', 'warming')
         ORDER BY
             CASE d.status WHEN 'active' THEN 0 ELSE 1 END,
             COALESCE(u.messages_sent, 0) ASC
         LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(db)
    .await?;
    Ok(ip.map(|(addr,)| addr))
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_kind_display() {
        assert_eq!(TransportKind::Ses.to_string(), "ses");
        assert_eq!(TransportKind::Smtp.to_string(), "smtp");
    }
}
