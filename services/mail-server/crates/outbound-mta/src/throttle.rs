//! Per-provider outbound throttle.
//!
//! This is the decision engine recovered from the retired
//! `outbound-queue::provider_throttle` (deleted in 755580c5) and wired back
//! into the two durable send boundaries that can actually transmit mail:
//!
//! * the recipient-facing relay ([`crate::relay::Relay`]), admission happens
//!   beside the warmup gate, before any SMTP connection is opened;
//! * the worker's SES transport (`worker-processors`), which returns a
//!   deferral error instead of consuming an attempt.
//!
//! # Semantics
//!
//! The effective throttle for a (sending identity, recipient provider,
//! tenant) is resolved in this order:
//!
//! 1. an ACTIVE operator row in `outbound_provider_throttle_overrides`
//!    (`expires_at IS NULL OR expires_at > NOW()`), tenant-specific before
//!    global, `throttle_pct` wins verbatim (0 = send all, 100 = block all);
//! 2. the latest `postmaster_reputation_summary` row written by the MTA's
//!    six-hourly postmaster scheduler, scored on the canonical 0–100 scale:
//!    `>= 70` green → 0 %, `40..=69` amber → 50 %, `< 40` red → 90 %
//!    (the thresholds `mta::postmaster::ReputationBand::from_score` has
//!    always used);
//! 3. no data → 0 % (`source = "default"`, matching the retired code).
//!
//! The decision is DETERMINISTIC per logical submission: a stable SHA-256 of
//! the send unit maps to `0..100`, and the submission defers when the roll
//! is below the effective percentage. The roll is stable WITHIN a five-minute
//! retry window (so a duplicated attempt gets one verdict) and re-rolls at
//! each window boundary, a persistent 50 % throttle therefore cannot starve
//! one submission forever (the retired implementation rolled randomly per
//! attempt; this keeps that liveness with cross-process determinism).
//! Deferral never consumes a permanent attempt.
//!
//! Lookups are cached for 60 seconds (the retired implementation's shape).
//! A READ FAILURE must not silently send: the last-known value for that key
//! is used when present, otherwise the key fails closed at 100 %. A WRITE
//! FAILURE (the best-effort audit row) is logged and never fails a send.
//!
//! # Audit
//!
//! One `outbound_throttle_decisions` row is written per ACTUAL deferral,
//! carrying the score, band, source, percentage and (migration 267) the
//! override id. Rows are buffered and inserted in bounded batches by one
//! background task; if the bounded queue is full the row is dropped and
//! counted ([`ProviderThrottle::audit_dropped`]) rather than blocking a send.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, QueryBuilder};
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Lookup cache TTL. The reputation scheduler refreshes every six hours, so a
/// one-minute cache is well inside the freshness budget; overrides take at
/// most this long to become effective.
pub const CACHE_TTL: Duration = Duration::from_secs(60);

/// Delay before a throttled durable submission is retried. Bounded (no
/// exponential growth) so a throttled unit is never escalated or expired; it
/// simply waits for the next poll after the window.
pub const THROTTLE_RETRY_DELAY: Duration = Duration::from_secs(5 * 60);

/// Fail-closed percentage used when the lookup store fails and no last-known
/// value exists for the key. 100 = block everything: a read failure must
/// never silently send.
pub const FAIL_CLOSED_PCT: u8 = 100;

/// Score at or above which the reputation band is green (0 % throttle).
pub const GREEN_MIN_SCORE: i32 = 70;
/// Score at or above which the reputation band is amber (50 % throttle).
pub const AMBER_MIN_SCORE: i32 = 40;
/// Throttle percentage for the green band.
pub const GREEN_THROTTLE_PCT: u8 = 0;
/// Throttle percentage for the amber band.
pub const AMBER_THROTTLE_PCT: u8 = 50;
/// Throttle percentage for the red band.
pub const RED_THROTTLE_PCT: u8 = 90;

/// Bound on buffered audit rows. A deferral burst beyond this drops audit
/// rows (observability must never block the send path) and counts them.
const AUDIT_QUEUE_CAPACITY: usize = 1024;
/// Rows per batched INSERT.
const AUDIT_BATCH_SIZE: usize = 64;
/// Maximum time an audit row waits before its batch is flushed.
const AUDIT_FLUSH_INTERVAL: Duration = Duration::from_millis(500);
/// Capacity/entry bound of the throttle caches (per sender/provider/tenant).
const CACHE_MAX_CAPACITY: u64 = 10_000;

/// Map a recipient domain, or a full `local@domain` address, to its
/// provider bucket. Returns `None` for everything else (treated as "no
/// provider throttle").
pub fn classify_provider(recipient_domain: &str) -> Option<&'static str> {
    let domain = recipient_domain
        .rsplit_once('@')
        .map(|(_, domain)| domain)
        .unwrap_or(recipient_domain);
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    match d.as_str() {
        "gmail.com" | "googlemail.com" => Some("google"),
        "outlook.com" | "hotmail.com" | "live.com" | "msn.com" | "outlook.office365.com" => {
            Some("microsoft")
        }
        "yahoo.com" | "yahoo.co.uk" | "ymail.com" | "rocketmail.com" => Some("yahoo"),
        "icloud.com" | "me.com" | "mac.com" => Some("apple"),
        "aol.com" => Some("aol"),
        _ => None,
    }
}

/// Extract the bare domain from an address (`local@domain`), lower-cased and
/// without a trailing dot. `None` for a null reverse path or an address
/// without a usable domain.
pub fn sender_domain(address: Option<&str>) -> Option<String> {
    let address = address?.trim();
    let (_, domain) = address.rsplit_once('@')?;
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

/// The canonical score → band mapping (the thresholds the MTA has always
/// used: green `>= 70`, amber `40..=69`, red `< 40`).
pub fn band_for_score(score: i32) -> &'static str {
    match score {
        score if score >= GREEN_MIN_SCORE => "green",
        score if score >= AMBER_MIN_SCORE => "amber",
        _ => "red",
    }
}

/// Throttle percentage for a reputation band. Unknown bands fail closed to
/// the red percentage.
pub fn throttle_pct_for_band(band: &str) -> u8 {
    match band {
        "green" => GREEN_THROTTLE_PCT,
        "amber" => AMBER_THROTTLE_PCT,
        _ => RED_THROTTLE_PCT,
    }
}

/// Stable 0–99 roll for a logical send unit. Deterministic across processes
/// and retries (SHA-256, first 8 bytes big-endian, modulo 100).
pub fn stable_roll(send_unit: &str) -> u8 {
    let digest = Sha256::digest(send_unit.as_bytes());
    let value = u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]);
    (value % 100) as u8
}

/// One resolved throttle state for a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThrottleSignal {
    /// Recipient provider bucket (`google`, `microsoft`, …).
    pub provider: String,
    /// Effective percentage: 0 send all, 100 block all.
    pub throttle_pct: u8,
    /// Reputation score when the signal came from a summary row.
    pub score: Option<i32>,
    /// Reputation band when the signal came from a summary row.
    pub band: Option<String>,
    /// `reputation`, `override` or `default`.
    pub source: &'static str,
    /// Operator override row id when `source = override` (migration 267).
    pub override_id: Option<String>,
}

impl ThrottleSignal {
    fn no_data(provider: &str) -> Self {
        Self {
            provider: provider.to_string(),
            throttle_pct: GREEN_THROTTLE_PCT,
            score: None,
            band: None,
            source: "default",
            override_id: None,
        }
    }

    fn fail_closed(provider: &str) -> Self {
        Self {
            provider: provider.to_string(),
            throttle_pct: FAIL_CLOSED_PCT,
            score: None,
            band: None,
            source: "default",
            override_id: None,
        }
    }
}

/// Outcome of a throttle decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThrottleDecision {
    /// Allow the send.
    Send,
    /// Defer without failing; the caller schedules a bounded retry.
    Defer { reason: String, throttle_pct: u8 },
}

/// Length of the deterministic roll window. Matches the deferral delay the
/// send boundaries apply, so each retry re-rolls.
pub const ROLL_WINDOW_SECS: u64 = 300;

fn current_roll_window() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() / ROLL_WINDOW_SECS)
        .unwrap_or(0)
}

/// Pure decision: stable per (send unit, roll window) and effective
/// percentage.
pub fn decide(send_unit: &str, signal: &ThrottleSignal) -> ThrottleDecision {
    decide_at(send_unit, signal, current_roll_window())
}

/// [`decide`] with an explicit roll window (unit tests pin the window).
pub fn decide_at(send_unit: &str, signal: &ThrottleSignal, window: u64) -> ThrottleDecision {
    if signal.throttle_pct == 0 {
        return ThrottleDecision::Send;
    }
    if signal.throttle_pct >= 100 {
        return ThrottleDecision::Defer {
            reason: format!(
                "{} throttle 100% (source={})",
                signal.provider, signal.source
            ),
            throttle_pct: signal.throttle_pct,
        };
    }
    let roll = stable_roll(&format!("{send_unit}:{window}"));
    if roll < signal.throttle_pct {
        ThrottleDecision::Defer {
            reason: format!(
                "{} throttle {}% (roll={}, band={}, score={}, source={})",
                signal.provider,
                signal.throttle_pct,
                roll,
                signal.band.as_deref().unwrap_or("unknown"),
                signal
                    .score
                    .map(|score| score.to_string())
                    .unwrap_or_else(|| "?".into()),
                signal.source,
            ),
            throttle_pct: signal.throttle_pct,
        }
    } else {
        ThrottleDecision::Send
    }
}

/// Cache key: sending identity (domain + optional source IP), recipient
/// provider and tenant scope.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ThrottleKey {
    sender_domain: Option<String>,
    sender_ip: Option<String>,
    provider: String,
    tenant_id: Option<String>,
}

/// One buffered audit row.
#[derive(Debug, Clone)]
struct AuditRow {
    tenant_id: Option<String>,
    sender_domain: Option<String>,
    recipient_domain: String,
    provider: String,
    throttle_pct: i32,
    source: &'static str,
    score: Option<i32>,
    band: Option<String>,
    override_id: Option<uuid::Uuid>,
}

enum AuditMessage {
    Row(AuditRow),
    #[cfg(test)]
    Flush(tokio::sync::oneshot::Sender<()>),
}

/// Per-process throttle engine. Cheap to clone; one instance should be
/// shared by each send boundary (relay or transport).
#[derive(Clone)]
pub struct ProviderThrottle {
    db: PgPool,
    cache: Cache<ThrottleKey, Arc<ThrottleSignal>>,
    /// Non-expiring last-known values, used to fail CLOSED to the previous
    /// verdict when a refresh read fails.
    last_known: Cache<ThrottleKey, Arc<ThrottleSignal>>,
    audit_tx: mpsc::Sender<AuditMessage>,
    audit_dropped: Arc<AtomicU64>,
}

impl ProviderThrottle {
    pub fn new(db: PgPool) -> Self {
        let (audit_tx, audit_rx) = mpsc::channel(AUDIT_QUEUE_CAPACITY);
        tokio::spawn(audit_writer(db.clone(), audit_rx));
        Self {
            db,
            cache: Cache::builder()
                .time_to_live(CACHE_TTL)
                .max_capacity(CACHE_MAX_CAPACITY)
                .build(),
            last_known: Cache::builder().max_capacity(CACHE_MAX_CAPACITY).build(),
            audit_tx,
            audit_dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Audit rows dropped because the bounded buffer was full/closed.
    pub fn audit_dropped(&self) -> u64 {
        self.audit_dropped.load(Ordering::Relaxed)
    }

    /// Decide whether this logical submission to `recipient_domain` should be
    /// deferred. Returns [`ThrottleDecision::Send`] for unclassified
    /// recipient domains (the retired implementation's behavior).
    pub async fn decide(
        &self,
        send_unit: &str,
        sender_domain: Option<&str>,
        recipient_domain: &str,
        tenant_id: Option<&str>,
        sender_ip: Option<IpAddr>,
    ) -> ThrottleDecision {
        let Some(provider) = classify_provider(recipient_domain) else {
            return ThrottleDecision::Send;
        };
        // Accept a full address at this boundary too; the audit row records
        // the recipient DOMAIN (the provider boundary), never the mailbox.
        let recipient_domain = recipient_domain
            .rsplit_once('@')
            .map(|(_, domain)| domain)
            .unwrap_or(recipient_domain)
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let signal = self
            .resolve(provider, sender_domain, tenant_id, sender_ip)
            .await;
        let decision = decide(send_unit, &signal);
        if let ThrottleDecision::Defer { .. } = &decision {
            debug!(
                send_unit,
                provider = %signal.provider,
                pct = signal.throttle_pct,
                source = signal.source,
                band = signal.band.as_deref().unwrap_or("unknown"),
                "outbound send deferred by provider throttle"
            );
            self.enqueue_audit(AuditRow {
                tenant_id: tenant_id.map(str::to_string),
                sender_domain: sender_domain.map(str::to_string),
                recipient_domain: recipient_domain.clone(),
                provider: signal.provider.clone(),
                throttle_pct: i32::from(signal.throttle_pct),
                source: signal.source,
                score: signal.score,
                band: signal.band.clone(),
                override_id: signal
                    .override_id
                    .as_deref()
                    .and_then(|id| uuid::Uuid::parse_str(id).ok()),
            });
        }
        decision
    }

    /// Resolve (and cache) the effective signal for one key. A database
    /// failure uses the last-known verdict, or 100 % if none exists.
    pub async fn resolve(
        &self,
        provider: &str,
        sender_domain: Option<&str>,
        tenant_id: Option<&str>,
        sender_ip: Option<IpAddr>,
    ) -> Arc<ThrottleSignal> {
        let key = ThrottleKey {
            sender_domain: sender_domain.map(str::to_string),
            sender_ip: sender_ip.map(|ip| ip.to_string()),
            provider: provider.to_string(),
            tenant_id: tenant_id.map(str::to_string),
        };
        match self.cache.try_get_with(key.clone(), self.fetch(&key)).await {
            Ok(signal) => {
                self.last_known.insert(key, signal.clone()).await;
                signal
            }
            Err(error) => {
                if let Some(signal) = self.last_known.get(&key).await {
                    warn!(
                        error = %error,
                        provider,
                        sender_domain = sender_domain.unwrap_or(""),
                        "provider_throttle: lookup failed; using last-known verdict"
                    );
                    return signal;
                }
                warn!(
                    error = %error,
                    provider,
                    sender_domain = sender_domain.unwrap_or(""),
                    "provider_throttle: lookup failed with no last-known verdict; failing closed at 100%"
                );
                Arc::new(ThrottleSignal::fail_closed(provider))
            }
        }
    }

    /// Fetch the effective override/reputation/default signal.
    async fn fetch(&self, key: &ThrottleKey) -> Result<Arc<ThrottleSignal>, sqlx::Error> {
        // 1. Operator override wins (tenant-specific before global).
        let override_row: Option<(String, i32)> = sqlx::query_as(
            "SELECT id::text, throttle_pct
             FROM outbound_provider_throttle_overrides
             WHERE provider = $1
               AND (tenant_id = $2 OR tenant_id IS NULL)
               AND (expires_at IS NULL OR expires_at > NOW())
             ORDER BY tenant_id NULLS LAST, updated_at DESC
             LIMIT 1",
        )
        .bind(&key.provider)
        .bind(key.tenant_id.as_deref())
        .fetch_optional(&self.db)
        .await?;
        if let Some((id, pct)) = override_row {
            debug!(
                provider = %key.provider,
                tenant_id = key.tenant_id.as_deref().unwrap_or(""),
                pct,
                "provider_throttle: operator override resolved"
            );
            return Ok(Arc::new(ThrottleSignal {
                provider: key.provider.clone(),
                throttle_pct: pct.clamp(0, 100) as u8,
                score: None,
                band: None,
                source: "override",
                override_id: Some(id),
            }));
        }

        // 2. Reputation-derived suggestion. Prefer the source-IP identity
        // (SNDS is IP-scoped); fall back to the sending domain (Google
        // Postmaster is domain-scoped).
        let mut reputation: Option<i32> = None;
        if let Some(ip) = key.sender_ip.as_deref() {
            reputation = sqlx::query_scalar::<_, i32>(
                "SELECT reputation_score
                 FROM postmaster_reputation_summary
                 WHERE provider = $1 AND scope = 'ip' AND identity = $2
                 ORDER BY computed_at DESC
                 LIMIT 1",
            )
            .bind(&key.provider)
            .bind(ip)
            .fetch_optional(&self.db)
            .await?;
        }
        if reputation.is_none() {
            if let Some(domain) = key.sender_domain.as_deref() {
                reputation = sqlx::query_scalar::<_, i32>(
                    "SELECT reputation_score
                     FROM postmaster_reputation_summary
                     WHERE provider = $1 AND scope = 'domain' AND identity = $2
                     ORDER BY computed_at DESC
                     LIMIT 1",
                )
                .bind(&key.provider)
                .bind(domain)
                .fetch_optional(&self.db)
                .await?;
            }
        }
        if let Some(score) = reputation {
            let band = band_for_score(score).to_string();
            debug!(
                provider = %key.provider,
                sender_domain = key.sender_domain.as_deref().unwrap_or(""),
                score,
                band = %band,
                "provider_throttle: reputation throttle resolved"
            );
            return Ok(Arc::new(ThrottleSignal {
                provider: key.provider.clone(),
                throttle_pct: throttle_pct_for_band(&band),
                score: Some(score),
                band: Some(band),
                source: "reputation",
                override_id: None,
            }));
        }

        // 3. No data → no throttle.
        Ok(Arc::new(ThrottleSignal::no_data(&key.provider)))
    }

    /// Best-effort enqueue of one audit row. Never blocks and never fails the
    /// send path.
    fn enqueue_audit(&self, row: AuditRow) {
        match self.audit_tx.try_send(AuditMessage::Row(row)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                let dropped = self.audit_dropped.fetch_add(1, Ordering::Relaxed) + 1;
                warn!(
                    dropped_total = dropped,
                    capacity = AUDIT_QUEUE_CAPACITY,
                    "throttle audit buffer full, decision not recorded (best-effort)"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                let dropped = self.audit_dropped.fetch_add(1, Ordering::Relaxed) + 1;
                warn!(
                    dropped_total = dropped,
                    "throttle audit writer stopped, decision not recorded (best-effort)"
                );
            }
        }
    }

    /// Test/ops hook: wait until every buffered audit row has been written.
    #[cfg(test)]
    async fn flush_audit(&self) {
        let (ack, wait) = tokio::sync::oneshot::channel();
        if self.audit_tx.send(AuditMessage::Flush(ack)).await.is_ok() {
            let _ = wait.await;
        }
    }
}

/// One background writer: bounded batches, failures only logged.
async fn audit_writer(db: PgPool, mut rx: mpsc::Receiver<AuditMessage>) {
    let mut buffer: Vec<AuditRow> = Vec::with_capacity(AUDIT_BATCH_SIZE);
    let mut flush_tick = tokio::time::interval(AUDIT_FLUSH_INTERVAL);
    flush_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    flush_tick.tick().await; // first tick completes immediately: skip it
    loop {
        tokio::select! {
            message = rx.recv() => match message {
                Some(AuditMessage::Row(row)) => {
                    buffer.push(row);
                    if buffer.len() >= AUDIT_BATCH_SIZE {
                        flush_audit_batch(&db, &mut buffer).await;
                    }
                }
                #[cfg(test)]
                Some(AuditMessage::Flush(ack)) => {
                    flush_audit_batch(&db, &mut buffer).await;
                    let _ = ack.send(());
                }
                None => {
                    flush_audit_batch(&db, &mut buffer).await;
                    break;
                }
            },
            _ = flush_tick.tick() => {
                if !buffer.is_empty() {
                    flush_audit_batch(&db, &mut buffer).await;
                }
            }
        }
    }
}

/// Insert one bounded batch. A failure is logged and the batch discarded —
/// audit is observability, never a send-path dependency.
async fn flush_audit_batch(db: &PgPool, buffer: &mut Vec<AuditRow>) {
    if buffer.is_empty() {
        return;
    }
    let rows = std::mem::take(buffer);
    let mut query = QueryBuilder::<Postgres>::new(
        "INSERT INTO outbound_throttle_decisions
           (tenant_id, sender_domain, recipient_domain, provider,
            throttle_pct, decision, source, score, band, override_id)
         ",
    );
    query.push_values(rows.iter(), |mut values, row| {
        values
            .push_bind(row.tenant_id.as_deref())
            .push_bind(row.sender_domain.as_deref())
            .push_bind(row.recipient_domain.as_str())
            .push_bind(row.provider.as_str())
            .push_bind(row.throttle_pct)
            .push_bind("deferred")
            .push_bind(row.source)
            .push_bind(row.score)
            .push_bind(row.band.as_deref())
            .push_bind(row.override_id);
    });
    if let Err(error) = query.build().execute(db).await {
        warn!(
            error = %error,
            rows = rows.len(),
            "throttle audit batch insert failed (best-effort; send unaffected)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_common_providers() {
        assert_eq!(classify_provider("gmail.com"), Some("google"));
        assert_eq!(classify_provider("googlemail.com"), Some("google"));
        assert_eq!(classify_provider("user@gmail.com"), Some("google"));
        assert_eq!(classify_provider("Outlook.com"), Some("microsoft"));
        assert_eq!(
            classify_provider("user@outlook.office365.com."),
            Some("microsoft")
        );
        assert_eq!(classify_provider("yahoo.co.uk"), Some("yahoo"));
        assert_eq!(classify_provider("icloud.com"), Some("apple"));
        assert_eq!(classify_provider("aol.com"), Some("aol"));
        assert_eq!(classify_provider("example.org"), None);
        assert_eq!(classify_provider(""), None);
    }

    #[test]
    fn band_thresholds_match_the_mta_bands() {
        assert_eq!(band_for_score(100), "green");
        assert_eq!(band_for_score(70), "green");
        assert_eq!(band_for_score(69), "amber");
        assert_eq!(band_for_score(40), "amber");
        assert_eq!(band_for_score(39), "red");
        assert_eq!(band_for_score(0), "red");
        assert_eq!(throttle_pct_for_band("green"), 0);
        assert_eq!(throttle_pct_for_band("amber"), 50);
        assert_eq!(throttle_pct_for_band("red"), 90);
        // Unknown bands fail closed to red.
        assert_eq!(throttle_pct_for_band("nonsense"), 90);
    }

    #[test]
    fn stable_roll_is_deterministic_and_bounded() {
        let first = stable_roll("email_queue:42:r@example.com");
        assert_eq!(first, stable_roll("email_queue:42:r@example.com"));
        assert!(first < 100);
        // Different logical submissions are not forced to the same roll.
        let distinct = (0..32)
            .map(|index| stable_roll(&format!("unit-{index}")))
            .collect::<std::collections::HashSet<_>>();
        assert!(distinct.len() > 1, "roll must vary across send units");
    }

    #[test]
    fn decide_zero_sends_and_one_hundred_defers() {
        let mut signal = ThrottleSignal::no_data("google");
        assert_eq!(decide("u", &signal), ThrottleDecision::Send);

        signal.throttle_pct = 100;
        assert!(matches!(
            decide("u", &signal),
            ThrottleDecision::Defer {
                throttle_pct: 100,
                ..
            }
        ));
    }

    #[test]
    fn decide_is_stable_for_intermediate_percentages() {
        let signal = ThrottleSignal {
            provider: "google".into(),
            throttle_pct: 50,
            score: Some(55),
            band: Some("amber".into()),
            source: "reputation",
            override_id: None,
        };
        let first = decide_at("email_queue:7:r@gmail.com", &signal, 7);
        for _ in 0..16 {
            assert_eq!(
                first,
                decide_at("email_queue:7:r@gmail.com", &signal, 7),
                "a retry inside the same roll window must get one verdict"
            );
        }
        // At 50 % at least one of a sample defers and at least one sends,
        // proving the percentage is actually applied.
        let verdicts = (0..64)
            .map(|i| decide_at(&format!("unit-{i}"), &signal, 7))
            .collect::<Vec<_>>();
        assert!(verdicts
            .iter()
            .any(|verdict| matches!(verdict, ThrottleDecision::Defer { .. })));
        assert!(verdicts
            .iter()
            .any(|verdict| matches!(verdict, ThrottleDecision::Send)));
    }

    /// A persistent 50 % throttle must not starve a submission: its roll
    /// re-rolls each window, so across windows both verdicts occur.
    #[test]
    fn persistent_throttle_rerolls_each_window_instead_of_starving() {
        let signal = ThrottleSignal {
            provider: "google".into(),
            throttle_pct: 50,
            score: Some(55),
            band: Some("amber".into()),
            source: "reputation",
            override_id: None,
        };
        let unit = "email_queue:7:r@gmail.com";
        let mut saw_defer = false;
        let mut saw_send = false;
        for window in 0..64u64 {
            match decide_at(unit, &signal, window) {
                ThrottleDecision::Defer { .. } => saw_defer = true,
                ThrottleDecision::Send => saw_send = true,
            }
            if saw_defer && saw_send {
                break;
            }
        }
        assert!(
            saw_defer && saw_send,
            "the roll must vary across windows (no permanent starvation)"
        );
    }

    #[test]
    fn sender_domain_extracts_and_normalizes() {
        assert_eq!(
            sender_domain(Some("Sender@Example.COM.")),
            Some("example.com".into())
        );
        assert_eq!(sender_domain(Some("")), None);
        assert_eq!(sender_domain(Some("no-at-sign")), None);
        assert_eq!(sender_domain(Some("a@")), None);
        assert_eq!(sender_domain(None), None);
    }

    #[test]
    fn fail_closed_signal_blocks_everything() {
        let signal = ThrottleSignal::fail_closed("google");
        assert_eq!(signal.throttle_pct, FAIL_CLOSED_PCT);
        assert_eq!(signal.source, "default");
        assert!(matches!(
            decide("any-unit", &signal),
            ThrottleDecision::Defer {
                throttle_pct: FAIL_CLOSED_PCT,
                ..
            }
        ));
    }

    // ── DB-backed arms (private per-test database, soft-skip when unset) ──

    use migrator::test_support::fresh_canonical_pool;

    async fn test_pool(name: &str) -> Option<PgPool> {
        match fresh_canonical_pool(name, name).await {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }

    async fn insert_override(
        pool: &PgPool,
        tenant: Option<&str>,
        provider: &str,
        pct: i32,
        expires_in: Option<&str>,
    ) -> String {
        sqlx::query_scalar::<_, String>(
            "INSERT INTO outbound_provider_throttle_overrides
               (tenant_id, provider, throttle_pct, reason, expires_at)
             VALUES ($1, $2, $3, 'test', $4::timestamptz)
             RETURNING id::text",
        )
        .bind(tenant)
        .bind(provider)
        .bind(pct)
        .bind(expires_in)
        .fetch_one(pool)
        .await
        .expect("insert override")
    }

    async fn insert_summary(
        pool: &PgPool,
        scope: &str,
        identity: &str,
        provider: &str,
        score: i32,
    ) {
        sqlx::query(
            "INSERT INTO postmaster_reputation_summary
               (scope, identity, provider, reputation_score, band,
                factors, suggested_throttle_pct, window_days, computed_at)
             VALUES ($1, $2, $3, $4, $5, '[]'::jsonb, $6, 7, NOW())",
        )
        .bind(scope)
        .bind(identity)
        .bind(provider)
        .bind(score)
        .bind(band_for_score(score))
        .bind(i32::from(throttle_pct_for_band(band_for_score(score))))
        .execute(pool)
        .await
        .expect("insert summary");
    }

    #[tokio::test]
    async fn operator_override_wins_over_reputation() {
        let Some(pool) = test_pool("throttle_override_wins").await else {
            return;
        };
        insert_summary(&pool, "domain", "sender.example", "google", 95).await;
        let override_id = insert_override(&pool, None, "google", 100, None).await;
        let throttle = ProviderThrottle::new(pool.clone());
        let signal = throttle
            .resolve("google", Some("sender.example"), None, None)
            .await;
        assert_eq!(signal.source, "override");
        assert_eq!(signal.throttle_pct, 100);
        assert_eq!(signal.override_id.as_deref(), Some(override_id.as_str()));
        assert!(matches!(
            throttle
                .decide("unit", Some("sender.example"), "r@gmail.com", None, None)
                .await,
            ThrottleDecision::Defer { .. }
        ));
    }

    #[tokio::test]
    async fn expired_override_is_ignored_and_reputation_applies() {
        let Some(pool) = test_pool("throttle_override_expired").await else {
            return;
        };
        insert_summary(&pool, "domain", "sender.example", "google", 50).await;
        insert_override(&pool, None, "google", 100, Some("epoch")).await;
        let throttle = ProviderThrottle::new(pool.clone());
        let signal = throttle
            .resolve("google", Some("sender.example"), None, None)
            .await;
        assert_eq!(signal.source, "reputation");
        assert_eq!(signal.throttle_pct, 50);
        assert_eq!(signal.band.as_deref(), Some("amber"));
        assert_eq!(signal.score, Some(50));
    }

    #[tokio::test]
    async fn reputation_band_mapping_uses_the_old_thresholds() {
        let Some(pool) = test_pool("throttle_band_mapping").await else {
            return;
        };
        for (domain, score, expected_pct) in [
            ("green.example", 70, 0),
            ("amber.example", 69, 50),
            ("amber-low.example", 40, 50),
            ("red.example", 39, 90),
        ] {
            insert_summary(&pool, "domain", domain, "google", score).await;
            let throttle = ProviderThrottle::new(pool.clone());
            let signal = throttle.resolve("google", Some(domain), None, None).await;
            assert_eq!(
                signal.throttle_pct, expected_pct,
                "score {score} must map to {expected_pct}%"
            );
            assert_eq!(signal.band.as_deref(), Some(band_for_score(score)));
        }
    }

    #[tokio::test]
    async fn ip_scope_is_preferred_over_domain_scope() {
        let Some(pool) = test_pool("throttle_ip_preferred").await else {
            return;
        };
        insert_summary(&pool, "domain", "sender.example", "google", 95).await;
        insert_summary(&pool, "ip", "203.0.113.9", "google", 10).await;
        let throttle = ProviderThrottle::new(pool.clone());
        let signal = throttle
            .resolve(
                "google",
                Some("sender.example"),
                None,
                Some("203.0.113.9".parse().expect("ip")),
            )
            .await;
        assert_eq!(signal.score, Some(10));
        assert_eq!(signal.throttle_pct, 90);
    }

    #[tokio::test]
    async fn no_data_sends_and_unknown_provider_sends() {
        let Some(pool) = test_pool("throttle_no_data").await else {
            return;
        };
        let throttle = ProviderThrottle::new(pool.clone());
        let signal = throttle
            .resolve("google", Some("unknown.example"), None, None)
            .await;
        assert_eq!(signal.source, "default");
        assert_eq!(signal.throttle_pct, 0);
        assert_eq!(
            throttle
                .decide("unit", Some("unknown.example"), "r@example.org", None, None)
                .await,
            ThrottleDecision::Send,
            "unclassified recipient domains are never throttled"
        );
    }

    #[tokio::test]
    async fn read_failure_without_last_known_fails_closed() {
        let Some(pool) = test_pool("throttle_fail_closed").await else {
            return;
        };
        let throttle = ProviderThrottle::new(pool.clone());
        pool.close().await;
        let signal = throttle
            .resolve("google", Some("sender.example"), None, None)
            .await;
        assert_eq!(signal.throttle_pct, FAIL_CLOSED_PCT);
        assert_eq!(signal.source, "default");
    }

    #[tokio::test]
    async fn read_failure_reuses_the_last_known_verdict() {
        let Some(pool) = test_pool("throttle_last_known").await else {
            return;
        };
        insert_summary(&pool, "domain", "sender.example", "google", 50).await;
        let throttle = ProviderThrottle::new(pool.clone());
        let first = throttle
            .resolve("google", Some("sender.example"), None, None)
            .await;
        assert_eq!(first.throttle_pct, 50);

        // Force the next call past the TTL cache but keep the last-known map.
        let key = ThrottleKey {
            sender_domain: Some("sender.example".into()),
            sender_ip: None,
            provider: "google".into(),
            tenant_id: None,
        };
        throttle.cache.invalidate(&key).await;
        pool.close().await;
        let after_failure = throttle
            .resolve("google", Some("sender.example"), None, None)
            .await;
        assert_eq!(after_failure.throttle_pct, 50);
        assert_eq!(after_failure.score, Some(50));
    }

    #[tokio::test]
    async fn deferral_writes_one_audit_row_with_score_band_and_override_id() {
        let Some(pool) = test_pool("throttle_audit_row").await else {
            return;
        };
        let override_id = insert_override(&pool, None, "google", 100, None).await;
        let throttle = ProviderThrottle::new(pool.clone());
        let decision = throttle
            .decide(
                "email_queue:9:r@gmail.com",
                Some("sender.example"),
                "r@gmail.com",
                Some("tenant-1"),
                None,
            )
            .await;
        assert!(matches!(decision, ThrottleDecision::Defer { .. }));
        throttle.flush_audit().await;

        let row: (Option<String>, String, String, i32, String, Option<String>) = sqlx::query_as(
            "SELECT tenant_id, sender_domain, recipient_domain, throttle_pct, source,
                    override_id::text
             FROM outbound_throttle_decisions",
        )
        .fetch_one(&pool)
        .await
        .expect("audit row");
        assert_eq!(row.0.as_deref(), Some("tenant-1"));
        assert_eq!(row.1, "sender.example");
        assert_eq!(row.2, "gmail.com");
        assert_eq!(row.3, 100);
        assert_eq!(row.4, "override");
        assert_eq!(row.5.as_deref(), Some(override_id.as_str()));
    }

    #[tokio::test]
    async fn allowed_sends_write_no_audit_rows() {
        let Some(pool) = test_pool("throttle_audit_send").await else {
            return;
        };
        let throttle = ProviderThrottle::new(pool.clone());
        for index in 0..8 {
            let decision = throttle
                .decide(
                    &format!("unit-{index}"),
                    Some("sender.example"),
                    "r@gmail.com",
                    None,
                    None,
                )
                .await;
            assert_eq!(decision, ThrottleDecision::Send);
        }
        throttle.flush_audit().await;
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM outbound_throttle_decisions")
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(count, 0, "no deferral, no audit row");
    }

    #[tokio::test]
    async fn audit_write_failure_never_fails_the_send() {
        let Some(pool) = test_pool("throttle_audit_failure").await else {
            return;
        };
        insert_override(&pool, None, "google", 100, None).await;
        let throttle = ProviderThrottle::new(pool.clone());
        sqlx::query("DROP TABLE outbound_throttle_decisions")
            .execute(&pool)
            .await
            .expect("drop decisions table");
        let decision = throttle
            .decide("unit", Some("sender.example"), "r@gmail.com", None, None)
            .await;
        assert!(matches!(decision, ThrottleDecision::Defer { .. }));
        throttle.flush_audit().await;
        // Reaching here without a panic (and with the deferral verdict) is
        // the contract: the audit insert failed and was logged.
    }

    #[tokio::test]
    async fn tenant_specific_override_wins_over_global() {
        let Some(pool) = test_pool("throttle_tenant_override").await else {
            return;
        };
        insert_override(&pool, None, "google", 100, None).await;
        insert_override(&pool, Some("tenant-1"), "google", 0, None).await;
        let throttle = ProviderThrottle::new(pool.clone());
        let signal = throttle
            .resolve("google", Some("sender.example"), Some("tenant-1"), None)
            .await;
        assert_eq!(signal.throttle_pct, 0);
        let other = throttle
            .resolve("google", Some("sender.example"), Some("tenant-2"), None)
            .await;
        assert_eq!(other.throttle_pct, 100);
    }
}
