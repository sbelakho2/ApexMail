//! Unified send admission — the ONE gate in front of every outbound send
//! path.
//!
//! Audit finding P0 (findings-2026-09-10): authenticated SMTP submission on
//! port 587 enqueued mail through `email_queue` without touching the billing
//! admission path, so a customer could send through SMTP without consuming
//! the same `EmailsSent` plan quota as `POST /v1/messages`. This module is
//! the extraction of the REST admission logic into a single service both
//! paths call:
//!
//! 1. **category** — validated/normalized through the ONE shared helper
//!    (`apexmail_lib::email_headers::message_category::validate`, audit F55)
//!    and returned explicitly. A send whose authenticated, server-owned input
//!    carries no category gets the documented policy default
//!    ([`DEFAULT_MESSAGE_CATEGORY`]) — never the
//!    `email_queue.message_category` schema default (finding P1).
//! 2. **suppression** — the tenant suppression list, through THE canonical
//!    query ([`suppressed_recipients_in_db`]) shared with the REST validation
//!    path; the SMTP caller lets admission drop suppressed recipients before
//!    queueing, the REST caller validates them up front.
//! 3. **entitlement + quota** — the plan gate and the `EmailsSent`
//!    reservation through the canonical
//!    [`crate::usage::record_with_quota_check`], keyed by the deterministic
//!    usage event id derived from the caller's idempotency identity
//!    ([`usage_event_id`]): a duplicate send on either path records the SAME
//!    metering event and can only ever reserve once.
//! 4. **settlement** — the returned [`SendAdmission`] handle is
//!    [`SendAdmission::commit`]ed after a successful enqueue and
//!    [`SendAdmission::rollback`]ed when the queue write fails, so a failed
//!    enqueue never consumes quota. A duplicate reservation owns no metering
//!    state and is never compensated (F22).
//!
//! ## Dependency direction
//!
//! The service lives in `billing-service` because the canonical metering
//! primitives (`record_with_quota_check` / `rollback_usage_record`) do, and
//! because `billing-service` already depends on `apexmail-lib` for the
//! category helper. `api-server` already depends on `billing-service`; the
//! `mta` crate (owner of the SMTP submission server) adds the same
//! dependency. `billing-service` depends on neither caller — no cycle.
//!
//! ## Category policy (P1)
//!
//! The REST path's category is a validated request field; the SMTP path has
//! no client category at all. The SMTP policy is therefore: the category
//! comes exclusively from server-owned, authenticated state (today the
//! submission policy default; once the minimal credential attribute
//! `message_category` exists on the SMTP credential record, that attribute)
//! and is passed through this service, which validates it with the SAME
//! helper REST uses and hands the normalized value back for the queue insert.
//! It is never read from the message headers, the envelope, or the body.

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use deadpool_redis::Pool as RedisPool;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use apexmail_lib::email_headers::message_category;

use crate::types::MeterEventType;
use crate::usage::{self, QuotaRecordResult, UsageError};

/// The metering dimension every outbound send path consumes.
pub const SEND_METER_EVENT: MeterEventType = MeterEventType::EmailsSent;

/// Documented category policy outcome for a send whose authenticated,
/// server-owned input carries no category.
///
/// `marketing` is deliberately the NON-preference-exempt category
/// (`message_category::PREFERENCE_EXEMPT` contains only `transactional` and
/// `service`): a missing attribute must never silently grant an opt-out
/// exemption. The value is returned EXPLICITLY and written into
/// `email_queue.message_category` by the caller — the schema default never
/// decides.
pub const DEFAULT_MESSAGE_CATEGORY: &str = message_category::MARKETING;

/// Canonicalize one recipient exactly like the REST send path
/// (`api_server::routes::messages::canonical_email`): trim + ASCII
/// lowercase.
pub fn canonical_recipient(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

/// Validate and normalize a server-owned category input through the ONE
/// shared helper (`apexmail_lib::email_headers::message_category::validate`).
///
/// `None` selects the documented policy default and returns it as an
/// explicit value — a caller can never end up with an empty category that
/// the `email_queue.message_category` schema default would silently fill in.
pub fn normalize_category(raw: Option<&str>) -> Result<String, SendAdmissionError> {
    match raw {
        Some(raw) => {
            message_category::validate(raw).ok_or_else(|| SendAdmissionError::InvalidCategory {
                raw: raw.to_string(),
            })
        }
        None => Ok(DEFAULT_MESSAGE_CATEGORY.to_string()),
    }
}

/// Stable logical usage ID for a send's quota reservation (F22, moved here
/// from the REST route so both paths derive the identity identically).
///
/// With an idempotency key the id is derived deterministically from
/// (tenant, key[, batch item index]), so concurrent duplicate sends — or a
/// retry whose Redis accelerator state was lost — record the SAME metering
/// event. `record_with_quota_check` de-duplicates on the event id and
/// reports `duplicate: true`, making a double reservation impossible.
/// Without a key the reservation keeps a random id (no replay identity to
/// bind to). UUID v5 is not compiled into the workspace `uuid` features;
/// the first 16 SHA-256 bytes of the namespace string serve the same purpose
/// (deterministic, collision-free in practice).
pub fn usage_event_id(tenant_id: &str, idempotency_key: Option<&str>, item: Option<usize>) -> Uuid {
    match idempotency_key {
        Some(key) => {
            let namespace = match item {
                Some(index) => format!("apexmail:usage:{tenant_id}:batch:{key}:{index}"),
                None => format!("apexmail:usage:{tenant_id}:send:{key}"),
            };
            let digest = Sha256::digest(namespace.as_bytes());
            Uuid::from_slice(&digest[..16])
                .expect("the first 16 SHA-256 bytes are always a valid UUID")
        }
        None => Uuid::new_v4(),
    }
}

/// THE canonical tenant suppression lookup: `tenant_id` plus canonical
/// (lowercased) recipient addresses in, suppressed canonical addresses out.
///
/// Shared by the REST validation path (`validate_send`) and the SMTP
/// admission backend, so the two send paths can never drift on the SQL,
/// the canonicalization, or the scoping.
pub async fn suppressed_recipients_in_db(
    db: &PgPool,
    tenant_id: &str,
    canonical_recipients: &[String],
) -> Result<Vec<String>, sqlx::Error> {
    if canonical_recipients.is_empty() {
        return Ok(Vec::new());
    }

    let mut suppressed: Vec<String> = sqlx::query_scalar(
        "SELECT LOWER(email) FROM suppressions WHERE tenant_id = $1 AND LOWER(email) = ANY($2)",
    )
    .bind(tenant_id)
    .bind(canonical_recipients)
    .fetch_all(db)
    .await?;

    suppressed.sort();
    suppressed.dedup();
    Ok(suppressed)
}

/// Why a send was refused admission, or why a settlement failed.
#[derive(Debug, thiserror::Error)]
pub enum SendAdmissionError {
    /// The server-owned category input failed validation. Carries the raw
    /// value so each caller can render its own contract message.
    #[error("invalid message category '{raw}'")]
    InvalidCategory { raw: String },

    /// EVERY recipient is on the tenant suppression list — the send is
    /// refused rather than queued with an empty recipient set.
    #[error("all recipients are suppressed")]
    Suppressed(Vec<String>),

    /// The plan's included volume and its overage allowance are exhausted
    /// (entitlement refusal).
    #[error("email quota exceeded")]
    QuotaExceeded,

    /// The canonical metering layer (Redis/Postgres) is unavailable — the
    /// send must be refused, never admitted unmetered.
    #[error("billing quota enforcement unavailable: {0}")]
    MeteringUnavailable(#[source] UsageError),

    /// The suppression lookup failed — fail closed, never admit unmetered
    /// or unscreened.
    #[error("suppression lookup unavailable: {0}")]
    SuppressionUnavailable(String),
}

/// The metering layer this service orchestrates.
///
/// The production implementation delegates to the canonical
/// [`crate::usage`] functions; tests substitute an in-memory backend so the
/// cross-path quota/rollback/idempotency contract is exercised without a
/// live Postgres/Redis.
#[async_trait]
pub trait SendAdmissionBackend: Send + Sync + 'static {
    /// Atomically check the quota and reserve `quantity` units for the
    /// deterministic `event_id` (canonical
    /// [`crate::usage::record_with_quota_check`]).
    async fn record_send_usage(
        &self,
        tenant_id: &str,
        quantity: i64,
        event_id: Uuid,
    ) -> Result<QuotaRecordResult, UsageError>;

    /// Release a reservation previously made by
    /// [`SendAdmissionBackend::record_send_usage`] (canonical
    /// [`crate::usage::rollback_usage_record`]).
    async fn rollback_send_usage(
        &self,
        tenant_id: &str,
        quantity: i64,
        event_id: Uuid,
        recorded_at: DateTime<Utc>,
    ) -> Result<(), UsageError>;

    /// Return the canonical addresses on `tenant_id`'s suppression list.
    async fn suppressed_recipients(
        &self,
        tenant_id: &str,
        canonical_recipients: &[String],
    ) -> Result<Vec<String>, String>;
}

/// Production backend over the canonical billing storage.
#[derive(Clone)]
pub struct PostgresAdmissionBackend {
    db: PgPool,
    redis: RedisPool,
}

impl PostgresAdmissionBackend {
    pub fn new(db: PgPool, redis: RedisPool) -> Self {
        Self { db, redis }
    }
}

#[async_trait]
impl SendAdmissionBackend for PostgresAdmissionBackend {
    async fn record_send_usage(
        &self,
        tenant_id: &str,
        quantity: i64,
        event_id: Uuid,
    ) -> Result<QuotaRecordResult, UsageError> {
        usage::record_with_quota_check(
            &self.db,
            &self.redis,
            tenant_id,
            SEND_METER_EVENT,
            quantity,
            Some(event_id),
            None,
        )
        .await
    }

    async fn rollback_send_usage(
        &self,
        tenant_id: &str,
        quantity: i64,
        event_id: Uuid,
        recorded_at: DateTime<Utc>,
    ) -> Result<(), UsageError> {
        usage::rollback_usage_record(
            &self.db,
            &self.redis,
            tenant_id,
            SEND_METER_EVENT,
            quantity,
            event_id,
            recorded_at,
        )
        .await
    }

    async fn suppressed_recipients(
        &self,
        tenant_id: &str,
        canonical_recipients: &[String],
    ) -> Result<Vec<String>, String> {
        suppressed_recipients_in_db(&self.db, tenant_id, canonical_recipients)
            .await
            .map_err(|error| error.to_string())
    }
}

/// How the metered quantity is determined.
#[derive(Debug)]
pub enum AdmissionMeter<'a> {
    /// Meter a fixed, already-validated quantity — the REST path's delivery
    /// recipient count (to + cc + bcc; each becomes one queue row).
    Quantity(i64),
    /// Check the tenant suppression list for these envelope recipients and
    /// meter the ALLOWED count (each allowed recipient becomes one queue row
    /// on the SMTP path). Refused with [`SendAdmissionError::Suppressed`]
    /// when every recipient is suppressed.
    FilteredRecipients(&'a [String]),
}

/// One send's admission request.
#[derive(Debug)]
pub struct SendAdmissionRequest<'a> {
    pub tenant_id: &'a str,
    pub meter: AdmissionMeter<'a>,
    /// The path's idempotency identity (HTTP `Idempotency-Key`, batch key +
    /// item index, or the SMTP message identity). `None` keeps a random
    /// usage event id.
    pub idempotency_key: Option<&'a str>,
    /// Batch item index for the shared batch idempotency key.
    pub idempotency_item: Option<usize>,
    /// Authenticated, server-owned category input. `None` applies the
    /// documented policy default — it never falls through to the schema
    /// default.
    pub category: Option<&'a str>,
}

/// A successful admission: the quota is reserved, the category is validated
/// and normalized, and (for [`AdmissionMeter::FilteredRecipients`]) the
/// allowed recipients are known.
///
/// Commit it after the enqueue succeeds, or roll it back when the queue
/// write fails.
pub struct SendAdmission {
    backend: Arc<dyn SendAdmissionBackend>,
    tenant_id: String,
    event_id: Uuid,
    recorded_at: DateTime<Utc>,
    quantity: i64,
    duplicate: bool,
    category: String,
    allowed_recipients: Vec<String>,
    suppressed_recipients: Vec<String>,
}

impl fmt::Debug for SendAdmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendAdmission")
            .field("tenant_id", &self.tenant_id)
            .field("event_id", &self.event_id)
            .field("quantity", &self.quantity)
            .field("duplicate", &self.duplicate)
            .field("category", &self.category)
            .field("allowed_recipients", &self.allowed_recipients)
            .field("suppressed_recipients", &self.suppressed_recipients)
            .finish_non_exhaustive()
    }
}

impl SendAdmission {
    /// The validated, normalized category to write into
    /// `messages.message_category` / `email_queue.message_category`. Always
    /// explicit — never empty, never decided by the schema default.
    pub fn category(&self) -> &str {
        &self.category
    }

    /// The recipients that survived the suppression check (empty when the
    /// caller metered a fixed quantity and did its own suppression gate).
    pub fn allowed_recipients(&self) -> &[String] {
        &self.allowed_recipients
    }

    /// The recipients dropped by the suppression check.
    pub fn suppressed_recipients(&self) -> &[String] {
        &self.suppressed_recipients
    }

    /// True when the billing layer recognized the usage event id as already
    /// recorded: this admission reserved NOTHING and must not be
    /// compensated (the concurrent winner owns the event — F22).
    pub fn duplicate(&self) -> bool {
        self.duplicate
    }

    pub fn event_id(&self) -> Uuid {
        self.event_id
    }

    pub fn quantity(&self) -> i64 {
        self.quantity
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// The enqueue succeeded: the reservation stands, nothing to undo.
    /// Consuming the handle makes the settlement explicit at every call
    /// site.
    pub fn commit(self) {
        tracing::debug!(
            tenant_id = %self.tenant_id,
            event_id = %self.event_id,
            quantity = self.quantity,
            duplicate = self.duplicate,
            "send admission committed after successful enqueue"
        );
    }

    /// The enqueue failed: release the reserved quota. Idempotent by event
    /// id, and a no-op for a duplicate reservation (which owns no metering
    /// state).
    pub async fn rollback(&self) -> Result<(), SendAdmissionError> {
        if self.duplicate {
            tracing::debug!(
                tenant_id = %self.tenant_id,
                event_id = %self.event_id,
                "skipping quota rollback for duplicate billing event (F22)"
            );
            return Ok(());
        }

        self.backend
            .rollback_send_usage(
                &self.tenant_id,
                self.quantity,
                self.event_id,
                self.recorded_at,
            )
            .await
            .map_err(SendAdmissionError::MeteringUnavailable)
    }
}

/// The shared admission service. Construct once per process (or cheaply per
/// request via `Arc`-backed clone) and call from every send path.
#[derive(Clone)]
pub struct SendAdmissionService {
    backend: Arc<dyn SendAdmissionBackend>,
}

impl SendAdmissionService {
    pub fn new(backend: Arc<dyn SendAdmissionBackend>) -> Self {
        Self { backend }
    }

    /// Canonical suppression lookup (see [`suppressed_recipients_in_db`]),
    /// exposed so a caller that validates recipients earlier in its request
    /// lifecycle (REST) uses the same SQL and canonicalization as the SMTP
    /// admission gate.
    pub async fn suppressed_recipients(
        &self,
        tenant_id: &str,
        recipients: &[String],
    ) -> Result<Vec<String>, SendAdmissionError> {
        let canonical: Vec<String> = recipients
            .iter()
            .map(|recipient| canonical_recipient(recipient))
            .collect();
        self.backend
            .suppressed_recipients(tenant_id, &canonical)
            .await
            .map_err(SendAdmissionError::SuppressionUnavailable)
    }

    /// The one admission gate: validate the server-owned category, apply the
    /// suppression policy, and reserve `EmailsSent` quota for the tenant's
    /// plan under the caller's idempotency identity.
    pub async fn admit(
        &self,
        request: SendAdmissionRequest<'_>,
    ) -> Result<SendAdmission, SendAdmissionError> {
        // 1. Category first: cheap, side-effect free, and a validation
        //    failure must never touch quota.
        let category = normalize_category(request.category)?;

        // 2. Suppression policy (SMTP drops suppressed recipients; REST has
        //    already rejected them) determines the metered quantity.
        let (quantity, allowed_recipients, suppressed_recipients) = match request.meter {
            AdmissionMeter::Quantity(quantity) => (quantity, Vec::new(), Vec::new()),
            AdmissionMeter::FilteredRecipients(recipients) => {
                let canonical: Vec<String> = recipients
                    .iter()
                    .map(|recipient| canonical_recipient(recipient))
                    .collect();
                let suppressed = self
                    .backend
                    .suppressed_recipients(request.tenant_id, &canonical)
                    .await
                    .map_err(SendAdmissionError::SuppressionUnavailable)?;
                let suppressed_set: HashSet<&str> =
                    suppressed.iter().map(|email| email.as_str()).collect();
                let allowed: Vec<String> = recipients
                    .iter()
                    .filter(|recipient| {
                        !suppressed_set.contains(canonical_recipient(recipient).as_str())
                    })
                    .cloned()
                    .collect();

                if allowed.is_empty() {
                    // Every recipient is suppressed: refuse. Queueing an
                    // empty recipient set would consume quota for a message
                    // that cannot be delivered.
                    return Err(SendAdmissionError::Suppressed(suppressed));
                }

                (allowed.len() as i64, allowed, suppressed)
            }
        };

        // 3. Reserve the quota/entitlement under the deterministic identity.
        let event_id = usage_event_id(
            request.tenant_id,
            request.idempotency_key,
            request.idempotency_item,
        );
        let recorded_at = Utc::now();
        let result = self
            .backend
            .record_send_usage(request.tenant_id, quantity, event_id)
            .await
            .map_err(SendAdmissionError::MeteringUnavailable)?;

        if !result.allowed {
            return Err(SendAdmissionError::QuotaExceeded);
        }

        Ok(SendAdmission {
            backend: Arc::clone(&self.backend),
            tenant_id: request.tenant_id.to_string(),
            event_id,
            recorded_at,
            quantity,
            duplicate: result.duplicate,
            category,
            allowed_recipients,
            suppressed_recipients,
        })
    }
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory metering backend modelling the canonical
    /// `record_with_quota_check` contract: one shared counter per tenant,
    /// event-id de-duplication, all-or-nothing reservation, event-id keyed
    /// rollback. The SAME backend instance can be shared by requests shaped
    /// like the REST path and the SMTP path.
    #[derive(Default)]
    struct FakeBackend {
        state: Mutex<FakeState>,
    }

    #[derive(Default)]
    struct FakeState {
        limit: i64,
        used: i64,
        events: HashMap<Uuid, i64>,
        suppressed: std::collections::HashSet<String>,
    }

    impl FakeBackend {
        fn with_limit(limit: i64) -> Self {
            Self {
                state: Mutex::new(FakeState {
                    limit,
                    ..FakeState::default()
                }),
            }
        }

        fn used(&self) -> i64 {
            self.state.lock().unwrap().used
        }

        fn suppress(&self, email: &str) {
            self.state
                .lock()
                .unwrap()
                .suppressed
                .insert(email.to_ascii_lowercase());
        }
    }

    #[async_trait]
    impl SendAdmissionBackend for FakeBackend {
        async fn record_send_usage(
            &self,
            _tenant_id: &str,
            quantity: i64,
            event_id: Uuid,
        ) -> Result<QuotaRecordResult, UsageError> {
            let mut state = self.state.lock().unwrap();
            if let Some(previous) = state.events.get(&event_id) {
                assert_eq!(
                    *previous, quantity,
                    "duplicate event must carry the same quantity"
                );
                return Ok(QuotaRecordResult {
                    allowed: true,
                    current: state.used,
                    duplicate: true,
                });
            }
            if state.used + quantity > state.limit {
                return Ok(QuotaRecordResult {
                    allowed: false,
                    current: state.used,
                    duplicate: false,
                });
            }
            state.used += quantity;
            state.events.insert(event_id, quantity);
            Ok(QuotaRecordResult {
                allowed: true,
                current: state.used,
                duplicate: false,
            })
        }

        async fn rollback_send_usage(
            &self,
            _tenant_id: &str,
            quantity: i64,
            event_id: Uuid,
            _recorded_at: DateTime<Utc>,
        ) -> Result<(), UsageError> {
            let mut state = self.state.lock().unwrap();
            if state.events.remove(&event_id).is_some() {
                state.used -= quantity;
            }
            Ok(())
        }

        async fn suppressed_recipients(
            &self,
            _tenant_id: &str,
            canonical_recipients: &[String],
        ) -> Result<Vec<String>, String> {
            let state = self.state.lock().unwrap();
            let mut suppressed: Vec<String> = canonical_recipients
                .iter()
                .filter(|email| state.suppressed.contains(email.as_str()))
                .cloned()
                .collect();
            suppressed.sort();
            suppressed.dedup();
            Ok(suppressed)
        }
    }

    const TENANT: &str = "ten_shared";

    fn service(limit: i64) -> (SendAdmissionService, Arc<FakeBackend>) {
        let backend = Arc::new(FakeBackend::with_limit(limit));
        (SendAdmissionService::new(backend.clone()), backend)
    }

    fn recipients(list: &[&str]) -> Vec<String> {
        list.iter().map(|email| email.to_string()).collect()
    }

    /// REST-shaped admission: fixed quantity (to + cc + bcc), suppression
    /// validated separately, identity = HTTP Idempotency-Key.
    async fn admit_rest(
        service: &SendAdmissionService,
        quantity: i64,
        key: &str,
    ) -> Result<SendAdmission, SendAdmissionError> {
        service
            .admit(SendAdmissionRequest {
                tenant_id: TENANT,
                meter: AdmissionMeter::Quantity(quantity),
                idempotency_key: Some(key),
                idempotency_item: None,
                category: None,
            })
            .await
    }

    /// SMTP-shaped admission: envelope recipients filtered against the
    /// suppression list, identity = submitted message identity, no client
    /// category.
    async fn admit_smtp(
        service: &SendAdmissionService,
        rcpt: &[String],
        message_identity: &str,
    ) -> Result<SendAdmission, SendAdmissionError> {
        service
            .admit(SendAdmissionRequest {
                tenant_id: TENANT,
                meter: AdmissionMeter::FilteredRecipients(rcpt),
                idempotency_key: Some(message_identity),
                idempotency_item: None,
                category: None,
            })
            .await
    }

    // ── P0: one shared quota across both paths ──────────────────────

    #[tokio::test]
    async fn rest_and_smtp_admissions_consume_the_same_tenant_quota() {
        let (service, backend) = service(10);

        // REST send: 2 delivery recipients.
        let rest = admit_rest(&service, 2, "http-key-1").await.unwrap();
        assert_eq!(backend.used(), 2);
        assert!(!rest.duplicate());

        // SMTP submission right after: 3 envelope recipients. It must see
        // the REST reservation and reserve on top of it (one shared
        // EmailsSent counter, same tenant/plan).
        let rcpt = recipients(&["a@example.com", "b@example.com", "c@example.com"]);
        let smtp = admit_smtp(&service, &rcpt, "smtp:<msg-1@example.com>")
            .await
            .unwrap();
        assert_eq!(backend.used(), 5, "both paths share one quota counter");
        assert_eq!(smtp.quantity(), 3);
        assert_eq!(smtp.allowed_recipients().len(), 3);
    }

    #[tokio::test]
    async fn unentitled_tenant_is_refused_without_consuming_quota() {
        let (service, backend) = service(1);

        let error = admit_rest(&service, 2, "http-key-over").await.unwrap_err();
        assert!(matches!(error, SendAdmissionError::QuotaExceeded));

        let rcpt = recipients(&["a@example.com", "b@example.com"]);
        let error = admit_smtp(&service, &rcpt, "smtp:<over@example.com>")
            .await
            .unwrap_err();
        assert!(
            matches!(error, SendAdmissionError::QuotaExceeded),
            "SMTP must be refused by the same entitlement gate"
        );
        assert_eq!(backend.used(), 0, "a refused admission reserves nothing");
    }

    // ── queue failure rolls the reservation back on both paths ─────

    #[tokio::test]
    async fn queue_failure_rollback_releases_quota_on_both_paths() {
        let (service, backend) = service(10);

        let rest = admit_rest(&service, 2, "http-key-rollback").await.unwrap();
        assert_eq!(backend.used(), 2);
        rest.rollback().await.unwrap();
        assert_eq!(backend.used(), 0, "REST queue failure must release quota");

        let rcpt = recipients(&["a@example.com", "b@example.com", "c@example.com"]);
        let smtp = admit_smtp(&service, &rcpt, "smtp:<rollback@example.com>")
            .await
            .unwrap();
        assert_eq!(backend.used(), 3);
        smtp.rollback().await.unwrap();
        assert_eq!(backend.used(), 0, "SMTP queue failure must release quota");
    }

    #[tokio::test]
    async fn commit_after_enqueue_keeps_the_reservation() {
        let (service, backend) = service(10);
        let admission = admit_rest(&service, 2, "http-key-commit").await.unwrap();
        admission.commit();
        assert_eq!(backend.used(), 2, "a committed admission stands");
    }

    #[tokio::test]
    async fn duplicate_rollback_never_releases_the_winners_reservation() {
        let (service, backend) = service(10);
        let winner = admit_smtp(
            &service,
            &recipients(&["a@example.com"]),
            "smtp:<dup@example.com>",
        )
        .await
        .unwrap();
        let duplicate = admit_smtp(
            &service,
            &recipients(&["a@example.com"]),
            "smtp:<dup@example.com>",
        )
        .await
        .unwrap();
        assert!(duplicate.duplicate());

        // The loser's queue failure must NOT delete the winner's event.
        duplicate.rollback().await.unwrap();
        assert_eq!(backend.used(), 1);
        winner.commit();
        assert_eq!(backend.used(), 1);
    }

    // ── idempotency identity collapses duplicates ───────────────────

    #[tokio::test]
    async fn duplicate_submission_identity_collapses_to_one_reservation() {
        let (service, backend) = service(10);
        let rcpt = recipients(&["a@example.com", "b@example.com"]);

        let first = admit_smtp(&service, &rcpt, "smtp:<retry@example.com>")
            .await
            .unwrap();
        let second = admit_smtp(&service, &rcpt, "smtp:<retry@example.com>")
            .await
            .unwrap();

        assert!(!first.duplicate());
        assert!(
            second.duplicate(),
            "a duplicate submission identity must collapse to one reservation"
        );
        assert_eq!(
            first.event_id(),
            second.event_id(),
            "the same identity derives the same usage event id"
        );
        assert_eq!(backend.used(), 2, "the duplicate reserved nothing");
    }

    #[test]
    fn usage_event_id_is_stable_per_idempotency_identity() {
        let a = usage_event_id("ten_1", Some("key-1"), None);
        assert_eq!(a, usage_event_id("ten_1", Some("key-1"), None));
        assert_ne!(a, usage_event_id("ten_1", Some("key-2"), None));
        assert_ne!(a, usage_event_id("ten_2", Some("key-1"), None));
        assert_ne!(a, usage_event_id("ten_1", Some("key-1"), Some(0)));
        assert_eq!(
            usage_event_id("ten_1", Some("bk"), Some(3)),
            usage_event_id("ten_1", Some("bk"), Some(3))
        );
        assert_ne!(
            usage_event_id("ten_1", Some("bk"), Some(3)),
            usage_event_id("ten_1", Some("bk"), Some(4))
        );
    }

    // ── P1: category policy ─────────────────────────────────────────

    #[test]
    fn missing_category_gets_the_documented_policy_not_an_implicit_default() {
        assert_eq!(
            DEFAULT_MESSAGE_CATEGORY, "marketing",
            "the documented policy default is the non-preference-exempt category"
        );
        assert_eq!(normalize_category(None).unwrap(), DEFAULT_MESSAGE_CATEGORY);
    }

    #[tokio::test]
    async fn submission_without_category_admits_with_the_policy_category() {
        let (service, _backend) = service(10);
        let admission = admit_smtp(
            &service,
            &recipients(&["a@example.com"]),
            "smtp:<nocat@example.com>",
        )
        .await
        .unwrap();
        assert_eq!(admission.category(), DEFAULT_MESSAGE_CATEGORY);
        assert_eq!(admission.category(), "marketing");
        assert!(
            !admission.category().is_empty(),
            "the queue write must never rely on the schema default"
        );
    }

    #[tokio::test]
    async fn invalid_server_owned_category_is_refused_before_reserving() {
        let (service, backend) = service(10);
        let error = service
            .admit(SendAdmissionRequest {
                tenant_id: TENANT,
                meter: AdmissionMeter::Quantity(1),
                idempotency_key: Some("http-key-bad-cat"),
                idempotency_item: None,
                category: Some("marketing\nBcc: victim@example.com"),
            })
            .await
            .unwrap_err();
        assert!(matches!(error, SendAdmissionError::InvalidCategory { .. }));
        assert_eq!(backend.used(), 0, "validation failure must not reserve");
    }

    #[test]
    fn category_validation_uses_the_shared_helper_semantics() {
        assert_eq!(
            normalize_category(Some("  MARKETING ")).unwrap(),
            "marketing"
        );
        assert_eq!(
            normalize_category(Some("Transactional")).unwrap(),
            "transactional"
        );
        assert_eq!(
            normalize_category(Some("newsletter_2026")).unwrap(),
            "newsletter_2026"
        );
        assert!(normalize_category(Some("")).is_err());
        assert!(normalize_category(Some("cat\ngory")).is_err());
        assert!(normalize_category(Some(&"x".repeat(101))).is_err());
    }

    // ── suppression policy ──────────────────────────────────────────

    #[tokio::test]
    async fn smtp_suppression_filters_recipients_and_meters_only_allowed() {
        let (service, backend) = service(10);
        backend.suppress("blocked@example.com");
        let rcpt = recipients(&[
            "Blocked@Example.com",
            "allowed@example.com",
            "second@example.com",
        ]);

        let admission = admit_smtp(&service, &rcpt, "smtp:<suppressed@example.com>")
            .await
            .unwrap();

        assert_eq!(admission.allowed_recipients().len(), 2);
        assert_eq!(admission.suppressed_recipients(), ["blocked@example.com"]);
        assert_eq!(
            backend.used(),
            2,
            "quota is metered for the queued (allowed) recipients only"
        );
    }

    #[tokio::test]
    async fn all_recipients_suppressed_refuses_without_reserving() {
        let (service, backend) = service(10);
        backend.suppress("only@example.com");
        let rcpt = recipients(&["Only@Example.com", "only@example.com"]);

        let error = admit_smtp(&service, &rcpt, "smtp:<all-suppressed@example.com>")
            .await
            .unwrap_err();
        assert!(matches!(error, SendAdmissionError::Suppressed(_)));
        assert_eq!(backend.used(), 0);
    }

    #[tokio::test]
    async fn suppression_lookup_failure_fails_closed() {
        struct FailingSuppressionBackend;

        #[async_trait]
        impl SendAdmissionBackend for FailingSuppressionBackend {
            async fn record_send_usage(
                &self,
                _tenant_id: &str,
                _quantity: i64,
                _event_id: Uuid,
            ) -> Result<QuotaRecordResult, UsageError> {
                panic!("must not reserve when the suppression check failed");
            }

            async fn rollback_send_usage(
                &self,
                _tenant_id: &str,
                _quantity: i64,
                _event_id: Uuid,
                _recorded_at: DateTime<Utc>,
            ) -> Result<(), UsageError> {
                Ok(())
            }

            async fn suppressed_recipients(
                &self,
                _tenant_id: &str,
                _canonical_recipients: &[String],
            ) -> Result<Vec<String>, String> {
                Err("redis down".to_string())
            }
        }

        let service = SendAdmissionService::new(Arc::new(FailingSuppressionBackend));
        let error = service
            .admit(SendAdmissionRequest {
                tenant_id: TENANT,
                meter: AdmissionMeter::FilteredRecipients(&recipients(&["a@example.com"])),
                idempotency_key: Some("smtp:<fail>"),
                idempotency_item: None,
                category: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            SendAdmissionError::SuppressionUnavailable(_)
        ));
    }
}
