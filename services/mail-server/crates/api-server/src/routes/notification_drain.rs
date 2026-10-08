//! Drainer for the billing `notification_queue` (dogfood 2026-10-06, wave B).
//!
//! Producers (`billing-service`): usage alerts, cost alerts, dunning
//! (`payment_reminder` / `account_soft_suspended` / `account_hard_suspended`),
//! `payment_failed`, `trial_ending`, `messages_purged`, duplicate-Stripe-
//! collection refusals. Every one of them INSERTs a row with
//! `status = 'pending'` and, for usage alerts, treats the INSERT itself as
//! delivery (`send_usage_alert` sets `delivered = true` on enqueue).
//!
//! Before this module NOTHING read the table: the live stack carried 64
//! pending `usage_alert` rows, the oldest two days old, all with
//! `attempts = 0` — every billing notification was silently never sent.
//!
//! This module is the missing consumer. Contract:
//!
//! * **Claim** — pending rows (plus `processing` rows abandoned by a crashed
//!   drainer) are claimed with `FOR UPDATE SKIP LOCKED`, so any number of
//!   api-server replicas may run the drainer concurrently without double
//!   delivery. `attempts` increments at claim time: a process death cannot
//!   lose the attempt record.
//! * **Backoff** — a row that failed is only re-claimable after
//!   `attempts² × 60 s` (capped at [`MAX_RETRY_BACKOFF_SECS`]), so a transient
//!   mail-pipeline outage cannot hot-loop. After `max_attempts` the row is
//!   parked as `failed` with the last error — never deleted, never a silent
//!   drop.
//! * **Deliver** — the notification is rendered and handed to the SAME
//!   platform mail pipeline account mail uses
//!   ([`crate::routes::system_sender::queue_system_email_in_transaction`]:
//!   DKIM-ready system sender, `email_queue` + `messages` rows, worker
//!   pickup). The queue row and the queued message commit in ONE transaction,
//!   so a crash can never mark a notification sent without the message.
//! * **Recipient** — the tenant's owner (the billing contact). A tenant with
//!   no owner address fails loudly and retries rather than vanishing.
//!
//! Unknown notification types are still delivered with a generic rendering
//! (type + payload) — a new producer type must never be a silent drop.

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::ApiError;

/// Maximum rows claimed per drain tick.
pub const DRAIN_BATCH_SIZE: i64 = 50;

/// A `processing` row older than this was abandoned by a crashed drainer and
/// is re-claimable (the claim still counts as an attempt).
pub const STUCK_PROCESSING_RECLAIM_SECS: i64 = 15 * 60;

/// Retry backoff cap: `min(attempts² × 60 s, 1 h)`.
pub const MAX_RETRY_BACKOFF_SECS: i64 = 3600;

/// One claimed queue row.
#[derive(Debug, sqlx::FromRow)]
pub struct ClaimedNotification {
    pub id: Uuid,
    pub tenant_id: String,
    pub notification_type: String,
    pub payload: serde_json::Value,
    pub attempts: i32,
    pub max_attempts: i32,
}

/// What one drain pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DrainStats {
    pub claimed: usize,
    pub sent: usize,
    pub retried: usize,
    pub failed: usize,
}

impl DrainStats {
    pub fn is_empty(&self) -> bool {
        self.claimed == 0
    }
}

/// The claimed rows of one pass, plus the outcome counters.
struct ClaimOutcome {
    rows: Vec<ClaimedNotification>,
    stats: DrainStats,
}

/// Claim one batch of deliverable rows.
///
/// The backoff window is enforced in the claim predicate (not in a post-hoc
/// filter) so a backed-off row is never locked or counted.
async fn claim_batch(db: &PgPool, batch: i64) -> Result<ClaimOutcome, ApiError> {
    let rows = sqlx::query_as::<_, ClaimedNotification>(
        "UPDATE notification_queue AS nq \
            SET status = 'processing', attempts = nq.attempts + 1, updated_at = NOW() \
          WHERE nq.id IN ( \
                SELECT id FROM notification_queue \
                 WHERE (status = 'pending' \
                        AND updated_at <= NOW() - make_interval(secs => LEAST(attempts * attempts * 60, $3::int))) \
                    OR (status = 'processing' \
                        AND updated_at <= NOW() - make_interval(secs => $2::int)) \
                 ORDER BY created_at ASC \
                 FOR UPDATE SKIP LOCKED \
                 LIMIT $1) \
          RETURNING nq.id, nq.tenant_id, nq.type AS notification_type, nq.payload, \
                    nq.attempts, nq.max_attempts",
    )
    .bind(batch.clamp(1, 500))
    .bind(STUCK_PROCESSING_RECLAIM_SECS)
    .bind(MAX_RETRY_BACKOFF_SECS)
    .fetch_all(db)
    .await?;

    let claimed = rows.len();
    Ok(ClaimOutcome {
        rows,
        stats: DrainStats {
            claimed,
            ..DrainStats::default()
        },
    })
}

/// The tenant's billing contact: its owner user.
async fn owner_email(db: &PgPool, tenant_id: &str) -> Result<Option<String>, ApiError> {
    let email: Option<String> = sqlx::query_scalar(
        "SELECT email FROM users \
          WHERE tenant_id = $1 AND role = 'owner' AND email <> '' \
          ORDER BY created_at ASC LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(db)
    .await?;
    Ok(email)
}

/// A rendered platform notification.
struct RenderedNotification {
    subject: String,
    html: String,
    text: String,
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn payload_str<'a>(payload: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    payload.get(key).and_then(serde_json::Value::as_str)
}

fn payload_i64(payload: &serde_json::Value, key: &str) -> Option<i64> {
    payload.get(key).and_then(serde_json::Value::as_i64)
}

/// Render one notification. Known types get a product-specific message; any
/// other type gets a generic rendering so a producer added later is never a
/// silent drop (the payload travels verbatim).
fn render_notification(
    notification_type: &str,
    payload: &serde_json::Value,
) -> RenderedNotification {
    let (subject, body_lines) = match notification_type {
        "usage_alert" => {
            let metric = payload_str(payload, "metricType").unwrap_or("usage");
            let percent = payload_i64(payload, "currentPercent")
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".into());
            let current = payload_i64(payload, "currentValue")
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".into());
            let limit = payload_i64(payload, "limitValue")
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".into());
            let threshold = payload_i64(payload, "thresholdPercent")
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".into());
            (
                format!("ApexMail usage alert: {metric} at {percent}% of plan"),
                format!(
                    "Your {metric} usage has reached {percent}% of the plan allowance \
                     (threshold: {threshold}%).\n\nUsage: {current} of {limit}.\n\n\
                     Review your usage and plan at https://app.apexmail.ee/billing."
                ),
            )
        }
        "cost_alert" => {
            let detail = payload.get("message").and_then(serde_json::Value::as_str);
            (
                "ApexMail cost alert".to_string(),
                detail
                    .map(str::to_string)
                    .unwrap_or_else(|| "A cost threshold was crossed on your account.".into()),
            )
        }
        "payment_failed" => {
            let amount = payload_i64(payload, "amount")
                .map(|cents| format!("{:.2}", cents as f64 / 100.0))
                .unwrap_or_else(|| "?".into());
            (
                "ApexMail payment failed".to_string(),
                format!(
                    "We could not collect the payment of {amount} for your latest invoice.\n\n\
                     Update your payment method at https://app.apexmail.ee/billing to avoid \
                     service interruption."
                ),
            )
        }
        "payment_reminder" => (
            "ApexMail payment reminder".to_string(),
            "A payment on your account is past due. Update your payment method at \
             https://app.apexmail.ee/billing to avoid service interruption."
                .to_string(),
        ),
        "account_soft_suspended" => (
            "ApexMail account suspended (grace period)".to_string(),
            "Your account was soft-suspended because payment could not be collected. \
             Sending is paused; your data is retained during the grace period. \
             Update your payment method at https://app.apexmail.ee/billing."
                .to_string(),
        ),
        "account_hard_suspended" => (
            "ApexMail account suspended".to_string(),
            "Your account was suspended after the payment grace period ended. \
             Contact support@apexmail.ee or update your payment method at \
             https://app.apexmail.ee/billing."
                .to_string(),
        ),
        "trial_ending" => {
            let trial_end = payload_i64(payload, "trialEnd")
                .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
                .map(|ts| ts.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "soon".into());
            (
                "Your ApexMail trial is ending".to_string(),
                format!(
                    "Your trial ends on {trial_end}. Add a payment method at \
                     https://app.apexmail.ee/billing to keep sending without interruption."
                ),
            )
        }
        "messages_purged" => {
            let purged = payload_i64(payload, "purgedCount")
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".into());
            (
                "ApexMail: messages removed after suspension".to_string(),
                format!(
                    "{purged} queued message(s) were removed while your account was \
                     suspended. Historical records are unaffected."
                ),
            )
        }
        "duplicate_stripe_collection_refused" => (
            "ApexMail billing safety notice".to_string(),
            "A duplicate Stripe collection attempt was refused to protect your account. \
             No extra charge was made. Our team has been notified."
                .to_string(),
        ),
        other => (
            format!("ApexMail notification: {other}"),
            format!(
                "This is an automated notification from ApexMail.\n\nType: {other}\n\
                 Details: {}",
                payload
            ),
        ),
    };

    let html = format!(
        "<p>{}</p><hr><p style=\"color:#666;font-size:12px\">ApexMail · \
         automated notification</p>",
        escape_html(&body_lines).replace('\n', "<br>")
    );
    RenderedNotification {
        subject,
        html,
        text: format!("{body_lines}\n\n— ApexMail (automated notification)"),
    }
}

/// Deliver one claimed row. The queue-row transition and the queued platform
/// message commit in the SAME transaction.
async fn deliver_one(db: &PgPool, row: &ClaimedNotification) -> Result<Uuid, ApiError> {
    let recipient = owner_email(db, &row.tenant_id).await?.ok_or_else(|| {
        ApiError::ServiceUnavailable(format!(
            "tenant {} has no owner email to notify",
            row.tenant_id
        ))
    })?;

    let rendered = render_notification(&row.notification_type, &row.payload);

    let mut tx = db.begin().await?;
    let message_id = crate::routes::system_sender::queue_system_email_in_transaction(
        &mut tx,
        &recipient,
        &rendered.subject,
        &rendered.html,
        &rendered.text,
        vec![format!("notification:{}", row.notification_type)],
        crate::routes::system_sender::QUEUE_PRIORITY_DEFAULT,
    )
    .await?;

    sqlx::query(
        "UPDATE notification_queue \
            SET status = 'sent', last_error = NULL, updated_at = NOW(), \
                payload = payload || jsonb_build_object('queuedMessageId', $2::text) \
          WHERE id = $1",
    )
    .bind(row.id)
    .bind(message_id.to_string())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(message_id)
}

/// Record a failed delivery attempt: retry until `max_attempts`, then park.
async fn record_failure(db: &PgPool, row: &ClaimedNotification, error: &str) {
    let terminal = row.attempts >= row.max_attempts;
    let result = sqlx::query(
        "UPDATE notification_queue \
            SET status = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'pending' END, \
                last_error = $2, updated_at = NOW() \
          WHERE id = $1",
    )
    .bind(row.id)
    .bind(error)
    .execute(db)
    .await;

    match result {
        Ok(_) if terminal => {
            tracing::error!(
                notification_id = %row.id,
                tenant_id = %row.tenant_id,
                notification_type = %row.notification_type,
                attempts = row.attempts,
                error,
                "notification permanently failed after max attempts"
            );
        }
        Ok(_) => {
            tracing::warn!(
                notification_id = %row.id,
                tenant_id = %row.tenant_id,
                notification_type = %row.notification_type,
                attempts = row.attempts,
                max_attempts = row.max_attempts,
                error,
                "notification delivery failed; will retry with backoff"
            );
        }
        Err(write_error) => {
            tracing::error!(
                notification_id = %row.id,
                error = %write_error,
                "could not record notification failure; row stays processing until reclaim"
            );
        }
    }
}

/// Drain one batch of the notification queue.
///
/// Returns the pass's counters. A per-row delivery failure is recorded on the
/// row (retry/park) and does NOT fail the pass — one bad tenant cannot block
/// the queue for everyone.
pub async fn drain_notification_queue(
    db: &PgPool,
    batch: i64,
) -> Result<DrainStats, ApiError> {
    let ClaimOutcome { rows, mut stats } = claim_batch(db, batch).await?;

    for row in &rows {
        match deliver_one(db, row).await {
            Ok(message_id) => {
                stats.sent += 1;
                tracing::info!(
                    notification_id = %row.id,
                    tenant_id = %row.tenant_id,
                    notification_type = %row.notification_type,
                    message_id = %message_id,
                    "notification queued to the platform mail pipeline"
                );
            }
            Err(error) => {
                let reason = error.to_string();
                if row.attempts >= row.max_attempts {
                    stats.failed += 1;
                } else {
                    stats.retried += 1;
                }
                record_failure(db, row, &reason).await;
            }
        }
    }

    if !stats.is_empty() {
        tracing::info!(
            claimed = stats.claimed,
            sent = stats.sent,
            retried = stats.retried,
            failed = stats.failed,
            "notification queue drain pass complete"
        );
    }
    Ok(stats)
}

/// Startup log line, so an operator reading the log knows the drainer exists.
pub fn drain_interval_log(interval_secs: u64) {
    tracing::info!(
        interval_secs,
        "billing notification queue drainer started (notification_queue → system mail pipeline)"
    );
}

/// Timestamp helper kept public for tests to reason about backoff windows.
pub fn claim_now() -> chrono::DateTime<Utc> {
    Utc::now()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    const DKIM_ENV: &str = apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV;

    /// Seed a tenant with an owner user. Returns the tenant id.
    async fn seed_tenant_with_owner(db: &PgPool, suffix: &str) -> String {
        let tenant = format!("nd{}", &suffix[..4.min(suffix.len())].replace(['-', '_'], "x"));
        let tenant: String = tenant.chars().take(26).collect();
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at) \
             VALUES ($1, 'Notification Drain Co', $2, 'starter', 'active', NOW(), NOW()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&tenant)
        .bind(format!("slug-{tenant}"))
        .execute(db)
        .await
        .expect("seed tenant");
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, \
                                email_verified, metadata, created_at, updated_at) \
             VALUES ($1::uuid, $2, $3, 'Owner', 'x', 'owner', 'active', true, '{}'::jsonb, \
                     NOW(), NOW())",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&tenant)
        .bind(format!("owner-{suffix}@example.test"))
        .execute(db)
        .await
        .expect("seed owner");
        tenant
    }

    async fn seed_notification(
        db: &PgPool,
        tenant: &str,
        notification_type: &str,
        attempts: i32,
        max_attempts: i32,
    ) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO notification_queue \
                (id, tenant_id, type, payload, status, attempts, max_attempts, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, 'pending', $5, $6, NOW(), NOW() - INTERVAL '1 hour')",
        )
        .bind(id)
        .bind(tenant)
        .bind(notification_type)
        .bind(serde_json::json!({
            "metricType": "emails",
            "thresholdPercent": 80,
            "currentPercent": 85,
            "currentValue": 85,
            "limitValue": 100
        }))
        .bind(attempts)
        .bind(max_attempts)
        .execute(db)
        .await
        .expect("seed notification");
        id
    }

    /// Seed the system sender domain (apexmail.ee) with real DKIM material so
    /// the platform mail pipeline accepts the message — the same convention
    /// as `routes::web`'s coverage fixture. Callers hold
    /// [`crate::test_db::DKIM_ENV_MUTEX`].
    async fn seed_system_sender(db: &PgPool) {
        std::env::set_var(
            DKIM_ENV,
            "3f7a1c9e2b5d48f01a6c3e792d4b8f15a0c6e3917d2f4b8a5c1e7309d4f2b6a8",
        );
        let key_pair = apexmail_lib::dkim::generate_dkim_keypair()
            .expect("test DKIM keypair generation must not fail");
        let aad = apexmail_lib::dkim::dkim_private_key_aad(
            crate::routes::system_sender::SYSTEM_TENANT_ID,
            crate::routes::system_sender::SYSTEM_DOMAIN_ID,
        );
        let encrypted =
            apexmail_lib::dkim::encrypt_dkim_private_key(&key_pair.private_key_pem, &aad)
                .expect("test DKIM private key encryption must not fail");
        let public_key =
            apexmail_lib::dkim::public_key_base64_from_private_key_pem(&key_pair.private_key_pem)
                .expect("test DKIM public key derivation must not fail");
        // The system tenant must exist for the domain FK.
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at) \
             VALUES ($1, 'System', 'system', 'enterprise', 'active', NOW(), NOW()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(crate::routes::system_sender::SYSTEM_TENANT_ID)
        .execute(db)
        .await
        .expect("seed system tenant");
        sqlx::query(
            "INSERT INTO domains (id, tenant_id, name, status, verified, ses_verified, \
                                  dkim_enabled, dkim_selector, dkim_public_key, dkim_private_key) \
             VALUES ($1::uuid, $2, $3, 'verified', true, true, true, 'testsel', $4, $5) \
             ON CONFLICT (tenant_id, lower(name)) DO UPDATE \
               SET status = 'verified', verified = true, ses_verified = true, \
                   dkim_enabled = true, dkim_selector = 'testsel', \
                   dkim_public_key = EXCLUDED.dkim_public_key, \
                   dkim_private_key = EXCLUDED.dkim_private_key",
        )
        .bind(crate::routes::system_sender::SYSTEM_DOMAIN_ID)
        .bind(crate::routes::system_sender::SYSTEM_TENANT_ID)
        .bind(crate::routes::system_sender::SYSTEM_DOMAIN)
        .bind(public_key)
        .bind(encrypted)
        .execute(db)
        .await
        .expect("seed system sender domain");
    }

    /// The core finding fix: a pending row is drained into a REAL queued
    /// platform message for the tenant owner and marked `sent`. Before the
    /// drainer existed the row stayed `pending` forever.
    #[tokio::test]
    async fn pending_notification_is_delivered_to_the_owner_and_marked_sent() {
        let _guard = crate::test_db::DKIM_ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(db) = crate::test_db::canonical_pool("notif_drain_sent").await else {
            return;
        };

        let tenant = seed_tenant_with_owner(&db, "sent").await;
        let notification_id = seed_notification(&db, &tenant, "usage_alert", 0, 3).await;
        seed_system_sender(&db).await;

        let stats = drain_notification_queue(&db, 50)
            .await
            .expect("drain pass");
        assert_eq!(stats.claimed, 1, "the pending row must be claimed");
        assert_eq!(stats.sent, 1, "the notification must be delivered");

        let (status, message_id): (String, Option<String>) = sqlx::query_as(
            "SELECT status, payload->>'queuedMessageId' FROM notification_queue WHERE id = $1",
        )
        .bind(notification_id)
        .fetch_one(&db)
        .await
        .expect("read notification row");
        assert_eq!(status, "sent");
        let message_id: Uuid = message_id.expect("message id").parse().expect("uuid");

        // The platform mail pipeline carries the rendered message to the
        // owner's address, not the raw payload.
        let (subject, from_email): (String, String) =
            sqlx::query_as("SELECT subject, from_email FROM messages WHERE id = $1")
                .bind(message_id)
                .fetch_one(&db)
                .await
                .expect("queued message must exist");
        assert_eq!(from_email, crate::routes::system_sender::SYSTEM_FROM_ADDRESS);
        assert!(
            subject.contains("usage alert") && subject.contains("emails"),
            "subject must be the rendered notification, got {subject:?}"
        );

        let (queued_to,): (Vec<String>,) =
            sqlx::query_as("SELECT to_addresses FROM email_queue WHERE message_id = $1")
                .bind(message_id)
                .fetch_one(&db)
                .await
                .expect("email_queue row must exist");
        assert_eq!(
            queued_to,
            vec!["owner-sent@example.test".to_string()],
            "the owner address must be the recipient"
        );

        db.close().await;
    }

    /// A row whose tenant has no owner address must NOT be marked sent and
    /// must not vanish: it retries, and after max_attempts it parks as failed
    /// with the reason.
    #[tokio::test]
    async fn orphan_over_attempted_row_parks_failed_with_the_reason() {
        let Some(db) = crate::test_db::canonical_pool("notif_drain_orphan").await else {
            return;
        };

        // Tenant without any user row: recipient resolution must fail.
        let tenant = "ndorphantenant0000000001".to_string();
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at) \
             VALUES ($1, 'Orphan Co', $2, 'starter', 'active', NOW(), NOW()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&tenant)
        .bind(format!("slug-{tenant}"))
        .execute(&db)
        .await
        .expect("seed tenant");

        // attempts=2, max=3: the claim increments to 3 → this failure is terminal.
        let notification_id = seed_notification(&db, &tenant, "trial_ending", 2, 3).await;

        let stats = drain_notification_queue(&db, 50).await.expect("drain pass");
        assert_eq!(stats.claimed, 1);
        assert_eq!(stats.failed, 1, "a terminal attempt must count as failed");
        assert_eq!(stats.sent, 0);

        let (status, attempts, last_error): (String, i32, Option<String>) = sqlx::query_as(
            "SELECT status, attempts, last_error FROM notification_queue WHERE id = $1",
        )
        .bind(notification_id)
        .fetch_one(&db)
        .await
        .expect("read notification row");
        assert_eq!(status, "failed", "no owner email → never marked sent");
        assert_eq!(attempts, 3, "the claim must have recorded the attempt");
        assert!(
            last_error
                .as_deref()
                .is_some_and(|error| error.contains("no owner email")),
            "the failure reason must be recorded, got {last_error:?}"
        );

        db.close().await;
    }

    /// A retryable failure stays pending with backoff — and is NOT re-claimed
    /// on the immediate next pass.
    #[tokio::test]
    async fn retryable_failure_backs_off_before_the_next_claim() {
        let Some(db) = crate::test_db::canonical_pool("notif_drain_backoff").await else {
            return;
        };
        let tenant = "ndbackofftenant000000001".to_string();
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at) \
             VALUES ($1, 'Backoff Co', $2, 'starter', 'active', NOW(), NOW()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&tenant)
        .bind(format!("slug-{tenant}"))
        .execute(&db)
        .await
        .expect("seed tenant");

        let notification_id = seed_notification(&db, &tenant, "payment_failed", 0, 5).await;

        let first = drain_notification_queue(&db, 50).await.expect("first pass");
        assert_eq!(first.claimed, 1);
        assert_eq!(first.retried, 1, "attempt 1 of 5 must retry");

        // attempts is now 1 → backoff 60 s; an immediate second pass must not
        // re-claim the row.
        let second = drain_notification_queue(&db, 50).await.expect("second pass");
        assert_eq!(
            second.claimed, 0,
            "a backed-off row must not be re-claimed immediately"
        );

        let (status, attempts): (String, i32) =
            sqlx::query_as("SELECT status, attempts FROM notification_queue WHERE id = $1")
                .bind(notification_id)
                .fetch_one(&db)
                .await
                .expect("read row");
        assert_eq!(status, "pending");
        assert_eq!(attempts, 1);

        db.close().await;
    }

    /// Unknown notification types are still delivered (generic rendering) —
    /// a producer added later must never be a silent drop.
    #[test]
    fn unknown_type_renders_a_generic_message_with_the_payload() {
        let rendered = render_notification(
            "brand_new_alert",
            &serde_json::json!({"foo": "bar"}),
        );
        assert!(rendered.subject.contains("brand_new_alert"));
        assert!(rendered.text.contains("brand_new_alert"));
        assert!(rendered.text.contains("bar"));
    }

    /// HTML escaping: payload values never inject markup.
    #[test]
    fn rendered_html_escapes_payload_values() {
        let rendered = render_notification(
            "cost_alert",
            &serde_json::json!({"message": "<script>alert(1)</script>"}),
        );
        assert!(!rendered.html.contains("<script>"));
        assert!(rendered.html.contains("&lt;script&gt;"));
    }
}
