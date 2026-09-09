//! Human approval surface for AI-generated inbound-reply drafts.
//!
//! The email agent (ai-service) writes drafts with `pending_approval = true`
//! and NEVER sends anything. This surface is the missing reader: operators
//! list pending drafts, approve (which sends the reply through the
//! platform's verified system sender — `queue_system_email`, attributed to
//! the system tenant that owns the sending domain) or reject them. Every
//! decision is audit-logged with full actor attribution.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_drafts))
        .route("/:id/approve", post(approve_draft))
        .route("/:id/reject", post(reject_draft))
}

#[derive(Debug, Serialize)]
struct DraftDto {
    id: String,
    tenant_id: String,
    from_email: String,
    subject: String,
    draft_reply: String,
    received_at: String,
}

/// `inbound_messages.id` is the canonical VARCHAR(26) MTA identifier
/// (`inb_<22 hex>` — migration 088), never a UUID. Every statement below
/// binds it as text: a `$1::uuid` cast makes the comparison invalid
/// (`operator does not exist: character varying = uuid`) and the route
/// fails on every call (audit F11).
async fn list_drafts(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["*"])?;

    let rows: Vec<(
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as(
        r#"
        SELECT id, tenant_id, from_email, subject, ai_response, received_at
        FROM inbound_messages
        WHERE pending_approval = true
          AND ai_response IS NOT NULL
        ORDER BY received_at ASC
        LIMIT 100
        "#,
    )
    .fetch_all(&state.db)
    .await?;

    let drafts: Vec<DraftDto> = rows
        .into_iter()
        .map(|(id, tenant, from, subject, reply, ts)| DraftDto {
            id,
            tenant_id: tenant.unwrap_or_default(),
            from_email: from.unwrap_or_default(),
            subject: subject.unwrap_or_default(),
            draft_reply: reply.unwrap_or_default(),
            received_at: ts.to_rfc3339(),
        })
        .collect();

    Ok(Json(
        serde_json::json!({ "drafts": drafts, "count": drafts.len() }),
    ))
}

#[derive(Debug, Deserialize)]
struct ApproveBody {
    /// Operator note recorded in the audit log.
    #[serde(default)]
    pub note: String,
}

/// Atomically claim a pending draft inside an open transaction: the
/// conditional `pending_approval = true` predicate makes exactly one
/// approve/reject the winner across concurrent callers (the row lock
/// serialises them; the loser's UPDATE matches nothing). The id is bound
/// as the canonical VARCHAR identifier — never cast to UUID (audit F11).
const CLAIM_DRAFT_FOR_APPROVAL_SQL: &str = r#"
    UPDATE inbound_messages
    SET pending_approval = false, processed_at = NOW()
    WHERE id = $1
      AND pending_approval = true
      AND ai_response IS NOT NULL
    RETURNING tenant_id, from_email, subject, ai_response
"#;

/// Actor-attributed audit for AI-draft decisions (P1-4/P2-2): an approved
/// AI reply is a platform-sent message to a customer — the operator who
/// approved it (tenant + user) and the routed tenant must be on record.
async fn log_draft_audit(
    state: &AppState,
    auth: &AuthUser,
    action: &str,
    draft_id: &str,
    metadata: serde_json::Value,
) {
    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        action,
        "ai_draft",
        Some(draft_id),
        metadata,
        None,
        None,
    )
    .await;
}

async fn approve_draft(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    body: Option<Json<ApproveBody>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["*"])?;
    let note = body.map(|Json(b)| b.note).unwrap_or_default();

    // The reply/outbox rows and the approval consumption commit together:
    // the enqueue is persisted BEFORE the pending_approval flip becomes
    // visible, so a crash or failed enqueue can never leave an
    // approved-but-unanswered (consumed) draft behind (audit F11).
    let mut tx = state.db.begin().await?;

    // Claim the draft atomically: exactly one approve/reject wins.
    let row: Option<(
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(CLAIM_DRAFT_FOR_APPROVAL_SQL)
        .bind(&id)
        .fetch_optional(&mut *tx)
        .await?;

    let Some((tenant_id, from_email, subject, reply)) = row else {
        // Dropping the transaction rolls the claim back — nothing consumed.
        return Err(ApiError::NotFound(
            "draft not found or already handled".into(),
        ));
    };
    let tenant_id = tenant_id.unwrap_or_default();
    let from_email = from_email.unwrap_or_default();
    let subject = subject.unwrap_or_default();
    let reply = reply.unwrap_or_default();

    if tenant_id.is_empty() || from_email.is_empty() {
        // Cannot route the reply — the uncommitted claim rolls back with
        // the transaction, so the draft stays pending and visible.
        return Err(ApiError::Validation(vec![
            "draft is missing tenant or sender; reject it instead".into(),
        ]));
    }

    // P1-4: route through the platform's verified system sender. The
    // previous hand-rolled email_queue INSERT hardcoded
    // `support@apexmail.ee` as the from-address while attributing the row to
    // the CUSTOMER's tenant — the customer neither owns apexmail.ee (SPF/
    // DKIM alignment broken) nor sent the mail. `queue_system_email`
    // enforces system-sender readiness under lock and attributes the queue
    // row to the system tenant that actually owns the sending domain.
    let message_uuid = match crate::routes::system_sender::queue_system_email_in_transaction(
        &mut tx,
        &from_email,
        &subject,
        "",
        &reply,
        vec!["ai-draft-approval".to_string()],
    )
    .await
    {
        Ok(message_uuid) => message_uuid,
        Err(e) => {
            // Enqueue failed — rolling back undoes the claim, so the draft
            // remains pending and recoverable instead of consumed.
            let _ = tx.rollback().await;
            tracing::error!(error = %e, draft_id = %id, "approve: queue insert failed");
            return Err(ApiError::Internal(
                "could not queue the reply; draft still pending".into(),
            ));
        }
    };

    // Commit makes the consumption of the approval visible only now, with
    // the reply already persisted in the same transaction.
    tx.commit().await?;

    tracing::info!(
        operator = %auth.user_id.clone().unwrap_or_default(),
        draft_id = %id,
        tenant_id = %tenant_id,
        note = %note,
        "AI reply draft APPROVED and queued"
    );
    log_draft_audit(
        &state,
        &auth,
        "control_plane.ai_draft.approved",
        &id,
        serde_json::json!({
            "note": note,
            "routedTenantId": tenant_id,
            "recipient": from_email,
            "queuedMessageId": message_uuid.to_string(),
        }),
    )
    .await;
    Ok(Json(serde_json::json!({
        "approved": true,
        "queued_message_id": message_uuid.to_string(),
    })))
}

/// Reject a pending draft. Same canonical VARCHAR id binding (audit F11).
const REJECT_DRAFT_SQL: &str =
    "UPDATE inbound_messages SET pending_approval = false, processed_at = NOW() \
     WHERE id = $1 AND pending_approval = true";

async fn reject_draft(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    body: Option<Json<ApproveBody>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["*"])?;
    let note = body.map(|Json(b)| b.note).unwrap_or_default();

    let result = sqlx::query(REJECT_DRAFT_SQL)
        .bind(&id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound(
            "draft not found or already handled".into(),
        ));
    }
    tracing::info!(
        operator = %auth.user_id.clone().unwrap_or_default(),
        draft_id = %id,
        note = %note,
        "AI reply draft REJECTED"
    );
    log_draft_audit(
        &state,
        &auth,
        "control_plane.ai_draft.rejected",
        &id,
        serde_json::json!({ "note": note }),
    )
    .await;
    Ok(Json(serde_json::json!({ "rejected": true })))
}

// Keep StatusCode import used uniformly.
#[allow(dead_code)]
fn _status_guard(_s: StatusCode) {}

// ─── F11 database tests ────────────────────────────────────────
//
// Exercise the approval claim against a real PostgreSQL using the
// canonical VARCHAR(26) inbound_messages shape (migration 088 subset),
// following the audit_log.rs isolated-per-test database convention.
// Skipped unless TEST_DATABASE_URL is set.

#[cfg(test)]
mod approval_db_tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use std::time::Duration;

    /// Canonical inbound_messages columns used by this route, mirroring
    /// migration 088's shape: `id` is the MTA's VARCHAR(26) `inb_<22 hex>`,
    /// never a UUID.
    const INBOUND_MESSAGES_DDL: &str = r#"
        CREATE TABLE inbound_messages (
            id               VARCHAR(26) PRIMARY KEY,
            tenant_id        VARCHAR(26),
            from_email       VARCHAR(255),
            subject          VARCHAR(255),
            ai_response      TEXT,
            pending_approval BOOLEAN NOT NULL DEFAULT false,
            processed_at     TIMESTAMPTZ,
            received_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )"#;

    /// The claim and reject statements must never regain a `::uuid` cast:
    /// `inbound_messages.id` is VARCHAR(26) and `varchar = uuid` has no
    /// operator, so the cast made approval/rejection fail on every call.
    #[test]
    fn draft_statements_bind_the_canonical_varchar_id() {
        for sql in [CLAIM_DRAFT_FOR_APPROVAL_SQL, REJECT_DRAFT_SQL] {
            assert!(!sql.contains("::uuid"), "regression: {sql}");
            assert!(sql.contains("id = $1"), "must bind the id as text: {sql}");
        }
    }

    async fn isolated_pool(db_suffix: &str) -> Option<sqlx::PgPool> {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())?;
        let (server_part, db_part) = database_url.rsplit_once('/')?;
        let db_only = db_part.split('?').next().unwrap_or(db_part);
        let isolated_db = format!("{db_only}_api_ai_drafts_f11_{db_suffix}");
        let isolated_url = format!("{server_part}/{isolated_db}");
        let admin_url = format!("{server_part}/postgres");

        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(3))
            .connect(&admin_url)
            .await
            .ok()?;
        let _ = sqlx::query(&format!(
            r#"DROP DATABASE IF EXISTS "{isolated_db}" WITH (FORCE)"#
        ))
        .execute(&admin)
        .await;
        let created = sqlx::query(&format!(r#"CREATE DATABASE "{isolated_db}""#))
            .execute(&admin)
            .await;
        admin.close().await;
        created.ok()?;

        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&isolated_url)
            .await
            .ok()?;
        sqlx::query(INBOUND_MESSAGES_DDL)
            .execute(&pool)
            .await
            .ok()?;
        Some(pool)
    }

    /// A canonical MTA id — deliberately NOT parseable as a UUID, which the
    /// old `$1::uuid` binding could never match.
    fn canonical_draft_id() -> String {
        format!("inb_{}", "0123456789abcdef012345")
    }

    async fn insert_draft(pool: &sqlx::PgPool, id: &str, pending: bool) {
        sqlx::query(
            "INSERT INTO inbound_messages (id, tenant_id, from_email, subject, ai_response, pending_approval) \
             VALUES ($1, 'test-f11-tenant', 'customer@x.ee', 'Re: invoice', 'please approve', $2)",
        )
        .bind(id)
        .bind(pending)
        .execute(pool)
        .await
        .expect("draft seed");
    }

    async fn pending_state(pool: &sqlx::PgPool, id: &str) -> (bool, bool) {
        // (pending_approval, processed_at IS NOT NULL)
        sqlx::query_as::<_, (bool, bool)>(
            "SELECT pending_approval, processed_at IS NOT NULL FROM inbound_messages WHERE id = $1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("draft row must exist")
    }

    async fn claim(
        pool: &sqlx::PgPool,
        id: &str,
    ) -> Result<
        (
            sqlx::PgTransaction<'static>,
            Option<(
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
            )>,
        ),
        sqlx::Error,
    > {
        let mut tx = pool.begin().await?;
        let row = sqlx::query_as::<
            _,
            (
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
            ),
        >(CLAIM_DRAFT_FOR_APPROVAL_SQL)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        Ok((tx, row))
    }

    /// The approval path binds the canonical VARCHAR id without a UUID
    /// cast: a non-UUID `inb_…` id claims its draft (this exact statement
    /// errored with `operator does not exist: character varying = uuid`
    /// before F11), and the claim is conditional — a second claim of the
    /// same draft matches nothing.
    #[tokio::test]
    async fn approval_binds_canonical_varchar_id() {
        let Some(pool) = isolated_pool("varchar").await else {
            eprintln!("skipping approval_binds_canonical_varchar_id: TEST_DATABASE_URL not set");
            return;
        };
        let id = canonical_draft_id();
        insert_draft(&pool, &id, true).await;

        let (tx, row) = claim(&pool, &id)
            .await
            .expect("claim must bind a varchar id");
        let (tenant, from, subject, reply) = row.expect("pending draft must be claimable");
        assert_eq!(tenant.as_deref(), Some("test-f11-tenant"));
        assert_eq!(from.as_deref(), Some("customer@x.ee"));
        assert_eq!(subject.as_deref(), Some("Re: invoice"));
        assert_eq!(reply.as_deref(), Some("please approve"));
        tx.commit().await.expect("commit claim");

        assert_eq!(pending_state(&pool, &id).await, (false, true));

        // Conditional claim semantics: the handled draft cannot be claimed
        // again.
        let (tx, row) = claim(&pool, &id).await.expect("second claim queries fine");
        assert!(row.is_none(), "handled draft must not be claimable");
        tx.rollback().await.expect("rollback no-op claim");

        pool.close().await;
    }

    /// Concurrent approvals: exactly one claim wins, so exactly one reply
    /// can be enqueued. Each racing attempt is a full approval flow
    /// (claim -> enqueue -> commit): the loser's UPDATE blocks on the
    /// winner's row lock and then, once the winner commits, matches
    /// nothing — so only the winner's transaction ever persists a reply.
    #[tokio::test]
    async fn concurrent_approvals_exactly_one_reply() {
        let Some(pool) = isolated_pool("concurrent").await else {
            eprintln!("skipping concurrent_approvals_exactly_one_reply: TEST_DATABASE_URL not set");
            return;
        };
        let id = canonical_draft_id();
        insert_draft(&pool, &id, true).await;

        let attempt = |pool: sqlx::PgPool, id: String| async move {
            let mut tx = pool.begin().await.expect("approval begins a transaction");
            let row = sqlx::query_as::<
                _,
                (
                    Option<String>,
                    Option<String>,
                    Option<String>,
                    Option<String>,
                ),
            >(CLAIM_DRAFT_FOR_APPROVAL_SQL)
            .bind(&id)
            .fetch_optional(&mut *tx)
            .await
            .expect("claim query");
            // In the handler, the reply/outbox insert happens here —
            // inside the claim's transaction, before the commit.
            if row.is_some() {
                tx.commit().await.expect("winner commits claim and reply");
            } else {
                tx.rollback().await.expect("loser rolls back");
            }
            row.is_some()
        };

        let (won_first, won_second) = tokio::time::timeout(Duration::from_secs(30), async {
            tokio::join!(
                attempt(pool.clone(), id.clone()),
                attempt(pool.clone(), id.clone())
            )
        })
        .await
        .expect("concurrent approvals must not deadlock");
        assert_eq!(
            usize::from(won_first) + usize::from(won_second),
            1,
            "exactly one approve may win the claim, so exactly one reply is enqueued"
        );

        // The approval was consumed exactly once.
        assert_eq!(pending_state(&pool, &id).await, (false, true));
        // And no further claim is possible.
        let (tx, row) = claim(&pool, &id)
            .await
            .expect("post-commit claim queries fine");
        assert!(row.is_none());
        tx.rollback().await.expect("rollback final claim");

        pool.close().await;
    }

    /// Failed enqueue leaves a recoverable draft: the enqueue runs inside
    /// the claim's transaction, so when it fails the claim rolls back and
    /// the draft stays pending and claimable again.
    #[tokio::test]
    async fn failed_enqueue_leaves_recoverable_draft() {
        let Some(pool) = isolated_pool("recoverable").await else {
            eprintln!(
                "skipping failed_enqueue_leaves_recoverable_draft: TEST_DATABASE_URL not set"
            );
            return;
        };
        let id = canonical_draft_id();
        insert_draft(&pool, &id, true).await;

        // Claim succeeded, but the enqueue "failed" (modeled by the
        // handler's error path: roll back before anything commits).
        let (tx, row) = claim(&pool, &id)
            .await
            .expect("claim before failed enqueue");
        assert!(row.is_some(), "draft must be claimable");
        tx.rollback().await.expect("enqueue-failure rollback");

        // The draft is untouched and recoverable.
        assert_eq!(pending_state(&pool, &id).await, (true, false));
        let (tx, row) = claim(&pool, &id).await.expect("draft is claimable again");
        assert!(row.is_some(), "recovered draft must be claimable");
        tx.commit().await.expect("retry commits");

        pool.close().await;
    }
}
