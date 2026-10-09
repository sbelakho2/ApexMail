//! Human approval surface for AI-generated inbound-reply drafts.
//!
//! The email agent (ai-service) writes drafts with `pending_approval = true`
//! and NEVER sends anything. This surface is the missing reader: operators
//! list pending drafts, approve (which sends the reply through the
//! platform's verified system sender — `queue_system_email`, attributed to
//! the system tenant that owns the sending domain) or reject them.
//!
//! Consent guarantee (F4, live-mailbot dogfood): an AI-composed reply is a
//! MARKETING-class send (`email_queue.message_category` defaults to
//! 'marketing'), so approval runs the SAME shared send-admission consent gate
//! as the REST send path. A recipient without an ACTIVE marketing consent
//! record is refused with the enforcer's named reason; the claim rolls back,
//! nothing is queued, and the draft stays pending and recoverable.
//!
//! Audit guarantee (external-audit P1): every decision's evidence is written
//! INSIDE the transaction that applies the decision, and its failure aborts
//! the decision — approve (claim + queued reply + audit row) and reject
//! (claim + audit row) commit atomically or not at all. A decision can
//! never take effect without its durable actor-attributed record, and
//! evidence is never written after the effect has committed. The one
//! effect-less path (a refused approval of an unroutable draft, whose claim
//! rolls back) records its evidence in its own committed write before the
//! error response.

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

/// The CP drafts list, with the defense-in-depth tenant scope.
///
/// `$1` (`is_system_tenant`) is the operator flag: a system-tenant caller
/// (the control-plane gate's ONLY admitted caller) reviews every tenant's
/// queue. Any other caller — reachable only if the gate were ever bypassed —
/// is restricted by `tenant_id = $2` inside the SQL itself, so another
/// tenant's rows can never be selected, whatever the middleware did.
const LIST_DRAFTS_SQL: &str = r#"
        SELECT id, tenant_id, from_email, subject, ai_response, received_at
        FROM inbound_messages
        WHERE pending_approval = true
          AND ai_response IS NOT NULL
          AND ($1 OR tenant_id = $2)
        ORDER BY received_at ASC
        LIMIT 100
"#;

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
    let (is_system_tenant, tenant_id) = draft_scope(&state, &auth).await?;

    let rows: Vec<(
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as(LIST_DRAFTS_SQL)
        .bind(is_system_tenant)
        .bind(&tenant_id)
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

/// Defense-in-depth scope for every CP drafts statement: the system-tenant
/// operator manages the platform queue across tenants; any other caller is
/// pinned to its own tenant by the SQL predicate, so a future regression in
/// the upstream gate cannot turn a tenant credential into a cross-tenant
/// read or write. Mirrors `require_system_tenant`'s membership test (the
/// literal `system` id, else `tenants.slug = 'system'`).
async fn draft_scope(state: &AppState, auth: &AuthUser) -> Result<(bool, String), ApiError> {
    let is_system = if auth.tenant_id == "system" {
        true
    } else {
        crate::routes::web::is_system_tenant(state, &auth.tenant_id)
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "draft scope: system-tenant lookup failed");
                ApiError::Internal("authentication error".into())
            })?
    };
    Ok((is_system, auth.tenant_id.clone()))
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
/// `$2`/`$3` carry the same defense-in-depth tenant scope as the list: a
/// caller outside the system tenant can only ever consume its own rows.
const CLAIM_DRAFT_FOR_APPROVAL_SQL: &str = r#"
    UPDATE inbound_messages
    SET pending_approval = false, processed_at = NOW()
    WHERE id = $1
      AND pending_approval = true
      AND ai_response IS NOT NULL
      AND ($2 OR tenant_id = $3)
    RETURNING tenant_id, from_email, subject, ai_response,
              (suggested_action->>'first_response') = 'true',
              received_at,
              suggested_action->>'first_response_request_id'
"#;

/// Actor-attributed audit for AI-draft decisions (P1-4/P2-2 + external-audit
/// P1): an approved AI reply is a platform-sent message to a customer — the
/// operator who approved it (tenant + user) and the routed tenant must be on
/// record. The entry is written INSIDE the caller's open transaction and its
/// failure is PROPAGATED, not swallowed: the decision evidence commits
/// atomically with the decision's effect, or the effect rolls back with the
/// failed evidence write. This is the transaction-scoped
/// [`crate::audit_log::insert_audit_log_in_tx_with_env`] variant — never the
/// best-effort pool writer, which could leave an effect (a queued
/// platform-sent reply, a consumed claim) with no durable decision record.
async fn log_draft_audit_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    is_production: bool,
    auth: &AuthUser,
    action: &str,
    draft_id: &str,
    metadata: serde_json::Value,
) -> Result<(), sqlx::Error> {
    crate::audit_log::insert_audit_log_in_tx_with_env(
        tx,
        is_production,
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        action,
        "ai_draft",
        Some(draft_id),
        metadata,
        None,
        None,
        chrono::Utc::now(),
    )
    .await
}

async fn approve_draft(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    body: Option<Json<ApproveBody>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["*"])?;
    let note = body.map(|Json(b)| b.note).unwrap_or_default();
    approve_draft_core(&state, &auth, &id, &note).await
}

/// The approval flow, shared by the JSON API and the control-plane review
/// page's PRG handler: claim, enqueue on the (first-response aware) priority
/// lane, close the request, write the actor-attributed audit — one
/// transaction, exactly as the JSON contract documents.
pub(crate) async fn approve_draft_core(
    state: &AppState,
    auth: &AuthUser,
    id: &str,
    note: &str,
) -> Result<Json<serde_json::Value>, ApiError> {
    let note = note.to_string();
    let id = id.to_string();

    // The reply/outbox rows, the decision evidence, and the approval
    // consumption commit together: the enqueue AND the audit row are
    // persisted BEFORE the pending_approval flip becomes visible, so a
    // crash or a failed enqueue/audit write can never leave an
    // approved-but-unanswered (consumed) draft behind, nor a queued reply
    // without its approval record (audit F11 + external-audit P1).
    let mut tx = state.db.begin().await?;

    // Defense-in-depth tenant scope (see `draft_scope`): the system-tenant
    // operator manages any tenant's draft; anyone else only their own.
    let (is_system_tenant, caller_tenant) = draft_scope(state, auth).await?;

    // Claim the draft atomically: exactly one approve/reject wins.
    let row: Option<(
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<bool>,
        chrono::DateTime<chrono::Utc>,
        Option<String>,
    )> = sqlx::query_as(CLAIM_DRAFT_FOR_APPROVAL_SQL)
        .bind(&id)
        .bind(is_system_tenant)
        .bind(&caller_tenant)
        .fetch_optional(&mut *tx)
        .await?;

    let Some((
        tenant_id,
        from_email,
        subject,
        reply,
        is_first_response,
        accepted_at,
        first_response_request_id,
    )) = row
    else {
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
        // the transaction, so the draft stays pending and visible. The
        // refused attempt is still decision evidence: it is recorded in its
        // own committed write BEFORE the error response. This is the one
        // path where the evidence cannot share the business transaction
        // (the claim must roll back and nothing commits), which is also why
        // best-effort is correct here: the refusal consumes nothing, so a
        // failed evidence write must not mask the operator-facing
        // validation error.
        let _ = tx.rollback().await;
        crate::audit_log::insert_audit_log_best_effort_with_env(
            &state.db,
            state.config.environment.is_production(),
            Some(auth.tenant_id.as_str()),
            auth.user_id.as_deref(),
            "control_plane.ai_draft.approval_refused",
            "ai_draft",
            Some(&id),
            serde_json::json!({
                "note": note,
                "reason": "draft is missing tenant or sender; cannot route the reply",
            }),
            None,
            None,
        )
        .await;
        return Err(ApiError::Validation(vec![
            "draft is missing tenant or sender; reject it instead".into(),
        ]));
    }

    // F4 (live-mailbot dogfood): an approved AI reply is a MARKETING-class
    // send — `email_queue.message_category` is NOT NULL DEFAULT 'marketing',
    // and this path never asked for a narrower category. The REST send path
    // runs the shared send-admission consent gate ([`SendAdmissionService::
    // enforce_consent`]) before it queues; this approval is the same kind of
    // recipient-carrying admission, so it must run the same gate, or an
    // approved reply could mail a recipient with NO marketing consent on
    // file. The check runs INSIDE the claim's transaction and a refusal (or
    // an unavailable consent store — fail closed) rolls the claim back:
    // nothing is consumed, nothing is queued, and the draft stays pending for
    // review. The refusal is still durable decision evidence via the
    // committed best-effort write below, exactly like the unroutable-draft
    // refusal.
    let admission =
        billing_service::send_admission::SendAdmissionService::new(std::sync::Arc::new(
            billing_service::send_admission::PostgresAdmissionBackend::new(
                state.db.clone(),
                state.redis.clone(),
            ),
        ));
    let category = apexmail_lib::email_headers::message_category::MARKETING;
    {
        match admission
            .enforce_consent(&tenant_id, std::slice::from_ref(&from_email), category)
            .await
        {
            Ok(()) => {}
            Err(billing_service::send_admission::SendAdmissionError::ConsentRefused {
                email,
                reason,
            }) => {
                let _ = tx.rollback().await;
                let refusal = format!("marketing consent required for {email}: {reason}");
                crate::audit_log::insert_audit_log_best_effort_with_env(
                    &state.db,
                    state.config.environment.is_production(),
                    Some(auth.tenant_id.as_str()),
                    auth.user_id.as_deref(),
                    "control_plane.ai_draft.approval_refused",
                    "ai_draft",
                    Some(&id),
                    serde_json::json!({
                        "note": note,
                        "reason": refusal,
                        "routedTenantId": tenant_id,
                        "recipient": email,
                    }),
                    None,
                    None,
                )
                .await;
                return Err(ApiError::Validation(vec![refusal]));
            }
            Err(error) => {
                // FAIL CLOSED: a consent store we cannot read is never
                // permission to send. The claim rolls back and the draft
                // stays pending and approvable once the store recovers.
                let _ = tx.rollback().await;
                tracing::error!(error = %error, draft_id = %id, "approve: consent lookup failed");
                return Err(ApiError::Internal(
                    "could not verify the recipient's marketing consent; draft still pending"
                        .into(),
                ));
            }
        }
    }

    // P1-4: route through the platform's verified system sender. The
    // previous hand-rolled email_queue INSERT hardcoded
    // `support@apexmail.ee` as the from-address while attributing the row to
    // the CUSTOMER's tenant — the customer neither owns apexmail.ee (SPF/
    // DKIM alignment broken) nor sent the mail. `queue_system_email`
    // enforces system-sender readiness under lock and attributes the queue
    // row to the system tenant that actually owns the sending domain.
    // A first-response draft rides the priority lane (plan §5.4): the lead
    // promise outranks ordinary platform mail, and the enqueue moment is
    // where the measured accept->enqueue latency lands.
    let priority = if is_first_response.unwrap_or(false) {
        crate::routes::system_sender::QUEUE_PRIORITY_FIRST_RESPONSE
    } else {
        crate::routes::system_sender::QUEUE_PRIORITY_DEFAULT
    };
    // R6 (review §12.1/R1 finding): the approval path previously enqueued
    // with an EMPTY html_body. The queue layer stores presentation verbatim
    // and refuses empty bodies (`system email refused: callers must supply
    // a non-empty html_body and text_body`), so every approval answered 500
    // and the draft could never leave the queue. The draft's own text is
    // rendered through the SAME shared transactional shell every other
    // platform mail uses (viewport, background/foreground pair, footer),
    // escaped paragraph by paragraph: the AI reply is the message body,
    // never dropped, never wrapped in a second, divergent shell.
    let heading = if subject.trim().is_empty() {
        "A message from the ApexMail sales team".to_string()
    } else {
        subject.clone()
    };
    let reply_html: String = crate::routes::helpers::html_escape(&reply)
        .split("\n\n")
        .map(|paragraph| format!("<p>{}</p>", paragraph.replace('\n', "<br/>")))
        .collect();
    let html_body = crate::routes::system_sender::render_transactional_email(
        &crate::routes::system_sender::TransactionalEmail {
            document_title: &heading,
            heading: &heading,
            body_html: &reply_html,
            // A direct reply to someone who wrote in carries no action
            // buttons — only the message.
            actions: &[],
            footer_link: true,
        },
    );
    let text_body = reply.clone();
    let message_uuid = match crate::routes::system_sender::queue_system_email_in_transaction(
        &mut tx,
        &from_email,
        &subject,
        &html_body,
        &text_body,
        vec!["ai-draft-approval".to_string()],
        priority,
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

    if is_first_response.unwrap_or(false) {
        // The SLO's measured interval: from the platform ACCEPTING the lead
        // (the synthesized row's received_at) to the reply being durably
        // enqueued. Human review time is deliberately excluded — this is the
        // automated portion the platform controls (docs/operations/
        // first-response-slo.md).
        let latency = (chrono::Utc::now() - accepted_at).num_seconds().max(0) as f64;
        metrics::histogram!("first_response_latency_seconds").record(latency);
        if let Some(request_id) = first_response_request_id.as_deref() {
            // The request becomes terminal once its reply left the queue;
            // best-effort INSIDE the transaction so it commits with the send.
            // `queued_at` IS the approval marker (migration 241: "a human
            // approval is the next step, not a state here"; migration 244
            // indexes it for the queue-side SLO percentiles). The old
            // `state = 'pending'` guard never matched a drafted lead — the
            // mailbot always moves the request to 'drafted' while it waits
            // for the human — so queued_at stayed NULL and the measured
            // accept→enqueue interval had no end for every approved reply
            // (dogfood 2026-10-06). Idempotent on queued_at so a repeated
            // approval cannot re-stamp it.
            let _ = sqlx::query(
                "UPDATE first_response_requests \
                 SET updated_at = NOW(), queued_at = NOW() \
                 WHERE id = $1 AND queued_at IS NULL",
            )
            .bind(request_id)
            .execute(&mut *tx)
            .await;
        }
    }

    // External-audit P1: the decision evidence is written INSIDE the same
    // transaction, BEFORE the commit — approval claim, queued reply, and
    // audit row commit atomically or not at all. A failed audit write rolls
    // back the claim AND the queued reply, so platform-originated mail can
    // never be durably queued without its durable operator-attributed
    // approval record. (The evidence is never written after the commit:
    // the previous post-commit best-effort write left a sent reply with no
    // decision record whenever that write failed.)
    log_draft_audit_in_tx(
        &mut tx,
        state.config.environment.is_production(),
        auth,
        "control_plane.ai_draft.approved",
        &id,
        serde_json::json!({
            "note": note.clone(),
            "routedTenantId": tenant_id.clone(),
            "recipient": from_email.clone(),
            "queuedMessageId": message_uuid.to_string(),
        }),
    )
    .await?;

    // Commit makes the consumption of the approval visible only now, with
    // the reply and its audit evidence already persisted in the same
    // transaction.
    tx.commit().await?;

    tracing::info!(
        operator = %auth.user_id.clone().unwrap_or_default(),
        draft_id = %id,
        tenant_id = %tenant_id,
        note = %note,
        "AI reply draft APPROVED and queued"
    );
    Ok(Json(serde_json::json!({
        "approved": true,
        "queued_message_id": message_uuid.to_string(),
    })))
}

/// Reject a pending draft, claiming it atomically and returning the routed
/// tenant for the audit record. Same canonical VARCHAR id binding (audit
/// F11).
const REJECT_DRAFT_SQL: &str = r#"
    UPDATE inbound_messages
    SET pending_approval = false, processed_at = NOW()
    WHERE id = $1
      AND pending_approval = true
      AND ($2 OR tenant_id = $3)
    RETURNING tenant_id
"#;

async fn reject_draft(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    body: Option<Json<ApproveBody>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["*"])?;
    let note = body.map(|Json(b)| b.note).unwrap_or_default();
    reject_draft_core(&state, &auth, &id, &note).await
}

/// The rejection flow, shared by the JSON API and the control-plane review
/// page's PRG handler.
pub(crate) async fn reject_draft_core(
    state: &AppState,
    auth: &AuthUser,
    id: &str,
    note: &str,
) -> Result<Json<serde_json::Value>, ApiError> {
    let note = note.to_string();
    let id = id.to_string();

    // Same guarantee as approve (external-audit P1): the rejection claim and
    // its actor-attributed evidence commit atomically — a failed audit
    // write rolls the claim back, so a rejection either happens fully on
    // record or not at all, leaving the draft pending and rejectable.
    let mut tx = state.db.begin().await?;

    // Same defense-in-depth tenant scope as the approve claim.
    let (is_system_tenant, caller_tenant) = draft_scope(state, auth).await?;

    let routed_tenant_id: Option<(Option<String>,)> = sqlx::query_as(REJECT_DRAFT_SQL)
        .bind(&id)
        .bind(is_system_tenant)
        .bind(&caller_tenant)
        .fetch_optional(&mut *tx)
        .await?;

    let Some((routed_tenant_id,)) = routed_tenant_id else {
        // Dropping the transaction rolls the claim back — nothing consumed.
        // No decision happened here (the draft is unknown or was already
        // handled, and the decision that consumed it is already on the
        // audit record), so there is nothing to evidence.
        return Err(ApiError::NotFound(
            "draft not found or already handled".into(),
        ));
    };

    log_draft_audit_in_tx(
        &mut tx,
        state.config.environment.is_production(),
        auth,
        "control_plane.ai_draft.rejected",
        &id,
        serde_json::json!({
            "note": note.clone(),
            "routedTenantId": routed_tenant_id,
        }),
    )
    .await?;

    tx.commit().await?;

    tracing::info!(
        operator = %auth.user_id.clone().unwrap_or_default(),
        draft_id = %id,
        note = %note,
        "AI reply draft REJECTED"
    );
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
            received_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            -- The first-response marker the claim reads (plan §5.4).
            suggested_action JSONB
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
        insert_draft_for(pool, id, "test-f11-tenant", pending).await;
    }

    async fn insert_draft_for(pool: &sqlx::PgPool, id: &str, tenant: &str, pending: bool) {
        sqlx::query(
            "INSERT INTO inbound_messages (id, tenant_id, from_email, subject, ai_response, pending_approval) \
             VALUES ($1, $2, 'customer@x.ee', 'Re: invoice', 'please approve', $3)",
        )
        .bind(id)
        .bind(tenant)
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
                Option<bool>,
                chrono::DateTime<chrono::Utc>,
                Option<String>,
            )>,
        ),
        sqlx::Error,
    > {
        // Same scope the handler passes for a NON-system caller: the draft
        // helper row belongs to `test-f11-tenant`, so the claim succeeds.
        claim_as(pool, id, false, "test-f11-tenant").await
    }

    async fn claim_as(
        pool: &sqlx::PgPool,
        id: &str,
        is_system_tenant: bool,
        caller_tenant: &str,
    ) -> Result<
        (
            sqlx::PgTransaction<'static>,
            Option<(
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<bool>,
                chrono::DateTime<chrono::Utc>,
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
                Option<bool>,
                chrono::DateTime<chrono::Utc>,
                Option<String>,
            ),
        >(CLAIM_DRAFT_FOR_APPROVAL_SQL)
        .bind(id)
        .bind(is_system_tenant)
        .bind(caller_tenant)
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
        let (tenant, from, subject, reply, first_response, _accepted_at, request_ref) =
            row.expect("pending draft must be claimable");
        // SQL three-valued logic: a NULL suggested_action yields NULL here,
        // which the handler treats as not-a-first-response.
        assert_eq!(first_response, None, "an ordinary draft has no marker");
        assert_eq!(request_ref, None);
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

    /// Defense-in-depth (dogfood scope extension 2026-10-07): every CP
    /// drafts statement carries the tenant predicate in SQL, so even IF the
    /// system-tenant gate were bypassed, a caller could only ever list,
    /// claim or reject its OWN tenant's rows. The system-tenant operator's
    /// cross-tenant queue is preserved by the `$is_system` arm.
    #[tokio::test]
    async fn another_tenants_draft_is_unreachable_without_the_system_tenant(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Some(pool) = isolated_pool("tenant_scope").await else {
            eprintln!(
                "skipping another_tenants_draft_is_unreachable_without_the_system_tenant: \
                 TEST_DATABASE_URL not set"
            );
            return Ok(());
        };
        // Two distinct canonical-shaped ids (VARCHAR(26), `inb_` + 22 hex).
        let a = canonical_draft_id();
        let b = format!("inb_{}", "fedcba9876543210fedcba");
        assert_ne!(a, b);
        insert_draft_for(&pool, &a, "tenant-a", true).await;
        insert_draft_for(&pool, &b, "tenant-b", true).await;

        type ListRow = (
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            chrono::DateTime<chrono::Utc>,
        );

        // LIST as tenant A: A's row is visible, B's never.
        let listed: Vec<ListRow> = sqlx::query_as(LIST_DRAFTS_SQL)
            .bind(false)
            .bind("tenant-a")
            .fetch_all(&pool)
            .await
            .expect("tenant-scoped list");
        let ids: Vec<&str> = listed.iter().map(|row| row.0.as_str()).collect();
        assert!(ids.contains(&a.as_str()), "own draft must be listed");
        assert!(
            !ids.contains(&b.as_str()),
            "another tenant's draft must never be listed: {ids:?}"
        );

        // CLAIM as tenant A against B's draft id: nothing matches, and B
        // stays pending (the uncommitted claim rolls back).
        let (tx, row) = claim_as(&pool, &b, false, "tenant-a").await?;
        assert!(
            row.is_none(),
            "a non-system caller must not claim another tenant's draft"
        );
        tx.rollback().await?;
        assert_eq!(
            pending_state(&pool, &b).await,
            (true, false),
            "B's draft must stay pending after the refused claim"
        );

        // REJECT as tenant A against B's draft id: nothing matches either.
        let rejected: Option<(Option<String>,)> = sqlx::query_as(REJECT_DRAFT_SQL)
            .bind(&b)
            .bind(false)
            .bind("tenant-a")
            .fetch_optional(&pool)
            .await
            .expect("tenant-scoped reject");
        assert!(
            rejected.is_none(),
            "a non-system caller must not reject another tenant's draft"
        );
        assert_eq!(
            pending_state(&pool, &b).await,
            (true, false),
            "B's draft must stay pending after the refused reject"
        );

        // The system-tenant operator (the gate's admitted caller) still sees
        // the whole platform queue.
        let all: Vec<ListRow> = sqlx::query_as(LIST_DRAFTS_SQL)
            .bind(true)
            .bind("system")
            .fetch_all(&pool)
            .await
            .expect("system-tenant list");
        let all_ids: Vec<&str> = all.iter().map(|row| row.0.as_str()).collect();
        assert!(
            all_ids.contains(&a.as_str()) && all_ids.contains(&b.as_str()),
            "the operator queue must keep both tenants' drafts: {all_ids:?}"
        );

        let _ = sqlx::query("DELETE FROM inbound_messages WHERE id IN ($1, $2)")
            .bind(&a)
            .bind(&b)
            .execute(&pool)
            .await;
        pool.close().await;
        Ok(())
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
            .bind(false)
            .bind("test-f11-tenant")
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

/// HTTP-surface coverage for the human-approval routes against the
/// canonical schema and the real system-sender machinery.
#[cfg(test)]
mod approval_http_tests {
    use crate::app::test_support::adv::AdvEnv;
    use crate::routes::system_sender::{SYSTEM_DOMAIN, SYSTEM_DOMAIN_ID, SYSTEM_TENANT_ID};

    /// Seed the system sender domain exactly as the signup fixture does:
    /// real DKIM material, encrypted under the test key. The caller holds
    /// `crate::test_db::DKIM_ENV_MUTEX` for the process-global env var.
    async fn seed_system_sender(db: &sqlx::PgPool) {
        let key_pair = apexmail_lib::dkim::generate_dkim_keypair()
            .expect("test DKIM keypair generation must not fail");
        let aad = apexmail_lib::dkim::dkim_private_key_aad(SYSTEM_TENANT_ID, SYSTEM_DOMAIN_ID);
        let encrypted =
            apexmail_lib::dkim::encrypt_dkim_private_key(&key_pair.private_key_pem, &aad)
                .expect("test DKIM private key encryption must not fail");
        let public_key =
            apexmail_lib::dkim::public_key_base64_from_private_key_pem(&key_pair.private_key_pem)
                .expect("test DKIM public key derivation must not fail");
        sqlx::query(
            "INSERT INTO domains (id, tenant_id, name, status, verified, ses_verified,
                                  dkim_enabled, dkim_selector, dkim_public_key, dkim_private_key)
             VALUES ($1, $2, $3, 'verified', true, true, true, 'testsel', $4, $5)
             ON CONFLICT (tenant_id, lower(name)) DO UPDATE
               SET status = 'verified', verified = true, ses_verified = true,
                   dkim_enabled = true, dkim_selector = 'testsel',
                   dkim_public_key = EXCLUDED.dkim_public_key,
                   dkim_private_key = EXCLUDED.dkim_private_key",
        )
        .bind(uuid::Uuid::parse_str(SYSTEM_DOMAIN_ID).expect("system domain id"))
        .bind(SYSTEM_TENANT_ID)
        .bind(SYSTEM_DOMAIN)
        .bind(&public_key)
        .bind(&encrypted)
        .execute(db)
        .await
        .expect("seed system sender");
    }

    /// Grant an ACTIVE marketing consent record for `recipient` under
    /// `tenant`. The shared send admission refuses a marketing-class send for
    /// a recipient without one (`ConsentEnforcer` reads exactly this row).
    async fn grant_marketing_consent(pool: &sqlx::PgPool, tenant: &str, recipient: &str) {
        sqlx::query(
            "INSERT INTO consent_records \
                 (id, tenant_id, subscriber_id, email, consent_type, granted, granted_at, source) \
             VALUES ($1, $2, $3, $4, 'marketing', true, NOW(), 'dogfood-test') \
             ON CONFLICT (tenant_id, subscriber_id, consent_type) DO UPDATE SET \
                 granted = true, granted_at = NOW(), revoked_at = NULL, email = EXCLUDED.email",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(tenant)
        .bind(format!(
            "sub-{tenant}-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ))
        .bind(recipient)
        .execute(pool)
        .await
        .expect("grant marketing consent");
    }

    async fn seed_pending_draft(db: &sqlx::PgPool, id: &str, tenant: &str, from_email: &str) {
        sqlx::query(
            "INSERT INTO inbound_messages
                 (id, tenant_id, from_email, subject, ai_response, pending_approval,
                  is_verp_reply, received_at)
             VALUES ($1, $2, $3, 'Re: invoice', 'please approve', true, false, NOW())
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(id)
        .bind(tenant)
        .bind(from_email)
        .execute(db)
        .await
        .expect("seed draft");
    }

    fn draft_id() -> String {
        format!("inb_{}", &uuid::Uuid::new_v4().simple().to_string()[..22])
    }

    /// SalesCloser plan §5.4: approving a first-response draft queues the
    /// reply on the PRIORITY lane (100 over the default 5) and closes its
    /// request — the two halves of the instant-response chain that meet in
    /// this handler.
    #[test]
    fn first_response_approval_uses_the_priority_lane_and_closes_the_request() {
        let _dkim_guard = crate::test_db::DKIM_ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::env::set_var(
            apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
            "3f7a1c9e2b5d48f01a6c3e792d4b8f15a0c6e3917d2f4b8a5c1e7309d4f2b6a8",
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let Some(pool) = crate::test_db::canonical_pool("ai_draft_first_response").await else {
                return;
            };
            seed_system_sender(&pool).await;
            let env = AdvEnv::admin(pool.clone()).await;
            let tenant = "ten_first_response_00000";
            let from_email = format!(
                "lead-{}@corp.example",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            );
            // F4: the shared send-admission consent gate runs on approval.
            grant_marketing_consent(&pool, tenant, &from_email).await;

            // The request this draft answers. It is seeded in the state the
            // MAILBOT leaves it in ('drafted' — the AI wrote the reply and
            // is waiting for the human), NOT the initial 'pending'. Seeding
            // 'pending' made this test pass while every real approval left
            // queued_at NULL (dogfood 2026-10-06).
            let request_id = format!("frr_{}", &uuid::Uuid::new_v4().simple().to_string()[..22]);
            sqlx::query(
                "INSERT INTO first_response_requests (id, tenant_id, kind, subject_ref, payload, state) \
                 VALUES ($1, 'system', 'contact_form', $2, '{}'::jsonb, 'drafted')",
            )
            .bind(&request_id)
            .bind(format!("lead-{}", &request_id[..10]))
            .execute(&pool)
            .await
            .expect("request row");

            // A pending draft marked as first-response.
            let id = draft_id();
            sqlx::query(
                "INSERT INTO inbound_messages
                     (id, tenant_id, from_email, subject, ai_response, pending_approval,
                      is_verp_reply, received_at, suggested_action)
                 VALUES ($1, $2, $3, 'Contact form: Acme', 'the grounded reply', true, false,
                         NOW() - interval '45 seconds', $4::jsonb)
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(&id)
            .bind(tenant)
            .bind(&from_email)
            .bind(serde_json::json!({
                "first_response": true,
                "first_response_request_id": request_id,
            }))
            .execute(&pool)
            .await
            .expect("seed first-response draft");

            let (status, body) = env
                .post(&format!("/v1/admin/ai/drafts/{id}/approve"), "{}")
                .await;
            assert_eq!(status, axum::http::StatusCode::OK, "{body}");

            // The reply is on the queue at the first-response priority…
            let priorities: Vec<i32> = sqlx::query_scalar(
                "SELECT priority FROM email_queue WHERE \"to\" = $1 \
                 ORDER BY created_at DESC LIMIT 1",
            )
            .bind(&from_email)
            .fetch_all(&pool)
            .await
            .expect("queue rows");
            assert_eq!(
                priorities,
                vec![crate::routes::system_sender::QUEUE_PRIORITY_FIRST_RESPONSE],
                "a first-response reply rides the priority lane"
            );

            // …and the request it answers carries the approval marker: the
            // measured accept→enqueue interval needs a non-NULL queued_at,
            // and the human approval is what supplies it.
            let (queued_at, updated_at): (Option<chrono::DateTime<chrono::Utc>>, chrono::DateTime<chrono::Utc>) =
                sqlx::query_as(
                    "SELECT queued_at, updated_at FROM first_response_requests WHERE id = $1",
                )
                .bind(&request_id)
                .fetch_one(&pool)
                .await
                .expect("request state");
            assert!(
                queued_at.is_some(),
                "approval stamps the request's queued_at — the only marker of the human step"
            );

            // A repeated approval must not re-stamp the interval (the guard
            // is idempotent on queued_at).
            let (status2, _) = env
                .post(&format!("/v1/admin/ai/drafts/{id}/approve"), "{}")
                .await;
            let (_status2b, _) = (status2, ());
            let queued_after: Option<chrono::DateTime<chrono::Utc>> =
                sqlx::query_scalar("SELECT queued_at FROM first_response_requests WHERE id = $1")
                    .bind(&request_id)
                    .fetch_one(&pool)
                    .await
                    .expect("request state");
            assert_eq!(
                queued_after, queued_at,
                "a repeated approval leaves the original enqueue instant intact"
            );
            let _ = updated_at;

            let _ = sqlx::query("DELETE FROM first_response_requests WHERE id = $1")
                .bind(&request_id)
                .execute(&pool)
                .await;
        });
    }

    /// The DKIM env var is process-global: under nextest each test owns a
    /// process; under `cargo test` the DKIM mutex serialises the users.
    #[test]
    fn approval_http_surface_end_to_end() {
        let _dkim_guard = crate::test_db::DKIM_ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::env::set_var(
            apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
            "3f7a1c9e2b5d48f01a6c3e792d4b8f15a0c6e3917d2f4b8a5c1e7309d4f2b6a8",
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let Some(pool) = crate::test_db::canonical_pool("ai_draft_http").await else {
                return;
            };
            seed_system_sender(&pool).await;
            let env = AdvEnv::admin(pool.clone()).await;

            // Empty list.
            let (status, body) = env.get("/v1/admin/ai/drafts").await;
            assert_eq!(status, axum::http::StatusCode::OK, "{body}");
            assert_eq!(body["count"], 0, "{body}");

            // A routable pending draft and one that cannot be routed.
            let id = draft_id();
            seed_pending_draft(
                &pool,
                &id,
                "ten_probe_0000000000000000",
                "buyer@corp.example",
            )
            .await;
            // F4: approvals run the shared send-admission consent gate; the
            // fixture recipient needs an active marketing consent record.
            grant_marketing_consent(&pool, "ten_probe_0000000000000000", "buyer@corp.example")
                .await;
            let broken = draft_id();
            seed_pending_draft(&pool, &broken, "", "").await;

            let (status, body) = env.get("/v1/admin/ai/drafts").await;
            assert_eq!(status, axum::http::StatusCode::OK, "{body}");
            assert!(
                body["count"].as_i64().unwrap_or(0) >= 2,
                "both pending drafts listed: {body}"
            );

            // Approving the unroutable draft is a validation error and the
            // draft stays pending (the claim rolled back).
            let (status, body) = env
                .post(&format!("/v1/admin/ai/drafts/{broken}/approve"), "{}")
                .await;
            assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
            let pending: bool =
                sqlx::query_scalar("SELECT pending_approval FROM inbound_messages WHERE id = $1")
                    .bind(&broken)
                    .fetch_one(&pool)
                    .await
                    .expect("broken draft");
            assert!(pending, "the unroutable draft stays pending");

            // Approving the healthy draft queues the reply.
            let (status, body) = env
                .post(
                    &format!("/v1/admin/ai/drafts/{id}/approve"),
                    r#"{"note":"looks good"}"#,
                )
                .await;
            assert_eq!(status, axum::http::StatusCode::OK, "{body}");
            assert_eq!(body["approved"], true, "{body}");
            let queued: (bool, bool) = sqlx::query_as(
                "SELECT pending_approval = false, processed_at IS NOT NULL \
                 FROM inbound_messages WHERE id = $1",
            )
            .bind(&id)
            .fetch_one(&pool)
            .await
            .expect("approved draft");
            assert_eq!(queued, (true, true));
            let reply: Option<(String,)> =
                sqlx::query_as("SELECT subject FROM messages WHERE tenant_id = $1 LIMIT 1")
                    .bind(crate::routes::system_sender::SYSTEM_TENANT_ID)
                    .fetch_optional(&pool)
                    .await
                    .expect("queued message");
            assert!(reply.is_some(), "a system message row was queued");

            // Approving again is a 404 (the claim is consumed).
            let (status, _body) = env
                .post(&format!("/v1/admin/ai/drafts/{id}/approve"), "{}")
                .await;
            assert_eq!(status, axum::http::StatusCode::NOT_FOUND);

            // Unknown ids are 404s.
            let (status, _body) = env.post("/v1/admin/ai/drafts/inb_nope/approve", "{}").await;
            assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
            let (status, _body) = env.post("/v1/admin/ai/drafts/inb_nope/reject", "{}").await;
            assert_eq!(status, axum::http::StatusCode::NOT_FOUND);

            // Reject consumes the remaining pending draft.
            let (status, body) = env
                .post(
                    &format!("/v1/admin/ai/drafts/{broken}/reject"),
                    r#"{"note":"nope"}"#,
                )
                .await;
            assert_eq!(status, axum::http::StatusCode::OK, "{body}");
            assert_eq!(body["rejected"], true);
            let (status, _body) = env
                .post(&format!("/v1/admin/ai/drafts/{broken}/reject"), "{}")
                .await;
            assert_eq!(status, axum::http::StatusCode::NOT_FOUND);

            // External-audit P1: every decision left durable evidence in the
            // SAME commit as its effect — exactly one approved row, one
            // rejected row, and one refused-attempt row (the unroutable
            // approval above); the 404 re-attempts wrote nothing.
            for (action, expected) in [
                ("control_plane.ai_draft.approved", 1_i64),
                ("control_plane.ai_draft.rejected", 1_i64),
                ("control_plane.ai_draft.approval_refused", 1_i64),
            ] {
                let count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM audit_logs WHERE resource = 'ai_draft' AND action = $1",
                )
                .bind(action)
                .fetch_one(&pool)
                .await
                .expect("audit evidence count");
                assert_eq!(count, expected, "audit rows for {action}");
            }

            // Customers are refused outright.
            let (customer, _t) = AdvEnv::tenant(pool.clone(), &["*"]).await;
            let (status, _body) = customer.get("/v1/admin/ai/drafts").await;
            assert_eq!(status, axum::http::StatusCode::FORBIDDEN);

            pool.close().await;
        });
    }

    /// The shared send-admission consent gate (F4) applies to AI-draft
    /// approvals: an AI-composed reply is a MARKETING-class send, so a
    /// recipient with no active marketing consent record must be REFUSED with
    /// the enforcer's named reason — the draft stays pending (nothing
    /// consumed), nothing is queued and nothing can reach Mailpit. The same
    /// draft then approves cleanly once an active consent record exists.
    #[test]
    fn approve_refuses_without_marketing_consent_and_stays_recoverable() {
        let _dkim_guard = crate::test_db::DKIM_ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::env::set_var(
            apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
            "3f7a1c9e2b5d48f01a6c3e792d4b8f15a0c6e3917d2f4b8a5c1e7309d4f2b6a8",
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let Some(pool) = crate::test_db::canonical_pool("ai_draft_consent").await else {
                return;
            };
            seed_system_sender(&pool).await;
            let env = AdvEnv::admin(pool.clone()).await;
            let tenant = "ten_consent_gate_000000";
            let recipient = format!(
                "no-consent-{}@corp.example",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            );
            let id = draft_id();
            seed_pending_draft(&pool, &id, tenant, &recipient).await;

            let (status, body) = env
                .post(&format!("/v1/admin/ai/drafts/{id}/approve"), "{}")
                .await;
            assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
            assert!(
                body.to_string().contains("marketing consent"),
                "the refusal must carry the enforcer's named reason: {body}"
            );

            // Nothing was consumed and nothing was queued.
            let pending: bool =
                sqlx::query_scalar("SELECT pending_approval FROM inbound_messages WHERE id = $1")
                    .bind(&id)
                    .fetch_one(&pool)
                    .await
                    .expect("draft row");
            assert!(
                pending,
                "a consent-refused approval must not consume the draft"
            );
            let queued: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM email_queue WHERE lower(\"to\") = lower($1)",
            )
            .bind(&recipient)
            .fetch_one(&pool)
            .await
            .expect("queue count");
            assert_eq!(
                queued, 0,
                "a consent-refused approval must not queue a reply"
            );

            // An active marketing consent record makes the same draft approvable.
            grant_marketing_consent(&pool, tenant, &recipient).await;
            let (status, body) = env
                .post(&format!("/v1/admin/ai/drafts/{id}/approve"), "{}")
                .await;
            assert_eq!(status, axum::http::StatusCode::OK, "{body}");
            assert_eq!(body["approved"], true, "{body}");

            pool.close().await;
        });
    }

    /// When the system sender cannot be proven ready the enqueue fails and
    /// the approval rolls back: the draft stays pending and recoverable,
    /// and the route answers 500 (an operator-visible failure), not 200.
    #[tokio::test]
    async fn approve_fails_closed_when_the_reply_cannot_be_queued() {
        let Some(pool) = crate::test_db::canonical_pool("ai_draft_no_sender").await else {
            return;
        };
        // NOTE: no seed_system_sender — the readiness lookup fails.
        let env = AdvEnv::admin(pool.clone()).await;
        let id = draft_id();
        seed_pending_draft(
            &pool,
            &id,
            "ten_probe_0000000000000000",
            "buyer@corp.example",
        )
        .await;
        // F4: consent is granted so the armed failure really is the sender
        // readiness arm, not the consent gate.
        grant_marketing_consent(&pool, "ten_probe_0000000000000000", "buyer@corp.example").await;

        let (status, body) = env
            .post(&format!("/v1/admin/ai/drafts/{id}/approve"), "{}")
            .await;
        assert_eq!(
            status,
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "{body}"
        );

        // The claim rolled back — the draft is still pending.
        let pending: bool =
            sqlx::query_scalar("SELECT pending_approval FROM inbound_messages WHERE id = $1")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .expect("draft row");
        assert!(pending, "a failed enqueue must not consume the draft");
        pool.close().await;
    }

    /// External-audit P1, fault-injected: when the audit INSERT fails, the
    /// ENTIRE approval rolls back — the draft stays pending (claim not
    /// consumed), no reply is queued, no evidence row exists, and the very
    /// same draft is approvable again once the fault is disarmed. Decision
    /// evidence and decision effect commit atomically or not at all.
    ///
    /// Sync test + current-thread runtime (like the end-to-end test) so the
    /// process-global DKIM env guard is not held across an await point.
    #[test]
    fn approve_rolls_back_entirely_when_the_audit_write_fails() {
        let _dkim_guard = crate::test_db::DKIM_ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::env::set_var(
            apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
            "3f7a1c9e2b5d48f01a6c3e792d4b8f15a0c6e3917d2f4b8a5c1e7309d4f2b6a8",
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let Some(pool) = crate::test_db::canonical_pool("ai_draft_audit_rollback").await else {
                return;
            };
            // The system sender IS seeded so the enqueue succeeds and the
            // armed failure point is the audit write, not the queue insert.
            seed_system_sender(&pool).await;
            let env = AdvEnv::admin(pool.clone()).await;
            let id = draft_id();
            seed_pending_draft(
                &pool,
                &id,
                "ten_probe_0000000000000000",
                "buyer@corp.example",
            )
            .await;
            // F4: approvals run the shared send-admission consent gate; the
            // fixture recipient needs an active marketing consent record.
            grant_marketing_consent(&pool, "ten_probe_0000000000000000", "buyer@corp.example")
                .await;

            // The first write to `audit_logs` — the decision-evidence INSERT
            // inside the approval transaction — fails.
            crate::routes::fault::arm_write_fault(&pool, "audit_logs", "ai_draft_approve_audit", 0)
                .await
                .expect("arm audit fault");

            let (status, body) = env
                .post(&format!("/v1/admin/ai/drafts/{id}/approve"), "{}")
                .await;
            assert_eq!(
                status,
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "{body}"
            );

            // Nothing committed: the claim rolled back…
            let state: (bool, bool) = sqlx::query_as(
                "SELECT pending_approval, processed_at IS NOT NULL \
                 FROM inbound_messages WHERE id = $1",
            )
            .bind(&id)
            .fetch_one(&pool)
            .await
            .expect("draft row");
            assert_eq!(state, (true, false), "the claim must roll back");
            // …no reply was queued…
            let queued: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE tenant_id = $1")
                    .bind(crate::routes::system_sender::SYSTEM_TENANT_ID)
                    .fetch_one(&pool)
                    .await
                    .expect("count queued system messages");
            assert_eq!(
                queued, 0,
                "a failed audit write must not leave a queued reply"
            );
            // …and no evidence row exists.
            let evidence: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE resource = 'ai_draft'")
                    .fetch_one(&pool)
                    .await
                    .expect("count audit rows");
            assert_eq!(evidence, 0, "the failed evidence write must leave no row");

            // The approval was NOT consumed: with the fault disarmed, the
            // very same draft approves successfully.
            sqlx::query("DROP TRIGGER IF EXISTS _fi_ai_draft_approve_audit ON audit_logs")
                .execute(&pool)
                .await
                .expect("disarm audit fault");
            let (status, body) = env
                .post(&format!("/v1/admin/ai/drafts/{id}/approve"), "{}")
                .await;
            assert_eq!(status, axum::http::StatusCode::OK, "{body}");
            assert_eq!(body["approved"], true, "{body}");

            pool.close().await;
        });
    }

    /// External-audit P1, happy path: the approval's evidence lands in
    /// `audit_logs` in the same commit as the queued reply — canonical
    /// hash-chained shape, operator attribution (the machine admin's system
    /// tenant; user id when the identity carries one), routed tenant,
    /// recipient, note, and the queued message id.
    ///
    /// Sync test + current-thread runtime (like the end-to-end test) so the
    /// process-global DKIM env guard is not held across an await point.
    #[test]
    fn approve_writes_operator_attribution_audit_with_the_reply() {
        let _dkim_guard = crate::test_db::DKIM_ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::env::set_var(
            apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
            "3f7a1c9e2b5d48f01a6c3e792d4b8f15a0c6e3917d2f4b8a5c1e7309d4f2b6a8",
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let Some(pool) = crate::test_db::canonical_pool("ai_draft_audit_commit").await else {
                return;
            };
            seed_system_sender(&pool).await;
            let env = AdvEnv::admin(pool.clone()).await;
            let id = draft_id();
            seed_pending_draft(
                &pool,
                &id,
                "ten_probe_0000000000000000",
                "buyer@corp.example",
            )
            .await;
            // F4: approvals run the shared send-admission consent gate; the
            // fixture recipient needs an active marketing consent record.
            grant_marketing_consent(&pool, "ten_probe_0000000000000000", "buyer@corp.example")
                .await;

            let (status, body) = env
                .post(
                    &format!("/v1/admin/ai/drafts/{id}/approve"),
                    r#"{"note":"ship it"}"#,
                )
                .await;
            assert_eq!(status, axum::http::StatusCode::OK, "{body}");
            let queued_message_id = body["queued_message_id"]
                .as_str()
                .expect("queued message id in the response")
                .to_string();

            let row: (
                String,
                Option<String>,
                String,
                String,
                serde_json::Value,
                Option<String>,
                Option<String>,
            ) = sqlx::query_as(
                "SELECT action, user_id, resource, tenant_id, details, hash, signature \
                 FROM audit_logs WHERE resource = 'ai_draft' AND resource_id = $1",
            )
            .bind(&id)
            .fetch_one(&pool)
            .await
            .expect("approval evidence committed with the reply");
            assert_eq!(row.0, "control_plane.ai_draft.approved");
            assert_eq!(row.1, None, "the machine admin identity has no user id");
            assert_eq!(row.2, "ai_draft");
            assert_eq!(row.3, "system", "operator tenant attribution");
            assert_eq!(row.4["routedTenantId"], "ten_probe_0000000000000000");
            assert_eq!(row.4["recipient"], "buyer@corp.example");
            assert_eq!(row.4["queuedMessageId"], queued_message_id.as_str());
            assert_eq!(row.4["note"], "ship it");
            // Canonical hash-chained shape: the evidence is tamper-evident.
            assert!(row.5.is_some(), "chain hash present");
            assert!(row.6.is_some(), "signature present");

            pool.close().await;
        });
    }

    /// Reject gets the same atomic treatment (external-audit P1): a failed
    /// audit write rolls the rejection claim back — the draft stays pending
    /// and the rejection is retryable; the retry then commits WITH its
    /// actor-attributed evidence.
    #[tokio::test]
    async fn reject_rolls_back_when_the_audit_write_fails() {
        let Some(pool) = crate::test_db::canonical_pool("ai_draft_reject_audit").await else {
            return;
        };
        // No system sender: rejection never enqueues, so the armed failure
        // point can only be the audit write.
        let env = AdvEnv::admin(pool.clone()).await;
        let id = draft_id();
        seed_pending_draft(
            &pool,
            &id,
            "ten_probe_0000000000000000",
            "buyer@corp.example",
        )
        .await;

        crate::routes::fault::arm_write_fault(&pool, "audit_logs", "ai_draft_reject_audit", 0)
            .await
            .expect("arm audit fault");

        let (status, body) = env
            .post(&format!("/v1/admin/ai/drafts/{id}/reject"), "{}")
            .await;
        assert_eq!(
            status,
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "{body}"
        );

        // The claim rolled back: the draft is still pending and rejectable.
        let state: (bool, bool) = sqlx::query_as(
            "SELECT pending_approval, processed_at IS NOT NULL \
             FROM inbound_messages WHERE id = $1",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .expect("draft row");
        assert_eq!(state, (true, false), "the rejection must roll back");

        sqlx::query("DROP TRIGGER IF EXISTS _fi_ai_draft_reject_audit ON audit_logs")
            .execute(&pool)
            .await
            .expect("disarm audit fault");
        let (status, body) = env
            .post(
                &format!("/v1/admin/ai/drafts/{id}/reject"),
                r#"{"note":"nope"}"#,
            )
            .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["rejected"], true, "{body}");

        // The retried rejection committed WITH its evidence.
        let row: (String, String, serde_json::Value) = sqlx::query_as(
            "SELECT action, tenant_id, details FROM audit_logs \
             WHERE resource = 'ai_draft' AND resource_id = $1",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .expect("rejection evidence committed with the claim");
        assert_eq!(row.0, "control_plane.ai_draft.rejected");
        assert_eq!(row.1, "system", "operator tenant attribution");
        assert_eq!(row.2["routedTenantId"], "ten_probe_0000000000000000");
        assert_eq!(row.2["note"], "nope");

        pool.close().await;
    }
}
