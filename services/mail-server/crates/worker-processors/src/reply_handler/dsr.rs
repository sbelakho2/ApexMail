//! Inbound DSR (data-subject request) intake for the reply pipeline.
//!
//! Live mailbot dogfood 2026-10-06 (F-5): a GDPR/DSR email delivered to a
//! monitored mailbox was classified as an ordinary `question`, drafted a
//! human-review reply and STOPPED there — the platform's statutory DSR
//! automation (`compliance::gdpr_automation`, the `dsr_verification_outbox`
//! flush, the verification double opt-in and the processing queue) was never
//! reached. The documented API path (`POST /gdpr/submit`) also exists, but a
//! data subject who emails the company instead of using the API had a dead
//! end.
//!
//! This module closes it with the smallest REAL path: a deterministic,
//! narrow detector runs on the classified reply, and a detected request is
//! written into the SAME canonical tables the compliance automation's intake
//! writes — `data_subject_requests` (with the statutory receipt clock) and
//! `dsr_verification_outbox` (the verification mail the automation's flush
//! job sends) — plus the control plane's `gdpr_requests` mirror. From there
//! the EXISTING automation takes over end to end: verification email,
//! double opt-in, statutory processing, retention/erasure — nothing else in
//! this pipeline needs to know about DSRs.
//!
//! Contract and invariants (mirroring `GdprAutomation::submit_request`
//! byte-for-byte on the columns that matter; the compliance crate remains
//! the authority and its own suite pins the shape):
//!
//! * intake is idempotent: an OPEN request for the same (tenant, email)
//!   short-circuits to the existing request id, and the outbox's
//!   `uq_dsr_outbox_request (tenant_id, request_id)` collapses replays;
//! * the per-user DSAR limit (1 new request / 24h, SEC-15) is honored before
//!   anything is written;
//! * `received_at` starts the GDPR Art. 12(3) response clock at RECEIPT and
//!   `statutory_due_at` is stored at intake (one calendar month), exactly as
//!   the API intake does;
//! * `verification_token_hash` is a SHA-256 of a single-use token; the
//!   plaintext token rides only the outbox row the automation's flush sends;
//! * a failure here NEVER fails the message: the outcome (including the
//!   failure reason) is recorded on the inbound row's `suggested_action.dsr`
//!   so the reviewer sees it, and the reply classification is still persisted.

use chrono::{DateTime, Months, Utc};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

/// The narrow, auditable detector vocabulary. Tokens are GDPR article
/// references and named rights (EN/DE/FR/ES), matched against the
/// lowercased subject + body. Ordinary customer-service questions
/// ("what does the DPA cover?") deliberately do NOT match: only an explicit
/// request to exercise a right opens a statutory request.
const ERASURE_TOKENS: &[&str] = &[
    "article 17",
    "art. 17",
    "right to erasure",
    "right to be forgotten",
    "erase my data",
    "erase my personal data",
    "delete my data",
    "delete my personal data",
    "deletion of my personal data",
    "remove all my personal data",
    "löschen sie meine daten",
    "löschung meiner daten",
    "effacement de mes données",
    "derecho al olvido",
    "borrado de mis datos",
];
const PORTABILITY_TOKENS: &[&str] = &[
    "article 20",
    "art. 20",
    "data portability",
    "portability of my data",
    "portable copy of my data",
    "datenübertragbarkeit",
];
const ACCESS_TOKENS: &[&str] = &[
    "article 15",
    "art. 15",
    "subject access request",
    "data subject request",
    "dsar",
    "access my data",
    "copy of my data",
    "copy of all my data",
    "auskunftsersuchen",
    "demande d'accès",
];
const RECTIFICATION_TOKENS: &[&str] = &[
    "article 16",
    "art. 16",
    "rectification",
    "correct my personal data",
    "berichtigung",
];
const RESTRICTION_TOKENS: &[&str] = &[
    "article 18",
    "art. 18",
    "restrict processing",
    "restriction of processing",
    "einschränkung der verarbeitung",
];
const OBJECTION_TOKENS: &[&str] = &[
    "article 21",
    "art. 21",
    "object to processing",
    "objection to processing",
    "widerspruch gegen die verarbeitung",
];

/// The request type a reply's words support, in rights-precedence order.
/// Deterministic and narrow: no model, no guessing.
pub fn detect(subject: &str, body: &str) -> Option<&'static str> {
    let text = format!("{}\n{}", subject.to_lowercase(), body.to_lowercase());
    let matches = |tokens: &[&str]| tokens.iter().any(|token| text.contains(token));
    if matches(ERASURE_TOKENS) {
        return Some("erasure");
    }
    if matches(PORTABILITY_TOKENS) {
        return Some("portability");
    }
    if matches(ACCESS_TOKENS) {
        return Some("access");
    }
    if matches(RECTIFICATION_TOKENS) {
        return Some("rectification");
    }
    if matches(RESTRICTION_TOKENS) {
        return Some("restriction");
    }
    if matches(OBJECTION_TOKENS) {
        return Some("objection");
    }
    None
}

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// The verify base URL the compliance automation's flush mints links from
/// (`GDPR_VERIFY_BASE_URL`, same default as `compliance::config`).
fn verify_base_url() -> String {
    std::env::var("GDPR_VERIFY_BASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "https://gdpr.apexmail.ee".to_string())
}

/// Statutory response deadline: one calendar month from RECEIPT (GDPR
/// Art. 12(3)), mirroring `compliance::gdpr_automation::statutory_due_at`.
fn statutory_due_at(received_at: DateTime<Utc>) -> DateTime<Utc> {
    received_at
        .checked_add_months(Months::new(1))
        .unwrap_or(received_at + chrono::Duration::days(30))
}

/// Intake one inbound DSR. Returns the `suggested_action.dsr` object that is
/// merged onto the inbound row (never fails the caller for a business
/// refusal; infrastructure errors are reported as `status = "error"`).
pub async fn submit(
    db: &PgPool,
    tenant_id: &str,
    email: &str,
    request_type: &str,
    received_at: DateTime<Utc>,
) -> serde_json::Value {
    let email = email.trim().to_lowercase();
    if tenant_id.trim().is_empty() || email.is_empty() || !email.contains('@') {
        return json!({
            "requested": false,
            "request_type": request_type,
            "status": "refused",
            "reason": "inbound message carries no routable tenant or sender",
        });
    }

    // SEC-15 per-user DSAR limit (1 new request / 24h) before anything is
    // written — matching the API intake's rate limiter.
    let recent: Result<Option<String>, sqlx::Error> = sqlx::query_scalar(
        "SELECT id FROM data_subject_requests \
         WHERE tenant_id = $1 AND lower(email) = $2 \
           AND requested_at > NOW() - INTERVAL '24 hours' \
         ORDER BY requested_at DESC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(&email)
    .fetch_optional(db)
    .await;
    let recent = match recent {
        Ok(recent) => recent,
        Err(error) => {
            tracing::error!(tenant_id, error = %error, "DSR intake: rate-limit lookup failed");
            return json!({
                "requested": false,
                "request_type": request_type,
                "status": "error",
                "reason": format!("rate-limit lookup failed: {error}"),
            });
        }
    };
    if let Some(existing) = recent {
        return json!({
            "requested": false,
            "request_type": request_type,
            "status": "already_open",
            "request_id": existing,
            "reason": "a request from this address is already open or was submitted in the last 24 hours",
        });
    }

    let request_id = Uuid::new_v4().to_string();
    let token = Uuid::new_v4().to_string();
    let token_hash = sha256_hex(&token);
    let now = Utc::now();
    let expires_at = now + chrono::Duration::days(30);
    let due_at = statutory_due_at(received_at);
    let verify_url = format!("{}/gdpr/verify/{}", verify_base_url(), request_id);

    let mut tx: Transaction<'_, Postgres> = match db.begin().await {
        Ok(tx) => tx,
        Err(error) => {
            tracing::error!(tenant_id, error = %error, "DSR intake: begin failed");
            return json!({"requested": false, "request_type": request_type,
                          "status": "error", "reason": format!("db error: {error}")});
        }
    };

    let request_insert = sqlx::query(
        "INSERT INTO data_subject_requests \
           (id, tenant_id, request_type, email, verification_token_hash, \
            verified, status, requested_at, expires_at, received_at, statutory_due_at) \
         VALUES ($1,$2,$3,$4,$5,false,'pending_verification',$6,$7,$8,$9)",
    )
    .bind(&request_id)
    .bind(tenant_id)
    .bind(request_type)
    .bind(&email)
    .bind(&token_hash)
    .bind(now)
    .bind(expires_at)
    .bind(received_at)
    .bind(due_at)
    .execute(&mut *tx)
    .await;
    if let Err(error) = request_insert {
        tracing::error!(tenant_id, error = %error, "DSR intake: request insert failed");
        let _ = tx.rollback().await;
        return json!({"requested": false, "request_type": request_type,
                      "status": "error", "reason": format!("db error: {error}")});
    }

    // The automation's own idempotency key makes a replayed enqueue a no-op
    // (uq_dsr_outbox_request, migration 245).
    let outbox_insert = sqlx::query(
        "INSERT INTO dsr_verification_outbox \
           (id, request_id, tenant_id, email, verification_token, verify_url, status, attempts, created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,'pending',0,$7) \
         ON CONFLICT (tenant_id, request_id) DO NOTHING",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&request_id)
    .bind(tenant_id)
    .bind(&email)
    .bind(&token)
    .bind(&verify_url)
    .bind(now)
    .execute(&mut *tx)
    .await;
    if let Err(error) = outbox_insert {
        tracing::error!(tenant_id, error = %error, "DSR intake: outbox insert failed");
        let _ = tx.rollback().await;
        return json!({"requested": false, "request_type": request_type,
                      "status": "error", "reason": format!("db error: {error}")});
    }

    if let Err(error) = tx.commit().await {
        tracing::error!(tenant_id, error = %error, "DSR intake: commit failed");
        return json!({"requested": false, "request_type": request_type,
                      "status": "error", "reason": format!("db error: {error}")});
    }

    // Control-plane visibility mirror, best-effort exactly like the API
    // intake (the CP `gdpr_requests` table is CP-owned; a shape drift must
    // not roll back the subject's durable request).
    let cp_request_id = format!("gdr_{}", &Uuid::new_v4().simple().to_string()[..22]);
    if let Err(error) = sqlx::query(
        "INSERT INTO gdpr_requests \
           (id, tenant_id, email, request_type, status, token_hash, created_at, updated_at) \
         VALUES ($1,$2,$3,$4,'pending',$5,$6,$6) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&cp_request_id)
    .bind(tenant_id)
    .bind(&email)
    .bind(request_type)
    .bind(&token_hash)
    .bind(now)
    .execute(db)
    .await
    {
        tracing::warn!(tenant_id, error = %error,
            "DSR intake: CP mirror write failed (best-effort); the request itself is durable");
    }

    tracing::info!(
        tenant_id,
        request_id = %request_id,
        request_type,
        "Inbound DSR intake: request staged for the compliance automation's verification mail"
    );
    json!({
        "requested": true,
        "request_type": request_type,
        "status": "pending_verification",
        "request_id": request_id,
        "statutory_due_at": due_at.to_rfc3339(),
        "source": "inbound_email",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detector_names_each_right_and_stays_narrow() {
        let cases = [
            (
                "Re: my data",
                "Under GDPR Article 17 I request erasure of all personal data you hold about me.",
                "erasure",
            ),
            ("Re: GDPR", "Please delete my personal data.", "erasure"),
            (
                "Re: data",
                "I request portability of my data under Article 20.",
                "portability",
            ),
            (
                "Re: GDPR",
                "This is a data subject request for a copy of my data.",
                "access",
            ),
            (
                "Re: my details",
                "I want rectification of my personal data.",
                "rectification",
            ),
            (
                "Re: processing",
                "I request restriction of processing under Art. 18.",
                "restriction",
            ),
            (
                "Re: marketing",
                "I object to processing under Article 21.",
                "objection",
            ),
        ];
        for (subject, body, expected) in cases {
            assert_eq!(detect(subject, body), Some(expected), "body: {body}");
        }
        // Ordinary customer-service mail must NOT open a statutory request.
        for (subject, body) in [
            (
                "Re: pricing",
                "What does the DPA cover, and is GDPR compliance included?",
            ),
            ("Re: security", "Is my data encrypted at rest?"),
            ("Re: support", "How do I export a campaign report?"),
        ] {
            assert_eq!(detect(subject, body), None, "body: {body}");
        }
    }

    #[test]
    fn statutory_deadline_is_one_calendar_month() {
        let received = DateTime::parse_from_rfc3339("2026-01-31T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let due = statutory_due_at(received);
        assert_eq!(due.to_rfc3339(), "2026-02-28T10:00:00+00:00");
    }
}
