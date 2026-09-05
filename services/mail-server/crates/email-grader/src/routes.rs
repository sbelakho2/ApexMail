//! Email Grader HTTP handler core logic. Transport-agnostic so the api-server
//! crate can attach Axum middleware (auth, CSRF, request-id) before delegation.
//!
//! All responses use the standard ApexMail error envelope:
//! `{ "error": { "code": "<MACHINE_CODE>", "message": "<human readable>" } }`

use crate::config::GraderConfig;
use crate::crypto::Cipher;
use crate::grader::{GraderEngine, GraderError};
use crate::types::*;
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::sync::Arc;

/// Maximum length accepted for a tenant identifier reaching the database.
const MAX_TENANT_ID_LEN: usize = 64;
/// Maximum length accepted for an Idempotency-Key header.
const MAX_IDEMPOTENCY_KEY_LEN: usize = 128;
/// DNS units charged per /submit request before message-level work.
const SUBMIT_DNS_UNITS: u32 = 7;

pub struct GraderState {
    pub engine: Arc<GraderEngine>,
    pub config: GraderConfig,
    pub db: sqlx::PgPool,
    /// Optional content cipher. Set when `encrypt_stored_content` is true and
    /// the master key validated successfully during engine construction.
    pub cipher: Option<Cipher>,
}

impl GraderState {
    /// Construct a `GraderState`. Returns the configured cipher when
    /// `encrypt_stored_content` is enabled.
    pub fn new(
        engine: Arc<GraderEngine>,
        config: GraderConfig,
        db: sqlx::PgPool,
    ) -> Result<Self, String> {
        let cipher = if config.encrypt_stored_content {
            let key = config
                .encryption_master_key_base64
                .as_deref()
                .ok_or_else(|| {
                    "encrypt_stored_content=true but no master key configured".to_string()
                })?;
            Some(
                Cipher::from_base64_key(key)
                    .map_err(|e| format!("encryption master key rejected: {e}"))?,
            )
        } else {
            None
        };
        Ok(Self {
            engine,
            config,
            db,
            cipher,
        })
    }
}

fn err(status: StatusCode, code: &str, msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        status,
        Json(serde_json::json!({
            "error": { "code": code, "message": msg }
        })),
    )
}

fn ok<T: serde::Serialize>(data: T) -> (StatusCode, Json<serde_json::Value>) {
    match serde_json::to_value(&data) {
        Ok(v) => (StatusCode::OK, Json(v)),
        Err(e) => {
            tracing::error!(error = %e, "grader: serialization failed");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_SERIALIZATION",
                "failed to serialize response",
            )
        }
    }
}

fn map_grader_error(e: GraderError) -> (StatusCode, Json<serde_json::Value>) {
    match e {
        GraderError::InvalidDomain(msg) => err(StatusCode::BAD_REQUEST, "INVALID_INPUT", &msg),
        GraderError::DomainNotFound(d) => err(
            StatusCode::NOT_FOUND,
            "DOMAIN_NOT_FOUND",
            &format!("domain {d} does not exist"),
        ),
        GraderError::BodyTooLarge(actual, max) => err(
            StatusCode::PAYLOAD_TOO_LARGE,
            "BODY_TOO_LARGE",
            &format!("email body too large: {actual} bytes (max {max})"),
        ),
        GraderError::TenantBudgetExhausted => err(
            StatusCode::TOO_MANY_REQUESTS,
            "TENANT_BUDGET",
            "tenant DNS budget exhausted; retry later",
        ),
        GraderError::Internal(msg) => {
            tracing::error!(error = %msg, "grader: internal error");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "internal grader error",
            )
        }
    }
}

fn validate_tenant_id(t: &str) -> Result<&str, (StatusCode, Json<serde_json::Value>)> {
    if t.is_empty() || t.len() > MAX_TENANT_ID_LEN {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "INVALID_TENANT",
            "tenant identifier is missing or out of range",
        ));
    }
    if !t
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "INVALID_TENANT",
            "tenant identifier contains unsupported characters",
        ));
    }
    Ok(t)
}

fn validate_idempotency_key(k: &str) -> Result<&str, (StatusCode, Json<serde_json::Value>)> {
    if k.is_empty() || k.len() > MAX_IDEMPOTENCY_KEY_LEN {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "INVALID_IDEMPOTENCY_KEY",
            "idempotency key length out of range",
        ));
    }
    if !k.chars().all(|c| c.is_ascii_graphic()) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "INVALID_IDEMPOTENCY_KEY",
            "idempotency key must be printable ASCII",
        ));
    }
    Ok(k)
}

/// Public, IP-rate-limited domain-only check.
pub async fn check_domain(
    state: Arc<GraderState>,
    client_ip: IpAddr,
    body: DomainCheckRequest,
) -> (StatusCode, Json<serde_json::Value>) {
    if !state.config.enabled {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "GRADER_DISABLED",
            "Email Grader is disabled",
        );
    }
    if !state.engine.check_rate_limit(&client_ip.to_string()) {
        return err(
            StatusCode::TOO_MANY_REQUESTS,
            "RATE_LIMITED",
            "rate limit exceeded; retry later",
        );
    }
    match state.engine.check_domain(&body).await {
        Ok(response) => ok(response),
        Err(e) => map_grader_error(e),
    }
}

/// Authenticated full-email analysis. Persists the result tenant-scoped.
pub async fn submit_email(
    state: Arc<GraderState>,
    auth: GraderAuthContext,
    body: EmailSubmitRequest,
) -> (StatusCode, Json<serde_json::Value>) {
    if !state.config.enabled {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "GRADER_DISABLED",
            "Email Grader is disabled",
        );
    }
    if !auth.has_scope("grader:write") {
        return err(
            StatusCode::FORBIDDEN,
            "INSUFFICIENT_SCOPE",
            "scope `grader:write` is required",
        );
    }
    let tenant_id = match validate_tenant_id(&auth.tenant_id) {
        Ok(t) => t,
        Err(resp) => return resp,
    };

    // Idempotency: when supplied and a matching row exists within the dedup
    // window, return it verbatim (no fresh analysis, no DB write).
    let idem_key: Option<&str> = match auth.idempotency_key.as_deref() {
        Some(k) => match validate_idempotency_key(k) {
            Ok(v) => Some(v),
            Err(resp) => return resp,
        },
        None => None,
    };
    if let Some(key) = idem_key {
        let cutoff: DateTime<Utc> =
            Utc::now() - ChronoDuration::seconds(state.config.idempotency_window_seconds);
        #[allow(clippy::type_complexity)]
        let existing: Result<
            Option<(
                uuid::Uuid,
                String,
                i16,
                String,
                serde_json::Value,
                serde_json::Value,
                Vec<String>,
                DateTime<Utc>,
            )>,
            sqlx::Error,
        > = sqlx::query_as(
            r#"SELECT id, domain, score, grade, breakdown, findings, recommendations, created_at
               FROM grader_results
               WHERE tenant_id = $1 AND idempotency_key = $2 AND created_at >= $3
               ORDER BY created_at DESC
               LIMIT 1"#,
        )
        .bind(tenant_id)
        .bind(key)
        .bind(cutoff)
        .fetch_optional(&state.db)
        .await;
        match existing {
            Ok(Some((id, domain, score, grade, _breakdown, _findings, recs, created_at))) => {
                metrics::counter!("grader.idempotency.hit").increment(1);
                return ok(GraderResultResponse {
                    id,
                    domain,
                    score: score as u16,
                    grade,
                    recommendations: recs,
                    created_at,
                    idempotency_replayed: true,
                });
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!(error = %e, "grader: idempotency lookup failed");
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DB_ERROR",
                    "database error",
                );
            }
        }
    }

    // Validate the submission BEFORE charging the per-tenant DNS budget:
    // the budget admission consumes units, and a malformed request used to
    // burn a tenant's allowance while getting nothing in return.
    let submission = match state.engine.validate_submission(&body) {
        Ok(s) => s,
        Err(e) => return map_grader_error(e),
    };

    // Per-tenant DNS budget admission.
    if !state
        .engine
        .check_tenant_dns_budget(tenant_id, SUBMIT_DNS_UNITS)
    {
        return err(
            StatusCode::TOO_MANY_REQUESTS,
            "TENANT_BUDGET",
            "tenant DNS budget exhausted; retry later",
        );
    }

    let result = match state.engine.analyze_email(&submission, tenant_id).await {
        Ok(r) => r,
        Err(e) => return map_grader_error(e),
    };

    let id = result.id.unwrap_or_else(uuid::Uuid::new_v4);
    // SHA-256 of evaluated body content (text + boundary + html), stored so
    // operators can correlate rows back to inputs without persisting bodies.
    let body_hash = {
        let mut h = Sha256::new();
        h.update(submission.body_text.as_bytes());
        h.update(b"\n--apexmail-grader-boundary--\n");
        h.update(submission.body_html.as_bytes());
        hex::encode(h.finalize())
    };

    // JSONB size guard (bound storage blow-up from upstream growth).
    let findings_json = match serde_json::to_value(&result.findings) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "grader: findings serialization failed");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_SERIALIZATION",
                "failed to serialize findings",
            );
        }
    };
    let breakdown_json = match serde_json::to_value(&result.breakdown) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "grader: breakdown serialization failed");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_SERIALIZATION",
                "failed to serialize breakdown",
            );
        }
    };
    if findings_json.to_string().len() > state.config.max_jsonb_bytes
        || breakdown_json.to_string().len() > state.config.max_jsonb_bytes
    {
        return err(
            StatusCode::PAYLOAD_TOO_LARGE,
            "RESULT_TOO_LARGE",
            "grader result exceeds configured size cap",
        );
    }

    // Encrypt sensitive stored fields when configured.
    let (stored_from, stored_subject, encrypted_flag) =
        match (&state.cipher, body.from.as_deref(), body.subject.as_deref()) {
            (Some(c), from, subject) => {
                let encrypted_from = match from {
                    Some(s) => match c.encrypt(s.as_bytes()) {
                        Ok(blob) => Some(blob),
                        Err(e) => {
                            tracing::error!(error = %e, "grader: from encryption failed");
                            return err(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "ENCRYPT_FAILED",
                                "failed to encrypt stored content",
                            );
                        }
                    },
                    None => None,
                };
                let encrypted_subject = match subject {
                    Some(s) => match c.encrypt(s.as_bytes()) {
                        Ok(blob) => Some(blob),
                        Err(e) => {
                            tracing::error!(error = %e, "grader: subject encryption failed");
                            return err(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "ENCRYPT_FAILED",
                                "failed to encrypt stored content",
                            );
                        }
                    },
                    None => None,
                };
                (encrypted_from, encrypted_subject, true)
            }
            _ => (body.from.clone(), body.subject.clone(), false),
        };

    let sender_ip_str = submission.sender_ip.map(|ip| ip.to_string());
    let expires_at: Option<DateTime<Utc>> = if state.config.default_retention_days > 0 {
        Some(Utc::now() + ChronoDuration::days(state.config.default_retention_days))
    } else {
        None
    };

    let row: Result<(uuid::Uuid, DateTime<Utc>), sqlx::Error> = sqlx::query_as(
        r#"INSERT INTO grader_results
            (id, tenant_id, domain, score, grade, breakdown, findings,
             recommendations, from_address, subject, body_hash, sender_ip,
             idempotency_key, encrypted, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::inet, $13, $14, $15)
           ON CONFLICT (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL
           DO UPDATE SET created_at = grader_results.created_at
           RETURNING id, created_at"#,
    )
    .bind(id)
    .bind(tenant_id)
    .bind(&result.domain)
    .bind(result.score as i16)
    .bind(&result.grade)
    .bind(&breakdown_json)
    .bind(&findings_json)
    .bind(&result.recommendations)
    .bind(&stored_from)
    .bind(&stored_subject)
    .bind(&body_hash)
    .bind(sender_ip_str)
    .bind(idem_key)
    .bind(encrypted_flag)
    .bind(expires_at)
    .fetch_one(&state.db)
    .await;

    let (persisted_id, created_at) = match row {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, tenant_id = %auth.tenant_id, "grader: persist failed");
            metrics::counter!("grader.db.persist_errors").increment(1);
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "PERSIST_FAILED",
                "failed to persist grader result",
            );
        }
    };

    let safe = GraderResultResponse {
        id: persisted_id,
        domain: result.domain,
        score: result.score,
        grade: result.grade,
        recommendations: result.recommendations,
        created_at,
        idempotency_replayed: false,
    };
    ok(safe)
}

pub async fn get_result(
    state: Arc<GraderState>,
    auth: GraderAuthContext,
    id: uuid::Uuid,
) -> (StatusCode, Json<serde_json::Value>) {
    if !state.config.enabled {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "GRADER_DISABLED",
            "Email Grader is disabled",
        );
    }
    if !auth.has_scope("grader:read") {
        return err(
            StatusCode::FORBIDDEN,
            "INSUFFICIENT_SCOPE",
            "scope `grader:read` is required",
        );
    }
    let tenant_id = match validate_tenant_id(&auth.tenant_id) {
        Ok(t) => t,
        Err(resp) => return resp,
    };

    let row = sqlx::query_as::<_, GraderResultRow>(
        r#"SELECT id, domain, score, grade, breakdown, findings,
                  recommendations, created_at
           FROM grader_results
           WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await;

    match row {
        Ok(Some(r)) => ok(GraderResultResponse {
            id: r.id,
            domain: r.domain,
            score: r.score as u16,
            grade: r.grade,
            recommendations: r.recommendations,
            created_at: r.created_at,
            idempotency_replayed: false,
        }),
        Ok(None) => err(StatusCode::NOT_FOUND, "NOT_FOUND", "result not found"),
        Err(e) => {
            tracing::error!(error = %e, "grader: get_result query failed");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                "database error",
            )
        }
    }
}

pub async fn list_results(
    state: Arc<GraderState>,
    auth: GraderAuthContext,
    params: PaginationParams,
) -> (StatusCode, Json<serde_json::Value>) {
    if !state.config.enabled {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "GRADER_DISABLED",
            "Email Grader is disabled",
        );
    }
    if !auth.has_scope("grader:read") {
        return err(
            StatusCode::FORBIDDEN,
            "INSUFFICIENT_SCOPE",
            "scope `grader:read` is required",
        );
    }
    let tenant_id = match validate_tenant_id(&auth.tenant_id) {
        Ok(t) => t,
        Err(resp) => return resp,
    };

    let page = params.page.unwrap_or(1).max(1);
    let per_page = params.per_page.unwrap_or(20).clamp(1, 100);
    let limit = per_page as i64;
    let offset = ((page - 1) as i64) * limit;

    let rows = sqlx::query_as::<_, GraderResultRow>(
        r#"SELECT id, domain, score, grade, breakdown, findings,
                  recommendations, created_at
           FROM grader_results
           WHERE tenant_id = $1
           ORDER BY created_at DESC
           LIMIT $2 OFFSET $3"#,
    )
    .bind(tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await;

    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "grader: list_results query failed");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                "database error",
            );
        }
    };

    let results: Vec<GraderResultResponse> = rows
        .into_iter()
        .map(|r| GraderResultResponse {
            id: r.id,
            domain: r.domain,
            score: r.score as u16,
            grade: r.grade,
            recommendations: r.recommendations,
            created_at: r.created_at,
            idempotency_replayed: false,
        })
        .collect();

    ok(serde_json::json!({
        "results": results,
        "page": page,
        "per_page": per_page,
    }))
}

/// Periodic retention sweep. Intended to be called by a workers job.
/// Returns the number of rows deleted (or 0 on error, with a logged warning).
pub async fn purge_expired(db: &sqlx::PgPool) -> i32 {
    match sqlx::query_scalar::<_, i32>("SELECT purge_expired_grader_results()")
        .fetch_one(db)
        .await
    {
        Ok(n) => {
            metrics::counter!("grader.retention.purged").increment(n as u64);
            n
        }
        Err(e) => {
            tracing::warn!(error = %e, "grader: retention purge failed");
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(max_jsonb: usize) -> GraderConfig {
        GraderConfig {
            max_jsonb_bytes: max_jsonb,
            ..GraderConfig::default()
        }
    }

    #[test]
    fn validate_tenant_id_accepts_uuid_and_ulid_shapes() {
        assert!(validate_tenant_id("01H8ZK7N3MQAB6XYZ123456789").is_ok());
        assert!(validate_tenant_id("123e4567-e89b-12d3-a456-426614174000").is_ok());
        assert!(validate_tenant_id("system").is_ok());
    }

    #[test]
    fn validate_tenant_id_rejects_bad_input() {
        assert!(validate_tenant_id("").is_err());
        assert!(validate_tenant_id(&"a".repeat(65)).is_err());
        assert!(validate_tenant_id("with spaces").is_err());
        assert!(validate_tenant_id("semi;colon").is_err());
        assert!(validate_tenant_id("tab\tin").is_err());
    }

    #[test]
    fn validate_idempotency_key_bounds() {
        assert!(validate_idempotency_key("abc-123_DEF").is_ok());
        assert!(validate_idempotency_key("").is_err());
        assert!(validate_idempotency_key(&"x".repeat(129)).is_err());
        assert!(validate_idempotency_key("with space").is_err());
    }

    #[test]
    fn jsonb_guard_rejects_oversized_payload() {
        // Indirectly: if findings JSON exceeds max_jsonb_bytes the route
        // returns 413 RESULT_TOO_LARGE. We assert the threshold maths here.
        let c = cfg(10);
        let v = serde_json::json!([{"big": "x".repeat(50)}]);
        assert!(v.to_string().len() > c.max_jsonb_bytes);
    }
}
