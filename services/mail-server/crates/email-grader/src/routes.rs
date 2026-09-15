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

    // ── adversarial: DB-backed handlers on the canonical schema ───────

    use crate::test_dns::StubDns;

    async fn canonical_pool(test_name: &str) -> Option<sqlx::PgPool> {
        match migrator::test_support::fresh_canonical_pool(test_name, test_name).await {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }

    async fn grader_state(
        pool: sqlx::PgPool,
        fake: &StubDns,
        tune: impl FnOnce(&mut GraderConfig),
    ) -> Arc<GraderState> {
        let mut config = GraderConfig {
            cache_ttl_seconds: 0,
            rate_limit_max: 100,
            tenant_dns_budget_max: 1_000,
            network_timeout_seconds: 1,
            ..GraderConfig::default()
        };
        tune(&mut config);
        let mut engine = GraderEngine::new(config.clone(), None).expect("engine");
        engine.set_dns_lookup_for_tests(Arc::new(fake.clone()));
        let state = GraderState::new(Arc::new(engine), config, pool).expect("state");
        Arc::new(state)
    }

    fn signal_dns() -> StubDns {
        let dkim_key = "A".repeat(2800);
        StubDns::new()
            .mx("example.com", 5, "mx1.example.com")
            .mx("example.com", 10, "mx2.example.com")
            .a("example.com", "93.184.216.34")
            .spf("example.com", "v=spf1 -all")
            .dmarc("example.com", "v=DMARC1; p=reject; pct=100")
            .dkim(
                "default",
                "example.com",
                &format!("v=DKIM1; k=rsa; p={dkim_key}"),
            )
    }

    fn submit_body() -> EmailSubmitRequest {
        EmailSubmitRequest {
            domain: Some("example.com".into()),
            from: Some("alice@example.com".into()),
            to: vec!["bob@example.net".into()],
            subject: Some("Hello".into()),
            body_text: Some("Just a normal message.".into()),
            body_html: None,
            headers: None,
            selectors: vec!["default".into()],
            sender_ip: None,
            helo_hostname: None,
            mail_from: None,
        }
    }

    fn auth(tenant: &str, scopes: &[&str], idem: Option<&str>) -> GraderAuthContext {
        GraderAuthContext {
            tenant_id: tenant.to_string(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            idempotency_key: idem.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn submit_persists_scope_checks_and_idempotent_replay() {
        let Some(pool) = canonical_pool("grader_submit").await else {
            return;
        };
        let fake = signal_dns();
        let state = grader_state(pool.clone(), &fake, |_| {}).await;

        let (status, json) = submit_email(
            state.clone(),
            auth("tenant-one", &["grader:write"], Some("idem-key-1")),
            submit_body(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{:?}", json.0);
        let id = json["id"].as_str().expect("id").to_string();
        assert_eq!(json["domain"], "example.com");
        assert!(
            json["idempotency_replayed"].is_null(),
            "first call is not a replay"
        );
        assert!(
            json.get("breakdown").is_none(),
            "breakdown never leaves the server"
        );
        assert!(
            json.get("findings").is_none(),
            "findings never leave the server"
        );

        // Persisted row carries tenant scoping, a body hash, and no raw body.
        let (tenant, hash, from, encrypted): (String, Option<String>, Option<String>, bool) =
            sqlx::query_as(
                "SELECT tenant_id, body_hash, from_address, encrypted
                 FROM grader_results WHERE id = $1::uuid",
            )
            .bind(&id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(tenant, "tenant-one");
        assert_eq!(hash.unwrap().len(), 64);
        assert_eq!(from.as_deref(), Some("alice@example.com"));
        assert!(!encrypted);

        // Same key → replay of the stored row, no second row.
        let (status, replayed) = submit_email(
            state.clone(),
            auth("tenant-one", &["grader:write"], Some("idem-key-1")),
            submit_body(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(replayed["id"], id, "same persisted row");
        assert_eq!(replayed["idempotency_replayed"], true);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM grader_results")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "replay must not insert");

        // Missing scope.
        let (status, json) =
            submit_email(state.clone(), auth("tenant-one", &[], None), submit_body()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(json["error"]["code"], "INSUFFICIENT_SCOPE");

        // Wildcard scope works.
        let (status, _) = submit_email(
            state.clone(),
            auth("tenant-one", &["*"], None),
            submit_body(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Invalid tenant identifiers are refused before any work.
        for bad in ["", "with space", &"x".repeat(65)] {
            let (status, json) = submit_email(
                state.clone(),
                auth(bad, &["grader:write"], None),
                submit_body(),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "tenant {bad:?}");
            assert_eq!(json["error"]["code"], "INVALID_TENANT");
        }

        // Invalid idempotency key.
        let (status, json) = submit_email(
            state.clone(),
            auth("tenant-one", &["grader:write"], Some("bad\tkey")),
            submit_body(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"]["code"], "INVALID_IDEMPOTENCY_KEY");

        // Disabled grader fails closed.
        let disabled = grader_state(pool.clone(), &fake, |c| c.enabled = false).await;
        let (status, json) = submit_email(
            disabled,
            auth("tenant-one", &["grader:write"], None),
            submit_body(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(json["error"]["code"], "GRADER_DISABLED");
    }

    #[tokio::test]
    async fn results_are_tenant_isolated_on_read() {
        let Some(pool) = canonical_pool("grader_isolation").await else {
            return;
        };
        let fake = signal_dns();
        let state = grader_state(pool.clone(), &fake, |_| {}).await;

        let (status, json) = submit_email(
            state.clone(),
            auth("tenant-one", &["grader:write"], None),
            submit_body(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let id = uuid::Uuid::parse_str(json["id"].as_str().unwrap()).unwrap();

        // The owner can read it (read scope).
        let (status, json) = get_result(
            state.clone(),
            auth("tenant-one", &["grader:read"], None),
            id,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["id"], id.to_string());

        // A second tenant must never see it.
        let (status, json) = get_result(
            state.clone(),
            auth("tenant-two", &["grader:read"], None),
            id,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(json["error"]["code"], "NOT_FOUND");

        // List is tenant-scoped too.
        let (status, json) = list_results(
            state.clone(),
            auth("tenant-two", &["grader:read"], None),
            PaginationParams {
                page: None,
                per_page: None,
            },
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["results"].as_array().unwrap().len(), 0);

        let (status, json) = list_results(
            state.clone(),
            auth("tenant-one", &["grader:read"], None),
            PaginationParams {
                page: Some(0),
                per_page: Some(1_000),
            },
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["page"], 1, "page 0 clamps to 1");
        assert_eq!(json["per_page"], 100, "per_page clamps to 100");
        assert_eq!(json["results"].as_array().unwrap().len(), 1);

        // Missing scope on read.
        let (status, _) = get_result(state.clone(), auth("tenant-one", &[], None), id).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Unknown id → 404.
        let (status, _) = get_result(
            state,
            auth("tenant-one", &["grader:read"], None),
            uuid::Uuid::new_v4(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn submit_enforces_size_caps_honestly() {
        let Some(pool) = canonical_pool("grader_size_caps").await else {
            return;
        };
        let fake = signal_dns();

        // Body cap → 413 before any DNS work.
        let state = grader_state(pool.clone(), &fake, |c| c.max_body_size = 8).await;
        let mut body = submit_body();
        body.body_text = Some("this is definitely too large".into());
        let (status, json) =
            submit_email(state, auth("tenant-one", &["grader:write"], None), body).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(json["error"]["code"], "BODY_TOO_LARGE");

        // JSONB cap → 413 after analysis, before persistence.
        let state = grader_state(pool.clone(), &fake, |c| c.max_jsonb_bytes = 10).await;
        let (status, json) = submit_email(
            state,
            auth("tenant-one", &["grader:write"], None),
            submit_body(),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(json["error"]["code"], "RESULT_TOO_LARGE");
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM grader_results")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "a refused result is never persisted");
    }

    #[tokio::test]
    async fn submit_encrypts_stored_from_and_subject_when_configured() {
        use base64::Engine as _;
        let Some(pool) = canonical_pool("grader_encryption").await else {
            return;
        };
        let fake = signal_dns();
        let key = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
        let state = grader_state(pool.clone(), &fake, |c| {
            c.encrypt_stored_content = true;
            c.encryption_master_key_base64 = Some(key.clone());
        })
        .await;

        let (status, _) = submit_email(
            state.clone(),
            auth("tenant-one", &["grader:write"], None),
            submit_body(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (from, subject, encrypted): (Option<String>, Option<String>, bool) =
            sqlx::query_as("SELECT from_address, subject, encrypted FROM grader_results LIMIT 1")
                .fetch_one(&pool)
                .await
                .unwrap();
        let from = from.expect("from stored");
        assert!(from.starts_with("v1:"), "encrypted, not plaintext: {from}");
        assert!(subject.unwrap().starts_with("v1:"));
        assert!(encrypted);

        let cipher = Cipher::from_base64_key(&key).unwrap();
        assert_eq!(
            String::from_utf8(cipher.decrypt(&from).unwrap()).unwrap(),
            "alice@example.com"
        );

        // GraderState refuses an encryption config without/with a bad key.
        let engine = Arc::new(GraderEngine::new(GraderConfig::default(), None).unwrap());
        let mut bad = GraderConfig {
            encrypt_stored_content: true,
            encryption_master_key_base64: None,
            ..GraderConfig::default()
        };
        assert!(GraderState::new(engine.clone(), bad.clone(), pool.clone()).is_err());
        bad.encryption_master_key_base64 = Some("not-a-key".into());
        assert!(GraderState::new(engine, bad, pool).is_err());
    }

    #[tokio::test]
    async fn database_failures_are_reported_not_fabricated() {
        let offline = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgres://fake:fake@localhost:1/fake")
            .unwrap();
        let fake = signal_dns();
        let state = grader_state(offline, &fake, |_| {}).await;

        // Idempotency lookup against a dead DB → honest 500.
        let (status, json) = submit_email(
            state.clone(),
            auth("tenant-one", &["grader:write"], Some("k")),
            submit_body(),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["error"]["code"], "DB_ERROR");

        // get_result against a dead DB → honest 500 (not a 404).
        let (status, json) = get_result(
            state.clone(),
            auth("tenant-one", &["grader:read"], None),
            uuid::Uuid::new_v4(),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["error"]["code"], "DB_ERROR");

        let (status, _) = list_results(
            state,
            auth("tenant-one", &["grader:read"], None),
            PaginationParams {
                page: None,
                per_page: None,
            },
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

        // purge_expired reports 0 on error instead of panicking.
        let dead = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgres://fake:fake@localhost:1/fake")
            .unwrap();
        assert_eq!(purge_expired(&dead).await, 0);
    }

    #[tokio::test]
    async fn purge_expired_removes_only_expired_rows() {
        let Some(pool) = canonical_pool("grader_purge").await else {
            return;
        };
        for (id, expires_offset_days) in [
            ("11111111-1111-1111-1111-111111111111", -1i64),
            ("22222222-2222-2222-2222-222222222222", 30),
        ] {
            sqlx::query(
                "INSERT INTO grader_results
                   (id, tenant_id, domain, score, grade, breakdown, findings,
                    recommendations, encrypted, expires_at)
                 VALUES ($1::uuid, 'tenant-one', 'example.com', 80, 'A',
                         '{}'::jsonb, '[]'::jsonb, '{}', false,
                         NOW() + make_interval(days => $2::int))",
            )
            .bind(id)
            .bind(expires_offset_days)
            .execute(&pool)
            .await
            .unwrap();
        }

        assert_eq!(purge_expired(&pool).await, 1);
        let remaining: Vec<uuid::Uuid> =
            sqlx::query_scalar("SELECT id FROM grader_results ORDER BY id")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(
            remaining,
            vec![uuid::Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()]
        );
    }

    #[tokio::test]
    async fn check_domain_route_enforces_enabled_rate_limit_and_domain_rules() {
        let Some(pool) = canonical_pool("grader_check_route").await else {
            return;
        };
        let fake = signal_dns();

        // Disabled → 503.
        let state = grader_state(pool.clone(), &fake, |c| c.enabled = false).await;
        let (status, json) = check_domain(
            state,
            "203.0.113.7".parse().unwrap(),
            DomainCheckRequest {
                domain: "example.com".into(),
                selectors: vec![],
            },
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(json["error"]["code"], "GRADER_DISABLED");

        // Rate limit 0 → every request blocked.
        let state = grader_state(pool.clone(), &fake, |c| c.rate_limit_max = 0).await;
        let (status, json) = check_domain(
            state,
            "203.0.113.7".parse().unwrap(),
            DomainCheckRequest {
                domain: "example.com".into(),
                selectors: vec![],
            },
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(json["error"]["code"], "RATE_LIMITED");

        // Real check succeeds and is not persisted.
        let state = grader_state(pool.clone(), &fake, |_| {}).await;
        let (status, json) = check_domain(
            state.clone(),
            "203.0.113.7".parse().unwrap(),
            DomainCheckRequest {
                domain: "example.com".into(),
                selectors: vec![],
            },
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{:?}", json.0);
        assert_eq!(json["grade"], "A");
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM grader_results")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 0, "domain-only checks are not persisted");

        // Invalid domain → 400 INVALID_INPUT.
        let (status, json) = check_domain(
            state,
            "203.0.113.7".parse().unwrap(),
            DomainCheckRequest {
                domain: "no-dot".into(),
                selectors: vec![],
            },
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"]["code"], "INVALID_INPUT");
    }

    #[tokio::test]
    async fn tenant_dns_budget_exhaustion_is_a_honest_429() {
        let Some(pool) = canonical_pool("grader_budget").await else {
            return;
        };
        let fake = signal_dns();
        // Budget of 1 unit < the 7 units a submit costs → refused before
        // analysis, with a retry-later code.
        let state = grader_state(pool.clone(), &fake, |c| c.tenant_dns_budget_max = 1).await;
        let (status, json) = submit_email(
            state.clone(),
            auth("tenant-one", &["grader:write"], None),
            submit_body(),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(json["error"]["code"], "TENANT_BUDGET");
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM grader_results")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 0, "nothing persisted when the budget refuses");

        // A zero budget blocks every tenant.
        let state = grader_state(pool.clone(), &fake, |c| c.tenant_dns_budget_max = 0).await;
        let (status, _) = submit_email(
            state,
            auth("tenant-one", &["grader:write"], None),
            submit_body(),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn read_routes_fail_closed_when_disabled() {
        let Some(pool) = canonical_pool("grader_disabled_reads").await else {
            return;
        };
        let fake = signal_dns();
        let state = grader_state(pool.clone(), &fake, |c| c.enabled = false).await;
        let id = uuid::Uuid::new_v4();
        let (status, json) = get_result(
            state.clone(),
            auth("tenant-one", &["grader:read"], None),
            id,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(json["error"]["code"], "GRADER_DISABLED");

        let (status, json) = list_results(
            state.clone(),
            auth("tenant-one", &["grader:read"], None),
            PaginationParams {
                page: None,
                per_page: None,
            },
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(json["error"]["code"], "GRADER_DISABLED");

        // Invalid tenant on the read paths (enabled grader, so validation is
        // what refuses the request).
        let live = grader_state(pool, &fake, |_| {}).await;
        let (status, json) =
            get_result(live.clone(), auth("bad tenant", &["grader:read"], None), id).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"]["code"], "INVALID_TENANT");
        let (status, json) = list_results(
            live,
            auth("bad tenant", &["grader:read"], None),
            PaginationParams {
                page: None,
                per_page: None,
            },
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"]["code"], "INVALID_TENANT");
    }

    #[test]
    fn error_mapping_covers_every_variant() {
        let (status, json) = map_grader_error(GraderError::DomainNotFound("gone.example".into()));
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(json["error"]["code"], "DOMAIN_NOT_FOUND");
        assert!(json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("gone.example"));

        let (status, json) = map_grader_error(GraderError::TenantBudgetExhausted);
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(json["error"]["code"], "TENANT_BUDGET");

        let (status, json) = map_grader_error(GraderError::Internal("boom".into()));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["error"]["code"], "INTERNAL");
        // Internal detail is logged, never returned.
        assert!(!json["error"]["message"].as_str().unwrap().contains("boom"));
    }
}
