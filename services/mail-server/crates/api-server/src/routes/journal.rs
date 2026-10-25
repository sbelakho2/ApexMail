//! Tenant-scoped mail journal retrieval (`mail_journal`, migration 264).
//!
//! The Mailboxes "Archive + Journaling" add-on writes one immutable row per
//! journaled message. This module is the CUSTOMER read surface:
//!
//! * `GET /v1/journal?tenantId=…&limit=…&offset=…`, metadata only (id,
//!   direction, from, to, subject, messageId, journaledAt), newest first.
//!   The raw body is deliberately absent from list rows.
//! * `GET /v1/journal/:id`, metadata plus the raw message, capped at
//!   [`mailstore_core::journal::JOURNAL_RAW_JSON_CAP_BYTES`] with
//!   `rawTruncated`/`rawSize` telling the caller exactly what it received.
//! * `GET /v1/journal/:id/raw`, the complete stored raw copy as
//!   `message/rfc822` (the console's download link).
//!
//! Authorization is tenant-admin (`*` scope) AND tenant-scoped: the resolved
//! tenant is always the authenticated tenant. A `tenantId` naming another
//! tenant is refused, and a row id from another tenant is indistinguishable
//! from a missing row (both 404).
//!
//! Retrieval is intentionally NOT gated on the add-on being currently
//! active: disabling archive + journaling stops new copies but must never
//! remove access to the legal record already written.

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{success_with_meta, ApiError, ApiResponse};
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_journal))
        .route("/:id", get(get_journal_entry))
        .route("/:id/raw", get(get_journal_raw))
}

/// Reading the journal is a tenant-administrator action (the same wildcard
/// scope the console's admin/owner roles carry).
pub const JOURNAL_ADMIN_SCOPE: &str = "*";
const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 200;
const MAX_OFFSET: i64 = 10_000_000;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JournalQuery {
    /// Explicit tenant scope. Must equal the authenticated tenant (a
    /// different value is refused, there is no cross-tenant read).
    pub tenant_id: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    DEFAULT_LIMIT
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JournalEntry {
    pub id: Uuid,
    pub direction: String,
    pub from: Option<String>,
    pub to: Vec<String>,
    pub subject: Option<String>,
    pub message_id: Option<String>,
    pub journaled_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JournalList {
    pub entries: Vec<JournalEntry>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JournalDetail {
    pub id: Uuid,
    pub direction: String,
    pub from: Option<String>,
    pub to: Vec<String>,
    pub subject: Option<String>,
    pub message_id: Option<String>,
    pub journaled_at: DateTime<Utc>,
    pub source_table: Option<String>,
    pub source_id: Option<String>,
    /// The raw RFC 5322 copy when it is valid UTF-8 (capped at
    /// `JOURNAL_RAW_JSON_CAP_BYTES`). `None` when `rawEncoding` is base64.
    pub raw_message: Option<String>,
    /// Base64 of the stored bytes when the message is not valid UTF-8
    /// (8-bit MIME bodies, NUL bytes). `None` when `rawEncoding` is utf-8.
    pub raw_base64: Option<String>,
    /// `utf-8` or `base64`, how to read the payload above.
    pub raw_encoding: String,
    pub raw_size: usize,
    pub raw_truncated: bool,
}

/// Resolve the tenant the request may read. The caller must hold the
/// tenant-admin scope and may only name its OWN tenant.
fn authorized_tenant(auth: &AuthUser, requested: Option<&str>) -> Result<String, ApiError> {
    require_scopes(auth, &[JOURNAL_ADMIN_SCOPE])?;
    let requested = requested.map(str::trim).filter(|value| !value.is_empty());
    match requested {
        Some(tenant) if tenant != auth.tenant_id => Err(ApiError::Forbidden(
            "the journal is tenant-scoped: tenantId must match the authenticated tenant".into(),
        )),
        _ => Ok(auth.tenant_id.clone()),
    }
}

fn validate_paging(limit: i64, offset: i64) -> Result<(), ApiError> {
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(ApiError::BadRequest(format!(
            "limit must be between 1 and {MAX_LIMIT}"
        )));
    }
    if !(0..=MAX_OFFSET).contains(&offset) {
        return Err(ApiError::BadRequest(format!(
            "offset must be between 0 and {MAX_OFFSET}"
        )));
    }
    Ok(())
}

fn parse_id(raw: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(raw).map_err(|_| ApiError::BadRequest("journal id must be a UUID".into()))
}

async fn list_journal(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<JournalQuery>,
) -> Result<Json<ApiResponse<JournalList>>, ApiError> {
    let tenant_id = authorized_tenant(&auth, query.tenant_id.as_deref())?;
    validate_paging(query.limit, query.offset)?;

    let rows =
        mailstore_core::journal::list_journal(&state.db, &tenant_id, query.limit, query.offset)
            .await?;
    let total = mailstore_core::journal::count_journal(&state.db, &tenant_id).await?;

    let entries = rows
        .into_iter()
        .map(|row| JournalEntry {
            id: row.id,
            direction: row.direction,
            from: row.from_address,
            to: row.to_addresses.0,
            subject: row.subject,
            message_id: row.message_id,
            journaled_at: row.journaled_at,
        })
        .collect();

    Ok(success_with_meta(
        JournalList {
            entries,
            total,
            limit: query.limit,
            offset: query.offset,
        },
        serde_json::json!({
            "total": total,
            "limit": query.limit,
            "offset": query.offset,
        }),
    ))
}

async fn get_journal_entry(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<JournalDetail>>, ApiError> {
    let tenant_id = authorized_tenant(&auth, None)?;
    let id = parse_id(&id)?;
    let row = mailstore_core::journal::get_journal(&state.db, &tenant_id, id)
        .await?
        .ok_or_else(|| ApiError::NotFound("journal entry not found".into()))?;

    let raw_size = row.raw_message.len();
    let (raw, raw_truncated) = mailstore_core::journal::cap_raw_message(&row.raw_message);
    let (raw_message, raw_base64, raw_encoding) = match std::str::from_utf8(raw) {
        Ok(text) => (Some(text.to_string()), None, "utf-8".to_string()),
        Err(_) => (
            None,
            Some(base64::engine::general_purpose::STANDARD.encode(raw)),
            "base64".to_string(),
        ),
    };

    Ok(Json(ApiResponse::success(JournalDetail {
        id: row.id,
        direction: row.direction,
        from: row.from_address,
        to: row.to_addresses.0,
        subject: row.subject,
        message_id: row.message_id,
        journaled_at: row.journaled_at,
        source_table: row.source_table,
        source_id: row.source_id,
        raw_message,
        raw_base64,
        raw_encoding,
        raw_size,
        raw_truncated,
    })))
}

async fn get_journal_raw(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let tenant_id = authorized_tenant(&auth, None)?;
    let id = parse_id(&id)?;
    let row = mailstore_core::journal::get_journal(&state.db, &tenant_id, id)
        .await?
        .ok_or_else(|| ApiError::NotFound("journal entry not found".into()))?;

    let mut response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "message/rfc822")],
        row.raw_message,
    )
        .into_response();
    if let Ok(value) = format!("attachment; filename=\"journal-{id}.eml\"").parse() {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, value);
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(tenant_id: &str, scopes: &[&str]) -> AuthUser {
        AuthUser {
            tenant_id: tenant_id.to_string(),
            user_id: Some("user-1".into()),
            api_key_id: None,
            session_id: None,
            scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
        }
    }

    #[test]
    fn tenant_scope_requires_admin_and_rejects_foreign_tenants() {
        let admin = auth("tenant-a", &["*"]);
        assert_eq!(
            authorized_tenant(&admin, Some("tenant-a")).unwrap(),
            "tenant-a"
        );
        assert_eq!(authorized_tenant(&admin, None).unwrap(), "tenant-a");

        // A scoped non-admin credential is refused.
        let reader = auth("tenant-a", &["messages:read"]);
        assert!(matches!(
            authorized_tenant(&reader, Some("tenant-a")),
            Err(ApiError::Forbidden(_))
        ));

        // Another tenant, even for an admin, is refused.
        assert!(matches!(
            authorized_tenant(&admin, Some("tenant-b")),
            Err(ApiError::Forbidden(_))
        ));
    }

    #[test]
    fn paging_bounds_are_validated() {
        assert!(validate_paging(1, 0).is_ok());
        assert!(validate_paging(MAX_LIMIT, 0).is_ok());
        assert!(validate_paging(0, 0).is_err());
        assert!(validate_paging(MAX_LIMIT + 1, 0).is_err());
        assert!(validate_paging(10, -1).is_err());
        assert!(validate_paging(10, MAX_OFFSET + 1).is_err());
    }

    #[test]
    fn malformed_ids_are_named_400s() {
        assert!(parse_id("not-a-uuid").is_err());
        assert!(parse_id(&Uuid::new_v4().to_string()).is_ok());
    }

    // ── DB-backed retrieval contract ─────────────────────────────────────

    async fn seed_journal(
        pool: &sqlx::PgPool,
        tenant_id: &str,
        subject: &str,
        journaled_at: DateTime<Utc>,
    ) -> Uuid {
        let mut tx = pool.begin().await.expect("tx");
        let id = mailstore_core::journal::insert_journal_entry_tx(
            &mut tx,
            &mailstore_core::journal::NewJournalEntry {
                tenant_id: tenant_id.to_string(),
                direction: mailstore_core::journal::JournalDirection::Outbound,
                source_table: Some("email_queue".into()),
                source_id: Some(Uuid::new_v4().to_string()),
                message_id: Some(format!("<{subject}@example.com>")),
                from_address: Some("sender@example.com".into()),
                to_addresses: vec!["rcpt@example.com".into()],
                subject: Some(subject.into()),
                raw_message: format!("From: sender@example.com\r\nSubject: {subject}\r\n\r\nbody")
                    .into_bytes(),
            },
        )
        .await
        .expect("insert journal row")
        .expect("a fresh source identity must insert");
        sqlx::query("UPDATE mail_journal SET journaled_at = $2 WHERE id = $1")
            .bind(id)
            .bind(journaled_at)
            .execute(&mut *tx)
            .await
            .expect("stamp journaled_at");
        tx.commit().await.expect("commit");
        id
    }

    fn query(tenant_id: Option<&str>, limit: i64, offset: i64) -> JournalQuery {
        JournalQuery {
            tenant_id: tenant_id.map(str::to_string),
            limit,
            offset,
        }
    }

    #[tokio::test]
    async fn list_detail_and_raw_are_tenant_scoped_paginated_and_capped() {
        let Some(pool) = crate::test_db::canonical_pool("journal_routes_scope").await else {
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let tenant_a = format!("jr{}", &Uuid::new_v4().simple().to_string()[..12]);
        let tenant_b = format!("js{}", &Uuid::new_v4().simple().to_string()[..12]);
        let now = Utc::now();
        let older = seed_journal(
            &pool,
            &tenant_a,
            "older",
            now - chrono::Duration::minutes(2),
        )
        .await;
        let newer = seed_journal(
            &pool,
            &tenant_a,
            "newer",
            now - chrono::Duration::minutes(1),
        )
        .await;
        let foreign = seed_journal(&pool, &tenant_b, "foreign", now).await;

        let admin_a = auth(&tenant_a, &["*"]);

        // First page: newest first, metadata only.
        let Json(page) = list_journal(
            State(state.clone()),
            admin_a.clone(),
            Query(query(Some(&tenant_a), 1, 0)),
        )
        .await
        .expect("list page 1");
        let list = page.data.expect("data");
        assert_eq!(list.total, 2);
        assert_eq!(list.entries.len(), 1);
        assert_eq!(list.entries[0].id, newer);
        assert_eq!(list.entries[0].direction, "outbound");
        assert_eq!(list.entries[0].from.as_deref(), Some("sender@example.com"));
        assert_eq!(list.entries[0].to, vec!["rcpt@example.com"]);
        assert_eq!(list.entries[0].subject.as_deref(), Some("newer"));

        // Second page: the older row, never the foreign tenant's.
        let Json(page) = list_journal(
            State(state.clone()),
            admin_a.clone(),
            Query(query(None, 1, 1)),
        )
        .await
        .expect("list page 2");
        let list = page.data.expect("data");
        assert_eq!(list.entries.len(), 1);
        assert_eq!(list.entries[0].id, older);

        // Foreign tenantId is refused before any read.
        let denied = list_journal(
            State(state.clone()),
            admin_a.clone(),
            Query(query(Some(&tenant_b), 10, 0)),
        )
        .await;
        assert!(matches!(denied, Err(ApiError::Forbidden(_))));

        // A non-admin credential is refused.
        let denied = list_journal(
            State(state.clone()),
            auth(&tenant_a, &["messages:read"]),
            Query(query(None, 10, 0)),
        )
        .await;
        assert!(matches!(denied, Err(ApiError::Forbidden(_))));

        // Detail: own row carries the raw copy; a foreign id is a 404.
        let Json(detail) = get_journal_entry(
            State(state.clone()),
            admin_a.clone(),
            Path(newer.to_string()),
        )
        .await
        .expect("own detail");
        let detail = detail.data.expect("detail");
        let raw_text = detail.raw_message.as_deref().expect("utf-8 message");
        assert_eq!(detail.raw_encoding, "utf-8");
        assert!(detail.raw_base64.is_none());
        assert!(raw_text.contains("Subject: newer"));
        assert_eq!(detail.raw_size, raw_text.len());
        assert!(!detail.raw_truncated);
        assert!(matches!(
            get_journal_entry(
                State(state.clone()),
                admin_a.clone(),
                Path(foreign.to_string())
            )
            .await,
            Err(ApiError::NotFound(_))
        ));

        // Raw download: exact body + message/rfc822.
        let response = get_journal_raw(
            State(state.clone()),
            admin_a.clone(),
            Path(newer.to_string()),
        )
        .await
        .expect("raw download");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("message/rfc822")
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("raw body");
        assert_eq!(
            std::str::from_utf8(&body).expect("utf8"),
            "From: sender@example.com\r\nSubject: newer\r\n\r\nbody".to_string()
        );

        // A foreign row's raw download is a 404, never the bytes.
        assert!(matches!(
            get_journal_raw(State(state), admin_a, Path(foreign.to_string())).await,
            Err(ApiError::NotFound(_))
        ));
        pool.close().await;
    }

    /// A message that is not valid UTF-8 (NUL and 8-bit octets) is served as
    /// base64 in JSON and byte-exactly by the download endpoint; nothing is
    /// lossily rewritten.
    #[tokio::test]
    async fn non_utf8_raw_is_served_as_base64_and_downloaded_byte_exact() {
        let Some(pool) = crate::test_db::canonical_pool("journal_routes_binary").await else {
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let tenant = format!("jx{}", &Uuid::new_v4().simple().to_string()[..12]);
        let raw = vec![0x00, 0xff, 0xfe, b'a', 0x80];

        let mut tx = pool.begin().await.expect("tx");
        let id = mailstore_core::journal::insert_journal_entry_tx(
            &mut tx,
            &mailstore_core::journal::NewJournalEntry {
                tenant_id: tenant.clone(),
                direction: mailstore_core::journal::JournalDirection::Inbound,
                source_table: Some("mail_messages".into()),
                source_id: Some(Uuid::new_v4().to_string()),
                message_id: Some("<binary@example.com>".into()),
                from_address: Some("sender@example.com".into()),
                to_addresses: vec!["rcpt@example.com".into()],
                subject: Some("binary".into()),
                raw_message: raw.clone(),
            },
        )
        .await
        .expect("insert journal row")
        .expect("a fresh source identity must insert");
        tx.commit().await.expect("commit");

        let admin = auth(&tenant, &["*"]);
        let Json(detail) =
            get_journal_entry(State(state.clone()), admin.clone(), Path(id.to_string()))
                .await
                .expect("own detail");
        let detail = detail.data.expect("detail");
        assert_eq!(detail.raw_encoding, "base64");
        assert!(detail.raw_message.is_none());
        let expected = base64::engine::general_purpose::STANDARD.encode(&raw);
        assert_eq!(detail.raw_base64.as_deref(), Some(expected.as_str()));
        assert_eq!(detail.raw_size, raw.len());
        assert!(!detail.raw_truncated);

        let response = get_journal_raw(State(state), admin, Path(id.to_string()))
            .await
            .expect("raw download");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("raw body");
        assert_eq!(
            body.as_ref(),
            raw.as_slice(),
            "bytes must round-trip exactly"
        );
        pool.close().await;
    }

    #[tokio::test]
    async fn empty_journal_is_an_honest_200() {
        let Some(pool) = crate::test_db::canonical_pool("journal_routes_empty").await else {
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let tenant = format!("je{}", &Uuid::new_v4().simple().to_string()[..12]);
        let Json(page) = list_journal(
            State(state),
            auth(&tenant, &["*"]),
            Query(query(Some(&tenant), 50, 0)),
        )
        .await
        .expect("empty list is 200");
        let list = page.data.expect("data");
        assert!(list.entries.is_empty());
        assert_eq!(list.total, 0);
        pool.close().await;
    }
}
