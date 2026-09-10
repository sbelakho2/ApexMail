//! SCIM 2.0 provisioning routes for enterprise SSO.
//!
//! Compliance notes (RFC 7643/7644):
//! - `id` is server-assigned and read-only (RFC 7643 §3.1 / §7): create and
//!   replace bodies never require or honour a client-supplied `id`, and
//!   every write returns the canonical stored resource with 201 + Location
//!   (RFC 7644 §3.3).
//! - The `active` lifecycle requested by the caller is persisted verbatim
//!   on create, replace AND patch; any final deactivated state revokes the
//!   user's sessions and invalidates the auth status caches.
//! - List endpoints support bounded, parsed, fully parameterized `filter`
//!   lookups (`eq` on `userName`, `emails.value`, `externalId`) and
//!   normalized pagination metadata.
//! - Errors carry the RFC 7644 §3.12 envelope (`schemas`, `detail`,
//!   `status`).

use axum::extract::{rejection::JsonRejection, Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{
    invalidate_user_status_cache, require_scopes, session_revocation_key, AuthUser,
};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/Users", get(list_users).post(create_user))
        .route(
            "/Users/:id",
            get(get_user)
                .put(update_user)
                .patch(patch_user)
                .delete(delete_user),
        )
        .route("/Groups", get(list_groups).post(create_group))
        .route(
            "/Groups/:id",
            get(get_group)
                .put(update_group)
                .patch(patch_group)
                .delete(delete_group),
        )
        .route("/ServiceProviderConfig", get(service_provider_config))
}

// ─── SCIM Types ────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ScimListResponse<T: Serialize> {
    pub schemas: Vec<String>,
    #[serde(rename = "totalResults")]
    pub total_results: i64,
    #[serde(rename = "startIndex")]
    pub start_index: i64,
    #[serde(rename = "itemsPerPage")]
    pub items_per_page: i64,
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

/// Canonical SCIM User resource returned by every user endpoint. This is a
/// response-only type: request bodies are parsed into [`UserUpsertRequest`]
/// so ordinary creates (which omit the server-assigned `id`) deserialize
/// cleanly (F40, RFC 7643 §7 `id` is read-only).
#[derive(Debug, Serialize)]
pub struct ScimUser {
    pub schemas: Vec<String>,
    pub id: String,
    #[serde(rename = "userName")]
    pub user_name: String,
    pub name: Option<ScimName>,
    pub emails: Vec<ScimEmail>,
    pub active: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScimName {
    #[serde(rename = "givenName", default)]
    pub given_name: Option<String>,
    #[serde(rename = "familyName", default)]
    pub family_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScimEmail {
    pub value: String,
    #[serde(default)]
    pub primary: bool,
}

/// Canonical SCIM Group resource (response-only; see
/// [`GroupUpsertRequest`] for the write DTO).
#[derive(Debug, Serialize)]
pub struct ScimGroup {
    pub schemas: Vec<String>,
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub members: Vec<ScimMember>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScimMember {
    pub value: String,
    pub display: Option<String>,
}

/// SCIM User create (POST) / replace (PUT) body (F40). Ordinary IdP create
/// requests carry only `userName` (plus optional attributes); `id` is
/// absent by design — the server generates it. Unknown attributes
/// (including a client-supplied `id`) are ignored, mirroring SCIM's
/// tolerant resource model.
#[derive(Debug, Deserialize)]
struct UserUpsertRequest {
    #[serde(default)]
    schemas: Vec<String>,
    #[serde(rename = "userName", default)]
    user_name: Option<String>,
    #[serde(default)]
    name: Option<ScimName>,
    #[serde(default)]
    emails: Vec<ScimEmail>,
    /// RFC 7644 §3.1: `active` defaults to true when omitted.
    #[serde(default = "default_active")]
    active: bool,
}

fn default_active() -> bool {
    true
}

/// SCIM Group create/replace body (F40): `displayName` is required,
/// `members` optional.
#[derive(Debug, Deserialize)]
struct GroupUpsertRequest {
    #[serde(default)]
    schemas: Vec<String>,
    #[serde(rename = "displayName", default)]
    display_name: Option<String>,
    #[serde(default)]
    members: Vec<ScimMember>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimListQuery {
    #[serde(default = "default_start")]
    #[serde(rename = "startIndex")]
    pub start_index: i64,
    #[serde(default = "default_count")]
    pub count: i64,
    #[serde(default)]
    pub cursor: Option<i64>,
    /// RFC 7644 §3.4.2.2 filter. Previously this parameter was rejected
    /// wholesale by `deny_unknown_fields` (F42); it is now parsed into a
    /// bounded, parameterized predicate.
    #[serde(default)]
    pub filter: Option<String>,
}

fn default_start() -> i64 {
    1
}
fn default_count() -> i64 {
    100
}

const SCIM_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const SCIM_GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const SCIM_LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const SCIM_ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const SCIM_SPC_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";

/// Maximum allowed count parameter for list operations.
const MAX_SCIM_COUNT: i64 = 200;

/// Upper bound on accepted filter strings — filters are parsed into bound
/// SQL parameters, so pathological inputs are rejected up front instead of
/// parsed (F42).
const MAX_SCIM_FILTER_LEN: usize = 512;

/// SCIM placeholder hash that can never be valid Argon2.
/// Users with this hash must authenticate via SSO.
const SCIM_DISABLED_HASH: &str = "!scim:disabled";

// ─── SCIM error envelope (RFC 7644 §3.12) ──────────────────────

/// SCIM-formatted protocol error: SCIM clients read the Error schema urn,
/// `detail` and `status`, not ApexMail's generic error envelope (F42).
#[derive(Debug)]
struct ScimError {
    status: StatusCode,
    detail: String,
}

impl ScimError {
    fn bad_request(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            detail: detail.into(),
        }
    }

    fn forbidden(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            detail: detail.into(),
        }
    }

    fn not_found(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            detail: detail.into(),
        }
    }
}

impl IntoResponse for ScimError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({
            "schemas": [SCIM_ERROR_SCHEMA],
            "status": self.status.as_u16().to_string(),
            "detail": self.detail,
        }));
        (self.status, body).into_response()
    }
}

impl From<ApiError> for ScimError {
    fn from(error: ApiError) -> Self {
        let status = match &error {
            ApiError::BadRequest(_) | ApiError::Validation(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::RateLimited | ApiError::RateLimitedMessage(_) => {
                StatusCode::TOO_MANY_REQUESTS
            }
            ApiError::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            ApiError::Timeout => StatusCode::REQUEST_TIMEOUT,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        };
        let detail = match &error {
            ApiError::Internal(message) => {
                tracing::error!(error = %message, "internal error in SCIM route");
                "internal server error".to_string()
            }
            ApiError::Validation(details) => {
                format!("validation failed: {}", details.join("; "))
            }
            other => other.to_string(),
        };
        Self { status, detail }
    }
}

impl From<sqlx::Error> for ScimError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(error = %error, "database error in SCIM route");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            detail: "internal server error".into(),
        }
    }
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(db_error) if db_error.code().as_deref() == Some("23505"))
}

/// Actor-attributed audit for SCIM mutations (P1-8): provisioning changes
/// arrive bearer-token-authenticated, so the API key's tenant AND user id
/// are the actor. Without this, silent directory rewrites were invisible in
/// the compliance trail.
async fn log_scim_audit(
    state: &AppState,
    auth: &AuthUser,
    action: &str,
    resource: &str,
    resource_id: Option<&str>,
    details: serde_json::Value,
) {
    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        action,
        resource,
        resource_id,
        details,
        None,
        None,
    )
    .await;
}

// ─── Shared write-path helpers ─────────────────────────────────

/// Structural email gate shared by SCIM create/update/patch — SCIM clients
/// send whatever the IdP holds; a blank or @-less value must never reach the
/// UNIQUE index or the login lookup.
fn is_plausible_email(email: &str) -> bool {
    let email = email.trim();
    if !(3..=320).contains(&email.len()) || email.chars().any(char::is_whitespace) {
        return false;
    }
    match email.split_once('@') {
        Some((local, domain)) => {
            !local.is_empty()
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        }
        None => false,
    }
}

/// Validate the `schemas` attribute of a request body (F40): absent/empty is
/// accepted for lenience with minimal IdPs, but a present list that does not
/// contain the expected core schema is a client error.
fn validate_schemas(schemas: &[String], expected: &str) -> Result<(), String> {
    if schemas.is_empty() || schemas.iter().any(|schema| schema == expected) {
        Ok(())
    } else {
        Err(format!("schemas must contain '{expected}'"))
    }
}

fn validate_user_upsert(request: &UserUpsertRequest) -> Result<(), ScimError> {
    if let Err(detail) = validate_schemas(&request.schemas, SCIM_USER_SCHEMA) {
        return Err(ScimError::bad_request(detail));
    }
    // RFC 7644 §3.1: userName is REQUIRED for User create/replace.
    if request
        .user_name
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .is_empty()
    {
        return Err(ScimError::bad_request(
            "userName is required and must not be empty",
        ));
    }
    Ok(())
}

fn validate_group_upsert(request: &GroupUpsertRequest) -> Result<(), ScimError> {
    if let Err(detail) = validate_schemas(&request.schemas, SCIM_GROUP_SCHEMA) {
        return Err(ScimError::bad_request(detail));
    }
    if request
        .display_name
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .is_empty()
    {
        return Err(ScimError::bad_request(
            "displayName is required and must not be empty",
        ));
    }
    Ok(())
}

/// The address a SCIM write stores: `emails[0].value` when the IdP sent
/// emails, otherwise the userName. Normalized to lowercase at every write
/// path (which is also what makes `eq` filters simple equality).
fn derive_user_email(request: &UserUpsertRequest) -> String {
    request
        .emails
        .first()
        .map(|email| email.value.clone())
        .unwrap_or_else(|| request.user_name.clone().unwrap_or_default())
        .trim()
        .to_lowercase()
}

/// Single canonical mapping from the SCIM `active` flag to the stored
/// lifecycle status, shared by create, replace and patch (F41) so the three
/// paths can never disagree.
fn status_for_active(active: bool) -> &'static str {
    if active {
        "active"
    } else {
        "deactivated"
    }
}

/// The canonical SCIM User resource for a stored user state — used by
/// create/get/replace/patch alike so responses always reflect exactly what
/// was persisted (server id, stored email/name, stored lifecycle).
fn canonical_scim_user(id: String, email: String, name: Option<String>, active: bool) -> ScimUser {
    ScimUser {
        schemas: vec![SCIM_USER_SCHEMA.into()],
        id,
        user_name: email.clone(),
        name: name.map(|given| ScimName {
            given_name: Some(given),
            family_name: None,
        }),
        emails: vec![ScimEmail {
            value: email,
            primary: true,
        }],
        active,
    }
}

fn user_location(id: &str) -> String {
    format!("/v1/scim/Users/{id}")
}

fn group_location(scim_id: &str) -> String {
    format!("/v1/scim/Groups/{scim_id}")
}

/// RFC 7644 §3.3: successful creates return 201 with a Location header
/// pointing at the created resource.
fn created_response(location: &str, resource: impl Serialize) -> Response {
    (
        StatusCode::CREATED,
        [(header::LOCATION, location.to_string())],
        Json(resource),
    )
        .into_response()
}

/// Parse a JSON request body into a typed DTO, converting both malformed
/// payloads and shape mismatches into SCIM-formatted 400 errors.
fn parse_json_body<T: DeserializeOwned>(
    body: Result<Json<serde_json::Value>, JsonRejection>,
    resource: &str,
) -> Result<T, ScimError> {
    let Json(raw) = body.map_err(|rejection| {
        ScimError::bad_request(format!("malformed {resource} request body: {rejection}"))
    })?;
    serde_json::from_value(raw)
        .map_err(|error| ScimError::bad_request(format!("invalid {resource} resource: {error}")))
}

// ─── Lifecycle enforcement (F41) ───────────────────────────────

/// Insert a SCIM-provisioned user with the lifecycle the caller requested
/// (`active=false` lands as `deactivated`, not silently `active`).
async fn insert_scim_user(
    db: &sqlx::PgPool,
    tenant_id: &str,
    id: Uuid,
    email: &str,
    name: Option<&str>,
    active: bool,
) -> Result<(), ApiError> {
    // users.id is UUID on the canonical schema (audit 1.6) — the previous
    // text-id insert (generate_id) failed at runtime exactly like the SSO
    // twin did before its fix.
    // SCIM users must authenticate via SSO; direct password login is blocked
    // via the never-valid Argon2 placeholder hash.
    let result = sqlx::query(
        "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,'member',$6,NOW(),NOW())",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(email)
    .bind(name)
    .bind(SCIM_DISABLED_HASH)
    .bind(status_for_active(active))
    .execute(db)
    .await;

    match result {
        Ok(_) => Ok(()),
        Err(error) if is_unique_violation(&error) => {
            Err(ApiError::Conflict("user already exists".into()))
        }
        Err(error) => Err(error.into()),
    }
}

/// Single-statement user write shared by replace and PATCH: one UPDATE
/// covers every planned change, so a multi-operation PATCH is atomic.
async fn apply_user_patch(
    db: &sqlx::PgPool,
    tenant_id: &str,
    id: &str,
    email: &str,
    name: Option<&str>,
    active: bool,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        "UPDATE users SET email=$1, name=$2, status=$3, updated_at=NOW()
         WHERE id=$4::uuid AND tenant_id=$5",
    )
    .bind(email)
    .bind(name)
    .bind(status_for_active(active))
    .bind(id)
    .bind(tenant_id)
    .execute(db)
    .await
    .map(|result| result.rows_affected())
}

/// Session revocation on SCIM deactivation (F41): writes the
/// `apexmail:session_revoked_after:{tenant}:{user}` marker the auth
/// middleware checks on every request — same mechanism as the password
/// change / admin disable flows (see the private
/// `routes::web::revoke_user_sessions`; the key builder itself is shared
/// via `middleware::auth::session_revocation_key`).
async fn revoke_user_sessions(state: &AppState, tenant_id: &str, user_id: &str) {
    let key = session_revocation_key(tenant_id, user_id);
    let ttl = state.config.jwt_expiry.as_secs();
    if let Ok(mut conn) = state.redis.get().await {
        let now = Utc::now().timestamp();
        let _: Result<(), _> =
            deadpool_redis::redis::AsyncCommands::set_ex(&mut *conn, key, now, ttl).await;
    }
}

/// Deactivation side effects shared by create/replace/patch/delete (F41):
/// the user-status auth cache is invalidated on every user write, and any
/// final deactivated state revokes all live sessions for that user.
async fn enforce_lifecycle_authz(state: &AppState, tenant_id: &str, user_id: &str, active: bool) {
    invalidate_user_status_cache(user_id, tenant_id, state).await;
    if !active {
        revoke_user_sessions(state, tenant_id, user_id).await;
    }
}

// ─── Filter parsing (F42) ──────────────────────────────────────

/// Bounded SCIM filter for Users. `userName` and `emails.value` are both
/// backed by the stored (lowercased) `email` column; `externalId` is
/// syntactically supported but matches nothing because ApexMail does not
/// persist external ids — reporting zero results is more honest than
/// silently ignoring the parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ScimUserFilter {
    /// Case-insensitive equality against the stored email (SCIM eq over
    /// non-caseExact string attributes).
    Email(String),
    /// Supported attribute with no stored values: an eq filter matches no
    /// resource.
    NeverMatches,
}

/// Parse a bounded `<attribute> eq "<literal>"` filter (RFC 7644 §3.4.2.2).
///
/// Everything outside that grammar — other operators, `and`/`or`,
/// unquoted or unterminated literals, unknown escapes, oversized input —
/// is rejected with a descriptive error instead of being half-applied.
/// The literal never reaches SQL as text: handlers bind it as a parameter.
fn parse_scim_filter(raw: &str) -> Result<ScimUserFilter, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("filter must not be empty".into());
    }
    if raw.len() > MAX_SCIM_FILTER_LEN {
        return Err(format!(
            "filter exceeds the {MAX_SCIM_FILTER_LEN}-character limit"
        ));
    }

    let mut parts = raw.splitn(2, char::is_whitespace);
    let attribute = parts.next().unwrap_or_default();
    let Some(rest) = parts.next() else {
        return Err("filter must be of the form '<attribute> eq \"<value>\"'".into());
    };

    let rest = rest.trim_start();
    let operator_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let (operator, literal_part) = rest.split_at(operator_end);
    if !operator.eq_ignore_ascii_case("eq") {
        return Err(format!(
            "unsupported filter operator '{operator}': only 'eq' is supported"
        ));
    }

    match attribute.to_lowercase().as_str() {
        "username" | "emails.value" => Ok(ScimUserFilter::Email(
            parse_quoted_filter_literal(literal_part.trim_start())?.to_lowercase(),
        )),
        "externalid" => {
            let _ = parse_quoted_filter_literal(literal_part.trim_start())?;
            Ok(ScimUserFilter::NeverMatches)
        }
        other => Err(format!(
            "unsupported filter attribute '{other}': supported attributes are userName, emails.value and externalId"
        )),
    }
}

/// Parse one double-quoted SCIM filter literal, decoding the RFC 7644
/// `\"`, `\\` and `\/` escapes. Rejects unterminated literals, unescaped
/// quotes, unknown escapes, control characters and trailing garbage (which
/// also covers `and`/`or` composition).
fn parse_quoted_filter_literal(raw: &str) -> Result<String, String> {
    let Some(rest) = raw.strip_prefix('"') else {
        return Err("filter value must be a double-quoted string".into());
    };

    let mut decoded = String::with_capacity(rest.len());
    let mut chars = rest.chars().peekable();
    while let Some(current) = chars.next() {
        match current {
            '"' => {
                if chars.next().is_some() {
                    return Err(
                        "unexpected trailing characters after the filter value (combined filters are not supported)"
                            .into(),
                    );
                }
                return Ok(decoded);
            }
            '\\' => match chars.next() {
                Some(escaped @ ('"' | '\\' | '/')) => decoded.push(escaped),
                Some(other) => {
                    return Err(format!("unsupported escape '\\{other}' in filter value"))
                }
                None => return Err("filter value ends with a dangling backslash".into()),
            },
            control if control.is_control() => {
                return Err("control characters are not allowed in filter values".into())
            }
            other => decoded.push(other),
        }
    }
    Err("filter value is not terminated by a double quote".into())
}

// ─── Pagination normalization (F43) ─────────────────────────────

#[derive(Debug, PartialEq, Eq)]
struct NormalizedScimPage {
    /// 1-based page start, echoed in ListResponse.startIndex.
    start_index: i64,
    /// 0-based SQL OFFSET (start_index - 1; never negative, overflow-free).
    offset: i64,
    /// Page size clamped to 0..=MAX_SCIM_COUNT. 0 means "report totals
    /// only": no Resources, but totalResults is still present.
    count: i64,
}

/// Exact normalization contract (F43): `cursor` wins over `startIndex`,
/// `startIndex` below 1 normalizes to 1 (which also makes the `- 1`
/// subtraction overflow-free even for `i64::MIN`), and `count` clamps to
/// 0..=MAX_SCIM_COUNT (negatives → 0).
fn normalize_scim_page(params: &ScimListQuery) -> NormalizedScimPage {
    let start_index = params.cursor.unwrap_or(params.start_index).max(1);
    let offset = start_index - 1;
    let count = params.count.clamp(0, MAX_SCIM_COUNT);
    NormalizedScimPage {
        start_index,
        offset,
        count,
    }
}

/// Build a ListResponse whose metadata cannot contradict the query (F43):
/// `startIndex` is the normalized value and `itemsPerPage` is the number of
/// resources actually returned (never the raw requested count).
fn scim_list_response<T: Serialize>(
    total_results: i64,
    start_index: i64,
    resources: Vec<T>,
) -> ScimListResponse<T> {
    ScimListResponse {
        schemas: vec![SCIM_LIST_SCHEMA.into()],
        total_results,
        start_index,
        items_per_page: resources.len() as i64,
        resources,
    }
}

// ─── User PATCH planning (F42) ─────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScimPatchOp {
    op: String,
    path: Option<String>,
    value: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScimPatchRequest {
    #[serde(rename = "Operations")]
    operations: Vec<ScimPatchOp>,
}

/// Folded result of a User PATCH request: only the attributes a supported
/// operation touched are present. `name: Some(None)` means "clear the
/// stored name" (remove name.givenName).
#[derive(Debug, Default, PartialEq, Eq)]
struct UserPatchChanges {
    email: Option<String>,
    name: Option<Option<String>>,
    active: Option<bool>,
}

fn patch_string_value(
    value: Option<&serde_json::Value>,
    index: usize,
    attribute: &str,
) -> Result<String, String> {
    match value {
        Some(serde_json::Value::String(text)) if !text.trim().is_empty() => Ok(text.clone()),
        Some(serde_json::Value::String(_)) => Err(format!(
            "Operations[{index}]: '{attribute}' must not be empty"
        )),
        _ => Err(format!(
            "Operations[{index}]: '{attribute}' requires a non-empty string value"
        )),
    }
}

fn patch_bool_value(
    value: Option<&serde_json::Value>,
    index: usize,
    attribute: &str,
) -> Result<bool, String> {
    match value {
        Some(serde_json::Value::Bool(flag)) => Ok(*flag),
        _ => Err(format!(
            "Operations[{index}]: '{attribute}' requires a boolean value"
        )),
    }
}

/// Validate and fold ALL patch operations into a change set BEFORE any
/// mutation (F42 atomicity): one invalid operation rejects the whole
/// request, and the handler only reaches the database after this returns
/// Ok. Supported paths are `userName`, `active` and `name.givenName` with
/// add/replace (RFC 7644 §3.5.2: add onto an existing single-valued
/// attribute replaces it) and remove (`name.givenName` only). The RFC's
/// path-less form (`{"op":"replace","value":{"active":false}}`, as sent by
/// Azure AD) applies the writable subset of the object value.
fn plan_user_patch(request: &ScimPatchRequest) -> Result<UserPatchChanges, String> {
    let mut changes = UserPatchChanges::default();

    for (index, operation) in request.operations.iter().enumerate() {
        let op = operation.op.trim().to_lowercase();
        let path = operation.path.as_deref().map(str::trim);

        match (op.as_str(), path) {
            ("add" | "replace", None) => {
                let Some(serde_json::Value::Object(fields)) = &operation.value else {
                    return Err(format!(
                        "Operations[{index}]: '{op}' without a path requires an object value"
                    ));
                };
                for (field, value) in fields {
                    match field.as_str() {
                        "userName" => {
                            changes.email =
                                Some(patch_string_value(Some(value), index, "userName")?);
                        }
                        "active" => {
                            changes.active = Some(patch_bool_value(Some(value), index, "active")?);
                        }
                        "name" => {
                            if let serde_json::Value::Object(name_fields) = value {
                                for (name_field, name_value) in name_fields {
                                    if name_field == "givenName" {
                                        changes.name = Some(Some(patch_string_value(
                                            Some(name_value),
                                            index,
                                            "name.givenName",
                                        )?));
                                    }
                                    // Other name sub-attributes have no
                                    // storage (same as create/replace).
                                }
                            }
                        }
                        // Unknown attributes in the merge object are
                        // ignored, consistent with create/replace bodies.
                        _ => {}
                    }
                }
            }
            ("add" | "replace", Some(attribute)) => match attribute {
                "userName" => {
                    changes.email =
                        Some(patch_string_value(operation.value.as_ref(), index, "userName")?)
                }
                "active" => {
                    changes.active =
                        Some(patch_bool_value(operation.value.as_ref(), index, "active")?)
                }
                "name.givenName" => changes.name = Some(Some(patch_string_value(
                    operation.value.as_ref(),
                    index,
                    "name.givenName",
                )?)),
                other => {
                    return Err(format!(
                        "Operations[{index}]: unsupported path '{other}' (supported: userName, active, name.givenName)"
                    ))
                }
            },
            ("remove", None) => {
                return Err(format!(
                    "Operations[{index}]: 'remove' requires a path (RFC 7644 §3.5.2.3)"
                ))
            }
            ("remove", Some(attribute)) => match attribute {
                "name.givenName" => changes.name = Some(None),
                "userName" | "active" => {
                    return Err(format!(
                        "Operations[{index}]: cannot remove required attribute '{attribute}'"
                    ))
                }
                other => {
                    return Err(format!(
                        "Operations[{index}]: unsupported path '{other}' (supported: userName, active, name.givenName)"
                    ))
                }
            },
            _ => {
                return Err(format!(
                    "Operations[{index}]: invalid op '{}' (must be add, replace or remove)",
                    operation.op.trim()
                ))
            }
        }
    }

    Ok(changes)
}

// ─── Handlers: Users ───────────────────────────────────────────

async fn list_users(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ScimListQuery>,
) -> Result<Json<ScimListResponse<ScimUser>>, ScimError> {
    require_scopes(&auth, &["scim:read"])?;

    let page = normalize_scim_page(&params);
    let filter = match params.filter.as_deref() {
        Some(raw) => Some(parse_scim_filter(raw).map_err(ScimError::bad_request)?),
        None => None,
    };

    let (total, rows): (i64, Vec<UserScimRow>) = match &filter {
        // externalId has no stored values, so an eq filter matches nothing.
        Some(ScimUserFilter::NeverMatches) => (0, Vec::new()),
        Some(ScimUserFilter::Email(value)) => {
            // Binds only — the literal never becomes SQL text (F42).
            let total = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND LOWER(email) = $2",
            )
            .bind(&auth.tenant_id)
            .bind(value)
            .fetch_one(&state.db)
            .await?;
            let rows = if page.count == 0 {
                Vec::new()
            } else {
                sqlx::query_as::<_, UserScimRow>(
                    "SELECT id::text, email, name, status FROM users
                     WHERE tenant_id = $1 AND LOWER(email) = $2
                     ORDER BY email LIMIT $3 OFFSET $4",
                )
                .bind(&auth.tenant_id)
                .bind(value)
                .bind(page.count)
                .bind(page.offset)
                .fetch_all(&state.db)
                .await?
            };
            (total, rows)
        }
        None => {
            let total =
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE tenant_id = $1")
                    .bind(&auth.tenant_id)
                    .fetch_one(&state.db)
                    .await?;
            // count=0: no Resources, but totalResults is still reported (F43).
            let rows = if page.count == 0 {
                Vec::new()
            } else {
                sqlx::query_as::<_, UserScimRow>(
                    "SELECT id::text, email, name, status FROM users WHERE tenant_id = $1 ORDER BY email LIMIT $2 OFFSET $3",
                )
                .bind(&auth.tenant_id)
                .bind(page.count)
                .bind(page.offset)
                .fetch_all(&state.db)
                .await?
            };
            (total, rows)
        }
    };

    let resources: Vec<ScimUser> = rows
        .into_iter()
        .map(|row| canonical_scim_user(row.id, row.email, row.name, row.status == "active"))
        .collect();

    Ok(Json(scim_list_response(total, page.start_index, resources)))
}

async fn create_user(
    State(state): State<AppState>,
    auth: AuthUser,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Response, ScimError> {
    require_scopes(&auth, &["scim:write"])?;
    let request: UserUpsertRequest = parse_json_body(body, "User")?;
    validate_user_upsert(&request)?;

    let email = derive_user_email(&request);
    if !is_plausible_email(&email) {
        return Err(ScimError::bad_request(format!(
            "userName/emails[0].value must be a valid address, got '{email}'"
        )));
    }
    let name = request
        .name
        .as_ref()
        .and_then(|name| name.given_name.clone());

    // F40 / RFC 7643 §7: `id` is server-assigned. The request DTO has no id
    // field, so any client-supplied id was ignored during deserialization.
    let id = Uuid::new_v4();

    insert_scim_user(
        &state.db,
        &auth.tenant_id,
        id,
        &email,
        name.as_deref(),
        request.active,
    )
    .await?;

    // F41: a user provisioned inactive must land deactivated with no usable
    // auth (no live sessions, no stale status-cache entries).
    enforce_lifecycle_authz(&state, &auth.tenant_id, &id.to_string(), request.active).await;

    log_scim_audit(
        &state,
        &auth,
        "scim.user.created",
        "scim_user",
        Some(&id.to_string()),
        serde_json::json!({
            "email": email,
            "role": "member",
            "status": status_for_active(request.active),
        }),
    )
    .await;

    // 201 + Location + the canonical stored resource (F40).
    Ok(created_response(
        &user_location(&id.to_string()),
        canonical_scim_user(id.to_string(), email, name, request.active),
    ))
}

async fn get_user(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<ScimUser>, ScimError> {
    require_scopes(&auth, &["scim:read"])?;

    let row = sqlx::query_as::<_, UserScimRow>(
        "SELECT id::text, email, name, status FROM users WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ScimError::not_found("user not found"))?;

    Ok(Json(canonical_scim_user(
        row.id,
        row.email,
        row.name,
        row.status == "active",
    )))
}

async fn update_user(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Json<ScimUser>, ScimError> {
    require_scopes(&auth, &["scim:write"])?;
    let request: UserUpsertRequest = parse_json_body(body, "User")?;
    validate_user_upsert(&request)?;

    let email = derive_user_email(&request);
    // Never blank: an empty email locks every lookup path (login, password
    // reset, SCIM get) for the user.
    if !is_plausible_email(&email) {
        return Err(ScimError::bad_request(format!(
            "userName/emails[0].value must be a valid address, got '{email}'"
        )));
    }
    let name = request
        .name
        .as_ref()
        .and_then(|name| name.given_name.clone());

    // Privilege-surface guard (P2-1): rewriting an admin/owner's email
    // moves their identity to an address the SCIM caller controls — an
    // in-tenant takeover primitive for any scim:write holder. Members may
    // be re-emailed by the IdP; privileged roles must be changed through
    // the console, not SCIM.
    let current: Option<(String, String)> =
        sqlx::query_as("SELECT email, role FROM users WHERE id = $1::uuid AND tenant_id = $2")
            .bind(&id)
            .bind(&auth.tenant_id)
            .fetch_optional(&state.db)
            .await?;
    let Some((current_email, current_role)) = current else {
        return Err(ScimError::not_found("user not found"));
    };
    let email_changed = email != current_email;
    if email_changed && matches!(current_role.as_str(), "admin" | "owner") {
        return Err(ScimError::forbidden(
            "SCIM cannot change the email of an admin or owner user",
        ));
    }

    // F41: PUT maps `active` through the same lifecycle mapping as create
    // and PATCH, and deactivation revokes sessions + invalidates caches.
    let rows = apply_user_patch(
        &state.db,
        &auth.tenant_id,
        &id,
        &email,
        name.as_deref(),
        request.active,
    )
    .await?;
    if rows == 0 {
        return Err(ScimError::not_found("user not found"));
    }

    enforce_lifecycle_authz(&state, &auth.tenant_id, &id, request.active).await;

    log_scim_audit(
        &state,
        &auth,
        "scim.user.updated",
        "scim_user",
        Some(&id),
        serde_json::json!({
            "email": email,
            "emailChanged": email_changed,
            "status": status_for_active(request.active),
        }),
    )
    .await;

    Ok(Json(canonical_scim_user(id, email, name, request.active)))
}

async fn patch_user(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Json<ScimUser>, ScimError> {
    require_scopes(&auth, &["scim:write"])?;
    let request: ScimPatchRequest = parse_json_body(body, "User PATCH")?;

    let current: Option<(String, Option<String>, String, String)> = sqlx::query_as(
        "SELECT email, name, status, role FROM users WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((current_email, current_name, current_status, current_role)) = current else {
        return Err(ScimError::not_found("user not found"));
    };

    // F42 atomicity: every operation is validated before any mutation — a
    // single invalid op rejects the whole request and leaves the user
    // untouched.
    let changes = plan_user_patch(&request).map_err(ScimError::bad_request)?;
    let UserPatchChanges {
        email: change_email,
        name: change_name,
        active: change_active,
    } = changes;

    // Fold onto the current stored state (later operations win).
    let email = change_email
        .map(|value| value.trim().to_lowercase())
        .unwrap_or(current_email.clone());
    let name = change_name.unwrap_or(current_name);
    let active = change_active.unwrap_or(current_status == "active");

    let email_changed = email != current_email;
    if email_changed {
        if !is_plausible_email(&email) {
            return Err(ScimError::bad_request(format!(
                "userName/emails[0].value must be a valid address, got '{email}'"
            )));
        }
        // Same privilege-surface guard as PUT (P2-1).
        if matches!(current_role.as_str(), "admin" | "owner") {
            return Err(ScimError::forbidden(
                "SCIM cannot change the email of an admin or owner user",
            ));
        }
    }

    // One UPDATE covers the whole folded plan → atomic write.
    let rows = apply_user_patch(
        &state.db,
        &auth.tenant_id,
        &id,
        &email,
        name.as_deref(),
        active,
    )
    .await?;
    if rows == 0 {
        return Err(ScimError::not_found("user not found"));
    }

    enforce_lifecycle_authz(&state, &auth.tenant_id, &id, active).await;

    log_scim_audit(
        &state,
        &auth,
        "scim.user.patched",
        "scim_user",
        Some(&id),
        serde_json::json!({
            "email": email,
            "emailChanged": email_changed,
            "status": status_for_active(active),
        }),
    )
    .await;

    Ok(Json(canonical_scim_user(id, email, name, active)))
}

async fn delete_user(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ScimError> {
    require_scopes(&auth, &["scim:write"])?;

    let result = sqlx::query(
        "UPDATE users SET status = 'deactivated', updated_at = NOW() WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ScimError::not_found("user not found"));
    }

    // Delete is a deactivation (F41): sessions must die with it.
    enforce_lifecycle_authz(&state, &auth.tenant_id, &id, false).await;

    log_scim_audit(
        &state,
        &auth,
        "scim.user.deleted",
        "scim_user",
        Some(&id),
        serde_json::json!({ "deactivated": true }),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

// ─── Handlers: Groups ──────────────────────────────────────────

async fn list_groups(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ScimListQuery>,
) -> Result<Json<ScimListResponse<ScimGroup>>, ScimError> {
    require_scopes(&auth, &["scim:read"])?;

    // Only Users support filtering (see /ServiceProviderConfig); say so
    // instead of silently ignoring the parameter.
    if params
        .filter
        .as_deref()
        .map(str::trim)
        .is_some_and(|filter| !filter.is_empty())
    {
        return Err(ScimError::bad_request("filter is only supported for Users"));
    }

    let page = normalize_scim_page(&params);
    let total =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM scim_groups WHERE tenant_id = $1")
            .bind(&auth.tenant_id)
            .fetch_one(&state.db)
            .await?;

    let group_rows = if page.count == 0 {
        Vec::new()
    } else {
        sqlx::query_as::<_, GroupScimRow>(
            "SELECT id, scim_id, display_name, created_at FROM scim_groups
             WHERE tenant_id = $1 ORDER BY display_name LIMIT $2 OFFSET $3",
        )
        .bind(&auth.tenant_id)
        .bind(page.count)
        .bind(page.offset)
        .fetch_all(&state.db)
        .await?
    };

    let group_ids: Vec<String> = group_rows.iter().map(|row| row.id.clone()).collect();
    let all_members = if group_ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_as::<_, GroupMemberWithGroupRow>(
            "SELECT m.group_id, m.user_id, m.display, u.email
             FROM scim_group_members m
             LEFT JOIN users u ON u.id = m.user_id
             WHERE m.group_id = ANY($1) AND m.tenant_id = $2",
        )
        .bind(&group_ids)
        .bind(auth.tenant_id.to_string())
        .fetch_all(&state.db)
        .await?
    };

    // Group members by group_id for efficient lookup.
    let mut members_by_group: std::collections::HashMap<String, Vec<ScimMember>> =
        std::collections::HashMap::new();
    for member in all_members {
        members_by_group
            .entry(member.group_id.clone())
            .or_default()
            .push(ScimMember {
                value: member.user_id.to_string(),
                display: member.display.or(member.email),
            });
    }

    let resources: Vec<ScimGroup> = group_rows
        .into_iter()
        .map(|row| ScimGroup {
            schemas: vec![SCIM_GROUP_SCHEMA.into()],
            id: row.scim_id,
            display_name: row.display_name,
            members: members_by_group.remove(&row.id).unwrap_or_default(),
        })
        .collect();

    Ok(Json(scim_list_response(total, page.start_index, resources)))
}

async fn create_group(
    State(state): State<AppState>,
    auth: AuthUser,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Response, ScimError> {
    require_scopes(&auth, &["scim:write"])?;
    let request: GroupUpsertRequest = parse_json_body(body, "Group")?;
    validate_group_upsert(&request)?;
    let display_name = request.display_name.clone().unwrap_or_default();

    // F40: the SCIM-visible id is server-generated (UUID); a client-supplied
    // id in the body is ignored by the request DTO.
    let id = Uuid::new_v4();
    let scim_id = id.to_string();
    let now = Utc::now();

    // Audit C: verify every member belongs to the caller's tenant BEFORE the
    // group row is written — foreign-tenant user UUIDs must be rejected with
    // a 400 and leave no group row behind, instead of being silently
    // enrolled and later exposed via list/get (their emails leak through the
    // users JOIN display fallback).
    let member_ids = validate_members_in_tenant(
        &state.db,
        &auth.tenant_id,
        &request
            .members
            .iter()
            .map(|member| member.value.clone())
            .collect::<Vec<_>>(),
    )
    .await?;

    sqlx::query(
        "INSERT INTO scim_groups (id, tenant_id, display_name, scim_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $5)",
    )
    .bind(id)
    .bind(auth.tenant_id.to_string())
    .bind(&display_name)
    .bind(&scim_id)
    .bind(now)
    .execute(&state.db)
    .await?;

    // Add members if provided (validated above)
    for (member, user_id) in request.members.iter().zip(member_ids) {
        sqlx::query(
            "INSERT INTO scim_group_members (group_id, user_id, tenant_id, display, created_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (group_id, user_id) DO NOTHING",
        )
        .bind(id)
        .bind(user_id)
        .bind(auth.tenant_id.to_string())
        .bind(&member.display)
        .bind(now)
        .execute(&state.db)
        .await?;
    }

    log_scim_audit(
        &state,
        &auth,
        "scim.group.created",
        "scim_group",
        Some(&scim_id),
        serde_json::json!({
            "displayName": display_name,
            "memberCount": request.members.len(),
        }),
    )
    .await;

    Ok(created_response(
        &group_location(&scim_id),
        ScimGroup {
            schemas: vec![SCIM_GROUP_SCHEMA.into()],
            id: scim_id,
            display_name,
            members: request.members,
        },
    ))
}

async fn get_group(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(scim_id): Path<String>,
) -> Result<Json<ScimGroup>, ScimError> {
    require_scopes(&auth, &["scim:read"])?;

    let row = sqlx::query_as::<_, GroupScimRow>(
        "SELECT id, scim_id, display_name, created_at FROM scim_groups
         WHERE scim_id = $1 AND tenant_id = $2",
    )
    .bind(&scim_id)
    .bind(auth.tenant_id.to_string())
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ScimError::not_found("group not found"))?;

    let members = sqlx::query_as::<_, GroupMemberRow>(
        "SELECT m.user_id, m.display, u.email
         FROM scim_group_members m
         LEFT JOIN users u ON u.id = m.user_id
            WHERE m.group_id = $1 AND m.tenant_id = $2",
    )
    .bind(row.id.clone())
    .bind(auth.tenant_id.to_string())
    .fetch_all(&state.db)
    .await?;

    Ok(Json(ScimGroup {
        schemas: vec![SCIM_GROUP_SCHEMA.into()],
        id: row.scim_id,
        display_name: row.display_name,
        members: members
            .into_iter()
            .map(|member| ScimMember {
                value: member.user_id.to_string(),
                display: member.display.or(member.email),
            })
            .collect(),
    }))
}

async fn update_group(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(scim_id): Path<String>,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Json<ScimGroup>, ScimError> {
    require_scopes(&auth, &["scim:write"])?;
    let request: GroupUpsertRequest = parse_json_body(body, "Group")?;
    validate_group_upsert(&request)?;

    let row = sqlx::query_as::<_, GroupScimRow>(
        "SELECT id, scim_id, display_name, created_at FROM scim_groups
         WHERE scim_id = $1 AND tenant_id = $2",
    )
    .bind(&scim_id)
    .bind(auth.tenant_id.to_string())
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ScimError::not_found("group not found"))?;

    // Validate the REPLACEMENT member list BEFORE any mutation (P3): the
    // previous order deleted the existing members first and validated
    // after — a bad replacement list left the group permanently emptied.
    let now = Utc::now();
    // Audit C: every replacement member must belong to the caller's tenant.
    let member_ids = validate_members_in_tenant(
        &state.db,
        &auth.tenant_id,
        &request
            .members
            .iter()
            .map(|member| member.value.clone())
            .collect::<Vec<_>>(),
    )
    .await?;

    // One transaction for delete+insert (P3): a mid-flight failure used to
    // leave the group with members deleted but replacements missing.
    let mut tx = state.db.begin().await?;

    sqlx::query("UPDATE scim_groups SET display_name = $1, updated_at = NOW() WHERE id = $2")
        .bind(&request.display_name)
        .bind(&row.id)
        .execute(&mut *tx)
        .await?;

    // Replace members entirely
    sqlx::query("DELETE FROM scim_group_members WHERE group_id = $1 AND tenant_id = $2")
        .bind(&row.id)
        .bind(auth.tenant_id.to_string())
        .execute(&mut *tx)
        .await?;

    for (member, user_id) in request.members.iter().zip(member_ids) {
        sqlx::query(
            "INSERT INTO scim_group_members (group_id, user_id, tenant_id, display, created_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&row.id)
        .bind(user_id)
        .bind(auth.tenant_id.to_string())
        .bind(&member.display)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    log_scim_audit(
        &state,
        &auth,
        "scim.group.updated",
        "scim_group",
        Some(&scim_id),
        serde_json::json!({
            "displayName": request.display_name,
            "memberCount": request.members.len(),
        }),
    )
    .await;

    Ok(Json(ScimGroup {
        schemas: vec![SCIM_GROUP_SCHEMA.into()],
        id: scim_id,
        display_name: request.display_name.unwrap_or_default(),
        members: request.members,
    }))
}

async fn patch_group(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(scim_id): Path<String>,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Json<ScimGroup>, ScimError> {
    require_scopes(&auth, &["scim:write"])?;
    let request: ScimPatchRequest = parse_json_body(body, "Group PATCH")?;

    let row = sqlx::query_as::<_, GroupScimRow>(
        "SELECT id, scim_id, display_name, created_at FROM scim_groups
         WHERE scim_id = $1 AND tenant_id = $2",
    )
    .bind(&scim_id)
    .bind(auth.tenant_id.to_string())
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ScimError::not_found("group not found"))?;

    let mut display_name = row.display_name.clone();
    let now = Utc::now();
    // Count of operations that actually mutated the group — the audit entry
    // distinguishes "nothing applied" (bad paths) from real changes.
    let mut applied_ops = 0u32;

    for op in request.operations {
        match op.op.to_lowercase().as_str() {
            "replace" => {
                if op.path.as_deref() == Some("displayName") {
                    if let Some(serde_json::Value::String(val)) = op.value {
                        display_name = val;
                        sqlx::query("UPDATE scim_groups SET display_name = $1, updated_at = NOW() WHERE id = $2")
                            .bind(&display_name)
                            .bind(&row.id)
                            .execute(&state.db)
                            .await?;
                        applied_ops += 1;
                    }
                }
            }
            "add" => {
                if op.path.as_deref() == Some("members") {
                    if let Some(serde_json::Value::Array(members)) = op.value {
                        let mut values = Vec::with_capacity(members.len());
                        for member in &members {
                            if let Some(value) = member.get("value").and_then(|v| v.as_str()) {
                                values.push(value.to_string());
                            }
                        }
                        // Audit C: added members must belong to the caller's
                        // tenant — same rule as create/update.
                        let validated =
                            validate_members_in_tenant(&state.db, &auth.tenant_id, &values).await?;
                        for (member, user_id) in members.iter().zip(validated) {
                            let display = member
                                .get("display")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                            sqlx::query(
                                "INSERT INTO scim_group_members (group_id, user_id, tenant_id, display, created_at)
                                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (group_id, user_id) DO NOTHING",
                            )
                            .bind(&row.id)
                            .bind(user_id)
                            .bind(auth.tenant_id.to_string())
                            .bind(&display)
                            .bind(now)
                            .execute(&state.db)
                            .await?;
                        }
                        applied_ops += 1;
                    }
                }
            }
            "remove" => {
                if let Some(path) = &op.path {
                    // Path like: members[value eq "user-uuid"]. Parse EXACTLY
                    // once (parse_member_removal_path) — the previous
                    // repeated trim matches mangled ids containing '"' or ']'
                    // into silently-wrong deletions.
                    if let Some(user_id_str) = parse_member_removal_path(path) {
                        if let Ok(user_id) = Uuid::parse_str(user_id_str) {
                            sqlx::query(
                                "DELETE FROM scim_group_members WHERE group_id = $1 AND user_id = $2 AND tenant_id = $3",
                            )
                            .bind(&row.id)
                            .bind(user_id)
                            .bind(auth.tenant_id.to_string())
                            .execute(&state.db)
                            .await?;
                            applied_ops += 1;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Fetch updated members
    let members = sqlx::query_as::<_, GroupMemberRow>(
        "SELECT m.user_id, m.display, u.email
         FROM scim_group_members m
         LEFT JOIN users u ON u.id = m.user_id
            WHERE m.group_id = $1 AND m.tenant_id = $2",
    )
    .bind(&row.id)
    .bind(auth.tenant_id.to_string())
    .fetch_all(&state.db)
    .await?;

    log_scim_audit(
        &state,
        &auth,
        "scim.group.patched",
        "scim_group",
        Some(&scim_id),
        serde_json::json!({ "appliedOperations": applied_ops }),
    )
    .await;

    Ok(Json(ScimGroup {
        schemas: vec![SCIM_GROUP_SCHEMA.into()],
        id: scim_id,
        display_name,
        members: members
            .into_iter()
            .map(|member| ScimMember {
                value: member.user_id.to_string(),
                display: member.display.or(member.email),
            })
            .collect(),
    }))
}

async fn delete_group(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(scim_id): Path<String>,
) -> Result<StatusCode, ScimError> {
    require_scopes(&auth, &["scim:write"])?;

    let result = sqlx::query("DELETE FROM scim_groups WHERE scim_id = $1 AND tenant_id = $2")
        .bind(&scim_id)
        .bind(auth.tenant_id.to_string())
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ScimError::not_found("group not found"));
    }

    log_scim_audit(
        &state,
        &auth,
        "scim.group.deleted",
        "scim_group",
        Some(&scim_id),
        serde_json::json!({}),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

// ─── Handlers: capabilities ────────────────────────────────────

/// RFC 7644 ServiceProviderConfig document — advertises exactly what these
/// routes implement (F42): PATCH on Users and Groups, bounded `eq`
/// filtering on Users, and no sort/bulk/etag/changePassword support.
fn service_provider_config_document() -> serde_json::Value {
    serde_json::json!({
        "schemas": [SCIM_SPC_SCHEMA],
        "patch": { "supported": true },
        "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter": { "supported": true, "maxResults": MAX_SCIM_COUNT },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": false },
    })
}

async fn service_provider_config(auth: AuthUser) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["scim:read"])?;
    Ok(Json(service_provider_config_document()))
}

// ─── Shared group helpers ──────────────────────────────────────

/// Parse a SCIM `remove` filter path of the exact form
/// `members[value eq "<uuid>"]`. Prefix/suffix are stripped EXACTLY ONCE
/// and the remainder rejected if it still contains quoting characters —
/// the previous repeated trim_start/trim_end matches mangled ids
/// containing `"` or `]` into different, silently-wrong deletions.
fn parse_member_removal_path(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("members[value eq \"")?;
    let value = rest.strip_suffix("\"]")?;
    if value.contains('"') || value.contains(']') {
        return None;
    }
    Some(value)
}

/// Validate that every SCIM group member reference resolves to a user that
/// exists AND belongs to the caller's tenant (audit C).
///
/// Previously the member `value` UUIDs were inserted into
/// `scim_group_members` without any ownership check, so a tenant admin could
/// enrol arbitrary foreign-tenant user UUIDs into their SCIM group; the
/// group list/get endpoints then exposed those users' email addresses via
/// the `LEFT JOIN users` display fallback.
///
/// Returns the parsed, tenant-verified user UUIDs in the same order as
/// `values`, or a 400 listing how many references failed validation.
async fn validate_members_in_tenant(
    db: &sqlx::PgPool,
    tenant_id: &str,
    values: &[String],
) -> Result<Vec<Uuid>, ApiError> {
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        let user_id = Uuid::parse_str(value).map_err(|_| {
            ApiError::BadRequest(format!("invalid member id '{value}': must be a user UUID"))
        })?;
        parsed.push(user_id);
    }

    if parsed.is_empty() {
        return Ok(parsed);
    }

    let found: Vec<(uuid::Uuid,)> =
        sqlx::query_as("SELECT id FROM users WHERE id = ANY($1) AND tenant_id = $2")
            .bind(&parsed)
            .bind(tenant_id)
            .fetch_all(db)
            .await
            .map_err(|error| {
                tracing::error!(error = %error, tenant_id = %tenant_id, "SCIM member tenant validation query failed");
                ApiError::Internal("database error".into())
            })?;

    let found_ids: std::collections::HashSet<Uuid> = found.into_iter().map(|(id,)| id).collect();
    let invalid_count = parsed.iter().filter(|id| !found_ids.contains(id)).count();

    if invalid_count > 0 {
        return Err(ApiError::BadRequest(format!(
            "{invalid_count} member(s) do not exist in this tenant"
        )));
    }

    Ok(parsed)
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct UserScimRow {
    id: String,
    email: String,
    name: Option<String>,
    status: String,
}

#[derive(sqlx::FromRow)]
struct GroupScimRow {
    id: String,
    scim_id: String,
    display_name: String,
    #[expect(
        dead_code,
        reason = "SCIM group row keeps created_at for stable SELECT mapping"
    )]
    created_at: chrono::DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct GroupMemberRow {
    user_id: String,
    display: Option<String>,
    email: Option<String>,
}

#[derive(sqlx::FromRow)]
struct GroupMemberWithGroupRow {
    group_id: String,
    user_id: String,
    display: Option<String>,
    email: Option<String>,
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── User Serialization ──────────────────────────────────────

    #[test]
    fn test_scim_user_serialisation() {
        let user = canonical_scim_user(
            String::new(),
            "alice@example.com".into(),
            Some("Alice".into()),
            true,
        );
        let json = serde_json::to_value(&user).unwrap();
        assert_eq!(json["userName"], "alice@example.com");
        assert_eq!(json["schemas"][0], SCIM_USER_SCHEMA);
        assert_eq!(json["name"]["givenName"], "Alice");
        assert!(json["active"].as_bool().unwrap());
    }

    #[test]
    fn test_scim_user_serialises_with_all_name_fields() {
        let user = ScimUser {
            schemas: vec![SCIM_USER_SCHEMA.into()],
            id: "u-001".into(),
            user_name: "bob@example.com".into(),
            name: Some(ScimName {
                given_name: Some("Bob".into()),
                family_name: Some("Smith".into()),
            }),
            emails: vec![ScimEmail {
                value: "bob@example.com".into(),
                primary: true,
            }],
            active: false,
        };
        let json = serde_json::to_value(&user).unwrap();
        assert_eq!(json["id"], "u-001");
        assert_eq!(json["name"]["familyName"], "Smith");
        assert!(!json["active"].as_bool().unwrap());
    }

    #[test]
    fn test_scim_user_rejects_wrong_schema_type() {
        // F40: the schemas attribute is validated application-side — a User
        // body declaring the Group schema is a client error.
        let request: UserUpsertRequest = serde_json::from_value(json!({
            "schemas": [SCIM_GROUP_SCHEMA], // Wrong schema!
            "userName": "alice@example.com"
        }))
        .unwrap();
        let error = validate_user_upsert(&request).expect_err("wrong schema must be rejected");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert!(error.detail.contains(SCIM_USER_SCHEMA), "{}", error.detail);
    }

    // ── Group Serialization ─────────────────────────────────────

    #[test]
    fn test_scim_group_serialisation() {
        let group = ScimGroup {
            schemas: vec![SCIM_GROUP_SCHEMA.into()],
            id: "g-001".into(),
            display_name: "Engineering".into(),
            members: vec![
                ScimMember {
                    value: "u-001".into(),
                    display: Some("Alice".into()),
                },
                ScimMember {
                    value: "u-002".into(),
                    display: None,
                },
            ],
        };
        let json = serde_json::to_value(&group).unwrap();
        assert_eq!(json["displayName"], "Engineering");
        assert_eq!(json["members"].as_array().unwrap().len(), 2);
        assert_eq!(json["members"][0]["display"], "Alice");
        assert_eq!(json["members"][1]["display"], serde_json::Value::Null);
    }

    #[test]
    fn test_scim_group_empty_members() {
        let group = ScimGroup {
            schemas: vec![SCIM_GROUP_SCHEMA.into()],
            id: "g-003".into(),
            display_name: "EmptyGroup".into(),
            members: vec![],
        };
        let json = serde_json::to_value(&group).unwrap();
        assert!(json["members"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_scim_member_serialises_with_and_without_display() {
        let member_with = ScimMember {
            value: "u-001".into(),
            display: Some("Alice".into()),
        };
        let json = serde_json::to_value(&member_with).unwrap();
        assert_eq!(json["display"], "Alice");

        let member_without = ScimMember {
            value: "u-002".into(),
            display: None,
        };
        let json = serde_json::to_value(&member_without).unwrap();
        assert_eq!(json["display"], serde_json::Value::Null);
    }

    // ── F40: create/replace DTOs vs response DTOs ───────────────

    #[test]
    fn create_user_body_requires_no_id_and_defaults_active_true() {
        // A minimal, ordinary IdP create body: userName only. No id, no
        // active, no emails — previously this failed deserialization
        // because the shared DTO required the server-assigned id.
        let request: UserUpsertRequest =
            serde_json::from_value(json!({ "userName": "carol@example.com" })).unwrap();
        validate_user_upsert(&request).expect("minimal create body must be accepted");
        assert_eq!(request.user_name.as_deref(), Some("carol@example.com"));
        assert!(request.name.is_none());
        assert!(request.emails.is_empty());
        assert!(
            request.active,
            "active must default to true (RFC 7644 §3.1)"
        );
        assert_eq!(derive_user_email(&request), "carol@example.com");
    }

    #[test]
    fn create_user_body_accepts_optional_attributes() {
        let request: UserUpsertRequest = serde_json::from_value(json!({
            "schemas": [SCIM_USER_SCHEMA],
            "userName": "eve@example.com",
            "name": { "givenName": "Eve", "familyName": "Doe" },
            "emails": [
                { "value": "eve@example.com", "primary": true },
                { "value": "eve@personal.com", "primary": false }
            ],
            "active": false
        }))
        .unwrap();
        validate_user_upsert(&request).expect("full create body must be accepted");
        assert_eq!(request.emails.len(), 2);
        assert!(request.emails[0].primary);
        assert!(!request.emails[1].primary);
        assert!(!request.active);
        // emails[0].value wins over userName for the stored address.
        assert_eq!(derive_user_email(&request), "eve@example.com");
    }

    #[test]
    fn client_supplied_id_is_ignored_by_request_dto() {
        // RFC 7643 §7: id is read-only / server-assigned. A client that
        // (incorrectly) sends one must not break the request — and must not
        // get its own id back: the DTO simply has no id field.
        let request: UserUpsertRequest = serde_json::from_value(json!({
            "id": "attacker-chosen-id",
            "userName": "frank@example.com",
            "nickName": "Frankie"
        }))
        .unwrap();
        validate_user_upsert(&request).expect("body with id must still parse");
        assert_eq!(request.user_name.as_deref(), Some("frank@example.com"));
        // Unknown fields (nickName, meta, ...) are ignored, not rejected.
    }

    #[test]
    fn create_user_body_missing_user_name_is_rejected() {
        let request: UserUpsertRequest = serde_json::from_value(json!({
            "emails": [{ "value": "someone@example.com" }]
        }))
        .unwrap();
        let error = validate_user_upsert(&request).expect_err("userName is required");
        assert!(error.detail.contains("userName"), "{}", error.detail);
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn blank_user_name_is_rejected() {
        let request: UserUpsertRequest =
            serde_json::from_value(json!({ "userName": "   " })).unwrap();
        assert!(validate_user_upsert(&request).is_err());
    }

    #[test]
    fn group_create_body_display_name_required() {
        let missing: GroupUpsertRequest = serde_json::from_value(json!({
            "schemas": [SCIM_GROUP_SCHEMA]
        }))
        .unwrap();
        let error = validate_group_upsert(&missing).expect_err("displayName is required");
        assert!(error.detail.contains("displayName"), "{}", error.detail);

        let minimal: GroupUpsertRequest =
            serde_json::from_value(json!({ "displayName": "Engineering" })).unwrap();
        validate_group_upsert(&minimal).expect("minimal group body must be accepted");
        assert!(minimal.members.is_empty());
        assert!(minimal.schemas.is_empty());
    }

    #[test]
    fn group_create_body_parses_members_and_rejects_wrong_schema() {
        let request: GroupUpsertRequest = serde_json::from_value(json!({
            "schemas": [SCIM_GROUP_SCHEMA],
            "displayName": "Marketing",
            "members": [{ "value": "u-003", "display": "Carol" }]
        }))
        .unwrap();
        validate_group_upsert(&request).expect("valid group body must be accepted");
        assert_eq!(request.members.len(), 1);
        assert_eq!(request.members[0].value, "u-003");

        let wrong_schema: GroupUpsertRequest = serde_json::from_value(json!({
            "schemas": [SCIM_USER_SCHEMA],
            "displayName": "Oops"
        }))
        .unwrap();
        assert!(validate_group_upsert(&wrong_schema).is_err());
    }

    #[test]
    fn created_response_sets_201_and_location_header() {
        // F40: creates return 201 with Location pointing at the
        // server-generated id (RFC 7644 §3.3).
        let id = Uuid::new_v4().to_string();
        let resource = canonical_scim_user(id.clone(), "located@example.com".into(), None, true);
        let response = created_response(&user_location(&id), resource);
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some(format!("/v1/scim/Users/{id}").as_str())
        );

        let group_response = created_response(
            &group_location("g-9"),
            ScimGroup {
                schemas: vec![SCIM_GROUP_SCHEMA.into()],
                id: "g-9".into(),
                display_name: "Ops".into(),
                members: vec![],
            },
        );
        assert_eq!(group_response.status(), StatusCode::CREATED);
        assert_eq!(
            group_response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/v1/scim/Groups/g-9")
        );
    }

    #[tokio::test]
    async fn scim_error_envelope_follows_rfc_7644() {
        // F42: SCIM-formatted errors carry detail + status + the Error urn.
        let response = ScimError::bad_request("filter is invalid").into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read error body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("json error body");
        assert_eq!(
            body["schemas"][0],
            "urn:ietf:params:scim:api:messages:2.0:Error"
        );
        assert_eq!(body["detail"], json!("filter is invalid"));
        assert_eq!(body["status"], json!("400"));

        // Mapped ApiErrors keep the same envelope shape.
        let response: ScimError = ApiError::NotFound("user not found".into()).into();
        assert_eq!(response.status, StatusCode::NOT_FOUND);
        let response: ScimError = ApiError::Conflict("user already exists".into()).into();
        assert_eq!(response.status, StatusCode::CONFLICT);
    }

    // ── F41: active=false lifecycle ─────────────────────────────

    #[test]
    fn status_for_active_maps_the_scim_lifecycle() {
        // The single mapping shared by create/replace/patch — a
        // provisioned-inactive user must land deactivated, not active.
        assert_eq!(status_for_active(true), "active");
        assert_eq!(status_for_active(false), "deactivated");
    }

    #[test]
    fn create_with_active_false_maps_to_deactivated_resource() {
        let request: UserUpsertRequest = serde_json::from_value(json!({
            "userName": "suspended@example.com",
            "active": false
        }))
        .unwrap();
        validate_user_upsert(&request).expect("valid body");

        // The exact chain create_user uses: derive → status_for_active →
        // canonical response reports the stored state.
        let email = derive_user_email(&request);
        assert_eq!(status_for_active(request.active), "deactivated");
        let resource = canonical_scim_user(
            Uuid::new_v4().to_string(),
            email.clone(),
            None,
            request.active,
        );
        let body = serde_json::to_value(&resource).unwrap();
        assert_eq!(body["active"], json!(false));
        assert_eq!(body["userName"], email);
    }

    #[test]
    fn omitted_active_defaults_to_active_lifecycle() {
        let request: UserUpsertRequest =
            serde_json::from_value(json!({ "userName": "default@example.com" })).unwrap();
        assert!(request.active);
        assert_eq!(status_for_active(request.active), "active");
    }

    // ── F42: filter parsing ─────────────────────────────────────

    #[test]
    fn parse_scim_filter_accepts_eq_on_supported_attributes() {
        assert_eq!(
            parse_scim_filter("userName eq \"alice@example.com\"").unwrap(),
            ScimUserFilter::Email("alice@example.com".into())
        );
        // Attribute names and operators are case-insensitive; emails.value
        // is backed by the same stored address.
        assert_eq!(
            parse_scim_filter("emails.value eq \"bob@example.com\"").unwrap(),
            ScimUserFilter::Email("bob@example.com".into())
        );
        assert_eq!(
            parse_scim_filter("USERNAME EQ \"Mixed@Case.COM\"").unwrap(),
            ScimUserFilter::Email("mixed@case.com".into())
        );
        // Tolerant whitespace.
        assert_eq!(
            parse_scim_filter("  userName    eq   \"x@y.zz\"  ").unwrap(),
            ScimUserFilter::Email("x@y.zz".into())
        );
    }

    #[test]
    fn parse_scim_filter_decodes_escaped_literals() {
        assert_eq!(
            parse_scim_filter("userName eq \"weird\\\"name@example.com\"").unwrap(),
            ScimUserFilter::Email("weird\"name@example.com".into())
        );
        assert_eq!(
            parse_scim_filter("emails.value eq \"a\\\\b@example.com\"").unwrap(),
            ScimUserFilter::Email("a\\b@example.com".into())
        );
        assert_eq!(
            parse_scim_filter("userName eq \"sl\\/ash@example.com\"").unwrap(),
            ScimUserFilter::Email("sl/ash@example.com".into())
        );
    }

    #[test]
    fn parse_scim_filter_rejects_unsupported_input() {
        let bad = [
            // Unsupported operators.
            "userName co \"a\"",
            "userName sw \"a\"",
            "userName ne \"a\"",
            "userName pr",
            // Composition is not supported.
            "userName eq \"a\" and emails.value eq \"b\"",
            "userName eq \"a\" or emails.value eq \"b\"",
            // Malformed literals.
            "userName eq alice@example.com",
            "userName eq \"unterminated",
            "userName eq \"inner\"quote@x.com\"",
            "userName eq \"bad\\nescape\"",
            "userName eq \"dangling\\",
            "userName eq \"a\" trailing",
            // Unsupported attributes.
            "title eq \"ceo\"",
            "name.givenName eq \"Alice\"",
            // Structure / bounds.
            "",
            "   ",
            "userName",
            "userName eq",
            &format!("userName eq \"{}\"", "a".repeat(MAX_SCIM_FILTER_LEN)),
        ];
        for filter in bad {
            assert!(
                parse_scim_filter(filter).is_err(),
                "filter {filter:?} must be rejected"
            );
        }
    }

    #[test]
    fn parse_scim_filter_rejects_control_characters() {
        assert!(parse_scim_filter("userName eq \"a\nb@example.com\"").is_err());
        assert!(parse_scim_filter("userName eq \"a\tb@example.com\"").is_err());
        assert!(parse_scim_filter("userName eq \"a\0b@example.com\"").is_err());
    }

    #[test]
    fn parse_scim_filter_external_id_matches_nothing() {
        // externalId is accepted syntactically but ApexMail stores no
        // external ids, so an eq filter matches zero resources.
        assert_eq!(
            parse_scim_filter("externalId eq \"idp-123\"").unwrap(),
            ScimUserFilter::NeverMatches
        );
    }

    #[test]
    fn service_provider_config_advertises_implemented_capabilities() {
        let config = service_provider_config_document();
        assert_eq!(
            config["schemas"][0],
            "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
        );
        assert_eq!(config["patch"]["supported"], json!(true));
        assert_eq!(config["filter"]["supported"], json!(true));
        assert_eq!(config["filter"]["maxResults"], json!(MAX_SCIM_COUNT));
        assert_eq!(config["sort"]["supported"], json!(false));
        assert_eq!(config["bulk"]["supported"], json!(false));
        assert_eq!(config["etag"]["supported"], json!(false));
        assert_eq!(config["changePassword"]["supported"], json!(false));
    }

    // ── F42: User PATCH planning ────────────────────────────────

    fn patch_body(operations: serde_json::Value) -> ScimPatchRequest {
        serde_json::from_value(json!({ "Operations": operations })).expect("valid patch request")
    }

    #[test]
    fn plan_user_patch_supports_documented_ops() {
        // add onto an existing single-valued attribute replaces it
        // (RFC 7644 §3.5.2.1); op keywords are case-insensitive.
        let request: ScimPatchRequest = serde_json::from_value(json!({
            "Operations": [
                { "op": "replace", "path": "active", "value": false },
                { "op": "replace", "path": "name.givenName", "value": "Renamed" },
                { "op": "Add", "path": "userName", "value": "renamed@example.com" }
            ]
        }))
        .unwrap();
        let changes = plan_user_patch(&request).expect("valid multi-op plan");
        assert_eq!(changes.active, Some(false));
        assert_eq!(changes.name, Some(Some("Renamed".to_string())));
        assert_eq!(changes.email, Some("renamed@example.com".to_string()));
    }

    #[test]
    fn plan_user_patch_applies_path_less_object_form() {
        // Azure AD style: replace without a path, value is a partial object.
        let request = patch_body(json!([
            { "op": "replace", "value": { "active": false } }
        ]));
        let changes = plan_user_patch(&request).expect("object form must be supported");
        assert_eq!(changes.active, Some(false));

        let request = patch_body(json!([
            { "op": "Replace", "value": { "active": true, "nickName": "ignored" } }
        ]));
        let changes = plan_user_patch(&request).expect("unknown object keys are ignored");
        assert_eq!(changes.active, Some(true));

        let request = patch_body(json!([
            { "op": "replace", "value": { "name": { "givenName": "Obj" } } }
        ]));
        let changes = plan_user_patch(&request).expect("nested name object is supported");
        assert_eq!(changes.name, Some(Some("Obj".to_string())));
    }

    #[test]
    fn plan_user_patch_last_op_wins() {
        let request = patch_body(json!([
            { "op": "replace", "path": "active", "value": true },
            { "op": "replace", "path": "active", "value": false }
        ]));
        let changes = plan_user_patch(&request).unwrap();
        assert_eq!(changes.active, Some(false));
    }

    #[test]
    fn plan_user_patch_invalid_op_rejects_whole_request() {
        // F42 atomicity: one invalid operation rejects everything — because
        // planning happens before any write, nothing is applied.
        let request = patch_body(json!([
            { "op": "replace", "path": "active", "value": false },
            { "op": "explode", "path": "active" }
        ]));
        let error = plan_user_patch(&request).expect_err("invalid op must fail the request");
        assert!(error.contains("Operations[1]"), "{error}");
        assert!(error.contains("explode"), "{error}");
    }

    #[test]
    fn plan_user_patch_rejects_unsupported_paths_values_and_removes() {
        let cases: Vec<(serde_json::Value, &str)> = vec![
            (
                json!([{ "op": "replace", "path": "emails", "value": [] }]),
                "unsupported path",
            ),
            (
                json!([{ "op": "replace", "path": "name.familyName", "value": "X" }]),
                "unsupported path",
            ),
            (
                json!([{ "op": "remove", "path": "userName" }]),
                "cannot remove required attribute",
            ),
            (
                json!([{ "op": "remove", "path": "active" }]),
                "cannot remove required attribute",
            ),
            (json!([{ "op": "remove" }]), "requires a path"),
            (
                json!([{ "op": "replace", "path": "active", "value": "yes" }]),
                "boolean value",
            ),
            (
                json!([{ "op": "replace", "path": "userName", "value": 42 }]),
                "string value",
            ),
            (
                json!([{ "op": "replace", "path": "name.givenName", "value": "" }]),
                "must not be empty",
            ),
            (json!([{ "op": "replace", "value": false }]), "object value"),
        ];
        for (operations, expected_detail) in cases {
            let request = patch_body(operations);
            let error =
                plan_user_patch(&request).expect_err("case must be rejected by the planner");
            assert!(
                error.contains(expected_detail),
                "planner error {error:?} must mention {expected_detail:?}"
            );
        }
    }

    #[test]
    fn plan_user_patch_remove_clears_only_the_stored_name() {
        let request = patch_body(json!([{ "op": "remove", "path": "name.givenName" }]));
        let changes = plan_user_patch(&request).unwrap();
        assert_eq!(changes.name, Some(None));
    }

    // ── F43: pagination normalization ───────────────────────────

    fn query(start_index: i64, count: i64, cursor: Option<i64>) -> ScimListQuery {
        serde_json::from_value(json!({
            "startIndex": start_index,
            "count": count,
            "cursor": cursor,
        }))
        .unwrap()
    }

    #[test]
    fn normalize_scim_page_handles_edge_values() {
        let normal = normalize_scim_page(&query(1, 100, None));
        assert_eq!(
            normal,
            NormalizedScimPage {
                start_index: 1,
                offset: 0,
                count: 100
            }
        );

        // start < 1 normalizes to 1.
        assert_eq!(normalize_scim_page(&query(0, 10, None)).start_index, 1);
        assert_eq!(normalize_scim_page(&query(-5, 10, None)).start_index, 1);

        // i64::MIN must neither panic (overflow) nor leak through.
        let extreme = normalize_scim_page(&query(i64::MIN, i64::MIN, None));
        assert_eq!(
            extreme,
            NormalizedScimPage {
                start_index: 1,
                offset: 0,
                count: 0
            }
        );

        // Negative counts normalize to 0; oversized counts clamp to MAX.
        assert_eq!(normalize_scim_page(&query(3, -1, None)).count, 0);
        assert_eq!(normalize_scim_page(&query(3, 0, None)).count, 0);
        assert_eq!(
            normalize_scim_page(&query(3, 1_000_000, None)).count,
            MAX_SCIM_COUNT
        );

        // cursor wins over startIndex (and is normalized too).
        let cursor_page = normalize_scim_page(&query(2, 10, Some(9)));
        assert_eq!(
            cursor_page,
            NormalizedScimPage {
                start_index: 9,
                offset: 8,
                count: 10
            }
        );
        assert_eq!(
            normalize_scim_page(&query(2, 10, Some(i64::MIN))).start_index,
            1
        );

        // offset is always start_index - 1.
        let page = normalize_scim_page(&query(51, 25, None));
        assert_eq!(page.offset, 50);
    }

    #[test]
    fn list_response_metadata_reports_normalized_start_and_actual_count() {
        // Metadata must not contradict the query (F43): startIndex is the
        // normalized value and itemsPerPage is the number of resources
        // actually returned — never the raw requested count.
        let two = vec![
            canonical_scim_user("u-1".into(), "a@example.com".into(), None, true),
            canonical_scim_user("u-2".into(), "b@example.com".into(), None, false),
        ];
        let response = scim_list_response(57, 1, two);
        let body = serde_json::to_value(&response).unwrap();
        assert_eq!(body["totalResults"], 57);
        assert_eq!(body["startIndex"], 1);
        assert_eq!(body["itemsPerPage"], 2);
        assert_eq!(body["Resources"].as_array().unwrap().len(), 2);

        // count=0: no Resources, but totalResults is present.
        let empty = scim_list_response::<ScimUser>(57, 1, Vec::new());
        let body = serde_json::to_value(&empty).unwrap();
        assert_eq!(body["totalResults"], 57);
        assert_eq!(body["itemsPerPage"], 0);
        assert!(body["Resources"].as_array().unwrap().is_empty());
    }

    // ── Pagination Query ────────────────────────────────────────

    #[test]
    fn test_scim_list_query_defaults() {
        let q: ScimListQuery = serde_json::from_value(json!({})).unwrap();
        assert_eq!(q.start_index, 1);
        assert_eq!(q.count, 100);
        assert!(q.cursor.is_none());
        assert!(q.filter.is_none());
    }

    #[test]
    fn test_scim_list_query_accepts_start_index_and_count() {
        let q: ScimListQuery =
            serde_json::from_value(json!({ "startIndex": 5, "count": 25 })).unwrap();
        assert_eq!(q.start_index, 5);
        assert_eq!(q.count, 25);
    }

    #[test]
    fn test_scim_list_query_accepts_cursor() {
        let q: ScimListQuery =
            serde_json::from_value(json!({ "startIndex": 1, "count": 10, "cursor": 50 })).unwrap();
        assert_eq!(q.cursor, Some(50));
    }

    #[test]
    fn test_scim_list_query_accepts_filter() {
        // F42: `filter` used to be rejected by deny_unknown_fields.
        let q: ScimListQuery = serde_json::from_value(json!({
            "filter": "userName eq \"alice@example.com\""
        }))
        .unwrap();
        assert_eq!(
            q.filter.as_deref(),
            Some("userName eq \"alice@example.com\"")
        );
    }

    // ── Patch request DTO ───────────────────────────────────────

    #[test]
    fn test_scim_patch_request_single_add_operation() {
        let json = json!({
            "Operations": [{
                "op": "add",
                "path": "members",
                "value": [{ "value": "u-010", "display": "New Member" }]
            }]
        });
        let req: ScimPatchRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.operations.len(), 1);
        assert_eq!(req.operations[0].op, "add");
        assert_eq!(req.operations[0].path.as_deref(), Some("members"));
    }

    #[test]
    fn test_scim_patch_request_remove_operation() {
        let json = json!({
            "Operations": [{
                "op": "remove",
                "path": "members[value eq \"u-001\"]"
            }]
        });
        let req: ScimPatchRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.operations.len(), 1);
        assert_eq!(req.operations[0].op, "remove");
        assert!(req.operations[0].value.is_none());
    }

    #[test]
    fn test_scim_patch_request_rejects_unknown_fields() {
        let json = json!({
            "Operations": [{
                "op": "add",
                "unknownField": "should-fail"
            }]
        });
        let result: Result<ScimPatchRequest, _> = serde_json::from_value(json);
        assert!(result.is_err(), "Should reject unknown patch op fields");
    }

    #[test]
    fn test_scim_patch_request_rejects_unknown_request_fields() {
        let json = json!({
            "Operations": [{ "op": "add", "path": "members" }],
            "extra": true
        });
        let result: Result<ScimPatchRequest, _> = serde_json::from_value(json);
        assert!(result.is_err(), "Should reject unknown request fields");
    }

    // ── Name/Email Validation ───────────────────────────────────

    #[test]
    fn test_scim_name_both_fields_optional() {
        let name: ScimName = serde_json::from_value(json!({})).unwrap();
        assert!(name.given_name.is_none());
        assert!(name.family_name.is_none());
    }

    #[test]
    fn test_scim_name_accepts_given_name_only() {
        let name: ScimName = serde_json::from_value(json!({ "givenName": "Alice" })).unwrap();
        assert_eq!(name.given_name.as_deref(), Some("Alice"));
        assert!(name.family_name.is_none());
    }

    #[test]
    fn test_scim_email_requires_value() {
        let email: ScimEmail =
            serde_json::from_value(json!({ "value": "a@b.com", "primary": false })).unwrap();
        assert_eq!(email.value, "a@b.com");
        assert!(!email.primary);
    }

    #[test]
    fn test_scim_email_defaults_primary_false_if_missing() {
        let email: ScimEmail = serde_json::from_value(json!({ "value": "a@b.com" })).unwrap();
        assert_eq!(email.value, "a@b.com");
        assert!(!email.primary);
    }

    #[test]
    fn plausible_email_gate_rejects_blank_and_malformed() {
        assert!(is_plausible_email("user@example.com"));
        for bad in [
            "",
            "   ",
            "noat",
            "@example.com",
            "user@",
            "user@nodot",
            "a b@example.com",
        ] {
            assert!(!is_plausible_email(bad), "{bad:?} must be rejected");
        }
    }

    // ── Constants ───────────────────────────────────────────────

    #[test]
    fn test_scim_schemas_are_well_known_urns() {
        assert_eq!(
            SCIM_USER_SCHEMA,
            "urn:ietf:params:scim:schemas:core:2.0:User"
        );
        assert_eq!(
            SCIM_GROUP_SCHEMA,
            "urn:ietf:params:scim:schemas:core:2.0:Group"
        );
        assert_eq!(
            SCIM_LIST_SCHEMA,
            "urn:ietf:params:scim:api:messages:2.0:ListResponse"
        );
        assert_eq!(
            SCIM_ERROR_SCHEMA,
            "urn:ietf:params:scim:api:messages:2.0:Error"
        );
    }

    #[test]
    fn test_scim_max_count_is_reasonable() {
        assert_eq!(MAX_SCIM_COUNT, 200);
    }

    #[test]
    fn test_scim_disabled_hash_is_not_valid_argon2() {
        assert_eq!(SCIM_DISABLED_HASH, "!scim:disabled");
        assert!(!SCIM_DISABLED_HASH.starts_with('$'));
    }

    #[test]
    fn test_scim_unique_violation_code() {
        let pg_unique_code = "23505";
        assert_eq!(pg_unique_code.len(), 5);
        assert!(pg_unique_code.chars().all(|c| c.is_ascii_digit()));
    }

    // ── Patch member-removal path parsing (P3) ──────────────────

    #[test]
    fn member_removal_path_parses_plain_uuids() {
        assert_eq!(
            parse_member_removal_path("members[value eq \"u-001\"]"),
            Some("u-001")
        );
    }

    #[test]
    fn member_removal_path_rejects_quoting_garbage_instead_of_mangling() {
        assert_eq!(
            parse_member_removal_path("members[value eq \"a\"]\"]"),
            None
        );
        assert_eq!(parse_member_removal_path("members[value eq \"]\"]"), None);
        assert_eq!(parse_member_removal_path("displayName"), None);
        assert_eq!(
            parse_member_removal_path("members[value eq \"u-001\""),
            None
        );
    }

    // ── Cross-tenant member injection (audit C) + lifecycle/patch DB tests ──

    async fn insert_test_tenant(pool: &sqlx::PgPool, tenant_id: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status)
             VALUES ($1, $2, $3, 'free', 'active')",
        )
        .bind(tenant_id)
        .bind(format!("SCIM test tenant {tenant_id}"))
        .bind(format!("scim-{tenant_id}"))
        .execute(pool)
        .await
        .expect("failed to insert test tenant");
    }

    #[tokio::test]
    async fn scim_group_creation_rejects_foreign_tenant_members_and_writes_no_rows() {
        let Some(pool) = crate::test_db::optional_pg_pool(
            "scim_group_creation_rejects_foreign_tenant_members_and_writes_no_rows",
        )
        .await
        else {
            return;
        };

        // Malformed member ids are rejected with a 400 before any DB access
        // (schema-independent assertion).
        let parse_error = validate_members_in_tenant(&pool, "ten_any", &["not-a-uuid".into()])
            .await
            .expect_err("garbage member ids must be rejected");
        match parse_error {
            ApiError::BadRequest(message) => {
                assert!(
                    message.contains("invalid member id"),
                    "unexpected: {message}"
                );
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }

        // The shared `<db>_api` database now carries the canonical production
        // chain (users.id UUID — matching this route's `Uuid::parse_str`
        // convention), so the tenant-scoping DB assertions always run.

        // tenants.id is VARCHAR(26) — keep the generated IDs within bounds.
        let tenant_a = format!("ten_scm_{}", &Uuid::new_v4().simple().to_string()[..18]);
        let tenant_b = format!("ten_scn_{}", &Uuid::new_v4().simple().to_string()[..18]);
        for tenant_id in [&tenant_a, &tenant_b] {
            insert_test_tenant(&pool, tenant_id).await;
        }

        // A user that belongs ONLY to tenant B.
        let foreign_user_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status)
             VALUES ($1, $2, $3, NULL, '!disabled', 'member', 'active')",
        )
        .bind(foreign_user_id)
        .bind(&tenant_b)
        .bind(format!("victim-{foreign_user_id}@foreign.example"))
        .execute(&pool)
        .await
        .expect("failed to insert foreign user");

        // Tenant A's admin tries to enrol tenant B's user. (All ids here are
        // well-formed UUIDs: the handler's syntax gate rejects garbage ids
        // with its own message before any tenant scoping, which is the
        // assertion proven above.)
        let error = validate_members_in_tenant(&pool, &tenant_a, &[foreign_user_id.to_string()])
            .await
            .expect_err("foreign-tenant member must be rejected");

        match error {
            ApiError::BadRequest(message) => {
                assert!(
                    message.contains("do not exist in this tenant"),
                    "unexpected rejection message: {message}"
                );
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }

        // No group row may be written for the failed creation (the handler
        // validates members BEFORE inserting the group).
        let groups: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM scim_groups WHERE tenant_id = $1")
                .bind(&tenant_a)
                .fetch_one(&pool)
                .await
                .expect("failed to count groups");
        assert_eq!(groups.0, 0, "no group row may exist for a rejected create");

        // A same-tenant member validates cleanly.
        let own_user_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status)
             VALUES ($1, $2, $3, NULL, '!disabled', 'member', 'active')",
        )
        .bind(own_user_id)
        .bind(&tenant_a)
        .bind(format!("member-{own_user_id}@own.example"))
        .execute(&pool)
        .await
        .expect("failed to insert own-tenant user");

        let validated = validate_members_in_tenant(&pool, &tenant_a, &[own_user_id.to_string()])
            .await
            .expect("same-tenant member must validate");
        assert_eq!(validated, vec![own_user_id]);

        // Cleanup
        for tenant_id in [&tenant_a, &tenant_b] {
            let _ = sqlx::query("DELETE FROM users WHERE tenant_id = $1")
                .bind(tenant_id)
                .execute(&pool)
                .await;
            let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
                .bind(tenant_id)
                .execute(&pool)
                .await;
        }
    }

    /// Create a throwaway database carrying the REAL production schema:
    /// the full canonical migration chain applied through the production
    /// migrator (`migrator::test_support::fresh_canonical_db` — audit F01),
    /// i.e. the exact users.id UUID / tenant_id VARCHAR(26) shape the SCIM
    /// `$1::uuid` casts and status writes target, plus every constraint a
    /// deploy installs. Returns the pool plus what `drop_test_database`
    /// needs for cleanup. Soft-skips when `TEST_DATABASE_URL` is unset; a
    /// CONFIGURED provisioning failure panics (the F01 Result contract —
    /// adapted mechanically when `fresh_canonical_db` gained its error
    /// type).
    async fn prod_lineage_pool(test_name: &str) -> Option<(sqlx::PgPool, String, String)> {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| {
                eprintln!("skipping {test_name}: set TEST_DATABASE_URL to run it");
                None
            })?;
        let (server_part, _) = database_url.rsplit_once('/')?;

        let db_name = format!(
            "apexmail_scim_canon_{}",
            &Uuid::new_v4().simple().to_string()[..12]
        );
        let pool = migrator::test_support::fresh_canonical_db(&database_url, &db_name)
            .await
            .unwrap_or_else(|error| panic!("{}", error.panic_message()))?;
        Some((pool, db_name, server_part.to_string()))
    }

    async fn drop_test_database(server_part: &str, db_name: &str) {
        let Ok(admin) = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&format!("{server_part}/postgres"))
            .await
        else {
            return;
        };
        // The name is test-generated (UUID-derived); no identifier escaping
        // is needed.
        let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {db_name}"))
            .execute(&admin)
            .await;
        let _ = admin.close().await;
    }

    /// F41: `insert_scim_user` persists the requested lifecycle —
    /// `active=false` lands as `deactivated`, and duplicate emails surface
    /// as a Conflict, not a raw database error.
    #[tokio::test]
    async fn scim_user_creation_persists_requested_lifecycle() {
        let Some((pool, db_name, server_part)) =
            prod_lineage_pool("scim_user_creation_persists_requested_lifecycle").await
        else {
            return;
        };

        let tenant_id = format!("ten_scl_{}", &Uuid::new_v4().simple().to_string()[..18]);
        insert_test_tenant(&pool, &tenant_id).await;

        let inactive_id = Uuid::new_v4();
        insert_scim_user(
            &pool,
            &tenant_id,
            inactive_id,
            &format!("sleepy-{inactive_id}@lifecycle.example"),
            None,
            false,
        )
        .await
        .expect("inactive provision must succeed");
        let status: (String,) =
            sqlx::query_as("SELECT status FROM users WHERE id = $1 AND tenant_id = $2")
                .bind(inactive_id)
                .bind(&tenant_id)
                .fetch_one(&pool)
                .await
                .expect("inactive user row");
        assert_eq!(status.0, "deactivated", "active=false must be persisted");

        let active_id = Uuid::new_v4();
        insert_scim_user(
            &pool,
            &tenant_id,
            active_id,
            &format!("awake-{active_id}@lifecycle.example"),
            Some("Awake"),
            true,
        )
        .await
        .expect("active provision must succeed");
        let (status, name): (String, Option<String>) =
            sqlx::query_as("SELECT status, name FROM users WHERE id = $1 AND tenant_id = $2")
                .bind(active_id)
                .bind(&tenant_id)
                .fetch_one(&pool)
                .await
                .expect("active user row");
        assert_eq!(status, "active");
        assert_eq!(name.as_deref(), Some("Awake"));

        // Duplicate email → Conflict.
        let duplicate = insert_scim_user(
            &pool,
            &tenant_id,
            Uuid::new_v4(),
            &format!("awake-{active_id}@lifecycle.example"),
            None,
            true,
        )
        .await
        .expect_err("duplicate email must be rejected");
        assert!(matches!(duplicate, ApiError::Conflict(_)), "{duplicate:?}");

        let _ = pool.close().await;
        drop_test_database(&server_part, &db_name).await;
    }

    /// F42: a multi-operation PATCH is one atomic UPDATE; an invalid
    /// operation rejects the whole request before any write.
    #[tokio::test]
    async fn scim_user_patch_is_atomic_and_invalid_ops_write_nothing() {
        let Some((pool, db_name, server_part)) =
            prod_lineage_pool("scim_user_patch_is_atomic_and_invalid_ops_write_nothing").await
        else {
            return;
        };

        let tenant_id = format!("ten_scp_{}", &Uuid::new_v4().simple().to_string()[..18]);
        insert_test_tenant(&pool, &tenant_id).await;

        let user_id = Uuid::new_v4();
        let email = format!("patched-{user_id}@lifecycle.example");
        insert_scim_user(&pool, &tenant_id, user_id, &email, Some("Original"), true)
            .await
            .expect("seed user");

        // Valid multi-op plan: rename + deactivate in ONE statement.
        let valid_request: ScimPatchRequest = serde_json::from_value(json!({
            "Operations": [
                { "op": "replace", "path": "name.givenName", "value": "Renamed" },
                { "op": "replace", "path": "active", "value": false }
            ]
        }))
        .unwrap();
        let changes = plan_user_patch(&valid_request).expect("valid plan");
        let UserPatchChanges {
            email: _,
            name,
            active,
        } = changes;
        let rows = apply_user_patch(
            &pool,
            &tenant_id,
            &user_id.to_string(),
            &email,
            name.flatten().as_deref(),
            active.unwrap_or(true),
        )
        .await
        .expect("apply patch");
        assert_eq!(rows, 1, "the single UPDATE must touch the user");

        let (status, name): (String, Option<String>) =
            sqlx::query_as("SELECT status, name FROM users WHERE id = $1 AND tenant_id = $2")
                .bind(user_id)
                .bind(&tenant_id)
                .fetch_one(&pool)
                .await
                .expect("patched user row");
        assert_eq!(status, "deactivated");
        assert_eq!(name.as_deref(), Some("Renamed"));

        // Invalid plan → rejected before any write → row unchanged.
        let invalid_request: ScimPatchRequest = serde_json::from_value(json!({
            "Operations": [
                { "op": "replace", "path": "active", "value": true },
                { "op": "explode", "path": "active" }
            ]
        }))
        .unwrap();
        let error = plan_user_patch(&invalid_request).expect_err("invalid op must fail");
        assert!(error.contains("Operations[1]"), "{error}");

        let (status, name): (String, Option<String>) =
            sqlx::query_as("SELECT status, name FROM users WHERE id = $1 AND tenant_id = $2")
                .bind(user_id)
                .bind(&tenant_id)
                .fetch_one(&pool)
                .await
                .expect("user row after rejected patch");
        assert_eq!(status, "deactivated", "rejected patch must not reactivate");
        assert_eq!(
            name.as_deref(),
            Some("Renamed"),
            "rejected patch must not rename"
        );

        let _ = pool.close().await;
        drop_test_database(&server_part, &db_name).await;
    }
}
