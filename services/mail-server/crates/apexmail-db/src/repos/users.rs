//! Users repository.
//!
//! # Projection split (audit F12)
//!
//! Only [`UsersRepo::find_by_email_for_login`] selects `password_hash`
//! (returning the full [`crate::types::User`], whose hash is additionally
//! `#[serde(skip_serializing)]`). Every other read — create, find_by_id,
//! update, and both listings — returns the credential-free
//! [`crate::types::UserPublic`]: the SELECT never fetches the hash, so no
//! listing path can leak credential material through serialization, debug
//! output, or a future field addition.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::{User, UserPublic};

/// The column list for the credential-free projection (shared by every
/// non-login query so the shapes can never drift apart).
const PUBLIC_COLUMNS: &str = "id, tenant_id, email, name, role, status, created_at, updated_at";

/// The full column list — login fetch only.
const FULL_COLUMNS: &str =
    "id, tenant_id, email, name, password_hash, role, status, created_at, updated_at";

/// Repository for user operations.
pub struct UsersRepo;

impl UsersRepo {
    /// Create a new user. Returns the credential-free projection.
    pub async fn create(
        pool: &PgPool,
        tenant_id: &str,
        email: &str,
        name: Option<&str>,
        password_hash: &str,
        role: &str,
    ) -> Result<UserPublic, sqlx::Error> {
        sqlx::query_as::<_, UserPublic>(
            "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, 'active', NOW(), NOW()) \
             RETURNING id, tenant_id, email, name, role, status, created_at, updated_at"
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(email)
        .bind(name)
        .bind(password_hash)
        .bind(role)
        .fetch_one(pool)
        .await
    }

    /// Find a user by ID (credential-free projection).
    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<UserPublic>, sqlx::Error> {
        sqlx::query_as::<_, UserPublic>(&format!(
            "SELECT {PUBLIC_COLUMNS} FROM users WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// Find a user by email FOR LOGIN: the only fetch that returns the
    /// password hash (audit F12). The returned [`User`] never serializes the
    /// hash; callers must not persist or log it.
    pub async fn find_by_email_for_login(
        pool: &PgPool,
        email: &str,
    ) -> Result<Option<User>, sqlx::Error> {
        sqlx::query_as::<_, User>(&format!(
            "SELECT {FULL_COLUMNS} FROM users WHERE email = $1"
        ))
        .bind(email)
        .fetch_optional(pool)
        .await
    }

    /// Update user profile (credential-free projection).
    pub async fn update(
        pool: &PgPool,
        id: Uuid,
        name: Option<&str>,
        role: &str,
        status: &str,
    ) -> Result<Option<UserPublic>, sqlx::Error> {
        sqlx::query_as::<_, UserPublic>(&format!(
            "UPDATE users SET name = $1, role = $2, status = $3, updated_at = NOW() \
             WHERE id = $4 RETURNING {PUBLIC_COLUMNS}"
        ))
        .bind(name)
        .bind(role)
        .bind(status)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// List users in a tenant with pagination (credential-free projection).
    /// #220:Added limit/offset parameters to prevent unbounded queries
    pub async fn list_by_tenant(
        pool: &PgPool,
        tenant_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<UserPublic>, sqlx::Error> {
        // Clamp to prevent abuse
        let limit = limit.clamp(1, 1000);
        let offset = offset.max(0);
        sqlx::query_as::<_, UserPublic>(&format!(
            "SELECT {PUBLIC_COLUMNS} \
             FROM users WHERE tenant_id = $1 ORDER BY created_at ASC LIMIT $2 OFFSET $3"
        ))
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List users in a tenant using keyset (cursor-based) pagination.
    /// Uses `(created_at, id)` tuple comparison. Users uses ASC ordering,
    /// so cursors select rows AFTER the cursor position.
    /// Credential-free projection (audit F12).
    pub async fn list_keyset(
        pool: &PgPool,
        tenant_id: &str,
        limit: i64,
        cursor_created_at: Option<DateTime<Utc>>,
        cursor_id: Option<Uuid>,
    ) -> Result<Vec<UserPublic>, sqlx::Error> {
        let limit = limit.clamp(1, 200);
        let fetch_limit = limit + 1;
        match (cursor_created_at, cursor_id) {
            (Some(created_at), Some(id)) => {
                sqlx::query_as::<_, UserPublic>(&format!(
                    "SELECT {PUBLIC_COLUMNS} \
                     FROM users WHERE tenant_id = $1 AND (created_at, id) > ($2, $3) \
                     ORDER BY created_at ASC, id ASC LIMIT $4",
                ))
                .bind(tenant_id)
                .bind(created_at)
                .bind(id)
                .bind(fetch_limit)
                .fetch_all(pool)
                .await
            }
            _ => {
                // First page — no cursor
                sqlx::query_as::<_, UserPublic>(&format!(
                    "SELECT {PUBLIC_COLUMNS} \
                     FROM users WHERE tenant_id = $1 \
                     ORDER BY created_at ASC, id ASC LIMIT $2",
                ))
                .bind(tenant_id)
                .bind(fetch_limit)
                .fetch_all(pool)
                .await
            }
        }
    }
}

// The column-list constants keep the projections documented in one place;
// they are asserted against by the tests below.

#[cfg(test)]
mod tests {
    use crate::types::{User, UserPublic};
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_user_mock() {
        let u = User {
            id: Uuid::new_v4(),
            tenant_id: crate::types::short_id('t'),
            email: "admin@example.com".into(),
            name: Some("Admin".into()),
            password_hash: "$argon2id$v=19$...".into(),
            role: "admin".into(),
            status: "active".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(u.role, "admin");
        assert!(u.name.is_some());
    }

    #[test]
    fn test_user_without_name() {
        let u = User {
            id: Uuid::new_v4(),
            tenant_id: crate::types::short_id('t'),
            email: "bot@example.com".into(),
            name: None,
            password_hash: "hash".into(),
            role: "service".into(),
            status: "active".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(u.name.is_none());
    }

    #[test]
    fn test_users_repo_is_stateless() {
        let _repo = super::UsersRepo;
    }

    // ── Audit F12: projection split ────────────────────────────────

    /// `UserPublic` must carry NO password-hash field: its serialized form
    /// must never contain credential material, even as a skipped key.
    #[test]
    fn user_public_projection_never_serializes_a_hash() {
        let public = UserPublic {
            id: Uuid::new_v4(),
            tenant_id: crate::types::short_id('t'),
            email: "owner@example.com".into(),
            name: Some("Owner".into()),
            role: "owner".into(),
            status: "active".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&public).unwrap();
        assert!(
            !json.contains("password_hash") && !json.contains("argon"),
            "UserPublic JSON must be credential-free: {json}"
        );
        assert!(json.contains("owner@example.com"));
    }

    /// The full `User` (login fetch) keeps the hash OUT of its serialized
    /// form (defense in depth on top of the projection split).
    #[test]
    fn user_login_type_skips_the_hash_on_serialization() {
        let user = User {
            id: Uuid::new_v4(),
            tenant_id: crate::types::short_id('t'),
            email: "login@example.com".into(),
            name: None,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$TOPSECRET".into(),
            role: "owner".into(),
            status: "active".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&user).unwrap();
        assert!(
            !json.contains("TOPSECRET") && !json.contains("password_hash"),
            "hash must not serialize: {json}"
        );
        // Deserialization back still works (skip applies to serialization
        // only when the field has a default… serde's skip_serializing keeps
        // the field required on deserialize, so this must round-trip).
        let parsed: User = serde_json::from_value(serde_json::json!({
            "id": user.id,
            "tenant_id": user.tenant_id,
            "email": user.email,
            "name": null,
            "password_hash": "reloaded",
            "role": "owner",
            "status": "active",
            "created_at": user.created_at,
            "updated_at": user.updated_at,
        }))
        .expect("full shape deserializes with the hash supplied");
        assert_eq!(parsed.password_hash, "reloaded");
    }

    /// `User → UserPublic` conversion drops the hash field entirely.
    #[test]
    fn from_user_drops_the_hash() {
        let user = User {
            id: Uuid::new_v4(),
            tenant_id: crate::types::short_id('t'),
            email: "convert@example.com".into(),
            name: None,
            password_hash: "secret-hash".into(),
            role: "member".into(),
            status: "active".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let public: UserPublic = user.into();
        assert_eq!(public.email, "convert@example.com");
        let json = serde_json::to_string(&public).unwrap();
        assert!(!json.contains("secret-hash"));
    }

    /// The column lists encode the contract: the FULL list (login fetch)
    /// selects password_hash exactly once; the PUBLIC list never does.
    #[test]
    fn column_lists_match_the_projection_contract() {
        assert_eq!(
            super::FULL_COLUMNS.matches("password_hash").count(),
            1,
            "login projection selects the hash"
        );
        assert!(
            !super::PUBLIC_COLUMNS.contains("password_hash"),
            "public projection must not select the hash"
        );
    }
}
