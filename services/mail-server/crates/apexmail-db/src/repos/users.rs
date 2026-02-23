//! Users repository.

use sqlx::PgPool;
use uuid::Uuid;

use crate::types::User;

/// Repository for user operations.
pub struct UsersRepo;

impl UsersRepo {
    /// Create a new user.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        email: &str,
        name: Option<&str>,
        password_hash: &str,
        role: &str,
    ) -> Result<User, sqlx::Error> {
        sqlx::query_as::<_, User>(
            "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, 'active', NOW(), NOW()) \
             RETURNING *"
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

    /// Find a user by ID.
    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<User>, sqlx::Error> {
        sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// Find a user by email (for login).
    pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Option<User>, sqlx::Error> {
        sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE email = $1"
        )
        .bind(email)
        .fetch_optional(pool)
        .await
    }

    /// Update user profile.
    pub async fn update(
        pool: &PgPool,
        id: Uuid,
        name: Option<&str>,
        role: &str,
        status: &str,
    ) -> Result<Option<User>, sqlx::Error> {
        sqlx::query_as::<_, User>(
            "UPDATE users SET name = $1, role = $2, status = $3, updated_at = NOW() \
             WHERE id = $4 RETURNING *"
        )
        .bind(name)
        .bind(role)
        .bind(status)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// List all users in a tenant.
    pub async fn list_by_tenant(pool: &PgPool, tenant_id: Uuid) -> Result<Vec<User>, sqlx::Error> {
        sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE tenant_id = $1 ORDER BY created_at ASC"
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use crate::types::User;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_user_mock() {
        let u = User {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
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
            tenant_id: Uuid::new_v4(),
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
}
