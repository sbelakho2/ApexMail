//! F63 canonical persistence tests for the isolation component's remaining
//! relations: iso_access_attempts (migration 195) and iso_encryption_policies
//! (migration 196). These exercise the REAL services against the canonical
//! migration chain — create, read, update and restart (a fresh service
//! instance over the same database) — not migration-content substring
//! assertions.
//!
//! Gated on `TEST_DATABASE_URL` (workspace convention); each test provisions
//! its own canonical database via the production migrator's template clone.

use isolation::config::{IsolationLevel, SecurityConfig};
use isolation::data_isolation::DataIsolationService;
use isolation::encryption::EncryptionService;
use isolation::types::{EncryptionPolicy, IsolationContext};
use sqlx::PgPool;
use zeroize::Zeroizing;

async fn canonical_pool(db_suffix: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool("isolation_f63", db_suffix).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

async fn seed_org_and_workspace(
    pool: &PgPool,
    org_id: &str,
    workspace_id: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO iso_organizations (id, name, slug, billing_email, owner_id) \
         VALUES ($1, $1, $1, 'billing@example.com', 'owner-1')",
    )
    .bind(org_id)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO iso_workspaces (id, organization_id, name, slug, quota, usage, settings) \
         VALUES ($1, $2, $1, $1, '{}', '{}', '{}')",
    )
    .bind(workspace_id)
    .bind(org_id)
    .execute(pool)
    .await?;
    Ok(())
}

fn context_for(org: &str, workspace: &str) -> IsolationContext {
    IsolationContext {
        organization_id: org.to_string(),
        workspace_id: workspace.to_string(),
        user_id: "user-1".to_string(),
        isolation_level: IsolationLevel::Shared,
        schema_name: None,
        permissions: vec![],
    }
}

fn security_config() -> SecurityConfig {
    SecurityConfig {
        encryption_key: Zeroizing::new("test-master-key-change-in-prod!!".to_string()),
        data_key_rotation_days: 90,
        audit_retention_days: 365,
        session_timeout_minutes: 30,
    }
}

/// Create → read → restart → reread for iso_access_attempts: a denied access
/// decision must persist, survive a service restart, and stay scoped to its
/// organization.
#[tokio::test]
async fn access_attempts_persist_across_restart_and_stay_org_scoped() {
    let Some(pool) = canonical_pool("attempts").await else {
        return;
    };
    seed_org_and_workspace(&pool, "org-a", "ws-a")
        .await
        .expect("seed org/ws");
    seed_org_and_workspace(&pool, "org-b", "ws-b")
        .await
        .expect("seed org/ws");

    // A deny policy for the emails resource so a denied decision is audited.
    sqlx::query(
        "INSERT INTO iso_access_policies (id, name, resource, conditions, actions, effect) \
         VALUES ('pol-1', 'deny emails', 'emails', '[]', '[\"read\"]', 'deny')",
    )
    .execute(&pool)
    .await
    .expect("seed policy");

    let mut service = DataIsolationService::new(pool.clone());
    service
        .initialize()
        .await
        .expect("initialize requires the canonical schema (F63 readiness)");

    // The denied decision is audited through the component's persistence
    // entry point (check_resource_access only audits denials it computes;
    // the audit writer itself is the contract under test).
    service
        .audit_access_attempt(
            &context_for("org-a", "ws-a"),
            "ws-a",
            "emails",
            "read",
            false,
        )
        .await;
    // A second decision for another organization.
    service
        .audit_access_attempt(
            &context_for("org-b", "ws-b"),
            "ws-b",
            "emails",
            "read",
            true,
        )
        .await;

    let (count_a,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM iso_access_attempts WHERE organization_id = 'org-a'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        count_a, 1,
        "the denied decision must be audited exactly once"
    );

    // The audit row carries the decision contract the finding requires.
    let (allowed_flag, resource, action, actor): (bool, String, String, String) = sqlx::query_as(
        "SELECT allowed, resource, action, actor_id FROM iso_access_attempts \
         WHERE organization_id = 'org-a'",
    )
    .fetch_one(&pool)
    .await
    .expect("audit row exists");
    assert!(!allowed_flag);
    assert_eq!(resource, "emails");
    assert_eq!(action, "read");
    assert_eq!(actor, "user-1");

    // Restart: a fresh service over the same database still initializes
    // (readiness) and the audit row is still there.
    let mut restarted = DataIsolationService::new(pool.clone());
    restarted
        .initialize()
        .await
        .expect("restart initialize must succeed against the persisted schema");
    let still_there: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM iso_access_attempts WHERE organization_id = 'org-a'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(still_there, 1);

    // Another organization's decisions never leak into org-a's reads.
    let only_a: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM iso_access_attempts WHERE organization_id = 'org-a'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(only_a, 1, "org-b decisions must not be visible as org-a");

    pool.close().await;
}

/// iso_encryption_policies: create → restart → the policy reloads from the
/// canonical relation and resolves by resource; disabling it removes it from
/// the active set.
#[tokio::test]
async fn encryption_policies_persist_and_reload_across_restart() {
    let Some(pool) = canonical_pool("encpolicies").await else {
        return;
    };
    seed_org_and_workspace(&pool, "org-e", "ws-e")
        .await
        .expect("seed org/ws");

    let service = EncryptionService::new(pool.clone(), security_config());
    service
        .initialize()
        .await
        .expect("initialize requires the canonical schema (F63 readiness)");

    let policy = EncryptionPolicy {
        id: uuid::Uuid::new_v4().to_string(),
        name: "contacts PII".into(),
        resource: "contacts".into(),
        fields: vec!["email".into(), "phone".into()],
        algorithm: "aes-256-gcm".into(),
        key_rotation_days: 90,
        enabled: true,
    };
    service
        .create_policy(policy.clone())
        .await
        .expect("create_policy persists to iso_encryption_policies");

    // One policy per resource (the canonical ownership identity).
    let dup = service
        .create_policy(EncryptionPolicy {
            id: uuid::Uuid::new_v4().to_string(),
            name: "duplicate".into(),
            resource: "contacts".into(),
            fields: vec![],
            algorithm: "aes-256-gcm".into(),
            key_rotation_days: 30,
            enabled: true,
        })
        .await;
    assert!(dup.is_err(), "resource identity is UNIQUE");

    // Restart: a fresh service reloads the policy from the database.
    let restarted = EncryptionService::new(pool.clone(), security_config());
    restarted
        .initialize()
        .await
        .expect("restart initialize must reload persisted policies");
    let encrypted_value = restarted
        .encrypt_object("org-e", "contacts", &serde_json::json!({"email": "a@b.c"}))
        .await
        .expect("reloaded policy drives field encryption");
    assert!(
        encrypted_value
            .get("email")
            .and_then(|v| v.as_object())
            .is_some_and(|o| o.contains_key("ciphertext")),
        "the reloaded policy must encrypt the configured field"
    );

    // Disabling the policy removes it from the active set (load_policies
    // filters enabled = true) — the durable row survives.
    sqlx::query("UPDATE iso_encryption_policies SET enabled = false WHERE resource = 'contacts'")
        .execute(&pool)
        .await
        .unwrap();
    let after_disable = EncryptionService::new(pool.clone(), security_config());
    after_disable.initialize().await.unwrap();
    let passthrough = after_disable
        .encrypt_object("org-e", "contacts", &serde_json::json!({"email": "a@b.c"}))
        .await
        .expect("no active policy → passthrough");
    assert_eq!(
        passthrough.get("email").and_then(|v| v.as_str()),
        Some("a@b.c")
    );

    pool.close().await;
}

/// Retention: cleanup_access_attempts deletes only rows older than the
/// retention window.
#[tokio::test]
async fn access_attempt_retention_cleanup_removes_only_old_rows() {
    let Some(pool) = canonical_pool("attempts_retention").await else {
        return;
    };
    seed_org_and_workspace(&pool, "org-r", "ws-r")
        .await
        .expect("seed org/ws");

    sqlx::query(
        "INSERT INTO iso_access_attempts \
         (id, organization_id, workspace_id, actor_id, target_workspace_id, resource, action, allowed, context, created_at) \
         VALUES ('old-1', 'org-r', 'ws-r', 'u', 'ws-r', 'emails', 'read', false, '{}', NOW() - INTERVAL '400 days'), \
                ('new-1', 'org-r', 'ws-r', 'u', 'ws-r', 'emails', 'read', false, '{}', NOW())",
    )
    .execute(&pool)
    .await
    .unwrap();

    let service = DataIsolationService::new(pool.clone());
    let deleted = service
        .cleanup_access_attempts(365)
        .await
        .expect("retention cleanup");
    assert_eq!(deleted, 1, "only the 400-day-old row is purged");

    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM iso_access_attempts")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 1);

    pool.close().await;
}
