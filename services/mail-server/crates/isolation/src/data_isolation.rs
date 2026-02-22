//! Data isolation: connection scoping, RLS, access policies, migration.

use regex::Regex;
use sqlx::PgPool;
use std::sync::LazyLock;
use tracing::{info, warn};

use crate::config::IsolationLevel;
use crate::types::*;

// ── Dangerous Query Patterns ───────────────────────────────

static DANGEROUS_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)information_schema",
        r"(?i)pg_catalog",
        r"(?i)SET\s+search_path",
        r"(?i)SET\s+role",
        r"(?i)SET\s+session",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

// ── Data Isolation Service ─────────────────────────────────

pub struct DataIsolationService {
    db: PgPool,
    policies: Vec<DataAccessPolicy>,
}

impl DataIsolationService {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            policies: Vec::new(),
        }
    }

    /// Load access policies from DB on startup.
    pub async fn initialize(&mut self) -> anyhow::Result<()> {
        self.policies = self.load_policies().await?;
        info!(count = self.policies.len(), "Data access policies loaded");
        Ok(())
    }

    /// Validate a SQL query for safety in a tenant-isolated context.
    pub fn validate_query_access(&self, query: &str, ctx: &IsolationContext) -> bool {
        // Block dangerous patterns
        for pattern in DANGEROUS_PATTERNS.iter() {
            if pattern.is_match(query) {
                warn!(
                    user_id = ctx.user_id,
                    workspace_id = ctx.workspace_id,
                    "Blocked dangerous query pattern"
                );
                return false;
            }
        }

        // For SELECT queries on tenanted tables, ensure workspace filter present
        let upper = query.to_uppercase();
        if upper.starts_with("SELECT") {
            let tenanted_tables = ["emails", "contacts", "templates", "campaigns", "webhooks"];
            for table in tenanted_tables {
                if upper.contains(&table.to_uppercase())
                    && !upper.contains("WORKSPACE_ID")
                    && !upper.contains("ORGANIZATION_ID")
                {
                    warn!(
                        table = table,
                        "SELECT on tenanted table without workspace filter"
                    );
                    return false;
                }
            }
        }

        true
    }

    /// Check if a user has access to a specific resource.
    pub async fn check_resource_access(
        &self,
        ctx: &IsolationContext,
        resource: &str,
        resource_id: &str,
        action: &str,
    ) -> anyhow::Result<bool> {
        // Verify workspace ownership
        let owns = self.verify_resource_ownership(ctx, resource, resource_id).await?;
        if !owns {
            self.audit_access_attempt(ctx, &ctx.workspace_id, resource, action, false)
                .await;
            return Ok(false);
        }

        // Evaluate policies
        let allowed = self.evaluate_policies(ctx, resource, action);

        if !allowed {
            self.audit_access_attempt(ctx, &ctx.workspace_id, resource, action, false)
                .await;
        }

        Ok(allowed)
    }

    /// Set up Row-Level Security on the given table.
    pub async fn setup_rls(
        &self,
        table_name: &str,
        schema_name: &str,
    ) -> anyhow::Result<()> {
        let table = sanitize_sql_ident(table_name);
        let schema = sanitize_sql_ident(schema_name);

        sqlx::query(&format!(
            r#"ALTER TABLE "{}"."{}" ENABLE ROW LEVEL SECURITY"#,
            schema, table
        ))
        .execute(&self.db)
        .await?;

        // SELECT policy
        sqlx::query(&format!(
            r#"CREATE POLICY workspace_isolation_select ON "{}"."{}" FOR SELECT
               USING (workspace_id = current_setting('app.current_workspace_id'))"#,
            schema, table
        ))
        .execute(&self.db)
        .await?;

        // INSERT policy
        sqlx::query(&format!(
            r#"CREATE POLICY workspace_isolation_insert ON "{}"."{}" FOR INSERT
               WITH CHECK (workspace_id = current_setting('app.current_workspace_id'))"#,
            schema, table
        ))
        .execute(&self.db)
        .await?;

        // UPDATE policy
        sqlx::query(&format!(
            r#"CREATE POLICY workspace_isolation_update ON "{}"."{}" FOR UPDATE
               USING (workspace_id = current_setting('app.current_workspace_id'))"#,
            schema, table
        ))
        .execute(&self.db)
        .await?;

        // DELETE policy
        sqlx::query(&format!(
            r#"CREATE POLICY workspace_isolation_delete ON "{}"."{}" FOR DELETE
               USING (workspace_id = current_setting('app.current_workspace_id'))"#,
            schema, table
        ))
        .execute(&self.db)
        .await?;

        info!(table = table_name, schema = schema_name, "RLS configured");
        Ok(())
    }

    /// Migrate a workspace between isolation levels.
    pub async fn migrate_isolation_level(
        &self,
        workspace_id: &str,
        current_level: &IsolationLevel,
        target_level: &IsolationLevel,
    ) -> anyhow::Result<()> {
        info!(
            workspace_id = workspace_id,
            from = %current_level,
            to = %target_level,
            "Starting isolation migration"
        );

        let mut tx = self.db.begin().await?;

        match (current_level, target_level) {
            (IsolationLevel::Shared, IsolationLevel::DedicatedSchema) => {
                self.migrate_to_schema(workspace_id, &mut tx).await?;
            }
            (IsolationLevel::DedicatedSchema, IsolationLevel::Shared) => {
                self.migrate_from_schema(workspace_id, &mut tx).await?;
            }
            _ => {
                anyhow::bail!(
                    "Unsupported migration path: {} -> {}",
                    current_level,
                    target_level
                );
            }
        }

        // Update isolation config
        sqlx::query(
            "UPDATE iso_isolation_configs SET current_level=$1, migration_status='completed', updated_at=NOW()
             WHERE workspace_id=$2"
        )
            .bind(target_level.to_string()).bind(workspace_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        info!(workspace_id = workspace_id, "Isolation migration completed");
        Ok(())
    }

    // ── Private ────────────────────────────────────────────

    async fn load_policies(&self) -> anyhow::Result<Vec<DataAccessPolicy>> {
        let rows: Vec<(String, String, String, serde_json::Value, serde_json::Value, String)> =
            sqlx::query_as(
                "SELECT id, name, resource, conditions, actions, effect FROM iso_access_policies"
            )
            .fetch_all(&self.db)
            .await
            .unwrap_or_default();

        let mut policies = Vec::new();
        for (id, name, resource, conditions, actions, effect) in rows {
            policies.push(DataAccessPolicy {
                id,
                name,
                resource,
                conditions: serde_json::from_value(conditions).unwrap_or_default(),
                actions: serde_json::from_value(actions).unwrap_or_default(),
                effect: PolicyEffect::parse(&effect).unwrap_or(PolicyEffect::Deny),
            });
        }
        Ok(policies)
    }

    async fn verify_resource_ownership(
        &self,
        ctx: &IsolationContext,
        resource: &str,
        resource_id: &str,
    ) -> anyhow::Result<bool> {
        let table = resource_to_table(resource);
        let safe = sanitize_sql_ident(&table);

        let row: Option<(String,)> = sqlx::query_as(&format!(
            "SELECT workspace_id FROM {} WHERE id = $1",
            safe
        ))
        .bind(resource_id)
        .fetch_optional(&self.db)
        .await?;

        match row {
            Some((ws_id,)) => Ok(ws_id == ctx.workspace_id),
            None => Ok(false),
        }
    }

    fn evaluate_policies(&self, ctx: &IsolationContext, resource: &str, action: &str) -> bool {
        let matching: Vec<&DataAccessPolicy> = self
            .policies
            .iter()
            .filter(|p| p.resource == resource && p.actions.iter().any(|a| a == action))
            .collect();

        if matching.is_empty() {
            // Default allow if no policies defined for this resource
            return true;
        }

        // Check for deny first
        for policy in &matching {
            if policy.effect == PolicyEffect::Deny
                && self.evaluate_conditions(ctx, &policy.conditions)
            {
                return false;
            }
        }

        // Check for allow
        for policy in &matching {
            if policy.effect == PolicyEffect::Allow
                && self.evaluate_conditions(ctx, &policy.conditions)
            {
                return true;
            }
        }

        false // default deny when explicit policies exist
    }

    fn evaluate_conditions(&self, ctx: &IsolationContext, conditions: &[PolicyCondition]) -> bool {
        conditions.iter().all(|c| {
            let ctx_val = get_context_value(ctx, &c.field);
            match c.operator {
                ConditionOperator::Equals => {
                    ctx_val.as_deref() == c.value.as_str()
                }
                ConditionOperator::NotEquals => {
                    ctx_val.as_deref() != c.value.as_str()
                }
                ConditionOperator::In => {
                    if let Some(arr) = c.value.as_array() {
                        let v = ctx_val.as_deref().unwrap_or("");
                        arr.iter().any(|item| item.as_str() == Some(v))
                    } else {
                        false
                    }
                }
                ConditionOperator::NotIn => {
                    if let Some(arr) = c.value.as_array() {
                        let v = ctx_val.as_deref().unwrap_or("");
                        !arr.iter().any(|item| item.as_str() == Some(v))
                    } else {
                        true
                    }
                }
                ConditionOperator::Contains => {
                    ctx_val
                        .as_deref()
                        .map(|v| v.contains(c.value.as_str().unwrap_or("")))
                        .unwrap_or(false)
                }
                ConditionOperator::StartsWith => {
                    ctx_val
                        .as_deref()
                        .map(|v| v.starts_with(c.value.as_str().unwrap_or("")))
                        .unwrap_or(false)
                }
            }
        })
    }

    async fn audit_access_attempt(
        &self,
        ctx: &IsolationContext,
        target_workspace_id: &str,
        resource: &str,
        action: &str,
        allowed: bool,
    ) {
        let _ = sqlx::query(
            "INSERT INTO iso_access_attempts (id, organization_id, workspace_id, actor_id, target_workspace_id,
             resource, action, allowed, context, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())"
        )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&ctx.organization_id).bind(&ctx.workspace_id)
            .bind(&ctx.user_id).bind(target_workspace_id)
            .bind(resource).bind(action).bind(allowed)
            .bind(serde_json::json!({"isolation_level": ctx.isolation_level.to_string()}))
            .execute(&self.db)
            .await;
    }

    async fn migrate_to_schema(
        &self,
        workspace_id: &str,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> anyhow::Result<()> {
        let schema = format!("ws_{}", sanitize_sql_ident(workspace_id));
        sqlx::query(&format!(r#"CREATE SCHEMA IF NOT EXISTS "{}""#, schema))
            .execute(&mut **tx)
            .await?;

        let tables = ["emails", "contacts", "templates", "campaigns", "webhooks"];
        for table in tables {
            // Create table in new schema
            sqlx::query(&format!(
                r#"CREATE TABLE IF NOT EXISTS "{}"."{}" (LIKE public."{}" INCLUDING ALL)"#,
                schema, table, table
            ))
            .execute(&mut **tx)
            .await?;

            // Copy data
            sqlx::query(&format!(
                r#"INSERT INTO "{}"."{}" SELECT * FROM public."{}" WHERE workspace_id = $1"#,
                schema, table, table
            ))
            .bind(workspace_id)
            .execute(&mut **tx)
            .await?;

            // Delete from shared
            sqlx::query(&format!(
                r#"DELETE FROM public."{}" WHERE workspace_id = $1"#,
                table
            ))
            .bind(workspace_id)
            .execute(&mut **tx)
            .await?;
        }

        // Update workspace schema_name
        sqlx::query("UPDATE iso_workspaces SET schema_name=$1 WHERE id=$2")
            .bind(&schema)
            .bind(workspace_id)
            .execute(&mut **tx)
            .await?;

        Ok(())
    }

    async fn migrate_from_schema(
        &self,
        workspace_id: &str,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> anyhow::Result<()> {
        // Get current schema
        let row: Option<(Option<String>,)> = sqlx::query_as(
            "SELECT schema_name FROM iso_workspaces WHERE id=$1"
        )
            .bind(workspace_id)
            .fetch_optional(&mut **tx)
            .await?;

        let schema = match row.and_then(|r| r.0) {
            Some(s) => s,
            None => anyhow::bail!("No schema found for workspace {}", workspace_id),
        };

        let tables = ["emails", "contacts", "templates", "campaigns", "webhooks"];
        for table in tables {
            sqlx::query(&format!(
                r#"INSERT INTO public."{}" SELECT * FROM "{}"."{}" WHERE workspace_id = $1"#,
                table, sanitize_sql_ident(&schema), table
            ))
            .bind(workspace_id)
            .execute(&mut **tx)
            .await?;
        }

        // Drop the schema
        sqlx::query(&format!(
            r#"DROP SCHEMA IF EXISTS "{}" CASCADE"#,
            sanitize_sql_ident(&schema)
        ))
        .execute(&mut **tx)
        .await?;

        sqlx::query("UPDATE iso_workspaces SET schema_name=NULL WHERE id=$1")
            .bind(workspace_id)
            .execute(&mut **tx)
            .await?;

        Ok(())
    }
}

// ── Helpers ────────────────────────────────────────────────

fn sanitize_sql_ident(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .take(63)
        .collect()
}

fn resource_to_table(resource: &str) -> String {
    match resource {
        "email" => "emails".into(),
        "contact" => "contacts".into(),
        "template" => "templates".into(),
        "campaign" => "campaigns".into(),
        "webhook" => "webhooks".into(),
        "api_key" => "api_keys".into(),
        _ => format!("{}s", resource), // pluralize as fallback
    }
}

fn get_context_value(ctx: &IsolationContext, field: &str) -> Option<String> {
    match field {
        "organization_id" => Some(ctx.organization_id.clone()),
        "workspace_id" => Some(ctx.workspace_id.clone()),
        "user_id" => Some(ctx.user_id.clone()),
        "isolation_level" => Some(ctx.isolation_level.to_string()),
        _ => {
            // Check permissions
            if field == "permissions" {
                Some(ctx.permissions.join(","))
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx() -> IsolationContext {
        IsolationContext {
            organization_id: "org1".into(),
            workspace_id: "ws1".into(),
            user_id: "user1".into(),
            isolation_level: IsolationLevel::Shared,
            schema_name: None,
            permissions: vec!["read".into(), "write".into()],
        }
    }

    #[test]
    fn test_validate_query_blocks_information_schema() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
        };
        let ctx = make_ctx();
        assert!(!svc.validate_query_access(
            "SELECT * FROM information_schema.tables",
            &ctx
        ));
    }

    #[test]
    fn test_validate_query_blocks_pg_catalog() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
        };
        let ctx = make_ctx();
        assert!(!svc.validate_query_access("SELECT * FROM pg_catalog.pg_tables", &ctx));
    }

    #[test]
    fn test_validate_query_blocks_set_search_path() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
        };
        let ctx = make_ctx();
        assert!(!svc.validate_query_access("SET search_path TO public", &ctx));
    }

    #[test]
    fn test_validate_query_blocks_unscoped_select() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
        };
        let ctx = make_ctx();
        // SELECT on tenanted table without workspace_id filter
        assert!(!svc.validate_query_access("SELECT * FROM emails WHERE subject LIKE '%test%'", &ctx));
    }

    #[test]
    fn test_validate_query_allows_scoped_select() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
        };
        let ctx = make_ctx();
        assert!(svc.validate_query_access(
            "SELECT * FROM emails WHERE workspace_id = $1 AND subject LIKE '%test%'",
            &ctx
        ));
    }

    #[test]
    fn test_validate_query_allows_non_tenanted() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
        };
        let ctx = make_ctx();
        assert!(svc.validate_query_access("SELECT * FROM iso_organizations WHERE id = $1", &ctx));
    }

    #[test]
    fn test_evaluate_policies_default_allow_no_policies() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
        };
        let ctx = make_ctx();
        assert!(svc.evaluate_policies(&ctx, "email", "read"));
    }

    #[test]
    fn test_evaluate_policies_deny_overrides() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![DataAccessPolicy {
                id: "p1".into(),
                name: "Deny all writes".into(),
                resource: "email".into(),
                conditions: vec![],
                actions: vec!["write".into()],
                effect: PolicyEffect::Deny,
            }],
        };
        let ctx = make_ctx();
        assert!(!svc.evaluate_policies(&ctx, "email", "write"));
    }

    #[test]
    fn test_evaluate_policies_allow() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![DataAccessPolicy {
                id: "p1".into(),
                name: "Allow reads".into(),
                resource: "email".into(),
                conditions: vec![],
                actions: vec!["read".into()],
                effect: PolicyEffect::Allow,
            }],
        };
        let ctx = make_ctx();
        assert!(svc.evaluate_policies(&ctx, "email", "read"));
    }

    #[test]
    fn test_evaluate_conditions_equals() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
        };
        let ctx = make_ctx();
        let conds = vec![PolicyCondition {
            field: "organization_id".into(),
            operator: ConditionOperator::Equals,
            value: serde_json::json!("org1"),
        }];
        assert!(svc.evaluate_conditions(&ctx, &conds));
    }

    #[test]
    fn test_evaluate_conditions_not_equals() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
        };
        let ctx = make_ctx();
        let conds = vec![PolicyCondition {
            field: "organization_id".into(),
            operator: ConditionOperator::NotEquals,
            value: serde_json::json!("other_org"),
        }];
        assert!(svc.evaluate_conditions(&ctx, &conds));
    }

    #[test]
    fn test_evaluate_conditions_in() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
        };
        let ctx = make_ctx();
        let conds = vec![PolicyCondition {
            field: "workspace_id".into(),
            operator: ConditionOperator::In,
            value: serde_json::json!(["ws1", "ws2", "ws3"]),
        }];
        assert!(svc.evaluate_conditions(&ctx, &conds));
    }

    #[test]
    fn test_evaluate_conditions_not_in() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
        };
        let ctx = make_ctx();
        let conds = vec![PolicyCondition {
            field: "workspace_id".into(),
            operator: ConditionOperator::NotIn,
            value: serde_json::json!(["ws99"]),
        }];
        assert!(svc.evaluate_conditions(&ctx, &conds));
    }

    #[test]
    fn test_evaluate_conditions_contains() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
        };
        let ctx = make_ctx();
        let conds = vec![PolicyCondition {
            field: "user_id".into(),
            operator: ConditionOperator::Contains,
            value: serde_json::json!("user"),
        }];
        assert!(svc.evaluate_conditions(&ctx, &conds));
    }

    #[test]
    fn test_evaluate_conditions_starts_with() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
        };
        let ctx = make_ctx();
        let conds = vec![PolicyCondition {
            field: "organization_id".into(),
            operator: ConditionOperator::StartsWith,
            value: serde_json::json!("org"),
        }];
        assert!(svc.evaluate_conditions(&ctx, &conds));
    }

    #[test]
    fn test_sanitize_sql_ident() {
        assert_eq!(sanitize_sql_ident("table-name"), "tablename");
        assert_eq!(sanitize_sql_ident("my_table_123"), "my_table_123");
        let long = "x".repeat(100);
        assert_eq!(sanitize_sql_ident(&long).len(), 63);
    }

    #[test]
    fn test_resource_to_table() {
        assert_eq!(resource_to_table("email"), "emails");
        assert_eq!(resource_to_table("contact"), "contacts");
        assert_eq!(resource_to_table("api_key"), "api_keys");
        assert_eq!(resource_to_table("custom"), "customs");
    }

    #[test]
    fn test_get_context_value() {
        let ctx = make_ctx();
        assert_eq!(get_context_value(&ctx, "organization_id"), Some("org1".into()));
        assert_eq!(get_context_value(&ctx, "workspace_id"), Some("ws1".into()));
        assert_eq!(get_context_value(&ctx, "user_id"), Some("user1".into()));
        assert_eq!(get_context_value(&ctx, "isolation_level"), Some("shared".into()));
        assert!(get_context_value(&ctx, "unknown").is_none());
    }

    fn test_runtime() -> &'static tokio::runtime::Runtime {
        use std::sync::OnceLock;
        static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
        RT.get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        })
    }

    fn test_pool() -> PgPool {
        let _guard = test_runtime().enter();
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://fake:fake@localhost:1/fake")
            .unwrap()
    }
}
