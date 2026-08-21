//! Data isolation:connection scoping, RLS, access policies, migration.

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
        // set_config( is the functional form of SET and must never appear in
        // tenant-submitted SQL regardless of quoting/whitespace/case.
        r"(?i)set_config\s*\(",
    ]
    .iter()
    .filter_map(|p| Regex::new(p).ok())
    .collect()
});

static IDENT_REGEX: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^[a-z_][a-z0-9_]{0,62}$").ok());

/// Table references (`FROM x`, `JOIN s.t`, `UPDATE ONLY t`, `INTO "t"`) with
/// flexible whitespace and optional schema qualification.
static TABLE_REF_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)
        \b(?:from|join|update(?:\s+only)?|into)\s+
        (
            (?:"[^"]+"\s*\.\s*)*            # optional quoted schema qualification
            (?:[A-Za-z_][A-Za-z0-9_$]*\s*\.\s*)*  # optional bare schema qualification
            (?:"[^"]+"|[A-Za-z_][A-Za-z0-9_$]*)  # the table name itself
        )
        "#,
    )
    .ok()
});

/// Parameterized tenant predicate:`workspace_id = $N`, `workspace_id = ?`,
/// or a current_setting-based RLS binding.
static TENANT_PREDICATE_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)
        \b(?:workspace_id|organization_id)\s*=\s*(?:\$\d+|\?)
        |
        current_setting\s*\(\s*'app\.(?:current_workspace_id|current_org_id)'
        "#,
    )
    .ok()
});

/// Extract the (lowercased, unquoted) table names referenced by
/// FROM/JOIN/UPDATE/INTO clauses, tolerating schema qualification
/// (`public.emails`) and quoted identifiers (`"Emails"`).
fn referenced_tables(query: &str) -> Vec<String> {
    let mut tables = Vec::new();
    let Some(re) = TABLE_REF_RE.as_ref() else {
        return tables;
    };
    for caps in re.captures_iter(query) {
        let Some(m) = caps.get(1) else { continue };
        let reference = m.as_str();
        // Take the last dot-separated segment, strip quoting, lowercase.
        let table = reference
            .rsplit('.')
            .next()
            .unwrap_or(reference)
            .trim()
            .trim_matches('"')
            .trim_matches('"')
            .to_lowercase();
        if !table.is_empty() {
            tables.push(table);
        }
    }
    tables
}

/// Strip SQL comments (`-- … EOL` and `/* … */`) while respecting single-quote
/// string literals, so a predicate hidden inside a comment cannot satisfy the
/// tenant-predicate check and comment contents cannot be used for evasion.
fn strip_sql_comments(query: &str) -> String {
    let mut out = String::with_capacity(query.len());
    let bytes = query.as_bytes();
    let mut i = 0;
    let mut in_string = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            if c == b'\'' {
                // '' is an escaped quote inside the literal
                if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                    out.push_str("''");
                    i += 2;
                    continue;
                }
                in_string = false;
            }
            out.push(c as char);
            i += 1;
            continue;
        }
        match c {
            b'\'' => {
                in_string = true;
                out.push('\'');
                i += 1;
            }
            b'-' if i + 1 < bytes.len() && bytes[i + 1] == b'-' => {
                // line comment:skip to end of line
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                out.push('\n');
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                // block comment:skip to closing */
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
                out.push(' ');
            }
            _ => {
                // copy one UTF-8 char
                let ch_len = utf8_char_len(bytes, i);
                if let Ok(s) = std::str::from_utf8(&bytes[i..(i + ch_len).min(bytes.len())]) {
                    out.push_str(s);
                    i += ch_len;
                } else {
                    out.push(c as char);
                    i += 1;
                }
            }
        }
    }
    out
}

fn utf8_char_len(bytes: &[u8], i: usize) -> usize {
    let b = bytes[i];
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else if b >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

// ── Data Isolation Service ─────────────────────────────────

pub struct DataIsolationService {
    db: PgPool,
    policies: Vec<DataAccessPolicy>,
    /// Whether the policy set was successfully loaded from the database.
    /// Requests are denied while this is false (fail-closed) — an empty or
    /// failed policy load must never widen access.
    policies_loaded: bool,
}

impl DataIsolationService {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            policies: Vec::new(),
            policies_loaded: false,
        }
    }

    /// Load access policies from DB on startup.
    /// Fails loudly:policy load errors are a startup hard error so a
    /// misconfigured database cannot silently disable policy enforcement.
    pub async fn initialize(&mut self) -> anyhow::Result<()> {
        self.policies = self.load_policies().await?;
        self.policies_loaded = true;
        info!(count = self.policies.len(), "Data access policies loaded");
        Ok(())
    }

    /// Validate a SQL query for safety in a tenant-isolated context.
    pub fn validate_query_access(&self, query: &str, ctx: &IsolationContext) -> bool {
        if !self.policies_loaded {
            warn!(
                user_id = ctx.user_id,
                workspace_id = ctx.workspace_id,
                "Denied query:access policies have not been loaded (fail-closed)"
            );
            return false;
        }

        // Analyze the comment-stripped form so predicates hidden in comments
        // cannot satisfy checks and commented-out clauses cannot evade them.
        let stripped = strip_sql_comments(query);

        // Block dangerous patterns
        for pattern in DANGEROUS_PATTERNS.iter() {
            if pattern.is_match(&stripped) {
                warn!(
                    user_id = ctx.user_id,
                    workspace_id = ctx.workspace_id,
                    "Blocked dangerous query pattern"
                );
                return false;
            }
        }

        // #292:stronger table + predicate checks for SELECT/UPDATE/DELETE with
        // JOIN/CTE-aware parsing. Table extraction tolerates schema
        // qualification (`public.emails`), quoted identifiers, and arbitrary
        // whitespace/newlines between the clause keyword and the table name.
        let tenanted_tables = ["emails", "contacts", "templates", "campaigns", "webhooks"];
        let referenced = referenced_tables(&stripped);
        let touches_tenanted_table = referenced.iter().any(|t| tenanted_tables.contains(&t.as_str()));

        if touches_tenanted_table {
            let has_workspace_predicate = TENANT_PREDICATE_RE
                .as_ref()
                .map(|re| re.is_match(&stripped))
                .unwrap_or(false);

            if !has_workspace_predicate {
                warn!(
                    user_id = ctx.user_id,
                    workspace_id = ctx.workspace_id,
                    "Blocked query touching tenanted tables without required parameterized workspace/organization predicate"
                );
                return false;
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
        // Fail closed:if the policy set never loaded successfully, refuse.
        if !self.policies_loaded {
            warn!(
                user_id = ctx.user_id,
                resource = resource,
                "Denied access:access policies have not been loaded (fail-closed)"
            );
            return Ok(false);
        }

        // Verify workspace ownership
        let owns = self
            .verify_resource_ownership(ctx, resource, resource_id)
            .await?;
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
    pub async fn setup_rls(&self, table_name: &str, schema_name: &str) -> anyhow::Result<()> {
        // #293:fail-closed identifier validation for dynamic DDL.
        let table = validate_sql_ident(table_name)?;
        let schema = validate_sql_ident(schema_name)?;
        let table_quoted = quote_sql_ident(&table);
        let schema_quoted = quote_sql_ident(&schema);

        for stmt in rls_statements(&schema_quoted, &table_quoted) {
            sqlx::query(&stmt).execute(&self.db).await?;
        }

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
        let rows: Vec<(
            String,
            String,
            String,
            serde_json::Value,
            serde_json::Value,
            String,
        )> = sqlx::query_as(
            "SELECT id, name, resource, conditions, actions, effect FROM iso_access_policies",
        )
        .fetch_all(&self.db)
        .await?;

        let mut policies = Vec::with_capacity(rows.len());
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
        let safe = validate_sql_ident(&table)?;
        let safe_quoted = quote_sql_ident(&safe);

        let row: Option<(String,)> = sqlx::query_as(&format!(
            "SELECT workspace_id FROM {} WHERE id = $1",
            safe_quoted
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
                ConditionOperator::Equals => ctx_val.as_deref() == c.value.as_str(),
                ConditionOperator::NotEquals => ctx_val.as_deref() != c.value.as_str(),
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
                ConditionOperator::Contains => ctx_val
                    .as_deref()
                    .map(|v| v.contains(c.value.as_str().unwrap_or("")))
                    .unwrap_or(false),
                ConditionOperator::StartsWith => ctx_val
                    .as_deref()
                    .map(|v| v.starts_with(c.value.as_str().unwrap_or("")))
                    .unwrap_or(false),
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
        if let Err(e) = sqlx::query(
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
            .await
        {
            tracing::error!(
                error = %e,
                actor = %ctx.user_id,
                target = %target_workspace_id,
                allowed = allowed,
                "SECURITY: Failed to record access attempt — audit trail gap"
            );
        }
    }

    async fn migrate_to_schema(
        &self,
        workspace_id: &str,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> anyhow::Result<()> {
        let schema = format!("ws_{}", sanitize_sql_ident(workspace_id));
        let schema_safe = validate_sql_ident(&schema)?;
        let schema_quoted = quote_sql_ident(&schema_safe);
        sqlx::query(&format!("CREATE SCHEMA IF NOT EXISTS {}", schema_quoted))
            .execute(&mut **tx)
            .await?;

        let tables = ["emails", "contacts", "templates", "campaigns", "webhooks"];
        for table in tables {
            // Create table in new schema
            sqlx::query(&format!(
                "CREATE TABLE IF NOT EXISTS {}.{} (LIKE public.{} INCLUDING ALL)",
                schema_quoted,
                quote_sql_ident(table),
                quote_sql_ident(table)
            ))
            .execute(&mut **tx)
            .await?;

            // Copy data
            sqlx::query(&format!(
                "INSERT INTO {}.{} SELECT * FROM public.{} WHERE workspace_id = $1",
                schema_quoted,
                quote_sql_ident(table),
                quote_sql_ident(table)
            ))
            .bind(workspace_id)
            .execute(&mut **tx)
            .await?;

            // Delete from shared
            sqlx::query(&format!(
                "DELETE FROM public.{} WHERE workspace_id = $1",
                quote_sql_ident(table)
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
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT schema_name FROM iso_workspaces WHERE id=$1")
                .bind(workspace_id)
                .fetch_optional(&mut **tx)
                .await?;

        let schema = match row.and_then(|r| r.0) {
            Some(s) => s,
            None => anyhow::bail!("No schema found for workspace {}", workspace_id),
        };
        let schema_safe = validate_sql_ident(&schema)?;
        let schema_quoted = quote_sql_ident(&schema_safe);

        let tables = ["emails", "contacts", "templates", "campaigns", "webhooks"];
        for table in tables {
            sqlx::query(&format!(
                "INSERT INTO public.{} SELECT * FROM {}.{} WHERE workspace_id = $1",
                quote_sql_ident(table),
                schema_quoted,
                quote_sql_ident(table)
            ))
            .bind(workspace_id)
            .execute(&mut **tx)
            .await?;
        }

        // Drop the schema
        sqlx::query(&format!("DROP SCHEMA IF EXISTS {} CASCADE", schema_quoted))
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

fn validate_sql_ident(s: &str) -> anyhow::Result<String> {
    let normalized = s.trim().to_lowercase();
    let is_valid = IDENT_REGEX
        .as_ref()
        .map(|re| re.is_match(&normalized))
        .unwrap_or(false);
    if !is_valid {
        anyhow::bail!("Invalid SQL identifier: {s}");
    }
    Ok(normalized)
}

fn quote_sql_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// The full set of DDL statements to enable workspace-scoped RLS on a table.
///
/// `FORCE ROW LEVEL SECURITY` is issued alongside `ENABLE`:without FORCE the
/// table *owner* bypasses RLS entirely, so any code path connecting as the
/// owning role would silently defeat tenant isolation. Service accounts that
/// legitimately need to bypass RLS (migrations, backfills) must use a distinct
/// role with the BYPASSRLS attribute — never the owning application role.
fn rls_statements(schema_quoted: &str, table_quoted: &str) -> Vec<String> {
    vec![
        format!(
            "ALTER TABLE {}.{} ENABLE ROW LEVEL SECURITY",
            schema_quoted, table_quoted
        ),
        format!(
            "ALTER TABLE {}.{} FORCE ROW LEVEL SECURITY",
            schema_quoted, table_quoted
        ),
        format!(
            "CREATE POLICY workspace_isolation_select ON {}.{} FOR SELECT
               USING (workspace_id = current_setting('app.current_workspace_id'))",
            schema_quoted, table_quoted
        ),
        format!(
            "CREATE POLICY workspace_isolation_insert ON {}.{} FOR INSERT
               WITH CHECK (workspace_id = current_setting('app.current_workspace_id'))",
            schema_quoted, table_quoted
        ),
        format!(
            "CREATE POLICY workspace_isolation_update ON {}.{} FOR UPDATE
               USING (workspace_id = current_setting('app.current_workspace_id'))",
            schema_quoted, table_quoted
        ),
        format!(
            "CREATE POLICY workspace_isolation_delete ON {}.{} FOR DELETE
               USING (workspace_id = current_setting('app.current_workspace_id'))",
            schema_quoted, table_quoted
        ),
    ]
}

fn resource_to_table(resource: &str) -> String {
    match resource {
        "email" => "emails".into(),
        "contact" => "contacts".into(),
        "template" => "templates".into(),
        "campaign" => "campaigns".into(),
        "webhook" => "webhooks".into(),
        "api_key" => "api_keys".into(),
        // Reject unknown resources instead of blindly pluralising user input
        other => {
            tracing::error!(resource = %other, "Unknown resource type in data isolation — refusing to guess table name");
            "__unknown__".into()
        }
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
            policies_loaded: true,
        };
        let ctx = make_ctx();
        assert!(!svc.validate_query_access("SELECT * FROM information_schema.tables", &ctx));
    }

    #[test]
    fn test_validate_query_blocks_pg_catalog() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
            policies_loaded: true,
        };
        let ctx = make_ctx();
        assert!(!svc.validate_query_access("SELECT * FROM pg_catalog.pg_tables", &ctx));
    }

    #[test]
    fn test_validate_query_blocks_set_search_path() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
            policies_loaded: true,
        };
        let ctx = make_ctx();
        assert!(!svc.validate_query_access("SET search_path TO public", &ctx));
    }

    #[test]
    fn test_validate_query_blocks_unscoped_select() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
            policies_loaded: true,
        };
        let ctx = make_ctx();
        // SELECT on tenanted table without workspace_id filter
        assert!(
            !svc.validate_query_access("SELECT * FROM emails WHERE subject LIKE '%test%'", &ctx)
        );
    }

    #[test]
    fn test_validate_query_allows_scoped_select() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
            policies_loaded: true,
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
            policies_loaded: true,
        };
        let ctx = make_ctx();
        assert!(svc.validate_query_access("SELECT * FROM iso_organizations WHERE id = $1", &ctx));
    }

    // ── SQL validator bypass regression tests ──

    fn loaded_svc() -> DataIsolationService {
        DataIsolationService {
            db: test_pool(),
            policies: vec![],
            policies_loaded: true,
        }
    }

    #[test]
    fn test_validate_query_blocks_schema_qualified_table() {
        let svc = loaded_svc();
        let ctx = make_ctx();
        // Schema qualification previously hid the tenanted table name.
        assert!(!svc.validate_query_access(
            "SELECT * FROM public.emails WHERE subject LIKE '%test%'",
            &ctx
        ));
        // …and is fine when properly parameterized.
        assert!(svc.validate_query_access(
            "SELECT * FROM public.emails WHERE workspace_id = $1",
            &ctx
        ));
    }

    #[test]
    fn test_validate_query_blocks_newline_obfuscated_table() {
        let svc = loaded_svc();
        let ctx = make_ctx();
        assert!(!svc.validate_query_access(
            "SELECT * FROM\n\temails\nWHERE subject LIKE '%test%'",
            &ctx
        ));
    }

    #[test]
    fn test_validate_query_blocks_predicate_satisfied_by_comment() {
        let svc = loaded_svc();
        let ctx = make_ctx();
        // The workspace predicate only exists inside a comment — the real
        // predicate is a literal comparison. Must be blocked.
        assert!(!svc.validate_query_access(
            "SELECT * FROM emails WHERE subject = 'x' /* workspace_id = $1 */",
            &ctx
        ));
        assert!(!svc.validate_query_access(
            "SELECT * FROM emails WHERE subject = 'x' -- workspace_id = $1",
            &ctx
        ));
    }

    #[test]
    fn test_validate_query_blocks_set_config() {
        let svc = loaded_svc();
        let ctx = make_ctx();
        // set_config() is the functional form of SET and bypassed the
        // `SET search_path` regex.
        assert!(!svc.validate_query_access(
            "SELECT set_config('search_path', 'public', false)",
            &ctx
        ));
        assert!(!svc.validate_query_access(
            "SELECT SET_CONFIG ( 'role', 'admin', true )",
            &ctx
        ));
    }

    #[test]
    fn test_validate_query_blocks_literal_workspace_predicate() {
        let svc = loaded_svc();
        let ctx = make_ctx();
        // A literal (non-parameterized) workspace predicate must not satisfy
        // the tenancy requirement.
        assert!(!svc.validate_query_access(
            "SELECT * FROM emails WHERE workspace_id = 12345",
            &ctx
        ));
        // `?` placeholder is an accepted parameterized form.
        assert!(svc.validate_query_access(
            "SELECT * FROM emails WHERE workspace_id = ?",
            &ctx
        ));
    }

    #[test]
    fn test_validate_query_blocks_update_and_join_without_predicate() {
        let svc = loaded_svc();
        let ctx = make_ctx();
        assert!(!svc.validate_query_access(
            "UPDATE emails SET subject = $1 WHERE id = $2",
            &ctx
        ));
        assert!(!svc.validate_query_access(
            "SELECT * FROM contacts c JOIN emails e ON c.id = e.contact_id WHERE c.id = $1",
            &ctx
        ));
        assert!(svc.validate_query_access(
            "SELECT * FROM contacts c JOIN emails e ON c.id = e.contact_id WHERE e.workspace_id = $1",
            &ctx
        ));
    }

    #[test]
    fn test_validate_query_fail_closed_when_policies_not_loaded() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
            policies_loaded: false,
        };
        let ctx = make_ctx();
        assert!(
            !svc.validate_query_access("SELECT * FROM iso_organizations WHERE id = $1", &ctx),
            "queries must be denied while policies are not loaded (fail-closed)"
        );
    }

    #[test]
    fn test_strip_sql_comments_preserves_strings() {
        // `--` inside a string literal is not a comment.
        let stripped = strip_sql_comments("SELECT 'a--b' FROM t");
        assert!(stripped.contains("'a--b'"), "got: {}", stripped);
        // Block comment removed.
        let stripped = strip_sql_comments("SELECT 1 /* hidden workspace_id = $1 */ FROM t");
        assert!(!stripped.contains("workspace_id"), "got: {}", stripped);
    }

    #[test]
    fn test_referenced_tables_handles_qualification_and_whitespace() {
        let tables = referenced_tables("SELECT * FROM\npublic.\"Emails\" e JOIN contacts ON true");
        assert!(tables.contains(&"emails".to_string()), "got: {:?}", tables);
        assert!(tables.contains(&"contacts".to_string()), "got: {:?}", tables);
    }

    #[test]
    fn test_rls_statements_include_force() {
        let stmts = rls_statements("\"public\"", "\"emails\"");
        assert!(stmts.iter().any(|s| s.contains("ENABLE ROW LEVEL SECURITY")));
        assert!(
            stmts.iter().any(|s| s.contains("FORCE ROW LEVEL SECURITY")),
            "FORCE RLS must be issued so the table owner is also subject to policies: {:?}",
            stmts
        );
        assert_eq!(stmts.len(), 6);
    }

    #[test]
    fn test_evaluate_policies_default_allow_no_policies() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies: vec![],
            policies_loaded: true,
        };
        let ctx = make_ctx();
        assert!(svc.evaluate_policies(&ctx, "email", "read"));
    }

    #[test]
    fn test_evaluate_policies_deny_overrides() {
        let svc = DataIsolationService {
            db: test_pool(),
            policies_loaded: true,
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
            policies_loaded: true,
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
            policies_loaded: true,
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
            policies_loaded: true,
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
            policies_loaded: true,
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
            policies_loaded: true,
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
            policies_loaded: true,
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
            policies_loaded: true,
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
        assert_eq!(resource_to_table("custom"), "__unknown__");
    }

    #[test]
    fn test_get_context_value() {
        let ctx = make_ctx();
        assert_eq!(
            get_context_value(&ctx, "organization_id"),
            Some("org1".into())
        );
        assert_eq!(get_context_value(&ctx, "workspace_id"), Some("ws1".into()));
        assert_eq!(get_context_value(&ctx, "user_id"), Some("user1".into()));
        assert_eq!(
            get_context_value(&ctx, "isolation_level"),
            Some("shared".into())
        );
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
