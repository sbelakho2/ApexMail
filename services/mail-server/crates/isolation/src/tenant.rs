//! Tenant management: organizations, workspaces, members, quotas.

use chrono::Utc;
use dashmap::DashMap;
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::config::{Config, IsolationLevel, QuotaConfig};
use crate::types::*;

// ── Row Types ──────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct OrgRow {
    id: String,
    name: String,
    slug: String,
    billing_email: String,
    plan: String,
    status: String,
    isolation_level: String,
    schema_name: Option<String>,
    database_name: Option<String>,
    owner_id: String,
    metadata: serde_json::Value,
    settings: serde_json::Value,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

impl OrgRow {
    fn into_org(self) -> anyhow::Result<Organization> {
        Ok(Organization {
            id: self.id,
            name: self.name,
            slug: self.slug,
            billing_email: self.billing_email,
            plan: self.plan,
            status: TenantStatus::parse(&self.status)
                .unwrap_or(TenantStatus::Pending),
            isolation_level: IsolationLevel::parse(&self.isolation_level)
                .unwrap_or(IsolationLevel::Shared),
            schema_name: self.schema_name,
            database_name: self.database_name,
            owner_id: self.owner_id,
            metadata: self.metadata,
            settings: serde_json::from_value(self.settings)
                .unwrap_or_default(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct WorkspaceRow {
    id: String,
    organization_id: String,
    name: String,
    slug: String,
    status: String,
    schema_name: Option<String>,
    database_name: Option<String>,
    quota: serde_json::Value,
    usage: serde_json::Value,
    settings: serde_json::Value,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

impl WorkspaceRow {
    fn into_workspace(self) -> anyhow::Result<Workspace> {
        Ok(Workspace {
            id: self.id,
            organization_id: self.organization_id,
            name: self.name,
            slug: self.slug,
            status: TenantStatus::parse(&self.status).unwrap_or(TenantStatus::Pending),
            schema_name: self.schema_name,
            database_name: self.database_name,
            quota: serde_json::from_value(self.quota).unwrap_or_default(),
            usage: serde_json::from_value(self.usage).unwrap_or_default(),
            settings: serde_json::from_value(self.settings).unwrap_or_default(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

// ── Identifier Validation ──────────────────────────────────

static IDENT_RE: std::sync::LazyLock<Option<regex::Regex>> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]*$").ok());

fn validate_identifier(name: &str) -> bool {
    IDENT_RE
        .as_ref()
        .map(|re| re.is_match(name))
        .unwrap_or(false)
}

fn sanitize_identifier(id: &str) -> String {
    let s: String = id.chars().map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' }).collect();
    if s.len() > 63 { s[..63].to_string() } else { s }
}

fn validated_identifier(name: &str) -> anyhow::Result<String> {
    if !validate_identifier(name) {
        anyhow::bail!("Invalid identifier: {}", name);
    }
    Ok(name.to_string())
}

// ── Tenant Service ─────────────────────────────────────────

pub struct TenantService {
    db: PgPool,
    config: Config,
    org_cache: DashMap<String, CacheEntry<Organization>>,
    workspace_cache: DashMap<String, CacheEntry<Workspace>>,
}

const MAX_CACHE_ENTRIES: usize = 10_000;
const CACHE_TTL_SECONDS: i64 = 300;

#[derive(Clone)]
struct CacheEntry<T> {
    value: T,
    cached_at: chrono::DateTime<Utc>,
}

impl<T> CacheEntry<T> {
    fn new(value: T) -> Self {
        Self {
            value,
            cached_at: Utc::now(),
        }
    }

    fn is_expired(&self) -> bool {
        let age = Utc::now() - self.cached_at;
        age.num_seconds() > CACHE_TTL_SECONDS
    }
}

impl TenantService {
    pub fn new(db: PgPool, config: Config) -> Self {
        Self {
            db,
            config,
            org_cache: DashMap::new(),
            workspace_cache: DashMap::new(),
        }
    }

    // ── Organization CRUD ──────────────────────────────────

    pub async fn create_organization(
        &self,
        name: &str,
        slug: &str,
        billing_email: &str,
        plan: Option<&str>,
        isolation_level: Option<IsolationLevel>,
        owner_id: &str,
    ) -> anyhow::Result<Organization> {
        let plan = plan.unwrap_or("free");
        let level = isolation_level.unwrap_or(IsolationLevel::Shared);
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        // Check slug uniqueness
        let existing: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM iso_organizations WHERE slug = $1"
        )
            .bind(slug)
            .fetch_optional(&self.db)
            .await?;

        if existing.is_some() {
            anyhow::bail!("Organization slug '{}' already exists", slug);
        }

        let schema_name = if level == IsolationLevel::DedicatedSchema {
            let sn = format!("org_{}", sanitize_identifier(&id));
            let safe_schema = validated_identifier(&sanitize_identifier(&sn))?;
            sqlx::query(&format!(
                "CREATE SCHEMA IF NOT EXISTS \"{}\"",
                safe_schema
            ))
            .execute(&self.db)
            .await?;
            Some(safe_schema)
        } else {
            None
        };

        let settings = serde_json::to_value(OrgSettings::default())?;
        let metadata = serde_json::json!({});

        let mut tx = self.db.begin().await?;

        sqlx::query(
            "INSERT INTO iso_organizations (id, name, slug, billing_email, plan, status, isolation_level,
             schema_name, database_name, owner_id, settings, metadata, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)"
        )
            .bind(&id).bind(name).bind(slug).bind(billing_email)
            .bind(plan).bind("active").bind(&level.to_string())
            .bind(&schema_name).bind(Option::<String>::None)
            .bind(owner_id).bind(&settings).bind(&metadata)
            .bind(now).bind(now)
            .execute(&mut *tx)
            .await?;

        // Organization ownership is tracked via owner_id on iso_organizations.
        // Workspace membership is created when a concrete workspace is created.

        tx.commit().await?;

        let org = Organization {
            id,
            name: name.into(),
            slug: slug.into(),
            billing_email: billing_email.into(),
            plan: plan.into(),
            status: TenantStatus::Active,
            isolation_level: level,
            schema_name,
            database_name: None,
            owner_id: owner_id.into(),
            metadata,
            settings: OrgSettings::default(),
            created_at: now,
            updated_at: now,
        };
        self.cache_org(&org.id, &org);
        info!(slug = slug, "Organization created");
        Ok(org)
    }

    pub async fn get_organization(&self, id: &str) -> anyhow::Result<Organization> {
        if let Some(cached) = self.get_cached_org(id) {
            return Ok(cached);
        }
        let row: OrgRow = sqlx::query_as::<_, OrgRow>(
            r#"SELECT id, name, slug, billing_email, plan, status, isolation_level,
                      schema_name, database_name, owner_id, metadata, settings,
                      created_at, updated_at
               FROM iso_organizations WHERE id = $1"#
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Organization not found: {}", id))?;

        let org = row.into_org()?;
        self.cache_org(id, &org);
        Ok(org)
    }

    pub async fn update_organization(
        &self,
        id: &str,
        name: Option<&str>,
        billing_email: Option<&str>,
        plan: Option<&str>,
        settings: Option<serde_json::Value>,
    ) -> anyhow::Result<Organization> {
        let existing = self.get_organization(id).await?;
        let name = name.unwrap_or(&existing.name);
        let billing_email = billing_email.unwrap_or(&existing.billing_email);
        let plan = plan.unwrap_or(&existing.plan);
        let settings_val = settings
            .unwrap_or_else(|| serde_json::to_value(&existing.settings).expect("existing settings must serialize"));

        sqlx::query(
            "UPDATE iso_organizations SET name=$1, billing_email=$2, plan=$3, settings=$4, updated_at=$5 WHERE id=$6"
        )
            .bind(name).bind(billing_email).bind(plan)
            .bind(&settings_val).bind(Utc::now()).bind(id)
            .execute(&self.db)
            .await?;

        self.org_cache.remove(id);
        self.get_organization(id).await
    }

    pub async fn suspend_organization(&self, id: &str, reason: &str, actor_id: &str) -> anyhow::Result<()> {
        let mut tx = self.db.begin().await?;
        let now = Utc::now();

        sqlx::query(
            "UPDATE iso_organizations SET status='suspended', metadata = metadata || $1, updated_at=$2 WHERE id=$3"
        )
            .bind(serde_json::json!({"suspended_reason": reason, "suspended_by": actor_id}))
            .bind(now).bind(id)
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            "UPDATE iso_workspaces SET status='suspended', updated_at=$1 WHERE organization_id=$2"
        )
            .bind(now).bind(id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        self.org_cache.remove(id);
        info!(org_id = id, reason = reason, "Organization suspended");
        Ok(())
    }

    // ── Workspace CRUD ─────────────────────────────────────

    pub async fn create_workspace(
        &self,
        organization_id: &str,
        name: &str,
        slug: &str,
        creator_id: &str,
        quota: Option<QuotaConfig>,
    ) -> anyhow::Result<Workspace> {
        let org = self.get_organization(organization_id).await?;

        // Check workspace count limit
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM iso_workspaces WHERE organization_id=$1 AND status != 'deleted'"
        )
            .bind(organization_id)
            .fetch_one(&self.db)
            .await?;

        if count.0 >= self.config.tenant.max_workspaces_per_org as i64 {
            anyhow::bail!("Maximum workspace limit ({}) reached", self.config.tenant.max_workspaces_per_org);
        }

        // Check slug uniqueness within org
        let slug_exists: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM iso_workspaces WHERE organization_id=$1 AND slug=$2"
        )
            .bind(organization_id).bind(slug)
            .fetch_optional(&self.db)
            .await?;

        if slug_exists.is_some() {
            anyhow::bail!("Workspace slug '{}' already exists in this organization", slug);
        }

        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let quota = quota.unwrap_or_else(|| org.settings.default_workspace_quota.clone());
        let usage = WorkspaceUsage::default();
        let settings = WorkspaceSettings::default();

        let schema_name = if org.isolation_level == IsolationLevel::DedicatedSchema {
            let sn = format!("ws_{}", sanitize_identifier(&id));
            self.create_workspace_schema(&sn).await?;
            Some(sn)
        } else {
            None
        };

        let mut tx = self.db.begin().await?;

        sqlx::query(
            "INSERT INTO iso_workspaces (id, organization_id, name, slug, status, schema_name, database_name,
             quota, usage, settings, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)"
        )
            .bind(&id).bind(organization_id).bind(name).bind(slug)
            .bind("active").bind(&schema_name).bind(Option::<String>::None)
            .bind(serde_json::to_value(&quota)?).bind(serde_json::to_value(&usage)?)
            .bind(serde_json::to_value(&settings)?).bind(now).bind(now)
            .execute(&mut *tx)
            .await?;

        // Add creator as admin
        sqlx::query(
            "INSERT INTO iso_workspace_members (id, workspace_id, user_id, role, permissions, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7)"
        )
            .bind(Uuid::new_v4().to_string()).bind(&id)
            .bind(creator_id).bind("admin")
            .bind(serde_json::json!([])).bind(now).bind(now)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        let ws = Workspace {
            id,
            organization_id: organization_id.into(),
            name: name.into(),
            slug: slug.into(),
            status: TenantStatus::Active,
            schema_name,
            database_name: None,
            quota,
            usage,
            settings,
            created_at: now,
            updated_at: now,
        };
        self.cache_workspace(&ws.id, &ws);
        info!(slug = slug, org_id = organization_id, "Workspace created");
        Ok(ws)
    }

    pub async fn get_workspace(&self, id: &str) -> anyhow::Result<Workspace> {
        if let Some(cached) = self.get_cached_workspace(id) {
            return Ok(cached);
        }
        let row: WorkspaceRow = sqlx::query_as::<_, WorkspaceRow>(
            r#"SELECT id, organization_id, name, slug, status, schema_name, database_name,
                      quota, usage, settings, created_at, updated_at
               FROM iso_workspaces WHERE id = $1"#
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Workspace not found: {}", id))?;

        let ws = row.into_workspace()?;
        self.cache_workspace(id, &ws);
        Ok(ws)
    }

    pub async fn update_workspace(
        &self,
        id: &str,
        name: Option<&str>,
        settings: Option<serde_json::Value>,
    ) -> anyhow::Result<Workspace> {
        let existing = self.get_workspace(id).await?;
        let name = name.unwrap_or(&existing.name);
        let settings_val = settings
            .unwrap_or_else(|| serde_json::to_value(&existing.settings).expect("existing settings must serialize"));

        sqlx::query(
            "UPDATE iso_workspaces SET name=$1, settings=$2, updated_at=$3 WHERE id=$4"
        )
            .bind(name).bind(&settings_val).bind(Utc::now()).bind(id)
            .execute(&self.db)
            .await?;

        self.workspace_cache.remove(id);
        self.get_workspace(id).await
    }

    pub async fn delete_workspace(&self, id: &str, actor_id: &str) -> anyhow::Result<()> {
        let now = Utc::now();
        sqlx::query(
            "UPDATE iso_workspaces SET status='deleted', updated_at=$1 WHERE id=$2"
        )
            .bind(now).bind(id)
            .execute(&self.db)
            .await?;

        // Schedule cleanup with 30-day delay
        let cleanup_at = now + chrono::Duration::days(30);
        sqlx::query(
            "INSERT INTO iso_cleanup_queue (id, workspace_id, scheduled_at, created_by, created_at)
             VALUES ($1, $2, $3, $4, $5)"
        )
            .bind(Uuid::new_v4().to_string()).bind(id)
            .bind(cleanup_at).bind(actor_id).bind(now)
            .execute(&self.db)
            .await
            .ok(); // Ignore if table doesn't exist

        self.workspace_cache.remove(id);
        info!(workspace_id = id, "Workspace soft-deleted");
        Ok(())
    }

    pub async fn list_workspaces(&self, organization_id: &str) -> anyhow::Result<Vec<Workspace>> {
        let rows: Vec<WorkspaceRow> = sqlx::query_as::<_, WorkspaceRow>(
            r#"SELECT id, organization_id, name, slug, status, schema_name, database_name,
                      quota, usage, settings, created_at, updated_at
               FROM iso_workspaces
               WHERE organization_id = $1 AND status != 'deleted'
               ORDER BY created_at DESC"#
        )
        .bind(organization_id)
        .fetch_all(&self.db)
        .await?;

        rows.into_iter().map(|r| r.into_workspace()).collect()
    }

    // ── Members ────────────────────────────────────────────

    pub async fn add_workspace_member(
        &self,
        workspace_id: &str,
        user_id: &str,
        role: &TenantRole,
        inviter_id: &str,
    ) -> anyhow::Result<()> {
        // Check member count
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM iso_workspace_members WHERE workspace_id=$1"
        )
            .bind(workspace_id)
            .fetch_one(&self.db)
            .await?;

        if count.0 >= self.config.tenant.max_users_per_workspace as i64 {
            anyhow::bail!("Maximum member limit ({}) reached", self.config.tenant.max_users_per_workspace);
        }

        let now = Utc::now();
        sqlx::query(
            "INSERT INTO iso_workspace_members (id, workspace_id, user_id, role, permissions, invited_by, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
             ON CONFLICT (workspace_id, user_id) DO UPDATE SET role=$4, updated_at=$8"
        )
            .bind(Uuid::new_v4().to_string()).bind(workspace_id)
            .bind(user_id).bind(role.to_string())
            .bind(serde_json::json!([])).bind(inviter_id)
            .bind(now).bind(now)
            .execute(&self.db)
            .await?;

        info!(workspace_id = workspace_id, user_id = user_id, role = %role, "Member added");
        Ok(())
    }

    pub async fn remove_workspace_member(
        &self,
        workspace_id: &str,
        user_id: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "DELETE FROM iso_workspace_members WHERE workspace_id=$1 AND user_id=$2"
        )
            .bind(workspace_id).bind(user_id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    pub async fn check_member_access(
        &self,
        workspace_id: &str,
        user_id: &str,
    ) -> anyhow::Result<MemberAccess> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT role FROM iso_workspace_members WHERE workspace_id=$1 AND user_id=$2"
        )
            .bind(workspace_id).bind(user_id)
            .fetch_optional(&self.db)
            .await?;

        match row {
            Some((role,)) => Ok(MemberAccess {
                has_access: true,
                role: TenantRole::parse(&role),
            }),
            None => Ok(MemberAccess {
                has_access: false,
                role: None,
            }),
        }
    }

    // ── Quota ──────────────────────────────────────────────

    pub async fn check_quota(
        &self,
        workspace_id: &str,
        metric: &str,
        amount: i64,
    ) -> anyhow::Result<bool> {
        let ws = self.get_workspace(workspace_id).await?;
        let (current, limit) = match metric {
            "emails_per_month" => (ws.usage.emails_sent_this_month, ws.quota.emails_per_month),
            "storage_bytes" => (ws.usage.storage_used_bytes, ws.quota.storage_bytes),
            "api_requests_per_minute" => (ws.usage.api_requests_this_minute, ws.quota.api_requests_per_minute),
            "webhooks_per_month" => (ws.usage.webhooks_sent_this_month, ws.quota.webhooks_per_month),
            "contacts" => (ws.usage.contacts_count, ws.quota.contacts_limit),
            "templates" => (ws.usage.templates_count, ws.quota.templates_limit),
            "domains" => (ws.usage.domains_count, ws.quota.domains_limit),
            _ => anyhow::bail!("Unknown quota metric: {}", metric),
        };
        Ok(current + amount <= limit)
    }

    pub async fn update_quota(
        &self,
        workspace_id: &str,
        quota: QuotaConfig,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE iso_workspaces SET quota=$1, updated_at=$2 WHERE id=$3"
        )
            .bind(serde_json::to_value(&quota)?).bind(Utc::now()).bind(workspace_id)
            .execute(&self.db)
            .await?;
        self.workspace_cache.remove(workspace_id);
        Ok(())
    }

    pub async fn increment_usage(
        &self,
        workspace_id: &str,
        metric: &str,
        amount: i64,
    ) -> anyhow::Result<()> {
        let ws = self.get_workspace(workspace_id).await?;
        let mut usage = ws.usage;

        match metric {
            "emails_sent_this_month" => usage.emails_sent_this_month += amount,
            "storage_used_bytes" => usage.storage_used_bytes += amount,
            "api_requests_this_minute" => usage.api_requests_this_minute += amount,
            "webhooks_sent_this_month" => usage.webhooks_sent_this_month += amount,
            "contacts_count" => usage.contacts_count += amount,
            "templates_count" => usage.templates_count += amount,
            "domains_count" => usage.domains_count += amount,
            _ => anyhow::bail!("Unknown usage metric: {}", metric),
        }

        sqlx::query("UPDATE iso_workspaces SET usage=$1, updated_at=$2 WHERE id=$3")
            .bind(serde_json::to_value(&usage)?).bind(Utc::now()).bind(workspace_id)
            .execute(&self.db)
            .await?;

        self.workspace_cache.remove(workspace_id);
        Ok(())
    }

    // ── Cache Helpers ─────────────────────────────────────

    fn get_cached_org(&self, id: &str) -> Option<Organization> {
        let entry = self.org_cache.get(id)?;
        if entry.is_expired() {
            drop(entry);
            self.org_cache.remove(id);
            return None;
        }
        Some(entry.value.clone())
    }

    fn get_cached_workspace(&self, id: &str) -> Option<Workspace> {
        let entry = self.workspace_cache.get(id)?;
        if entry.is_expired() {
            drop(entry);
            self.workspace_cache.remove(id);
            return None;
        }
        Some(entry.value.clone())
    }

        fn cache_org(&self, id: &str, org: &Organization) {
        self.prune_org_cache();
        self.org_cache
            .insert(id.to_string(), CacheEntry::new(org.clone()));
    }

        fn cache_workspace(&self, id: &str, workspace: &Workspace) {
        self.prune_workspace_cache();
        self.workspace_cache
            .insert(id.to_string(), CacheEntry::new(workspace.clone()));
    }

    fn prune_org_cache(&self) {
        if self.org_cache.len() > MAX_CACHE_ENTRIES {
            self.org_cache.clear();
        }
    }

    fn prune_workspace_cache(&self) {
        if self.workspace_cache.len() > MAX_CACHE_ENTRIES {
            self.workspace_cache.clear();
        }
    }


    // ── Schema Helpers ─────────────────────────────────────

    async fn create_workspace_schema(&self, schema_name: &str) -> anyhow::Result<()> {
        let safe = validated_identifier(&sanitize_identifier(schema_name))?;
        sqlx::query(&format!(r#"CREATE SCHEMA IF NOT EXISTS "{}""#, safe))
            .execute(&self.db)
            .await?;

        // Create standard tables in the schema
        for table_sql in &[
            format!(r#"CREATE TABLE IF NOT EXISTS "{}".emails (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id TEXT NOT NULL, subject TEXT, body TEXT, created_at TIMESTAMPTZ DEFAULT NOW())"#, safe),
            format!(r#"CREATE TABLE IF NOT EXISTS "{}".contacts (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id TEXT NOT NULL, email TEXT NOT NULL, name TEXT, created_at TIMESTAMPTZ DEFAULT NOW())"#, safe),
            format!(r#"CREATE TABLE IF NOT EXISTS "{}".templates (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id TEXT NOT NULL, name TEXT NOT NULL, content TEXT, created_at TIMESTAMPTZ DEFAULT NOW())"#, safe),
        ] {
            sqlx::query(table_sql).execute(&self.db).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_identifier_valid() {
        assert!(validate_identifier("abc_123"));
        assert!(validate_identifier("_test"));
        assert!(validate_identifier("MyTable"));
    }

    #[test]
    fn test_validate_identifier_invalid() {
        assert!(!validate_identifier("123abc"));
        assert!(!validate_identifier("with space"));
        assert!(!validate_identifier("drop--table"));
        assert!(!validate_identifier(""));
    }

    #[test]
    fn test_sanitize_identifier() {
        assert_eq!(sanitize_identifier("org-abc-123"), "org_abc_123");
        assert_eq!(sanitize_identifier("clean_name"), "clean_name");
    }

    #[test]
    fn test_sanitize_identifier_length() {
        let long = "a".repeat(100);
        assert_eq!(sanitize_identifier(&long).len(), 63);
    }

    #[test]
    fn test_org_row_into_org() {
        let row = OrgRow {
            id: "o1".into(),
            name: "Test Org".into(),
            slug: "test-org".into(),
            billing_email: "bill@test.com".into(),
            plan: "pro".into(),
            status: "active".into(),
            isolation_level: "shared".into(),
            schema_name: None,
            database_name: None,
            owner_id: "u1".into(),
            metadata: serde_json::json!({}),
            settings: serde_json::json!({}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let org = row.into_org().unwrap();
        assert_eq!(org.id, "o1");
        assert_eq!(org.status, TenantStatus::Active);
        assert_eq!(org.isolation_level, IsolationLevel::Shared);
    }

    #[test]
    fn test_workspace_row_into_workspace() {
        let row = WorkspaceRow {
            id: "w1".into(),
            organization_id: "o1".into(),
            name: "My Workspace".into(),
            slug: "my-ws".into(),
            status: "active".into(),
            schema_name: None,
            database_name: None,
            quota: serde_json::to_value(QuotaConfig::default()).unwrap(),
            usage: serde_json::to_value(WorkspaceUsage::default()).unwrap(),
            settings: serde_json::to_value(WorkspaceSettings::default()).unwrap(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let ws = row.into_workspace().unwrap();
        assert_eq!(ws.id, "w1");
        assert_eq!(ws.status, TenantStatus::Active);
        assert_eq!(ws.quota.emails_per_month, 50_000);
    }

    #[test]
    fn test_org_row_unknown_status() {
        let row = OrgRow {
            id: "o2".into(),
            name: "X".into(),
            slug: "x".into(),
            billing_email: "x@x.com".into(),
            plan: "free".into(),
            status: "unknown_status".into(),
            isolation_level: "unknown_level".into(),
            schema_name: None,
            database_name: None,
            owner_id: "u".into(),
            metadata: serde_json::json!({}),
            settings: serde_json::json!({}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let org = row.into_org().unwrap();
        // Falls back to defaults
        assert_eq!(org.status, TenantStatus::Pending);
        assert_eq!(org.isolation_level, IsolationLevel::Shared);
    }
}
