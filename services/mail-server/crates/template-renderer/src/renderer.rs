//! Full template rendering pipeline:transpile → sandbox → render → plaintext.

use std::time::Instant;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::info;

use crate::cache::TemplateCache;
use crate::config::RendererConfig;
use crate::plaintext::html_to_plaintext;
use crate::sandbox::Sandbox;
use crate::transpiler;
use crate::types::{
    RenderMetadata, RenderOptions, RenderResult, Template, TemplateError, ValidationResult,
    STARTER_TEMPLATE,
};

/// F62: load the CURRENT version of a stored template from the canonical
/// `templates` table — the same table (and columns) the api-server templates
/// routes read. Ids and tenant scope are VARCHAR(26) TEXT, not UUIDs. The
/// `tenant_id = $2` predicate is the ownership check: a template id that
/// belongs to another tenant simply does not match and surfaces as
/// `TemplateError::NotFound`.
const LOAD_CURRENT_VERSION_SQL: &str = r#"
            SELECT id, tenant_id, name, subject, html_body, text_body, version, status, created_at, updated_at
            FROM templates
            WHERE id = $1 AND tenant_id = $2
            "#;

/// F62: load a HISTORICAL version snapshot from the canonical
/// `template_versions` table (migration 107; PK `(template_id, version)`).
/// Tenant-scoped exactly like the current-version load.
const LOAD_TEMPLATE_VERSION_SQL: &str = r#"
            SELECT template_id, tenant_id, version, subject, html_body, text_body, created_at
            FROM template_versions
            WHERE template_id = $1 AND tenant_id = $2 AND version = $3
            "#;

/// The main template rendering service.
pub struct TemplateRenderer {
    db: PgPool,
    sandbox: Sandbox,
    cache: TemplateCache,
    config: RendererConfig,
}

impl TemplateRenderer {
    pub fn new(db: PgPool, config: RendererConfig) -> Self {
        let sandbox = Sandbox::new(config.sandbox.clone());
        let cache = TemplateCache::new(config.cache.max_entries, config.cache.ttl_secs);
        Self {
            db,
            sandbox,
            cache,
            config,
        }
    }

    /// Render a template from source string.
    pub fn render_source(
        &self,
        source: &str,
        options: &RenderOptions,
    ) -> Result<RenderResult, TemplateError> {
        let start = Instant::now();

        // Execute in sandbox
        let sandbox_result = self.sandbox.execute(source, options)?;

        // Generate plaintext if requested
        let plaintext = if options.generate_plaintext {
            Some(html_to_plaintext(&sandbox_result.html))
        } else {
            None
        };

        // Resolve subject placeholders (plain text — no HTML escaping; the
        // subject is a header value, not markup) and strip CR/LF/NUL so a
        // merge field can never inject additional headers. Missing fields
        // follow the same fallback policy as the body.
        let fallback = options.missing_field_fallback.as_deref().unwrap_or("");
        let subject = options.subject.as_ref().map(|s| {
            transpiler::resolve_placeholders_subject_reported(s, &options.props, fallback).html
        });

        let elapsed = start.elapsed();

        Ok(RenderResult {
            html: sandbox_result.html.clone(),
            plaintext: plaintext.clone(),
            subject,
            metadata: RenderMetadata {
                render_time_ms: elapsed.as_millis() as u64,
                html_size_bytes: sandbox_result.html.len(),
                plaintext_size_bytes: plaintext.as_ref().map(|p| p.len()),
                cached: false,
            },
            warnings: sandbox_result.warnings,
        })
    }

    /// Render a stored template by ID from the canonical `templates` table,
    /// or — when `version` is given — a pinned historical snapshot from
    /// `template_versions`. Uses the render cache when the stored content is
    /// unchanged.
    ///
    /// F62: tenant ids are TEXT (`VARCHAR(26)`), matching the canonical
    /// repository. Both load queries are tenant-scoped, so a template id
    /// owned by a different tenant is indistinguishable from a missing one
    /// (`TemplateError::NotFound`) — no cross-tenant leak, cached or
    /// otherwise.
    pub async fn render_template(
        &self,
        tenant_id: &str,
        template_id: &str,
        version: Option<i32>,
        options: &RenderOptions,
    ) -> Result<RenderResult, TemplateError> {
        // Load BEFORE consulting the cache: the row's `version` and content
        // stamp are part of the cache key, and only the canonical tables can
        // supply them. The api-server writer bumps `version` on every save
        // and rewrites `updated_at` (and the snapshot's `created_at`) on
        // rollback, so any stored change rotates the key — a cached render
        // never outlives a canonical write. The cache therefore saves the
        // sandbox render work, not the DB read.
        let stored = match version {
            None => self.load_current_version(tenant_id, template_id).await?,
            Some(v) => {
                self.load_template_version(tenant_id, template_id, v)
                    .await?
            }
        };

        let cache_key = stored_render_cache_key(&stored, options);

        // Check cache
        if let Some(cached) = self.cache.get(&cache_key) {
            info!(template_id, version = stored.version, "Cache hit");
            return Ok(RenderResult {
                metadata: RenderMetadata {
                    cached: true,
                    ..cached.metadata
                },
                ..cached
            });
        }

        // Render
        let result = self.render_stored(&stored, options)?;

        // Store in cache
        self.cache.insert(cache_key, result.clone());

        Ok(result)
    }

    /// Validate template source without rendering.
    pub fn validate(&self, source: &str) -> ValidationResult {
        transpiler::validate_source(source, self.config.sandbox.max_source_length)
    }

    /// Get a starter template for new email designs.
    pub fn starter_template(&self) -> &'static str {
        STARTER_TEMPLATE
    }

    /// Store a template in the canonical repository (F62): insert into
    /// `templates` and snapshot v1 into `template_versions` in one
    /// transaction — the same write pair the api-server create route
    /// performs, so a template saved through this path is rollback-safe and
    /// versioned exactly like one saved through the API.
    pub async fn save_template(
        &self,
        tenant_id: &str,
        name: &str,
        subject: &str,
        html_body: &str,
        text_body: Option<&str>,
    ) -> Result<Template, TemplateError> {
        // Validate first (the HTML body goes through the sandbox pipeline)
        let validation = self.validate(html_body);
        if !validation.valid {
            let msg = validation
                .errors
                .iter()
                .map(|e| e.message.clone())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(TemplateError::InvalidSyntax { message: msg });
        }

        // templates.id is VARCHAR(26) — generate a 26-char text id (not a
        // UUID, whose 36-char hyphenated form overflows the column), exactly
        // like the api-server create route.
        let id = apexmail_lib::id::generate_id("", 26);
        let now = chrono::Utc::now();

        let mut tx = self.db.begin().await?;

        let row: CurrentTemplateRow = sqlx::query_as::<_, CurrentTemplateRow>(
            r#"
            INSERT INTO templates (id, tenant_id, name, subject, html_body, text_body, version, status, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, 1, 'active', $7, $7)
            RETURNING id, tenant_id, name, subject, html_body, text_body, version, status, created_at, updated_at
            "#,
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(name)
        .bind(subject)
        .bind(html_body)
        .bind(text_body)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;

        // v1 snapshot (upsert keeps history linear, mirroring the api-server
        // writer's `snapshot_template_version`).
        sqlx::query(
            r#"
            INSERT INTO template_versions (template_id, tenant_id, version, name, subject, html_body, text_body)
            VALUES ($1, $2, 1, $3, $4, $5, $6)
            ON CONFLICT (template_id, version) DO UPDATE SET
                tenant_id = EXCLUDED.tenant_id,
                name      = EXCLUDED.name,
                subject   = EXCLUDED.subject,
                html_body = EXCLUDED.html_body,
                text_body = EXCLUDED.text_body,
                created_at = NOW()
            "#,
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(name)
        .bind(subject)
        .bind(html_body)
        .bind(text_body)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(row.into_template())
    }

    /// Load the current version of a stored template (tenant-scoped).
    async fn load_current_version(
        &self,
        tenant_id: &str,
        template_id: &str,
    ) -> Result<StoredTemplate, TemplateError> {
        let row: Option<CurrentTemplateRow> =
            sqlx::query_as::<_, CurrentTemplateRow>(LOAD_CURRENT_VERSION_SQL)
                .bind(template_id)
                .bind(tenant_id)
                .fetch_optional(&self.db)
                .await?;

        row.map(CurrentTemplateRow::into_stored)
            .ok_or_else(|| TemplateError::NotFound {
                id: template_id.to_string(),
            })
    }

    /// Load a historical version snapshot (tenant-scoped).
    async fn load_template_version(
        &self,
        tenant_id: &str,
        template_id: &str,
        version: i32,
    ) -> Result<StoredTemplate, TemplateError> {
        let row: Option<VersionSnapshotRow> =
            sqlx::query_as::<_, VersionSnapshotRow>(LOAD_TEMPLATE_VERSION_SQL)
                .bind(template_id)
                .bind(tenant_id)
                .bind(version)
                .fetch_optional(&self.db)
                .await?;

        row.map(VersionSnapshotRow::into_stored)
            .ok_or_else(|| TemplateError::NotFound {
                id: template_id.to_string(),
            })
    }

    /// Render an already-loaded stored template. Mirrors the canonical
    /// stored-render contract (api-server `POST /v1/templates/:id/render`):
    /// the stored `subject` supplies the subject line unless the caller
    /// overrides it, and an explicit `text_body` (merge-field resolved) wins
    /// over plaintext generated from the HTML. No DB access — unit-testable
    /// with a fake row.
    fn render_stored(
        &self,
        stored: &StoredTemplate,
        options: &RenderOptions,
    ) -> Result<RenderResult, TemplateError> {
        let mut effective = options.clone();
        if effective.subject.is_none() {
            effective.subject = Some(stored.subject.clone());
        }

        let mut result = self.render_source(&stored.html_body, &effective)?;

        if effective.generate_plaintext {
            if let Some(text) = stored.text_body.as_deref() {
                let outcome = transpiler::resolve_placeholders_plain_reported(
                    text,
                    &options.props,
                    options.missing_field_fallback.as_deref().unwrap_or(""),
                );
                result.plaintext = Some(outcome.html);
                result.warnings.extend(outcome.warnings);
            }
        }

        Ok(result)
    }
}

/// A stored template loaded for rendering: either the current `templates`
/// row or a `template_versions` snapshot. Internal render model shared by
/// both load paths (and by the fake-row unit tests).
struct StoredTemplate {
    template_id: String,
    tenant_id: String,
    version: i32,
    subject: String,
    html_body: String,
    text_body: Option<String>,
    /// `templates.updated_at` (current) or the snapshot's `created_at`
    /// (historical). Part of the cache key so any canonical write — which
    /// always moves one of `version`/`updated_at` — rotates it.
    content_stamp: DateTime<Utc>,
}

/// Build the render-cache key for a stored template.
///
/// #191: the props JSON is hashed for a stable key regardless of key
/// ordering. F62: the key must cover EVERYTHING that affects the output —
/// tenant (scope), template, the stored content's `version` AND content
/// stamp, props, subject, minify and plaintext generation. The version and
/// stamp tie invalidation to the canonical writer: the api-server bumps
/// `version` on every save and rewrites `updated_at`/snapshot `created_at`
/// on rollback, so a stale render is never served after a stored change.
fn stored_render_cache_key(stored: &StoredTemplate, options: &RenderOptions) -> String {
    // serde_json::Value Display can produce different strings for
    // logically-equal JSON; a content hash is order-stable.
    use sha2::{Digest, Sha256};
    let hash_short = |input: &str| -> String {
        let hash = Sha256::digest(input.as_bytes());
        hex::encode(&hash[..16]) // 128-bit hash is sufficient for cache keys
    };
    let props_hash = hash_short(&serde_json::to_string(&options.props).unwrap_or_default());
    format!(
        "{}:{}:{}:{}:{}:{}:{}:{}",
        stored.tenant_id,
        stored.template_id,
        stored.version,
        stored.content_stamp.timestamp_micros(),
        props_hash,
        options.minify as u8,
        options.generate_plaintext as u8,
        options
            .subject
            .as_deref()
            .map(hash_short)
            .unwrap_or_else(|| "-".to_string()),
    )
}

/// Internal DB row type for the canonical `templates` table (avoids orphan
/// rule issues with sqlx).
#[derive(sqlx::FromRow)]
struct CurrentTemplateRow {
    id: String,
    tenant_id: String,
    name: String,
    subject: String,
    html_body: String,
    text_body: Option<String>,
    version: i32,
    status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl CurrentTemplateRow {
    fn into_stored(self) -> StoredTemplate {
        StoredTemplate {
            template_id: self.id,
            tenant_id: self.tenant_id,
            version: self.version,
            subject: self.subject,
            html_body: self.html_body,
            text_body: self.text_body,
            content_stamp: self.updated_at,
        }
    }

    fn into_template(self) -> Template {
        Template {
            id: self.id,
            tenant_id: self.tenant_id,
            name: self.name,
            subject: self.subject,
            html_body: self.html_body,
            text_body: self.text_body,
            version: self.version,
            status: self.status,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

/// Internal DB row type for the canonical `template_versions` snapshots
/// (only the render-relevant columns are selected).
#[derive(sqlx::FromRow)]
struct VersionSnapshotRow {
    template_id: String,
    tenant_id: String,
    version: i32,
    subject: String,
    html_body: String,
    text_body: Option<String>,
    created_at: DateTime<Utc>,
}

impl VersionSnapshotRow {
    fn into_stored(self) -> StoredTemplate {
        StoredTemplate {
            template_id: self.template_id,
            tenant_id: self.tenant_id,
            version: self.version,
            subject: self.subject,
            html_body: self.html_body,
            text_body: self.text_body,
            // Snapshots are upserted with `created_at = NOW()` when the
            // canonical writer rewrites them (post-rollback re-save), so the
            // stamp moves on rewrite just like `updated_at` does on the
            // current row.
            content_stamp: self.created_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    fn test_config() -> RendererConfig {
        RendererConfig {
            db: DatabaseConfig {
                url: "postgres://localhost/test".to_string(),
                max_connections: 5,
            },
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 9080,
                request_timeout_secs: 30,
            },
            sandbox: SandboxConfig {
                timeout_ms: 5000,
                max_memory_bytes: 64 * 1024 * 1024,
                max_source_length: 512 * 1024,
                max_output_length: 2 * 1024 * 1024,
                trusted_html_props: Vec::new(),
            },
            cache: CacheConfig {
                max_entries: 100,
                ttl_secs: 60,
            },
        }
    }

    #[test]
    fn test_render_source_simple() {
        // We can't use PgPool in unit tests, but we can test the rendering pipeline
        // by testing the sandbox and transpiler directly
        let config = test_config();
        let sandbox = Sandbox::new(config.sandbox);
        let source = "<h1>{{ title }}</h1><p>{{ body }}</p>";
        let opts = RenderOptions {
            props: serde_json::json!({"title": "Hello", "body": "World"}),
            generate_plaintext: true,
            minify: false,
            subject: None,
            missing_field_fallback: None,
        };
        let result = sandbox.execute(source, &opts).unwrap();
        assert_eq!(result.html, "<h1>Hello</h1><p>World</p>");
    }

    #[test]
    fn test_render_with_subject() {
        let config = test_config();
        let sandbox = Sandbox::new(config.sandbox);
        let source = "<p>{{ message }}</p>";
        let opts = RenderOptions {
            props: serde_json::json!({"message": "Hi", "name": "Alice"}),
            generate_plaintext: false,
            minify: false,
            subject: Some("Hello {{ name }}!".to_string()),
            missing_field_fallback: None,
        };
        let result = sandbox.execute(source, &opts).unwrap();
        assert_eq!(result.html, "<p>Hi</p>");

        // Verify subject resolution (plain-text — no HTML escaping)
        let resolved_subject =
            transpiler::resolve_placeholders_plain("Hello {{ name }}!", &opts.props);
        assert_eq!(resolved_subject, "Hello Alice!");
    }

    /// Subject merge fields are header-bound: CR/LF/NUL coming from props
    /// (or the subject template itself) is a header-injection primitive and
    /// must never survive into the resolved subject. Bodies may legitimately
    /// contain newlines and are NOT touched.
    #[tokio::test]
    async fn render_source_subject_merge_fields_are_single_line() {
        let config = test_config();
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let renderer = TemplateRenderer::new(pool, config);
        let opts = RenderOptions {
            props: serde_json::json!({
                "name": "Bob\r\nBcc: x@evil.example",
                "body": "first line\nsecond line",
                "nul": "a\0b",
            }),
            generate_plaintext: false,
            minify: false,
            subject: Some("Hi {{ name }} | {{ nul }}".to_string()),
            missing_field_fallback: None,
        };

        let result = renderer.render_source("<p>{{ body }}</p>", &opts).unwrap();

        let subject = result.subject.expect("subject must be resolved");
        assert!(
            !subject.contains('\r') && !subject.contains('\n') && !subject.contains('\0'),
            "subject must be a single line, got: {subject:?}"
        );
        assert!(subject.starts_with("Hi Bob"), "got: {subject:?}");
        assert!(
            subject.contains("Bcc:"),
            "text itself may survive; only the line break must not"
        );

        // The body keeps its newline — only header-bound values are stripped.
        assert!(
            result.html.contains("first line\nsecond line"),
            "{}",
            result.html
        );
    }

    #[test]
    fn test_validate_valid() {
        let source = "<div><p>Hello</p></div>";
        let result = transpiler::validate_source(source, 512 * 1024);
        assert!(result.valid);
    }

    #[test]
    fn test_validate_invalid_import() {
        let source = r#"import child_process from 'child_process'; <div/>"#;
        let result = transpiler::validate_source(source, 512 * 1024);
        assert!(!result.valid);
    }

    #[test]
    fn test_starter_template() {
        let tmpl = STARTER_TEMPLATE;
        assert!(tmpl.contains("<html>"));
        assert!(tmpl.contains("{{ title }}"));
        assert!(tmpl.len() > 100);
    }

    // ── F62: stored rendering path against the canonical repository ──

    fn fake_stored_template(version: i32, subject: &str, html_body: &str) -> StoredTemplate {
        StoredTemplate {
            template_id: "tpl_f62_canonical000001".to_string(),
            tenant_id: "ten_f62_owner00000000001".to_string(),
            version,
            subject: subject.to_string(),
            html_body: html_body.to_string(),
            text_body: None,
            content_stamp: Utc::now(),
        }
    }

    fn stored_opts() -> RenderOptions {
        RenderOptions {
            props: serde_json::json!({"name": "Alice", "title": "Welcome"}),
            generate_plaintext: true,
            minify: false,
            subject: None,
            missing_field_fallback: None,
        }
    }

    fn stored_renderer() -> TemplateRenderer {
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        TemplateRenderer::new(pool, test_config())
    }

    /// Render-current-version: a canonical `templates` row (subject + HTML
    /// body columns, TEXT ids) renders through the sandbox pipeline, with
    /// the stored subject supplying the subject line.
    #[tokio::test]
    async fn stored_render_renders_current_version_from_canonical_row() {
        let renderer = stored_renderer();
        let stored = fake_stored_template(2, "Hello {{ name }}", "<h1>{{ title }}</h1>");

        let result = renderer.render_stored(&stored, &stored_opts()).unwrap();

        assert_eq!(result.html, "<h1>Welcome</h1>");
        assert_eq!(result.subject.as_deref(), Some("Hello Alice"));
        assert!(!result.metadata.cached, "fresh render must not be cached");
    }

    /// Render-historical-version: a `template_versions` snapshot renders its
    /// OWN content, not the current row's — v1 snapshot vs v2 current must
    /// produce correspondingly different output.
    #[tokio::test]
    async fn stored_render_renders_historical_snapshot_not_current() {
        let renderer = stored_renderer();

        let v1 = fake_stored_template(1, "Welcome v1", "<p>v1 {{ name }}</p>");
        let v2 = fake_stored_template(2, "Welcome v2", "<p>v2 {{ name }}</p>");

        let r1 = renderer.render_stored(&v1, &stored_opts()).unwrap();
        let r2 = renderer.render_stored(&v2, &stored_opts()).unwrap();

        assert_eq!(r1.html, "<p>v1 Alice</p>");
        assert_eq!(r1.subject.as_deref(), Some("Welcome v1"));
        assert_eq!(r2.html, "<p>v2 Alice</p>");
        assert_eq!(r2.subject.as_deref(), Some("Welcome v2"));
    }

    /// A stored template's explicit `text_body` wins over generated
    /// plaintext (same contract as the api-server stored render route).
    #[tokio::test]
    async fn stored_render_prefers_explicit_text_body() {
        let renderer = stored_renderer();
        let mut stored = fake_stored_template(1, "s", "<p>Hello {{ name }}</p>");
        stored.text_body = Some("plain hello {{ name }}".to_string());

        let result = renderer.render_stored(&stored, &stored_opts()).unwrap();

        assert_eq!(
            result.plaintext.as_deref(),
            Some("plain hello Alice"),
            "explicit text_body must be merge-field resolved and preferred"
        );
    }

    /// Reject-foreign-tenant, SQL side: both load queries must be scoped by
    /// `tenant_id` bound at $2 (with the id at $1), against the CANONICAL
    /// tables — never `email_templates` (absent from every migration) and
    /// never an unscoped lookup that would let one tenant read another's
    /// template.
    #[test]
    fn stored_load_queries_are_tenant_scoped_and_canonical() {
        for sql in [LOAD_CURRENT_VERSION_SQL, LOAD_TEMPLATE_VERSION_SQL] {
            assert!(!sql.to_lowercase().contains("email_templates"));
            assert!(!sql.to_lowercase().contains("::uuid"));
            assert!(
                sql.contains("tenant_id = $2"),
                "load query must scope by tenant_id at bind position 2: {sql}"
            );
            assert!(
                sql.contains("= $1") && sql.contains("= $2"),
                "id must be bound before tenant (positional order): {sql}"
            );
        }
        assert!(LOAD_CURRENT_VERSION_SQL.contains("FROM templates"));
        assert!(LOAD_TEMPLATE_VERSION_SQL.contains("FROM template_versions"));
        assert!(LOAD_TEMPLATE_VERSION_SQL.contains("version = $3"));
    }

    /// Reject-foreign-tenant, cache side: the cache key embeds the tenant,
    /// so even a key collision elsewhere can never serve tenant B a render
    /// cached for tenant A.
    #[test]
    fn stored_cache_keys_are_tenant_scoped() {
        let opts = stored_opts();
        let mine = fake_stored_template(2, "s", "<p>x</p>");
        let mut foreign = fake_stored_template(2, "s", "<p>x</p>");
        foreign.tenant_id = "ten_f62_other000000000001".to_string();

        assert_ne!(
            stored_render_cache_key(&mine, &opts),
            stored_render_cache_key(&foreign, &opts),
            "cache keys must differ across tenants"
        );
    }

    /// Cache invalidation tied to the canonical writer: the api-server bumps
    /// `version` on every save and moves `updated_at` (or the snapshot's
    /// `created_at`) on rollback — either change must rotate the cache key
    /// so a stale render is never served.
    #[test]
    fn stored_cache_key_rotates_on_version_bump_and_content_stamp() {
        let opts = stored_opts();
        let v1 = fake_stored_template(1, "s", "<p>x</p>");

        let v2 = fake_stored_template(2, "s", "<p>x</p>");
        assert_ne!(
            stored_render_cache_key(&v1, &opts),
            stored_render_cache_key(&v2, &opts),
            "a version bump must rotate the cache key"
        );

        let mut restamped = fake_stored_template(1, "s", "<p>x</p>");
        restamped.content_stamp = v1.content_stamp + chrono::Duration::seconds(1);
        assert_ne!(
            stored_render_cache_key(&v1, &opts),
            stored_render_cache_key(&restamped, &opts),
            "a content-stamp move (rollback/rewrite) must rotate the cache key"
        );
    }

    /// The props component of the key must still discriminate renders
    /// (#191 regression guard, now on the versioned key).
    #[test]
    fn stored_cache_key_discriminates_props() {
        let stored = fake_stored_template(3, "s", "<p>x</p>");
        let mut other_opts = stored_opts();
        other_opts.props = serde_json::json!({"name": "Bob", "title": "Bye"});

        assert_ne!(
            stored_render_cache_key(&stored, &stored_opts()),
            stored_render_cache_key(&stored, &other_opts)
        );
    }

    // ── F62: DB-backed tests (skipped without TEST_DATABASE_URL; same
    //    convention as the api-server template routes tests) ──

    /// Minimal canonical schema (migrations 075 + 107) in a dedicated
    /// per-test database.
    async fn stored_template_test_pool(db_suffix: &str) -> Option<sqlx::PgPool> {
        use sqlx::postgres::PgPoolOptions;
        use std::time::Duration;

        let database_url = std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())?;
        let (server_part, db_part) = database_url.rsplit_once('/')?;
        let db_only = db_part.split('?').next().unwrap_or(db_part);
        let isolated_db = format!("{db_only}_renderer_templates_{db_suffix}");
        let isolated_url = format!("{server_part}/{isolated_db}");
        let admin_url = format!("{server_part}/postgres");

        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(3))
            .connect(&admin_url)
            .await
            .ok()?;
        let _ = sqlx::query(&format!(
            r#"DROP DATABASE IF EXISTS "{isolated_db}" WITH (FORCE)"#
        ))
        .execute(&admin)
        .await;
        let created = sqlx::query(&format!(r#"CREATE DATABASE "{isolated_db}""#))
            .execute(&admin)
            .await;
        admin.close().await;
        created.ok()?;

        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&isolated_url)
            .await
            .ok()?;
        sqlx::query(
            r#"
            CREATE TABLE templates (
                id          VARCHAR(26) PRIMARY KEY,
                tenant_id   VARCHAR(26) NOT NULL,
                name        VARCHAR(255) NOT NULL,
                slug        VARCHAR(100),
                subject     VARCHAR(255) NOT NULL,
                html_body   TEXT NOT NULL,
                text_body   TEXT,
                version     INTEGER NOT NULL DEFAULT 1,
                status      VARCHAR(20) NOT NULL DEFAULT 'active',
                created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE TABLE template_versions (
                template_id VARCHAR(26)  NOT NULL,
                tenant_id   VARCHAR(26)  NOT NULL,
                version     INTEGER      NOT NULL,
                name        VARCHAR(255) NOT NULL,
                subject     VARCHAR(255) NOT NULL,
                html_body   TEXT         NOT NULL,
                text_body   TEXT,
                created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
                PRIMARY KEY (template_id, version)
            );
            "#,
        )
        .execute(&pool)
        .await
        .ok()?;
        Some(pool)
    }

    /// Seed a template for `tenant` at v2 with a v1 snapshot (mirrors the
    /// api-server create + update write pair).
    async fn seed_versioned_template(pool: &sqlx::PgPool, tenant_id: &str, template_id: &str) {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO templates (id, tenant_id, name, subject, html_body, version, status)
             VALUES ($1, $2, 'welcome', 'Welcome v2 {{ name }}', '<p>v2 {{ name }}</p>', 2, 'active')",
        )
        .bind(template_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .unwrap();
        for (version, subject, html) in [
            (1i32, "Welcome v1 {{ name }}", "<p>v1 {{ name }}</p>"),
            (2i32, "Welcome v2 {{ name }}", "<p>v2 {{ name }}</p>"),
        ] {
            sqlx::query(
                "INSERT INTO template_versions (template_id, tenant_id, version, name, subject, html_body)
                 VALUES ($1, $2, $3, 'welcome', $4, $5)",
            )
            .bind(template_id)
            .bind(tenant_id)
            .bind(version)
            .bind(subject)
            .bind(html)
            .execute(&mut *tx)
            .await
            .unwrap();
        }
        tx.commit().await.unwrap();
    }

    /// Full stored-path flow on the canonical schema: current version,
    /// historical version, foreign-tenant rejection, cache hit, and cache
    /// rotation after a canonical version bump.
    #[tokio::test]
    async fn stored_render_current_historical_and_tenant_rejection() {
        let Some(pool) = stored_template_test_pool("full").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };

        let renderer = TemplateRenderer::new(pool.clone(), test_config());
        let tenant = "ten_f62_db_owner0000001";
        let foreign_tenant = "ten_f62_db_other0000001";
        let template_id = apexmail_lib::id::generate_id("", 26);
        seed_versioned_template(&pool, tenant, &template_id).await;

        let opts = RenderOptions {
            props: serde_json::json!({"name": "Alice"}),
            generate_plaintext: true,
            minify: false,
            subject: None,
            missing_field_fallback: None,
        };

        // Current version (v2).
        let current = renderer
            .render_template(tenant, &template_id, None, &opts)
            .await
            .unwrap();
        assert_eq!(current.html, "<p>v2 Alice</p>");
        assert_eq!(current.subject.as_deref(), Some("Welcome v2 Alice"));
        assert!(!current.metadata.cached);

        // Historical version (v1 snapshot).
        let historical = renderer
            .render_template(tenant, &template_id, Some(1), &opts)
            .await
            .unwrap();
        assert_eq!(historical.html, "<p>v1 Alice</p>");
        assert_eq!(historical.subject.as_deref(), Some("Welcome v1 Alice"));

        // Foreign tenant: same template id, wrong tenant scope → NotFound.
        let err = renderer
            .render_template(foreign_tenant, &template_id, None, &opts)
            .await
            .unwrap_err();
        assert!(
            matches!(err, TemplateError::NotFound { .. }),
            "foreign tenant must get NotFound, got: {err:?}"
        );

        // Unknown historical version → NotFound.
        let err = renderer
            .render_template(tenant, &template_id, Some(99), &opts)
            .await
            .unwrap_err();
        assert!(matches!(err, TemplateError::NotFound { .. }));

        // Second identical render is served from cache.
        let again = renderer
            .render_template(tenant, &template_id, None, &opts)
            .await
            .unwrap();
        assert!(again.metadata.cached, "identical re-render must hit cache");
        assert_eq!(again.html, "<p>v2 Alice</p>");

        // Canonical version bump (what the api-server update does) rotates
        // the cache key: the next render serves fresh v3 content, not the
        // cached v2.
        sqlx::query(
            "UPDATE templates SET subject = 'Welcome v3 {{ name }}', html_body = '<p>v3 {{ name }}</p>', version = 3, updated_at = NOW()
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(&template_id)
        .bind(tenant)
        .execute(&pool)
        .await
        .unwrap();

        let bumped = renderer
            .render_template(tenant, &template_id, None, &opts)
            .await
            .unwrap();
        assert!(
            !bumped.metadata.cached,
            "version bump must invalidate cache"
        );
        assert_eq!(bumped.html, "<p>v3 Alice</p>");
        assert_eq!(bumped.subject.as_deref(), Some("Welcome v3 Alice"));

        pool.close().await;
    }

    /// save_template writes the canonical pair: a `templates` row AND its
    /// v1 snapshot, loadable back through the stored render path.
    #[tokio::test]
    async fn save_template_writes_canonical_tables_and_snapshot() {
        let Some(pool) = stored_template_test_pool("save").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };

        let renderer = TemplateRenderer::new(pool.clone(), test_config());
        let tenant = "ten_f62_db_saver0000001";

        let saved = renderer
            .save_template(
                tenant,
                "welcome",
                "Hello {{ name }}",
                "<h1>Hi {{ name }}</h1>",
                Some("text hi {{ name }}"),
            )
            .await
            .unwrap();

        assert_eq!(saved.version, 1);
        assert_eq!(saved.status, "active");
        assert_eq!(saved.tenant_id, tenant);
        assert_eq!(saved.id.len(), 26, "canonical templates.id is VARCHAR(26)");

        // v1 snapshot exists.
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM template_versions WHERE template_id = $1 AND tenant_id = $2",
        )
        .bind(&saved.id)
        .bind(tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 1, "save must snapshot v1 into template_versions");

        // Round-trip through the stored render path.
        let opts = RenderOptions {
            props: serde_json::json!({"name": "Alice"}),
            generate_plaintext: true,
            minify: false,
            subject: None,
            missing_field_fallback: None,
        };
        let rendered = renderer
            .render_template(tenant, &saved.id, None, &opts)
            .await
            .unwrap();
        assert_eq!(rendered.html, "<h1>Hi Alice</h1>");
        assert_eq!(rendered.subject.as_deref(), Some("Hello Alice"));
        assert_eq!(rendered.plaintext.as_deref(), Some("text hi Alice"));

        // Invalid HTML body is still rejected up front.
        let err = renderer
            .save_template(tenant, "bad", "s", "<p>ok</p><oops>", None)
            .await
            .unwrap_err();
        assert!(matches!(err, TemplateError::InvalidSyntax { .. }));

        pool.close().await;
    }
}
