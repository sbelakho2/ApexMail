//! Full template rendering pipeline:transpile → sandbox → render → plaintext.

use std::time::Instant;

use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::cache::TemplateCache;
use crate::config::RendererConfig;
use crate::plaintext::html_to_plaintext;
use crate::sandbox::Sandbox;
use crate::transpiler;
use crate::types::{
    RenderMetadata, RenderOptions, RenderResult, Template, TemplateError, ValidationResult,
    STARTER_TEMPLATE,
};

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

    /// Render a stored template by ID, using cache when available.
    pub async fn render_template(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        options: &RenderOptions,
    ) -> Result<RenderResult, TemplateError> {
        // #191:Hash the props JSON for a stable cache key regardless of key ordering.
        // serde_json::Value Display can produce different strings for logically-equal JSON.
        use sha2::{Digest, Sha256};
        let hash_short = |input: &str| -> String {
            let hash = Sha256::digest(input.as_bytes());
            hex::encode(&hash[..16]) // 128-bit hash is sufficient for cache keys
        };
        let props_hash = hash_short(&serde_json::to_string(&options.props).unwrap_or_default());
        // The cache key must cover EVERYTHING that affects the output:
        // tenant (scope), template, props, subject, minify and plaintext
        // generation. A key missing any of these serves one tenant another
        // tenant's render or returns output with the wrong options.
        let cache_key = format!(
            "{}:{}:{}:{}:{}:{}",
            tenant_id,
            template_id,
            props_hash,
            options.minify as u8,
            options.generate_plaintext as u8,
            options
                .subject
                .as_deref()
                .map(hash_short)
                .unwrap_or_else(|| "-".to_string()),
        );

        // Check cache
        if let Some(cached) = self.cache.get(&cache_key) {
            info!(template_id = %template_id, "Cache hit");
            return Ok(RenderResult {
                metadata: RenderMetadata {
                    cached: true,
                    ..cached.metadata
                },
                ..cached
            });
        }

        // Load template from DB
        let template = self.load_template(tenant_id, template_id).await?;

        // Render
        let result = self.render_source(&template.source, options)?;

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

    /// Store a template in the database.
    pub async fn save_template(
        &self,
        tenant_id: Uuid,
        name: &str,
        source: &str,
    ) -> Result<Template, TemplateError> {
        // Validate first
        let validation = self.validate(source);
        if !validation.valid {
            let msg = validation
                .errors
                .iter()
                .map(|e| e.message.clone())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(TemplateError::InvalidSyntax { message: msg });
        }

        let id = Uuid::new_v4();
        let now = chrono::Utc::now();

        let row: TemplateRow = sqlx::query_as::<_, TemplateRow>(
            r#"
            INSERT INTO email_templates (id, tenant_id, name, source, version, created_at, updated_at)
            VALUES ($1, $2, $3, $4, 1, $5, $5)
            RETURNING id, tenant_id, name, source, version, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(name)
        .bind(source)
        .bind(now)
        .fetch_one(&self.db)
        .await?;

        Ok(row.into_template())
    }

    /// Load a template from DB.
    async fn load_template(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<Template, TemplateError> {
        let row: Option<TemplateRow> = sqlx::query_as::<_, TemplateRow>(
            r#"
            SELECT id, tenant_id, name, source, version, created_at, updated_at
            FROM email_templates
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(template_id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await?;

        match row {
            Some(r) => Ok(r.into_template()),
            None => Err(TemplateError::NotFound {
                id: template_id.to_string(),
            }),
        }
    }
}

/// Internal DB row type (avoids orphan rule issues with sqlx).
#[derive(sqlx::FromRow)]
struct TemplateRow {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    source: String,
    version: i32,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl TemplateRow {
    fn into_template(self) -> Template {
        Template {
            id: self.id,
            tenant_id: self.tenant_id,
            name: self.name,
            source: self.source,
            version: self.version,
            compiled: None,
            created_at: self.created_at,
            updated_at: self.updated_at,
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
}
