//! Full template rendering pipeline: transpile → sandbox → render → plaintext.

use std::sync::Arc;
use std::time::Instant;

use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

use crate::cache::TemplateCache;
use crate::config::RendererConfig;
use crate::plaintext::html_to_plaintext;
use crate::sandbox::Sandbox;
use crate::transpiler;
use crate::types::{
    RenderMetadata, RenderOptions, RenderResult, Template, TemplateError,
    ValidationResult, STARTER_TEMPLATE,
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

        // Resolve subject placeholders
        let subject = options
            .subject
            .as_ref()
            .map(|s| transpiler::resolve_placeholders(s, &options.props));

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
        })
    }

    /// Render a stored template by ID, using cache when available.
    pub async fn render_template(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        options: &RenderOptions,
    ) -> Result<RenderResult, TemplateError> {
        let cache_key = format!("{}:{}", template_id, options.props);

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
        };
        let result = sandbox.execute(source, &opts).unwrap();
        assert_eq!(result.html, "<p>Hi</p>");

        // Verify subject resolution
        let resolved_subject =
            transpiler::resolve_placeholders("Hello {{ name }}!", &opts.props);
        assert_eq!(resolved_subject, "Hello Alice!");
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
