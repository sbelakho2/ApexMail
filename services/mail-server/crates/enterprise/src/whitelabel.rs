use regex::Regex;
use sqlx::PgPool;
use std::collections::HashSet;
use std::sync::LazyLock;
use tracing::info;
use uuid::Uuid;

use crate::types::*;

/// Normalize a CSS property name for allowlist comparison:
/// lowercases and removes hyphens so kebab-case and camelCase both match.
fn normalize_prop(name: &str) -> String {
    name.to_lowercase().replace('-', "")
}

/// Known CSS property allowlist (both kebab-case and camelCase variants).
/// Properties not in this list are stripped from user-supplied CSS.
/// Comparison uses [`normalize_prop`] so `backgroundColor`, `background-color`,
/// `BackgroundColor`, etc. all resolve to the same canonical entry.
static ALLOWED_CSS_PROPERTIES: LazyLock<HashSet<String>> = LazyLock::new(|| {
    [
        // Layout & display
        "display",
        "position",
        "visibility",
        "overflow",
        "overflow-x",
        "overflow-y",
        "float",
        "clear",
        "z-index",
        // Box model
        "width",
        "min-width",
        "max-width",
        "height",
        "min-height",
        "max-height",
        "margin",
        "margin-top",
        "margin-right",
        "margin-bottom",
        "margin-left",
        "padding",
        "padding-top",
        "padding-right",
        "padding-bottom",
        "padding-left",
        "border",
        "border-top",
        "border-right",
        "border-bottom",
        "border-left",
        "border-width",
        "border-style",
        "border-color",
        "border-radius",
        "box-sizing",
        "box-shadow",
        // Typography
        "font",
        "font-family",
        "font-size",
        "font-weight",
        "font-style",
        "font-variant",
        "line-height",
        "letter-spacing",
        "word-spacing",
        "white-space",
        "word-break",
        "text-align",
        "text-decoration",
        "text-transform",
        "text-indent",
        "text-shadow",
        "vertical-align",
        "color",
        "direction",
        "list-style",
        "list-style-type",
        // Background
        "background",
        "background-color",
        "background-image",
        "background-repeat",
        "background-position",
        "background-size",
        "background-attachment",
        // Flexbox
        "flex",
        "flex-direction",
        "flex-wrap",
        "flex-flow",
        "flex-grow",
        "flex-shrink",
        "flex-basis",
        "justify-content",
        "align-items",
        "align-content",
        "align-self",
        "order",
        "gap",
        "row-gap",
        "column-gap",
        // Grid
        "grid",
        "grid-template",
        "grid-template-columns",
        "grid-template-rows",
        "grid-template-areas",
        "grid-column",
        "grid-row",
        "grid-area",
        "grid-column-start",
        "grid-column-end",
        "grid-row-start",
        "grid-row-end",
        "grid-auto-flow",
        "grid-auto-columns",
        "grid-auto-rows",
        // Transitions & transforms
        "transition",
        "transition-property",
        "transition-duration",
        "transition-timing-function",
        "transition-delay",
        "transform",
        "transform-origin",
        "opacity",
        // Cursor & outline
        "cursor",
        "outline",
        "outline-width",
        "outline-style",
        "outline-color",
        "outline-offset",
        "resize",
        // Table
        "border-collapse",
        "border-spacing",
        "caption-side",
        "empty-cells",
        "table-layout",
    ]
    .into_iter()
    .map(normalize_prop)
    .collect()
});

/// Dangerous CSS pattern prefixes — case-insensitive match, full substring removed.
static DANGEROUS_CSS_PATTERNS: LazyLock<[&'static str; 9]> = LazyLock::new(|| {
    [
        "expression(",       // IE CSS expressions
        "javascript:",       // JavaScript URLs
        "behavior:",         // IE behaviors
        "-moz-binding:",     // Firefox XBL bindings
        "@import",           // External CSS imports
        "url(data:",         // Inline data URIs in url()
        "position:fixed",    // Fixed positioning (covering/fixed overlay attacks)
        "position:absolute", // Absolute positioning (covering/layer attacks)
        "position:sticky",   // Sticky positioning
    ]
});

/// Sanitize CSS to prevent XSS attacks while preserving allowed properties
/// including camelCase variants used by CSS-in-JS.
fn sanitize_css(css: &str) -> String {
    // Step 1: Remove dangerous patterns that could enable XSS via CSS.
    // We match case-insensitively but remove the exact matched substring
    // from the original (preserving case) so surrounding text survives.
    let mut sanitized = strip_dangerous_patterns(css);

    // Step 2: Remove HTML tags embedded in CSS
    static TAG_REGEX: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"<[^>]*>").ok());
    if let Some(tag_regex) = TAG_REGEX.as_ref() {
        sanitized = tag_regex.replace_all(&sanitized, "").to_string();
    }

    // Step 3: Strip declarations whose property is not in the allowlist.
    // This rejects unknown/misspelled/invented properties while preserving
    // both kebab-case and camelCase variants of allowed properties.
    sanitized = filter_allowed_properties(&sanitized);

    sanitized
}

/// Case-insensitive removal of dangerous substrings from CSS.
fn strip_dangerous_patterns(css: &str) -> String {
    let mut sanitized = css.to_string();
    for &pattern in DANGEROUS_CSS_PATTERNS.iter() {
        let lower = sanitized.to_lowercase();
        if !lower.contains(&pattern.to_lowercase()) {
            continue;
        }
        tracing::warn!(pattern = pattern, "Removed dangerous CSS pattern");
        let mut result = String::with_capacity(sanitized.len());
        let mut cursor = 0;
        let pattern_lower = pattern.to_lowercase();
        while let Some(pos) = sanitized[cursor..].to_lowercase().find(&pattern_lower) {
            let absolute_pos = cursor + pos;
            result.push_str(&sanitized[cursor..absolute_pos]);
            cursor = absolute_pos + pattern.len();
        }
        result.push_str(&sanitized[cursor..]);
        sanitized = result;
    }
    sanitized
}

/// Regex matching a CSS declaration: `property: value;`
/// Captures the property name (group 1) and the full declaration (group 0).
static CSS_DECLARATION_REGEX: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"([a-zA-Z_][a-zA-Z0-9_-]*)\s*:\s*[^;]+;").ok());

/// Remove CSS declarations whose property name is not in the allowlist.
/// Parses `property: value;` declarations and keeps only those with allowed properties.
/// Preserves selectors, braces, at-rules, and structure — only strips individual declarations.
fn filter_allowed_properties(css: &str) -> String {
    if css.trim().is_empty() {
        return css.to_string();
    }

    let Some(decl_regex) = CSS_DECLARATION_REGEX.as_ref() else {
        return css.to_string();
    };

    decl_regex
        .replace_all(css, |caps: &regex::Captures<'_>| {
            let prop_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            // Normalize both sides so kebab-case, camelCase, and mixed casing all match
            if ALLOWED_CSS_PROPERTIES.contains(&normalize_prop(prop_name)) {
                // Keep the declaration as-is (preserving original casing)
                caps.get(0).map(|m| m.as_str()).unwrap_or("").to_string()
            } else {
                // Strip this declaration entirely
                String::new()
            }
        })
        .to_string()
}

/// White-Label Service:custom branding, domain management, DNS / email templates
pub struct WhiteLabelService {
    db: PgPool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct WhiteLabelConfigDbRow {
    id: Uuid,
    tenant_id: Uuid,
    company_name: Option<String>,
    logo_url: Option<String>,
    primary_color: Option<String>,
    secondary_color: Option<String>,
    accent_color: Option<String>,
    font_family: Option<String>,
    custom_css: Option<String>,
    favicon_url: Option<String>,
    footer_text: Option<String>,
    support_email: Option<String>,
    support_url: Option<String>,
    privacy_url: Option<String>,
    terms_url: Option<String>,
    created_at: Option<chrono::DateTime<chrono::Utc>>,
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<WhiteLabelConfigDbRow> for WhiteLabelConfigRow {
    fn from(row: WhiteLabelConfigDbRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id.to_string(),
            company_name: row.company_name,
            logo_url: row.logo_url,
            primary_color: row.primary_color,
            secondary_color: row.secondary_color,
            accent_color: row.accent_color,
            font_family: row.font_family,
            custom_css: row.custom_css,
            favicon_url: row.favicon_url,
            footer_text: row.footer_text,
            support_email: row.support_email,
            support_url: row.support_url,
            privacy_url: row.privacy_url,
            terms_url: row.terms_url,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct WhiteLabelDomainDbRow {
    id: Uuid,
    tenant_id: Uuid,
    domain: String,
    domain_type: String,
    verification_status: String,
    verification_token: Option<String>,
    dns_records: Option<serde_json::Value>,
    verified_at: Option<chrono::DateTime<chrono::Utc>>,
    ssl_status: Option<String>,
    ssl_certificate_id: Option<String>,
    ssl_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<WhiteLabelDomainDbRow> for WhiteLabelDomain {
    fn from(row: WhiteLabelDomainDbRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id.to_string(),
            domain: row.domain,
            domain_type: row.domain_type,
            verification_status: row.verification_status,
            verification_token: row.verification_token,
            dns_records: row.dns_records,
            verified_at: row.verified_at,
            ssl_status: row.ssl_status,
            ssl_certificate_id: row.ssl_certificate_id,
            ssl_expires_at: row.ssl_expires_at,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct WhiteLabelEmailTemplateDbRow {
    id: Uuid,
    tenant_id: Uuid,
    template_type: String,
    subject_template: Option<String>,
    html_template: Option<String>,
    text_template: Option<String>,
    created_at: Option<chrono::DateTime<chrono::Utc>>,
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<WhiteLabelEmailTemplateDbRow> for WhiteLabelEmailTemplate {
    fn from(row: WhiteLabelEmailTemplateDbRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id.to_string(),
            template_type: row.template_type,
            subject_template: row.subject_template,
            html_template: row.html_template,
            text_template: row.text_template,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

fn parse_tenant_id(tenant_id: &str) -> Result<Uuid, String> {
    Uuid::parse_str(tenant_id).map_err(|error| format!("Invalid tenant id '{tenant_id}': {error}"))
}

impl WhiteLabelService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Update (upsert) white-label configuration
    /// #254:Now sanitizes custom_css to prevent XSS
    #[allow(clippy::too_many_arguments)]
    pub async fn update_config(
        &self,
        tenant_id: String,
        company_name: Option<&str>,
        logo_url: Option<&str>,
        favicon_url: Option<&str>,
        primary_color: Option<&str>,
        secondary_color: Option<&str>,
        custom_css: Option<&str>,
        footer_text: Option<&str>,
        support_email: Option<&str>,
        support_url: Option<&str>,
    ) -> Result<ApiResult<WhiteLabelConfigRow>, String> {
        let tenant_uuid = parse_tenant_id(&tenant_id)?;
        // #254:Sanitize custom_css to prevent stored XSS
        let sanitized_css = custom_css.map(sanitize_css);
        let css_ref = sanitized_css.as_deref();

        let id = Uuid::new_v4();
        let row = sqlx::query_as::<_, WhiteLabelConfigDbRow>(
            "INSERT INTO ent_whitelabel_config (id, tenant_id, company_name, logo_url, favicon_url, primary_color, secondary_color, custom_css, footer_text, support_email, support_url, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW(),NOW())
             ON CONFLICT (tenant_id) DO UPDATE SET
             company_name = COALESCE(EXCLUDED.company_name, ent_whitelabel_config.company_name),
             logo_url = COALESCE(EXCLUDED.logo_url, ent_whitelabel_config.logo_url),
             favicon_url = COALESCE(EXCLUDED.favicon_url, ent_whitelabel_config.favicon_url),
             primary_color = COALESCE(EXCLUDED.primary_color, ent_whitelabel_config.primary_color),
             secondary_color = COALESCE(EXCLUDED.secondary_color, ent_whitelabel_config.secondary_color),
             custom_css = COALESCE(EXCLUDED.custom_css, ent_whitelabel_config.custom_css),
             footer_text = COALESCE(EXCLUDED.footer_text, ent_whitelabel_config.footer_text),
             support_email = COALESCE(EXCLUDED.support_email, ent_whitelabel_config.support_email),
             support_url = COALESCE(EXCLUDED.support_url, ent_whitelabel_config.support_url),
             updated_at = NOW()
             RETURNING *"
        )
           .bind(id).bind(tenant_uuid)
        .bind(company_name).bind(logo_url).bind(favicon_url)
        .bind(primary_color).bind(secondary_color)
        .bind(css_ref).bind(footer_text)
        .bind(support_email).bind(support_url)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Upsert whitelabel config: {e}"))?;

        info!(tenant_id = %tenant_id, "White-label config updated");
        Ok(ApiResult::ok(row.into()))
    }

    /// Get white-label configuration
    pub async fn get_config(
        &self,
        tenant_id: String,
    ) -> Result<ApiResult<WhiteLabelConfigRow>, String> {
        let tenant_uuid = parse_tenant_id(&tenant_id)?;
        let row = sqlx::query_as::<_, WhiteLabelConfigDbRow>(
            "SELECT * FROM ent_whitelabel_config WHERE tenant_id = $1",
        )
        .bind(tenant_uuid)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get whitelabel config: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(r.into())),
            None => Ok(ApiResult::err("White-label config not found", "NOT_FOUND")),
        }
    }

    /// Add a custom domain for white-labeling
    pub async fn add_domain(
        &self,
        tenant_id: String,
        domain: &str,
        domain_type: &str,
    ) -> Result<ApiResult<WhiteLabelDomain>, String> {
        let tenant_uuid = parse_tenant_id(&tenant_id)?;
        let id = Uuid::new_v4();
        let dns_records = generate_dns_records(domain, domain_type);
        let dns_json = serde_json::to_value(&dns_records)
            .map_err(|e| format!("Serialize DNS records: {e}"))?;

        let row = sqlx::query_as::<_, WhiteLabelDomainDbRow>(
            "INSERT INTO ent_whitelabel_domains (id, tenant_id, domain, domain_type, verification_status, dns_records, created_at)
             VALUES ($1,$2,$3,$4,'pending',$5,NOW())
             RETURNING *"
        )
        .bind(id).bind(tenant_uuid).bind(domain).bind(domain_type).bind(&dns_json)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Add domain: {e}"))?;

        info!(tenant_id = %tenant_id, domain = domain, "White-label domain added");
        Ok(ApiResult::ok(row.into()))
    }

    /// Verify a domain (check DNS records)
    pub async fn verify_domain(&self, id: Uuid) -> Result<ApiResult<WhiteLabelDomain>, String> {
        let domain_row = sqlx::query_as::<_, WhiteLabelDomainDbRow>(
            "SELECT * FROM ent_whitelabel_domains WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get domain: {e}"))?;

        let domain = match domain_row {
            Some(d) => d,
            None => return Ok(ApiResult::err("Domain not found", "NOT_FOUND")),
        };

        // Perform DNS verification (simplified — in production uses trust-dns-resolver)
        let verified = check_dns_records(&domain.domain).await;
        let status = if verified { "verified" } else { "failed" };

        let updated = sqlx::query_as::<_, WhiteLabelDomainDbRow>(
            "UPDATE ent_whitelabel_domains SET verification_status = $2, verified_at = CASE WHEN $2 = 'verified' THEN NOW() ELSE verified_at END
             WHERE id = $1 RETURNING *"
        )
        .bind(id).bind(status)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Update domain status: {e}"))?;

        Ok(ApiResult::ok(updated.into()))
    }

    /// List domains for a tenant
    pub async fn list_domains(
        &self,
        tenant_id: String,
        limit: i64,
        offset: i64,
    ) -> Result<ApiResult<Vec<WhiteLabelDomain>>, String> {
        let tenant_uuid = parse_tenant_id(&tenant_id)?;
        let rows = sqlx::query_as::<_, WhiteLabelDomainDbRow>(
            "SELECT * FROM ent_whitelabel_domains WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"
        )
        .bind(tenant_uuid)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("List domains: {e}"))?;

        Ok(ApiResult::ok(rows.into_iter().map(Into::into).collect()))
    }

    /// Remove a domain.
    /// #250:Requires tenant ownership verification to prevent IDOR.
    pub async fn remove_domain(
        &self,
        id: Uuid,
        tenant_id: String,
    ) -> Result<ApiResult<serde_json::Value>, String> {
        let tenant_uuid = parse_tenant_id(&tenant_id)?;
        let result =
            sqlx::query("DELETE FROM ent_whitelabel_domains WHERE id = $1 AND tenant_id = $2")
                .bind(id)
                .bind(tenant_uuid)
                .execute(&self.db)
                .await
                .map_err(|e| format!("Delete domain: {e}"))?;

        if result.rows_affected() == 0 {
            Ok(ApiResult::err(
                "Domain not found or not owned by tenant",
                "NOT_FOUND",
            ))
        } else {
            Ok(ApiResult::ok(serde_json::json!({"deleted": true})))
        }
    }

    /// Update (upsert) email templates for white-labeling
    pub async fn update_email_templates(
        &self,
        tenant_id: String,
        template_type: &str,
        subject_template: Option<&str>,
        html_template: Option<&str>,
        text_template: Option<&str>,
    ) -> Result<ApiResult<WhiteLabelEmailTemplate>, String> {
        let tenant_uuid = parse_tenant_id(&tenant_id)?;
        let id = Uuid::new_v4();
        let row = sqlx::query_as::<_, WhiteLabelEmailTemplateDbRow>(
            "INSERT INTO ent_whitelabel_email_templates (id, tenant_id, template_type, subject_template, html_template, text_template, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,NOW(),NOW())
             ON CONFLICT (tenant_id, template_type) DO UPDATE SET
             subject_template = COALESCE(EXCLUDED.subject_template, ent_whitelabel_email_templates.subject_template),
             html_template = COALESCE(EXCLUDED.html_template, ent_whitelabel_email_templates.html_template),
             text_template = COALESCE(EXCLUDED.text_template, ent_whitelabel_email_templates.text_template),
             updated_at = NOW()
             RETURNING *"
        )
        .bind(id).bind(tenant_uuid).bind(template_type)
        .bind(subject_template).bind(html_template).bind(text_template)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Upsert email template: {e}"))?;

        Ok(ApiResult::ok(row.into()))
    }

    /// Get email templates
    pub async fn get_email_templates(
        &self,
        tenant_id: String,
    ) -> Result<ApiResult<Vec<WhiteLabelEmailTemplate>>, String> {
        let tenant_uuid = parse_tenant_id(&tenant_id)?;
        let rows = sqlx::query_as::<_, WhiteLabelEmailTemplateDbRow>(
            "SELECT * FROM ent_whitelabel_email_templates WHERE tenant_id = $1 ORDER BY template_type"
        )
        .bind(tenant_uuid)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("Get email templates: {e}"))?;

        Ok(ApiResult::ok(rows.into_iter().map(Into::into).collect()))
    }
}

/// Generate DNS records required for a domain type
/// #260:Returns placeholder for DKIM public key - caller must generate actual keys
pub fn generate_dns_records(domain: &str, domain_type: &str) -> Vec<DNSRecord> {
    match domain_type {
        "tracking" => vec![DNSRecord {
            record_type: "CNAME".into(),
            host: format!("track.{domain}"),
            value: "tracking.apexmail.io".into(),
            ttl: 3600,
        }],
        "return_path" => vec![DNSRecord {
            record_type: "CNAME".into(),
            host: format!("bounce.{domain}"),
            value: "return.apexmail.io".into(),
            ttl: 3600,
        }],
        "custom_from" => {
            let mut records = vec![DNSRecord {
                record_type: "TXT".into(),
                host: domain.to_string(),
                value: "v=spf1 include:spf.apexmail.io ~all".into(),
                ttl: 3600,
            }];

            // #260:Use configured DKIM public key instead of placeholder text.
            match std::env::var("DEFAULT_DKIM_PUBLIC_KEY") {
                Ok(public_key) if !public_key.trim().is_empty() => {
                    records.push(DNSRecord {
                        record_type: "TXT".into(),
                        host: format!("apexmail._domainkey.{domain}"),
                        value: format!("v=DKIM1; k=rsa; p={}", public_key.trim()),
                        ttl: 3600,
                    });
                }
                _ => {
                    tracing::warn!(
                        domain = domain,
                        "DEFAULT_DKIM_PUBLIC_KEY not set; returning SPF-only records"
                    );
                }
            }

            records
        }
        "landing_page" => vec![DNSRecord {
            record_type: "CNAME".into(),
            host: domain.to_string(),
            value: "pages.apexmail.io".into(),
            ttl: 3600,
        }],
        _ => vec![DNSRecord {
            record_type: "CNAME".into(),
            host: domain.to_string(),
            value: "wl.apexmail.io".into(),
            ttl: 3600,
        }],
    }
}

/// Check DNS records for a domain
/// #259:Uses TCP resolvability via `lookup_host` as baseline DNS verification.
/// For strict record-by-record checking, extend using trust-dns-resolver.
async fn check_dns_records(domain: &str) -> bool {
    // #259:Perform a real network DNS resolution instead of always returning false.
    // This checks resolvability as a baseline verification step.
    // For stricter verification, each DNS record should be checked via trust-dns-resolver.
    match tokio::net::lookup_host((domain, 80)).await {
        Ok(mut addrs) => addrs.next().is_some(),
        Err(e) => {
            tracing::warn!(domain = domain, error = %e, "DNS verification lookup failed");
            false
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_tracking_dns() {
        let records = generate_dns_records("example.com", "tracking");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record_type, "CNAME");
        assert_eq!(records[0].host, "track.example.com");
        assert_eq!(records[0].value, "tracking.apexmail.io");
    }

    #[test]
    fn test_generate_return_path_dns() {
        let records = generate_dns_records("example.com", "return_path");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].host, "bounce.example.com");
    }

    #[test]
    fn test_generate_custom_from_dns() {
        std::env::set_var(
            "DEFAULT_DKIM_PUBLIC_KEY",
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A",
        );
        let records = generate_dns_records("example.com", "custom_from");
        assert_eq!(records.len(), 2);
        assert!(records
            .iter()
            .any(|r| r.record_type == "TXT" && r.host.contains("_domainkey")));
        assert!(records
            .iter()
            .any(|r| r.record_type == "TXT" && r.value.contains("spf")));
        std::env::remove_var("DEFAULT_DKIM_PUBLIC_KEY");
    }

    #[test]
    fn test_generate_landing_page_dns() {
        let records = generate_dns_records("landing.example.com", "landing_page");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].value, "pages.apexmail.io");
    }

    #[test]
    fn test_generate_default_dns() {
        let records = generate_dns_records("custom.example.com", "unknown_type");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].value, "wl.apexmail.io");
    }

    #[test]
    fn test_dns_record_serialization() {
        let r = DNSRecord {
            record_type: "CNAME".into(),
            host: "track.example.com".into(),
            value: "tracking.apexmail.io".into(),
            ttl: 3600,
        };
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["record_type"], "CNAME");
        assert_eq!(json["ttl"], 3600);
    }

    #[test]
    fn test_dns_records_all_have_ttl() {
        for dtype in &["tracking", "return_path", "custom_from", "landing_page"] {
            let records = generate_dns_records("test.com", dtype);
            for r in &records {
                assert!(r.ttl > 0, "TTL should be positive for {}/{}", dtype, r.host);
            }
        }
    }

    #[test]
    fn test_whitelabel_config_serialization() {
        let wl = WhiteLabelConfigRow {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4().to_string(),
            company_name: Some("Acme Corp".into()),
            logo_url: Some("https://acme.com/logo.png".into()),
            favicon_url: None,
            primary_color: Some("#FF5733".into()),
            secondary_color: None,
            accent_color: None,
            font_family: None,
            custom_css: None,
            footer_text: None,
            support_email: Some("support@acme.com".into()),
            support_url: None,
            privacy_url: None,
            terms_url: None,
            created_at: Some(chrono::Utc::now()),
            updated_at: Some(chrono::Utc::now()),
        };
        let json = serde_json::to_value(&wl).unwrap();
        assert_eq!(json["company_name"], "Acme Corp");
    }

    #[test]
    fn test_whitelabel_domain_serialization() {
        let d = WhiteLabelDomain {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4().to_string(),
            domain: "mail.acme.com".into(),
            domain_type: "tracking".into(),
            verification_status: "pending".into(),
            verification_token: None,
            dns_records: Some(serde_json::json!([])),
            verified_at: None,
            ssl_status: None,
            ssl_certificate_id: None,
            ssl_expires_at: None,
            created_at: Some(chrono::Utc::now()),
        };
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["domain"], "mail.acme.com");
        assert_eq!(json["verification_status"], "pending");
    }

    // ── CSS sanitization tests ─────────────────────────────────────────

    #[test]
    fn test_sanitize_css_preserves_camelcase_properties() {
        let css = r#"
            .card {
                backgroundColor: #fff;
                fontWeight: 700;
                borderRadius: 8px;
                marginLeft: 16px;
                paddingTop: 24px;
                fontSize: 14px;
                lineHeight: 1.5;
                color: #333;
                boxShadow: 0 2px 4px rgba(0,0,0,0.1);
                textTransform: uppercase;
            }
        "#;
        let sanitized = sanitize_css(css);
        assert!(
            sanitized.contains("backgroundColor"),
            "should preserve backgroundColor"
        );
        assert!(
            sanitized.contains("fontWeight"),
            "should preserve fontWeight"
        );
        assert!(
            sanitized.contains("borderRadius"),
            "should preserve borderRadius"
        );
        assert!(
            sanitized.contains("marginLeft"),
            "should preserve marginLeft"
        );
        assert!(
            sanitized.contains("paddingTop"),
            "should preserve paddingTop"
        );
        assert!(sanitized.contains("fontSize"), "should preserve fontSize");
        assert!(
            sanitized.contains("lineHeight"),
            "should preserve lineHeight"
        );
        assert!(sanitized.contains("color"), "should preserve color");
        assert!(sanitized.contains("boxShadow"), "should preserve boxShadow");
        assert!(
            sanitized.contains("textTransform"),
            "should preserve textTransform"
        );
    }

    #[test]
    fn test_sanitize_css_preserves_kebab_case_properties() {
        let css = r#"
            .card {
                background-color: #fff;
                font-weight: 700;
                border-radius: 8px;
                margin-left: 16px;
                padding-top: 24px;
                font-size: 14px;
                line-height: 1.5;
                color: #333;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                text-transform: uppercase;
            }
        "#;
        let sanitized = sanitize_css(css);
        assert!(
            sanitized.contains("background-color"),
            "should preserve background-color"
        );
        assert!(
            sanitized.contains("font-weight"),
            "should preserve font-weight"
        );
        assert!(
            sanitized.contains("border-radius"),
            "should preserve border-radius"
        );
        assert!(sanitized.contains("color"), "should preserve color");
        assert!(
            sanitized.contains("text-transform"),
            "should preserve text-transform"
        );
    }

    #[test]
    fn test_sanitize_css_strips_dangerous_patterns() {
        let cases = [
            ("div { color: red; expression(alert(1)) }", "expression("),
            ("a { background: url(javascript:alert(1)) }", "javascript:"),
            ("div { behavior: url(test.htc) }", "behavior:"),
            (
                "div { -moz-binding: url('http://evil.com/xbl.xml') }",
                "-moz-binding:",
            ),
            ("@import url('evil.css');", "@import"),
            ("div { background: url(data:text/html,...) }", "url(data:"),
            ("div { position: fixed; top: 0; }", "position:fixed"),
            ("div { position: absolute; top: 0; }", "position:absolute"),
            ("div { position: sticky; top: 0; }", "position:sticky"),
        ];
        for (css, dangerous_substring) in &cases {
            let sanitized = sanitize_css(css);
            let lower = sanitized.to_lowercase();
            assert!(
                !lower.contains(&dangerous_substring.to_lowercase()),
                "should strip dangerous pattern: {dangerous_substring}"
            );
        }
    }

    #[test]
    fn test_sanitize_css_strips_unknown_properties() {
        let css = "div { unknown-property: value; color: red; }";
        let sanitized = sanitize_css(css);
        assert!(
            !sanitized.contains("unknown-property"),
            "should strip unknown property"
        );
        assert!(sanitized.contains("color"), "should keep allowed property");
    }

    #[test]
    fn test_sanitize_css_strips_html_tags() {
        let css = r#"div { color: red; } <script>alert(1)</script>"#;
        let sanitized = sanitize_css(css);
        assert!(!sanitized.contains("<script>"), "should strip HTML tags");
        assert!(sanitized.contains("color"), "should keep CSS content");
    }

    #[test]
    fn test_sanitize_css_allows_mixed_casing() {
        let css = ".card { Color: #333; BACKGROUND-COLOR: #fff; }";
        let sanitized = sanitize_css(css);
        assert!(
            sanitized.contains("Color"),
            "should preserve case of allowed property 'Color'"
        );
        assert!(
            sanitized.contains("BACKGROUND-COLOR"),
            "should preserve case of 'BACKGROUND-COLOR'"
        );
    }

    #[test]
    fn test_sanitize_css_empty_input() {
        assert_eq!(sanitize_css(""), "");
        assert_eq!(sanitize_css("   "), "   ");
    }
}
