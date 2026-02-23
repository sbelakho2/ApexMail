use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::types::*;

/// White-Label Service: custom branding, domain management, DNS / email templates
pub struct WhiteLabelService {
    db: PgPool,
}

impl WhiteLabelService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Update (upsert) white-label configuration
    pub async fn update_config(
        &self, tenant_id: Uuid, company_name: Option<&str>,
        logo_url: Option<&str>, favicon_url: Option<&str>,
        primary_color: Option<&str>, secondary_color: Option<&str>,
        custom_css: Option<&str>, footer_text: Option<&str>,
        support_email: Option<&str>, support_url: Option<&str>,
    ) -> Result<ApiResult<WhiteLabelConfigRow>, String> {
        let id = Uuid::new_v4();
        let row = sqlx::query_as::<_, WhiteLabelConfigRow>(
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
        .bind(id).bind(tenant_id)
        .bind(company_name).bind(logo_url).bind(favicon_url)
        .bind(primary_color).bind(secondary_color)
        .bind(custom_css).bind(footer_text)
        .bind(support_email).bind(support_url)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Upsert whitelabel config: {e}"))?;

        info!(tenant_id = %tenant_id, "White-label config updated");
        Ok(ApiResult::ok(row))
    }

    /// Get white-label configuration
    pub async fn get_config(&self, tenant_id: Uuid) -> Result<ApiResult<WhiteLabelConfigRow>, String> {
        let row = sqlx::query_as::<_, WhiteLabelConfigRow>(
            "SELECT * FROM ent_whitelabel_config WHERE tenant_id = $1"
        )
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get whitelabel config: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(r)),
            None => Ok(ApiResult::err("White-label config not found", "NOT_FOUND")),
        }
    }

    /// Add a custom domain for white-labeling
    pub async fn add_domain(
        &self, tenant_id: Uuid, domain: &str, domain_type: &str,
    ) -> Result<ApiResult<WhiteLabelDomain>, String> {
        let id = Uuid::new_v4();
        let dns_records = generate_dns_records(domain, domain_type);
        let dns_json = serde_json::to_value(&dns_records).unwrap_or_default();

        let row = sqlx::query_as::<_, WhiteLabelDomain>(
            "INSERT INTO ent_whitelabel_domains (id, tenant_id, domain, domain_type, verification_status, dns_records, created_at)
             VALUES ($1,$2,$3,$4,'pending',$5,NOW())
             RETURNING *"
        )
        .bind(id).bind(tenant_id).bind(domain).bind(domain_type).bind(&dns_json)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Add domain: {e}"))?;

        info!(tenant_id = %tenant_id, domain = domain, "White-label domain added");
        Ok(ApiResult::ok(row))
    }

    /// Verify a domain (check DNS records)
    pub async fn verify_domain(&self, id: Uuid) -> Result<ApiResult<WhiteLabelDomain>, String> {
        let domain_row = sqlx::query_as::<_, WhiteLabelDomain>(
            "SELECT * FROM ent_whitelabel_domains WHERE id = $1"
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

        let updated = sqlx::query_as::<_, WhiteLabelDomain>(
            "UPDATE ent_whitelabel_domains SET verification_status = $2, verified_at = CASE WHEN $2 = 'verified' THEN NOW() ELSE verified_at END
             WHERE id = $1 RETURNING *"
        )
        .bind(id).bind(status)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Update domain status: {e}"))?;

        Ok(ApiResult::ok(updated))
    }

    /// List domains for a tenant
    pub async fn list_domains(&self, tenant_id: Uuid) -> Result<ApiResult<Vec<WhiteLabelDomain>>, String> {
        let rows = sqlx::query_as::<_, WhiteLabelDomain>(
            "SELECT * FROM ent_whitelabel_domains WHERE tenant_id = $1 ORDER BY created_at DESC"
        )
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("List domains: {e}"))?;

        Ok(ApiResult::ok(rows))
    }

    /// Remove a domain
    pub async fn remove_domain(&self, id: Uuid) -> Result<ApiResult<serde_json::Value>, String> {
        let result = sqlx::query("DELETE FROM ent_whitelabel_domains WHERE id = $1")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(|e| format!("Delete domain: {e}"))?;

        if result.rows_affected() == 0 {
            Ok(ApiResult::err("Domain not found", "NOT_FOUND"))
        } else {
            Ok(ApiResult::ok(serde_json::json!({"deleted": true})))
        }
    }

    /// Update (upsert) email templates for white-labeling
    pub async fn update_email_templates(
        &self, tenant_id: Uuid, template_type: &str,
        subject_template: Option<&str>, html_template: Option<&str>,
        text_template: Option<&str>,
    ) -> Result<ApiResult<WhiteLabelEmailTemplate>, String> {
        let id = Uuid::new_v4();
        let row = sqlx::query_as::<_, WhiteLabelEmailTemplate>(
            "INSERT INTO ent_whitelabel_email_templates (id, tenant_id, template_type, subject_template, html_template, text_template, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,NOW(),NOW())
             ON CONFLICT (tenant_id, template_type) DO UPDATE SET
             subject_template = COALESCE(EXCLUDED.subject_template, ent_whitelabel_email_templates.subject_template),
             html_template = COALESCE(EXCLUDED.html_template, ent_whitelabel_email_templates.html_template),
             text_template = COALESCE(EXCLUDED.text_template, ent_whitelabel_email_templates.text_template),
             updated_at = NOW()
             RETURNING *"
        )
        .bind(id).bind(tenant_id).bind(template_type)
        .bind(subject_template).bind(html_template).bind(text_template)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Upsert email template: {e}"))?;

        Ok(ApiResult::ok(row))
    }

    /// Get email templates
    pub async fn get_email_templates(
        &self, tenant_id: Uuid,
    ) -> Result<ApiResult<Vec<WhiteLabelEmailTemplate>>, String> {
        let rows = sqlx::query_as::<_, WhiteLabelEmailTemplate>(
            "SELECT * FROM ent_whitelabel_email_templates WHERE tenant_id = $1 ORDER BY template_type"
        )
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("Get email templates: {e}"))?;

        Ok(ApiResult::ok(rows))
    }
}

/// Generate DNS records required for a domain type
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
        "custom_from" => vec![
            DNSRecord {
                record_type: "TXT".into(),
                host: format!("apexmail._domainkey.{domain}"),
                value: "v=DKIM1; k=rsa; p=<generated_public_key>".into(),
                ttl: 3600,
            },
            DNSRecord {
                record_type: "TXT".into(),
                host: domain.to_string(),
                value: "v=spf1 include:spf.apexmail.io ~all".into(),
                ttl: 3600,
            },
        ],
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

/// Check DNS records for a domain (simplified — returns false in test/offline)
async fn check_dns_records(_domain: &str) -> bool {
    false
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
        let records = generate_dns_records("example.com", "custom_from");
        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|r| r.record_type == "TXT" && r.host.contains("_domainkey")));
        assert!(records.iter().any(|r| r.record_type == "TXT" && r.value.contains("spf")));
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
            tenant_id: Uuid::new_v4(),
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
            tenant_id: Uuid::new_v4(),
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
}
