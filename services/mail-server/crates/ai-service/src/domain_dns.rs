//! Authoritative tenant-scoped sender-DNS record lookup.
//!
//! This module deliberately reads the same domain key material used by the
//! sender control plane. It never derives a generic selector or returns a
//! shared vendor CNAME, and it never returns private key material.

use apexmail_lib::{dkim::dkim_txt_record_value, transport::email_transport_is_ses};
use serde::Serialize;
use sqlx::{postgres::PgPoolOptions, FromRow, PgPool};
use std::time::Duration;

use crate::types::AiError;

const RETURN_PATH_LABEL: &str = "bounce";
const SES_RETURN_PATH_MX_PRIORITY: u16 = 10;
const SES_SPF_RECORD: &str = "v=spf1 include:amazonses.com ~all";
const DMARC_RECORD: &str = "v=DMARC1; p=quarantine; rua=mailto:dmarc@apexmail.io";

#[derive(Clone)]
pub struct DomainDnsStore {
    pool: PgPool,
    aws_region: String,
    ses_transport: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DnsRecord {
    pub record_type: String,
    pub hostname: String,
    pub value: String,
    pub priority: Option<u16>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainDnsRecords {
    pub domain: String,
    pub status: String,
    pub records: Vec<DnsRecord>,
    pub transport: String,
}

#[derive(FromRow)]
struct DomainDnsRow {
    name: String,
    status: String,
    dkim_selector: Option<String>,
    dkim_public_key: Option<String>,
    dkim_private_key: Option<String>,
    dkim_enabled: bool,
}

impl DomainDnsStore {
    /// The connection is intentionally lazy: inference can start without a
    /// database, while an attempted domain lookup reports an actionable error
    /// if its database is unavailable.
    pub fn new(
        database_url: &str,
        aws_region: impl Into<String>,
        email_transport: Option<&str>,
    ) -> Result<Self, String> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(Duration::from_secs(5))
            .connect_lazy(database_url)
            .map_err(|error| format!("invalid AI domain database URL: {error}"))?;
        Ok(Self {
            pool,
            aws_region: aws_region.into(),
            ses_transport: email_transport_is_ses(email_transport),
        })
    }

    /// Fetch current DNS setup instructions for a domain owned by `tenant_id`.
    /// The SQL predicate is tenant scoped, so a caller cannot read a different
    /// tenant's selector or public key by guessing a domain name.
    pub async fn records_for_domain(
        &self,
        tenant_id: &str,
        requested_domain: &str,
    ) -> Result<DomainDnsRecords, AiError> {
        let domain = normalize_domain(requested_domain)?;
        if tenant_id.trim().is_empty() {
            return Err(AiError::InvalidInput(
                "an authenticated tenant identity is required for DNS records".into(),
            ));
        }

        let query = sqlx::query_as::<_, DomainDnsRow>(
            "SELECT name, status, dkim_selector, dkim_public_key, dkim_private_key, dkim_enabled
             FROM domains
             WHERE tenant_id::text = $1 AND lower(name) = $2",
        )
        .bind(tenant_id.trim())
        .bind(&domain)
        .fetch_optional(&self.pool);

        let row = tokio::time::timeout(Duration::from_secs(5), query)
            .await
            .map_err(|_| AiError::ModelUnavailable("domain-record lookup timed out".into()))?
            .map_err(|error| {
                AiError::ModelUnavailable(format!("domain-record lookup failed: {error}"))
            })?
            .ok_or_else(|| AiError::ModelNotFound("domain not found for authenticated tenant".into()))?;

        let selector = row
            .dkim_selector
            .as_deref()
            .filter(|value| is_valid_selector(value))
            .ok_or_else(|| {
                AiError::InvalidInput(
                    "domain DKIM material is incomplete; verify the domain before retrieving DNS records"
                        .into(),
                )
            })?;
        let public_key = row
            .dkim_public_key
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .filter(|_| row.dkim_private_key.as_deref().is_some_and(|key| !key.trim().is_empty()))
            .filter(|_| row.dkim_enabled)
            .ok_or_else(|| {
                AiError::InvalidInput(
                    "domain DKIM material is incomplete; verify the domain before retrieving DNS records"
                        .into(),
                )
            })?;

        Ok(DomainDnsRecords {
            domain: row.name.clone(),
            status: row.status,
            records: records_for_material(&row.name, selector, public_key, &self.aws_region, self.ses_transport),
            transport: if self.ses_transport { "ses" } else { "smtp" }.into(),
        })
    }
}

pub fn records_for_material(
    domain: &str,
    selector: &str,
    public_key: &str,
    aws_region: &str,
    ses_transport: bool,
) -> Vec<DnsRecord> {
    let mut records = vec![
        DnsRecord {
            record_type: "TXT".into(),
            hostname: format!("{selector}._domainkey.{domain}"),
            value: dkim_txt_record_value(public_key),
            priority: None,
        },
        DnsRecord {
            record_type: "TXT".into(),
            hostname: format!("_dmarc.{domain}"),
            value: DMARC_RECORD.into(),
            priority: None,
        },
    ];

    if ses_transport {
        records.insert(
            0,
            DnsRecord {
                record_type: "TXT".into(),
                hostname: format!("{RETURN_PATH_LABEL}.{domain}"),
                value: SES_SPF_RECORD.into(),
                priority: None,
            },
        );
        records.push(DnsRecord {
            record_type: "MX".into(),
            hostname: format!("{RETURN_PATH_LABEL}.{domain}"),
            value: format!("feedback-smtp.{aws_region}.amazonses.com"),
            priority: Some(SES_RETURN_PATH_MX_PRIORITY),
        });
    }
    records
}

fn normalize_domain(domain: &str) -> Result<String, AiError> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty()
        || domain.len() > 253
        || !domain.contains('.')
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label.chars().all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
    {
        return Err(AiError::InvalidInput("invalid domain name".into()));
    }
    Ok(domain)
}

fn is_valid_selector(selector: &str) -> bool {
    !selector.is_empty()
        && selector.len() <= 63
        && selector
            .chars()
            .all(|character| character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_dkim_records_use_the_domain_specific_selector_and_key() {
        let records = records_for_material("example.com", "am-customer-1", "ABC123", "eu-central-1", false);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].record_type, "TXT");
        assert_eq!(records[0].hostname, "am-customer-1._domainkey.example.com");
        assert!(records[0].value.contains("p=ABC123"));
        assert!(!records[0].value.contains("apexmail.dkim"));
    }

    #[test]
    fn ses_records_include_custom_mail_from_pair_only_in_ses_mode() {
        let records = records_for_material("example.com", "selector", "ABC", "us-east-1", true);
        assert_eq!(records[0].hostname, "bounce.example.com");
        assert_eq!(records[0].value, SES_SPF_RECORD);
        assert_eq!(records[3].record_type, "MX");
        assert_eq!(records[3].value, "feedback-smtp.us-east-1.amazonses.com");
    }

    #[test]
    fn normalizes_valid_domains_and_rejects_invalid_values() {
        assert_eq!(normalize_domain(" Example.COM. ").unwrap(), "example.com");
        assert!(normalize_domain("not a domain").is_err());
    }
}