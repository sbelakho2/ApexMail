//! EAI – Email Address Internationalization (RFC 6531).
//!
//! Validates and normalizes international email addresses, checks MX records,
//! SMTPUTF8 support, and common domain typos.

use std::sync::LazyLock;
use std::time::Duration;

use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioResolver;
use unicode_normalization::UnicodeNormalization;

// ── types ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAddress {
    pub local_part: String,
    pub domain: String,
    pub original: String,
    pub normalized: String,
    pub is_internationalized: bool,
    pub punycode_domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedEmail {
    pub address: EmailAddress,
    pub display_name: Option<String>,
    pub requires_smtputf8: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EAIValidationResult {
    pub is_valid: bool,
    pub requires_smtputf8: bool,
    pub normalized_address: Option<String>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentNormalization {
    pub original_charset: String,
    pub normalized_charset: String,
    pub has_unicode: bool,
    pub content_type: String,
}

// ── service ────────────────────────────────────────────────────────────────────

pub struct EAIService {
    pool: PgPool,
    redis: deadpool_redis::Pool,
    resolver: TokioResolver,
    mx_cache: Cache<String, bool>,
    eai_cache: Cache<String, bool>,
}

static EAI_RESOLVER: LazyLock<TokioResolver> = LazyLock::new(|| {
    trust_dns_resolver::Resolver::builder_with_config(
        ResolverConfig::default(),
        trust_dns_resolver::net::runtime::TokioRuntimeProvider::default(),
    )
    .build()
    .expect("system resolver configuration is always buildable")
});

impl EAIService {
    pub fn new(pool: PgPool, redis: deadpool_redis::Pool) -> Self {
        let resolver = EAI_RESOLVER.clone();
        Self {
            pool,
            redis,
            resolver,
            mx_cache: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(Duration::from_secs(3600))
                .build(),
            eai_cache: Cache::builder()
                .max_capacity(5_000)
                .time_to_live(Duration::from_secs(3600))
                .build(),
        }
    }

    /// Parse and validate an email address.
    pub async fn parse_email_address(
        &self,
        email: &str,
        display_name: Option<&str>,
    ) -> anyhow::Result<ParsedEmail> {
        let email = email.trim();

        // Handle "Name <email>" format
        let (name, addr) = if let Some(start) = email.find('<') {
            if let Some(end) = email.find('>') {
                let name = email[..start].trim().trim_matches('"');
                let addr = &email[start + 1..end];
                (
                    if name.is_empty() {
                        display_name.map(|s| s.to_string())
                    } else {
                        Some(name.to_string())
                    },
                    addr.to_string(),
                )
            } else {
                (display_name.map(|s| s.to_string()), email.to_string())
            }
        } else {
            (display_name.map(|s| s.to_string()), email.to_string())
        };

        // Split at last @
        let (local_part, domain) = addr
            .rsplit_once('@')
            .ok_or_else(|| anyhow::anyhow!("Missing @ in email address"))?;

        // NFC normalize
        let local_normalized = unicode_normalize_nfc(local_part);
        let domain_normalized = unicode_normalize_nfc(domain).to_lowercase();
        let is_intl =
            contains_non_ascii(&local_normalized) || contains_non_ascii(&domain_normalized);

        // Punycode the domain
        let punycode_domain = if contains_non_ascii(&domain_normalized) {
            match idna::domain_to_ascii(&domain_normalized) {
                Ok(p) => Some(p),
                Err(_) => {
                    anyhow::bail!("Invalid internationalized domain: {domain_normalized}");
                }
            }
        } else {
            None
        };

        // Validate local part
        self.validate_local_part(&local_normalized, is_intl)?;
        // Validate domain
        self.validate_domain(
            &domain_normalized,
            punycode_domain.as_deref().unwrap_or(&domain_normalized),
        )?;

        let normalized = format!(
            "{}@{}",
            local_normalized,
            punycode_domain.as_deref().unwrap_or(&domain_normalized)
        );

        let address = EmailAddress {
            local_part: local_normalized,
            domain: domain_normalized,
            original: addr,
            normalized: normalized.clone(),
            is_internationalized: is_intl,
            punycode_domain,
        };

        Ok(ParsedEmail {
            address,
            display_name: name,
            requires_smtputf8: is_intl,
        })
    }

    /// Full validation:parse + MX check + SMTPUTF8 support + typo check.
    pub async fn validate_email(&self, email: &str) -> anyhow::Result<EAIValidationResult> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        let parsed = match self.parse_email_address(email, None).await {
            Ok(p) => p,
            Err(e) => {
                return Ok(EAIValidationResult {
                    is_valid: false,
                    requires_smtputf8: false,
                    normalized_address: None,
                    errors: vec![e.to_string()],
                    warnings: vec![],
                });
            }
        };

        // Check MX records
        if !self.check_domain_mx(&parsed.address.domain).await {
            errors.push(format!(
                "No MX records found for domain: {}",
                parsed.address.domain
            ));
        }

        // Check common typos
        if let Some(suggestion) = check_common_typos(&parsed.address.domain) {
            warnings.push(format!("Did you mean {suggestion}?"));
        }

        // Check SMTPUTF8 support if internationalized
        if parsed.requires_smtputf8 {
            let supported = self.check_eai_support(&parsed.address.domain).await;
            if !supported {
                warnings.push(format!(
                    "Domain {} may not support SMTPUTF8; delivery might fail",
                    parsed.address.domain
                ));
            }
        }

        Ok(EAIValidationResult {
            is_valid: errors.is_empty(),
            requires_smtputf8: parsed.requires_smtputf8,
            normalized_address: Some(parsed.address.normalized),
            errors,
            warnings,
        })
    }

    /// Batch validation.
    pub async fn validate_emails(
        &self,
        emails: &[String],
    ) -> anyhow::Result<Vec<EAIValidationResult>> {
        let mut results = Vec::with_capacity(emails.len());
        for email in emails {
            results.push(self.validate_email(email).await?);
        }
        Ok(results)
    }

    /// Build MAIL FROM command with optional SMTPUTF8.
    pub fn build_mail_from_command(from: &EmailAddress, requires_smtputf8: bool) -> String {
        if requires_smtputf8 {
            format!("MAIL FROM:<{}> SMTPUTF8", from.normalized)
        } else {
            let addr = from
                .punycode_domain
                .as_ref()
                .map(|p| format!("{}@{}", from.local_part, p))
                .unwrap_or_else(|| from.normalized.clone());
            format!("MAIL FROM:<{addr}>")
        }
    }

    /// Build RCPT TO command.
    pub fn build_rcpt_to_command(to: &EmailAddress, requires_smtputf8: bool) -> String {
        if requires_smtputf8 {
            format!("RCPT TO:<{}>", to.normalized)
        } else {
            let addr = to
                .punycode_domain
                .as_ref()
                .map(|p| format!("{}@{}", to.local_part, p))
                .unwrap_or_else(|| to.normalized.clone());
            format!("RCPT TO:<{addr}>")
        }
    }

    /// Update domain EAI capability in DB.
    pub async fn update_domain_capability(
        &self,
        domain: &str,
        supports_smtputf8: bool,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"INSERT INTO edge_domain_capabilities (domain, supports_smtputf8, checked_at)
               VALUES ($1, $2, NOW())
               ON CONFLICT (domain) DO UPDATE
               SET supports_smtputf8 = $2, checked_at = NOW()"#,
        )
        .bind(domain)
        .bind(supports_smtputf8)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ── internal ───────────────────────────────────────────────────────────────

    fn validate_local_part(&self, local: &str, is_intl: bool) -> anyhow::Result<()> {
        if local.is_empty() {
            anyhow::bail!("Local part is empty");
        }
        if local.len() > 64 {
            anyhow::bail!("Local part exceeds 64 characters");
        }
        if local.starts_with('.') || local.ends_with('.') {
            anyhow::bail!("Local part must not start or end with a dot");
        }
        if local.contains("..") {
            anyhow::bail!("Local part must not contain consecutive dots");
        }

        if is_intl {
            // UTF-8 is allowed, but no control characters
            for ch in local.chars() {
                if ch.is_control() {
                    anyhow::bail!("Local part contains control characters");
                }
            }
        } else {
            // ASCII validation
            for ch in local.chars() {
                if !ch.is_ascii_alphanumeric()
                    && !matches!(
                        ch,
                        '.' | '_'
                            | '-'
                            | '+'
                            | '='
                            | '!'
                            | '#'
                            | '$'
                            | '%'
                            | '&'
                            | '\''
                            | '*'
                            | '/'
                            | '?'
                            | '^'
                            | '`'
                            | '{'
                            | '|'
                            | '}'
                            | '~'
                    )
                {
                    anyhow::bail!("Invalid character in local part: {ch}");
                }
            }
        }
        Ok(())
    }

    /// O-21.3: Reject punycode-encoded domain labels exceeding 63 characters
    /// (RFC 5891 §4.2.3.1). The `punycode` parameter is the ACE-encoded form
    /// (`xn--...`). Its labels are checked for length ≤ 63 ASCII characters,
    /// which catches cases where a long Unicode label expands beyond the limit
    /// during Punycode encoding.
    fn validate_domain(&self, domain: &str, punycode: &str) -> anyhow::Result<()> {
        if domain.is_empty() {
            anyhow::bail!("Domain is empty");
        }
        if punycode.len() > 255 {
            anyhow::bail!("Domain exceeds 255 characters");
        }

        let labels: Vec<&str> = punycode.split('.').collect();
        if labels.len() < 2 {
            anyhow::bail!("Domain must have at least 2 labels");
        }
        for label in &labels {
            if label.len() > 63 {
                anyhow::bail!("Domain punycode label exceeds 63 ASCII characters: {label}");
            }
            if label.is_empty() {
                anyhow::bail!("Domain contains empty label");
            }
        }

        // TLD must not be all numeric
        if let Some(tld) = labels.last() {
            if tld.chars().all(|c| c.is_ascii_digit()) {
                anyhow::bail!("TLD must not be all numeric");
            }
        }

        Ok(())
    }

    async fn check_domain_mx(&self, domain: &str) -> bool {
        if let Some(cached) = self.mx_cache.get(domain) {
            return cached;
        }

        let has_mx = match self.resolver.mx_lookup(domain).await {
            Ok(mx) => mx
                .answers()
                .iter()
                .any(|r| matches!(&r.data, trust_dns_resolver::proto::rr::RData::MX(_))),
            Err(_) => {
                // Fallback to A record
                self.resolver.lookup_ip(domain).await.is_ok()
            }
        };

        self.mx_cache.insert(domain.to_string(), has_mx);
        has_mx
    }

    async fn check_eai_support(&self, domain: &str) -> bool {
        if let Some(cached) = self.eai_cache.get(domain) {
            return cached;
        }

        // Try Redis
        if let Ok(mut conn) = self.redis.get().await {
            let key = format!("eai:support:{domain}");
            if let Ok(Some(v)) = redis::cmd("GET")
                .arg(&key)
                .query_async::<Option<String>>(&mut *conn)
                .await
            {
                let supported = v == "1";
                self.eai_cache.insert(domain.to_string(), supported);
                return supported;
            }
        }

        // Try DB
        let result = sqlx::query_scalar::<_, bool>(
            "SELECT supports_smtputf8 FROM edge_domain_capabilities WHERE domain = $1 AND checked_at > NOW() - INTERVAL '7 days'"
        )
        .bind(domain)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten()
        .unwrap_or(false);

        self.eai_cache.insert(domain.to_string(), result);
        result
    }
}

// ── helpers ────────────────────────────────────────────────────────────────────

/// NFC Unicode normalization (Rust strings are UTF-8; we use unicode-normalization).
fn unicode_normalize_nfc(s: &str) -> String {
    s.nfc().collect()
}

/// Check if string contains non-ASCII characters.
pub fn contains_non_ascii(s: &str) -> bool {
    s.bytes().any(|b| b > 127)
}

/// Normalize charset name.
pub fn normalize_content(content: &str, charset: Option<&str>) -> ContentNormalization {
    let original_charset = charset.unwrap_or("utf-8").to_lowercase();
    let normalized_charset = match original_charset.as_str() {
        "iso-8859-1" | "latin1" | "latin-1" => "iso-8859-1",
        "windows-1252" | "cp1252" => "windows-1252",
        "us-ascii" | "ascii" => "ascii",
        _ => "utf-8",
    };
    ContentNormalization {
        original_charset: original_charset.clone(),
        normalized_charset: normalized_charset.to_string(),
        has_unicode: contains_non_ascii(content),
        content_type: "text/plain".into(),
    }
}

/// Common domain typo suggestions.
fn check_common_typos(domain: &str) -> Option<&'static str> {
    match domain {
        "gmial.com" | "gmai.com" | "gmal.com" | "gamil.com" => Some("gmail.com"),
        "yahoocom" | "yaho.com" | "yahooo.com" => Some("yahoo.com"),
        "hotmial.com" | "hotmal.com" | "hotmil.com" => Some("hotmail.com"),
        "outlok.com" | "outloo.com" | "outlookcom" => Some("outlook.com"),
        "iclod.com" | "icoud.com" => Some("icloud.com"),
        "protonmal.com" | "protonmial.com" => Some("protonmail.com"),
        _ => None,
    }
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_non_ascii() {
        assert!(!contains_non_ascii("hello@example.com"));
        assert!(contains_non_ascii("héllo@example.com"));
        assert!(contains_non_ascii("user@例え.jp"));
    }

    #[test]
    fn test_check_common_typos() {
        assert_eq!(check_common_typos("gmial.com"), Some("gmail.com"));
        assert_eq!(check_common_typos("hotmial.com"), Some("hotmail.com"));
        assert_eq!(check_common_typos("gmail.com"), None);
        assert_eq!(check_common_typos("example.com"), None);
    }

    #[test]
    fn test_normalize_content() {
        let result = normalize_content("hello", None);
        assert_eq!(result.normalized_charset, "utf-8");
        assert!(!result.has_unicode);

        let result = normalize_content("héllo", Some("iso-8859-1"));
        assert_eq!(result.normalized_charset, "iso-8859-1");
        assert!(result.has_unicode);
    }

    #[test]
    fn test_build_mail_from_command() {
        let addr = EmailAddress {
            local_part: "user".into(),
            domain: "example.com".into(),
            original: "user@example.com".into(),
            normalized: "user@example.com".into(),
            is_internationalized: false,
            punycode_domain: None,
        };
        assert_eq!(
            EAIService::build_mail_from_command(&addr, false),
            "MAIL FROM:<user@example.com>"
        );
        assert_eq!(
            EAIService::build_mail_from_command(&addr, true),
            "MAIL FROM:<user@example.com> SMTPUTF8"
        );
    }

    #[test]
    fn test_build_rcpt_to_command() {
        let addr = EmailAddress {
            local_part: "user".into(),
            domain: "例え.jp".into(),
            original: "user@例え.jp".into(),
            normalized: "user@xn --r8jz45g.jp".into(),
            is_internationalized: true,
            punycode_domain: Some("xn --r8jz45g.jp".into()),
        };
        assert_eq!(
            EAIService::build_rcpt_to_command(&addr, false),
            "RCPT TO:<user@xn --r8jz45g.jp>"
        );
        assert_eq!(
            EAIService::build_rcpt_to_command(&addr, true),
            "RCPT TO:<user@xn --r8jz45g.jp>"
        );
    }
}
