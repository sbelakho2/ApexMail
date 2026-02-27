//! validator-native – Native Node.js bindings for ApexMail email validation.
//!
//! Validates email addresses per RFC 5321/6531 (EAI), with optional MX lookups
//! and disposable domain detection. Runs entirely in Rust off the JS thread.

#![deny(clippy::unwrap_used)]
#![allow(clippy::needless_pass_by_value)]

use napi::bindgen_prelude::*;
use napi_derive::napi;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, OnceLock, RwLock};
use std::time::{Duration, Instant};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Max local part length (RFC 5321).
const MAX_LOCAL_PART: usize = 64;
/// Max domain length.
const MAX_DOMAIN: usize = 253;
/// Max total address length.
const MAX_ADDRESS: usize = 254;

static EMAIL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~\u{0080}-\u{FFFF}-]+@[a-zA-Z0-9.\u{0080}-\u{FFFF}-]+\.[a-zA-Z\u{0080}-\u{FFFF}]{2,}$")
        .expect("email regex must compile")
});

/// Known disposable email domains.
static DISPOSABLE_DOMAINS: LazyLock<RwLock<HashSet<String>>> = LazyLock::new(|| {
    let mut domains: HashSet<String> = [
        "mailinator.com", "guerrillamail.com", "tempmail.com", "throwaway.email",
        "yopmail.com", "sharklasers.com", "guerrillamailblock.com", "grr.la",
        "dispostable.com", "trashmail.com", "temp-mail.org", "fakeinbox.com",
        "mailnesia.com", "maildrop.cc", "discard.email", "getnada.com",
        "mohmal.com", "tempail.com", "burner.kiwi", "mailcatch.com",
        "minutemail.com", "emailondeck.com", "tempr.email", "33mail.com",
        "mytemp.email", "harakirimail.com", "incognitomail.org", "tempinbox.com",
        "maildrop.cc", "10minutemail.com", "maildrop.me", "guerrillamail.net",
        "guerrillamail.org", "guerrillamail.biz", "guerrillamail.de",
        "guerrillamail.info", "guerrillamailblock.com", "mailinator.net",
        "mailinator.org", "mailinator2.com", "trash-mail.com", "trashmail.net",
        "tempmail.net", "tempmail.ninja", "tempmaildev.com", "temp-mail.io",
    ]
    .into_iter()
    .map(String::from)
    .collect();

    if let Ok(extra) = std::env::var("APEXMAIL_DISPOSABLE_DOMAINS") {
        for entry in extra.split(',') {
            let trimmed = entry.trim().to_lowercase();
            if !trimmed.is_empty() {
                domains.insert(trimmed);
            }
        }
    }

    RwLock::new(domains)
});

static DNS_CACHE: LazyLock<RwLock<HashMap<String, DnsCacheEntry>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

const DNS_CACHE_TTL: Duration = Duration::from_secs(300);
const DNS_CACHE_MAX_ENTRIES: usize = 10_000;

struct DnsCacheEntry {
    has_mx: bool,
    expires_at: Instant,
}

static RESOLVER: OnceLock<TokioAsyncResolver> = OnceLock::new();

fn get_resolver() -> Option<&'static TokioAsyncResolver> {
    RESOLVER.get()
}

fn lookup_dns_cache(domain: &str) -> Option<bool> {
    let Ok(cache) = DNS_CACHE.read() else {
        return None;
    };
    cache.get(domain).and_then(|entry| {
        if entry.expires_at > Instant::now() {
            Some(entry.has_mx)
        } else {
            None
        }
    })
}

fn store_dns_cache(domain: String, has_mx: bool) {
    let Ok(mut cache) = DNS_CACHE.write() else {
        return;
    };
    cache.retain(|_, entry| entry.expires_at > Instant::now());
    while cache.len() >= DNS_CACHE_MAX_ENTRIES {
        if let Some(key) = cache.keys().next().cloned() {
            cache.remove(&key);
        } else {
            break;
        }
    }
    cache.insert(
        domain,
        DnsCacheEntry {
            has_mx,
            expires_at: Instant::now() + DNS_CACHE_TTL,
        },
    );
}

// ─── Types ────────────────────────────────────────────────────────────────────

#[napi(object)]
pub struct ValidationResult {
    pub valid: bool,
    pub email: String,
    pub local_part: String,
    pub domain: String,
    pub is_eai: bool,
    pub is_disposable: bool,
    pub has_mx: Option<bool>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[napi(object)]
pub struct MxCheckResult {
    pub domain: String,
    pub has_mx: bool,
    pub mx_records: Vec<String>,
    pub has_a_fallback: bool,
}

#[napi(object)]
pub struct BatchResult {
    pub results: Vec<ValidationResult>,
    pub valid_count: u32,
    pub invalid_count: u32,
}

// ─── Core validation ──────────────────────────────────────────────────────────

fn is_eai(s: &str) -> bool {
    s.chars().any(|c| c as u32 > 127)
}

fn validate_email_sync(email: &str) -> ValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    let email = email.trim();

    if email.is_empty() {
        return ValidationResult {
            valid: false,
            email: email.to_string(),
            local_part: String::new(),
            domain: String::new(),
            is_eai: false,
            is_disposable: false,
            has_mx: None,
            errors: vec!["Email address is empty".into()],
            warnings,
        };
    }

    if email.len() > MAX_ADDRESS {
        errors.push(format!("Address exceeds {MAX_ADDRESS} characters"));
    }

    let Some((local_part, domain)) = email.split_once('@') else {
        return ValidationResult {
            valid: false,
            email: email.to_string(),
            local_part: String::new(),
            domain: String::new(),
            is_eai: false,
            is_disposable: false,
            has_mx: None,
            errors: vec!["Missing @ separator".into()],
            warnings,
        };
    };

    // Local part checks
    if local_part.is_empty() {
        errors.push("Local part is empty".into());
    } else if local_part.len() > MAX_LOCAL_PART {
        errors.push(format!("Local part exceeds {MAX_LOCAL_PART} characters"));
    }
    if local_part.starts_with('.') || local_part.ends_with('.') {
        errors.push("Local part cannot start or end with a dot".into());
    }
    if local_part.contains("..") {
        errors.push("Local part cannot contain consecutive dots".into());
    }

    // Domain checks
    if domain.is_empty() {
        errors.push("Domain is empty".into());
    } else if domain.len() > MAX_DOMAIN {
        errors.push(format!("Domain exceeds {MAX_DOMAIN} characters"));
    }
    if domain.starts_with('.') || domain.starts_with('-') {
        errors.push("Domain cannot start with dot or hyphen".into());
    }
    if domain.ends_with('-') {
        errors.push("Domain cannot end with hyphen".into());
    }

    // Check domain labels
    for label in domain.split('.') {
        if label.is_empty() {
            errors.push("Domain has empty label".into());
        } else if label.len() > 63 {
            errors.push(format!("Domain label '{}' exceeds 63 characters", label));
        }
    }

    // Regex validation (supports EAI)
    if !EMAIL_REGEX.is_match(email) && errors.is_empty() {
        errors.push("Invalid email format".into());
    }

    let eai = is_eai(email);
    if eai {
        warnings.push("Address contains international characters (EAI/RFC 6531)".into());
    }

    let is_disposable = DISPOSABLE_DOMAINS
        .read()
        .map(|domains| domains.contains(&domain.to_lowercase()))
        .unwrap_or(false);
    if is_disposable {
        warnings.push("Disposable email domain detected".into());
    }

    // Check for common role addresses
    let lower_local = local_part.to_lowercase();
    if ["noreply", "no-reply", "postmaster", "abuse", "mailer-daemon"]
        .iter()
        .any(|r| lower_local == *r)
    {
        warnings.push(format!("Role address detected: {lower_local}"));
    }

    ValidationResult {
        valid: errors.is_empty(),
        email: email.to_string(),
        local_part: local_part.to_string(),
        domain: domain.to_string(),
        is_eai: eai,
        is_disposable,
        has_mx: None,
        errors,
        warnings,
    }
}

// ─── Exported functions ───────────────────────────────────────────────────────

/// Synchronous email validation (syntax + disposable check, no MX).
#[napi]
pub fn validate_email(email: String) -> ValidationResult {
    validate_email_sync(&email)
}

/// Async email validation with MX record check.
#[napi]
pub async fn validate_email_with_mx(email: String) -> Result<ValidationResult> {
    let mut result = validate_email_sync(&email);

    if result.valid {
        let domain = result.domain.clone();
        if let Some(cached) = lookup_dns_cache(&domain) {
            result.has_mx = Some(cached);
            if !cached {
                result.errors.push("Domain has no MX or A records".into());
                result.valid = false;
            }
            return Ok(result);
        }
        let Some(resolver) = get_resolver() else {
            result.warnings.push("DNS resolver not initialized".into());
            return Ok(result);
        };

        let has_mx = match resolver.mx_lookup(&domain).await {
            Ok(mx) => mx.iter().next().is_some(),
            Err(_) => {
                // Fallback: check A record
                resolver.ipv4_lookup(&domain).await.is_ok()
            }
        };

        result.has_mx = Some(has_mx);
        if !has_mx {
            result.errors.push("Domain has no MX or A records".into());
            result.valid = false;
        }
        store_dns_cache(domain, has_mx);
    }

    Ok(result)
}

/// Batch validate multiple emails (sync).
#[napi]
pub async fn validate_emails_batch(emails: Vec<String>) -> BatchResult {
    let mut set = tokio::task::JoinSet::new();
    for (index, email) in emails.into_iter().enumerate() {
        set.spawn_blocking(move || (index, validate_email_sync(&email)));
    }

    let mut ordered: Vec<(usize, ValidationResult)> = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(item) = joined {
            ordered.push(item);
        }
    }

    ordered.sort_by_key(|(index, _)| *index);
    let results: Vec<ValidationResult> = ordered.into_iter().map(|(_, result)| result).collect();
    let valid_count = results.iter().filter(|r| r.valid).count() as u32;
    let invalid_count = results.len() as u32 - valid_count;
    BatchResult {
        results,
        valid_count,
        invalid_count,
    }
}

/// Replace or extend the disposable domain list at runtime.
#[napi]
pub fn set_disposable_domains(domains: Vec<String>, replace: bool) -> Result<u32> {
    let Ok(mut guard) = DISPOSABLE_DOMAINS.write() else {
        return Err(napi::Error::from_reason("Disposable domain list lock poisoned"));
    };
    if replace {
        guard.clear();
    }
    for domain in domains {
        let trimmed = domain.trim().to_lowercase();
        if !trimmed.is_empty() {
            guard.insert(trimmed);
        }
    }
    Ok(guard.len() as u32)
}

/// Check MX records for a domain.
#[napi]
pub async fn check_mx(domain: String) -> Result<MxCheckResult> {
    let Some(resolver) = get_resolver() else {
        return Err(napi::Error::from_reason("DNS resolver not initialized"));
    };

    let mx_result = resolver.mx_lookup(&domain).await;
    let mx_records: Vec<String> = match &mx_result {
        Ok(mx) => mx.iter().map(|r| format!("{} {}", r.preference(), r.exchange())).collect(),
        Err(_) => Vec::new(),
    };
    let has_mx = !mx_records.is_empty();

    let has_a_fallback = if !has_mx {
        resolver.ipv4_lookup(&domain).await.is_ok()
    } else {
        false
    };

    Ok(MxCheckResult {
        domain,
        has_mx,
        mx_records,
        has_a_fallback,
    })
}

/// Check if a domain is in the disposable email list.
#[napi]
pub fn is_disposable_domain(domain: String) -> bool {
    let Ok(domains) = DISPOSABLE_DOMAINS.read() else {
        return false;
    };
    domains.contains(domain.to_lowercase().as_str())
}

/// Normalize an email address (lowercase domain, trim).
#[napi]
pub fn normalize_email(email: String) -> Result<String> {
    let email = email.trim();
    let Some((local_part, domain)) = email.split_once('@') else {
        return Err(napi::Error::from_reason("Invalid email format"));
    };
    Ok(format!("{}@{}", local_part, domain.to_lowercase()))
}

/// Get the list of known disposable domains.
#[napi]
pub fn get_disposable_domains() -> Vec<String> {
    let Ok(domains) = DISPOSABLE_DOMAINS.read() else {
        return Vec::new();
    };
    domains.iter().map(|d| d.to_string()).collect()
}

#[napi]
pub fn initialize_dns_resolver() {
    let _ = RESOLVER.get_or_init(|| {
        TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
    });
}
