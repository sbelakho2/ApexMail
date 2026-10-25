//! Opt-in public-page discovery source (`public_web`).
//!
//! This is the one source that fetches public web pages (company sites,
//! national registers that publish an HTML/JSON-LD extract). It is opt-in by
//! construction and deliberately narrow:
//!
//! * **The operator names the URLs.** `SALES_SCRAPE_PUBLIC_URLS` is a
//!   comma-separated allowlist; the source is not registered at all when it
//!   is unset, so no page is ever fetched by default. There is no crawl, no
//!   link following, no URL discovery, only the listed URLs are requested.
//! * **One shared hardened client.** Every request goes through
//!   [`ScrapeClient`]: robots.txt (fail closed), per-host politeness, bounded
//!   retries, size/content-type caps, same-host redirects only, and
//!   deterministic challenge classification. A challenge page is a typed
//!   [`DiscoveryError::Blocked`], never a data row and never an "empty
//!   result".
//! * **A blocked pass stores nothing.** If any listed URL is blocked, the
//!   whole pass fails with the evidence: no candidate from that pass is
//!   persisted (a failed run must not leave partial data that looks
//!   complete).
//! * **Extraction is deterministic and standard.** Only two documented
//!   things are read from a page: schema.org `Organization` nodes in
//!   JSON-LD (`name`, `url`, `email`, `address.addressCountry`) and
//!   `mailto:` links. Anything else is ignored rather than guessed at; the
//!   run's candidates carry the provenance of the fetch
//!   (`source_url`, `fetched_at`, and the body's SHA-256 as the snapshot
//!   hash).

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use sha2::{Digest, Sha256};
use sqlx::PgPool;

use super::blocked::{hydrate_registry, record_host_block, record_host_success};
use super::fetch::{BlockedEvidence, ScrapeClient, ScrapeConfig, ScrapedPage};
use super::job::{normalize_email, sanitize_domain};
use super::provider::{
    DiscoveredCandidate, DiscoveryError, DiscoveryPage, DiscoveryQuery, DiscoverySource,
};

/// Source id persisted in `sales_discovery_candidates.source`.
pub const PUBLIC_WEB_SOURCE_ID: &str = "public_web";

/// Operator allowlist of public URLs this source may fetch.
pub const PUBLIC_URLS_ENV: &str = "SALES_SCRAPE_PUBLIC_URLS";

/// Ceiling on the allowlist (a scrape source, not a crawler).
pub const MAX_PUBLIC_URLS: usize = 50;

/// Ceiling on candidates taken from one page.
pub const MAX_CANDIDATES_PER_PAGE: usize = 50;

/// Sentinel for "no fetch has happened yet".
const NO_STATUS: i32 = 0;

/// Approved-page discovery source.
#[derive(Debug)]
pub struct PublicWebSource {
    id: &'static str,
    db: PgPool,
    tenant_id: String,
    urls: Vec<String>,
    client: ScrapeClient,
    max_candidates_per_page: usize,
    /// Last HTTP status seen by this source, surfaced through
    /// [`DiscoverySource::last_http_status`] into
    /// `sales_source_runs.http_status` (the status IS evidence for a block).
    last_status: AtomicI32,
    /// Whether this instance has loaded the tenant's persisted host health.
    hydrated: AtomicBool,
}

impl PublicWebSource {
    /// Build a source over an explicit URL list (already operator-approved).
    pub fn new(db: PgPool, tenant_id: &str, urls: Vec<String>, client: ScrapeClient) -> Self {
        Self {
            id: PUBLIC_WEB_SOURCE_ID,
            db,
            tenant_id: tenant_id.to_string(),
            urls: urls.into_iter().take(MAX_PUBLIC_URLS).collect(),
            client,
            max_candidates_per_page: MAX_CANDIDATES_PER_PAGE,
            last_status: AtomicI32::new(NO_STATUS),
            hydrated: AtomicBool::new(false),
        }
    }

    /// Build from `SALES_SCRAPE_PUBLIC_URLS`. `None` means the operator has
    /// not enabled the source (it must then not be registered at all, the
    /// absence of an allowlist is not "scrape everything").
    pub fn from_env(
        db: PgPool,
        tenant_id: &str,
        config: ScrapeConfig,
    ) -> Result<Option<Self>, String> {
        let Some(raw) = std::env::var(PUBLIC_URLS_ENV)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };

        let mut urls: Vec<String> = Vec::new();
        for entry in raw.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let parsed = url::Url::parse(entry)
                .map_err(|error| format!("{PUBLIC_URLS_ENV}: `{entry}` is not a URL: {error}"))?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(format!(
                    "{PUBLIC_URLS_ENV}: `{entry}` is not an http(s) URL; refusing to register \
                     the public-web source"
                ));
            }
            urls.push(parsed.to_string());
        }
        if urls.is_empty() {
            return Ok(None);
        }

        let client = ScrapeClient::new(config)
            .map_err(|error| format!("{PUBLIC_URLS_ENV} is configured but {error}"))?;
        Ok(Some(Self::new(db, tenant_id, urls, client)))
    }

    pub fn client(&self) -> &ScrapeClient {
        &self.client
    }

    pub fn urls(&self) -> &[String] {
        &self.urls
    }

    /// Load persisted host health once per instance (see `discover`).
    async fn ensure_hydrated(&self) -> Result<(), DiscoveryError> {
        if self.hydrated.load(Ordering::SeqCst) {
            return Ok(());
        }
        hydrate_registry(&self.db, &self.tenant_id, &self.client.host_health())
            .await
            .map_err(|error| {
                DiscoveryError::Internal(format!("host-health hydration failed: {error}"))
            })?;
        self.hydrated.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Override the per-page candidate ceiling (tests).
    pub fn with_max_candidates_per_page(mut self, value: usize) -> Self {
        self.max_candidates_per_page = value.clamp(1, MAX_CANDIDATES_PER_PAGE);
        self
    }
}

#[async_trait::async_trait]
impl DiscoverySource for PublicWebSource {
    fn id(&self) -> &'static str {
        self.id
    }

    /// Public pages carry whatever jurisdiction they state; the source itself
    /// declares none, and the job runner still enforces any operator-set
    /// restriction on the returned values.
    fn allowed_jurisdictions(&self) -> &[&'static str] {
        &[]
    }

    fn last_http_status(&self) -> Option<i32> {
        match self.last_status.load(Ordering::SeqCst) {
            NO_STATUS => None,
            status => Some(status),
        }
    }

    async fn discover(
        &self,
        _query: &DiscoveryQuery,
        _cursor: Option<&str>,
    ) -> Result<DiscoveryPage, DiscoveryError> {
        // A fresh process (or a fresh request-scoped runner, which is how the
        // service constructs sources) must NOT hand a host a clean slate: the
        // persisted backoff windows are loaded before the first request. A
        // hydration failure fails the pass loudly rather than quietly
        // scraping a host the engine had decided to leave alone.
        self.ensure_hydrated().await?;
        let mut candidates: Vec<DiscoveredCandidate> = Vec::new();

        for url in &self.urls {
            match self.client.fetch(url).await {
                Ok(page) => {
                    self.last_status
                        .store(i32::from(page.status), Ordering::SeqCst);
                    if let Ok(parsed) = url::Url::parse(&page.url) {
                        if let Some(host) = parsed.host_str() {
                            record_host_success(&self.db, &self.tenant_id, host)
                                .await
                                .map_err(|error| {
                                    DiscoveryError::Internal(format!(
                                        "host health write failed: {error}"
                                    ))
                                })?;
                        }
                    }
                    candidates.extend(extract_candidates(&page, self.max_candidates_per_page));
                }
                Err(error) => {
                    // A blocked fetch keeps its structured evidence, and
                    // nothing from this pass is returned, so a blocked page
                    // can never become a candidate or an empty page. The
                    // host's transport-level health (backoff window) is
                    // persisted here, where the client that saw the block
                    // lives; the review-queue row is written by the job
                    // runner from the typed evidence.
                    let status = match &error {
                        super::fetch::FetchError::Blocked(evidence) => {
                            evidence.http_status.map(i32::from)
                        }
                        _ => None,
                    };
                    self.last_status
                        .store(status.unwrap_or(NO_STATUS), Ordering::SeqCst);
                    if let Some(evidence) = BlockedEvidence::from_fetch_error(&error) {
                        if let Some(state) = self.client.host_health().snapshot(&evidence.host) {
                            record_host_block(
                                &self.db,
                                &self.tenant_id,
                                evidence.classification,
                                &state,
                            )
                            .await
                            .map_err(|write_error| {
                                DiscoveryError::Internal(format!(
                                    "host health write failed: {write_error}"
                                ))
                            })?;
                        }
                    }
                    return Err(DiscoveryError::from_fetch_error(error));
                }
            }
        }

        Ok(DiscoveryPage {
            candidates,
            next_cursor: None,
            cost_eur: 0.0,
        })
    }
}

// ---------------------------------------------------------------------------
// Extraction (pure; every rule documented and fixture-tested)
// ---------------------------------------------------------------------------

/// The fields this extractor reads from a schema.org `Organization` node.
#[derive(Debug, Clone, Default, PartialEq)]
struct OrganizationNode {
    name: Option<String>,
    url: Option<String>,
    email: Option<String>,
    country: Option<String>,
}

/// Extract candidates from one fetched page.
pub fn extract_candidates(page: &ScrapedPage, max_candidates: usize) -> Vec<DiscoveredCandidate> {
    let body = page.text();
    let mut candidates: Vec<DiscoveredCandidate> = Vec::new();

    let mut organizations: Vec<OrganizationNode> = Vec::new();
    for block in json_ld_blocks(body) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&block) {
            collect_organizations(&value, &mut organizations);
        }
    }
    organizations.retain(|node| node.name.is_some() || node.url.is_some() || node.email.is_some());

    let emails = mailto_emails(body);
    let mut claimed: Vec<String> = Vec::new();

    for node in &organizations {
        let email = node.email.as_deref().and_then(normalize_email);
        if let Some(email) = &email {
            claimed.push(email.clone());
        }
        candidates.push(DiscoveredCandidate {
            source: PUBLIC_WEB_SOURCE_ID.to_string(),
            source_url: Some(candidate_url(page, "org", &organization_key(node))),
            company_name: node.name.clone(),
            domain: node
                .url
                .as_deref()
                .and_then(|url| sanitize_domain(Some(url))),
            contact_email: email,
            jurisdiction: node.country.clone(),
            jurisdiction_confidence: if node.country.is_some() { 0.5 } else { 0.0 },
            confidence: 0.6,
            raw_snapshot_hash: Some(page.sha256.clone()),
            fetched_at: Some(page.fetched_at),
        });
    }

    // Emails the page links but no organization node claims: keep them, with
    // the domain the address itself states, and no invented company name.
    for email in emails {
        if claimed.contains(&email) {
            continue;
        }
        claimed.push(email.clone());
        let domain = email.split('@').nth(1).map(str::to_string);
        candidates.push(DiscoveredCandidate {
            source: PUBLIC_WEB_SOURCE_ID.to_string(),
            source_url: Some(candidate_url(page, "email", &email)),
            company_name: None,
            domain,
            contact_email: Some(email),
            jurisdiction: None,
            jurisdiction_confidence: 0.0,
            confidence: 0.4,
            raw_snapshot_hash: Some(page.sha256.clone()),
            fetched_at: Some(page.fetched_at),
        });
    }

    dedupe_extracted(&mut candidates);
    candidates.truncate(max_candidates);
    candidates
}

/// The identity of one organization within a page: its normalized
/// (name, domain) pair. Stable across re-fetches, which is what makes the
/// candidate row's URL a real dedupe key rather than a page-wide collision.
fn organization_key(node: &OrganizationNode) -> String {
    format!(
        "{}|{}",
        node.name
            .as_deref()
            .map(|name| name.trim().to_ascii_lowercase())
            .unwrap_or_default(),
        node.url.as_deref().unwrap_or_default()
    )
}

/// The `source_url` for one extracted candidate: the fetched page URL plus a
/// fragment naming the document region the values came from.
///
/// The fragment is deliberate and is not sent to the server: it identifies
/// the exact entity inside the page, satisfies the
/// `(tenant, source, source_url)` unique index (one page can yield several
/// organizations), and stays stable across re-fetches of the same page.
fn candidate_url(page: &ScrapedPage, kind: &str, key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    format!("{}#{kind}:{}", page.url, &digest[..12])
}

/// Collapse duplicates the page itself produced (same name+domain, or the
/// same email): the first occurrence wins, later ones only fill gaps.
fn dedupe_extracted(candidates: &mut Vec<DiscoveredCandidate>) {
    let mut kept: Vec<DiscoveredCandidate> = Vec::new();
    for candidate in candidates.drain(..) {
        let duplicate = kept.iter_mut().find(|existing| {
            let same_email = match (&existing.contact_email, &candidate.contact_email) {
                (Some(left), Some(right)) => left == right,
                _ => false,
            };
            let same_company = existing
                .company_name
                .as_deref()
                .map(|name| name.trim().to_ascii_lowercase())
                .zip(
                    candidate
                        .company_name
                        .as_deref()
                        .map(|name| name.trim().to_ascii_lowercase()),
                )
                .map(|(left, right)| left == right)
                .unwrap_or(false)
                && existing.domain == candidate.domain;
            same_email || same_company
        });
        match duplicate {
            Some(existing) => {
                if existing.company_name.is_none() {
                    existing.company_name = candidate.company_name;
                }
                if existing.domain.is_none() {
                    existing.domain = candidate.domain;
                }
                if existing.contact_email.is_none() {
                    existing.contact_email = candidate.contact_email;
                }
                if existing.jurisdiction.is_none() {
                    existing.jurisdiction = candidate.jurisdiction;
                }
                if candidate.confidence > existing.confidence {
                    existing.confidence = candidate.confidence;
                }
            }
            None => kept.push(candidate),
        }
    }
    *candidates = kept;
}

/// `<script type="application/ld+json">…</script>` blocks, in document order.
fn json_ld_blocks(html: &str) -> Vec<String> {
    let lowered = html.to_ascii_lowercase();
    let mut blocks: Vec<String> = Vec::new();
    let mut search_from = 0usize;
    while let Some(offset) = lowered[search_from..].find("<script") {
        let start = search_from + offset;
        let Some(tag_end_offset) = lowered[start..].find('>') else {
            break;
        };
        let tag_end = start + tag_end_offset;
        let tag = &lowered[start..tag_end];
        let is_json_ld = tag.contains("application/ld+json");
        if is_json_ld {
            if let Some(close_offset) = lowered[tag_end..].find("</script>") {
                let body_start = tag_end + 1;
                let body_end = tag_end + close_offset;
                blocks.push(html[body_start..body_end].to_string());
                search_from = body_end;
                continue;
            }
        }
        search_from = tag_end + 1;
    }
    blocks
}

/// Recursively collect `Organization` nodes (handles `@graph`, arrays, and
/// nested `subOrganization`/`parentOrganization`).
fn collect_organizations(value: &serde_json::Value, out: &mut Vec<OrganizationNode>) {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                collect_organizations(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            if is_organization(map.get("@type")) {
                out.push(OrganizationNode {
                    name: map
                        .get("name")
                        .or_else(|| map.get("legalName"))
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                    url: map
                        .get("url")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                    email: map
                        .get("email")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                    country: map.get("address").and_then(address_country),
                });
            }
            for (key, nested) in map {
                if key == "address" {
                    continue;
                }
                if nested.is_object() || nested.is_array() {
                    collect_organizations(nested, out);
                }
            }
        }
        _ => {}
    }
}

fn is_organization(value: Option<&serde_json::Value>) -> bool {
    match value {
        Some(serde_json::Value::String(kind)) => kind.eq_ignore_ascii_case("Organization"),
        Some(serde_json::Value::Array(kinds)) => kinds.iter().any(|kind| {
            kind.as_str()
                .map(|kind| kind.eq_ignore_ascii_case("Organization"))
                .unwrap_or(false)
        }),
        _ => false,
    }
}

/// `address.addressCountry` is either a string or a `Country` object.
fn address_country(address: &serde_json::Value) -> Option<String> {
    match address {
        serde_json::Value::String(country) => Some(country.trim().to_string()),
        serde_json::Value::Object(map) => map
            .get("addressCountry")
            .and_then(|country| match country {
                serde_json::Value::String(value) => Some(value.trim().to_string()),
                serde_json::Value::Object(nested) => nested
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
                _ => None,
            })
            .filter(|value| !value.is_empty()),
        _ => None,
    }
}

/// Distinct, normalized `mailto:` addresses in document order.
fn mailto_emails(html: &str) -> Vec<String> {
    let lowered = html.to_ascii_lowercase();
    let mut emails: Vec<String> = Vec::new();
    let mut search_from = 0usize;
    while let Some(offset) = lowered[search_from..].find("mailto:") {
        let start = search_from + offset + "mailto:".len();
        let rest = &html[start..];
        let end = rest
            .find(|c: char| {
                c.is_whitespace()
                    || matches!(
                        c,
                        '"' | '\'' | '<' | '>' | ')' | '}' | ']' | ',' | ';' | '?'
                    )
            })
            .unwrap_or(rest.len());
        if let Some(email) = normalize_email(&rest[..end]) {
            if !emails.contains(&email) {
                emails.push(email);
            }
        }
        search_from = start + end;
        if search_from >= html.len() {
            break;
        }
    }
    emails
}
