//! Hardened scrape fetch layer with deterministic challenge classification.
//!
//! This is the ONE way any ApexMail discovery source may fetch a public page.
//! It exists because the previous path had no fetch discipline at all: one
//! attempt, no politeness, and, the invariant the owner's plan closes with —
//! **no way to tell a CAPTCHA/challenge page from data**. A 403 was reported
//! as a credentials problem, a 429 as "rate limited", and a 200 challenge
//! shell was handed to the JSON parser or read as an empty result.
//!
//! # Guarantees
//!
//! * **A blocked body is never data.** [`ScrapeClient::fetch`] returns
//!   [`ScrapedPage`] only for a response that classification says is `ok`;
//!   every blocked outcome is a typed [`FetchError::Blocked`] carrying the
//!   evidence (classification, status, markers). There is no code path that
//!   returns a challenge body to a parser, and therefore none that can count
//!   a challenge as zero results.
//! * **Deterministic classification.** Marker tables below drive
//!   [`classify_response`]; the rules are a fixed decision table, not
//!   heuristics on vibes, and each challenge family has a fixture pinning it
//!   (`tests/scrape_challenges.rs`).
//! * **No bypass.** There is no challenge solving, no cookie injection, no
//!   proxy rotation or residential exit pool, no stealth browser, no
//!   "disable robots" switch and no path behind a login. The only response
//!   to a block is to back off and, for the permanent-exclusion reasons
//!   below, to leave the host alone for good.
//! * **Politeness and robots.** Per-host minimum interval, optional
//!   `Crawl-delay`, and `robots.txt` evaluation (RFC 9309 shape: 4xx means
//!   allow, 5xx or an unreachable robots.txt means DISALLOW, fail closed).
//!   Robots is not configurable off.
//! * **Permanent host exclusion.** A CAPTCHA page, a robots.txt disallow,
//!   HTTP 401/403 or three 429 responses in a row mark the host excluded for
//!   good. The state is persisted in `sales_scrape_host_health` and enforced
//!   before the first byte of the next attempt (not even `robots.txt` is
//!   fetched again); only the owner can lift it, with a written reason in the
//!   exclusion audit log.
//! * **Bounded everything.** Total and connect timeouts, bounded retries
//!   with exponential backoff plus jitter on transient outcomes only, a
//!   response size cap, a content-type allowlist, and a redirect policy that
//!   follows at most N same-host hops and never a cross-host hop (so no
//!   credential or cookie can travel to another origin).
//! * **Persistent host health.** Recent failures/blocks feed a per-host
//!   backoff that survives process restarts through
//!   `sales_scrape_host_health` (see [`super::blocked`]) and is surfaced in
//!   admin.
//!
//! # Decision table (the whole classification)
//!
//! | matched markers | status | outcome |
//! |---|---|---|
//! | `cf-mitigated: challenge` header | any | `blocked_captcha` |
//! | vendor challenge infrastructure (`__cf_chl_opt`, `/cdn-cgi/challenge-platform/`, `incap_ses`, `px-captcha`, `captcha-delivery.com`, …) | any | `blocked_captcha` |
//! | CAPTCHA widget embed (reCAPTCHA/hCaptcha/Turnstile) | 403 / 429 / 503 | `blocked_captcha` |
//! | ≥2 challenge-shell phrases | any | `blocked_captcha` |
//! |, | 401 / 451 | `blocked_policy` |
//! |, | 403 | `blocked_policy` |
//! |, | 408 / 425 / 429 / 500 / 502 / 503 / 504 | `blocked_transient` |
//! |, | network error / timeout | `blocked_transient` |
//! |, | other | `ok` (the caller decides: non-2xx is
//!   [`FetchError::HttpStatus`], never a data row) |
//!
//! Deliberate asymmetry, documented so it cannot be mistaken for an
//! oversight: a single challenge-shell phrase on a 2xx page is NOT a block
//! (a blog post quoting "Just a moment…" must not lose its data), while a
//! vendor infrastructure marker on a 2xx page IS a block (those strings do
//! not occur in page content, and parsing a challenge script as a document
//! is the failure the owner's invariant forbids).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// The four documented fetch outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FetchClassification {
    Ok,
    BlockedCaptcha,
    BlockedPolicy,
    BlockedTransient,
}

impl FetchClassification {
    /// Exact wire/persisted string (`sales_source_runs.status`,
    /// `sales_scrape_blocked_sources.classification`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::BlockedCaptcha => "blocked_captcha",
            Self::BlockedPolicy => "blocked_policy",
            Self::BlockedTransient => "blocked_transient",
        }
    }

    /// Parse a persisted value; an unknown string is `None`, callers must
    /// not invent a classification.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "ok" => Some(Self::Ok),
            "blocked_captcha" => Some(Self::BlockedCaptcha),
            "blocked_policy" => Some(Self::BlockedPolicy),
            "blocked_transient" => Some(Self::BlockedTransient),
            _ => None,
        }
    }

    pub fn is_blocked(self) -> bool {
        matches!(
            self,
            Self::BlockedCaptcha | Self::BlockedPolicy | Self::BlockedTransient
        )
    }

    /// Only transient blocks are retried. A CAPTCHA is never retried and a
    /// policy block is never retried at all; a CAPTCHA also excludes the
    /// host permanently.
    pub fn is_retryable(self) -> bool {
        matches!(self, Self::BlockedTransient)
    }
}

impl std::fmt::Display for FetchClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The challenge family a marker belongs to. Names are the persisted
/// vocabulary, so they are stable strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    Recaptcha,
    Hcaptcha,
    Turnstile,
    Cloudflare,
    Imperva,
    Akamai,
    DataDome,
    PerimeterX,
    JsShell,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Recaptcha => "recaptcha",
            Self::Hcaptcha => "hcaptcha",
            Self::Turnstile => "turnstile",
            Self::Cloudflare => "cloudflare",
            Self::Imperva => "imperva",
            Self::Akamai => "akamai",
            Self::DataDome => "datadome",
            Self::PerimeterX => "perimeterx",
            Self::JsShell => "js_shell",
        }
    }
}

/// How strongly a matched marker implies "this response is a challenge page".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MarkerStrength {
    /// Challenge infrastructure that does not occur in page content.
    VendorInfrastructure,
    /// A CAPTCHA widget embed (a contact form may legitimately carry one).
    Widget,
    /// Challenge-page prose (can legitimately appear in prose).
    Shell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MarkerScope {
    Body,
    Header,
}

/// One marker in the detection table. `needle` is matched
/// case-insensitively; a header marker matches the header NAME and, when
/// `value_contains` is set, the header value must contain that string.
struct ChallengeMarker {
    kind: ChallengeKind,
    strength: MarkerStrength,
    scope: MarkerScope,
    needle: &'static str,
    value_contains: Option<&'static str>,
}

const fn header_marker(
    kind: ChallengeKind,
    strength: MarkerStrength,
    name: &'static str,
    value_contains: Option<&'static str>,
) -> ChallengeMarker {
    ChallengeMarker {
        kind,
        strength,
        scope: MarkerScope::Header,
        needle: name,
        value_contains,
    }
}

const fn body_marker(
    kind: ChallengeKind,
    strength: MarkerStrength,
    needle: &'static str,
) -> ChallengeMarker {
    ChallengeMarker {
        kind,
        strength,
        scope: MarkerScope::Body,
        needle,
        value_contains: None,
    }
}

/// The complete marker table. Adding a vendor means adding rows here (the
/// table is the documentation), never a heuristic elsewhere.
const CHALLENGE_MARKERS: &[ChallengeMarker] = &[
    // --- Cloudflare: the response header Cloudflare itself sets on a
    // mitigated (challenged) response. ---
    header_marker(
        ChallengeKind::Cloudflare,
        MarkerStrength::VendorInfrastructure,
        "cf-mitigated",
        Some("challenge"),
    ),
    // --- Cloudflare challenge infrastructure, body. ---
    body_marker(
        ChallengeKind::Cloudflare,
        MarkerStrength::VendorInfrastructure,
        "__cf_chl_opt",
    ),
    body_marker(
        ChallengeKind::Cloudflare,
        MarkerStrength::VendorInfrastructure,
        "__cf_chl_tk",
    ),
    body_marker(
        ChallengeKind::Cloudflare,
        MarkerStrength::VendorInfrastructure,
        "/cdn-cgi/challenge-platform/",
    ),
    body_marker(
        ChallengeKind::Cloudflare,
        MarkerStrength::VendorInfrastructure,
        "cf-browser-verification",
    ),
    body_marker(
        ChallengeKind::Cloudflare,
        MarkerStrength::VendorInfrastructure,
        "cf_chl_prog",
    ),
    // --- Cloudflare challenge shells (the IUAM/managed-challenge prose). ---
    body_marker(
        ChallengeKind::Cloudflare,
        MarkerStrength::Shell,
        "just a moment",
    ),
    body_marker(
        ChallengeKind::Cloudflare,
        MarkerStrength::Shell,
        "checking your browser before accessing",
    ),
    body_marker(
        ChallengeKind::Cloudflare,
        MarkerStrength::Shell,
        "enable javascript and cookies to continue",
    ),
    body_marker(
        ChallengeKind::Cloudflare,
        MarkerStrength::Shell,
        "verifying you are human",
    ),
    body_marker(
        ChallengeKind::Cloudflare,
        MarkerStrength::Shell,
        "ddos protection by cloudflare",
    ),
    // --- reCAPTCHA widget embeds. ---
    body_marker(
        ChallengeKind::Recaptcha,
        MarkerStrength::Widget,
        "g-recaptcha",
    ),
    body_marker(
        ChallengeKind::Recaptcha,
        MarkerStrength::Widget,
        "www.google.com/recaptcha",
    ),
    body_marker(
        ChallengeKind::Recaptcha,
        MarkerStrength::Widget,
        "recaptcha/api.js",
    ),
    body_marker(
        ChallengeKind::Recaptcha,
        MarkerStrength::Widget,
        "g-recaptcha-response",
    ),
    // --- hCaptcha widget embeds. ---
    body_marker(ChallengeKind::Hcaptcha, MarkerStrength::Widget, "h-captcha"),
    body_marker(
        ChallengeKind::Hcaptcha,
        MarkerStrength::Widget,
        "hcaptcha.com/1/api.js",
    ),
    body_marker(
        ChallengeKind::Hcaptcha,
        MarkerStrength::Widget,
        "h-captcha-response",
    ),
    // --- Cloudflare Turnstile widget embeds. ---
    body_marker(
        ChallengeKind::Turnstile,
        MarkerStrength::Widget,
        "cf-turnstile",
    ),
    body_marker(
        ChallengeKind::Turnstile,
        MarkerStrength::Widget,
        "challenges.cloudflare.com/turnstile",
    ),
    body_marker(
        ChallengeKind::Turnstile,
        MarkerStrength::Widget,
        "turnstile.render",
    ),
    // --- Imperva / Incapsula. ---
    body_marker(
        ChallengeKind::Imperva,
        MarkerStrength::VendorInfrastructure,
        "_incapsula_resource",
    ),
    body_marker(
        ChallengeKind::Imperva,
        MarkerStrength::VendorInfrastructure,
        "incap_ses",
    ),
    body_marker(
        ChallengeKind::Imperva,
        MarkerStrength::VendorInfrastructure,
        "visid_incap",
    ),
    body_marker(
        ChallengeKind::Imperva,
        MarkerStrength::Shell,
        "incapsula incident id",
    ),
    body_marker(
        ChallengeKind::Imperva,
        MarkerStrength::Shell,
        "request unsuccessful. incapsula",
    ),
    // --- Akamai Bot Manager. `_abck` is a bot-detection cookie that also
    // appears on protected-but-served pages, so it is a Shell marker (it
    // needs a companion); "Access Denied" + a Reference # is the classic
    // Akamai block page. ---
    body_marker(
        ChallengeKind::Akamai,
        MarkerStrength::VendorInfrastructure,
        "akamai bot manager",
    ),
    body_marker(ChallengeKind::Akamai, MarkerStrength::Shell, "_abck"),
    body_marker(
        ChallengeKind::Akamai,
        MarkerStrength::Shell,
        "reference #18.",
    ),
    body_marker(
        ChallengeKind::Akamai,
        MarkerStrength::Shell,
        "reference #9.",
    ),
    // --- DataDome. ---
    body_marker(
        ChallengeKind::DataDome,
        MarkerStrength::VendorInfrastructure,
        "captcha-delivery.com",
    ),
    body_marker(ChallengeKind::DataDome, MarkerStrength::Shell, "datadome"),
    // --- PerimeterX / HUMAN. ---
    body_marker(
        ChallengeKind::PerimeterX,
        MarkerStrength::VendorInfrastructure,
        "px-captcha",
    ),
    body_marker(
        ChallengeKind::PerimeterX,
        MarkerStrength::Shell,
        "perimeterx",
    ),
    body_marker(
        ChallengeKind::PerimeterX,
        MarkerStrength::Shell,
        "please verify you are a human",
    ),
    // --- Vendor-neutral JS-challenge shells. ---
    body_marker(
        ChallengeKind::JsShell,
        MarkerStrength::Shell,
        "please enable javascript",
    ),
    body_marker(
        ChallengeKind::JsShell,
        MarkerStrength::Shell,
        "javascript is required",
    ),
];

/// A response reduced to what classification needs, no reqwest types, so
/// every challenge family can be pinned with a plain-text fixture.
#[derive(Debug, Clone, Default)]
pub struct ResponseSnapshot {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl ResponseSnapshot {
    pub fn new(status: u16, headers: Vec<(String, String)>, body: impl Into<String>) -> Self {
        Self {
            status,
            headers,
            body: body.into(),
        }
    }

    /// Case-insensitive header lookup (first match wins).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Every value of a repeated header, in order.
    pub fn header_values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect()
    }
}

/// Everything classification recorded about a challenge response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChallengeEvidence {
    pub classification: FetchClassification,
    /// Challenge families that matched, in table order, de-duplicated.
    pub kinds: Vec<&'static str>,
    /// `kind:marker` strings, the exact evidence persisted in the queue.
    pub markers: Vec<String>,
}

/// The result of classifying one response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClassifiedResponse {
    pub classification: FetchClassification,
    pub challenge: Option<ChallengeEvidence>,
    /// `Retry-After` in seconds, when the server sent a bounded integer.
    pub retry_after_seconds: Option<u64>,
}

/// Detects a challenge page. `None` means no marker matched, the caller
/// still has to verify the status and content type before treating the body
/// as data ([`classify_response`] documents the full table).
pub fn detect_challenge(snapshot: &ResponseSnapshot) -> Option<ChallengeEvidence> {
    let lowered = snapshot.body.to_ascii_lowercase();
    let mut hits: Vec<&ChallengeMarker> = Vec::new();
    for marker in CHALLENGE_MARKERS {
        let matched = match marker.scope {
            MarkerScope::Body => lowered.contains(marker.needle),
            MarkerScope::Header => snapshot
                .header(marker.needle)
                .map(|value| match marker.value_contains {
                    Some(needle) => value.to_ascii_lowercase().contains(needle),
                    None => true,
                })
                .unwrap_or(false),
        };
        if matched {
            hits.push(marker);
        }
    }
    if hits.is_empty() {
        return None;
    }

    let vendor_infrastructure = hits
        .iter()
        .any(|marker| marker.strength == MarkerStrength::VendorInfrastructure);
    let widget = hits
        .iter()
        .any(|marker| marker.strength == MarkerStrength::Widget);
    let shells = hits
        .iter()
        .filter(|marker| marker.strength == MarkerStrength::Shell)
        .count();
    let challenge_status = matches!(snapshot.status, 403 | 429 | 503);

    let is_challenge =
        vendor_infrastructure || (challenge_status && (widget || shells > 0)) || shells >= 2;
    if !is_challenge {
        return None;
    }

    let mut kinds: Vec<&'static str> = Vec::new();
    let mut markers: Vec<String> = Vec::new();
    for marker in hits {
        let kind = marker.kind.as_str();
        if !kinds.contains(&kind) {
            kinds.push(kind);
        }
        let rendered = if marker.scope == MarkerScope::Header {
            format!("{kind}:header:{}", marker.needle)
        } else {
            format!("{kind}:{}", marker.needle)
        };
        if !markers.contains(&rendered) {
            markers.push(rendered);
        }
    }

    Some(ChallengeEvidence {
        classification: FetchClassification::BlockedCaptcha,
        kinds,
        markers,
    })
}

/// Parses a bounded integer `Retry-After` (seconds only; an HTTP-date form is
/// deliberately not guessed at, the backoff window still applies).
fn parse_retry_after(snapshot: &ResponseSnapshot) -> Option<u64> {
    let raw = snapshot.header("retry-after")?.trim();
    let seconds: u64 = raw.parse().ok()?;
    Some(seconds.min(MAX_RETRY_AFTER_SECONDS))
}

/// Ceiling for a server-provided `Retry-After`.
pub const MAX_RETRY_AFTER_SECONDS: u64 = 3_600;

/// The whole decision table. `ok` means "no block detected": the caller still
/// refuses non-2xx statuses as [`FetchError::HttpStatus`], so a 404 can never
/// become a data row either.
pub fn classify_response(snapshot: &ResponseSnapshot) -> ClassifiedResponse {
    let retry_after_seconds = parse_retry_after(snapshot);

    if let Some(challenge) = detect_challenge(snapshot) {
        return ClassifiedResponse {
            classification: challenge.classification,
            challenge: Some(challenge),
            retry_after_seconds,
        };
    }

    let classification = match snapshot.status {
        401 => FetchClassification::BlockedPolicy,
        403 => FetchClassification::BlockedPolicy,
        451 => FetchClassification::BlockedPolicy,
        408 | 425 | 429 => FetchClassification::BlockedTransient,
        500 | 502 | 503 | 504 => FetchClassification::BlockedTransient,
        _ => FetchClassification::Ok,
    };
    ClassifiedResponse {
        classification,
        challenge: None,
        retry_after_seconds,
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Default user agent. It names the crawler and where to complain; robots
/// group matching uses its first token (`ApexMail`).
pub const DEFAULT_USER_AGENT: &str = "ApexMail/1.0 (+https://apexmail.ee/about; discovery crawler)";
pub const DEFAULT_TIMEOUT_MS: u64 = 20_000;
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 5_000;
pub const DEFAULT_MAX_RETRIES: u32 = 2;
pub const DEFAULT_BACKOFF_BASE_MS: u64 = 250;
pub const DEFAULT_HOST_MIN_INTERVAL_MS: u64 = 1_000;
pub const DEFAULT_MAX_HOST_BLOCK_BACKOFF_MS: u64 = 3_600_000;
pub const DEFAULT_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
pub const DEFAULT_MAX_REDIRECTS: usize = 5;
pub const DEFAULT_ROBOTS_TTL_SECS: u64 = 3_600;
/// Jitter added to a retry sleep, as a fraction of the delay (per mille).
pub const BACKOFF_JITTER_PERMILLE: u64 = 250;

/// Content types a scraped document may declare.
pub const DEFAULT_ALLOWED_CONTENT_TYPES: &[&str] = &[
    "text/html",
    "application/xhtml+xml",
    "application/json",
    "text/plain",
    "application/xml",
    "text/xml",
];

/// Fetch discipline. Every knob is env-overridable, and every override is
/// validated (an invalid value keeps the default and logs a warning rather
/// than silently widening the policy).
#[derive(Debug, Clone, PartialEq)]
pub struct ScrapeConfig {
    pub user_agent: String,
    pub timeout: Duration,
    pub connect_timeout: Duration,
    pub max_retries: u32,
    pub backoff_base: Duration,
    pub host_min_interval: Duration,
    pub max_host_block_backoff: Duration,
    pub max_body_bytes: usize,
    pub allowed_content_types: Vec<String>,
    pub max_redirects: usize,
    pub robots_ttl: Duration,
}

impl Default for ScrapeConfig {
    fn default() -> Self {
        Self {
            user_agent: DEFAULT_USER_AGENT.to_string(),
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            connect_timeout: Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS),
            max_retries: DEFAULT_MAX_RETRIES,
            backoff_base: Duration::from_millis(DEFAULT_BACKOFF_BASE_MS),
            host_min_interval: Duration::from_millis(DEFAULT_HOST_MIN_INTERVAL_MS),
            max_host_block_backoff: Duration::from_millis(DEFAULT_MAX_HOST_BLOCK_BACKOFF_MS),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            allowed_content_types: DEFAULT_ALLOWED_CONTENT_TYPES
                .iter()
                .map(|value| value.to_string())
                .collect(),
            max_redirects: DEFAULT_MAX_REDIRECTS,
            robots_ttl: Duration::from_secs(DEFAULT_ROBOTS_TTL_SECS),
        }
    }
}

impl ScrapeConfig {
    /// Read the `SCRAPE_*` environment overrides. There is deliberately NO
    /// `SCRAPE_RESPECT_ROBOTS` switch: robots is policy, not a knob.
    pub fn from_env() -> Self {
        let mut config = Self::default();
        if let Some(user_agent) = env_string("SCRAPE_USER_AGENT") {
            config.user_agent = user_agent;
        }
        config.timeout = env_duration_ms("SCRAPE_TIMEOUT_MS", config.timeout);
        config.connect_timeout =
            env_duration_ms("SCRAPE_CONNECT_TIMEOUT_MS", config.connect_timeout);
        config.backoff_base = env_duration_ms("SCRAPE_BACKOFF_BASE_MS", config.backoff_base);
        config.host_min_interval =
            env_duration_ms("SCRAPE_HOST_MIN_INTERVAL_MS", config.host_min_interval);
        config.max_host_block_backoff = env_duration_ms(
            "SCRAPE_MAX_HOST_BLOCK_BACKOFF_MS",
            config.max_host_block_backoff,
        );
        config.robots_ttl = env_duration_ms("SCRAPE_ROBOTS_TTL_MS", config.robots_ttl);
        if let Some(value) = env_u64("SCRAPE_MAX_RETRIES") {
            config.max_retries = value.min(10) as u32;
        }
        if let Some(value) = env_u64("SCRAPE_MAX_BODY_BYTES") {
            config.max_body_bytes = value.clamp(1_024, 64 * 1024 * 1024) as usize;
        }
        if let Some(value) = env_u64("SCRAPE_MAX_REDIRECTS") {
            config.max_redirects = value.min(20) as usize;
        }
        if let Some(value) = env_string("SCRAPE_ALLOWED_CONTENT_TYPES") {
            let types: Vec<String> = value
                .split(',')
                .map(|entry| entry.trim().to_ascii_lowercase())
                .filter(|entry| !entry.is_empty())
                .collect();
            if types.is_empty() {
                tracing::warn!(
                    "SCRAPE_ALLOWED_CONTENT_TYPES is empty; keeping the default allowlist"
                );
            } else {
                config.allowed_content_types = types;
            }
        }
        config
    }

    /// The robots user-agent token: the leading product token of the UA.
    pub fn robots_user_agent_token(&self) -> String {
        self.user_agent
            .split(['/', ' ', '('])
            .next()
            .unwrap_or("ApexMail")
            .to_string()
    }

    fn content_type_allowed(&self, content_type: Option<&str>) -> bool {
        let Some(content_type) = content_type else {
            // Fail closed: a document whose type we cannot verify is not
            // parsed. A register that wants to be read declares its type.
            return false;
        };
        let mime = content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        self.allowed_content_types
            .iter()
            .any(|allowed| allowed == &mime)
    }
}

fn env_string(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_u64(name: &str) -> Option<u64> {
    let raw = std::env::var(name).ok()?;
    match raw.trim().parse::<u64>() {
        Ok(value) => Some(value),
        Err(_) => {
            tracing::warn!(variable = name, value = %raw, "ignoring invalid scrape config value");
            None
        }
    }
}

fn env_duration_ms(name: &str, default: Duration) -> Duration {
    env_u64(name).map(Duration::from_millis).unwrap_or(default)
}

// ---------------------------------------------------------------------------
// Host health (politeness + backoff), shared across a process
// ---------------------------------------------------------------------------

/// Number of consecutive 429 responses that excludes a host permanently.
pub const RATE_LIMIT_EXCLUSION_THRESHOLD: u32 = 3;

/// Exclusion reasons persisted in `sales_scrape_host_health.exclusion_reason`.
/// The vocabulary is deliberately closed: every value is a condition the
/// owner's policy says must end public fetching for that host.
pub const EXCLUSION_CAPTCHA: &str = "captcha";
/// `robots.txt` disallowed the requested path.
pub const EXCLUSION_ROBOTS_DISALLOW: &str = "robots_disallow";
/// The server answered HTTP 401 (credentials required).
pub const EXCLUSION_HTTP_401: &str = "http_401";
/// The server answered HTTP 403 (access forbidden).
pub const EXCLUSION_HTTP_403: &str = "http_403";
/// Three 429 responses in a row (rate-limit exclusion).
pub const EXCLUSION_HTTP_429_REPEATED: &str = "http_429_repeated";

/// The permanent-exclusion reason for one block, if it is an exclusion
/// condition. 451 and other policy statuses are NOT exclusions: the owner's
/// sourcing policy names CAPTCHA, robots disallow, 401/403 and three
/// consecutive 429s.
pub fn exclusion_reason(
    classification: FetchClassification,
    status: Option<u16>,
) -> Option<&'static str> {
    match (classification, status) {
        (FetchClassification::BlockedCaptcha, _) => Some(EXCLUSION_CAPTCHA),
        (FetchClassification::BlockedPolicy, None) => Some(EXCLUSION_ROBOTS_DISALLOW),
        (FetchClassification::BlockedPolicy, Some(401)) => Some(EXCLUSION_HTTP_401),
        (FetchClassification::BlockedPolicy, Some(403)) => Some(EXCLUSION_HTTP_403),
        _ => None,
    }
}

/// Persisted per-host state (mirrors `sales_scrape_host_health`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HostState {
    pub host: String,
    pub consecutive_blocks: u32,
    pub total_blocks: u64,
    /// Consecutive 429 responses; reset by any other outcome. Reaching
    /// [`RATE_LIMIT_EXCLUSION_THRESHOLD`] excludes the host permanently.
    pub consecutive_429: u32,
    pub last_classification: Option<FetchClassification>,
    pub last_status: Option<u16>,
    pub last_blocked_at: Option<DateTime<Utc>>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub blocked_until: Option<DateTime<Utc>>,
    /// Set once, never cleared by a fetch. Only
    /// [`super::blocked::lift_host_exclusion`] clears it (owner-only).
    pub excluded_at: Option<DateTime<Utc>>,
    pub exclusion_reason: Option<String>,
}

impl HostState {
    fn new(host: &str) -> Self {
        Self {
            host: host.to_string(),
            consecutive_blocks: 0,
            total_blocks: 0,
            consecutive_429: 0,
            last_classification: None,
            last_status: None,
            last_blocked_at: None,
            last_success_at: None,
            blocked_until: None,
            excluded_at: None,
            exclusion_reason: None,
        }
    }

    /// Is this host permanently excluded from fetching?
    pub fn is_excluded(&self) -> bool {
        self.exclusion_reason.is_some()
    }

    /// Apply a permanent exclusion unless one is already recorded. The first
    /// reason wins: the state is permanent, so later failures must not
    /// rewrite the historical cause.
    fn exclude_for(&mut self, reason: &str, now: DateTime<Utc>) {
        if !self.is_excluded() {
            self.exclusion_reason = Some(reason.to_string());
            self.excluded_at = Some(now);
        }
    }
}

/// In-process enforcement of politeness and backoff, mirrored to the database
/// by [`super::blocked`]. Cloneable; all clones share one table.
#[derive(Debug, Clone)]
pub struct HostHealthRegistry {
    inner: Arc<Mutex<HashMap<String, HostState>>>,
    config: Arc<ScrapeConfig>,
    /// Enforcement clock, separate from the reported wall clock so a paused
    /// tokio clock makes the policy deterministically testable.
    blocked_until_instant: Arc<Mutex<HashMap<String, tokio::time::Instant>>>,
    next_request_at: Arc<Mutex<HashMap<String, tokio::time::Instant>>>,
}

impl HostHealthRegistry {
    pub fn new(config: Arc<ScrapeConfig>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            config,
            blocked_until_instant: Arc::new(Mutex::new(HashMap::new())),
            next_request_at: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Seed the registry from persisted state (a fresh process must not hand
    /// an attacking host a clean slate).
    pub fn hydrate(&self, state: HostState) {
        if let Some(until) = state.blocked_until {
            let remaining = (until - Utc::now()).to_std().unwrap_or_default();
            if !remaining.is_zero() {
                self.blocked_until_instant
                    .lock()
                    .insert(state.host.clone(), tokio::time::Instant::now() + remaining);
            }
        }
        self.inner.lock().insert(state.host.clone(), state);
    }

    pub fn snapshot(&self, host: &str) -> Option<HostState> {
        self.inner.lock().get(host).cloned()
    }

    /// All hosts currently tracked, sorted for a stable admin listing.
    pub fn snapshot_all(&self) -> Vec<HostState> {
        let mut states: Vec<HostState> = self.inner.lock().values().cloned().collect();
        states.sort_by(|a, b| a.host.cmp(&b.host));
        states
    }

    /// The active backoff window, if any.
    pub fn backoff_until(&self, host: &str) -> Option<tokio::time::Instant> {
        self.blocked_until_instant.lock().get(host).copied()
    }

    /// Wait out the per-host minimum interval. Robots `Crawl-delay` raises
    /// the interval for the call site that knows it.
    pub async fn wait_turn(&self, host: &str, interval: Duration) {
        let next = *self
            .next_request_at
            .lock()
            .get(host)
            .unwrap_or(&tokio::time::Instant::now());
        let deadline = next.max(tokio::time::Instant::now());
        if deadline > tokio::time::Instant::now() {
            tokio::time::sleep_until(deadline).await;
        }
        self.note_request(host, interval);
    }

    /// Record that a request is about to go out to `host`.
    fn note_request(&self, host: &str, interval: Duration) {
        self.next_request_at
            .lock()
            .insert(host.to_string(), tokio::time::Instant::now() + interval);
    }

    /// A successful fetch clears the backoff window, the failure streak and
    /// the 429 streak. It deliberately does NOT clear a permanent exclusion:
    /// only the owner can lift that.
    pub fn note_success(&self, host: &str) -> HostState {
        let mut inner = self.inner.lock();
        let state = inner
            .entry(host.to_string())
            .or_insert_with(|| HostState::new(host));
        state.consecutive_blocks = 0;
        state.consecutive_429 = 0;
        state.last_classification = Some(FetchClassification::Ok);
        state.last_success_at = Some(Utc::now());
        state.blocked_until = None;
        self.blocked_until_instant.lock().remove(host);
        state.clone()
    }

    /// Record one 429 response that will be retried. The final 429 of a
    /// fetch goes through [`Self::note_blocked_with_floor`]; this method is
    /// called for the intermediate attempts so the "three in a row"
    /// exclusion counts every observed response exactly once.
    pub fn note_rate_limited(&self, host: &str) -> HostState {
        let mut inner = self.inner.lock();
        let state = inner
            .entry(host.to_string())
            .or_insert_with(|| HostState::new(host));
        let now = Utc::now();
        state.consecutive_429 = state.consecutive_429.saturating_add(1);
        state.last_classification = Some(FetchClassification::BlockedTransient);
        state.last_status = Some(429);
        state.last_blocked_at = Some(now);
        if state.consecutive_429 >= RATE_LIMIT_EXCLUSION_THRESHOLD {
            state.exclude_for(EXCLUSION_HTTP_429_REPEATED, now);
        }
        state.clone()
    }

    /// Record a block and compute the next backoff window. Returns the
    /// updated state; the window is `min(base * 2^(n-1), cap)` plus jitter.
    pub fn note_blocked(
        &self,
        host: &str,
        classification: FetchClassification,
        status: Option<u16>,
    ) -> HostState {
        self.note_blocked_with_floor(host, classification, status, Duration::ZERO)
    }

    /// As [`Self::note_blocked`], but the window is at least `floor` (used
    /// when the server sent `Retry-After`).
    pub fn note_blocked_with_floor(
        &self,
        host: &str,
        classification: FetchClassification,
        status: Option<u16>,
        floor: Duration,
    ) -> HostState {
        let mut inner = self.inner.lock();
        let state = inner
            .entry(host.to_string())
            .or_insert_with(|| HostState::new(host));
        let now = Utc::now();
        state.consecutive_blocks = state.consecutive_blocks.saturating_add(1);
        state.total_blocks = state.total_blocks.saturating_add(1);
        state.last_classification = Some(classification);
        state.last_status = status;
        state.last_blocked_at = Some(now);

        // The 429 streak counts every response: reset it on any outcome
        // that is not a 429, and grow it on a 429. The third consecutive
        // response is the permanent-exclusion trigger.
        if status == Some(429) {
            state.consecutive_429 = state.consecutive_429.saturating_add(1);
            if state.consecutive_429 >= RATE_LIMIT_EXCLUSION_THRESHOLD {
                state.exclude_for(EXCLUSION_HTTP_429_REPEATED, now);
            }
        } else {
            state.consecutive_429 = 0;
        }
        if let Some(reason) = exclusion_reason(classification, status) {
            state.exclude_for(reason, now);
        }

        // A robots disallow is a stable condition; a backoff window would
        // not change it, so it must not grow the host's penalty.
        let window = if classification == FetchClassification::BlockedPolicy
            && status.is_none()
            && floor.is_zero()
        {
            Duration::ZERO
        } else {
            self.backoff_window(state.consecutive_blocks).max(floor)
        };

        if window.is_zero() {
            // A stable block (robots disallow) carries no window: the host is
            // not being throttled, it is simply not ours to fetch.
            self.blocked_until_instant.lock().remove(host);
            state.blocked_until = None;
            self.next_request_at.lock().insert(
                host.to_string(),
                tokio::time::Instant::now() + self.config.host_min_interval,
            );
        } else {
            let instant = tokio::time::Instant::now() + window;
            self.blocked_until_instant
                .lock()
                .insert(host.to_string(), instant);
            state.blocked_until =
                Some(Utc::now() + chrono::Duration::from_std(window).unwrap_or_default());
            self.next_request_at
                .lock()
                .insert(host.to_string(), instant);
        }
        state.clone()
    }

    fn backoff_window(&self, consecutive_blocks: u32) -> Duration {
        let exponent = consecutive_blocks.saturating_sub(1).min(20);
        let base = self.config.backoff_base.as_millis() as u64;
        let capped = base
            .saturating_mul(1u64 << exponent)
            .min(self.config.max_host_block_backoff.as_millis() as u64);
        let jitter_span = capped.saturating_mul(BACKOFF_JITTER_PERMILLE) / 1_000;
        let jitter = if jitter_span == 0 {
            0
        } else {
            rand::rng().random_range(0..=jitter_span)
        };
        Duration::from_millis(capped.saturating_add(jitter))
    }

    /// Backoff window for retry attempt `attempt` (1-based), the same
    /// growing schedule the per-host block backoff uses, so a retry storm
    /// cannot outpace the polite pace.
    pub fn backoff_window_for(&self, attempt: u32) -> Duration {
        self.backoff_window(attempt.max(1))
    }

    /// Clear a permanent exclusion. This is owner-only policy, exposed
    /// through [`super::blocked::lift_host_exclusion`], which is the only
    /// caller; the registry itself trusts that the owner decision and its
    /// written reason were already recorded.
    pub fn lift_exclusion(&self, host: &str) -> Option<HostState> {
        let mut inner = self.inner.lock();
        let state = inner.get_mut(host)?;
        state.excluded_at = None;
        state.exclusion_reason = None;
        state.consecutive_blocks = 0;
        state.consecutive_429 = 0;
        state.blocked_until = None;
        self.blocked_until_instant.lock().remove(host);
        Some(state.clone())
    }
}

// ---------------------------------------------------------------------------
// robots.txt (RFC 9309 shape, fail closed)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RobotsRule {
    pub allow: bool,
    pub path: String,
}

/// Why robots allows or disallows, persisted/visible, never guessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RobotsState {
    /// No matching group and no `*` group: nothing is disallowed.
    NoRules,
    /// robots.txt was fetched and parsed.
    Parsed,
    /// robots.txt could not be fetched (5xx, network failure, or a block):
    /// fail closed, an unknown policy is not permission.
    Unavailable,
    /// A 4xx response: RFC 9309 says the crawler may access anything.
    Absent,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RobotsRules {
    pub state: RobotsState,
    pub rules: Vec<RobotsRule>,
    pub crawl_delay: Option<Duration>,
}

impl RobotsRules {
    pub fn unavailable() -> Self {
        Self {
            state: RobotsState::Unavailable,
            rules: Vec::new(),
            crawl_delay: None,
        }
    }

    /// Longest-match wins; a tie goes to `Allow` (RFC 9309 §2.2.2).
    pub fn allows(&self, path: &str) -> bool {
        match self.state {
            RobotsState::Unavailable => false,
            RobotsState::Absent | RobotsState::NoRules => true,
            RobotsState::Parsed => {
                let path = if path.is_empty() { "/" } else { path };
                let mut best: Option<&RobotsRule> = None;
                for rule in &self.rules {
                    if rule.path.is_empty() || !path.starts_with(rule.path.as_str()) {
                        continue;
                    }
                    match best {
                        Some(current) if current.path.len() > rule.path.len() => {}
                        Some(current) if current.path.len() == rule.path.len() && current.allow => {
                            // An allow already won the tie.
                        }
                        _ => best = Some(rule),
                    }
                }
                best.map(|rule| rule.allow).unwrap_or(true)
            }
        }
    }
}

/// Parse `robots.txt` for one user-agent token.
///
/// A group naming our token takes precedence over `*` (RFC 9309 §2.2.1);
/// entities and comments are handled the way the RFC describes; nothing is
/// inferred from malformed lines beyond ignoring them.
pub fn parse_robots(body: &str, user_agent_token: &str) -> RobotsRules {
    struct Group {
        agents: Vec<String>,
        rules: Vec<RobotsRule>,
        crawl_delay: Option<Duration>,
    }

    let mut groups: Vec<Group> = Vec::new();
    let mut current: Option<usize> = None;
    let mut last_was_agent = false;

    for raw_line in body.lines() {
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        let field = field.trim().to_ascii_lowercase();
        let value = value.trim();
        match field.as_str() {
            "user-agent" => {
                if !last_was_agent || current.is_none() {
                    groups.push(Group {
                        agents: Vec::new(),
                        rules: Vec::new(),
                        crawl_delay: None,
                    });
                    current = Some(groups.len() - 1);
                }
                if let Some(index) = current {
                    groups[index].agents.push(value.to_ascii_lowercase());
                }
                last_was_agent = true;
            }
            "disallow" | "allow" => {
                if let Some(index) = current {
                    if !value.is_empty() {
                        groups[index].rules.push(RobotsRule {
                            allow: field == "allow",
                            path: value.to_string(),
                        });
                    }
                    last_was_agent = false;
                }
            }
            "crawl-delay" => {
                if let Some(index) = current {
                    if let Ok(seconds) = value.parse::<f64>() {
                        if seconds.is_finite() && seconds > 0.0 && seconds <= 3_600.0 {
                            groups[index].crawl_delay = Some(Duration::from_secs_f64(seconds));
                        }
                    }
                    last_was_agent = false;
                }
            }
            _ => {
                last_was_agent = false;
            }
        }
    }

    let token = user_agent_token.to_ascii_lowercase();
    let specific = groups.iter().find(|group| {
        group
            .agents
            .iter()
            .any(|agent| agent != "*" && agent.contains(&token))
    });
    let wildcard = groups
        .iter()
        .find(|group| group.agents.iter().any(|a| a == "*"));
    match specific.or(wildcard) {
        Some(group) => RobotsRules {
            state: if group.rules.is_empty() {
                RobotsState::NoRules
            } else {
                RobotsState::Parsed
            },
            rules: group.rules.clone(),
            crawl_delay: group.crawl_delay,
        },
        None => RobotsRules {
            state: RobotsState::NoRules,
            rules: Vec::new(),
            crawl_delay: None,
        },
    }
}

// ---------------------------------------------------------------------------
// Fetch outcomes
// ---------------------------------------------------------------------------

/// A fetched, allowed document. Constructed ONLY for `ok` classifications —
/// this type is the invariant "a blocked body is never data".
#[derive(Debug, Clone, Serialize)]
pub struct ScrapedPage {
    /// Final URL after same-host redirects.
    pub url: String,
    pub status: u16,
    pub content_type: String,
    pub body: String,
    pub body_bytes: usize,
    /// SHA-256 of the body, the provenance snapshot hash.
    pub sha256: String,
    pub fetched_at: DateTime<Utc>,
    pub attempts: u32,
}

impl ScrapedPage {
    pub fn text(&self) -> &str {
        &self.body
    }
}

/// The structured, persistable form of one blocked fetch, the evidence the
/// review queue stores.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockedEvidence {
    pub classification: FetchClassification,
    pub url: String,
    pub host: String,
    pub http_status: Option<u16>,
    /// `kind:marker` evidence strings, plus transport-level markers
    /// (`robots_disallow`, `host_backoff`, `transport_error`).
    pub markers: Vec<String>,
    pub detail: String,
    pub retry_after_seconds: Option<u64>,
    pub fetched_at: DateTime<Utc>,
}

impl BlockedEvidence {
    /// The retry window as a duration, when the server named one.
    pub fn retry_after(&self) -> Option<Duration> {
        self.retry_after_seconds.map(Duration::from_secs)
    }
}

impl BlockedEvidence {
    /// Extract the evidence from a blocked [`FetchError`]; `None` for every
    /// other failure (a 404 or a size-cap rejection is not a blocked source).
    pub fn from_fetch_error(error: &FetchError) -> Option<Self> {
        match error {
            FetchError::Blocked(evidence) => Some((**evidence).clone()),
            _ => None,
        }
    }
}

/// Every way a fetch can fail. Only [`FetchError::Blocked`] is a *blocked
/// source* (persisted in the queue); the others are ordinary fetch failures
/// that must never become data either.
#[derive(Debug, Clone, thiserror::Error)]
pub enum FetchError {
    /// Boxed: the evidence is deliberately rich, and the fetch path returns
    /// this error from every layer (`clippy::result_large_err`).
    #[error(transparent)]
    Blocked(Box<BlockedEvidence>),
    #[error("transport failure during fetch: {detail}")]
    Transport { detail: String },
    #[error("fetch returned HTTP {status} for {url}")]
    HttpStatus { url: String, status: u16 },
    #[error("redirect refused for {url}: {detail}")]
    RedirectRefused { url: String, detail: String },
    #[error("content type {content_type:?} is not allowed for {url}")]
    ContentTypeRejected {
        url: String,
        content_type: Option<String>,
    },
    #[error("response body for {url} exceeds the {limit_bytes} byte cap")]
    BodyTooLarge { url: String, limit_bytes: usize },
    #[error("invalid fetch url {url}: {detail}")]
    InvalidUrl { url: String, detail: String },
}

impl std::fmt::Display for BlockedEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} at {} [{}], markers: {}",
            self.classification,
            self.url,
            self.http_status
                .map(|status| format!("HTTP {status}"))
                .unwrap_or_else(|| "no HTTP status".to_string()),
            if self.markers.is_empty() {
                "none".to_string()
            } else {
                self.markers.join(", ")
            }
        )
    }
}

impl std::error::Error for BlockedEvidence {}

impl FetchError {
    /// The blocked classification, when this failure is a block.
    pub fn classification(&self) -> Option<FetchClassification> {
        match self {
            Self::Blocked(evidence) => Some(evidence.classification),
            _ => None,
        }
    }

    pub fn url(&self) -> Option<&str> {
        match self {
            Self::Blocked(evidence) => Some(&evidence.url),
            Self::HttpStatus { url, .. }
            | Self::RedirectRefused { url, .. }
            | Self::ContentTypeRejected { url, .. }
            | Self::BodyTooLarge { url, .. }
            | Self::InvalidUrl { url, .. } => Some(url),
            Self::Transport { .. } => None,
        }
    }
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// The one scrape client. Cheap to clone; shares the host-health registry.
#[derive(Debug, Clone)]
pub struct ScrapeClient {
    client: reqwest::Client,
    config: Arc<ScrapeConfig>,
    health: Arc<HostHealthRegistry>,
    robots: Arc<RobotsCache>,
}

#[derive(Debug, Default)]
struct RobotsCache {
    entries: Mutex<HashMap<String, (tokio::time::Instant, RobotsRules)>>,
}

impl ScrapeClient {
    /// Build the client. A construction failure is a typed `Err` the caller
    /// must surface (never a fall back to a default client, which would
    /// silently drop the timeout, UA, redirect and size policy).
    pub fn new(config: ScrapeConfig) -> Result<Self, String> {
        let config = Arc::new(config);
        let max_redirects = config.max_redirects;
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .connect_timeout(config.connect_timeout)
            .user_agent(config.user_agent.clone())
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() >= max_redirects {
                    return attempt.stop();
                }
                if let Some(previous) = attempt.previous().last() {
                    // Same host only (and never https -> http): no cookie,
                    // credential or solved session may reach another origin.
                    if previous.host_str() != attempt.url().host_str() {
                        return attempt.stop();
                    }
                    if previous.scheme() == "https" && attempt.url().scheme() != "https" {
                        return attempt.stop();
                    }
                }
                attempt.follow()
            }))
            .build()
            .map_err(|error| format!("failed to build the scrape HTTP client: {error}"))?;
        Ok(Self {
            client,
            health: Arc::new(HostHealthRegistry::new(config.clone())),
            robots: Arc::new(RobotsCache::default()),
            config,
        })
    }

    /// Replace the host-health registry (used to share one registry across
    /// sources in a job runner, or to inject a hydrated one).
    pub fn with_host_health(mut self, health: Arc<HostHealthRegistry>) -> Self {
        self.health = health;
        self
    }

    pub fn config(&self) -> &ScrapeConfig {
        &self.config
    }

    pub fn host_health(&self) -> Arc<HostHealthRegistry> {
        self.health.clone()
    }

    /// Fetch one document under the full policy (exclusion, backoff, robots,
    /// politeness, bounded retries, size and type caps, challenge
    /// classification).
    pub async fn fetch(&self, url: &str) -> Result<ScrapedPage, FetchError> {
        let target = TargetUrl::parse(url)?;
        // The exclusion gate is FIRST: an excluded host receives no request
        // at all, not even a robots.txt fetch. This is what makes the
        // exclusion permanent and observable in the fixture hit counter.
        self.check_excluded(&target)?;
        self.check_backoff(&target).await?;

        // robots.txt first: a disallowed path must not produce a request,
        // and the robots fetch itself goes through politeness.
        let rules = self.robots_rules(&target).await;
        let path = target.request_path().to_string();
        if !rules.allows(&path) {
            self.health
                .note_blocked(&target.host, FetchClassification::BlockedPolicy, None);
            return Err(FetchError::Blocked(Box::new(BlockedEvidence {
                classification: FetchClassification::BlockedPolicy,
                url: target.url.clone(),
                host: target.host.clone(),
                http_status: None,
                markers: vec!["robots_disallow".to_string()],
                detail: format!("robots.txt disallows {path} for this user agent"),
                retry_after_seconds: None,
                fetched_at: Utc::now(),
            })));
        }
        let interval = self.effective_interval(&rules);

        let mut attempts: u32 = 0;
        loop {
            attempts += 1;
            self.health.wait_turn(&target.host, interval).await;
            match self.send_once(&target, &[]).await {
                Ok(page) => {
                    self.health.note_success(&target.host);
                    return Ok(ScrapedPage { attempts, ..page });
                }
                Err(FetchError::Blocked(evidence)) => {
                    let classification = evidence.classification;
                    let retryable =
                        classification.is_retryable() && attempts <= self.config.max_retries;
                    if retryable {
                        // Count every observed 429, including the attempts
                        // that are about to be retried, so "three 429s in a
                        // row" is measured on responses and not on final
                        // outcomes only. Reaching the threshold stops the
                        // retry loop immediately: an excluded host gets no
                        // further request.
                        if evidence.http_status == Some(429) {
                            let state = self.health.note_rate_limited(&evidence.host);
                            if state.is_excluded() {
                                let mut blocked = *evidence;
                                blocked.markers.push("host_excluded".to_string());
                                blocked.detail = format!(
                                    "{} (excluded permanently after {} consecutive 429s; no further request)",
                                    blocked.detail, state.consecutive_429
                                );
                                return Err(FetchError::Blocked(Box::new(blocked)));
                            }
                        }
                        let window = self
                            .health
                            .backoff_window_for(attempts)
                            .max(evidence.retry_after().unwrap_or_default());
                        tracing::debug!(
                            host = %evidence.host,
                            status = ?evidence.http_status,
                            attempt = attempts,
                            "transient block; retrying after backoff"
                        );
                        tokio::time::sleep(window).await;
                        continue;
                    }
                    let state = self.health.note_blocked_with_floor(
                        &evidence.host,
                        classification,
                        evidence.http_status,
                        evidence.retry_after().unwrap_or_default(),
                    );
                    let mut blocked = *evidence;
                    blocked.detail = format!(
                        "{} (backoff until {})",
                        blocked.detail,
                        backoff_display(&state)
                    );
                    if let Some(reason) = &state.exclusion_reason {
                        blocked.markers.push("host_excluded".to_string());
                        blocked.detail.push_str(&format!(
                            " (host excluded permanently: {reason}; no further request)"
                        ));
                    }
                    return Err(FetchError::Blocked(Box::new(blocked)));
                }
                Err(FetchError::Transport { detail: _ }) if attempts <= self.config.max_retries => {
                    tracing::debug!(host = %target.host, attempt = attempts, "transport error; retrying");
                    let window = self.health.backoff_window_for(attempts);
                    tokio::time::sleep(window).await;
                    continue;
                }
                Err(FetchError::Transport { detail }) => {
                    let state = self.health.note_blocked(
                        &target.host,
                        FetchClassification::BlockedTransient,
                        None,
                    );
                    return Err(FetchError::Blocked(Box::new(BlockedEvidence {
                        classification: FetchClassification::BlockedTransient,
                        url: target.url.clone(),
                        host: target.host.clone(),
                        http_status: None,
                        markers: vec!["transport_error".to_string()],
                        detail: format!(
                            "transport failure after {attempts} attempt(s): {detail} (backoff until {})",
                            backoff_display(&state)
                        ),
                        retry_after_seconds: None,
                        fetched_at: Utc::now(),
                    })));
                }
                Err(other) => return Err(other),
            }
        }
    }

    /// Refuse an excluded host BEFORE any request (including `robots.txt`).
    /// The refusal is a `blocked_policy` block with the `host_excluded`
    /// marker, so the review queue and the run ledger record why nothing was
    /// sent.
    fn check_excluded(&self, target: &TargetUrl) -> Result<(), FetchError> {
        let Some(state) = self.health.snapshot(&target.host) else {
            return Ok(());
        };
        let Some(reason) = state.exclusion_reason else {
            return Ok(());
        };
        Err(FetchError::Blocked(Box::new(BlockedEvidence {
            classification: FetchClassification::BlockedPolicy,
            url: target.url.clone(),
            host: target.host.clone(),
            http_status: state.last_status,
            markers: vec!["host_excluded".to_string()],
            detail: format!("host is permanently excluded ({reason}); no request was sent"),
            retry_after_seconds: None,
            fetched_at: Utc::now(),
        })))
    }

    fn effective_interval(&self, rules: &RobotsRules) -> Duration {
        rules
            .crawl_delay
            .map(|delay| delay.max(self.config.host_min_interval))
            .unwrap_or(self.config.host_min_interval)
    }

    /// Refuse to touch a host inside its backoff window. The refusal is
    /// itself a `blocked_transient` outcome so it is visible in the queue
    /// instead of looking like "nothing to see".
    async fn check_backoff(&self, target: &TargetUrl) -> Result<(), FetchError> {
        let Some(until) = self.health.backoff_until(&target.host) else {
            return Ok(());
        };
        if until <= tokio::time::Instant::now() {
            return Ok(());
        }
        let remaining = until.duration_since(tokio::time::Instant::now());
        let state = self.health.snapshot(&target.host);
        Err(FetchError::Blocked(Box::new(BlockedEvidence {
            classification: FetchClassification::BlockedTransient,
            url: target.url.clone(),
            host: target.host.clone(),
            http_status: state.and_then(|state| state.last_status),
            markers: vec!["host_backoff".to_string()],
            detail: format!(
                "host is in its backoff window for another {}s; no request was sent",
                remaining.as_secs()
            ),
            retry_after_seconds: Some(remaining.as_secs()),
            fetched_at: Utc::now(),
        })))
    }

    /// robots.txt for the host, cached; a failure to fetch it means DISALLOW.
    async fn robots_rules(&self, target: &TargetUrl) -> RobotsRules {
        let key = target.origin_key();
        if let Some((fetched_at, rules)) = self.robots.entries.lock().get(&key).cloned() {
            if fetched_at.elapsed() < self.config.robots_ttl {
                return rules;
            }
        }
        let robots_url = format!("{}/robots.txt", target.origin());
        let rules = match self.fetch_robots(&robots_url).await {
            Ok(Some(body)) => parse_robots(&body, &self.config.robots_user_agent_token()),
            Ok(None) => RobotsRules {
                state: RobotsState::Absent,
                rules: Vec::new(),
                crawl_delay: None,
            },
            Err(()) => {
                tracing::warn!(url = %robots_url, "robots.txt unavailable; failing closed (disallow)");
                RobotsRules::unavailable()
            }
        };
        self.robots
            .entries
            .lock()
            .insert(key, (tokio::time::Instant::now(), rules.clone()));
        rules
    }

    /// `Ok(Some(body))` 2xx, `Ok(None)` 4xx (absent → allow), `Err(())`
    /// 5xx/network/blocked (→ disallow).
    async fn fetch_robots(&self, robots_url: &str) -> Result<Option<String>, ()> {
        let Ok(target) = TargetUrl::parse(robots_url) else {
            return Err(());
        };
        self.health
            .wait_turn(&target.host, self.config.host_min_interval)
            .await;
        let response = self.client.get(&target.url).send().await.map_err(|_| ())?;
        let status = response.status().as_u16();
        if status >= 500 || matches!(status, 403 | 429) {
            return Err(());
        }
        if status >= 400 {
            return Ok(None);
        }
        let body = read_bounded(response, 256 * 1024).await.map_err(|_| ())?;
        let snapshot = ResponseSnapshot::new(status, Vec::new(), body.as_str());
        if detect_challenge(&snapshot).is_some() {
            // A CAPTCHA on robots.txt is not permission.
            return Err(());
        }
        Ok(Some(body))
    }

    /// One HTTP attempt: send, bound the body, classify, then (and only then)
    /// decide whether the body is a document.
    async fn send_once(
        &self,
        target: &TargetUrl,
        extra_headers: &[(String, String)],
    ) -> Result<ScrapedPage, FetchError> {
        let mut request = self.client.get(&target.url);
        for (name, value) in extra_headers {
            request = request.header(name, value);
        }
        let response = request
            .send()
            .await
            .map_err(|error| FetchError::Transport {
                detail: describe_transport(&error),
            })?;

        let status = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let final_url = response.url().to_string();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());

        if (300..400).contains(&status) {
            return Err(FetchError::RedirectRefused {
                url: final_url,
                detail: format!(
                    "redirect to {:?} was not followed (cross-host, downgrade, or more than \
                     {} hops)",
                    headers
                        .iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case("location"))
                        .map(|(_, value)| value.clone())
                        .unwrap_or_else(|| "unknown".to_string()),
                    self.config.max_redirects
                ),
            });
        }

        let body = match read_bounded(response, self.config.max_body_bytes).await {
            Ok(body) => body,
            Err(ReadError::TooLarge) => {
                return Err(FetchError::BodyTooLarge {
                    url: final_url,
                    limit_bytes: self.config.max_body_bytes,
                })
            }
            Err(ReadError::Transport(detail)) => return Err(FetchError::Transport { detail }),
        };

        let snapshot = ResponseSnapshot::new(status, headers, body.as_str());
        let classified = classify_response(&snapshot);
        if classified.classification.is_blocked() {
            let evidence = classified.challenge;
            let mut markers: Vec<String> = evidence
                .as_ref()
                .map(|e| e.markers.clone())
                .unwrap_or_default();
            if markers.is_empty() {
                markers.push(format!("http_{status}"));
            }
            let kinds = evidence
                .as_ref()
                .map(|e| e.kinds.join(","))
                .filter(|value| !value.is_empty())
                .map(|value| format!("challenge kinds: {value}"))
                .unwrap_or_else(|| format!("HTTP {status} without challenge markers"));
            return Err(FetchError::Blocked(Box::new(BlockedEvidence {
                classification: classified.classification,
                url: final_url,
                host: target.host.clone(),
                http_status: Some(status),
                markers,
                detail: kinds,
                retry_after_seconds: classified.retry_after_seconds,
                fetched_at: Utc::now(),
            })));
        }

        if !(200..300).contains(&status) {
            return Err(FetchError::HttpStatus {
                url: final_url,
                status,
            });
        }
        if !self.config.content_type_allowed(content_type.as_deref()) {
            return Err(FetchError::ContentTypeRejected {
                url: final_url,
                content_type,
            });
        }

        let fetches = ScrapedPage {
            url: final_url,
            status,
            content_type: content_type.unwrap_or_default(),
            body_bytes: body.len(),
            sha256: sha256_hex(body.as_bytes()),
            body,
            fetched_at: Utc::now(),
            attempts: 1,
        };
        Ok(fetches)
    }
}

/// A validated absolute http(s) URL with no userinfo.
#[derive(Debug, Clone)]
struct TargetUrl {
    url: String,
    host: String,
    scheme: String,
    port: Option<u16>,
    /// Path plus query, exactly as sent, used for robots matching.
    request_path: String,
}

impl TargetUrl {
    fn parse(raw: &str) -> Result<Self, FetchError> {
        let invalid = |detail: &str| FetchError::InvalidUrl {
            url: raw.to_string(),
            detail: detail.to_string(),
        };
        let parsed = url::Url::parse(raw.trim()).map_err(|error| invalid(&error.to_string()))?;
        let scheme = parsed.scheme().to_string();
        if scheme != "http" && scheme != "https" {
            return Err(invalid("only http and https are fetched"));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(invalid("credentials in the URL are refused"));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| invalid("missing host"))?
            .to_string();
        let mut request_path = if parsed.path().is_empty() {
            "/".to_string()
        } else {
            parsed.path().to_string()
        };
        if let Some(query) = parsed.query() {
            request_path.push('?');
            request_path.push_str(query);
        }
        let host = host.to_ascii_lowercase();
        Ok(Self {
            url: parsed.to_string(),
            host,
            scheme,
            port: parsed.port(),
            request_path,
        })
    }

    fn origin(&self) -> String {
        match self.port {
            Some(port) => format!("{}://{}:{}", self.scheme, self.host, port),
            None => format!("{}://{}", self.scheme, self.host),
        }
    }

    fn origin_key(&self) -> String {
        self.origin()
    }

    /// Path plus query, for robots matching (borrowed, no allocation on the
    /// hot path).
    fn request_path(&self) -> &str {
        &self.request_path
    }
}

enum ReadError {
    TooLarge,
    Transport(String),
}

/// Read a response body, refusing anything above `limit` bytes.
///
/// Two layers: `Content-Length` is checked first (cheap rejection), then the
/// stream is counted, a lying or chunked response cannot exceed the cap.
async fn read_bounded(response: reqwest::Response, limit: usize) -> Result<String, ReadError> {
    if let Some(length) = response.content_length() {
        if length > limit as u64 {
            return Err(ReadError::TooLarge);
        }
    }
    let mut response = response;
    let mut buffer: Vec<u8> = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if buffer.len() + chunk.len() > limit {
                    return Err(ReadError::TooLarge);
                }
                buffer.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(error) => return Err(ReadError::Transport(describe_transport(&error))),
        }
    }
    Ok(String::from_utf8_lossy(&buffer).to_string())
}

fn describe_transport(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "timeout".to_string()
    } else if error.is_connect() {
        "connect error".to_string()
    } else if error.is_redirect() {
        "redirect error".to_string()
    } else if error.is_body() || error.is_decode() {
        "body read error".to_string()
    } else {
        "request error".to_string()
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn backoff_display(state: &HostState) -> String {
    state
        .blocked_until
        .map(|until| until.to_rfc3339())
        .unwrap_or_else(|| "no window (stable block)".to_string())
}

// ---------------------------------------------------------------------------
// Tests, fixture-driven, no network
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Fixture bodies are realistic challenge pages: the exact strings the
    // detector keys on, in the shape the vendor serves them.
    const FIXTURE_CLOUDFLARE_IUAM: &str = r#"<!DOCTYPE html><html><head>
<title>Just a moment...</title>
<script>window._cf_chl_opt = {"cvId":"3","cType":"managed"};</script>
<script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script>
</head><body><noscript>Enable JavaScript and cookies to continue</noscript></body></html>"#;

    const FIXTURE_RECAPTCHA_BLOCK: &str = r#"<!DOCTYPE html><html><body>
<h1>Access denied</h1>
<p>We detected unusual traffic from your network. Complete the check to continue.</p>
<div class="g-recaptcha" data-sitekey="6Lc..."></div>
<script src="https://www.google.com/recaptcha/api.js"></script>
<noscript>Please enable JavaScript</noscript>
</body></html>"#;

    const FIXTURE_HCAPTCHA_BLOCK: &str = r#"<html><head><title>Rate limited</title></head><body>
<div class="h-captcha" data-sitekey="10000000-ffff"></div>
<script src="https://hcaptcha.com/1/api.js" async defer></script>
</body></html>"#;

    const FIXTURE_TURNSTILE_BLOCK: &str = r#"<html><body>
<form><div class="cf-turnstile" data-sitekey="0x4AAA"></div></form>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<script>turnstile.render('#widget', {sitekey: '0x4AAA'});</script>
</body></html>"#;

    const FIXTURE_IMPERVA_BLOCK: &str = r#"<html><head><title>Request unsuccessful.</title></head><body>
Request unsuccessful. Incapsula incident ID: 123-000000-000000
<script src="/_Incapsula_Resource?SWJIYLWA=719d34d31c8e3a6e"></script>
</body></html>"#;

    const FIXTURE_AKAMAI_BLOCK: &str = r#"<html><head><title>Access Denied</title></head><body>
<h1>Access Denied</h1>
<p>You don't have permission to access this resource.</p>
<p>Reference #18.abcd1234.1700000000.1a2b3c</p>
<script>var _abck = document.cookie;</script>
</body></html>"#;

    const FIXTURE_DATADOME_BLOCK: &str = r#"<html><head><title>Blocked</title></head><body>
<iframe src="https://geo.captcha-delivery.com/captcha/?initialCid=abc"></iframe>
<script>window.dd={'referer':''};</script>
</body></html>"#;

    const FIXTURE_PERIMETERX_BLOCK: &str = r#"<html><head><title>Verification</title></head><body>
<div id="px-captcha"></div>
<p>Please verify you are a human. Powered by PerimeterX.</p>
</body></html>"#;

    const FIXTURE_JS_SHELL: &str = r#"<html><body>
<noscript>Please enable JavaScript to continue.</noscript>
<p>JavaScript is required to view this page.</p>
</body></html>"#;

    const FIXTURE_ORDINARY_PAGE: &str = r#"<!DOCTYPE html><html><head><title>Acme OÜ, company register extract</title>
<script type="application/ld+json">
{"@context":"https://schema.org","@type":"Organization","name":"Acme OÜ",
 "email":"info@acme.ee","url":"https://acme.ee","address":{"addressCountry":"EE"}}
</script></head><body><h1>Acme OÜ</h1><p>A normal company page.</p>
<noscript>Please enable JavaScript for the search form.</noscript></body></html>"#;

    fn html_snapshot(status: u16, body: &str) -> ResponseSnapshot {
        ResponseSnapshot::new(
            status,
            vec![(
                "Content-Type".to_string(),
                "text/html; charset=utf-8".to_string(),
            )],
            body,
        )
    }

    fn assert_captcha(body: &str, status: u16, expected_kind: &str) {
        let snapshot = html_snapshot(status, body);
        let classified = classify_response(&snapshot);
        assert_eq!(
            classified.classification,
            FetchClassification::BlockedCaptcha,
            "fixture must classify as blocked_captcha"
        );
        let evidence = classified.challenge.expect("challenge evidence");
        assert!(
            evidence.kinds.contains(&expected_kind),
            "expected kind {expected_kind} in {:?}",
            evidence.kinds
        );
        assert!(!evidence.markers.is_empty(), "markers are the evidence");
    }

    // --- one fixture per challenge type (the invariant the plan closes with) ---

    #[test]
    fn fixture_cloudflare_iuam_page_is_blocked_captcha() {
        assert_captcha(FIXTURE_CLOUDFLARE_IUAM, 403, "cloudflare");
    }

    #[test]
    fn fixture_cloudflare_mitigated_header_is_blocked_captcha_even_on_200() {
        let snapshot = ResponseSnapshot::new(
            200,
            vec![
                ("Content-Type".to_string(), "text/html".to_string()),
                ("cf-mitigated".to_string(), "challenge".to_string()),
            ],
            "<html><body>challenge</body></html>",
        );
        let classified = classify_response(&snapshot);
        assert_eq!(
            classified.classification,
            FetchClassification::BlockedCaptcha
        );
        assert!(classified
            .challenge
            .expect("evidence")
            .markers
            .iter()
            .any(|marker| marker.contains("cf-mitigated")));
    }

    #[test]
    fn fixture_recaptcha_page_is_blocked_captcha() {
        assert_captcha(FIXTURE_RECAPTCHA_BLOCK, 403, "recaptcha");
    }

    #[test]
    fn fixture_hcaptcha_page_is_blocked_captcha() {
        assert_captcha(FIXTURE_HCAPTCHA_BLOCK, 429, "hcaptcha");
    }

    #[test]
    fn fixture_turnstile_page_is_blocked_captcha() {
        assert_captcha(FIXTURE_TURNSTILE_BLOCK, 403, "turnstile");
    }

    #[test]
    fn fixture_imperva_page_is_blocked_captcha() {
        assert_captcha(FIXTURE_IMPERVA_BLOCK, 403, "imperva");
    }

    #[test]
    fn fixture_akamai_block_page_is_blocked_captcha() {
        assert_captcha(FIXTURE_AKAMAI_BLOCK, 403, "akamai");
    }

    #[test]
    fn fixture_datadome_page_is_blocked_captcha() {
        assert_captcha(FIXTURE_DATADOME_BLOCK, 403, "datadome");
    }

    #[test]
    fn fixture_perimeterx_page_is_blocked_captcha() {
        assert_captcha(FIXTURE_PERIMETERX_BLOCK, 403, "perimeterx");
    }

    #[test]
    fn fixture_js_challenge_shell_is_blocked_captcha() {
        assert_captcha(FIXTURE_JS_SHELL, 200, "js_shell");
    }

    #[test]
    fn fixture_ordinary_page_is_ok_and_extractable() {
        let snapshot = html_snapshot(200, FIXTURE_ORDINARY_PAGE);
        let classified = classify_response(&snapshot);
        assert_eq!(classified.classification, FetchClassification::Ok);
        assert!(classified.challenge.is_none());
    }

    /// The documented asymmetry: ONE vendor-neutral shell phrase on a 2xx
    /// page is prose, not a block (the same page also carries a reCAPTCHA
    /// widget on its search form, which is not a block either).
    #[test]
    fn single_shell_phrase_and_widget_on_a_200_page_is_not_a_block() {
        let page = format!(
            "<html><body><p>Our commentary quotes the Cloudflare interstitial: \
             \"verifying you are human\".</p><form>{}</form></body></html>",
            "<div class=\"g-recaptcha\"></div>"
        );
        let classified = classify_response(&html_snapshot(200, &page));
        assert_eq!(classified.classification, FetchClassification::Ok);
    }

    /// …but infrastructure strings that cannot occur in prose are a block
    /// even on a 200 page, parsing a challenge script as a document is the
    /// failure mode the invariant forbids.
    #[test]
    fn vendor_infrastructure_on_a_200_page_is_still_a_block() {
        let page = "<html><body><script>window.__cf_chl_opt = {};</script></body></html>";
        let classified = classify_response(&html_snapshot(200, page));
        assert_eq!(
            classified.classification,
            FetchClassification::BlockedCaptcha
        );
    }

    // --- policy vs transient ---

    #[test]
    fn policy_blocks_are_classified_and_never_retryable() {
        for status in [401, 403, 451] {
            let classified = classify_response(&html_snapshot(status, "<html>denied</html>"));
            assert_eq!(
                classified.classification,
                FetchClassification::BlockedPolicy,
                "status {status}"
            );
            assert!(!classified.classification.is_retryable());
            assert!(classified.challenge.is_none());
        }
    }

    #[test]
    fn transient_statuses_are_retryable() {
        for status in [408, 425, 429, 500, 502, 503, 504] {
            let classified = classify_response(&html_snapshot(status, "<html>later</html>"));
            assert_eq!(
                classified.classification,
                FetchClassification::BlockedTransient,
                "status {status}"
            );
            assert!(classified.classification.is_retryable());
        }
    }

    #[test]
    fn not_found_and_other_statuses_are_not_blocks() {
        for status in [200, 301, 404, 410, 501] {
            let classified = classify_response(&html_snapshot(status, "<html>x</html>"));
            assert_eq!(
                classified.classification,
                FetchClassification::Ok,
                "status {status}"
            );
            assert!(!classified.classification.is_blocked());
        }
    }

    #[test]
    fn retry_after_is_bounded() {
        let snapshot = ResponseSnapshot::new(
            429,
            vec![("Retry-After".to_string(), "120".to_string())],
            "slow down",
        );
        assert_eq!(classify_response(&snapshot).retry_after_seconds, Some(120));

        let snapshot = ResponseSnapshot::new(
            429,
            vec![("Retry-After".to_string(), "999999".to_string())],
            "slow down",
        );
        assert_eq!(
            classify_response(&snapshot).retry_after_seconds,
            Some(MAX_RETRY_AFTER_SECONDS)
        );

        // An HTTP-date Retry-After is not guessed at.
        let snapshot = ResponseSnapshot::new(
            429,
            vec![(
                "Retry-After".to_string(),
                "Wed, 21 Oct 2026 07:28:00 GMT".to_string(),
            )],
            "slow down",
        );
        assert_eq!(classify_response(&snapshot).retry_after_seconds, None);
    }

    #[test]
    fn classification_strings_round_trip() {
        for value in [
            FetchClassification::Ok,
            FetchClassification::BlockedCaptcha,
            FetchClassification::BlockedPolicy,
            FetchClassification::BlockedTransient,
        ] {
            assert_eq!(FetchClassification::parse(value.as_str()), Some(value));
        }
        assert_eq!(FetchClassification::parse("maybe"), None);
        assert_eq!(
            FetchClassification::parse("BLOCKED_CAPTCHA"),
            Some(FetchClassification::BlockedCaptcha)
        );
    }

    // --- robots.txt ---

    #[test]
    fn robots_groups_precedence_and_longest_match() {
        let body = "\
# comment line
User-agent: *
Disallow: /private/
Allow: /private/public/
Crawl-delay: 2

User-agent: SomeOtherBot
Disallow: /

User-agent: ApexMail
Disallow: /nope/
";
        let rules = parse_robots(body, "ApexMail");
        assert_eq!(rules.state, RobotsState::Parsed);
        assert!(rules.allows("/public/page"));
        assert!(!rules.allows("/nope/x"));
        // The specific group wins for our token: the `*` group's /private/
        // rule does not apply to us.
        assert!(rules.allows("/private/secret"));
        // Crawl-delay came from our group (absent there) -> None.
        assert_eq!(rules.crawl_delay, None);

        let wildcard = parse_robots(body, "UnknownBot");
        assert!(!wildcard.allows("/private/secret"));
        // Longest match wins: the allow under /private/ beats the disallow.
        assert!(wildcard.allows("/private/public/report"));
        assert_eq!(
            wildcard.crawl_delay,
            Some(Duration::from_secs(2)),
            "crawl-delay applies to the wildcard group"
        );
    }

    #[test]
    fn robots_tie_goes_to_allow_and_empty_disallow_blocks_nothing() {
        let rules = parse_robots(
            "User-agent: *\nDisallow: /path\nAllow: /path\nDisallow:\n",
            "ApexMail",
        );
        assert!(rules.allows("/path"), "equal-length tie goes to Allow");
        assert!(rules.allows("/other"));
        // "Disallow:" (empty) is a no-op rule, not a block of everything.
        assert_eq!(rules.state, RobotsState::Parsed);
        assert_eq!(rules.rules.len(), 2);
    }

    #[test]
    fn robots_absent_allows_and_unavailable_fails_closed() {
        let absent = parse_robots("", "ApexMail");
        assert_eq!(absent.state, RobotsState::NoRules);
        assert!(absent.allows("/anything"));

        let unavailable = RobotsRules::unavailable();
        assert_eq!(unavailable.state, RobotsState::Unavailable);
        assert!(
            !unavailable.allows("/"),
            "an unreachable robots.txt is not permission"
        );
    }

    // --- host health: politeness and backoff (paused clock) ---

    #[tokio::test(start_paused = true)]
    async fn per_host_min_interval_is_enforced_between_requests() {
        let registry = HostHealthRegistry::new(Arc::new(ScrapeConfig::default()));
        let start = tokio::time::Instant::now();
        registry
            .wait_turn("example.com", Duration::from_millis(1_000))
            .await;
        assert_eq!(
            tokio::time::Instant::now() - start,
            Duration::ZERO,
            "the first request is immediate"
        );
        registry
            .wait_turn("example.com", Duration::from_millis(1_000))
            .await;
        assert!(
            tokio::time::Instant::now() - start >= Duration::from_millis(1_000),
            "the second request waits out the interval"
        );
        // A different host is not delayed by another host's pace.
        let other = tokio::time::Instant::now();
        registry
            .wait_turn("other.example", Duration::from_millis(1_000))
            .await;
        assert_eq!(tokio::time::Instant::now() - other, Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_blocks_grow_and_cap_the_backoff_window() {
        let config = ScrapeConfig {
            backoff_base: Duration::from_millis(100),
            max_host_block_backoff: Duration::from_millis(800),
            ..ScrapeConfig::default()
        };
        let registry = HostHealthRegistry::new(Arc::new(config));

        let first = registry.note_blocked(
            "example.com",
            FetchClassification::BlockedTransient,
            Some(503),
        );
        assert_eq!(first.consecutive_blocks, 1);
        let window_one = registry
            .backoff_until("example.com")
            .expect("window")
            .duration_since(tokio::time::Instant::now());
        assert!(
            window_one >= Duration::from_millis(100) && window_one <= Duration::from_millis(125),
            "first window is the base plus at most 25% jitter, got {window_one:?}"
        );

        registry.note_blocked(
            "example.com",
            FetchClassification::BlockedTransient,
            Some(503),
        );
        let window_two = registry
            .backoff_until("example.com")
            .expect("window")
            .duration_since(tokio::time::Instant::now());
        assert!(
            window_two >= Duration::from_millis(200),
            "the window grows with consecutive blocks, got {window_two:?}"
        );

        for _ in 0..8 {
            registry.note_blocked(
                "example.com",
                FetchClassification::BlockedTransient,
                Some(503),
            );
        }
        let capped = registry
            .backoff_until("example.com")
            .expect("window")
            .duration_since(tokio::time::Instant::now());
        assert!(
            capped <= Duration::from_millis(800 + 200),
            "the window is capped, got {capped:?}"
        );

        // A success clears the streak AND the window.
        let cleared = registry.note_success("example.com");
        assert_eq!(cleared.consecutive_blocks, 0);
        assert_eq!(cleared.blocked_until, None);
        assert!(registry.backoff_until("example.com").is_none());
        assert!(cleared.last_success_at.is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn robots_disallow_records_a_block_without_growing_the_penalty() {
        let registry = HostHealthRegistry::new(Arc::new(ScrapeConfig::default()));
        let state = registry.note_blocked("example.com", FetchClassification::BlockedPolicy, None);
        assert_eq!(
            state.last_classification,
            Some(FetchClassification::BlockedPolicy)
        );
        assert_eq!(state.consecutive_blocks, 1);
        assert!(
            state.blocked_until.is_none(),
            "a stable policy disallow must not be treated as a load problem"
        );
        assert!(registry.backoff_until("example.com").is_none());
        // A robots disallow is a permanent exclusion, not just a backoff.
        assert_eq!(
            state.exclusion_reason.as_deref(),
            Some(EXCLUSION_ROBOTS_DISALLOW)
        );
        assert!(state.excluded_at.is_some());
    }

    #[test]
    fn exclusion_reasons_are_closed_and_sticky() {
        let registry = HostHealthRegistry::new(Arc::new(ScrapeConfig::default()));
        // A CAPTCHA excludes immediately.
        let state = registry.note_blocked(
            "captcha.example",
            FetchClassification::BlockedCaptcha,
            Some(403),
        );
        assert_eq!(state.exclusion_reason.as_deref(), Some(EXCLUSION_CAPTCHA));
        // A later, different failure never rewrites the first cause.
        let state = registry.note_blocked(
            "captcha.example",
            FetchClassification::BlockedPolicy,
            Some(401),
        );
        assert_eq!(state.exclusion_reason.as_deref(), Some(EXCLUSION_CAPTCHA));
        // Nor does a success clear it.
        let state = registry.note_success("captcha.example");
        assert!(state.is_excluded());

        assert_eq!(
            exclusion_reason(FetchClassification::BlockedPolicy, Some(401)),
            Some(EXCLUSION_HTTP_401)
        );
        assert_eq!(
            exclusion_reason(FetchClassification::BlockedPolicy, Some(403)),
            Some(EXCLUSION_HTTP_403)
        );
        assert_eq!(
            exclusion_reason(FetchClassification::BlockedPolicy, Some(451)),
            None
        );
        assert_eq!(
            exclusion_reason(FetchClassification::BlockedTransient, Some(429)),
            None
        );
        assert_eq!(
            exclusion_reason(FetchClassification::BlockedCaptcha, Some(200)),
            Some(EXCLUSION_CAPTCHA)
        );
    }

    #[test]
    fn three_429s_in_a_row_exclude_the_host() {
        let registry = HostHealthRegistry::new(Arc::new(ScrapeConfig::default()));
        let first = registry.note_blocked(
            "limited.example",
            FetchClassification::BlockedTransient,
            Some(429),
        );
        assert_eq!(first.consecutive_429, 1);
        assert!(!first.is_excluded());
        let second = registry.note_blocked(
            "limited.example",
            FetchClassification::BlockedTransient,
            Some(429),
        );
        assert_eq!(second.consecutive_429, 2);
        assert!(!second.is_excluded());
        let third = registry.note_blocked(
            "limited.example",
            FetchClassification::BlockedTransient,
            Some(429),
        );
        assert_eq!(third.consecutive_429, 3);
        assert_eq!(
            third.exclusion_reason.as_deref(),
            Some(EXCLUSION_HTTP_429_REPEATED)
        );

        // A non-429 outcome between responses resets the streak.
        registry.note_success("other.example");
        registry.note_blocked(
            "other.example",
            FetchClassification::BlockedTransient,
            Some(429),
        );
        registry.note_blocked(
            "other.example",
            FetchClassification::BlockedTransient,
            Some(429),
        );
        let reset = registry.note_blocked(
            "other.example",
            FetchClassification::BlockedTransient,
            Some(503),
        );
        assert_eq!(reset.consecutive_429, 0);
        assert!(!reset.is_excluded());
    }

    #[tokio::test(start_paused = true)]
    async fn hydrate_restores_a_persisted_backoff_window() {
        let registry = HostHealthRegistry::new(Arc::new(ScrapeConfig::default()));
        registry.hydrate(HostState {
            host: "example.com".to_string(),
            consecutive_blocks: 3,
            total_blocks: 9,
            consecutive_429: 0,
            last_classification: Some(FetchClassification::BlockedCaptcha),
            last_status: Some(403),
            last_blocked_at: Some(Utc::now()),
            last_success_at: None,
            blocked_until: Some(Utc::now() + chrono::Duration::seconds(30)),
            excluded_at: Some(Utc::now()),
            exclusion_reason: Some(EXCLUSION_CAPTCHA.to_string()),
        });
        assert!(registry.backoff_until("example.com").is_some());
        assert_eq!(registry.snapshot("example.com").unwrap().total_blocks, 9);
        assert!(registry.snapshot("example.com").unwrap().is_excluded());

        tokio::time::advance(Duration::from_secs(31)).await;
        // The instant has passed, but the snapshot still reports the state.
        assert!(registry.snapshot("example.com").unwrap().total_blocks == 9);
    }

    // --- URL validation ---

    #[test]
    fn url_validation_refuses_credentials_and_foreign_schemes() {
        assert!(TargetUrl::parse("https://registry.example/company/1").is_ok());
        for bad in [
            "ftp://registry.example/x",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "https://user:secret@registry.example/x",
            "not a url",
        ] {
            let error = TargetUrl::parse(bad).expect_err("must be refused");
            assert!(matches!(error, FetchError::InvalidUrl { .. }), "{bad}");
        }
    }

    #[test]
    fn request_path_and_origin_are_exact() {
        let target = TargetUrl::parse("https://Registry.Example:8443/a/b?q=1").unwrap();
        assert_eq!(target.host, "registry.example");
        assert_eq!(target.origin(), "https://registry.example:8443");
        assert_eq!(target.request_path(), "/a/b?q=1");
        let bare = TargetUrl::parse("https://registry.example").unwrap();
        assert_eq!(bare.request_path(), "/");
    }

    #[test]
    fn content_type_allowlist_fails_closed() {
        let config = ScrapeConfig::default();
        assert!(config.content_type_allowed(Some("text/html; charset=utf-8")));
        assert!(config.content_type_allowed(Some("application/json")));
        assert!(!config.content_type_allowed(Some("application/pdf")));
        assert!(!config.content_type_allowed(Some("image/png")));
        assert!(
            !config.content_type_allowed(None),
            "an unverifiable content type is not parsed"
        );
    }

    #[test]
    fn config_defaults_are_conservative() {
        let config = ScrapeConfig::default();
        assert_eq!(config.max_retries, 2);
        assert!(config.host_min_interval >= Duration::from_millis(500));
        assert!(config.max_body_bytes <= 8 * 1024 * 1024);
        assert!(config.max_redirects <= 10);
        assert_eq!(config.robots_user_agent_token(), "ApexMail");
        assert_eq!(
            config.timeout,
            Duration::from_millis(DEFAULT_TIMEOUT_MS),
            "a public site fetch is bounded"
        );
    }
}
