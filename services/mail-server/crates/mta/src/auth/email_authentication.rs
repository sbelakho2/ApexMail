//! Core email authentication:SPF, DKIM, DMARC (RFC 7208, 6376, 7489).
//!
//! Leverages `mail-auth` for the heavy lifting (DNS‑based checks, crypto) and adds
//! caching, policy evaluation, and the `AuthenticationResults` header builder.

use std::net::IpAddr;
use std::time::Duration;

use mail_auth::{AuthenticatedMessage, DkimResult, Resolver, SpfResult};
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use trust_dns_resolver::config::ResolverConfig;
use trust_dns_resolver::net::runtime::TokioRuntimeProvider;
use trust_dns_resolver::TokioResolver;

use crate::config::EmailAuthConfig;

// ── result types ───────────────────────────────────────────────────────────────

/// Whether the SPF result was served from cache or freshly evaluated.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpfStatus {
    #[default]
    Cached,
    Fresh,
}

/// Outcome of an individual SPF check.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SpfOutcome {
    pub result: SpfVerdict,
    pub domain: String,
    pub explanation: Option<String>,
    pub status: SpfStatus,
}

/// Outcome of an individual DKIM check.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DkimOutcome {
    pub result: DkimVerdict,
    pub domain: String,
    pub selector: String,
    pub explanation: Option<String>,
}

/// Outcome of DMARC evaluation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DmarcOutcome {
    pub result: DmarcVerdict,
    pub domain: String,
    pub policy: DmarcPolicy,
    pub alignment: DmarcAlignment,
}

/// Combined results for a single message.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthenticationResults {
    pub spf: SpfOutcome,
    pub dkim: Vec<DkimOutcome>,
    pub dmarc: DmarcOutcome,
    pub auth_results_header: String,
}

/// The action recommended by DMARC policy + config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageDisposition {
    Accept,
    Quarantine,
    Reject,
    /// The DMARC policy lookup transiently failed AND neither SPF nor DKIM
    /// passed — the message cannot be authenticated right now. The SMTP
    /// session must answer with a temporary failure (451) so the sender
    /// retries, instead of fail-open accepting a potentially spoofed message.
    TempFail,
}

// ── verdict enums ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpfVerdict {
    #[default]
    Pass,
    Fail,
    SoftFail,
    Neutral,
    None,
    TempError,
    PermError,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DkimVerdict {
    #[default]
    Pass,
    Fail,
    Neutral,
    None,
    TempError,
    PermError,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DmarcVerdict {
    #[default]
    Pass,
    Fail,
    None,
    TempError,
    PermError,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DmarcPolicy {
    #[default]
    None,
    Quarantine,
    Reject,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DmarcAlignment {
    pub spf: bool,
    pub dkim: bool,
}

/// DMARC alignment mode (RFC 7489 §6.6.1): `adkim=`/`aspf=` tags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DmarcAlignmentMode {
    #[default]
    Relaxed,
    Strict,
}

/// Parsed DMARC policy record (RFC 7489 §6.3 / §6.6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmarcRecord {
    /// The `p=` policy (already adjusted to the effective policy by the lookup).
    pub policy: DmarcPolicy,
    /// The `sp=` subdomain policy, when present.
    pub subdomain_policy: Option<DmarcPolicy>,
    /// The `aspf=` alignment mode (defaults to relaxed).
    pub spf_alignment: DmarcAlignmentMode,
    /// The `adkim=` alignment mode (defaults to relaxed).
    pub dkim_alignment: DmarcAlignmentMode,
}

/// Why a DMARC TXT record could not be turned into a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcRecordError {
    /// Not a DMARC record (no `v=DMARC1` tag) — ignored.
    NotDmarc,
    /// `v=DMARC1` present but the record is malformed (RFC 7489 §6.6.3 → permerror).
    PermError,
}

/// Result of a DMARC policy lookup for a message domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DmarcLookup {
    /// No DMARC record published for the domain or its organizational domain.
    None,
    /// A valid record; `policy` already carries the effective policy (sp= vs p=).
    Record(DmarcRecord),
    /// A `v=DMARC1` record that failed to parse — RFC 7489 §6.6.3 permerror.
    PermError,
    /// The lookup itself failed transiently (timeout, SERVFAIL, network) —
    /// NOT the same as "no record published" (NXDOMAIN/NODATA). Consumers
    /// must not treat this as a published `p=none`.
    TempError,
}

// ── authenticator ──────────────────────────────────────────────────────────────

/// Stateful email authenticator with DNS caching.
pub struct EmailAuthenticator {
    resolver: Resolver,
    /// #120:Dedicated DNS resolver for DMARC TXT lookups.
    dns_resolver: TokioResolver,
    config: EmailAuthConfig,
    hostname: String,
    /// Domain → SPF evaluation cache (TTL 5 min).
    spf_cache: Cache<String, SpfVerdict>,
    /// #120:Domain → DMARC policy cache (TTL 5 min).
    dmarc_cache: Cache<String, DmarcLookup>,
}

impl EmailAuthenticator {
    /// Create a new authenticator.
    pub async fn new(config: EmailAuthConfig, hostname: String) -> anyhow::Result<Self> {
        let resolver = Resolver::new_system_conf().map_err(|e| anyhow::anyhow!("resolver: {e}"))?;

        // #120:Shared DNS resolver for DMARC TXT lookups (avoids per-call allocation).
        // trust-dns 0.26: TokioAsyncResolver::tokio is gone; build a TokioResolver
        // (builder defaults already equal ResolverOpts::default()).
        let dns_resolver = trust_dns_resolver::Resolver::builder_with_config(
            ResolverConfig::default(),
            TokioRuntimeProvider::default(),
        )
        .build()
        .map_err(|e| anyhow::anyhow!("dns resolver: {e}"))?;

        // Default SPF cache: 10K entries, 5 min TTL
        let spf_cache = Cache::builder()
            .max_capacity(config.spf_cache_max_entries)
            .time_to_live(Duration::from_secs(300))
            .build();

        // #120:DMARC policy cache – avoids repeated TXT lookups
        let dmarc_cache = Cache::builder()
            .max_capacity(5_000)
            .time_to_live(Duration::from_secs(300))
            .build();

        Ok(Self {
            resolver,
            dns_resolver,
            config,
            hostname,
            spf_cache,
            dmarc_cache,
        })
    }

    /// Authenticate an inbound email. Runs SPF + DKIM concurrently, then DMARC.
    pub async fn authenticate(
        &self,
        raw_message: &[u8],
        client_ip: IpAddr,
        helo_hostname: &str,
        mail_from: &str,
    ) -> anyhow::Result<AuthenticationResults> {
        // SMTP envelope (MAIL FROM) domain — used for the SPF check itself.
        let envelope_domain = mail_from
            .rsplit_once('@')
            .map(|(_, d)| d)
            .unwrap_or(mail_from)
            .trim()
            .to_lowercase();

        // Parse message synchronously (AuthenticatedMessage::parse is sync)
        let authenticated_msg = AuthenticatedMessage::parse(raw_message);

        // #121:Run SPF + DKIM concurrently using tokio::join!
        let (spf, dkim_outcomes) = tokio::join!(
            self.check_spf(client_ip, helo_hostname, mail_from, &envelope_domain),
            async {
                if let Some(ref auth_msg) = authenticated_msg {
                    self.check_dkim(auth_msg).await
                } else {
                    vec![DkimOutcome {
                        result: DkimVerdict::None,
                        domain: envelope_domain.clone(),
                        selector: String::new(),
                        explanation: Some("Failed to parse message for DKIM".into()),
                    }]
                }
            }
        );

        // DMARC is evaluated against the RFC 5322 From domain (RFC 7489 §3).
        // Without a parseable From header the message cannot be DMARC-authenticated.
        let dmarc = match authenticated_msg.as_ref().and_then(extract_from_domain) {
            Some(from_domain) => {
                self.check_dmarc(&from_domain, &envelope_domain, &spf, &dkim_outcomes)
                    .await
            }
            None => DmarcOutcome {
                result: DmarcVerdict::None,
                domain: String::new(),
                policy: DmarcPolicy::None,
                alignment: DmarcAlignment {
                    spf: false,
                    dkim: false,
                },
            },
        };

        // Build Authentication-Results header
        let auth_results_header = self.build_auth_results_header(&spf, &dkim_outcomes, &dmarc);

        Ok(AuthenticationResults {
            spf,
            dkim: dkim_outcomes,
            dmarc,
            auth_results_header,
        })
    }

    /// Decide whether to accept, quarantine, reject, or tempfail based on
    /// authentication + config.
    pub fn should_accept(&self, results: &AuthenticationResults) -> MessageDisposition {
        disposition_for(&self.config, results)
    }

    // ── internal checks ────────────────────────────────────────────────────────

    async fn check_spf(
        &self,
        client_ip: IpAddr,
        helo: &str,
        mail_from: &str,
        from_domain: &str,
    ) -> SpfOutcome {
        // #122:Cache key includes helo + mail_from (not just domain) so SPF results
        // are correct for empty MAIL FROM (HELO identity) and per-sender subdomains
        let cache_key = format!("{client_ip}:{helo}:{mail_from}");
        if let Some(cached) = self.spf_cache.get(&cache_key) {
            // O-1.2:Increment SPF cache hit counter for observability
            metrics::counter!("mta.spf_cache.hit").increment(1);
            return SpfOutcome {
                result: cached,
                domain: from_domain.to_string(),
                explanation: Some("cached".into()),
                status: SpfStatus::Cached,
            };
        }

        // O-1.2:Increment SPF cache miss counter
        metrics::counter!("mta.spf_cache.miss").increment(1);

        let output = self
            .resolver
            .verify_spf_sender(client_ip, helo, from_domain, mail_from)
            .await;
        let verdict = map_spf_result(&output.result());
        self.spf_cache.insert(cache_key.clone(), verdict);
        SpfOutcome {
            result: verdict,
            domain: from_domain.to_string(),
            explanation: None,
            status: SpfStatus::Fresh,
        }
    }

    async fn check_dkim(&self, auth_msg: &AuthenticatedMessage<'_>) -> Vec<DkimOutcome> {
        let output = self.resolver.verify_dkim(auth_msg).await;
        if output.is_empty() {
            return vec![DkimOutcome {
                result: DkimVerdict::None,
                domain: String::new(),
                selector: String::new(),
                explanation: Some("No DKIM signatures found".into()),
            }];
        }
        output
            .iter()
            .map(|sig| {
                let verdict = map_dkim_result(sig.result());
                DkimOutcome {
                    result: verdict,
                    domain: sig.signature().map(|s| s.d.to_string()).unwrap_or_default(),
                    selector: sig.signature().map(|s| s.s.to_string()).unwrap_or_default(),
                    explanation: None,
                }
            })
            .collect()
    }

    /// Evaluate DMARC for a message: RFC 7489 alignment (SPF/DKIM against the
    /// RFC 5322 From domain) plus policy lookup on the From domain.
    async fn check_dmarc(
        &self,
        from_domain: &str,
        envelope_domain: &str,
        spf: &SpfOutcome,
        dkim: &[DkimOutcome],
    ) -> DmarcOutcome {
        let lookup = self.lookup_dmarc(from_domain).await;
        evaluate_dmarc(from_domain, envelope_domain, spf, dkim, lookup)
    }

    /// RFC 7489 §6.6.3: look up `_dmarc.<domain>`; if absent, fall back to the
    /// organizational (registrable) domain, honouring `sp=` for subdomains.
    async fn lookup_dmarc(&self, domain: &str) -> DmarcLookup {
        if let Some(cached) = self.dmarc_cache.get(domain) {
            return cached;
        }

        let lookup = match self.fetch_dmarc(domain).await {
            DmarcLookup::None => match registrable_domain(domain) {
                Some(org) if org != domain.to_ascii_lowercase() => {
                    match self.fetch_dmarc(&org).await {
                        DmarcLookup::Record(mut record) => {
                            // The message comes from a subdomain of the record owner:
                            // sp= applies when present, otherwise p= (RFC 7489 §6.6.3).
                            record.policy = dmarc_effective_policy(&record, domain, &org);
                            record.subdomain_policy = None;
                            DmarcLookup::Record(record)
                        }
                        other => other,
                    }
                }
                _ => DmarcLookup::None,
            },
            other => other,
        };

        // Transient failures are NOT cached: a 5-minute cached TempError
        // would turn a blip into a persistent failure window.
        if lookup != DmarcLookup::TempError {
            self.dmarc_cache.insert(domain.to_string(), lookup);
        }
        lookup
    }

    /// Fetch and parse a single `_dmarc.{domain}` TXT record.
    async fn fetch_dmarc(&self, domain: &str) -> DmarcLookup {
        let dmarc_domain = format!("_dmarc.{domain}");
        let mut saw_permerror = false;
        match self.dns_resolver.txt_lookup(&dmarc_domain).await {
            Ok(lookup) => {
                for txt in txt_record_strings(&lookup) {
                    match parse_dmarc_record(&txt) {
                        Ok(record) => return DmarcLookup::Record(record),
                        Err(DmarcRecordError::PermError) => saw_permerror = true,
                        Err(DmarcRecordError::NotDmarc) => {}
                    }
                }
                if saw_permerror {
                    DmarcLookup::PermError
                } else {
                    DmarcLookup::None
                }
            }
            // C:NXDOMAIN / NODATA arrive as NoRecordsFound — that is a
            // definitive "no record published" (→ None). Any other error
            // (timeout, SERVFAIL, network) is transient and must surface as
            // TempError so the caller can tempfail instead of treating the
            // domain as p=none (fail-open).
            Err(err) => match err {
                // trust-dns 0.26: ResolveErrorKind was replaced by
                // net::NetError; NoRecordsFound is now a nested DnsError
                // variant holding a NoRecords struct (response_code et al.).
                trust_dns_resolver::net::NetError::Dns(
                    trust_dns_resolver::net::DnsError::NoRecordsFound { .. },
                ) => DmarcLookup::None,
                other => {
                    tracing::debug!(
                        domain,
                        error = %other,
                        "DMARC policy lookup transiently failed"
                    );
                    DmarcLookup::TempError
                }
            },
        }
    }

    fn build_auth_results_header(
        &self,
        spf: &SpfOutcome,
        dkim: &[DkimOutcome],
        dmarc: &DmarcOutcome,
    ) -> String {
        let mut parts = vec![format!("Authentication-Results: {}", self.hostname)];

        // SPF
        parts.push(format!(
            ";\r\n\tspf={} smtp.mailfrom={}",
            verdict_str_spf(spf.result),
            spf.domain,
        ));

        // DKIM
        for d in dkim {
            if d.domain.is_empty() {
                continue;
            }
            parts.push(format!(
                ";\r\n\tdkim={} header.d={} header.s={}",
                verdict_str_dkim(d.result),
                d.domain,
                d.selector,
            ));
        }

        // DMARC
        parts.push(format!(
            ";\r\n\tdmarc={} header.from={}",
            verdict_str_dmarc(dmarc.result),
            dmarc.domain,
        ));

        parts.join("")
    }
}

// ── mapping helpers ────────────────────────────────────────────────────────────

/// Flatten a TXT lookup into one String per TXT record.
///
/// trust-dns 0.26 removed typed lookup iteration; `txt_lookup` now returns raw
/// records. Each record's character-string chunks are joined without a
/// separator (mirroring apexmail-dns-resolver's migrated TXT handling).
fn txt_record_strings(lookup: &trust_dns_resolver::lookup::Lookup) -> Vec<String> {
    lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            trust_dns_resolver::proto::rr::RData::TXT(txt) => Some(
                txt.txt_data
                    .iter()
                    .map(|d| String::from_utf8_lossy(d).to_string())
                    .collect::<Vec<_>>()
                    .join(""),
            ),
            _ => None,
        })
        .collect()
}

/// Pure disposition decision (extracted from
/// [`EmailAuthenticator::should_accept`] so the policy matrix is testable
/// without a DNS resolver).
fn disposition_for(
    config: &EmailAuthConfig,
    results: &AuthenticationResults,
) -> MessageDisposition {
    // SPF hard fail + strict
    if config.require_spf && results.spf.result == SpfVerdict::Fail {
        return MessageDisposition::Reject;
    }

    // DKIM required but none passed
    if config.require_dkim && !results.dkim.iter().any(|d| d.result == DkimVerdict::Pass) {
        return MessageDisposition::Reject;
    }

    // C:DMARC lookup transiently failed (timeout/SERVFAIL — distinct from
    // NXDOMAIN) while NEITHER SPF nor DKIM passed. The message cannot be
    // authenticated: tempfail (451) so the sender retries, instead of
    // fail-open accepting a potentially spoofed message.
    if config.enforce_dmarc
        && results.dmarc.result == DmarcVerdict::TempError
        && results.spf.result != SpfVerdict::Pass
        && !results.dkim.iter().any(|d| d.result == DkimVerdict::Pass)
    {
        return MessageDisposition::TempFail;
    }

    // DMARC enforcement
    if config.enforce_dmarc && results.dmarc.result == DmarcVerdict::Fail {
        return match results.dmarc.policy {
            DmarcPolicy::Reject => MessageDisposition::Reject,
            DmarcPolicy::Quarantine => MessageDisposition::Quarantine,
            DmarcPolicy::None => {
                if config.allow_soft_fail {
                    MessageDisposition::Accept
                } else {
                    MessageDisposition::Quarantine
                }
            }
        };
    }

    MessageDisposition::Accept
}

fn map_spf_result(r: &SpfResult) -> SpfVerdict {
    match r {
        SpfResult::Pass => SpfVerdict::Pass,
        SpfResult::Fail => SpfVerdict::Fail,
        SpfResult::SoftFail => SpfVerdict::SoftFail,
        SpfResult::Neutral => SpfVerdict::Neutral,
        SpfResult::None => SpfVerdict::None,
        SpfResult::TempError => SpfVerdict::TempError,
        SpfResult::PermError => SpfVerdict::PermError,
    }
}

fn map_dkim_result(r: &DkimResult) -> DkimVerdict {
    match r {
        DkimResult::Pass => DkimVerdict::Pass,
        DkimResult::Fail(_) => DkimVerdict::Fail,
        DkimResult::Neutral(_) => DkimVerdict::Neutral,
        DkimResult::None => DkimVerdict::None,
        DkimResult::TempError(_) => DkimVerdict::TempError,
        DkimResult::PermError(_) => DkimVerdict::PermError,
    }
}

fn verdict_str_spf(v: SpfVerdict) -> &'static str {
    match v {
        SpfVerdict::Pass => "pass",
        SpfVerdict::Fail => "fail",
        SpfVerdict::SoftFail => "softfail",
        SpfVerdict::Neutral => "neutral",
        SpfVerdict::None => "none",
        SpfVerdict::TempError => "temperror",
        SpfVerdict::PermError => "permerror",
    }
}

fn verdict_str_dkim(v: DkimVerdict) -> &'static str {
    match v {
        DkimVerdict::Pass => "pass",
        DkimVerdict::Fail => "fail",
        DkimVerdict::Neutral => "neutral",
        DkimVerdict::None => "none",
        DkimVerdict::TempError => "temperror",
        DkimVerdict::PermError => "permerror",
    }
}

fn verdict_str_dmarc(v: DmarcVerdict) -> &'static str {
    match v {
        DmarcVerdict::Pass => "pass",
        DmarcVerdict::Fail => "fail",
        DmarcVerdict::None => "none",
        DmarcVerdict::TempError => "temperror",
        DmarcVerdict::PermError => "permerror",
    }
}

// ── DMARC record parsing & alignment helpers ──────────────────────────────────

/// Parse a DMARC policy record (RFC 7489 §6.6.3).
///
/// A record without a `v=DMARC1` tag is not a DMARC record; a `v=DMARC1`
/// record missing or mis-stating `p=` is a permanent error (permerror), NOT a
/// policy of "none".
fn parse_dmarc_record(txt: &str) -> Result<DmarcRecord, DmarcRecordError> {
    let mut policy = None;
    let mut subdomain_policy = None;
    let mut spf_alignment = DmarcAlignmentMode::Relaxed;
    let mut dkim_alignment = DmarcAlignmentMode::Relaxed;
    let mut saw_version = false;

    for part in txt.split(';') {
        let part = part.trim();
        let (tag, value) = match part.split_once('=') {
            Some(t) => t,
            None => continue,
        };
        match tag.trim().to_ascii_lowercase().as_str() {
            "v" => {
                if value.trim() != "DMARC1" {
                    return Err(DmarcRecordError::NotDmarc);
                }
                saw_version = true;
            }
            "p" => {
                policy = Some(match value.trim().to_ascii_lowercase().as_str() {
                    "none" => DmarcPolicy::None,
                    "quarantine" => DmarcPolicy::Quarantine,
                    "reject" => DmarcPolicy::Reject,
                    _ => return Err(DmarcRecordError::PermError),
                });
            }
            "sp" => {
                subdomain_policy = Some(match value.trim().to_ascii_lowercase().as_str() {
                    "none" => DmarcPolicy::None,
                    "quarantine" => DmarcPolicy::Quarantine,
                    "reject" => DmarcPolicy::Reject,
                    _ => return Err(DmarcRecordError::PermError),
                });
            }
            "aspf" => {
                spf_alignment = parse_dmarc_alignment_mode(value)?;
            }
            "adkim" => {
                dkim_alignment = parse_dmarc_alignment_mode(value)?;
            }
            _ => {}
        }
    }

    if !saw_version {
        return Err(DmarcRecordError::NotDmarc);
    }
    // RFC 7489 §6.6.3: a v=DMARC1 record without p= is a permanent error.
    let policy = policy.ok_or(DmarcRecordError::PermError)?;

    Ok(DmarcRecord {
        policy,
        subdomain_policy,
        spf_alignment,
        dkim_alignment,
    })
}

fn parse_dmarc_alignment_mode(value: &str) -> Result<DmarcAlignmentMode, DmarcRecordError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "s" => Ok(DmarcAlignmentMode::Strict),
        "r" | "" => Ok(DmarcAlignmentMode::Relaxed),
        _ => Err(DmarcRecordError::PermError),
    }
}

/// Registrable (organizational) domain via the Public Suffix List.
/// `a.b.example.com` → `example.com`, `x.co.uk` → `x.co.uk`, `co.uk` → None.
fn registrable_domain(domain: &str) -> Option<String> {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() {
        return None;
    }
    psl::domain_str(&d).map(|s| s.to_string())
}

/// Effective policy for `message_domain` from a record published at
/// `record_owner`: subdomains get `sp=` when present, else `p=` (RFC 7489 §6.6.3).
fn dmarc_effective_policy(
    record: &DmarcRecord,
    message_domain: &str,
    record_owner: &str,
) -> DmarcPolicy {
    let message_domain = message_domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let record_owner = record_owner
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if message_domain == record_owner {
        record.policy
    } else {
        record.subdomain_policy.unwrap_or(record.policy)
    }
}

/// RFC 7489 §3.1 alignment check between the RFC 5322 From domain and the
/// SPF (envelope) or DKIM `d=` domain, honouring the aspf=/adkim= mode.
fn domains_aligned(from_domain: &str, auth_domain: &str, mode: DmarcAlignmentMode) -> bool {
    let from = from_domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let auth = auth_domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if from.is_empty() || auth.is_empty() {
        return false;
    }
    match mode {
        // Strict: exact match after lowercasing (RFC 7489 §6.6.1).
        DmarcAlignmentMode::Strict => from == auth,
        // Relaxed: same registrable domain after stripping subdomain labels.
        DmarcAlignmentMode::Relaxed => registrable_domain(&from) == registrable_domain(&auth),
    }
}

/// Extract the domain of the first RFC 5322 From address (lowercased).
fn extract_from_domain(message: &AuthenticatedMessage) -> Option<String> {
    message
        .froms()
        .first()
        .and_then(|addr| addr.rsplit_once('@'))
        .map(|(_, d)| d.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|d| !d.is_empty())
}

/// Evaluate DMARC given the authenticated results and a looked-up policy.
fn evaluate_dmarc(
    from_domain: &str,
    envelope_domain: &str,
    spf: &SpfOutcome,
    dkim: &[DkimOutcome],
    dmarc: DmarcLookup,
) -> DmarcOutcome {
    let (result, policy, alignment) = match dmarc {
        DmarcLookup::None => (
            DmarcVerdict::None,
            DmarcPolicy::None,
            DmarcAlignment {
                spf: false,
                dkim: false,
            },
        ),
        DmarcLookup::PermError => (
            DmarcVerdict::PermError,
            DmarcPolicy::None,
            DmarcAlignment {
                spf: false,
                dkim: false,
            },
        ),
        // C:the lookup itself failed transiently — never conflated with a
        // published p=none.
        DmarcLookup::TempError => (
            DmarcVerdict::TempError,
            DmarcPolicy::None,
            DmarcAlignment {
                spf: false,
                dkim: false,
            },
        ),
        DmarcLookup::Record(record) => {
            // SPF-aligned: SPF Pass AND the envelope domain aligns with the
            // RFC 5322 From domain (RFC 7489 §3.1 / §6.6.1).
            let spf_aligned = spf.result == SpfVerdict::Pass
                && domains_aligned(from_domain, envelope_domain, record.spf_alignment);
            // DKIM-aligned: any passing signature whose d= domain aligns.
            let dkim_aligned = dkim.iter().any(|d| {
                d.result == DkimVerdict::Pass
                    && domains_aligned(from_domain, &d.domain, record.dkim_alignment)
            });
            let result = if spf_aligned || dkim_aligned {
                DmarcVerdict::Pass
            } else {
                match record.policy {
                    DmarcPolicy::None => DmarcVerdict::None,
                    _ => DmarcVerdict::Fail,
                }
            };
            (
                result,
                record.policy,
                DmarcAlignment {
                    spf: spf_aligned,
                    dkim: dkim_aligned,
                },
            )
        }
    };

    DmarcOutcome {
        result,
        domain: from_domain.to_string(),
        policy,
        alignment,
    }
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_authenticator(config: EmailAuthConfig, hostname: &str) -> Option<EmailAuthenticator> {
        let resolver = Resolver::new_system_conf().ok()?;
        // trust-dns 0.26: build the TokioResolver via the builder API; the
        // default builder options equal the old default ResolverOpts.
        let dns_resolver = trust_dns_resolver::Resolver::builder_with_config(
            ResolverConfig::default(),
            TokioRuntimeProvider::default(),
        )
        .build()
        .ok()?;
        Some(EmailAuthenticator {
            resolver,
            dns_resolver,
            config,
            hostname: hostname.into(),
            spf_cache: Cache::builder().max_capacity(10).build(),
            dmarc_cache: Cache::builder().max_capacity(10).build(),
        })
    }

    #[test]
    fn test_parse_dmarc_policy_reject() {
        let record =
            parse_dmarc_record("v=DMARC1; p=reject; rua=mailto:dmarc@example.com").unwrap();
        assert_eq!(record.policy, DmarcPolicy::Reject);
        assert_eq!(record.subdomain_policy, None);
        assert_eq!(record.spf_alignment, DmarcAlignmentMode::Relaxed);
        assert_eq!(record.dkim_alignment, DmarcAlignmentMode::Relaxed);
    }

    #[test]
    fn test_parse_dmarc_policy_quarantine() {
        let record = parse_dmarc_record("v=DMARC1; p=quarantine").unwrap();
        assert_eq!(record.policy, DmarcPolicy::Quarantine);
    }

    #[test]
    fn test_parse_dmarc_policy_none() {
        let record = parse_dmarc_record("v=DMARC1; p=none").unwrap();
        assert_eq!(record.policy, DmarcPolicy::None);
    }

    #[test]
    fn test_parse_dmarc_policy_invalid() {
        assert_eq!(
            parse_dmarc_record("not a dmarc record"),
            Err(DmarcRecordError::NotDmarc)
        );
        assert_eq!(
            parse_dmarc_record("v=spf1 include:_spf.example.com ~all"),
            Err(DmarcRecordError::NotDmarc)
        );
    }

    #[test]
    fn test_parse_dmarc_record_sp_aspf_adkim() {
        let record = parse_dmarc_record(
            "v=DMARC1; p=none; sp=reject; aspf=s; adkim=s; rua=mailto:dmarc@example.com",
        )
        .unwrap();
        assert_eq!(record.policy, DmarcPolicy::None);
        assert_eq!(record.subdomain_policy, Some(DmarcPolicy::Reject));
        assert_eq!(record.spf_alignment, DmarcAlignmentMode::Strict);
        assert_eq!(record.dkim_alignment, DmarcAlignmentMode::Strict);
    }

    // ── FIX-B (d): TXT record present but missing p= is a permerror, NOT a
    //    "policy none" (RFC 7489 §6.6.3). ─────────────────────────────────

    #[test]
    fn test_parse_dmarc_record_missing_p_is_permerror() {
        assert_eq!(
            parse_dmarc_record("v=DMARC1; rua=mailto:dmarc@example.com"),
            Err(DmarcRecordError::PermError)
        );
    }

    #[test]
    fn test_parse_dmarc_record_invalid_p_is_permerror() {
        assert_eq!(
            parse_dmarc_record("v=DMARC1; p=maybe"),
            Err(DmarcRecordError::PermError)
        );
        assert_eq!(
            parse_dmarc_record("v=DMARC1; p=reject; aspf=banana"),
            Err(DmarcRecordError::PermError)
        );
    }

    // ── FIX-B (a)/(b): registrable-domain derivation ───────────────────────

    #[test]
    fn test_registrable_domain_multi_label_uses_org_domain() {
        // a.b.example.com must resolve DMARC from example.com
        assert_eq!(
            registrable_domain("a.b.example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            registrable_domain("mail.example.com"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_registrable_domain_two_label_cc_tld() {
        // x.co.uk must resolve from the registrable domain x.co.uk, NOT co.uk
        assert_eq!(registrable_domain("x.co.uk"), Some("x.co.uk".to_string()));
        assert_eq!(registrable_domain("a.b.co.uk"), Some("b.co.uk".to_string()));
        assert_eq!(
            registrable_domain("shop.com.au"),
            Some("shop.com.au".to_string())
        );
        // The suffix itself is not a registrable domain
        assert_eq!(registrable_domain("co.uk"), None);
        assert_eq!(registrable_domain("com"), None);
    }

    #[test]
    fn test_registrable_domain_single_label_and_empty() {
        assert_eq!(
            registrable_domain("example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(registrable_domain(""), None);
    }

    // ── FIX-B (c): sp= applies to subdomains ───────────────────────────────

    #[test]
    fn test_dmarc_effective_policy_sp_applies_to_subdomains() {
        let record = DmarcRecord {
            policy: DmarcPolicy::None,
            subdomain_policy: Some(DmarcPolicy::Reject),
            spf_alignment: DmarcAlignmentMode::Relaxed,
            dkim_alignment: DmarcAlignmentMode::Relaxed,
        };
        assert_eq!(
            dmarc_effective_policy(&record, "sub.example.com", "example.com"),
            DmarcPolicy::Reject
        );
        // Same-domain messages use p=
        assert_eq!(
            dmarc_effective_policy(&record, "example.com", "example.com"),
            DmarcPolicy::None
        );
    }

    #[test]
    fn test_dmarc_effective_policy_falls_back_to_p_without_sp() {
        let record = DmarcRecord {
            policy: DmarcPolicy::Quarantine,
            subdomain_policy: None,
            spf_alignment: DmarcAlignmentMode::Relaxed,
            dkim_alignment: DmarcAlignmentMode::Relaxed,
        };
        assert_eq!(
            dmarc_effective_policy(&record, "sub.example.com", "example.com"),
            DmarcPolicy::Quarantine
        );
    }

    // ── FIX-A: alignment helpers ───────────────────────────────────────────

    #[test]
    fn test_domains_aligned_relaxed_and_strict() {
        let from = "example.com";
        assert!(domains_aligned(
            from,
            "example.com",
            DmarcAlignmentMode::Strict
        ));
        assert!(!domains_aligned(
            from,
            "sub.example.com",
            DmarcAlignmentMode::Strict
        ));
        assert!(domains_aligned(
            from,
            "sub.example.com",
            DmarcAlignmentMode::Relaxed
        ));
        assert!(!domains_aligned(
            from,
            "evil.com",
            DmarcAlignmentMode::Relaxed
        ));
        assert!(!domains_aligned(
            "",
            "evil.com",
            DmarcAlignmentMode::Relaxed
        ));
    }

    #[test]
    fn test_extract_from_domain_uses_from_header() {
        // RFC 5322 From header must drive DMARC, never the envelope domain.
        let raw = b"From: Attacker <attacker@evil.com>\r\nTo: victim@example.com\r\nSubject: hi\r\n\r\nbody\r\n";
        let msg = AuthenticatedMessage::parse(raw).expect("parse message");
        assert_eq!(extract_from_domain(&msg), Some("evil.com".to_string()));
    }

    // ── FIX-A: DMARC evaluation ────────────────────────────────────────────

    fn spf_outcome(result: SpfVerdict, domain: &str) -> SpfOutcome {
        SpfOutcome {
            result,
            domain: domain.into(),
            explanation: None,
            status: SpfStatus::Fresh,
        }
    }

    fn dkim_outcome(result: DkimVerdict, domain: &str) -> DkimOutcome {
        DkimOutcome {
            result,
            domain: domain.into(),
            selector: "sel".into(),
            explanation: None,
        }
    }

    fn reject_record() -> DmarcRecord {
        DmarcRecord {
            policy: DmarcPolicy::Reject,
            subdomain_policy: None,
            spf_alignment: DmarcAlignmentMode::Relaxed,
            dkim_alignment: DmarcAlignmentMode::Relaxed,
        }
    }

    #[test]
    fn test_dmarc_spf_pass_on_envelope_domain_but_unaligned_from_fails() {
        // From: victim.com, MAIL FROM: evil.com, SPF passes on evil.com.
        // The envelope domain does not align with the From domain → DMARC must NOT pass.
        let dmarc = evaluate_dmarc(
            "victim.com",
            "evil.com",
            &spf_outcome(SpfVerdict::Pass, "evil.com"),
            &[],
            DmarcLookup::Record(reject_record()),
        );
        assert_eq!(dmarc.result, DmarcVerdict::Fail);
        assert_eq!(dmarc.domain, "victim.com");
    }

    #[test]
    fn test_dmarc_aligned_dkim_passes() {
        let dmarc = evaluate_dmarc(
            "victim.com",
            "evil.com",
            &spf_outcome(SpfVerdict::Fail, "evil.com"),
            &[dkim_outcome(DkimVerdict::Pass, "victim.com")],
            DmarcLookup::Record(reject_record()),
        );
        assert_eq!(dmarc.result, DmarcVerdict::Pass);
    }

    #[test]
    fn test_dmarc_unaligned_dkim_fails() {
        let dmarc = evaluate_dmarc(
            "victim.com",
            "evil.com",
            &spf_outcome(SpfVerdict::Fail, "evil.com"),
            &[dkim_outcome(DkimVerdict::Pass, "evil.com")],
            DmarcLookup::Record(reject_record()),
        );
        assert_eq!(dmarc.result, DmarcVerdict::Fail);
    }

    #[test]
    fn test_dmarc_strict_vs_relaxed_alignment() {
        // Envelope sub.victim.com with From victim.com: aligned relaxed, not strict.
        let relaxed = DmarcRecord {
            spf_alignment: DmarcAlignmentMode::Relaxed,
            ..reject_record()
        };
        let strict = DmarcRecord {
            spf_alignment: DmarcAlignmentMode::Strict,
            ..reject_record()
        };
        assert_eq!(
            evaluate_dmarc(
                "victim.com",
                "sub.victim.com",
                &spf_outcome(SpfVerdict::Pass, "sub.victim.com"),
                &[],
                DmarcLookup::Record(relaxed),
            )
            .result,
            DmarcVerdict::Pass
        );
        assert_eq!(
            evaluate_dmarc(
                "victim.com",
                "sub.victim.com",
                &spf_outcome(SpfVerdict::Pass, "sub.victim.com"),
                &[],
                DmarcLookup::Record(strict),
            )
            .result,
            DmarcVerdict::Fail
        );
    }

    #[test]
    fn test_dmarc_aspf_strict_subdomain_envelope_fails() {
        // aspf=s: a subdomain envelope domain must NOT satisfy alignment.
        let strict = DmarcRecord {
            spf_alignment: DmarcAlignmentMode::Strict,
            ..reject_record()
        };
        let dmarc = evaluate_dmarc(
            "victim.com",
            "sub.victim.com",
            &spf_outcome(SpfVerdict::Pass, "sub.victim.com"),
            &[],
            DmarcLookup::Record(strict),
        );
        assert_eq!(dmarc.result, DmarcVerdict::Fail);
        assert!(!dmarc.alignment.spf);
    }

    #[test]
    fn test_dmarc_no_record_is_none() {
        let dmarc = evaluate_dmarc(
            "victim.com",
            "evil.com",
            &spf_outcome(SpfVerdict::Pass, "evil.com"),
            &[],
            DmarcLookup::None,
        );
        assert_eq!(dmarc.result, DmarcVerdict::None);
    }

    #[test]
    fn test_dmarc_permerror_record_is_permerror() {
        let dmarc = evaluate_dmarc(
            "victim.com",
            "evil.com",
            &spf_outcome(SpfVerdict::Pass, "evil.com"),
            &[],
            DmarcLookup::PermError,
        );
        assert_eq!(dmarc.result, DmarcVerdict::PermError);
        assert_eq!(dmarc.policy, DmarcPolicy::None);
    }

    #[test]
    fn test_dmarc_temperror_is_distinct_from_no_record() {
        // C:a transient lookup failure must surface as TempError, never as
        // the "no record published" None (which downstream treats as p=none).
        let dmarc = evaluate_dmarc(
            "victim.com",
            "evil.com",
            &spf_outcome(SpfVerdict::Fail, "evil.com"),
            &[],
            DmarcLookup::TempError,
        );
        assert_eq!(dmarc.result, DmarcVerdict::TempError);
        assert_eq!(dmarc.policy, DmarcPolicy::None);
    }

    // ── C:disposition matrix incl. DMARC tempfail ─────────────────────────

    fn results_with(
        spf: SpfVerdict,
        dkim: DkimVerdict,
        dmarc: DmarcVerdict,
        policy: DmarcPolicy,
    ) -> AuthenticationResults {
        AuthenticationResults {
            spf: spf_outcome(spf, "example.com"),
            dkim: vec![dkim_outcome(dkim, "example.com")],
            dmarc: DmarcOutcome {
                result: dmarc,
                domain: "example.com".into(),
                policy,
                alignment: DmarcAlignment {
                    spf: false,
                    dkim: false,
                },
            },
            auth_results_header: String::new(),
        }
    }

    fn enforced_config() -> EmailAuthConfig {
        EmailAuthConfig {
            require_spf: false,
            require_dkim: false,
            enforce_dmarc: true,
            allow_soft_fail: true,
            trusted_relays: Vec::new(),
            spf_cache_max_entries: 1000,
        }
    }

    #[test]
    fn dmarc_temperror_with_failed_spf_and_dkim_tempfails() {
        let results = results_with(
            SpfVerdict::Fail,
            DkimVerdict::Fail,
            DmarcVerdict::TempError,
            DmarcPolicy::None,
        );
        assert_eq!(
            disposition_for(&enforced_config(), &results),
            MessageDisposition::TempFail,
            "transient DMARC failure with no passing auth must tempfail, not accept"
        );
    }

    #[test]
    fn dmarc_temperror_with_passing_spf_accepts() {
        let results = results_with(
            SpfVerdict::Pass,
            DkimVerdict::None,
            DmarcVerdict::TempError,
            DmarcPolicy::None,
        );
        assert_eq!(
            disposition_for(&enforced_config(), &results),
            MessageDisposition::Accept,
            "a passing SPF means the message is authenticated despite the DMARC lookup blip"
        );
    }

    #[test]
    fn dmarc_temperror_with_passing_dkim_accepts() {
        let results = results_with(
            SpfVerdict::Fail,
            DkimVerdict::Pass,
            DmarcVerdict::TempError,
            DmarcPolicy::None,
        );
        assert_eq!(
            disposition_for(&enforced_config(), &results),
            MessageDisposition::Accept
        );
    }

    #[test]
    fn dmarc_temperror_when_enforcement_disabled_accepts() {
        // Operator opt-out (ENFORCE_DMARC=false) keeps today's fail-open
        // behaviour explicitly.
        let mut config = enforced_config();
        config.enforce_dmarc = false;
        let results = results_with(
            SpfVerdict::Fail,
            DkimVerdict::Fail,
            DmarcVerdict::TempError,
            DmarcPolicy::None,
        );
        assert_eq!(
            disposition_for(&config, &results),
            MessageDisposition::Accept
        );
    }

    #[test]
    fn dmarc_enforcement_matrix_reject_and_quarantine() {
        let results = results_with(
            SpfVerdict::Fail,
            DkimVerdict::Fail,
            DmarcVerdict::Fail,
            DmarcPolicy::Reject,
        );
        assert_eq!(
            disposition_for(&enforced_config(), &results),
            MessageDisposition::Reject
        );

        let results = results_with(
            SpfVerdict::Fail,
            DkimVerdict::Fail,
            DmarcVerdict::Fail,
            DmarcPolicy::Quarantine,
        );
        assert_eq!(
            disposition_for(&enforced_config(), &results),
            MessageDisposition::Quarantine
        );

        // p=none with allow_soft_fail → deliver (with the header).
        let results = results_with(
            SpfVerdict::Fail,
            DkimVerdict::Fail,
            DmarcVerdict::Fail,
            DmarcPolicy::None,
        );
        assert_eq!(
            disposition_for(&enforced_config(), &results),
            MessageDisposition::Accept
        );
    }

    #[test]
    fn test_dmarc_policy_none_without_alignment_is_none_not_fail() {
        let none_record = DmarcRecord {
            policy: DmarcPolicy::None,
            ..reject_record()
        };
        let dmarc = evaluate_dmarc(
            "victim.com",
            "evil.com",
            &spf_outcome(SpfVerdict::Fail, "evil.com"),
            &[],
            DmarcLookup::Record(none_record),
        );
        assert_eq!(dmarc.result, DmarcVerdict::None);
    }

    #[test]
    fn test_dmarc_sp_reject_applies_for_subdomain_even_with_p_none() {
        // FIX-B (c): p=none + sp=reject → subdomain messages get reject.
        // Mirrors lookup_dmarc's org-domain fallback: the effective policy is
        // computed via dmarc_effective_policy before evaluation.
        let record = DmarcRecord {
            policy: DmarcPolicy::None,
            subdomain_policy: Some(DmarcPolicy::Reject),
            spf_alignment: DmarcAlignmentMode::Relaxed,
            dkim_alignment: DmarcAlignmentMode::Relaxed,
        };
        let mut effective = record;
        effective.policy = dmarc_effective_policy(&effective, "sub.example.com", "example.com");
        assert_eq!(effective.policy, DmarcPolicy::Reject);

        let dmarc = evaluate_dmarc(
            "sub.example.com",
            "evil.com",
            &spf_outcome(SpfVerdict::Fail, "evil.com"),
            &[],
            DmarcLookup::Record(effective),
        );
        assert_eq!(dmarc.result, DmarcVerdict::Fail);
        assert_eq!(dmarc.policy, DmarcPolicy::Reject);
    }

    #[test]
    fn test_should_accept_all_pass() {
        let config = EmailAuthConfig {
            require_spf: true,
            require_dkim: true,
            enforce_dmarc: true,
            allow_soft_fail: true,
            trusted_relays: vec![],
            spf_cache_max_entries: 1000,
        };
        let Some(auth) = test_authenticator(config, "mx.test") else {
            return;
        };

        let results = AuthenticationResults {
            spf: SpfOutcome {
                result: SpfVerdict::Pass,
                domain: "example.com".into(),
                explanation: None,
                status: SpfStatus::Fresh,
            },
            dkim: vec![DkimOutcome {
                result: DkimVerdict::Pass,
                domain: "example.com".into(),
                selector: "s1".into(),
                explanation: None,
            }],
            dmarc: DmarcOutcome {
                result: DmarcVerdict::Pass,
                domain: "example.com".into(),
                policy: DmarcPolicy::Reject,
                alignment: DmarcAlignment {
                    spf: true,
                    dkim: true,
                },
            },
            auth_results_header: String::new(),
        };

        assert_eq!(auth.should_accept(&results), MessageDisposition::Accept);
    }

    #[test]
    fn test_should_reject_spf_fail_strict() {
        let config = EmailAuthConfig {
            require_spf: true,
            require_dkim: false,
            enforce_dmarc: false,
            allow_soft_fail: false,
            trusted_relays: vec![],
            spf_cache_max_entries: 1000,
        };
        let Some(auth) = test_authenticator(config, "mx.test") else {
            return;
        };

        let results = AuthenticationResults {
            spf: SpfOutcome {
                result: SpfVerdict::Fail,
                domain: "bad.com".into(),
                explanation: None,
                status: SpfStatus::Fresh,
            },
            dkim: vec![],
            dmarc: DmarcOutcome {
                result: DmarcVerdict::None,
                domain: "bad.com".into(),
                policy: DmarcPolicy::None,
                alignment: DmarcAlignment {
                    spf: false,
                    dkim: false,
                },
            },
            auth_results_header: String::new(),
        };

        assert_eq!(auth.should_accept(&results), MessageDisposition::Reject);
    }

    #[test]
    fn test_should_quarantine_dmarc_fail() {
        let config = EmailAuthConfig {
            require_spf: false,
            require_dkim: false,
            enforce_dmarc: true,
            allow_soft_fail: false,
            trusted_relays: vec![],
            spf_cache_max_entries: 1000,
        };
        let Some(auth) = test_authenticator(config, "mx.test") else {
            return;
        };

        let results = AuthenticationResults {
            spf: SpfOutcome {
                result: SpfVerdict::Fail,
                domain: "spoofed.com".into(),
                explanation: None,
                status: SpfStatus::Fresh,
            },
            dkim: vec![],
            dmarc: DmarcOutcome {
                result: DmarcVerdict::Fail,
                domain: "spoofed.com".into(),
                policy: DmarcPolicy::Quarantine,
                alignment: DmarcAlignment {
                    spf: false,
                    dkim: false,
                },
            },
            auth_results_header: String::new(),
        };

        assert_eq!(auth.should_accept(&results), MessageDisposition::Quarantine);
    }

    #[test]
    fn test_build_auth_results_header() {
        let config = EmailAuthConfig::default();
        let Some(auth) = test_authenticator(config, "mx.apexmail.ee") else {
            return;
        };

        let spf = SpfOutcome {
            result: SpfVerdict::Pass,
            domain: "example.com".into(),
            explanation: None,
            status: SpfStatus::Fresh,
        };
        let dkim = vec![DkimOutcome {
            result: DkimVerdict::Pass,
            domain: "example.com".into(),
            selector: "sel1".into(),
            explanation: None,
        }];
        let dmarc = DmarcOutcome {
            result: DmarcVerdict::Pass,
            domain: "example.com".into(),
            policy: DmarcPolicy::Reject,
            alignment: DmarcAlignment {
                spf: true,
                dkim: true,
            },
        };

        let header = auth.build_auth_results_header(&spf, &dkim, &dmarc);
        assert!(header.contains("Authentication-Results: mx.apexmail.ee"));
        assert!(header.contains("spf=pass"));
        assert!(header.contains("dkim=pass"));
        assert!(header.contains("dmarc=pass"));
    }

    #[test]
    fn auth_results_header_uses_crlf_exclusively_and_needs_one_final_crlf() {
        // The inbound server prepends this header to the stored raw message
        // with exactly one CRLF separator. If the header itself contained a
        // bare LF (or already ended with CRLF), the stored MIME would mix
        // line endings and downstream parsers could resync mid-header.
        let config = EmailAuthConfig::default();
        let Some(auth) = test_authenticator(config, "mx.apexmail.ee") else {
            return;
        };
        let spf = SpfOutcome {
            result: SpfVerdict::SoftFail,
            domain: "example.com".into(),
            explanation: None,
            status: SpfStatus::Fresh,
        };
        let dkim = vec![DkimOutcome {
            result: DkimVerdict::Fail,
            domain: "other.com".into(),
            selector: "s".into(),
            explanation: None,
        }];
        let dmarc = DmarcOutcome {
            result: DmarcVerdict::Fail,
            domain: "example.com".into(),
            policy: DmarcPolicy::Quarantine,
            alignment: DmarcAlignment {
                spf: false,
                dkim: false,
            },
        };

        let header = auth.build_auth_results_header(&spf, &dkim, &dmarc);
        let bytes = header.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'\n' {
                assert!(
                    i > 0 && bytes[i - 1] == b'\r',
                    "bare LF at offset {i} in A-R header: {header:?}"
                );
            }
        }
        assert!(
            !header.ends_with("\r\n") && !header.ends_with('\n'),
            "header must NOT carry its own trailing terminator: {header:?}"
        );
        assert!(header.starts_with("Authentication-Results: mx.apexmail.ee;"));
    }
}
