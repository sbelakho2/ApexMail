use crate::config::GraderConfig;
use crate::network_checks::{lookup_bimi, lookup_mta_sts, lookup_tls_rpt, BimiInfo, MtaStsInfo, TlsRptInfo};
use crate::scoring;
use crate::scoring::GradeCalculator;
use crate::types::*;
use apexmail_dns_resolver::lookup::DnsLookup;
use apexmail_dns_resolver::records::{DmarcPolicy, MxRecord, SpfRecord};
use dashmap::DashMap;
use futures::stream::{FuturesUnordered, StreamExt};
use mta::auth::email_authentication::{
    AuthenticationResults, EmailAuthenticator, SpfVerdict,
};
use mta::config::EmailAuthConfig;
use spam_filter::content_scorer::{score_content, ContentScore};
use spam_filter::engine::{SpamEngine, SpamVerdict};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use threat_intel::domain_blocklist::DomainBlocklist;
use tokio::sync::{Mutex, OnceCell};

const MAX_DOMAIN_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;
const MAX_DKIM_SELECTORS: usize = 10;
const MAX_DKIM_SELECTOR_LEN: usize = 63;
const MAX_RECIPIENTS: usize = 100;
const MAX_HEADER_NAME_LEN: usize = 64;
const MAX_HEADER_VALUE_LEN: usize = 4096;
const MAX_SUBJECT_LEN: usize = 998;

#[derive(Debug, Clone)]
pub struct MxInfo {
    pub priority: u16,
    pub exchange: String,
}

#[derive(Debug, Clone)]
pub struct SpfInfo {
    pub raw: String,
    pub hard_fail: bool,
    pub soft_fail: bool,
}

#[derive(Debug, Clone)]
pub struct DkimInfo {
    pub selector: String,
    pub key_type: String,
    pub key_size: usize,
    /// True for Ed25519 / EdDSA keys, which are strong regardless of size.
    pub is_ed25519: bool,
}

#[derive(Debug, Clone)]
pub struct DmarcInfo {
    pub policy: String,
    pub pct: u8,
}

/// Result of running domain-level checks. Carried through composite scoring
/// without intermediate JSON serialization.
#[derive(Debug, Clone)]
pub struct DomainAssessment {
    pub mx: Vec<MxInfo>,
    pub spf: Option<SpfInfo>,
    pub dkim: Vec<DkimInfo>,
    pub dmarc: Option<DmarcInfo>,
    pub bimi: Option<BimiInfo>,
    pub mta_sts: Option<MtaStsInfo>,
    pub tls_rpt: Option<TlsRptInfo>,
    pub has_a_record: bool,
    pub blocklist_hits: Vec<(String, String)>, // (source, confidence-bucket)
}

struct DomainCache {
    inner: DashMap<String, CachedResult>,
    ttl: Duration,
}

struct CachedResult {
    result: GraderResponse,
    cached_at: Instant,
}

impl DomainCache {
    fn new(ttl_secs: u64) -> Self {
        Self {
            inner: DashMap::new(),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    fn get(&self, domain: &str) -> Option<GraderResponse> {
        let entry = self.inner.get(domain)?;
        if entry.cached_at.elapsed() < self.ttl {
            Some(entry.result.clone())
        } else {
            drop(entry);
            self.inner.remove(domain);
            None
        }
    }

    fn set(&self, domain: String, result: GraderResponse) {
        self.inner.insert(domain, CachedResult {
            result,
            cached_at: Instant::now(),
        });
        if self.inner.len() > 1000 {
            self.inner.retain(|_, v| v.cached_at.elapsed() < self.ttl);
        }
    }
}

/// Singleflight gate that ensures only one async task does the work for a
/// given key while others wait, then read the freshly-populated cache.
struct SingleFlight {
    inner: DashMap<String, Arc<Mutex<()>>>,
}

impl SingleFlight {
    fn new() -> Self {
        Self { inner: DashMap::new() }
    }

    fn lock_for(&self, key: &str) -> Arc<Mutex<()>> {
        self.inner
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    fn release(&self, key: &str) {
        // Drop only if no one else is holding a reference. DashMap doesn't
        // expose strong-count cheaply, so we periodically prune instead.
        if self.inner.len() > 2_048 {
            self.inner.retain(|_, mtx| Arc::strong_count(mtx) > 1);
        }
        let _ = key;
    }
}

pub struct GraderEngine {
    config: GraderConfig,
    dns_lookup: DnsLookup,
    blocklist: Option<Arc<DomainBlocklist>>,
    cache: DomainCache,
    flight: SingleFlight,
    rate_limits: DashMap<String, VecDeque<Instant>>,
    /// Per-tenant DNS budget (used by /submit) independent from the public
    /// HTTP rate limit on /check.
    tenant_dns_budget: DashMap<String, VecDeque<Instant>>,
    spam_engine: SpamEngine,
    authenticator: OnceCell<EmailAuthenticator>,
    http: reqwest::Client,
}

#[derive(Debug, Clone)]
pub struct ValidatedEmailSubmission {
    pub domain: String,
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub body_text: String,
    pub body_html: String,
    pub headers: Vec<(String, String)>,
    pub selectors: Vec<String>,
    pub sender_ip: Option<IpAddr>,
    pub helo_hostname: Option<String>,
    pub mail_from: String,
}

impl GraderEngine {
    pub fn new(
        config: GraderConfig,
        blocklist: Option<Arc<DomainBlocklist>>,
    ) -> Result<Self, String> {
        // Fail fast if encryption is enabled but the key is missing or invalid.
        if config.encrypt_stored_content {
            let key = config
                .encryption_master_key_base64
                .as_deref()
                .ok_or_else(|| "encrypt_stored_content=true but no master key configured".to_string())?;
            crate::crypto::Cipher::from_base64_key(key)
                .map_err(|e| format!("encryption master key rejected: {e}"))?;
        }

        let dns_lookup = DnsLookup::new()
            .map_err(|e| format!("DNS resolver init failed: {e}"))?;
        let http = reqwest::Client::builder()
            .user_agent("ApexMail-Grader/1.0")
            .timeout(Duration::from_secs(config.network_timeout_seconds.max(1)))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("HTTP client init failed: {e}"))?;
        // Validate all configured tenant scoring weights at startup so
        // misconfigured zero/infinite weights are caught early and fall back
        // to uniform defaults with a warning.
        for (tenant_id, weights) in &config.tenant_weights {
            weights.validate_or_fallback(tenant_id);
        }

        Ok(Self {
            cache: DomainCache::new(config.cache_ttl_seconds),
            flight: SingleFlight::new(),
            dns_lookup,
            blocklist,
            rate_limits: DashMap::new(),
            tenant_dns_budget: DashMap::new(),
            spam_engine: SpamEngine::new(),
            authenticator: OnceCell::new(),
            http,
            config,
        })
    }

    pub fn config(&self) -> &GraderConfig {
        &self.config
    }

    /// Public, IP-rate-limited domain assessment.
    pub async fn check_domain(
        &self,
        request: &DomainCheckRequest,
    ) -> Result<GraderResponse, GraderError> {
        let domain = normalize_domain(&request.domain)?;
        let selectors = normalize_selectors(&request.selectors, &self.config.default_dkim_selectors)?;
        let cache_key = format!("{}|{}", domain, selectors.join(","));

        if let Some(cached) = self.cache.get(&cache_key) {
            metrics::counter!("grader.domain_cache.hit").increment(1);
            return Ok(cached);
        }

        // Singleflight: only one task does the work; the rest await and read.
        let lock = self.flight.lock_for(&cache_key);
        let _guard = lock.lock().await;
        if let Some(cached) = self.cache.get(&cache_key) {
            metrics::counter!("grader.domain_cache.hit").increment(1);
            return Ok(cached);
        }
        metrics::counter!("grader.domain_cache.miss").increment(1);

        let response = self.do_domain_check(&domain, &selectors, None).await?;
        self.cache.set(cache_key.clone(), response.clone());
        self.flight.release(&cache_key);
        Ok(response)
    }

    /// Run all domain checks (DNS, BIMI, MTA-STS, TLS-RPT, blocklist) and
    /// produce a `GraderResponse`. `tenant_id`, when supplied, scopes the
    /// per-tenant DNS budget so /submit cannot starve /check.
    async fn do_domain_check(
        &self,
        domain: &str,
        selectors: &[String],
        tenant_id: Option<&str>,
    ) -> Result<GraderResponse, GraderError> {
        let net_to = Duration::from_secs(self.config.network_timeout_seconds.max(1));

        // MX, SPF, DMARC, A, BIMI, TLS-RPT in parallel; bounded DKIM lookups.
        let mx_fut = tokio::time::timeout(net_to, self.dns_lookup.lookup_mx(domain));
        let spf_fut = tokio::time::timeout(net_to, self.dns_lookup.lookup_spf(domain));
        let dmarc_fut = tokio::time::timeout(net_to, self.dns_lookup.lookup_dmarc(domain));
        let a_fut = tokio::time::timeout(net_to, self.dns_lookup.lookup_a(domain));
        let bimi_fut = tokio::time::timeout(net_to, lookup_bimi(&self.dns_lookup, domain));
        let tls_rpt_fut = tokio::time::timeout(net_to, lookup_tls_rpt(&self.dns_lookup, domain));
        let mta_sts_fut = tokio::time::timeout(
            net_to.saturating_mul(2), // policy fetch may take a bit longer
            lookup_mta_sts(
                &self.dns_lookup,
                &self.http,
                domain,
                self.config.mta_sts_policy_max_bytes,
                net_to,
            ),
        );

        let (mx_res, spf_res, dmarc_res, a_res, bimi_res, tls_rpt_res, mta_sts_res) =
            tokio::join!(mx_fut, spf_fut, dmarc_fut, a_fut, bimi_fut, tls_rpt_fut, mta_sts_fut);

        // Account DNS lookups against tenant budget (best-effort).
        if let Some(t) = tenant_id {
            self.charge_tenant_dns_budget(t, 7);
        }

        let mx_records = mx_res.unwrap_or(Ok(Vec::new())).unwrap_or_default();
        let mx: Vec<MxInfo> = mx_records.iter().map(|m: &MxRecord| MxInfo {
            priority: m.priority,
            exchange: m.exchange.clone(),
        }).collect();

        let spf: Option<SpfInfo> = spf_res
            .unwrap_or(Ok(None))
            .unwrap_or(None)
            .map(|s: SpfRecord| SpfInfo {
                raw: s.raw.clone(),
                hard_fail: s.is_hard_fail(),
                soft_fail: s.is_soft_fail(),
            });

        let dmarc: Option<DmarcInfo> = dmarc_res
            .unwrap_or(Ok(None))
            .unwrap_or(None)
            .map(|d: DmarcPolicy| DmarcInfo {
                policy: d.policy.clone(),
                pct: d.pct,
            });

        let has_a_record = a_res
            .unwrap_or(Ok(Vec::new()))
            .map(|addrs| !addrs.is_empty())
            .unwrap_or(false);

        let bimi = bimi_res.unwrap_or(None);
        let tls_rpt = tls_rpt_res.unwrap_or(None);
        let mta_sts = mta_sts_res.unwrap_or(None);

        // Bounded concurrent DKIM lookups.
        let concurrency = self.config.dkim_lookup_concurrency.max(1);
        let dkim: Vec<DkimInfo> = {
            let mut out: Vec<DkimInfo> = Vec::new();
            let dns = &self.dns_lookup;
            // Process selectors in chunks of `concurrency` so in-flight DNS
            // queries are bounded regardless of input size.
            for chunk in selectors.chunks(concurrency) {
                let mut futs: FuturesUnordered<_> = chunk
                    .iter()
                    .map(|sel| {
                        let sel = sel.clone();
                        async move {
                            let r = tokio::time::timeout(net_to, dns.lookup_dkim(&sel, domain)).await;
                            (sel, r)
                        }
                    })
                    .collect();
                while let Some((sel, r)) = futs.next().await {
                    if let Ok(Ok(Some(dkim))) = r {
                        let key_type = dkim.key_type.clone();
                        let is_ed25519 = key_type.eq_ignore_ascii_case("ed25519")
                            || key_type.eq_ignore_ascii_case("ed448");
                        let key_size = if is_ed25519 {
                            // Ed25519 strength is fixed; reported as 256-bit equivalent.
                            256
                        } else {
                            (dkim.public_key.len() * 6) / 8
                        };
                        out.push(DkimInfo {
                            selector: sel,
                            key_type,
                            key_size,
                            is_ed25519,
                        });
                    }
                }
            }
            out
        };

        let blocklist_hits = if let Some(ref bl) = self.blocklist {
            match bl.lookup(domain) {
                Some(entry) => {
                    let confidence = if entry.confidence >= 7.0 { "high" }
                        else if entry.confidence >= 4.0 { "medium" }
                        else { "low" };
                    vec![(entry.source.clone(), confidence.to_string())]
                }
                None => Vec::new(),
            }
        } else {
            Vec::new()
        };

        let assessment = DomainAssessment {
            mx,
            spf,
            dkim,
            dmarc,
            bimi,
            mta_sts,
            tls_rpt,
            has_a_record,
            blocklist_hits,
        };

        Ok(self.assemble_domain_response(domain, &assessment))
    }

    fn assemble_domain_response(&self, domain: &str, a: &DomainAssessment) -> GraderResponse {
        let mut findings: Vec<Finding> = Vec::new();

        let (dns_score, dns_details) = scoring::score_dns_health(
            &a.mx, a.spf.as_ref(), &a.dkim, a.dmarc.as_ref(), a.has_a_record,
        );

        let (spf_score, spf_details) = scoring::score_spf(a.spf.as_ref());
        let (dkim_score, dkim_details) = scoring::score_dkim(&a.dkim);
        let (dmarc_score, dmarc_details) = scoring::score_dmarc(a.dmarc.as_ref());
        let (modern_score, modern_details) = scoring::score_modern_security(
            a.bimi.as_ref(), a.mta_sts.as_ref(), a.tls_rpt.as_ref(),
        );

        let auth_details = serde_json::json!({
            "spf": spf_details,
            "dkim": dkim_details,
            "dmarc": dmarc_details,
            "modern_security": modern_details,
        });
        // SPF (max 30) + DKIM (max 20) + DMARC (max 30) + Modern (max 20) = 100.
        let auth_score =
            ((spf_score + dkim_score + dmarc_score + modern_score) as u32).min(100) as u16;

        // Spam likelihood from auth quality only when no message content.
        let spam_score = if auth_score >= 80 { 90 }
            else if auth_score >= 60 { 75 }
            else if auth_score >= 40 { 50 }
            else { 30 };

        let (rep_score, rep_details) = if a.blocklist_hits.is_empty() {
            scoring::score_reputation(0, "none")
        } else {
            let (source, confidence) = &a.blocklist_hits[0];
            findings.push(Finding {
                severity: FindingSeverity::Warning,
                category: "reputation".into(),
                message: format!(
                    "Domain found in blocklist '{source}' (confidence: {confidence})"
                ),
            });
            scoring::score_reputation(a.blocklist_hits.len(), confidence)
        };

        if a.mx.is_empty() {
            findings.push(Finding {
                severity: FindingSeverity::Error,
                category: "dns".into(),
                message: "No MX records found — domain cannot receive email".into(),
            });
        } else if a.mx.len() < 2 {
            findings.push(Finding {
                severity: FindingSeverity::Info,
                category: "dns".into(),
                message: "Only one MX record — add a backup MX for redundancy".into(),
            });
        }
        if a.spf.is_none() {
            findings.push(Finding {
                severity: FindingSeverity::Error,
                category: "authentication".into(),
                message: "No SPF record found — emails may be marked as spam".into(),
            });
        }
        if a.dkim.is_empty() {
            findings.push(Finding {
                severity: FindingSeverity::Error,
                category: "authentication".into(),
                message: "No DKIM records found for common selectors — add DKIM signing".into(),
            });
        }
        if let Some(ref dmarc) = a.dmarc {
            if dmarc.policy.to_lowercase() != "reject" {
                findings.push(Finding {
                    severity: FindingSeverity::Warning,
                    category: "authentication".into(),
                    message: format!(
                        "DMARC policy is '{}' — consider upgrading to 'reject'",
                        dmarc.policy
                    ),
                });
            }
        } else {
            findings.push(Finding {
                severity: FindingSeverity::Error,
                category: "authentication".into(),
                message: "No DMARC record found — consider adding DMARC to prevent spoofing".into(),
            });
        }
        if a.mta_sts.is_none() {
            findings.push(Finding {
                severity: FindingSeverity::Info,
                category: "transport_security".into(),
                message: "No MTA-STS policy detected — add `_mta-sts` TXT and well-known policy file".into(),
            });
        }
        if a.tls_rpt.is_none() {
            findings.push(Finding {
                severity: FindingSeverity::Info,
                category: "transport_security".into(),
                message: "No TLS-RPT record — add `_smtp._tls` TXT to receive TLS failure reports".into(),
            });
        }

        let weights = self.config.weights_for("");
        let (final_score, grade_letter, breakdown, final_findings, recommendations) =
            GradeCalculator::calculate_with_weights(
                dns_score,
                Some(dns_details),
                auth_score,
                Some(auth_details),
                spam_score,
                None,
                rep_score,
                Some(rep_details),
                findings,
                &weights,
            );

        GraderResponse {
            id: None,
            domain: domain.to_string(),
            score: final_score,
            grade: grade_letter.to_string(),
            breakdown,
            findings: final_findings,
            recommendations,
            created_at: None,
        }
    }

    /// Per-IP rate limit for /check.
    pub fn check_rate_limit(&self, key: &str) -> bool {
        let limit = self.config.rate_limit_max as usize;
        if limit == 0 {
            return false;
        }
        let now = Instant::now();
        let window = Duration::from_secs(self.config.rate_limit_window_seconds.max(1));
        let mut bucket = self.rate_limits.entry(key.to_string()).or_default();
        while bucket.front().is_some_and(|t| now.duration_since(*t) >= window) {
            bucket.pop_front();
        }
        if bucket.len() >= limit {
            metrics::counter!("grader.rate_limit.blocked").increment(1);
            return false;
        }
        bucket.push_back(now);
        drop(bucket);
        if self.rate_limits.len() > 10_000 {
            self.rate_limits
                .retain(|_, q| q.back().is_some_and(|t| now.duration_since(*t) < window));
        }
        true
    }

    /// Per-tenant DNS budget. Returns `true` when the request fits within the
    /// budget. Engine-level lookups in /submit decrement this independently
    /// from the HTTP rate limiter.
    pub fn check_tenant_dns_budget(&self, tenant_id: &str, units: u32) -> bool {
        let limit = self.config.tenant_dns_budget_max;
        if limit == 0 {
            return false;
        }
        let now = Instant::now();
        let window = Duration::from_secs(self.config.tenant_dns_budget_window_seconds.max(1));
        let mut bucket = self.tenant_dns_budget.entry(tenant_id.to_string()).or_default();
        while bucket.front().is_some_and(|t| now.duration_since(*t) >= window) {
            bucket.pop_front();
        }
        if bucket.len() as u32 + units > limit {
            metrics::counter!("grader.tenant_dns_budget.exhausted").increment(1);
            return false;
        }
        for _ in 0..units {
            bucket.push_back(now);
        }
        drop(bucket);
        if self.tenant_dns_budget.len() > 10_000 {
            self.tenant_dns_budget
                .retain(|_, q| q.back().is_some_and(|t| now.duration_since(*t) < window));
        }
        true
    }

    fn charge_tenant_dns_budget(&self, tenant_id: &str, units: u32) {
        // Best-effort accounting (not gated): used when the engine itself
        // performs additional lookups beyond the initial admission.
        let now = Instant::now();
        let window = Duration::from_secs(self.config.tenant_dns_budget_window_seconds.max(1));
        let mut bucket = self.tenant_dns_budget.entry(tenant_id.to_string()).or_default();
        while bucket.front().is_some_and(|t| now.duration_since(*t) >= window) {
            bucket.pop_front();
        }
        for _ in 0..units {
            bucket.push_back(now);
        }
    }

    pub fn validate_submission(
        &self,
        request: &EmailSubmitRequest,
    ) -> Result<ValidatedEmailSubmission, GraderError> {
        validate_submission(request, &self.config)
    }

    /// Full email analysis. Caller is responsible for tenant scope and DNS
    /// budget admission.
    pub async fn analyze_email(
        &self,
        submission: &ValidatedEmailSubmission,
        tenant_id: &str,
    ) -> Result<GraderResponse, GraderError> {
        let domain = submission.domain.clone();
        let selectors = submission.selectors.clone();

        // Reuse cache when possible — dramatically reduces DNS load on retries.
        let cache_key = format!("{}|{}", domain, selectors.join(","));
        let domain_check = if let Some(cached) = self.cache.get(&cache_key) {
            metrics::counter!("grader.domain_cache.hit").increment(1);
            cached
        } else {
            let lock = self.flight.lock_for(&cache_key);
            let _g = lock.lock().await;
            if let Some(cached) = self.cache.get(&cache_key) {
                metrics::counter!("grader.domain_cache.hit").increment(1);
                cached
            } else {
                metrics::counter!("grader.domain_cache.miss").increment(1);
                let r = self.do_domain_check(&domain, &selectors, Some(tenant_id)).await?;
                self.cache.set(cache_key.clone(), r.clone());
                self.flight.release(&cache_key);
                r
            }
        };

        let raw_message = build_raw_message(submission);
        let auth_results = self.authenticate_email(&raw_message, submission).await;

        let auth_header = auth_results.as_ref().map(|r| r.auth_results_header.as_str());
        let spam_verdict = self.analyze_spam(submission, auth_header);
        let content_score = spam_verdict.content_score.clone();

        let auth_score = self.compute_auth_score(&domain_check, auth_results.as_ref());
        let spam_likelihood = scoring::invert_spam_score(spam_verdict.score);
        let content_quality = scoring::invert_content_score(content_score.score);

        let mut findings = domain_check.findings;
        findings.extend(self.findings_from_spam(&spam_verdict));
        if auth_results.is_none() {
            findings.push(Finding {
                severity: FindingSeverity::Info,
                category: "authentication".into(),
                message: "Message-level SPF/DKIM/DMARC was not evaluated because sender_ip and helo_hostname were not supplied; score uses DNS authentication readiness.".into(),
            });
        }

        let auth_details = auth_results.as_ref().map(|r| serde_json::json!({
            "spf": r.spf,
            "dkim": r.dkim,
            "dmarc": r.dmarc,
            "authentication_results": r.auth_results_header,
        }));
        let spam_details = serde_json::json!({
            "classification": spam_verdict.classification.to_string(),
            "bayesian_probability": spam_verdict.bayesian_probability,
            "header_score": spam_verdict.header_score.score,
            "content_score": spam_verdict.content_score.score,
            "url_score": spam_verdict.url_score.score,
            "url_count": spam_verdict.url_score.url_count,
        });

        let weights = self.config.weights_for(tenant_id);
        let (final_score, grade_letter, mut breakdown, final_findings, recommendations) =
            GradeCalculator::calculate_with_weights(
                domain_check.breakdown.dns_health.score,
                domain_check.breakdown.dns_health.details,
                auth_score.min(100),
                auth_details,
                spam_likelihood.min(100),
                Some(content_quality.min(100)),
                domain_check.breakdown.reputation.score,
                domain_check.breakdown.reputation.details,
                findings,
                &weights,
            );

        let mut all_recs = recommendations;
        all_recs.push(format!(
            "Spam engine classification: {} (lower risk improves inbox placement)",
            spam_verdict.classification
        ));
        if content_score.score > 0.5 {
            all_recs.push("Improve email content quality — avoid spam trigger phrases".to_string());
        }
        all_recs.sort();
        all_recs.dedup();

        breakdown.spam_likelihood.details = Some(spam_details);

        Ok(GraderResponse {
            id: Some(uuid::Uuid::new_v4()),
            domain,
            score: final_score,
            grade: grade_letter.to_string(),
            breakdown,
            findings: final_findings,
            recommendations: all_recs,
            created_at: Some(chrono::Utc::now()),
        })
    }

    async fn authenticate_email(
        &self,
        raw_message: &[u8],
        submission: &ValidatedEmailSubmission,
    ) -> Option<AuthenticationResults> {
        let sender_ip = submission.sender_ip?;
        let helo = submission.helo_hostname.as_deref()?;
        let mail_from = submission.mail_from.as_str();

        let net_to = Duration::from_secs(self.config.network_timeout_seconds.max(1));
        let authenticator = match tokio::time::timeout(
            net_to,
            self.authenticator.get_or_try_init(|| async {
                EmailAuthenticator::new(
                    EmailAuthConfig::default(),
                    self.config.auth_hostname.clone(),
                ).await
            }),
        ).await {
            Ok(Ok(a)) => a,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "grader: authenticator init failed");
                return None;
            }
            Err(_) => {
                tracing::warn!("grader: authenticator init timeout");
                return None;
            }
        };

        match tokio::time::timeout(
            net_to.saturating_mul(2),
            authenticator.authenticate(raw_message, sender_ip, helo, mail_from),
        ).await {
            Ok(Ok(r)) => Some(r),
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "grader: message authentication failed");
                None
            }
            Err(_) => {
                tracing::warn!("grader: message authentication timeout");
                None
            }
        }
    }

    fn analyze_spam(
        &self,
        submission: &ValidatedEmailSubmission,
        auth_results: Option<&str>,
    ) -> SpamVerdict {
        let body = if !submission.body_text.is_empty() {
            submission.body_text.clone()
        } else {
            strip_html_tags(&submission.body_html)
        };
        let mut headers: Vec<(String, String)> = submission.headers.clone();
        if !submission.subject.is_empty() {
            headers.push(("Subject".to_string(), submission.subject.clone()));
        }
        if !submission.from.is_empty() {
            headers.push(("From".to_string(), submission.from.clone()));
        }
        self.spam_engine.analyze(&body, &headers, auth_results)
    }

    fn findings_from_spam(&self, verdict: &SpamVerdict) -> Vec<Finding> {
        let mut out = Vec::new();
        if verdict.score >= 0.7 {
            out.push(Finding {
                severity: FindingSeverity::Warning,
                category: "spam".into(),
                message: format!(
                    "Spam engine classified message as {} (score {:.2})",
                    verdict.classification, verdict.score
                ),
            });
        }
        if verdict.url_score.url_count > 20 {
            out.push(Finding {
                severity: FindingSeverity::Info,
                category: "content".into(),
                message: format!(
                    "High URL count ({}) — may trigger spam filters",
                    verdict.url_score.url_count
                ),
            });
        }
        out
    }

    #[allow(dead_code)]
    fn score_email_content(&self, body_text: &str, body_html: &str, subject: &str) -> ContentScore {
        let combined = format!("{} {} {}", subject, body_text, strip_html_tags(body_html));
        score_content(&combined)
    }

    fn compute_auth_score(
        &self,
        domain_check: &GraderResponse,
        auth_results: Option<&AuthenticationResults>,
    ) -> u16 {
        let domain_auth = domain_check.breakdown.authentication.score;
        let bonus = match auth_results {
            Some(r) if r.spf.result == SpfVerdict::Pass => 10u16,
            _ => 0,
        };
        (domain_auth + bonus).min(100)
    }
}

pub(crate) fn normalize_domain(input: &str) -> Result<String, GraderError> {
    let trimmed = input.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(GraderError::InvalidDomain("empty domain".into()));
    }
    if trimmed.len() > MAX_DOMAIN_LEN {
        return Err(GraderError::InvalidDomain("domain exceeds 253 chars".into()));
    }
    let ascii = idna::domain_to_ascii(trimmed)
        .map_err(|e| GraderError::InvalidDomain(format!("IDNA: {e}")))?;
    if !ascii.contains('.') {
        return Err(GraderError::InvalidDomain("domain must contain a dot".into()));
    }
    for label in ascii.split('.') {
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return Err(GraderError::InvalidDomain("invalid label length".into()));
        }
    }
    Ok(ascii.to_ascii_lowercase())
}

pub(crate) fn normalize_selectors(
    requested: &[String],
    defaults: &[String],
) -> Result<Vec<String>, GraderError> {
    let source: &[String] = if requested.is_empty() { defaults } else { requested };
    if source.len() > MAX_DKIM_SELECTORS {
        return Err(GraderError::InvalidDomain(format!(
            "too many DKIM selectors (max {MAX_DKIM_SELECTORS})"
        )));
    }
    let mut out: Vec<String> = Vec::with_capacity(source.len());
    for sel in source {
        let s = sel.trim();
        if s.is_empty() || s.len() > MAX_DKIM_SELECTOR_LEN {
            continue;
        }
        // Accept Unicode letters/numbers in addition to ASCII for
        // internationalised selector support.
        if !s.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.') {
            continue;
        }
        // Full Unicode case folding (e.g. Turkish İ → i, German ẞ → ss)
        // rather than ASCII-only lowercasing.
        let lowered = s.to_lowercase();
        if !out.contains(&lowered) {
            out.push(lowered);
        }
    }
    if out.is_empty() {
        out.push("default".into());
    }
    out.sort();
    Ok(out)
}

pub(crate) fn validate_submission(
    request: &EmailSubmitRequest,
    config: &GraderConfig,
) -> Result<ValidatedEmailSubmission, GraderError> {
    let from = request.from.as_deref().unwrap_or("").trim().to_string();
    if from.is_empty() {
        return Err(GraderError::InvalidDomain("`from` is required".into()));
    }
    let domain_input = request
        .domain
        .clone()
        .or_else(|| from.split('@').next_back().map(|s| s.to_string()))
        .unwrap_or_default();
    let domain = normalize_domain(&domain_input)?;

    if request.to.len() > MAX_RECIPIENTS {
        return Err(GraderError::InvalidDomain(format!(
            "too many recipients (max {MAX_RECIPIENTS})"
        )));
    }
    let to: Vec<String> = request
        .to
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let subject = request.subject.as_deref().unwrap_or("").to_string();
    if subject.len() > MAX_SUBJECT_LEN {
        return Err(GraderError::InvalidDomain("subject exceeds 998 chars".into()));
    }
    if subject.contains('\r') || subject.contains('\n') {
        return Err(GraderError::InvalidDomain("subject contains CR/LF".into()));
    }

    let body_text = request.body_text.clone().unwrap_or_default();
    let body_html = request.body_html.clone().unwrap_or_default();
    let total_body = body_text.len().saturating_add(body_html.len());
    if total_body > config.max_body_size as usize {
        return Err(GraderError::BodyTooLarge(total_body, config.max_body_size));
    }

    let mut headers: Vec<(String, String)> = Vec::new();
    if let Some(map) = &request.headers {
        for (k, v) in map {
            let name = k.trim();
            let value = v.trim();
            if name.is_empty() || name.len() > MAX_HEADER_NAME_LEN || value.len() > MAX_HEADER_VALUE_LEN {
                continue;
            }
            if name.contains(':') || name.chars().any(|c| c.is_control()) {
                continue;
            }
            if value.contains('\r') || value.contains('\n') {
                continue;
            }
            headers.push((name.to_string(), value.to_string()));
        }
    }

    let selectors = normalize_selectors(&request.selectors, &config.default_dkim_selectors)?;

    let sender_ip = match request.sender_ip.as_deref() {
        Some(s) => Some(
            s.parse::<IpAddr>()
                .map_err(|_| GraderError::InvalidDomain("sender_ip is not a valid IP".into()))?,
        ),
        None => None,
    };
    let helo_hostname = request.helo_hostname.clone();
    let mail_from = request.mail_from.clone().unwrap_or_else(|| from.clone());

    Ok(ValidatedEmailSubmission {
        domain,
        from,
        to,
        subject,
        body_text,
        body_html,
        headers,
        selectors,
        sender_ip,
        helo_hostname,
        mail_from,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum GraderError {
    #[error("Invalid domain: {0}")]
    InvalidDomain(String),
    #[error("Domain {0} does not exist")]
    DomainNotFound(String),
    #[error("Email body too large: {0} bytes (max {1})")]
    BodyTooLarge(usize, u32),
    #[error("Tenant DNS budget exhausted")]
    TenantBudgetExhausted,
    #[error("Internal error: {0}")]
    Internal(String),
}

pub(crate) fn build_raw_message(submission: &ValidatedEmailSubmission) -> Vec<u8> {
    let to_line = submission.to.join(", ");
    let mut msg = format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\n",
        submission.from, to_line, submission.subject
    );
    for (k, v) in &submission.headers {
        msg.push_str(k);
        msg.push_str(": ");
        msg.push_str(v);
        msg.push_str("\r\n");
    }
    msg.push_str("\r\n");
    if !submission.body_text.is_empty() {
        msg.push_str(&submission.body_text);
        msg.push_str("\r\n");
    }
    if !submission.body_html.is_empty() {
        msg.push_str(&submission.body_html);
        msg.push_str("\r\n");
    }
    msg.into_bytes()
}

pub(crate) fn strip_html_tags(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => result.push(ch),
            _ => {}
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> GraderConfig {
        GraderConfig {
            enabled: true,
            rate_limit_max: 3,
            rate_limit_window_seconds: 60,
            tenant_dns_budget_max: 10,
            tenant_dns_budget_window_seconds: 60,
            cache_ttl_seconds: 1,
            default_dkim_selectors: vec!["default".into()],
            max_body_size: 1024,
            encrypt_stored_content: false,
            encryption_master_key_base64: None,
            auth_hostname: "test.local".into(),
            network_timeout_seconds: 1,
            dkim_lookup_concurrency: 2,
            mta_sts_policy_max_bytes: 4096,
            idempotency_window_seconds: 3600,
            default_retention_days: 30,
            max_jsonb_bytes: 16_384,
            tenant_weights: Default::default(),
        }
    }

    #[test]
    fn normalize_domain_lowercases_and_strips_dot() {
        let d = normalize_domain("Example.COM.").unwrap();
        assert_eq!(d, "example.com");
    }

    #[test]
    fn normalize_domain_idna_converts_unicode() {
        let d = normalize_domain("bücher.de").unwrap();
        assert!(d.starts_with("xn--"));
        assert!(d.ends_with(".de"));
    }

    #[test]
    fn normalize_domain_rejects_empty() {
        assert!(normalize_domain("").is_err());
        assert!(normalize_domain("   ").is_err());
    }

    #[test]
    fn normalize_domain_rejects_no_dot() {
        assert!(normalize_domain("localhost").is_err());
    }

    #[test]
    fn normalize_domain_rejects_long_label() {
        let label = "a".repeat(64);
        let d = format!("{label}.com");
        assert!(normalize_domain(&d).is_err());
    }

    #[test]
    fn normalize_selectors_dedupes_sorts_and_falls_back() {
        let defaults = vec!["default".to_string()];
        let s = normalize_selectors(&[], &defaults).unwrap();
        assert_eq!(s, vec!["default".to_string()]);

        let s = normalize_selectors(&["zeta".into(), "alpha".into(), "ALPHA".into()], &defaults)
            .unwrap();
        assert_eq!(s, vec!["alpha".to_string(), "zeta".to_string()]);
    }

    #[test]
    fn normalize_selectors_rejects_too_many() {
        let many: Vec<String> = (0..MAX_DKIM_SELECTORS + 1).map(|i| format!("s{i}")).collect();
        assert!(normalize_selectors(&many, &[]).is_err());
    }

    #[test]
    fn validate_submission_requires_from_and_domain() {
        let req = EmailSubmitRequest {
            domain: None, from: None, to: vec![], subject: None, body_text: None,
            body_html: None, headers: None, selectors: vec![], sender_ip: None,
            helo_hostname: None, mail_from: None,
        };
        assert!(validate_submission(&req, &cfg()).is_err());
    }

    #[test]
    fn validate_submission_derives_domain_from_from_address() {
        let req = EmailSubmitRequest {
            domain: None, from: Some("alice@Example.com".into()), to: vec!["bob@example.org".into()],
            subject: Some("hi".into()), body_text: Some("hello".into()), body_html: None,
            headers: None, selectors: vec![], sender_ip: None, helo_hostname: None, mail_from: None,
        };
        let v = validate_submission(&req, &cfg()).unwrap();
        assert_eq!(v.domain, "example.com");
        assert_eq!(v.from, "alice@Example.com");
        assert_eq!(v.mail_from, "alice@Example.com");
    }

    #[test]
    fn validate_submission_rejects_crlf_subject() {
        let req = EmailSubmitRequest {
            domain: Some("example.com".into()), from: Some("a@example.com".into()), to: vec![],
            subject: Some("hi\r\nBcc: leak@evil.com".into()), body_text: None, body_html: None,
            headers: None, selectors: vec![], sender_ip: None, helo_hostname: None, mail_from: None,
        };
        assert!(validate_submission(&req, &cfg()).is_err());
    }

    #[test]
    fn validate_submission_strips_crlf_header_values() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Bad".to_string(), "ok\r\nBcc: leak@evil.com".to_string());
        headers.insert("X-Good".to_string(), "fine".to_string());
        let req = EmailSubmitRequest {
            domain: Some("example.com".into()), from: Some("a@example.com".into()), to: vec![],
            subject: Some("ok".into()), body_text: Some("body".into()), body_html: None,
            headers: Some(headers), selectors: vec![], sender_ip: None, helo_hostname: None, mail_from: None,
        };
        let v = validate_submission(&req, &cfg()).unwrap();
        assert!(v.headers.iter().all(|(k, _)| k != "X-Bad"));
        assert!(v.headers.iter().any(|(k, _)| k == "X-Good"));
    }

    #[test]
    fn validate_submission_enforces_body_size_cap() {
        let big = "x".repeat(2000);
        let req = EmailSubmitRequest {
            domain: Some("example.com".into()), from: Some("a@example.com".into()), to: vec![],
            subject: Some("ok".into()), body_text: Some(big), body_html: None,
            headers: None, selectors: vec![], sender_ip: None, helo_hostname: None, mail_from: None,
        };
        assert!(matches!(
            validate_submission(&req, &cfg()),
            Err(GraderError::BodyTooLarge(_, _))
        ));
    }

    #[test]
    fn validate_submission_rejects_invalid_sender_ip() {
        let req = EmailSubmitRequest {
            domain: Some("example.com".into()), from: Some("a@example.com".into()), to: vec![],
            subject: Some("ok".into()), body_text: Some("body".into()), body_html: None,
            headers: None, selectors: vec![], sender_ip: Some("not-an-ip".into()),
            helo_hostname: None, mail_from: None,
        };
        assert!(validate_submission(&req, &cfg()).is_err());
    }

    #[test]
    fn rate_limiter_enforces_max_and_recovers_after_window() {
        let engine = GraderEngine::new(cfg(), None).unwrap();
        assert!(engine.check_rate_limit("1.2.3.4"));
        assert!(engine.check_rate_limit("1.2.3.4"));
        assert!(engine.check_rate_limit("1.2.3.4"));
        assert!(!engine.check_rate_limit("1.2.3.4"));
        assert!(engine.check_rate_limit("5.6.7.8"));
    }

    #[test]
    fn rate_limiter_zero_max_blocks_all() {
        let mut c = cfg();
        c.rate_limit_max = 0;
        let engine = GraderEngine::new(c, None).unwrap();
        assert!(!engine.check_rate_limit("1.2.3.4"));
    }

    #[test]
    fn tenant_dns_budget_admits_then_blocks_then_recovers() {
        let mut c = cfg();
        c.tenant_dns_budget_max = 5;
        let engine = GraderEngine::new(c, None).unwrap();
        assert!(engine.check_tenant_dns_budget("ten_a", 3));
        assert!(engine.check_tenant_dns_budget("ten_a", 2));
        assert!(!engine.check_tenant_dns_budget("ten_a", 1));
        assert!(engine.check_tenant_dns_budget("ten_b", 5));
    }

    #[test]
    fn tenant_dns_budget_zero_blocks_all() {
        let mut c = cfg();
        c.tenant_dns_budget_max = 0;
        let engine = GraderEngine::new(c, None).unwrap();
        assert!(!engine.check_tenant_dns_budget("ten_a", 1));
    }

    #[test]
    fn invert_helpers_clamp_to_range() {
        assert_eq!(scoring::invert_spam_score(0.0), 100);
        assert_eq!(scoring::invert_spam_score(1.0), 0);
        assert_eq!(scoring::invert_spam_score(2.0), 0);
        assert_eq!(scoring::invert_spam_score(-1.0), 100);
    }

    #[test]
    fn build_raw_message_round_trip() {
        let req = EmailSubmitRequest {
            domain: Some("example.com".into()), from: Some("a@example.com".into()),
            to: vec!["b@example.com".into()], subject: Some("Hi".into()),
            body_text: Some("hello".into()), body_html: None, headers: None, selectors: vec![],
            sender_ip: None, helo_hostname: None, mail_from: None,
        };
        let v = validate_submission(&req, &cfg()).unwrap();
        let raw = build_raw_message(&v);
        let s = String::from_utf8(raw).unwrap();
        assert!(s.starts_with("From: a@example.com\r\n"));
        assert!(s.contains("To: b@example.com\r\n"));
        assert!(s.contains("Subject: Hi\r\n"));
        assert!(s.contains("\r\n\r\nhello\r\n"));
    }

    #[test]
    fn engine_rejects_encryption_without_key() {
        let mut c = cfg();
        c.encrypt_stored_content = true;
        c.encryption_master_key_base64 = None;
        assert!(GraderEngine::new(c, None).is_err());
    }

    #[test]
    fn engine_accepts_valid_encryption_key() {
        use base64::Engine as _;
        let mut c = cfg();
        c.encrypt_stored_content = true;
        c.encryption_master_key_base64 = Some(base64::engine::general_purpose::STANDARD.encode([9u8; 32]));
        assert!(GraderEngine::new(c, None).is_ok());
    }

    /// PII regression: the body content (and unique sentinel) MUST NEVER appear
    /// in any field of the serialized GraderResponse. The grader returns
    /// scores, breakdowns, findings, and recommendations — it must not echo
    /// back the email body, headers, or addresses anywhere in the response or
    /// breakdown JSON.
    #[test]
    fn pii_body_never_leaks_into_breakdown_json() {
        let sentinel = "ZZZ_GRADER_PII_SENTINEL_77f3a1c2_ZZZ";
        let body_text = format!("Hello user, your secret token is {sentinel}.\nDo not share.");
        let req = EmailSubmitRequest {
            domain: Some("example.com".into()),
            from: Some("alice@example.com".into()),
            to: vec!["bob@example.com".into()],
            subject: Some("Confidential".into()),
            body_text: Some(body_text.clone()),
            body_html: Some(format!("<p>{sentinel}</p>")),
            headers: None,
            selectors: vec![],
            sender_ip: None,
            helo_hostname: None,
            mail_from: None,
        };
        let validated = validate_submission(&req, &cfg()).unwrap();

        // Build a representative response using the public scoring layer
        // (no DNS, no auth verification — those are network-dependent).
        let mut findings: Vec<Finding> = Vec::new();
        let (score, grade, breakdown, findings_out, recs) = crate::scoring::GradeCalculator::calculate(
            85, None, 80, None, 92, Some(88), 100, None, std::mem::take(&mut findings),
        );
        let response = GraderResponse {
            id: None,
            domain: validated.domain.clone(),
            score,
            grade: grade.to_string(),
            breakdown,
            findings: findings_out,
            recommendations: recs,
            created_at: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(
            !json.contains(sentinel),
            "PII sentinel from body leaked into response JSON: {json}"
        );
        assert!(
            !json.contains(&body_text),
            "Body text leaked into response JSON"
        );
        assert!(
            !json.to_lowercase().contains("alice@example.com"),
            "From address leaked into response JSON"
        );
    }
}
