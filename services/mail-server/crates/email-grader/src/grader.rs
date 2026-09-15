use crate::config::GraderConfig;
use crate::dns_provider::DnsProvider;
use crate::network_checks::{
    lookup_bimi, lookup_mta_sts, lookup_tls_rpt, BimiInfo, MtaStsInfo, TlsRptInfo,
};
use crate::scoring;
use crate::scoring::GradeCalculator;
use crate::types::*;
use apexmail_dns_resolver::records::{DmarcPolicy, MxRecord, SpfRecord};
use dashmap::DashMap;
use futures::stream::{FuturesUnordered, StreamExt};
use mta::auth::email_authentication::{AuthenticationResults, EmailAuthenticator};
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
        self.inner.insert(
            domain,
            CachedResult {
                result,
                cached_at: Instant::now(),
            },
        );
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
        Self {
            inner: DashMap::new(),
        }
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
    dns_lookup: Arc<dyn DnsProvider>,
    blocklist: Option<Arc<DomainBlocklist>>,
    cache: DomainCache,
    flight: SingleFlight,
    rate_limits: DashMap<String, VecDeque<Instant>>,
    /// Per-tenant DNS budget (used by /submit) independent from the public
    /// HTTP rate limit on /check.
    tenant_dns_budget: DashMap<String, VecDeque<Instant>>,
    spam_engine: SpamEngine,
    authenticator: OnceCell<EmailAuthenticator>,
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
                .ok_or_else(|| {
                    "encrypt_stored_content=true but no master key configured".to_string()
                })?;
            crate::crypto::Cipher::from_base64_key(key)
                .map_err(|e| format!("encryption master key rejected: {e}"))?;
        }

        let dns_lookup: Arc<dyn DnsProvider> = Arc::new(
            apexmail_dns_resolver::lookup::DnsLookup::new()
                .map_err(|e| format!("DNS resolver init failed: {e}"))?,
        );
        // NOTE: no shared HTTP client anymore — the MTA-STS policy fetch
        // builds a per-request client pinned to pre-validated IPs (SSRF
        // hardening; see network_checks::lookup_mta_sts).
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
        let selectors =
            normalize_selectors(&request.selectors, &self.config.default_dkim_selectors)?;
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
        let bimi_fut = tokio::time::timeout(net_to, lookup_bimi(self.dns_lookup.as_ref(), domain));
        let tls_rpt_fut =
            tokio::time::timeout(net_to, lookup_tls_rpt(self.dns_lookup.as_ref(), domain));
        let mta_sts_fut = tokio::time::timeout(
            net_to.saturating_mul(2), // policy fetch may take a bit longer
            lookup_mta_sts(
                self.dns_lookup.as_ref(),
                domain,
                self.config.mta_sts_policy_max_bytes,
                net_to,
            ),
        );

        let (mx_res, spf_res, dmarc_res, a_res, bimi_res, tls_rpt_res, mta_sts_res) = tokio::join!(
            mx_fut,
            spf_fut,
            dmarc_fut,
            a_fut,
            bimi_fut,
            tls_rpt_fut,
            mta_sts_fut
        );

        // Account DNS lookups against tenant budget (best-effort).
        if let Some(t) = tenant_id {
            self.charge_tenant_dns_budget(t, 7);
        }

        let mx_records = mx_res.unwrap_or(Ok(Vec::new())).unwrap_or_default();
        let mx: Vec<MxInfo> = mx_records
            .iter()
            .map(|m: &MxRecord| MxInfo {
                priority: m.priority,
                exchange: m.exchange.clone(),
            })
            .collect();

        let spf: Option<SpfInfo> =
            spf_res
                .unwrap_or(Ok(None))
                .unwrap_or(None)
                .map(|s: SpfRecord| SpfInfo {
                    raw: s.raw.clone(),
                    hard_fail: s.is_hard_fail(),
                    soft_fail: s.is_soft_fail(),
                });

        let dmarc: Option<DmarcInfo> =
            dmarc_res
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
            let dns = Arc::clone(&self.dns_lookup);
            // Process selectors in chunks of `concurrency` so in-flight DNS
            // queries are bounded regardless of input size.
            for chunk in selectors.chunks(concurrency) {
                let mut futs: FuturesUnordered<_> = chunk
                    .iter()
                    .map(|sel| {
                        let sel = sel.clone();
                        let dns = Arc::clone(&dns);
                        async move {
                            let r =
                                tokio::time::timeout(net_to, dns.lookup_dkim(&sel, domain)).await;
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
                    let confidence = if entry.confidence >= 7.0 {
                        "high"
                    } else if entry.confidence >= 4.0 {
                        "medium"
                    } else {
                        "low"
                    };
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
            &a.mx,
            a.spf.as_ref(),
            &a.dkim,
            a.dmarc.as_ref(),
            a.has_a_record,
        );

        let (spf_score, spf_details) = scoring::score_spf(a.spf.as_ref());
        let (dkim_score, dkim_details) = scoring::score_dkim(&a.dkim);
        let (dmarc_score, dmarc_details) = scoring::score_dmarc(a.dmarc.as_ref());
        let (modern_score, modern_details) =
            scoring::score_modern_security(a.bimi.as_ref(), a.mta_sts.as_ref(), a.tls_rpt.as_ref());

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
        let spam_score = if auth_score >= 80 {
            90
        } else if auth_score >= 60 {
            75
        } else if auth_score >= 40 {
            50
        } else {
            30
        };

        let (rep_score, rep_details) = if a.blocklist_hits.is_empty() {
            scoring::score_reputation(0, "none")
        } else {
            let (source, confidence) = &a.blocklist_hits[0];
            findings.push(Finding {
                severity: FindingSeverity::Warning,
                category: "reputation".into(),
                message: format!("Domain found in blocklist '{source}' (confidence: {confidence})"),
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
                message:
                    "No MTA-STS policy detected — add `_mta-sts` TXT and well-known policy file"
                        .into(),
            });
        }
        if a.tls_rpt.is_none() {
            findings.push(Finding {
                severity: FindingSeverity::Info,
                category: "transport_security".into(),
                message: "No TLS-RPT record — add `_smtp._tls` TXT to receive TLS failure reports"
                    .into(),
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
        while bucket
            .front()
            .is_some_and(|t| now.duration_since(*t) >= window)
        {
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
        let mut bucket = self
            .tenant_dns_budget
            .entry(tenant_id.to_string())
            .or_default();
        while bucket
            .front()
            .is_some_and(|t| now.duration_since(*t) >= window)
        {
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
        let mut bucket = self
            .tenant_dns_budget
            .entry(tenant_id.to_string())
            .or_default();
        while bucket
            .front()
            .is_some_and(|t| now.duration_since(*t) >= window)
        {
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
                let r = self
                    .do_domain_check(&domain, &selectors, Some(tenant_id))
                    .await?;
                self.cache.set(cache_key.clone(), r.clone());
                self.flight.release(&cache_key);
                r
            }
        };

        let raw_message = build_raw_message(submission);
        let auth_results = self.authenticate_email(&raw_message, submission).await;

        let auth_header = auth_results
            .as_ref()
            .map(|r| r.auth_results_header.as_str());
        let spam_verdict = self.analyze_spam(submission, auth_header);
        let content_score = spam_verdict.content_score.clone();

        let auth_score = self.compute_auth_score(&domain_check);
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

        let auth_details = auth_results.as_ref().map(|r| {
            serde_json::json!({
                "spf": r.spf,
                "dkim": r.dkim,
                "dmarc": r.dmarc,
                "authentication_results": r.auth_results_header,
            })
        });
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
                )
                .await
            }),
        )
        .await
        {
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
        )
        .await
        {
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

    #[expect(
        dead_code,
        reason = "reserved helper for callers that provide split text/html inputs"
    )]
    fn score_email_content(&self, body_text: &str, body_html: &str, subject: &str) -> ContentScore {
        let combined = format!("{} {} {}", subject, body_text, strip_html_tags(body_html));
        score_content(&combined)
    }

    /// Authentication dimension for a submitted message.
    ///
    /// The DNS-level auth score (`breakdown.authentication`, which already
    /// weighs the published SPF record at up to 30/100) is used as-is: the
    /// old code added a flat +10 whenever the live SPF verdict passed,
    /// double-counting SPF and letting a single passing mechanism push the
    /// dimension past what the DNS evidence supports. The live message-level
    /// verdicts remain visible in `auth_details` and the spam engine, they
    /// just no longer inflate the auth score.
    fn compute_auth_score(&self, domain_check: &GraderResponse) -> u16 {
        domain_check.breakdown.authentication.score.min(100)
    }
}

/// Test-only seam: point the engine at a fake resolver so DNS-dependent
/// paths run without network egress. Compiled only under `cfg(test)`.
#[cfg(test)]
impl GraderEngine {
    pub(crate) fn set_dns_lookup_for_tests(&mut self, dns: Arc<dyn DnsProvider>) {
        self.dns_lookup = dns;
    }
}

pub(crate) fn normalize_domain(input: &str) -> Result<String, GraderError> {
    let trimmed = input.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(GraderError::InvalidDomain("empty domain".into()));
    }
    if trimmed.len() > MAX_DOMAIN_LEN {
        return Err(GraderError::InvalidDomain(
            "domain exceeds 253 chars".into(),
        ));
    }
    let ascii = idna::domain_to_ascii(trimmed)
        .map_err(|e| GraderError::InvalidDomain(format!("IDNA: {e}")))?;
    if !ascii.contains('.') {
        return Err(GraderError::InvalidDomain(
            "domain must contain a dot".into(),
        ));
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
    let source: &[String] = if requested.is_empty() {
        defaults
    } else {
        requested
    };
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
        if !s
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
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
    // Header-injection guard: `from` becomes the synthesized MIME's From:
    // line, so CR/LF anywhere in it rejects the submission outright (same
    // policy as the subject — it is a single required field, there is
    // nothing sensible to skip).
    if from.contains('\r') || from.contains('\n') {
        return Err(GraderError::InvalidDomain("`from` contains CR/LF".into()));
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
    // Recipients are spliced into the synthesized To: line — any entry
    // carrying CR/LF is skipped and flagged (same policy as custom
    // headers), never spliced into the MIME.
    let mut skipped_recipients = 0usize;
    let to: Vec<String> = request
        .to
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| {
            if s.is_empty() {
                return false;
            }
            if s.contains('\r') || s.contains('\n') {
                skipped_recipients += 1;
                return false;
            }
            true
        })
        .collect();
    if skipped_recipients > 0 {
        tracing::warn!(
            skipped = skipped_recipients,
            "grader: dropped recipients containing CR/LF (header-injection guard)"
        );
    }

    let subject = request.subject.as_deref().unwrap_or("").to_string();
    if subject.len() > MAX_SUBJECT_LEN {
        return Err(GraderError::InvalidDomain(
            "subject exceeds 998 chars".into(),
        ));
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
            if name.is_empty()
                || name.len() > MAX_HEADER_NAME_LEN
                || value.len() > MAX_HEADER_VALUE_LEN
            {
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
        let many: Vec<String> = (0..MAX_DKIM_SELECTORS + 1)
            .map(|i| format!("s{i}"))
            .collect();
        assert!(normalize_selectors(&many, &[]).is_err());
    }

    #[test]
    fn validate_submission_requires_from_and_domain() {
        let req = EmailSubmitRequest {
            domain: None,
            from: None,
            to: vec![],
            subject: None,
            body_text: None,
            body_html: None,
            headers: None,
            selectors: vec![],
            sender_ip: None,
            helo_hostname: None,
            mail_from: None,
        };
        assert!(validate_submission(&req, &cfg()).is_err());
    }

    #[test]
    fn validate_submission_derives_domain_from_from_address() {
        let req = EmailSubmitRequest {
            domain: None,
            from: Some("alice@Example.com".into()),
            to: vec!["bob@example.org".into()],
            subject: Some("hi".into()),
            body_text: Some("hello".into()),
            body_html: None,
            headers: None,
            selectors: vec![],
            sender_ip: None,
            helo_hostname: None,
            mail_from: None,
        };
        let v = validate_submission(&req, &cfg()).unwrap();
        assert_eq!(v.domain, "example.com");
        assert_eq!(v.from, "alice@Example.com");
        assert_eq!(v.mail_from, "alice@Example.com");
    }

    #[test]
    fn validate_submission_rejects_crlf_from() {
        // `from` is spliced into the synthesized From: line — a CR/LF there
        // is a header-injection attempt and rejects the whole submission.
        let req = EmailSubmitRequest {
            domain: Some("example.com".into()),
            from: Some("a@example.com\r\nBcc: leak@evil.com".into()),
            to: vec![],
            subject: Some("hi".into()),
            body_text: None,
            body_html: None,
            headers: None,
            selectors: vec![],
            sender_ip: None,
            helo_hostname: None,
            mail_from: None,
        };
        assert!(validate_submission(&req, &cfg()).is_err());
    }

    #[test]
    fn validate_submission_skips_crlf_recipients_and_never_splices_them() {
        let req = EmailSubmitRequest {
            domain: Some("example.com".into()),
            from: Some("a@example.com".into()),
            to: vec![
                "bob@example.org".into(),
                "evil@example.org\r\nBcc: leak@evil.com".into(),
                "carol@example.org".into(),
            ],
            subject: Some("hi".into()),
            body_text: Some("body".into()),
            body_html: None,
            headers: None,
            selectors: vec![],
            sender_ip: None,
            helo_hostname: None,
            mail_from: None,
        };
        let v = validate_submission(&req, &cfg()).unwrap();
        assert_eq!(v.to, vec!["bob@example.org", "carol@example.org"]);

        // And the synthesized MIME never contains the injected header line.
        let raw = String::from_utf8_lossy(&build_raw_message(&v)).into_owned();
        assert!(!raw.contains("Bcc:"));
        assert!(!raw.contains("\r\nBcc"));
        assert!(raw.contains("To: bob@example.org, carol@example.org"));
    }

    #[test]
    fn validate_submission_rejects_crlf_subject() {
        let req = EmailSubmitRequest {
            domain: Some("example.com".into()),
            from: Some("a@example.com".into()),
            to: vec![],
            subject: Some("hi\r\nBcc: leak@evil.com".into()),
            body_text: None,
            body_html: None,
            headers: None,
            selectors: vec![],
            sender_ip: None,
            helo_hostname: None,
            mail_from: None,
        };
        assert!(validate_submission(&req, &cfg()).is_err());
    }

    #[test]
    fn validate_submission_strips_crlf_header_values() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Bad".to_string(), "ok\r\nBcc: leak@evil.com".to_string());
        headers.insert("X-Good".to_string(), "fine".to_string());
        let req = EmailSubmitRequest {
            domain: Some("example.com".into()),
            from: Some("a@example.com".into()),
            to: vec![],
            subject: Some("ok".into()),
            body_text: Some("body".into()),
            body_html: None,
            headers: Some(headers),
            selectors: vec![],
            sender_ip: None,
            helo_hostname: None,
            mail_from: None,
        };
        let v = validate_submission(&req, &cfg()).unwrap();
        assert!(v.headers.iter().all(|(k, _)| k != "X-Bad"));
        assert!(v.headers.iter().any(|(k, _)| k == "X-Good"));
    }

    #[test]
    fn validate_submission_enforces_body_size_cap() {
        let big = "x".repeat(2000);
        let req = EmailSubmitRequest {
            domain: Some("example.com".into()),
            from: Some("a@example.com".into()),
            to: vec![],
            subject: Some("ok".into()),
            body_text: Some(big),
            body_html: None,
            headers: None,
            selectors: vec![],
            sender_ip: None,
            helo_hostname: None,
            mail_from: None,
        };
        assert!(matches!(
            validate_submission(&req, &cfg()),
            Err(GraderError::BodyTooLarge(_, _))
        ));
    }

    #[test]
    fn validate_submission_rejects_invalid_sender_ip() {
        let req = EmailSubmitRequest {
            domain: Some("example.com".into()),
            from: Some("a@example.com".into()),
            to: vec![],
            subject: Some("ok".into()),
            body_text: Some("body".into()),
            body_html: None,
            headers: None,
            selectors: vec![],
            sender_ip: Some("not-an-ip".into()),
            helo_hostname: None,
            mail_from: None,
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
            domain: Some("example.com".into()),
            from: Some("a@example.com".into()),
            to: vec!["b@example.com".into()],
            subject: Some("Hi".into()),
            body_text: Some("hello".into()),
            body_html: None,
            headers: None,
            selectors: vec![],
            sender_ip: None,
            helo_hostname: None,
            mail_from: None,
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
        c.encryption_master_key_base64 =
            Some(base64::engine::general_purpose::STANDARD.encode([9u8; 32]));
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
        let (score, grade, breakdown, findings_out, recs) =
            crate::scoring::GradeCalculator::calculate(
                85,
                None,
                80,
                None,
                92,
                Some(88),
                100,
                None,
                std::mem::take(&mut findings),
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

    // ── DNS-backed engine paths (fake resolver, no network) ───────────

    use crate::test_dns::StubDns;

    /// A fully-signalled domain: two MX, SPF hard-fail, 2048-bit RSA DKIM,
    /// DMARC reject, A record, BIMI, TLS-RPT, and MTA-STS TXT whose policy
    /// host resolves to a private IP (so the fetch is refused).
    fn full_signal_dns() -> StubDns {
        let dkim_key = "A".repeat(2800); // len*6/8 = 2100 bits → strong
        StubDns::new()
            .mx("example.com", 5, "mx1.example.com")
            .mx("example.com", 10, "mx2.example.com")
            .a("example.com", "93.184.216.34")
            .spf("example.com", "v=spf1 include:_spf.example.com -all")
            .dmarc("example.com", "v=DMARC1; p=reject; pct=100")
            .dkim(
                "default",
                "example.com",
                &format!("v=DKIM1; k=rsa; p={dkim_key}"),
            )
            .txt(
                "default._bimi.example.com",
                &["v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"],
            )
            .txt(
                "_smtp._tls.example.com",
                &["v=TLSRPTv1; rua=mailto:tls@example.com,https://example.com/tls"],
            )
            .txt("_mta-sts.example.com", &["v=STSv1; id=20250101T000000"])
            .a("mta-sts.example.com", "127.0.0.1")
    }

    fn engine_with(fake: &StubDns, tune: impl FnOnce(&mut GraderConfig)) -> GraderEngine {
        let mut c = cfg();
        tune(&mut c);
        let mut engine = GraderEngine::new(c, None).expect("engine");
        engine.set_dns_lookup_for_tests(Arc::new(fake.clone()));
        engine
    }

    /// A stub where every lookup fails, as if the resolver were down.
    fn broken_dns() -> StubDns {
        StubDns {
            fail_all: true,
            ..StubDns::new()
        }
    }

    fn submit_request(domain: &str) -> EmailSubmitRequest {
        EmailSubmitRequest {
            domain: Some(domain.into()),
            from: Some(format!("sender@{domain}")),
            to: vec!["recipient@example.net".into()],
            subject: Some("Hello".into()),
            body_text: Some("A perfectly ordinary message body.".into()),
            body_html: None,
            headers: None,
            selectors: vec![],
            sender_ip: None,
            helo_hostname: None,
            mail_from: None,
        }
    }

    #[tokio::test]
    async fn full_signal_domain_scores_at_the_top() {
        let fake = full_signal_dns();
        let engine = engine_with(&fake, |_| {});
        let response = engine
            .check_domain(&DomainCheckRequest {
                domain: "example.com".into(),
                selectors: vec![],
            })
            .await
            .expect("domain check");

        let dns = &response.breakdown.dns_health;
        assert_eq!(dns.score, 90, "mx(50)+spf(15)+dkim(15)+dmarc(10): {dns:?}");
        let details = dns.details.as_ref().unwrap();
        assert_eq!(details["mx"]["count"], 2);
        assert_eq!(details["spf_record"], true);
        assert_eq!(details["dkim_record"], true);
        assert_eq!(details["dmarc_record"], true);

        let auth = &response.breakdown.authentication;
        // spf 25 (hard fail) + dkim 20 + dmarc 30 + modern 10 = 85.
        assert_eq!(auth.score, 85, "auth components: {auth:?}");
        let auth_details = auth.details.as_ref().unwrap();
        assert_eq!(auth_details["spf"]["hard_fail"], true);
        assert_eq!(auth_details["dmarc"]["policy"], "reject");
        assert_eq!(
            auth_details["modern_security"]["bimi"]["logo_url"],
            "https://example.com/logo.svg"
        );
        // MTA-STS TXT exists but the policy host is private → no signal.
        assert!(auth_details["modern_security"]["mta_sts"].is_null());

        assert_eq!(response.score, 89, "composite: {response:?}");
        assert_eq!(response.grade, "A");
        assert_eq!(response.domain, "example.com");
        assert!(response.id.is_none(), "domain checks do not persist");

        // Only the two transport-security Info findings; no errors.
        assert!(
            response
                .findings
                .iter()
                .all(|f| format!("{:?}", f.severity) == "Info"),
            "{:?}",
            response.findings
        );
        assert!(response
            .recommendations
            .iter()
            .any(|r| r.contains("DNS configuration looks good")));
        assert!(response
            .recommendations
            .iter()
            .any(|r| r.contains("Email authentication is well configured")));
    }

    #[tokio::test]
    async fn minimal_domain_scores_at_the_bottom_with_actionable_findings() {
        let fake = StubDns::new(); // every name → NXDOMAIN
        let engine = engine_with(&fake, |_| {});
        let response = engine
            .check_domain(&DomainCheckRequest {
                domain: "nowhere.invalid".into(),
                selectors: vec!["default".into()],
            })
            .await
            .expect("domain check");

        assert_eq!(response.breakdown.dns_health.score, 0);
        assert_eq!(response.breakdown.authentication.score, 0);
        assert_eq!(response.grade, "F");
        assert!(response.score < 40, "{response:?}");

        let categories: Vec<&str> = response
            .findings
            .iter()
            .map(|f| f.category.as_str())
            .collect();
        for expected in ["dns", "authentication", "transport_security"] {
            assert!(categories.contains(&expected), "{categories:?}");
        }
        assert!(response
            .findings
            .iter()
            .any(|f| f.message.contains("No MX records")));
        assert!(response
            .recommendations
            .iter()
            .any(|r| r.starts_with("[Action Required]")));
        assert!(response
            .recommendations
            .iter()
            .any(|r| r.contains("Configure MX, SPF, DKIM, and DMARC")));
        assert!(response
            .recommendations
            .iter()
            .any(|r| r.contains("Implement email authentication")));
        assert!(response
            .recommendations
            .iter()
            .any(|r| r.contains("High spam-likelihood")));
    }

    #[tokio::test]
    async fn single_mx_and_weak_dmarc_are_reported_without_inflation() {
        let fake = StubDns::new()
            .mx("weak.example", 20, "mx1.weak.example")
            .spf("weak.example", "v=spf1 ~all")
            .dmarc("weak.example", "v=DMARC1; p=none")
            .dkim("default", "weak.example", "v=DKIM1; k=rsa; p=short");
        let engine = engine_with(&fake, |_| {});
        let response = engine
            .check_domain(&DomainCheckRequest {
                domain: "weak.example".into(),
                selectors: vec!["default".into()],
            })
            .await
            .expect("domain check");

        // MX 25 (present, single, priority >10) + spf 15 + dkim 15 + dmarc 10.
        assert_eq!(response.breakdown.dns_health.score, 65);
        // SPF soft-fail 20, weak DKIM 15, DMARC none + pct100 → 20, modern 0.
        assert_eq!(response.breakdown.authentication.score, 55);
        let details = response.breakdown.dns_health.details.as_ref().unwrap();
        assert_eq!(details["mx"]["count"], 1);
        assert!(response
            .findings
            .iter()
            .any(|f| f.message.contains("Only one MX record")));
        assert!(response
            .findings
            .iter()
            .any(|f| f.message.contains("DMARC policy is 'none'")));
        // auth 55 < 60 → the stronger "implement" recommendation.
        assert!(response
            .recommendations
            .iter()
            .any(|r| r.contains("Implement email authentication")));
    }

    #[tokio::test]
    async fn a_record_only_domain_gets_the_implicit_mx_credit() {
        let fake = StubDns::new().a("aonly.example", "93.184.216.34");
        let engine = engine_with(&fake, |_| {});
        let response = engine
            .check_domain(&DomainCheckRequest {
                domain: "aonly.example".into(),
                selectors: vec![],
            })
            .await
            .expect("domain check");
        // No MX, but the A record grants the 10-point fallback credit.
        assert_eq!(response.breakdown.dns_health.score, 10);
    }

    #[tokio::test]
    async fn domain_cache_hits_and_expires() {
        let fake = full_signal_dns();
        // TTL 0 → every entry is already expired when read (the cache still
        // stores it; the next read evicts and recomputes).
        let engine = engine_with(&fake, |c| c.cache_ttl_seconds = 0);
        let request = DomainCheckRequest {
            domain: "example.com".into(),
            selectors: vec![],
        };
        let first = engine.check_domain(&request).await.unwrap();
        let second = engine.check_domain(&request).await.unwrap();
        assert_eq!(first.domain, second.domain);
        assert_eq!(first.score, second.score);

        // Non-zero TTL → the cached clone is returned unchanged.
        let engine = engine_with(&fake, |c| c.cache_ttl_seconds = 300);
        let first = engine.check_domain(&request).await.unwrap();
        let second = engine.check_domain(&request).await.unwrap();
        assert_eq!(first.score, second.score);
    }

    #[tokio::test]
    async fn blocklist_hits_feed_reputation_and_findings() {
        let fake = full_signal_dns();
        let blocklist =
            std::sync::Arc::new(threat_intel::domain_blocklist::DomainBlocklist::new(10));
        let entry =
            |confidence: f64, source: &str| threat_intel::domain_blocklist::DomainBlockEntry {
                domain: "example.com".into(),
                source: source.into(),
                confidence,
                category: "spam".into(),
                added_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now() + chrono::Duration::days(1),
            };
        blocklist.add("example.com", entry(9.0, "test-feed"));

        let mut c = cfg();
        let mut engine = GraderEngine::new(c.clone(), Some(blocklist)).expect("engine");
        engine.set_dns_lookup_for_tests(Arc::new(fake.clone()));
        let response = engine
            .check_domain(&DomainCheckRequest {
                domain: "example.com".into(),
                selectors: vec![],
            })
            .await
            .unwrap();
        assert_eq!(response.breakdown.reputation.score, 20, "blocked domain");
        assert!(response
            .findings
            .iter()
            .any(|f| f.message.contains("test-feed") && f.message.contains("high")));

        // Low-confidence single hit: partial reputation credit.
        let blocklist =
            std::sync::Arc::new(threat_intel::domain_blocklist::DomainBlocklist::new(10));
        blocklist.add("example.com", entry(1.0, "weak-feed"));
        c.cache_ttl_seconds = 0; // avoid cross-test cache reuse
        let mut engine = GraderEngine::new(c, Some(blocklist)).expect("engine");
        engine.set_dns_lookup_for_tests(Arc::new(fake.clone()));
        let response = engine
            .check_domain(&DomainCheckRequest {
                domain: "example.com".into(),
                selectors: vec![],
            })
            .await
            .unwrap();
        assert_eq!(response.breakdown.reputation.score, 60);
        assert!(response
            .findings
            .iter()
            .any(|f| f.message.contains("confidence: low")));

        // No blocklist configured → full reputation, no finding.
        let engine = engine_with(&fake, |_| {});
        let response = engine
            .check_domain(&DomainCheckRequest {
                domain: "example.com".into(),
                selectors: vec![],
            })
            .await
            .unwrap();
        assert_eq!(response.breakdown.reputation.score, 100);
    }

    #[tokio::test]
    async fn analyze_email_covers_spam_content_and_dns_without_network_auth() {
        let fake = full_signal_dns();
        let mut c = cfg();
        c.cache_ttl_seconds = 0;
        let mut engine = GraderEngine::new(c, None).expect("engine");
        engine.set_dns_lookup_for_tests(Arc::new(fake.clone()));

        let request = EmailSubmitRequest {
            domain: Some("example.com".into()),
            from: Some("alice@example.com".into()),
            to: vec!["bob@example.net".into()],
            subject: Some("Act now — free money!!!".into()),
            body_text: Some(
                "Congratulations! You have won a FREE prize. Click here now to claim \
                 your cash reward. Limited time offer! Viagra cheap pills."
                    .into(),
            ),
            body_html: Some(
                "<html><body><a href=\"http://spam.example\">click</a></body></html>".into(),
            ),
            headers: Some(std::collections::HashMap::from([(
                "X-Custom".to_string(),
                "1".to_string(),
            )])),
            selectors: vec![],
            sender_ip: None,
            helo_hostname: None,
            mail_from: None,
        };
        let submission = engine.validate_submission(&request).unwrap();
        let response = engine.analyze_email(&submission, "tenant-a").await.unwrap();

        assert!(response.id.is_some(), "analyze_email mints an id");
        assert!(response.created_at.is_some());
        assert!(response
            .findings
            .iter()
            .any(|f| f.message.contains("was not evaluated because sender_ip")));
        assert!(response
            .recommendations
            .iter()
            .any(|r| r.contains("Spam engine classification:")));
        let spam_details = response.breakdown.spam_likelihood.details.as_ref().unwrap();
        assert!(spam_details["classification"].is_string());
        assert!(spam_details["url_count"].is_number());

        // The tenant DNS budget was charged by the engine.
        assert!(!engine.check_tenant_dns_budget("tenant-a", 10));
        // Another tenant is unaffected (isolation).
        assert!(engine.check_tenant_dns_budget("tenant-b", 10));
    }

    #[test]
    fn singleflight_lock_release_prunes_large_tables() {
        let flight = SingleFlight::new();
        for i in 0..2_100 {
            let key = format!("k{i}");
            let _lock = flight.lock_for(&key);
            flight.release(&key);
        }
        // After pruning only the currently-referenced entries remain; the
        // table is far below the insertion count.
        assert!(flight.inner.len() < 2_100);
    }

    #[test]
    fn domain_cache_set_prunes_when_over_capacity() {
        let cache = DomainCache::new(0); // everything is instantly stale
        for i in 0..1_050 {
            cache.set(
                format!("d{i}.example"),
                GraderResponse {
                    id: None,
                    domain: format!("d{i}.example"),
                    score: 50,
                    grade: "D".into(),
                    breakdown: scoring::GradeCalculator::calculate(
                        50,
                        None,
                        50,
                        None,
                        50,
                        Some(50),
                        50,
                        None,
                        vec![],
                    )
                    .2,
                    findings: vec![],
                    recommendations: vec![],
                    created_at: None,
                },
            );
        }
        assert!(cache.get("d1049.example").is_none(), "ttl 0 never serves");
        assert!(cache.inner.len() <= 1_000, "pruned: {}", cache.inner.len());
    }

    #[test]
    fn normalize_domain_bounds_and_idna_failures() {
        let long = format!("{}.com", "a".repeat(250));
        assert!(normalize_domain(&long).is_err(), "over 253 chars");
        assert!(normalize_domain("a..com").is_err(), "empty label");
        assert!(normalize_domain("*").is_err(), "dotless wildcard");
        assert!(
            normalize_domain("\u{FFFD}.com").is_err(),
            "IDNA rejects U+FFFD"
        );
        // A 253-char domain that is syntactically fine is accepted.
        let labels = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(57)
        );
        assert_eq!(labels.len(), 249);
        assert!(normalize_domain(&labels).is_ok());
    }

    #[test]
    fn normalize_selectors_unicode_and_skip_rules() {
        // Unicode case folding and a Turkish selector.
        let s = normalize_selectors(&["İSTANBUL".into(), "İstanbul".into()], &[]).unwrap();
        assert_eq!(s.len(), 1, "both fold to the same selector: {s:?}");
        assert!(s[0].to_lowercase().contains('i'));

        // Invalid entries are skipped; empty result falls back to "default".
        let s = normalize_selectors(
            &[
                "has space".into(),
                "semi;colon".into(),
                "x".repeat(MAX_DKIM_SELECTOR_LEN + 1),
                String::new(),
            ],
            &[],
        )
        .unwrap();
        assert_eq!(s, vec!["default".to_string()]);

        // Dots, underscores and hyphens are legal selector characters.
        let s = normalize_selectors(&["My_Selector-1.v2".into()], &[]).unwrap();
        assert_eq!(s, vec!["my_selector-1.v2".to_string()]);
    }

    #[test]
    fn submission_validation_edges() {
        let mut c = cfg();
        c.max_body_size = 10;

        // Too many recipients.
        let mut req = submit_request("example.com");
        req.to = (0..=MAX_RECIPIENTS).map(|i| format!("u{i}@x.y")).collect();
        assert!(validate_submission(&req, &c).is_err());

        // Subject over the cap and with CR/LF.
        let mut req = submit_request("example.com");
        req.subject = Some("a".repeat(MAX_SUBJECT_LEN + 1));
        assert!(validate_submission(&req, &c).is_err());
        let mut req = submit_request("example.com");
        req.subject = Some("bad\r\nBcc: x@y.z".into());
        assert!(validate_submission(&req, &c).is_err());

        // Body cap (text + html).
        let mut req = submit_request("example.com");
        req.body_text = Some("x".repeat(6));
        req.body_html = Some("y".repeat(6));
        assert!(matches!(
            validate_submission(&req, &c),
            Err(GraderError::BodyTooLarge(12, 10))
        ));

        // Header hygiene: long name/value, colon in name, control chars and
        // CRLF are all dropped, legal ones kept. (Restore the body cap so the
        // placeholder body does not short-circuit validation.)
        c.max_body_size = 1024;
        let mut req = submit_request("example.com");
        req.headers = Some(std::collections::HashMap::from([
            ("a".repeat(MAX_HEADER_NAME_LEN + 1), "v".to_string()),
            ("X-Long".to_string(), "v".repeat(MAX_HEADER_VALUE_LEN + 1)),
            ("X-Colon:Name".to_string(), "v".to_string()),
            ("X-Ctrl".to_string(), "bad\u{7}value".to_string()),
            ("X-CRLF".to_string(), "bad\r\nvalue".to_string()),
            ("  ".to_string(), "empty-name".to_string()),
            ("X-Good".to_string(), " fine ".to_string()),
        ]));
        let v = validate_submission(&req, &c).unwrap();
        // X-Good survives (trimmed). A BEL control character in a *value* is
        // not a header-injection vector and is kept; only name-side controls
        // and CR/LF anywhere are dropped.
        let names: Vec<&str> = v.headers.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names.len(), 2, "{names:?}");
        assert!(names.contains(&"X-Good"));
        assert!(names.contains(&"X-Ctrl"));
        assert_eq!(
            v.headers
                .iter()
                .find(|(k, _)| k == "X-Good")
                .map(|(_, val)| val.as_str()),
            Some("fine")
        );

        // A recipient with CR/LF is dropped, not spliced.
        let mut req = submit_request("example.com");
        req.to = vec![
            "good@example.net".into(),
            "evil@example.net\r\nBcc: leak@example.net".into(),
            "  ".into(),
        ];
        let v = validate_submission(&req, &c).unwrap();
        assert_eq!(v.to, vec!["good@example.net"]);
        let raw = String::from_utf8(build_raw_message(&v)).unwrap();
        assert!(!raw.contains("leak@example.net"));

        // `from` CR/LF is a hard error (not a skip).
        let mut req = submit_request("example.com");
        req.from = Some("a@b.c\r\nX-Evil: 1".into());
        assert!(validate_submission(&req, &c).is_err());
    }

    #[tokio::test]
    async fn broken_dns_degrades_to_zero_without_panicking() {
        // Resolver outage: every lookup errors; the response must be a
        // bottom score, never a panic or a fabricated pass.
        let engine = engine_with(&broken_dns(), |_| {});
        let response = engine
            .check_domain(&DomainCheckRequest {
                domain: "example.com".into(),
                selectors: vec![],
            })
            .await
            .expect("a resolver outage is reported, not fatal");
        assert_eq!(response.breakdown.dns_health.score, 0);
        assert_eq!(response.breakdown.authentication.score, 0);
        assert_eq!(response.grade, "F");
        assert!(response
            .recommendations
            .iter()
            .any(|r| r.starts_with("[Action Required]")));
    }

    #[tokio::test]
    async fn concurrent_requests_share_one_flight_result() {
        // Two overlapping checks: the second must wait on the singleflight
        // lock and then read the freshly-cached response (the double-check
        // path), not run a second DNS sweep.
        let fake = full_signal_dns();
        let engine = std::sync::Arc::new(engine_with(&fake, |c| c.cache_ttl_seconds = 300));
        let request = DomainCheckRequest {
            domain: "example.com".into(),
            selectors: vec![],
        };
        let (first, second) =
            tokio::join!(engine.check_domain(&request), engine.check_domain(&request));
        let (first, second) = (first.unwrap(), second.unwrap());
        assert_eq!(first.score, second.score);
        assert_eq!(first.domain, "example.com");
    }

    #[tokio::test]
    async fn ed25519_dkim_is_reported_at_the_equivalent_strength() {
        let fake = StubDns::new()
            .mx("ed.example", 5, "mx.ed.example")
            .spf("ed.example", "v=spf1 -all")
            .dkim("s1", "ed.example", "v=DKIM1; k=ed25519; p=AAAA");
        let engine = engine_with(&fake, |_| {});
        let response = engine
            .check_domain(&DomainCheckRequest {
                domain: "ed.example".into(),
                selectors: vec!["s1".into()],
            })
            .await
            .unwrap();
        let details = response.breakdown.authentication.details.as_ref().unwrap();
        assert_eq!(details["dkim"]["details"][0]["key_type"], "ed25519");
        assert_eq!(details["dkim"]["details"][0]["key_size"], 256);
        assert_eq!(details["dkim"]["details"][0]["strong"], true);
    }

    #[tokio::test]
    async fn tenant_weight_overrides_change_the_composite() {
        let fake = full_signal_dns();
        let mut weights = std::collections::HashMap::new();
        weights.insert(
            "tenant-heavy-dns".to_string(),
            crate::config::ScoringWeights {
                dns_health: 10.0,
                authentication: 0.0,
                spam_likelihood: 0.0,
                content_quality: 0.0,
                reputation: 0.0,
            },
        );
        // Also register a broken override so the startup validation loop runs
        // its fallback branch.
        weights.insert(
            "tenant-broken".to_string(),
            crate::config::ScoringWeights {
                dns_health: 0.0,
                authentication: 0.0,
                spam_likelihood: 0.0,
                content_quality: 0.0,
                reputation: 0.0,
            },
        );
        let engine = engine_with(&fake, |c| {
            c.tenant_weights = weights.clone();
            c.cache_ttl_seconds = 0;
        });

        let request = EmailSubmitRequest {
            domain: Some("example.com".into()),
            from: Some("alice@example.com".into()),
            to: vec!["bob@example.net".into()],
            subject: Some("Hello".into()),
            body_text: Some("ordinary".into()),
            body_html: None,
            headers: None,
            selectors: vec!["default".into()],
            sender_ip: None,
            helo_hostname: None,
            mail_from: None,
        };
        let submission = engine.validate_submission(&request).unwrap();
        let heavy = engine
            .analyze_email(&submission, "tenant-heavy-dns")
            .await
            .unwrap();
        let fallback = engine
            .analyze_email(&submission, "tenant-broken")
            .await
            .unwrap();
        // DNS 90 dominates the heavy-DNS tenant (all other weight is 0); the
        // broken override fell back to the default distribution.
        assert_eq!(heavy.score, 90);
        assert!(
            (60..90).contains(&fallback.score),
            "default weighted composite expected, got {}",
            fallback.score
        );
    }

    #[tokio::test]
    async fn spam_findings_fire_for_risky_content() {
        let fake = full_signal_dns();
        let engine = engine_with(&fake, |c| c.cache_ttl_seconds = 0);
        let urls = (0..25)
            .map(|i| format!("http://spam{i}.example/x"))
            .collect::<Vec<_>>()
            .join(" ");
        let request = EmailSubmitRequest {
            domain: Some("example.com".into()),
            from: Some("alice@example.com".into()),
            to: vec!["bob@example.net".into()],
            subject: Some("FREE MONEY NOW!!! ACT NOW!!!".into()),
            body_text: Some(format!(
                "Congratulations winner! Free cash prize claim now. Viagra cheap. {urls}"
            )),
            body_html: None,
            headers: None,
            selectors: vec![],
            sender_ip: None,
            helo_hostname: None,
            mail_from: None,
        };
        let submission = engine.validate_submission(&request).unwrap();
        let response = engine.analyze_email(&submission, "t").await.unwrap();
        assert!(
            response
                .findings
                .iter()
                .any(|f| f.category == "spam" || f.message.contains("High URL count")),
            "{:?}",
            response.findings
        );
        assert!(response
            .recommendations
            .iter()
            .any(|r| r.contains("Spam engine classification")));
    }

    #[test]
    fn authenticate_email_requires_both_sender_ip_and_helo() {
        let fake = full_signal_dns();
        let engine = engine_with(&fake, |_| {});
        // sender_ip without helo → no message-level authentication attempt.
        let request = EmailSubmitRequest {
            domain: Some("example.com".into()),
            from: Some("alice@example.com".into()),
            to: vec![],
            subject: None,
            body_text: Some("hi".into()),
            body_html: None,
            headers: None,
            selectors: vec![],
            sender_ip: Some("93.184.216.34".into()),
            helo_hostname: None,
            mail_from: None,
        };
        let submission = engine.validate_submission(&request).unwrap();
        assert!(submission.sender_ip.is_some());
        assert!(submission.helo_hostname.is_none());
        let raw = build_raw_message(&submission);
        assert!(raw.starts_with(b"From: alice@example.com\r\n"));
    }

    #[test]
    fn skipped_recipients_are_logged_and_never_spliced() {
        // Exercise the skip-warning path with a body of legal size.
        let c = GraderConfig {
            max_body_size: 1024,
            ..cfg()
        };
        let mut req = submit_request("example.com");
        req.to = vec!["ok@example.net".into(), "bad@example.net\r\nBcc: x".into()];
        let v = validate_submission(&req, &c).unwrap();
        assert_eq!(v.to, vec!["ok@example.net"]);
    }

    #[test]
    fn strip_html_tags_removes_markup_and_keeps_text() {
        assert_eq!(strip_html_tags("<p>Hello <b>world</b></p>"), "Hello world");
        // An unclosed '<' swallows the rest (documented lenient behaviour).
        assert_eq!(strip_html_tags("a < b and c > d"), "a  d");
        assert_eq!(strip_html_tags(""), "");
        assert_eq!(strip_html_tags("no tags"), "no tags");
    }
}
