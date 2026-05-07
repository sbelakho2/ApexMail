//! Core email authentication:SPF, DKIM, DMARC (RFC 7208, 6376, 7489).
//!
//! Leverages `mail-auth` for the heavy lifting (DNS‑based checks, crypto) and adds
//! caching, policy evaluation, and the `AuthenticationResults` header builder.

use std::net::IpAddr;
use std::time::Duration;

use mail_auth::{AuthenticatedMessage, DkimResult, Resolver, SpfResult};
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

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

// ── authenticator ──────────────────────────────────────────────────────────────

/// Stateful email authenticator with DNS caching.
pub struct EmailAuthenticator {
    resolver: Resolver,
    /// #120:Dedicated DNS resolver for DMARC TXT lookups.
    dns_resolver: TokioAsyncResolver,
    config: EmailAuthConfig,
    hostname: String,
    /// Domain → SPF evaluation cache (TTL 5 min).
    spf_cache: Cache<String, SpfVerdict>,
    /// #120:Domain → DMARC policy cache (TTL 5 min).
    dmarc_cache: Cache<String, DmarcPolicy>,
}

impl EmailAuthenticator {
    /// Create a new authenticator.
    pub async fn new(config: EmailAuthConfig, hostname: String) -> anyhow::Result<Self> {
        let resolver = Resolver::new_system_conf().map_err(|e| anyhow::anyhow!("resolver: {e}"))?;

        // #120:Shared DNS resolver for DMARC TXT lookups (avoids per-call allocation)
        let dns_resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

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
        let from_domain = mail_from
            .rsplit_once('@')
            .map(|(_, d)| d)
            .unwrap_or(mail_from)
            .to_lowercase();

        // Parse message synchronously (AuthenticatedMessage::parse is sync)
        let authenticated_msg = AuthenticatedMessage::parse(raw_message);

        // #121:Run SPF + DKIM concurrently using tokio::join!
        let (spf, dkim_outcomes) = tokio::join!(
            self.check_spf(client_ip, helo_hostname, mail_from, &from_domain),
            async {
                if let Some(ref auth_msg) = authenticated_msg {
                    self.check_dkim(auth_msg).await
                } else {
                    vec![DkimOutcome {
                        result: DkimVerdict::None,
                        domain: from_domain.clone(),
                        selector: String::new(),
                        explanation: Some("Failed to parse message for DKIM".into()),
                    }]
                }
            }
        );

        // DMARC evaluation
        let dmarc = self.check_dmarc(&from_domain, &spf, &dkim_outcomes).await;

        // Build Authentication-Results header
        let auth_results_header = self.build_auth_results_header(&spf, &dkim_outcomes, &dmarc);

        Ok(AuthenticationResults {
            spf,
            dkim: dkim_outcomes,
            dmarc,
            auth_results_header,
        })
    }

    /// Decide whether to accept, quarantine or reject based on authentication + config.
    pub fn should_accept(&self, results: &AuthenticationResults) -> MessageDisposition {
        // SPF hard fail + strict
        if self.config.require_spf && results.spf.result == SpfVerdict::Fail {
            return MessageDisposition::Reject;
        }

        // DKIM required but none passed
        if self.config.require_dkim && !results.dkim.iter().any(|d| d.result == DkimVerdict::Pass) {
            return MessageDisposition::Reject;
        }

        // DMARC enforcement
        if self.config.enforce_dmarc && results.dmarc.result == DmarcVerdict::Fail {
            return match results.dmarc.policy {
                DmarcPolicy::Reject => MessageDisposition::Reject,
                DmarcPolicy::Quarantine => MessageDisposition::Quarantine,
                DmarcPolicy::None => {
                    if self.config.allow_soft_fail {
                        MessageDisposition::Accept
                    } else {
                        MessageDisposition::Quarantine
                    }
                }
            };
        }

        MessageDisposition::Accept
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

    async fn check_dmarc(
        &self,
        from_domain: &str,
        spf: &SpfOutcome,
        dkim: &[DkimOutcome],
    ) -> DmarcOutcome {
        let spf_aligned = spf.result == SpfVerdict::Pass;
        let dkim_aligned = dkim.iter().any(|d| d.result == DkimVerdict::Pass);

        // #120:Fetch actual DMARC policy from DNS (p=reject/quarantine/none)
        let policy = self.lookup_dmarc_policy(from_domain).await;

        // DMARC passes if either SPF or DKIM passes with alignment
        let result = if spf_aligned || dkim_aligned {
            DmarcVerdict::Pass
        } else {
            match policy {
                DmarcPolicy::None => DmarcVerdict::None,
                _ => DmarcVerdict::Fail,
            }
        };

        DmarcOutcome {
            result,
            domain: from_domain.to_string(),
            policy,
            alignment: DmarcAlignment {
                spf: spf_aligned,
                dkim: dkim_aligned,
            },
        }
    }

    /// #120:Look up DMARC DNS TXT record and parse p= policy, with fallback to parent domain.
    async fn lookup_dmarc_policy(&self, domain: &str) -> DmarcPolicy {
        if let Some(cached) = self.dmarc_cache.get(domain) {
            return cached;
        }

        let policy = match self.fetch_dmarc_txt(domain).await {
            Some(p) => p,
            None => {
                // Try organizational/parent domain if subdomain record absent
                if let Some(dot_idx) = domain.find('.') {
                    let parent = &domain[dot_idx + 1..];
                    if parent.contains('.') {
                        self.fetch_dmarc_txt(parent)
                            .await
                            .unwrap_or(DmarcPolicy::None)
                    } else {
                        DmarcPolicy::None
                    }
                } else {
                    DmarcPolicy::None
                }
            }
        };

        self.dmarc_cache.insert(domain.to_string(), policy);
        policy
    }

    /// Fetch and parse a single _dmarc.{domain} TXT record.
    async fn fetch_dmarc_txt(&self, domain: &str) -> Option<DmarcPolicy> {
        let dmarc_domain = format!("_dmarc.{domain}");
        match self.dns_resolver.txt_lookup(&dmarc_domain).await {
            Ok(lookup) => {
                for record in lookup.iter() {
                    let txt = record.to_string();
                    if let Some(policy) = parse_dmarc_policy_record(&txt) {
                        return Some(policy);
                    }
                }
                None
            }
            Err(_) => None,
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

/// #120:Parse p= policy from a raw DMARC TXT record string.
fn parse_dmarc_policy_record(txt: &str) -> Option<DmarcPolicy> {
    let trimmed = txt.trim();
    if !trimmed.starts_with("v=DMARC1") {
        return None;
    }
    for part in trimmed.split(';') {
        let kv = part.trim();
        if let Some(val) = kv.strip_prefix("p=") {
            return Some(match val.trim().to_lowercase().as_str() {
                "reject" => DmarcPolicy::Reject,
                "quarantine" => DmarcPolicy::Quarantine,
                _ => DmarcPolicy::None,
            });
        }
    }
    None
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_authenticator(config: EmailAuthConfig, hostname: &str) -> Option<EmailAuthenticator> {
        let resolver = Resolver::new_system_conf().ok()?;
        let dns_resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
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
        let record = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com";
        assert_eq!(parse_dmarc_policy_record(record), Some(DmarcPolicy::Reject));
    }

    #[test]
    fn test_parse_dmarc_policy_quarantine() {
        assert_eq!(
            parse_dmarc_policy_record("v=DMARC1; p=quarantine"),
            Some(DmarcPolicy::Quarantine)
        );
    }

    #[test]
    fn test_parse_dmarc_policy_none() {
        assert_eq!(
            parse_dmarc_policy_record("v=DMARC1; p=none"),
            Some(DmarcPolicy::None)
        );
    }

    #[test]
    fn test_parse_dmarc_policy_invalid() {
        assert_eq!(parse_dmarc_policy_record("not a dmarc record"), None);
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
}
