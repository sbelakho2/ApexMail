//! Content scanning engine — multi-layer email analysis covering spam, phishing,
//! malware, and policy compliance.
//!
//! Spam:15 regex rules with fast-check combined alternation, caps/punctuation ratios.
//! Phishing:URL analysis (IP-based, shorteners, suspicious TLDs, brand impersonation,
//! homographs), sender mismatch, urgency patterns.
//! Malware:dangerous extensions, double extensions, magic byte mismatch, macros,
//! password-protected archives, oversized attachments.
//! Policy:tenant-specific rules from content_policies DB table + CAN-SPAM checks.

use aho_corasick::AhoCorasick;
use chrono::Utc;
use regex::{Regex, RegexBuilder};
use sqlx::PgPool;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, LazyLock};
use tokio::sync::RwLock;
use tracing::warn;

use uuid::Uuid;

use crate::config::ContentScanningConfig;
use crate::types::*;

const BLOCKED_POLICY_SCAN_PREFIX_BYTES: usize = 50_000;

// ─── Spam Rules ────────────────────────────────────────────────

struct SpamRule {
    name: &'static str,
    score: f64,
    description: &'static str,
    target: RuleTarget,
    pattern: &'static str,
}

#[derive(PartialEq, Copy, Clone)]
enum RuleTarget {
    Text,
    Html,
}

const SPAM_RULES: &[SpamRule] = &[
    SpamRule {
        name: "FREE_MONEY",
        score: 8.0,
        description: "Free money offer",
        target: RuleTarget::Text,
        pattern: r"(?i)free\s+money|earn\s+\$?\d+",
    },
    SpamRule {
        name: "WINNER",
        score: 7.0,
        description: "Winner notification",
        target: RuleTarget::Text,
        pattern: r"(?i)you('ve| have)\s+(been\s+)?selected|you('re| are)\s+a?\s*winner|congratulations.{0,30}winner",
    },
    SpamRule {
        name: "URGENT_ACTION",
        score: 6.0,
        description: "Urgent action required",
        target: RuleTarget::Text,
        pattern: r"(?i)urgent.{0,20}action|immediate.{0,20}response|act\s+now|limited\s+time",
    },
    SpamRule {
        name: "BANK_TRANSFER",
        score: 9.0,
        description: "Bank transfer solicitation",
        target: RuleTarget::Text,
        pattern: r"(?i)wire\s+transfer|bank\s+transfer|routing\s+number|swift\s+code",
    },
    SpamRule {
        name: "NIGERIAN_PRINCE",
        score: 10.0,
        description: "Advance fee fraud",
        target: RuleTarget::Text,
        pattern: r"(?i)(prince|minister|diplomat|barrister).{0,40}(million|fund|inheritance|estate)",
    },
    SpamRule {
        name: "MEDICATION_SPAM",
        score: 7.0,
        description: "Medication spam",
        target: RuleTarget::Text,
        pattern: r"(?i)(viagra|cialis|pharmacy|prescription).{0,30}(cheap|discount|buy|order)",
    },
    SpamRule {
        name: "WEIGHT_LOSS",
        score: 5.0,
        description: "Weight loss spam",
        target: RuleTarget::Text,
        pattern: r"(?i)weight\s+loss|lose\s+\d+\s*(lb|kg|pound)|diet\s+pill|fat\s+burn",
    },
    SpamRule {
        name: "CRYPTOCURRENCY_SCAM",
        score: 8.0,
        description: "Cryptocurrency scam",
        target: RuleTarget::Text,
        pattern: r"(?i)(bitcoin|crypto|blockchain).{0,30}(invest|profit|double|guaranteed)",
    },
    // Note:UNSUBSCRIBE_MISSING, IMAGE_ONLY, EXCESSIVE_LINKS, ALL_CAPS checks are implemented as custom logic below
    SpamRule {
        name: "HIDDEN_TEXT",
        score: 6.0,
        description: "Hidden text in HTML",
        target: RuleTarget::Html,
        pattern: r#"(?i)(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)"#,
    },
    SpamRule {
        name: "TINY_FONT",
        score: 5.0,
        description: "Extremely small font",
        target: RuleTarget::Html,
        pattern: r"(?i)font-size\s*:\s*[01](px|pt|em)",
    },
];

struct CompiledSpamRule {
    name: &'static str,
    score: f64,
    description: &'static str,
    target: RuleTarget,
    regex: Regex,
}

static COMPILED_SPAM_RULES: LazyLock<Vec<CompiledSpamRule>> = LazyLock::new(|| {
    SPAM_RULES
        .iter()
        .filter(|r| !r.pattern.contains("PLACEHOLDER"))
        .filter_map(|r| {
            compile_regex(r.pattern, "spam_rules").map(|regex| CompiledSpamRule {
                name: r.name,
                score: r.score,
                description: r.description,
                target: r.target,
                regex,
            })
        })
        .collect()
});

/// Combined alternation of all text-targeted spam rules for fast pre-check.
static FAST_SPAM_CHECK: LazyLock<Option<Regex>> = LazyLock::new(|| {
    let text_patterns: Vec<&str> = SPAM_RULES
        .iter()
        .filter(|r| r.target == RuleTarget::Text && !r.pattern.contains("PLACEHOLDER"))
        .map(|r| r.pattern)
        .collect();
    if text_patterns.is_empty() {
        return None;
    }
    compile_regex(&text_patterns.join("|"), "fast_spam_check")
});

// ─── Phishing ──────────────────────────────────────────

static URL_REGEX: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile_regex(r#"https?://[^\s<>"']+"#, "url_regex"));
static IP_URL_REGEX: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile_regex(
        r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        "ip_url_regex",
    )
});

static URL_SHORTENERS: LazyLock<Option<AhoCorasick>> = LazyLock::new(|| {
    compile_aho(
        &[
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "ow.ly",
            "is.gd",
            "buff.ly",
            "adf.ly",
            "tiny.cc",
            "shorte.st",
        ],
        "url_shorteners",
    )
});

static SUSPICIOUS_TLDS: LazyLock<Option<AhoCorasick>> = LazyLock::new(|| {
    compile_aho(
        &[
            ".xyz",
            ".top",
            ".work",
            ".date",
            ".review",
            ".bid",
            ".stream",
            ".click",
            ".download",
            ".loan",
            ".racing",
        ],
        "suspicious_tlds",
    )
});

static BRAND_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    let patterns = [
        ("PayPal", r"(?i)paypa[l1]|pay[-_]?pal"),
        ("Apple", r"(?i)app[l1]e|ap[p]+le"),
        ("Amazon", r"(?i)amaz[o0]n|amazo[n]+"),
        ("Microsoft", r"(?i)micros[o0]ft|micr[o0]soft|m[i1]crosoft"),
        ("Google", r"(?i)g[o0][o0]g[l1]e|googl[e3]"),
    ];

    patterns
        .iter()
        .filter_map(|(brand, pattern)| {
            compile_regex(pattern, "brand_patterns").map(|re| (*brand, re))
        })
        .collect()
});

static URGENCY_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    let patterns = [
        r"(?i)account.{0,20}suspended",
        r"(?i)verify\s+your\s+(identity|account)",
        r"(?i)unauthorized.{0,20}access",
        r"(?i)confirm.{0,20}now.{0,20}or.{0,20}lose",
        r"(?i)security\s+alert",
        r"(?i)click\s+here\s+immediately",
    ];
    patterns
        .iter()
        .filter_map(|pattern| compile_regex(pattern, "urgency_patterns"))
        .collect()
});

/// Homograph / confusable Unicode chars.
static HOMOGRAPH_REGEX: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile_regex(
        r"[\u{0400}-\u{04FF}\u{2000}-\u{206F}\u{FF00}-\u{FFEF}]",
        "homograph_regex",
    )
});

// ─── Malware ───────────────────────────────────────────

static DANGEROUS_EXTENSIONS: LazyLock<Option<AhoCorasick>> = LazyLock::new(|| {
    compile_aho(
        &[
            ".exe", ".bat", ".cmd", ".com", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".ps1",
            ".scr", ".pif", ".msi", ".hta", ".cpl",
        ],
        "dangerous_extensions",
    )
});

static MACRO_EXTENSIONS: LazyLock<Option<AhoCorasick>> = LazyLock::new(|| {
    compile_aho(
        &[".docm", ".xlsm", ".pptm", ".dotm", ".xltm"],
        "macro_extensions",
    )
});

static PHYSICAL_ADDRESS_REGEX: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile_regex(
        r"\d{1,6}\s+\w+\s+(St|Ave|Blvd|Dr|Rd|Ln|Way|Ct|Pl)",
        "physical_address_regex",
    )
});

fn compile_regex(pattern: &str, label: &str) -> Option<Regex> {
    match Regex::new(pattern) {
        Ok(regex) => Some(regex),
        Err(e) => {
            warn!(pattern = %pattern, label, error = %e, "Invalid regex pattern; disabling matcher");
            None
        }
    }
}

fn compile_aho(patterns: &[&str], label: &str) -> Option<AhoCorasick> {
    match AhoCorasick::new(patterns) {
        Ok(ac) => Some(ac),
        Err(e) => {
            warn!(label, error = %e, "Invalid Aho-Corasick patterns; disabling matcher");
            None
        }
    }
}

// ─── Magic bytes (file signature) ──────────────────────────────

fn expected_magic(ext: &str) -> Option<&'static [u8]> {
    match ext {
        "pdf" => Some(b"%PDF"),
        "zip" => Some(&[0x50, 0x4B, 0x03, 0x04]),
        "rar" => Some(&[0x52, 0x61, 0x72, 0x21]),
        "exe" | "dll" => Some(&[0x4D, 0x5A]),
        "png" => Some(&[0x89, 0x50, 0x4E, 0x47]),
        "jpg" | "jpeg" => Some(&[0xFF, 0xD8, 0xFF]),
        "gif" => Some(&[0x47, 0x49, 0x46]),
        _ => None,
    }
}

fn is_password_protected_zip(header_bytes: &[u8]) -> bool {
    header_bytes.len() > 6 && (header_bytes[6] & 0x01) != 0
}

pub struct ContentScanner {
    db: PgPool,
    config: ContentScanningConfig,
    policy_regex_cache: RwLock<HashMap<String, Arc<Vec<(String, Regex)>>>>,
}

impl ContentScanner {
    pub fn new(db: PgPool, config: ContentScanningConfig) -> Self {
        Self {
            db,
            config,
            policy_regex_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Scan an email through all analysis layers.
    pub async fn scan_email(&self, content: &EmailContent) -> Result<ContentScanResult, String> {
        let spam = self.analyze_spam(content);
        let phishing = self.analyze_phishing(content);
        let malware = self.analyze_malware(content);
        let policy = self.analyze_policy(content).await;

        let verdict = determine_verdict(&spam, &phishing, &malware, &policy);

        let now = Utc::now();
        let mut actions = Vec::new();
        match verdict {
            ScanVerdict::Blocked => actions.push(ContentAction {
                action: ContentActionType::Reject,
                reason: "Content blocked by security scan".into(),
                applied_at: now,
            }),
            ScanVerdict::Suspicious => actions.push(ContentAction {
                action: ContentActionType::Quarantine,
                reason: "Content flagged as suspicious".into(),
                applied_at: now,
            }),
            ScanVerdict::Clean => actions.push(ContentAction {
                action: ContentActionType::Allow,
                reason: "Content passed all checks".into(),
                applied_at: now,
            }),
        }

        let result = ContentScanResult {
            id: Uuid::new_v4().to_string(),
            tenant_id: content.tenant_id.clone(),
            message_id: content.message_id.clone(),
            scanned_at: now,
            spam,
            phishing,
            malware,
            policy,
            overall_verdict: verdict,
            actions,
        };

        // Persist result
        self.persist_result(&result).await?;

        Ok(result)
    }

    /// Retrieve a stored scan result.
    pub async fn get_result(&self, result_id: &str) -> Result<Option<ContentScanResult>, String> {
        let row: Option<(serde_json::Value,)> =
            sqlx::query_as("SELECT results FROM scan_results WHERE id = $1")
                .bind(result_id)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| format!("DB error: {e}"))?;

        match row {
            Some((json,)) => {
                let result: ContentScanResult =
                    serde_json::from_value(json).map_err(|e| format!("JSON: {e}"))?;
                Ok(Some(result))
            }
            None => Ok(None),
        }
    }

    /// Get scanning statistics.
    pub async fn get_stats(&self, tenant_id: Option<&str>) -> Result<serde_json::Value, String> {
        let (total, clean, suspicious, blocked, spam_count, phishing_count): (
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
        ) = if let Some(tid) = tenant_id {
            sqlx::query_as(
                "SELECT
                   COUNT(*),
                   COUNT(*) FILTER (WHERE overall_verdict = 'clean'),
                   COUNT(*) FILTER (WHERE overall_verdict = 'suspicious'),
                   COUNT(*) FILTER (WHERE overall_verdict = 'blocked'),
                   COUNT(*) FILTER (WHERE spam_detected = true),
                   COUNT(*) FILTER (WHERE phishing_detected = true)
                 FROM scan_results WHERE tenant_id = $1",
            )
            .bind(tid)
            .fetch_one(&self.db)
            .await
            .map_err(|e| format!("DB error: {e}"))?
        } else {
            sqlx::query_as(
                "SELECT
                   COUNT(*),
                   COUNT(*) FILTER (WHERE overall_verdict = 'clean'),
                   COUNT(*) FILTER (WHERE overall_verdict = 'suspicious'),
                   COUNT(*) FILTER (WHERE overall_verdict = 'blocked'),
                   COUNT(*) FILTER (WHERE spam_detected = true),
                   COUNT(*) FILTER (WHERE phishing_detected = true)
                 FROM scan_results",
            )
            .fetch_one(&self.db)
            .await
            .map_err(|e| format!("DB error: {e}"))?
        };

        Ok(serde_json::json!({
            "total": total,
            "clean": clean,
            "suspicious": suspicious,
            "blocked": blocked,
            "spam_detected": spam_count,
            "phishing_detected": phishing_count,
        }))
    }

    // ── Spam Analysis ─────────────────────────────────────────

    fn analyze_spam(&self, content: &EmailContent) -> SpamAnalysis {
        let mut triggers: Vec<SpamTrigger> = Vec::new();
        let mut score = 0.0_f64;

        let text = content.text_body.as_deref().unwrap_or("");
        let html = content.html_body.as_deref().unwrap_or("");
        let combined_text = format!("{} {}", content.subject, text);

        // Fast pre-check:if combined regex doesn't match, skip text rules.
        let text_rules_may_match = FAST_SPAM_CHECK
            .as_ref()
            .is_none_or(|regex| regex.is_match(&combined_text));

        for rule in COMPILED_SPAM_RULES.iter() {
            match rule.target {
                RuleTarget::Text => {
                    if !text_rules_may_match {
                        continue;
                    }
                    if rule.regex.is_match(&combined_text) {
                        score += rule.score;
                        triggers.push(SpamTrigger {
                            rule: rule.name.into(),
                            score: rule.score,
                            description: rule.description.into(),
                        });
                    }
                }
                RuleTarget::Html => {
                    if !html.is_empty() && rule.regex.is_match(html) {
                        score += rule.score;
                        triggers.push(SpamTrigger {
                            rule: rule.name.into(),
                            score: rule.score,
                            description: rule.description.into(),
                        });
                    }
                }
            }
        }

        // CAN-SPAM:check for missing unsubscribe
        if !text.contains("unsubscribe") && !html.contains("unsubscribe") {
            score += 3.0;
            triggers.push(SpamTrigger {
                rule: "UNSUBSCRIBE_MISSING".into(),
                score: 3.0,
                description: "No unsubscribe link found".into(),
            });
        }

        // Excessive caps in subject
        if content.subject.len() > 5 {
            let caps = content.subject.chars().filter(|c| c.is_uppercase()).count();
            let ratio = caps as f64 / content.subject.len() as f64;
            if ratio > 0.3 {
                score += 4.0;
                triggers.push(SpamTrigger {
                    rule: "EXCESSIVE_CAPS".into(),
                    score: 4.0,
                    description: format!("Caps ratio {:.0}% in subject", ratio * 100.0),
                });
            }

            // ALL CAPS subject (>90% uppercase)
            if ratio > 0.9 {
                score += 4.0;
                triggers.push(SpamTrigger {
                    rule: "ALL_CAPS_SUBJECT".into(),
                    score: 4.0,
                    description: "Subject line is all caps".into(),
                });
            }
        }

        // Sender mismatch:check if From domain doesn't match Reply-To or visible domain
        let from_domain = content.from_address.split('@').next_back().unwrap_or("");
        if let Some(reply_to) = content
            .headers
            .get("Reply-To")
            .or_else(|| content.headers.get("reply-to"))
        {
            let reply_domain = reply_to
                .split('@')
                .next_back()
                .unwrap_or("")
                .trim_end_matches('>');
            if !from_domain.is_empty() && !reply_domain.is_empty() && from_domain != reply_domain {
                score += 4.0;
                triggers.push(SpamTrigger {
                    rule: "SENDER_MISMATCH".into(),
                    score: 4.0,
                    description: format!(
                        "From domain '{}' differs from Reply-To '{}'",
                        from_domain, reply_domain
                    ),
                });
            }
        }

        // Excessive punctuation
        if combined_text.len() > 20 {
            let punct = combined_text
                .chars()
                .filter(|c| *c == '!' || *c == '?' || *c == '$')
                .count();
            let ratio = punct as f64 / combined_text.len() as f64;
            if ratio > 0.1 {
                score += 3.0;
                triggers.push(SpamTrigger {
                    rule: "EXCESSIVE_PUNCTUATION".into(),
                    score: 3.0,
                    description: format!("Punctuation ratio {:.0}%", ratio * 100.0),
                });
            }
        }

        // Image-only check:lots of <img> but very little text
        if !html.is_empty() && text.len() < 50 {
            let img_count = html.matches("<img").count();
            if img_count > 0 {
                score += 4.0;
                triggers.push(SpamTrigger {
                    rule: "IMAGE_ONLY".into(),
                    score: 4.0,
                    description: format!("{img_count} images with minimal text"),
                });
            }
        }

        // Excessive links
        if !html.is_empty() {
            let link_count = html.matches("<a ").count() + html.matches("<a\t").count();
            if link_count > 15 {
                score += 3.0;
                triggers.push(SpamTrigger {
                    rule: "EXCESSIVE_LINKS".into(),
                    score: 3.0,
                    description: format!("{link_count} links found"),
                });
            }
        }

        SpamAnalysis {
            score,
            is_spam: score >= self.config.spam_threshold,
            triggers,
        }
    }

    // ── Phishing Analysis ─────────────────────────────────────

    fn analyze_phishing(&self, content: &EmailContent) -> PhishingAnalysis {
        let mut indicators: Vec<PhishingIndicator> = Vec::new();
        let mut score = 0.0_f64;

        let text = content.text_body.as_deref().unwrap_or("");
        let html = content.html_body.as_deref().unwrap_or("");
        let combined = format!("{} {} {}", content.subject, text, html);

        // URL analysis
        if let Some(url_regex) = URL_REGEX.as_ref() {
            for url_match in url_regex.find_iter(&combined) {
                let url_str = url_match.as_str();

                // IP-based URL
                if IP_URL_REGEX
                    .as_ref()
                    .is_some_and(|regex| regex.is_match(url_str))
                {
                    score += 15.0;
                    indicators.push(PhishingIndicator {
                        indicator_type: PhishingIndicatorType::Url,
                        indicator: url_str.into(),
                        confidence: 0.7,
                        description: "IP-based URL".into(),
                    });
                }

                // URL shortener
                if URL_SHORTENERS
                    .as_ref()
                    .is_some_and(|ac| ac.is_match(url_str))
                {
                    score += 10.0;
                    indicators.push(PhishingIndicator {
                        indicator_type: PhishingIndicatorType::Url,
                        indicator: url_str.into(),
                        confidence: 0.5,
                        description: "URL shortener used".into(),
                    });
                }

                // Suspicious TLD
                if SUSPICIOUS_TLDS
                    .as_ref()
                    .is_some_and(|ac| ac.is_match(url_str))
                {
                    score += 8.0;
                    indicators.push(PhishingIndicator {
                        indicator_type: PhishingIndicatorType::Url,
                        indicator: url_str.into(),
                        confidence: 0.4,
                        description: "Suspicious TLD".into(),
                    });
                }

                // Excessive subdomains
                if let Ok(parsed) = url::Url::parse(url_str) {
                    if let Some(host) = parsed.host_str() {
                        let dot_count = host.chars().filter(|c| *c == '.').count();
                        if dot_count > 3 {
                            score += 8.0;
                            indicators.push(PhishingIndicator {
                                indicator_type: PhishingIndicatorType::Url,
                                indicator: url_str.into(),
                                confidence: 0.6,
                                description: "Excessive subdomains".into(),
                            });
                        }

                        // Brand impersonation in subdomain
                        for (brand, re) in BRAND_PATTERNS.iter() {
                            if re.is_match(host) {
                                // Only flag if it's not the real domain
                                let real_domain = brand.to_lowercase();
                                if !host.contains(&format!("{real_domain}.com")) {
                                    score += 20.0;
                                    indicators.push(PhishingIndicator {
                                        indicator_type: PhishingIndicatorType::Url,
                                        indicator: url_str.into(),
                                        confidence: 0.8,
                                        description: format!("Brand impersonation: {brand}"),
                                    });
                                }
                            }
                        }

                        // Homograph detection
                        if HOMOGRAPH_REGEX
                            .as_ref()
                            .is_some_and(|regex| regex.is_match(host))
                        {
                            score += 20.0;
                            indicators.push(PhishingIndicator {
                                indicator_type: PhishingIndicatorType::Url,
                                indicator: url_str.into(),
                                confidence: 0.9,
                                description: "Homograph attack suspected".into(),
                            });
                        }
                    }
                }
            }
        }

        // Sender analysis:display name vs email domain mismatch
        if let Some(display) = &content.from_display_name {
            let email_domain = content.from_address.rsplit('@').next().unwrap_or("");
            let display_lower = display.to_lowercase();

            for (brand, re) in BRAND_PATTERNS.iter() {
                if re.is_match(&display_lower)
                    && !email_domain.to_lowercase().contains(&brand.to_lowercase())
                {
                    score += 15.0;
                    indicators.push(PhishingIndicator {
                        indicator_type: PhishingIndicatorType::Sender,
                        indicator: format!("{display} <{}>", content.from_address),
                        confidence: 0.8,
                        description: format!(
                            "Display name impersonates {brand} but sent from {email_domain}"
                        ),
                    });
                }
            }
        }

        // Urgency patterns in content
        for re in URGENCY_PATTERNS.iter() {
            if re.is_match(&combined) {
                score += 5.0;
                indicators.push(PhishingIndicator {
                    indicator_type: PhishingIndicatorType::Content,
                    indicator: re.as_str().into(),
                    confidence: 0.5,
                    description: "Urgency language detected".into(),
                });
            }
        }

        // HTML attachment with password form
        for att in &content.attachments {
            let name_lower = att.filename.to_lowercase();
            if (name_lower.ends_with(".html") || name_lower.ends_with(".htm"))
                && att.content_type.contains("text/html")
            {
                score += 20.0;
                indicators.push(PhishingIndicator {
                    indicator_type: PhishingIndicatorType::Attachment,
                    indicator: att.filename.clone(),
                    confidence: 0.9,
                    description: "HTML attachment (potential phishing form)".into(),
                });
            }
        }

        let is_phishing = indicators.iter().any(|i| i.confidence > 0.7);

        PhishingAnalysis {
            score,
            is_phishing,
            indicators,
        }
    }

    // ── Malware Analysis ──────────────────────────────────────

    fn analyze_malware(&self, content: &EmailContent) -> MalwareAnalysis {
        let mut threats: Vec<MalwareThreat> = Vec::new();

        for att in &content.attachments {
            let name_lower = att.filename.to_lowercase();

            // Dangerous extension
            if DANGEROUS_EXTENSIONS
                .as_ref()
                .is_some_and(|ac| ac.is_match(&name_lower))
            {
                threats.push(MalwareThreat {
                    name: format!("Dangerous file type: {}", att.filename),
                    threat_type: "dangerous_extension".into(),
                    severity: ThreatSeverity::High,
                    location: att.filename.clone(),
                });
            }

            // Double extension detection (e.g., document.pdf.exe)
            let parts: Vec<&str> = att.filename.split('.').collect();
            if parts.len() > 2 {
                let last = format!(".{}", parts.last().unwrap_or(&""));
                if DANGEROUS_EXTENSIONS
                    .as_ref()
                    .is_some_and(|ac| ac.is_match(&last.to_lowercase()))
                {
                    threats.push(MalwareThreat {
                        name: format!("Double extension: {}", att.filename),
                        threat_type: "double_extension".into(),
                        severity: ThreatSeverity::Critical,
                        location: att.filename.clone(),
                    });
                }
            }

            // Magic byte mismatch
            if let Some(header) = &att.header_bytes {
                let ext = name_lower.rsplit('.').next().unwrap_or("");
                if let Some(expected) = expected_magic(ext) {
                    if header.len() >= expected.len() && &header[..expected.len()] != expected {
                        threats.push(MalwareThreat {
                            name: format!("File signature mismatch: {}", att.filename),
                            threat_type: "signature_mismatch".into(),
                            severity: ThreatSeverity::High,
                            location: att.filename.clone(),
                        });
                    }
                }

                // Password-protected ZIP
                if ext == "zip" && is_password_protected_zip(header) {
                    threats.push(MalwareThreat {
                        name: format!("Password-protected archive: {}", att.filename),
                        threat_type: "password_protected_archive".into(),
                        severity: ThreatSeverity::Medium,
                        location: att.filename.clone(),
                    });
                }
            }

            // Macro-enabled documents
            if MACRO_EXTENSIONS
                .as_ref()
                .is_some_and(|ac| ac.is_match(&name_lower))
            {
                threats.push(MalwareThreat {
                    name: format!("Macro-enabled document: {}", att.filename),
                    threat_type: "macro_document".into(),
                    severity: ThreatSeverity::Medium,
                    location: att.filename.clone(),
                });
            }

            // Oversized attachment
            if att.size > self.config.max_attachment_size {
                threats.push(MalwareThreat {
                    name: format!(
                        "Oversized attachment: {} ({} bytes)",
                        att.filename, att.size
                    ),
                    threat_type: "oversized".into(),
                    severity: ThreatSeverity::Low,
                    location: att.filename.clone(),
                });
            }
        }

        MalwareAnalysis {
            clean: threats.is_empty(),
            threats,
        }
    }

    // ── Policy Analysis ───────────────────────────────────────

    async fn analyze_policy(&self, content: &EmailContent) -> PolicyAnalysis {
        let mut violations: Vec<PolicyViolation> = Vec::new();

        // Standard:CAN-SPAM physical address check
        let text = content.text_body.as_deref().unwrap_or("");
        let html = content.html_body.as_deref().unwrap_or("");
        let body_combined = format!("{text} {html}");

        // Simplified physical address heuristic (US postal pattern)
        let has_address = PHYSICAL_ADDRESS_REGEX
            .as_ref()
            .is_none_or(|regex| regex.is_match(&body_combined));
        if !has_address {
            violations.push(PolicyViolation {
                policy: "CAN-SPAM".into(),
                rule: "physical_address".into(),
                description: "No physical mailing address found".into(),
                severity: ViolationSeverity::Warning,
            });
        }

        // RFC 5322:Message-ID header
        if !content.headers.contains_key("message-id")
            && !content.headers.contains_key("Message-ID")
            && !content.headers.contains_key("Message-Id")
        {
            violations.push(PolicyViolation {
                policy: "RFC5322".into(),
                rule: "message_id".into(),
                description: "Missing Message-ID header".into(),
                severity: ViolationSeverity::Warning,
            });
        }

        // Banned domains check
        for domain in &self.config.banned_domains {
            if content.from_address.contains(domain) {
                violations.push(PolicyViolation {
                    policy: "domain_policy".into(),
                    rule: "banned_domain".into(),
                    description: format!("Sender domain {domain} is banned"),
                    severity: ViolationSeverity::Error,
                });
            }
        }

        // Tenant-specific policies from DB
        let tenant_policies: Vec<(String, serde_json::Value)> = sqlx::query_as(
            "SELECT name, rules FROM content_policies
             WHERE tenant_id = $1 AND active = true",
        )
        .bind(&content.tenant_id)
        .fetch_all(&self.db)
        .await
        .unwrap_or_default();

        for (policy_name, rules) in &tenant_policies {
            if let Some(patterns) = rules.get("blocked_patterns") {
                if let Some(arr) = patterns.as_array() {
                    let blocked_patterns: Vec<String> = arr
                        .iter()
                        .filter_map(|v| v.as_str())
                        .filter(|pat| pat.len() <= 512)
                        .map(|pat| pat.to_string())
                        .collect();

                    if blocked_patterns.is_empty() {
                        continue;
                    }

                    let cache_key = policy_cache_key(policy_name, &blocked_patterns);
                    let cached = {
                        let cache = self.policy_regex_cache.read().await;
                        cache.get(&cache_key).cloned()
                    };

                    let compiled = if let Some(found) = cached {
                        found
                    } else {
                        let compiled: Vec<(String, Regex)> = blocked_patterns
                            .iter()
                            .filter_map(|pat| {
                                RegexBuilder::new(pat)
                                    .size_limit(1 << 20) // 1 MB compiled DFA limit — prevents ReDoS
                                    .build()
                                    .ok()
                                    .map(|re| (pat.clone(), re))
                            })
                            .collect();
                        let compiled = Arc::new(compiled);
                        let mut cache = self.policy_regex_cache.write().await;
                        cache.insert(cache_key, compiled.clone());
                        compiled
                    };

                    let check_text = utf8_prefix(&body_combined, BLOCKED_POLICY_SCAN_PREFIX_BYTES);

                    for (pattern, re) in compiled.iter() {
                        if re.is_match(check_text) {
                            violations.push(PolicyViolation {
                                policy: policy_name.clone(),
                                rule: pattern.clone(),
                                description: format!(
                                    "Content matches blocked pattern in {policy_name}"
                                ),
                                severity: ViolationSeverity::Error,
                            });
                            break;
                        }
                    }
                }
            }
        }

        PolicyAnalysis {
            compliant: violations.is_empty()
                || violations
                    .iter()
                    .all(|v| matches!(v.severity, ViolationSeverity::Warning)),
            violations,
        }
    }

    async fn persist_result(&self, result: &ContentScanResult) -> Result<(), String> {
        let results_json = serde_json::to_value(result).map_err(|e| format!("JSON: {e}"))?;

        sqlx::query(
            "INSERT INTO scan_results
               (id, tenant_id, message_id, scanned_at, results, overall_verdict,
                spam_detected, phishing_detected)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(&result.id)
        .bind(&result.tenant_id)
        .bind(&result.message_id)
        .bind(result.scanned_at)
        .bind(&results_json)
        .bind(result.overall_verdict.to_string())
        .bind(result.spam.is_spam)
        .bind(result.phishing.is_phishing)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        Ok(())
    }
}

fn determine_verdict(
    spam: &SpamAnalysis,
    phishing: &PhishingAnalysis,
    malware: &MalwareAnalysis,
    policy: &PolicyAnalysis,
) -> ScanVerdict {
    if phishing.is_phishing || !malware.clean {
        ScanVerdict::Blocked
    } else if spam.is_spam || !policy.compliant {
        ScanVerdict::Suspicious
    } else {
        ScanVerdict::Clean
    }
}

fn policy_cache_key(policy_name: &str, patterns: &[String]) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    patterns.hash(&mut hasher);
    format!("{policy_name}:{:x}", hasher.finish())
}

fn utf8_prefix(input: &str, max_bytes: usize) -> &str {
    if input.len() <= max_bytes {
        return input;
    }

    let mut end = max_bytes;
    while !input.is_char_boundary(end) {
        end -= 1;
    }

    &input[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn dummy_config() -> ContentScanningConfig {
        ContentScanningConfig {
            enabled: true,
            ocr_enabled: false,
            spam_threshold: 50.0,
            max_attachment_size: 26_214_400,
            max_ocr_images: 5,
            banned_domains: vec!["evil.com".into()],
        }
    }

    fn test_runtime() -> &'static tokio::runtime::Runtime {
        use std::sync::OnceLock;
        static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
        RT.get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        })
    }

    fn dummy_pool() -> PgPool {
        let _guard = test_runtime().enter();
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://fake:fake@localhost:1/fake")
            .unwrap()
    }

    fn clean_email() -> EmailContent {
        EmailContent {
            tenant_id: "t1".into(),
            message_id: "m1".into(),
            from_address: "sender@legit.com".into(),
            from_display_name: Some("Sender Name".into()),
            subject: "Monthly Newsletter".into(),
            text_body: Some("Hello, here is your monthly update. unsubscribe here".into()),
            html_body: Some(
                "<html><body><p>Hello world</p><a href=\"#\">unsubscribe</a></body></html>".into(),
            ),
            headers: {
                let mut h = HashMap::new();
                h.insert("Message-ID".into(), "<abc@legit.com>".into());
                h
            },
            attachments: vec![],
        }
    }

    // ── Spam Tests ──────────────────────────────────────────

    #[test]
    fn test_clean_email_not_spam() {
        let scanner = ContentScanner::new(dummy_pool(), dummy_config());
        let email = clean_email();
        let result = scanner.analyze_spam(&email);
        assert!(!result.is_spam);
        assert!(result.score < 50.0);
    }

    #[test]
    fn test_nigerian_prince_spam() {
        let scanner = ContentScanner::new(dummy_pool(), dummy_config());
        let mut email = clean_email();
        email.text_body = Some(
            "Dear friend, I am a prince from Nigeria with a million dollar estate to share. unsubscribe".into(),
        );
        let result = scanner.analyze_spam(&email);
        assert!(result.triggers.iter().any(|t| t.rule == "NIGERIAN_PRINCE"));
    }

    #[test]
    fn test_free_money_spam() {
        let scanner = ContentScanner::new(dummy_pool(), dummy_config());
        let mut email = clean_email();
        email.text_body = Some("Earn $5000 from home! Free money guaranteed! unsubscribe".into());
        let result = scanner.analyze_spam(&email);
        assert!(result.triggers.iter().any(|t| t.rule == "FREE_MONEY"));
    }

    #[test]
    fn test_hidden_text_html_rule() {
        let scanner = ContentScanner::new(dummy_pool(), dummy_config());
        let mut email = clean_email();
        email.html_body = Some(
            "<html><body><div style='display: none'>hidden spam</div><p>visible</p></body></html>"
                .into(),
        );
        let result = scanner.analyze_spam(&email);
        assert!(result.triggers.iter().any(|t| t.rule == "HIDDEN_TEXT"));
    }

    #[test]
    fn test_missing_unsubscribe() {
        let scanner = ContentScanner::new(dummy_pool(), dummy_config());
        let mut email = clean_email();
        email.text_body = Some("Hello, just a note.".into());
        email.html_body = Some("<html><body><p>Hi</p></body></html>".into());
        let result = scanner.analyze_spam(&email);
        assert!(result
            .triggers
            .iter()
            .any(|t| t.rule == "UNSUBSCRIBE_MISSING"));
    }

    #[test]
    fn test_excessive_caps_subject() {
        let scanner = ContentScanner::new(dummy_pool(), dummy_config());
        let mut email = clean_email();
        email.subject = "BUY NOW AMAZING DEAL!!!".into();
        let result = scanner.analyze_spam(&email);
        assert!(result.triggers.iter().any(|t| t.rule == "EXCESSIVE_CAPS"));
    }

    #[test]
    fn test_image_only_email() {
        let scanner = ContentScanner::new(dummy_pool(), dummy_config());
        let mut email = clean_email();
        email.text_body = Some("Hi".into());
        email.html_body =
            Some("<html><body><img src='spam.png'><img src='ad.png'></body></html>".into());
        let result = scanner.analyze_spam(&email);
        assert!(result.triggers.iter().any(|t| t.rule == "IMAGE_ONLY"));
    }

    #[test]
    fn test_utf8_prefix_truncates_on_char_boundary() {
        let input = format!("{}😀blocked", "a".repeat(49_999));

        let prefix = utf8_prefix(&input, BLOCKED_POLICY_SCAN_PREFIX_BYTES);

        assert_eq!(prefix.len(), 49_999);
        assert!(input.is_char_boundary(prefix.len()));
        assert!(!prefix.contains("blocked"));
    }

    // ── Phishing Tests ──────────────────────────────────────

    #[test]
    fn test_ip_url_phishing() {
        let scanner = ContentScanner::new(dummy_pool(), dummy_config());
        let mut email = clean_email();
        email.text_body = Some("Click here: http://192.168.1.1/login unsubscribe".into());
        let result = scanner.analyze_phishing(&email);
        assert!(!result.indicators.is_empty());
        assert!(result
            .indicators
            .iter()
            .any(|i| i.description == "IP-based URL"));
    }

    #[test]
    fn test_url_shortener_phishing() {
        let scanner = ContentScanner::new(dummy_pool(), dummy_config());
        let mut email = clean_email();
        email.text_body = Some("Click here: https://bit.ly/abc123 unsubscribe".into());
        let result = scanner.analyze_phishing(&email);
        assert!(result
            .indicators
            .iter()
            .any(|i| i.description == "URL shortener used"));
    }

    #[test]
    fn test_suspicious_tld() {
        let scanner = ContentScanner::new(dummy_pool(), dummy_config());
        let mut email = clean_email();
        email.text_body = Some("Visit https://offer.xyz/deal unsubscribe".into());
        let result = scanner.analyze_phishing(&email);
        assert!(result
            .indicators
            .iter()
            .any(|i| i.description == "Suspicious TLD"));
    }

    #[test]
    fn test_urgency_phishing() {
        let scanner = ContentScanner::new(dummy_pool(), dummy_config());
        let mut email = clean_email();
        email.text_body = Some(
            "Your account has been suspended! Verify your identity immediately. unsubscribe".into(),
        );
        let result = scanner.analyze_phishing(&email);
        assert!(!result.indicators.is_empty());
    }

    #[test]
    fn test_sender_brand_impersonation() {
        let scanner = ContentScanner::new(dummy_pool(), dummy_config());
        let mut email = clean_email();
        email.from_display_name = Some("PayPal Support".into());
        email.from_address = "scammer@phish.com".into();
        let result = scanner.analyze_phishing(&email);
        assert!(result
            .indicators
            .iter()
            .any(|i| i.indicator_type == PhishingIndicatorType::Sender));
    }

    #[test]
    fn test_html_attachment_phishing() {
        let scanner = ContentScanner::new(dummy_pool(), dummy_config());
        let mut email = clean_email();
        email.attachments.push(AttachmentInfo {
            filename: "login.html".into(),
            content_type: "text/html".into(),
            size: 5000,
            header_bytes: None,
        });
        let result = scanner.analyze_phishing(&email);
        assert!(result.is_phishing);
    }

    #[test]
    fn test_clean_email_no_phishing() {
        let scanner = ContentScanner::new(dummy_pool(), dummy_config());
        let email = clean_email();
        let result = scanner.analyze_phishing(&email);
        assert!(!result.is_phishing);
    }

    // ── Malware Tests ───────────────────────────────────────

    #[test]
    fn test_dangerous_extension() {
        let scanner = ContentScanner::new(dummy_pool(), dummy_config());
        let mut email = clean_email();
        email.attachments.push(AttachmentInfo {
            filename: "invoice.exe".into(),
            content_type: "application/octet-stream".into(),
            size: 10_000,
            header_bytes: None,
        });
        let result = scanner.analyze_malware(&email);
        assert!(!result.clean);
        assert!(result
            .threats
            .iter()
            .any(|t| t.threat_type == "dangerous_extension"));
    }

    #[test]
    fn test_double_extension() {
        let scanner = ContentScanner::new(dummy_pool(), dummy_config());
        let mut email = clean_email();
        email.attachments.push(AttachmentInfo {
            filename: "document.pdf.exe".into(),
            content_type: "application/octet-stream".into(),
            size: 10_000,
            header_bytes: None,
        });
        let result = scanner.analyze_malware(&email);
        assert!(result
            .threats
            .iter()
            .any(|t| t.threat_type == "double_extension"));
    }

    #[test]
    fn test_magic_byte_mismatch() {
        let scanner = ContentScanner::new(dummy_pool(), dummy_config());
        let mut email = clean_email();
        email.attachments.push(AttachmentInfo {
            filename: "document.pdf".into(),
            content_type: "application/pdf".into(),
            size: 5_000,
            header_bytes: Some(vec![0x4D, 0x5A, 0x90, 0x00]), // EXE magic, not PDF
        });
        let result = scanner.analyze_malware(&email);
        assert!(result
            .threats
            .iter()
            .any(|t| t.threat_type == "signature_mismatch"));
    }

    #[test]
    fn test_password_protected_zip() {
        let scanner = ContentScanner::new(dummy_pool(), dummy_config());
        let mut email = clean_email();
        email.attachments.push(AttachmentInfo {
            filename: "data.zip".into(),
            content_type: "application/zip".into(),
            size: 5_000,
            header_bytes: Some(vec![0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x01]),
        });
        let result = scanner.analyze_malware(&email);
        assert!(result
            .threats
            .iter()
            .any(|t| t.threat_type == "password_protected_archive"));
    }

    #[test]
    fn test_macro_enabled_document() {
        let scanner = ContentScanner::new(dummy_pool(), dummy_config());
        let mut email = clean_email();
        email.attachments.push(AttachmentInfo {
            filename: "report.xlsm".into(),
            content_type: "application/vnd.ms-excel.sheet.macroEnabled.12".into(),
            size: 15_000,
            header_bytes: None,
        });
        let result = scanner.analyze_malware(&email);
        assert!(result
            .threats
            .iter()
            .any(|t| t.threat_type == "macro_document"));
    }

    #[test]
    fn test_oversized_attachment() {
        let scanner = ContentScanner::new(dummy_pool(), dummy_config());
        let mut email = clean_email();
        email.attachments.push(AttachmentInfo {
            filename: "large_video.mp4".into(),
            content_type: "video/mp4".into(),
            size: 30_000_000,
            header_bytes: None,
        });
        let result = scanner.analyze_malware(&email);
        assert!(result.threats.iter().any(|t| t.threat_type == "oversized"));
    }

    #[test]
    fn test_clean_attachment() {
        let scanner = ContentScanner::new(dummy_pool(), dummy_config());
        let mut email = clean_email();
        email.attachments.push(AttachmentInfo {
            filename: "photo.jpg".into(),
            content_type: "image/jpeg".into(),
            size: 100_000,
            header_bytes: Some(vec![0xFF, 0xD8, 0xFF, 0xE0]),
        });
        let result = scanner.analyze_malware(&email);
        assert!(result.clean);
    }

    // ── Verdict Tests ───────────────────────────────────────

    #[test]
    fn test_verdict_clean() {
        let spam = SpamAnalysis {
            score: 5.0,
            is_spam: false,
            triggers: vec![],
        };
        let phishing = PhishingAnalysis {
            score: 0.0,
            is_phishing: false,
            indicators: vec![],
        };
        let malware = MalwareAnalysis {
            clean: true,
            threats: vec![],
        };
        let policy = PolicyAnalysis {
            compliant: true,
            violations: vec![],
        };
        assert_eq!(
            determine_verdict(&spam, &phishing, &malware, &policy),
            ScanVerdict::Clean
        );
    }

    #[test]
    fn test_verdict_blocked_phishing() {
        let spam = SpamAnalysis {
            score: 0.0,
            is_spam: false,
            triggers: vec![],
        };
        let phishing = PhishingAnalysis {
            score: 80.0,
            is_phishing: true,
            indicators: vec![],
        };
        let malware = MalwareAnalysis {
            clean: true,
            threats: vec![],
        };
        let policy = PolicyAnalysis {
            compliant: true,
            violations: vec![],
        };
        assert_eq!(
            determine_verdict(&spam, &phishing, &malware, &policy),
            ScanVerdict::Blocked
        );
    }

    #[test]
    fn test_verdict_blocked_malware() {
        let spam = SpamAnalysis {
            score: 0.0,
            is_spam: false,
            triggers: vec![],
        };
        let phishing = PhishingAnalysis {
            score: 0.0,
            is_phishing: false,
            indicators: vec![],
        };
        let malware = MalwareAnalysis {
            clean: false,
            threats: vec![MalwareThreat {
                name: "test".into(),
                threat_type: "test".into(),
                severity: ThreatSeverity::High,
                location: "test.exe".into(),
            }],
        };
        let policy = PolicyAnalysis {
            compliant: true,
            violations: vec![],
        };
        assert_eq!(
            determine_verdict(&spam, &phishing, &malware, &policy),
            ScanVerdict::Blocked
        );
    }

    #[test]
    fn test_verdict_suspicious_spam() {
        let spam = SpamAnalysis {
            score: 60.0,
            is_spam: true,
            triggers: vec![],
        };
        let phishing = PhishingAnalysis {
            score: 0.0,
            is_phishing: false,
            indicators: vec![],
        };
        let malware = MalwareAnalysis {
            clean: true,
            threats: vec![],
        };
        let policy = PolicyAnalysis {
            compliant: true,
            violations: vec![],
        };
        assert_eq!(
            determine_verdict(&spam, &phishing, &malware, &policy),
            ScanVerdict::Suspicious
        );
    }

    #[test]
    fn test_verdict_suspicious_policy() {
        let spam = SpamAnalysis {
            score: 0.0,
            is_spam: false,
            triggers: vec![],
        };
        let phishing = PhishingAnalysis {
            score: 0.0,
            is_phishing: false,
            indicators: vec![],
        };
        let malware = MalwareAnalysis {
            clean: true,
            threats: vec![],
        };
        let policy = PolicyAnalysis {
            compliant: false,
            violations: vec![],
        };
        assert_eq!(
            determine_verdict(&spam, &phishing, &malware, &policy),
            ScanVerdict::Suspicious
        );
    }

    // ── Fast-check optimization ─────────────────────────────

    #[test]
    fn test_fast_check_skips_clean_text() {
        // The combined regex should NOT match on clean text
        let Some(regex) = FAST_SPAM_CHECK.as_ref() else {
            assert!(FAST_SPAM_CHECK.is_some(), "FAST_SPAM_CHECK regex missing");
            return;
        };
        assert!(!regex.is_match("Hello, this is a normal monthly newsletter about technology."));
    }

    #[test]
    fn test_fast_check_matches_spam_text() {
        let Some(regex) = FAST_SPAM_CHECK.as_ref() else {
            assert!(FAST_SPAM_CHECK.is_some(), "FAST_SPAM_CHECK regex missing");
            return;
        };
        assert!(regex.is_match("Congratulations! You are a winner of $1000!"));
    }
}
