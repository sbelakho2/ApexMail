use crate::config::ScoringWeights;
use crate::network_checks::{BimiInfo, MtaStsInfo, TlsRptInfo};
use crate::types::{Finding, FindingSeverity, GradeBreakdown, GradeLetter, ScoreBreakdown};

pub struct GradeCalculator;

impl GradeCalculator {
    /// Calculate the composite score using the default weight distribution.
    #[allow(clippy::too_many_arguments)] // clippy: justified - public scoring API accepts individual score components (dns, auth, spam, content, reputation)
    pub fn calculate(
        dns_health_score: u16,
        dns_health_details: Option<serde_json::Value>,
        auth_score: u16,
        auth_details: Option<serde_json::Value>,
        spam_score: u16,
        content_score: Option<u16>,
        reputation_score: u16,
        reputation_details: Option<serde_json::Value>,
        findings: Vec<Finding>,
    ) -> (u16, GradeLetter, GradeBreakdown, Vec<Finding>, Vec<String>) {
        Self::calculate_with_weights(
            dns_health_score,
            dns_health_details,
            auth_score,
            auth_details,
            spam_score,
            content_score,
            reputation_score,
            reputation_details,
            findings,
            &ScoringWeights::default(),
        )
    }

    /// Calculate the composite score using a tenant-supplied weight set. The
    /// caller is responsible for normalizing weights; this function will also
    /// renormalize defensively.
    #[allow(clippy::too_many_arguments)] // clippy: justified - public scoring API accepts individual score components + custom weights
    pub fn calculate_with_weights(
        dns_health_score: u16,
        dns_health_details: Option<serde_json::Value>,
        auth_score: u16,
        auth_details: Option<serde_json::Value>,
        spam_score: u16,
        content_score: Option<u16>,
        reputation_score: u16,
        reputation_details: Option<serde_json::Value>,
        findings: Vec<Finding>,
        weights: &ScoringWeights,
    ) -> (u16, GradeLetter, GradeBreakdown, Vec<Finding>, Vec<String>) {
        let w = weights.normalized();

        let dns_breakdown = ScoreBreakdown {
            score: dns_health_score,
            max: 100,
            details: dns_health_details,
        };
        let auth_breakdown = ScoreBreakdown {
            score: auth_score,
            max: 100,
            details: auth_details,
        };
        let spam_breakdown = ScoreBreakdown {
            score: spam_score,
            max: 100,
            details: None,
        };
        let content_breakdown = content_score.map(|s| ScoreBreakdown {
            score: s,
            max: 100,
            details: None,
        });
        let rep_breakdown = ScoreBreakdown {
            score: reputation_score,
            max: 100,
            details: reputation_details,
        };

        let mut composite = (dns_health_score as f64 * w.dns_health)
            + (auth_score as f64 * w.authentication)
            + (spam_score as f64 * w.spam_likelihood)
            + (reputation_score as f64 * w.reputation);

        if let Some(cs) = content_score {
            composite += cs as f64 * w.content_quality;
        } else {
            // Redistribute content weight evenly across DNS and auth to
            // preserve a 0..=100 ceiling.
            let half = w.content_quality / 2.0;
            composite += (dns_health_score as f64 * half) + (auth_score as f64 * half);
        }

        let final_score = composite.round().clamp(0.0, 100.0) as u16;
        let grade = GradeLetter::from_score(final_score);

        let recommendations =
            Self::generate_recommendations(&findings, dns_health_score, auth_score, spam_score);

        let breakdown = GradeBreakdown {
            dns_health: dns_breakdown,
            authentication: auth_breakdown,
            spam_likelihood: spam_breakdown,
            content_quality: content_breakdown,
            reputation: rep_breakdown,
        };

        (final_score, grade, breakdown, findings, recommendations)
    }

    fn generate_recommendations(
        findings: &[Finding],
        dns_score: u16,
        auth_score: u16,
        spam_score: u16,
    ) -> Vec<String> {
        let mut recs: Vec<String> = Vec::new();

        if dns_score < 60 {
            recs.push(
                "Configure MX, SPF, DKIM, and DMARC DNS records to improve deliverability".into(),
            );
        } else if dns_score < 80 {
            recs.push(
                "Review DNS records: ensure MX redundancy and correct SPF/DKIM/DMARC configuration"
                    .into(),
            );
        } else {
            recs.push(
                "DNS configuration looks good — maintain regular monitoring of your DNS records"
                    .into(),
            );
        }

        if auth_score < 60 {
            recs.push("Implement email authentication (SPF, DKIM, DMARC) to prevent spoofing and improve inbox placement".into());
        } else if auth_score < 80 {
            recs.push("Strengthen authentication: ensure DMARC policy is set to 'reject' with 100% enforcement".into());
        } else {
            recs.push("Email authentication is well configured — consider adding BIMI and MTA-STS for enhanced security".into());
        }

        if spam_score < 60 {
            recs.push("High spam-likelihood detected — review email content, avoid spam trigger phrases, and maintain good sending practices".into());
        }

        for finding in findings {
            match finding.severity {
                FindingSeverity::Critical | FindingSeverity::Error => {
                    recs.push(format!(
                        "[Action Required] {}: {}",
                        finding.category, finding.message
                    ));
                }
                FindingSeverity::Warning => {
                    recs.push(format!(
                        "[Suggestion] {}: {}",
                        finding.category, finding.message
                    ));
                }
                _ => {}
            }
        }

        recs.sort();
        recs.dedup();
        recs
    }
}

pub fn score_spf(spf_record: Option<&crate::grader::SpfInfo>) -> (u16, serde_json::Value) {
    match spf_record {
        Some(spf) => {
            let mut score = 15u16;
            if spf.hard_fail {
                score += 10;
            }
            if spf.soft_fail {
                score += 5;
            }
            (
                score.min(30),
                serde_json::json!({
                    "exists": true,
                    "hard_fail": spf.hard_fail,
                    "soft_fail": spf.soft_fail,
                    "raw": spf.raw,
                }),
            )
        }
        None => (0, serde_json::json!({"exists": false})),
    }
}

pub fn score_dkim(dkim_keys: &[crate::grader::DkimInfo]) -> (u16, serde_json::Value) {
    if dkim_keys.is_empty() {
        return (0, serde_json::json!({"keys_found": 0, "selectors": []}));
    }
    let mut score = 15u16;
    let mut has_strong = false;
    let mut details: Vec<serde_json::Value> = Vec::new();
    for key in dkim_keys {
        let strong = key.is_ed25519 || key.key_size >= 2048;
        if strong {
            has_strong = true;
        }
        details.push(serde_json::json!({
            "selector": key.selector,
            "key_type": key.key_type,
            "key_size": key.key_size,
            "is_ed25519": key.is_ed25519,
            "strong": strong,
        }));
    }
    if has_strong {
        score = score.saturating_add(5);
    }
    (
        score.min(20),
        serde_json::json!({
            "keys_found": dkim_keys.len(),
            "selectors": dkim_keys.iter().map(|k| k.selector.as_str()).collect::<Vec<_>>(),
            "details": details,
        }),
    )
}

pub fn score_dmarc(dmarc_policy: Option<&crate::grader::DmarcInfo>) -> (u16, serde_json::Value) {
    match dmarc_policy {
        Some(dmarc) => {
            let mut score = 15u16;
            match dmarc.policy.to_lowercase().as_str() {
                "reject" => score += 10,
                "quarantine" => score += 5,
                _ => {}
            }
            if dmarc.pct == 100 {
                score += 5;
            }
            (
                score.min(30),
                serde_json::json!({
                    "exists": true,
                    "policy": dmarc.policy,
                    "pct": dmarc.pct,
                }),
            )
        }
        None => (0, serde_json::json!({"exists": false})),
    }
}

pub fn score_mx(mx_records: &[crate::grader::MxInfo]) -> (u16, serde_json::Value) {
    let priorities: Vec<u16> = mx_records.iter().map(|m| m.priority).collect();
    let mut score = 0u16;
    if !mx_records.is_empty() {
        score += 25;
    }
    if mx_records.len() >= 2 {
        score += 10;
    }
    if priorities.iter().any(|&p| p <= 10) {
        score += 15;
    }
    (
        score.min(50),
        serde_json::json!({
            "count": mx_records.len(),
            "priorities": priorities,
        }),
    )
}

pub fn score_dns_health(
    mx_records: &[crate::grader::MxInfo],
    spf_record: Option<&crate::grader::SpfInfo>,
    dkim_keys: &[crate::grader::DkimInfo],
    dmarc_policy: Option<&crate::grader::DmarcInfo>,
    has_a_record: bool,
) -> (u16, serde_json::Value) {
    let (mx_score, mx_details) = score_mx(mx_records);
    let mut dns_score = mx_score;
    if spf_record.is_some() {
        dns_score += 15;
    }
    if !dkim_keys.is_empty() {
        dns_score += 15;
    }
    if dmarc_policy.is_some() {
        dns_score += 10;
    }
    if mx_records.is_empty() && has_a_record {
        dns_score += 10;
    }
    let details = serde_json::json!({
        "mx": mx_details,
        "spf_record": spf_record.is_some(),
        "dkim_record": !dkim_keys.is_empty(),
        "dmarc_record": dmarc_policy.is_some(),
    });
    (dns_score.min(100), details)
}

/// Score modern transport-security signals (BIMI / MTA-STS / TLS-RPT).
/// Returns `(score 0..=20, details)`. Folded into the auth dimension so the
/// composite score reflects readiness for modern receiver expectations.
pub fn score_modern_security(
    bimi: Option<&BimiInfo>,
    mta_sts: Option<&MtaStsInfo>,
    tls_rpt: Option<&TlsRptInfo>,
) -> (u16, serde_json::Value) {
    let mut score: u16 = 0;
    if let Some(m) = mta_sts {
        score += match m.mode.as_str() {
            "enforce" => 10,
            "testing" => 5,
            _ => 0,
        };
    }
    if tls_rpt.is_some() {
        score += 5;
    }
    if bimi.is_some() {
        score += 5;
    }
    let details = serde_json::json!({
        "bimi": bimi.map(|b| serde_json::json!({
            "logo_url": b.logo_url,
            "vmc_url": b.vmc_url,
        })),
        "mta_sts": mta_sts.map(|m| serde_json::json!({
            "policy_id": m.policy_id,
            "mode": m.mode,
            "max_age_seconds": m.max_age_seconds,
            "mx_pattern_count": m.mx_patterns.len(),
        })),
        "tls_rpt": tls_rpt.map(|t| serde_json::json!({
            "rua_count": t.rua.len(),
        })),
    });
    (score.min(20), details)
}

pub fn score_reputation(
    blocklist_count: usize,
    highest_confidence: &str,
) -> (u16, serde_json::Value) {
    let score = if blocklist_count == 0 {
        100
    } else if blocklist_count == 1 && highest_confidence == "low" {
        60
    } else if blocklist_count >= 1 {
        20
    } else {
        0
    };
    (
        score,
        serde_json::json!({
            "blocklists": blocklist_count,
            "highest_confidence": highest_confidence,
        }),
    )
}

pub fn invert_spam_score(spam_score: f64) -> u16 {
    let clamped = spam_score.clamp(0.0, 1.0);
    ((1.0 - clamped) * 100.0).round() as u16
}

pub fn invert_content_score(penalty: f64) -> u16 {
    let score = 100.0 - (penalty * 3.33);
    score.max(0.0).round() as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grader::DkimInfo;

    #[test]
    fn ed25519_dkim_treated_as_strong_regardless_of_size() {
        let keys = vec![DkimInfo {
            selector: "s1".into(),
            key_type: "ed25519".into(),
            key_size: 256,
            is_ed25519: true,
        }];
        let (score, _details) = score_dkim(&keys);
        assert_eq!(score, 20, "Ed25519 should reach the DKIM ceiling");
    }

    #[test]
    fn rsa_2048_treated_as_strong() {
        let keys = vec![DkimInfo {
            selector: "s1".into(),
            key_type: "rsa".into(),
            key_size: 2048,
            is_ed25519: false,
        }];
        let (score, _) = score_dkim(&keys);
        assert_eq!(score, 20);
    }

    #[test]
    fn rsa_1024_does_not_get_strong_bonus() {
        let keys = vec![DkimInfo {
            selector: "s1".into(),
            key_type: "rsa".into(),
            key_size: 1024,
            is_ed25519: false,
        }];
        let (score, _) = score_dkim(&keys);
        assert_eq!(score, 15);
    }

    #[test]
    fn modern_security_full_marks() {
        let bimi = BimiInfo {
            raw: "v=BIMI1".into(),
            logo_url: Some("https://x/logo".into()),
            vmc_url: None,
        };
        let mta = MtaStsInfo {
            policy_id: "abc".into(),
            mode: "enforce".into(),
            max_age_seconds: 86400,
            mx_patterns: vec![],
        };
        let tls = TlsRptInfo {
            raw: "v=TLSRPTv1".into(),
            rua: vec!["mailto:t@e".into()],
        };
        let (score, _) = score_modern_security(Some(&bimi), Some(&mta), Some(&tls));
        assert_eq!(score, 20);
    }

    #[test]
    fn modern_security_zero_when_absent() {
        let (score, _) = score_modern_security(None, None, None);
        assert_eq!(score, 0);
    }

    #[test]
    fn weights_renormalize_when_unbalanced() {
        let w = ScoringWeights {
            dns_health: 2.0,
            authentication: 2.0,
            spam_likelihood: 2.0,
            content_quality: 2.0,
            reputation: 2.0,
        };
        let (score, grade, _, _, _) = GradeCalculator::calculate_with_weights(
            100,
            None,
            100,
            None,
            100,
            Some(100),
            100,
            None,
            vec![],
            &w,
        );
        assert_eq!(score, 100);
        assert_eq!(grade.to_string(), "A+");
    }
}
