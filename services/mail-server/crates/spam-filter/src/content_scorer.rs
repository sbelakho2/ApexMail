//! Content scoring via pattern-based analysis
//!
//! Uses Aho-Corasick multi-pattern matching to detect:
//! - Spam phrases (urgency, financial lures, pharma)
//! - Obfuscation patterns (zero-width characters, homoglyphs)
//! - Suspicious formatting (ALL CAPS ratio, HTML-to-text ratio)

use aho_corasick::AhoCorasick;
use std::sync::OnceLock;

/// Result of content scoring
#[derive(Debug, Clone)]
pub struct ContentScore {
    /// Total penalty from content analysis
    pub score: f64,
    /// Individual content findings
    pub findings: Vec<ContentFinding>,
}

/// A single content finding
#[derive(Debug, Clone)]
pub struct ContentFinding {
    /// Finding identifier
    pub id: &'static str,
    /// Description
    pub description: String,
    /// Penalty
    pub penalty: f64,
}

/// Spam phrase categories with per-match penalty
struct SpamPhraseSet {
    automaton: AhoCorasick,
    penalties: Vec<f64>,
    ids: Vec<&'static str>,
    descriptions: Vec<&'static str>,
}

fn spam_phrase_set() -> &'static SpamPhraseSet {
    static INSTANCE: OnceLock<SpamPhraseSet> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        let patterns: Vec<(&str, f64, &str, &str)> = vec![
            // Urgency / pressure
            ("act now", 1.5, "URGENCY_ACT_NOW", "Urgency phrase: act now"),
            ("limited time", 1.5, "URGENCY_LIMITED_TIME", "Urgency phrase: limited time"),
            ("expire", 1.0, "URGENCY_EXPIRE", "Urgency: expiration"),
            ("immediate action", 2.0, "URGENCY_IMMEDIATE", "Urgency: immediate action required"),
            ("urgent", 1.5, "URGENCY_GENERIC", "Urgency: urgent"),
            ("don't delay", 1.5, "URGENCY_DELAY", "Urgency: don't delay"),
            // Financial lures
            ("you have won", 3.0, "FINANCIAL_WON", "Financial lure: you have won"),
            ("congratulations", 1.0, "FINANCIAL_CONGRATS", "Financial lure: congratulations"),
            ("million dollars", 3.0, "FINANCIAL_MILLION", "Financial lure: million dollars"),
            ("wire transfer", 2.0, "FINANCIAL_WIRE", "Financial: wire transfer"),
            ("nigerian prince", 5.0, "FINANCIAL_419", "419 scam indicator"),
            ("inheritance", 2.0, "FINANCIAL_INHERIT", "Financial lure: inheritance"),
            ("lottery", 2.5, "FINANCIAL_LOTTERY", "Financial lure: lottery"),
            ("free money", 3.0, "FINANCIAL_FREE", "Financial lure: free money"),
            // Pharma spam
            ("viagra", 2.0, "PHARMA_VIAGRA", "Pharma spam: viagra"),
            ("cialis", 2.0, "PHARMA_CIALIS", "Pharma spam: cialis"),
            ("pharmacy", 1.0, "PHARMA_GENERIC", "Pharma spam indicator"),
            ("weight loss", 1.5, "PHARMA_WEIGHT", "Pharma: weight loss"),
            ("diet pill", 2.0, "PHARMA_DIET", "Pharma: diet pill"),
            // Credential phishing
            ("verify your account", 2.5, "PHISH_VERIFY", "Phishing: verify your account"),
            ("confirm your identity", 2.5, "PHISH_CONFIRM", "Phishing: confirm identity"),
            ("click here to login", 2.5, "PHISH_LOGIN", "Phishing: click here to login"),
            ("update your payment", 2.5, "PHISH_PAYMENT", "Phishing: update payment"),
            ("suspended", 1.5, "PHISH_SUSPENDED", "Phishing: account suspended"),
            // Unsubscribe tricks
            ("click below to unsubscribe", 0.5, "UNSUB_BELOW", "Suspicious unsubscribe"),
            ("to stop receiving", 0.3, "UNSUB_STOP", "Generic unsubscribe language"),
        ];

        let (pats, penalties, ids, descs): (Vec<_>, Vec<_>, Vec<_>, Vec<_>) = patterns
            .into_iter()
            .map(|(p, pen, id, desc)| (p, pen, id, desc))
            .multiunzip();

        SpamPhraseSet {
            automaton: AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&pats)
                .expect("valid patterns"),
            penalties,
            ids,
            descriptions: descs,
        }
    })
}

trait MultiUnzip {
    type Output;
    fn multiunzip(self) -> Self::Output;
}

impl<I, A, B, C, D> MultiUnzip for I
where
    I: Iterator<Item = (A, B, C, D)>,
{
    type Output = (Vec<A>, Vec<B>, Vec<C>, Vec<D>);
    fn multiunzip(self) -> Self::Output {
        let mut va = Vec::new();
        let mut vb = Vec::new();
        let mut vc = Vec::new();
        let mut vd = Vec::new();
        for (a, b, c, d) in self {
            va.push(a);
            vb.push(b);
            vc.push(c);
            vd.push(d);
        }
        (va, vb, vc, vd)
    }
}

/// Analyze message content (body text) for spam indicators
pub fn score_content(body: &str) -> ContentScore {
    let mut findings = Vec::new();

    // 1. Aho-Corasick phrase matching
    let phrases = spam_phrase_set();
    // Deduplicate pattern matches (count each pattern once)
    let mut matched = vec![false; phrases.ids.len()];
    for mat in phrases.automaton.find_iter(body) {
        let idx = mat.pattern().as_usize();
        if !matched[idx] {
            matched[idx] = true;
            findings.push(ContentFinding {
                id: phrases.ids[idx],
                description: phrases.descriptions[idx].to_string(),
                penalty: phrases.penalties[idx],
            });
        }
    }

    // 2. ALL-CAPS ratio
    let alpha_chars: Vec<char> = body.chars().filter(|c| c.is_alphabetic()).collect();
    if alpha_chars.len() > 20 {
        let upper_count = alpha_chars.iter().filter(|c| c.is_uppercase()).count();
        let ratio = upper_count as f64 / alpha_chars.len() as f64;
        if ratio > 0.7 {
            findings.push(ContentFinding {
                id: "CAPS_HEAVY",
                description: format!("High uppercase ratio: {:.0}%", ratio * 100.0),
                penalty: 2.0,
            });
        } else if ratio > 0.5 {
            findings.push(ContentFinding {
                id: "CAPS_MODERATE",
                description: format!("Moderate uppercase ratio: {:.0}%", ratio * 100.0),
                penalty: 1.0,
            });
        }
    }

    // 3. Excessive exclamation marks
    let exclamation_count = body.chars().filter(|c| *c == '!').count();
    if exclamation_count > 5 {
        let penalty = (exclamation_count as f64 * 0.2).min(3.0);
        findings.push(ContentFinding {
            id: "EXCESSIVE_EXCLAMATION",
            description: format!("{} exclamation marks", exclamation_count),
            penalty,
        });
    }

    // 4. Zero-width / invisible character obfuscation
    let invisible_count = body.chars().filter(|c| {
        matches!(*c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{00AD}')
    }).count();
    if invisible_count > 0 {
        findings.push(ContentFinding {
            id: "INVISIBLE_CHARS",
            description: format!("{} invisible/zero-width characters detected", invisible_count),
            penalty: (invisible_count as f64 * 0.5).min(5.0),
        });
    }

    // 5. HTML heavy (img tags, excessive links)
    let img_count = body.to_lowercase().matches("<img").count();
    if img_count > 3 {
        findings.push(ContentFinding {
            id: "EXCESSIVE_IMAGES",
            description: format!("{} embedded images", img_count),
            penalty: 1.5,
        });
    }
    let link_count = body.to_lowercase().matches("<a ").count()
        + body.to_lowercase().matches("<a\t").count();
    if link_count > 10 {
        findings.push(ContentFinding {
            id: "EXCESSIVE_LINKS",
            description: format!("{} links in message", link_count),
            penalty: 2.0,
        });
    }

    // 6. Very short body (often spam/phish with just a link)
    let text_len = body.trim().len();
    if text_len > 0 && text_len < 20 {
        findings.push(ContentFinding {
            id: "VERY_SHORT_BODY",
            description: "Message body is very short".into(),
            penalty: 1.0,
        });
    }

    let total_score: f64 = findings.iter().map(|f| f.penalty).sum();
    ContentScore {
        score: total_score,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spam_phrase_detection() {
        let body = "Congratulations! You have won a million dollars! Act now to claim your prize!";
        let result = score_content(body);
        assert!(result.findings.iter().any(|f| f.id == "FINANCIAL_WON"));
        assert!(result.findings.iter().any(|f| f.id == "FINANCIAL_MILLION"));
        assert!(result.findings.iter().any(|f| f.id == "URGENCY_ACT_NOW"));
        assert!(result.score > 5.0);
    }

    #[test]
    fn test_all_caps() {
        let body = "THIS IS A COMPLETELY UPPERCASE MESSAGE WITH LOTS OF SHOUTING";
        let result = score_content(body);
        assert!(result.findings.iter().any(|f| f.id == "CAPS_HEAVY"));
    }

    #[test]
    fn test_invisible_characters() {
        let body = "Hello\u{200B}World\u{200C}Test\u{200D}Check";
        let result = score_content(body);
        assert!(result.findings.iter().any(|f| f.id == "INVISIBLE_CHARS"));
    }

    #[test]
    fn test_clean_content() {
        let body = "Hi John, just wanted to follow up on our meeting from Tuesday. \
                     Could you send me the quarterly report when you get a chance? Thanks, Alice.";
        let result = score_content(body);
        assert!(result.score < 1.0, "Clean email scored {}", result.score);
    }

    #[test]
    fn test_phishing_content() {
        let body = "Your account has been suspended. Please verify your account \
                     immediately. Click here to login. Update your payment information.";
        let result = score_content(body);
        assert!(result.findings.iter().any(|f| f.id == "PHISH_VERIFY"));
        assert!(result.findings.iter().any(|f| f.id == "PHISH_LOGIN"));
        assert!(result.score > 4.0);
    }
}
