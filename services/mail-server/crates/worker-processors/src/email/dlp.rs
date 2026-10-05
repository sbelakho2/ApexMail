//! Worker PRE-SEND DLP gate — the enforcement point that makes the
//! marketing/compliance "advertised data-loss prevention" claim TRUE.
//!
//! ## Enforcement point
//!
//! The WORKER owns admission/settlement for every outbound send: it claims
//! queue rows, reserves admission, and only then submits to the transport.
//! The gate therefore runs inside
//! [`EmailProcessor::process_job_inner`](super::processor::EmailProcessor)
//! on the fully PREPARED per-recipient copy (`PreparedEmail`: subject, text
//! body, HTML body stripped to text, and the decoded attachment bytes) and
//! BEFORE the durable acceptance reservation (`claim_acceptance`) — so a
//! refusal or hold can never strand a `reserved` ledger row and can never
//! follow an SMTP effect.
//!
//! ## Action mapping (engine severity → queue effect)
//!
//! The dlp-engine emits one of four actions per scan. They map onto the
//! `email_queue` status model (the CHECK constraint admits exactly
//! pending/processing/sent/failed/deferred/cancelled/bounced/suppressed —
//! migration 088; there is no `held` status and adding one is a schema
//! change outside this crate):
//!
//! | engine action | severity | worker effect |
//! |---------------|----------|---------------|
//! | `Allow`       | clean    | deliver, untouched |
//! | `Audit`       | low      | allow + loud structured log (findings retained) |
//! | `Quarantine`  | medium   | HOLD: row → `deferred` + `metadata.dlp` annotation + audit row. `deferred` rows are never re-claimed by the poller, so the message stays in the queue, visible and unsent, pending operator review. The hold applies to the MESSAGE (all per-recipient copies share the content). |
//! | `Block`       | high     | REFUSE: per-recipient terminal `bounced` (the typed DSN surface this pipeline has — the same shape `handle_hard_bounce` gives a transport 5xx) with honest sender-visible copy naming the rule classes, plus an audit row and a `bounced` recipient event. No suppression (a policy refusal proves nothing about the mailbox) and no sales sender-health feedback (a self-inflicted policy refusal is not a reputation bounce). |
//!
//! Per-tenant override: there is no cheap tenant-scoped DLP settings surface
//! (no per-tenant policy table exists; adding one is a migration outside this
//! crate's ownership). Enforcement is GLOBAL, gated by `WORKER_DLP_ENABLED`
//! (default OFF so dev deployments keep byte-identical behavior; compose/
//! prod set it explicitly).
//!
//! ## Fail-open / fail-closed semantics
//!
//! * ENGINE ERROR (the scanner cannot produce a verdict) → FAIL OPEN: the
//!   message is delivered and the failure is loud (error-level log + metric).
//!   Legitimate mail must never be held hostage by a broken scanner.
//! * DETECTION (the scanner produced a verdict) → FAIL CLOSED per the
//!   action mapping above. A hold/refusal also writes an `audit_logs` row
//!   naming the rule class in the same transaction as the queue-row write —
//!   a refusal or hold can never be a silent drop.

use super::types::PreparedEmail;
use dlp_engine::attachment::AttachmentVerdict;
use dlp_engine::engine::{DlpAction, DlpEngine, DlpVerdict};
use dlp_engine::pii::PiiType;
use scraper::Html;

/// The DLP engine could not produce a verdict. The gate FAILS OPEN on this.
#[derive(Debug, Clone)]
pub struct DlpGateError(pub String);

impl std::fmt::Display for DlpGateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DLP engine error: {}", self.0)
    }
}

impl std::error::Error for DlpGateError {}

/// One pre-send scan's combined verdict (body + attachments, worst action wins).
#[derive(Debug, Clone)]
pub struct PreSendVerdict {
    /// The WORST action across all scanned channels (Block > Quarantine >
    /// Audit > Allow): the conservative combination — one high-severity
    /// channel must not be averaged away by clean siblings.
    pub action: DlpAction,
    /// Highest risk score seen across channels (annotation/audit evidence).
    pub risk_score: f64,
    /// Stable rule-class identifiers named by the audit row and the
    /// sender-visible refusal copy (e.g. `pii:ssn`, `policy:confidential`,
    /// `secret:high_entropy_token`).
    pub rule_classes: Vec<String>,
    /// The engine's own (redacted) finding summary for the audit trail.
    pub summary: String,
}

/// The scanner seam the email processor depends on (the same pattern the
/// transport layer uses with `EmailTransport`). Production wires
/// [`EngineDlpScanner`]; tests inject doubles — including an always-failing
/// one that proves the gate fails OPEN on engine errors.
pub trait PreSendDlpScanner: Send + Sync {
    /// Scan one fully prepared outbound copy. `Err` = engine unavailable
    /// (fail-open in the caller); `Ok` = an enforceable verdict.
    fn scan_prepared(&self, email: &PreparedEmail) -> Result<PreSendVerdict, DlpGateError>;
}

/// The production scanner: a `dlp_engine::DlpEngine` with the canonical
/// default policy (PII + secrets + confidentiality keywords, 5.0 quarantine /
/// 10.0 block thresholds).
pub struct EngineDlpScanner {
    engine: DlpEngine,
}

impl EngineDlpScanner {
    /// Build the production scanner with the engine's default policy.
    pub fn new() -> Self {
        Self {
            engine: DlpEngine::with_config(dlp_engine::config::DlpConfig::default()),
        }
    }
}

impl Default for EngineDlpScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl PreSendDlpScanner for EngineDlpScanner {
    fn scan_prepared(&self, email: &PreparedEmail) -> Result<PreSendVerdict, DlpGateError> {
        // The engine's allowlist / trusted-domain / temporary-exception
        // machinery keys on the RECIPIENT domain, so it is threaded through
        // to every channel scan.
        let recipient_domain = recipient_domain_of(&email.to);

        // Channel 1: subject + text body + HTML stripped to text + attachment
        // filenames, newline-joined so patterns cannot splice across seams.
        let mut corpus = String::with_capacity(1024);
        corpus.push_str(&email.subject);
        corpus.push('\n');
        if let Some(text) = &email.text {
            corpus.push_str(text);
            corpus.push('\n');
        }
        if let Some(html) = &email.html {
            corpus.push_str(&html_to_text(html));
            corpus.push('\n');
        }
        for attachment in &email.attachments {
            corpus.push_str(&attachment.filename);
            corpus.push('\n');
        }
        let body = self.engine.scan(&corpus, recipient_domain.as_deref());

        // Channel 2..N: every decoded attachment, content-scanned with the
        // engine's format-aware extractor (plaintext/BOM, OOXML, PDF, RTF,
        // best-effort binary).
        let attachments: Vec<AttachmentVerdict> = email
            .attachments
            .iter()
            .map(|attachment| {
                self.engine.scan_attachment(
                    &attachment.content,
                    Some(&attachment.filename),
                    recipient_domain.as_deref(),
                )
            })
            .collect();

        Ok(combine(body, attachments))
    }
}

/// Recipient domain of an envelope address (the engine canonicalizes both
/// sides; a domainless address simply gets no domain context).
fn recipient_domain_of(recipient: &str) -> Option<String> {
    recipient
        .rsplit_once('@')
        .map(|(_, domain)| domain.trim().trim_end_matches('.').to_string())
        .filter(|domain| !domain.is_empty())
}

/// Strip an HTML body to its text content (entities decoded by the parser).
/// Every text node lands on its own line so a tag boundary can never splice
/// two innocuous fragments into a sensitive pattern.
pub(crate) fn html_to_text(html: &str) -> String {
    let document = Html::parse_document(html);
    let mut text = String::with_capacity(html.len() / 2);
    for node in document.tree.nodes() {
        if let Some(value) = node.value().as_text() {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                text.push_str(trimmed);
                text.push('\n');
            }
        }
    }
    text
}

/// Stable rule-class identifiers for every finding in a verdict.
pub(crate) fn rule_classes_of(verdict: &DlpVerdict) -> Vec<String> {
    let mut classes: Vec<String> = Vec::new();
    for finding in &verdict.pii_findings {
        let slug = match finding.pii_type {
            PiiType::CreditCard => "credit_card",
            PiiType::Ssn => "ssn",
            PiiType::PhoneNumber => "phone_number",
            PiiType::EmailAddress => "email_address",
        };
        classes.push(format!("pii:{slug}"));
    }
    if !verdict.entropy_findings.is_empty() {
        classes.push("secret:high_entropy_token".to_string());
    }
    for policy in &verdict.policy_matches {
        classes.push(format!(
            "policy:{}",
            policy.keyword.to_lowercase().replace(' ', "_")
        ));
    }
    classes.sort();
    classes.dedup();
    classes
}

/// Rank actions worst-first so the combination takes the MOST severe.
fn severity_rank(action: DlpAction) -> u8 {
    match action {
        DlpAction::Allow => 0,
        DlpAction::Audit => 1,
        DlpAction::Quarantine => 2,
        DlpAction::Block => 3,
    }
}

/// Combine the body verdict with every attachment verdict: worst action,
/// highest risk, union of rule classes, joined summaries.
pub(crate) fn combine(body: DlpVerdict, attachments: Vec<AttachmentVerdict>) -> PreSendVerdict {
    let mut channels: Vec<&DlpVerdict> = vec![&body];
    channels.extend(attachments.iter().map(|a| &a.dlp_verdict));

    let mut worst: &DlpVerdict = &body;
    for channel in &channels {
        if severity_rank(channel.action) > severity_rank(worst.action) {
            worst = channel;
        }
    }

    let mut rule_classes: Vec<String> = Vec::new();
    let mut risk_score = 0.0_f64;
    let mut summaries: Vec<String> = Vec::new();
    for channel in &channels {
        rule_classes.extend(rule_classes_of(channel));
        risk_score = risk_score.max(channel.risk_score);
        if channel.risk_score > 0.0 && !channel.summary.is_empty() {
            summaries.push(channel.summary.clone());
        }
    }
    rule_classes.sort();
    rule_classes.dedup();

    PreSendVerdict {
        action: worst.action,
        risk_score,
        rule_classes,
        summary: summaries.join(" | "),
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::Attachment;
    use super::*;

    /// A deterministic PreparedEmail builder for the scanner unit tests.
    fn prepared(subject: &str, text: Option<&str>, html: Option<&str>) -> PreparedEmail {
        PreparedEmail {
            send_unit: "email_queue:dlp-test:r@example.test".into(),
            from: "s@example.test".into(),
            from_name: None,
            ses_configuration_set: None,
            to: "r@example.test".into(),
            mime_to: vec![],
            mime_cc: vec![],
            reply_to: None,
            subject: subject.into(),
            html: html.map(str::to_string),
            text: text.map(str::to_string),
            headers: vec![],
            attachments: vec![],
            dkim: None,
            verp: None,
        }
    }

    #[test]
    fn clean_copy_scans_allow() {
        let scanner = EngineDlpScanner::new();
        let verdict = scanner
            .scan_prepared(&prepared(
                "Your September statement",
                Some("Hello, your monthly summary is ready. Regards, the team."),
                None,
            ))
            .expect("engine is infallible");
        assert_eq!(verdict.action, DlpAction::Allow);
        assert!(verdict.rule_classes.is_empty());
    }

    /// The HTML body is stripped to text before scanning: PII hidden behind
    /// tags (invisible in a plain-text reader, but very much present in the
    /// MIME part that leaves) must be detected.
    #[test]
    fn html_hidden_card_is_detected_after_stripping() {
        let scanner = EngineDlpScanner::new();
        let verdict = scanner
            .scan_prepared(&prepared(
                "Receipt",
                None,
                Some("<p>Thanks for your order.</p><div>Card 4111 1111 1111 1111 charged.</div>"),
            ))
            .expect("engine is infallible");
        assert_eq!(
            verdict.action,
            DlpAction::Quarantine,
            "a Luhn-valid card (risk 8.0 >= quarantine threshold 5.0) hidden in HTML must still be found"
        );
        assert!(verdict
            .rule_classes
            .contains(&"pii:credit_card".to_string()));
    }

    /// The subject line is part of the scanned corpus.
    #[test]
    fn subject_is_scanned() {
        let scanner = EngineDlpScanner::new();
        let verdict = scanner
            .scan_prepared(&prepared(
                "Employee SSN: 123-45-6789 and card 4111 1111 1111 1111",
                Some("Payroll details attached below."),
                None,
            ))
            .expect("engine is infallible");
        assert_eq!(verdict.action, DlpAction::Block);
        assert!(verdict.rule_classes.contains(&"pii:ssn".to_string()));
        assert!(verdict
            .rule_classes
            .contains(&"pii:credit_card".to_string()));
    }

    /// Decoded attachment CONTENT is scanned (the processor hands the gate
    /// the decoded bytes), and the filename rides the body corpus.
    #[test]
    fn attachment_content_and_filename_are_scanned() {
        let scanner = EngineDlpScanner::new();
        let mut email = prepared("Report", Some("See attachment."), None);
        email.attachments.push(Attachment {
            filename: "payroll.txt".into(),
            content: b"SSN: 123-45-6789 card 4111 1111 1111 1111".to_vec(),
            content_type: "text/plain".into(),
        });
        let verdict = scanner.scan_prepared(&email).expect("engine is infallible");
        assert_eq!(
            verdict.action,
            DlpAction::Block,
            "attachment content must reach the verdict"
        );
        assert!(verdict.rule_classes.contains(&"pii:ssn".to_string()));
    }

    /// Low severity (a bare phone number, risk 1.5 < 5.0) stays below every
    /// enforcement rung: the send is allowed and only logged.
    #[test]
    fn low_severity_finding_maps_to_audit_not_enforcement() {
        let scanner = EngineDlpScanner::new();
        let verdict = scanner
            .scan_prepared(&prepared(
                "Welcome",
                Some("Reach us on 555-123-4567 any time."),
                None,
            ))
            .expect("engine is infallible");
        assert_eq!(verdict.action, DlpAction::Audit);
        assert!(verdict
            .rule_classes
            .contains(&"pii:phone_number".to_string()));
    }

    /// The combined verdict takes the WORST channel: a clean body cannot
    /// launder a held attachment.
    #[test]
    fn combine_takes_the_worst_channel() {
        let scanner = EngineDlpScanner::new();
        let body = scanner.engine.scan("perfectly clean prose", None);
        let attachment_scan =
            scanner
                .engine
                .scan_attachment(b"ssn_column\n123-45-6789", Some("data.csv"), None);
        let combined = combine(body, vec![attachment_scan]);
        assert_eq!(combined.action, DlpAction::Quarantine);
        assert!(combined.rule_classes.contains(&"pii:ssn".to_string()));
        assert!(
            combined.summary.contains("SSN"),
            "the engine's redacted summary must carry into the audit evidence: {}",
            combined.summary
        );
    }

    /// `html_to_text` decodes entities and never lets two nodes splice.
    #[test]
    fn html_to_text_strips_tags_and_decodes_entities() {
        let text = html_to_text("<p>Hello &amp; welcome</p><style>x{}</style><b>world</b>");
        assert!(text.contains("Hello & welcome"), "entities decoded: {text}");
        assert!(text.contains("world"));
        assert!(!text.contains('<'), "tags stripped: {text}");
    }

    /// Domainless recipient: the gate still scans (no domain context).
    #[test]
    fn recipient_domain_extraction_is_safe() {
        assert_eq!(
            recipient_domain_of("user@Recipient.Example.COM").as_deref(),
            Some("Recipient.Example.COM")
        );
        assert_eq!(recipient_domain_of("not-an-address"), None);
    }

    /// `Default` must be exactly the production constructor (same policy).
    #[test]
    fn default_scanner_is_the_production_scanner() {
        let scanner = EngineDlpScanner::default();
        let verdict = scanner
            .scan_prepared(&prepared(
                "Monthly note",
                Some("Nothing sensitive here, just a note."),
                None,
            ))
            .expect("engine is infallible");
        assert_eq!(verdict.action, DlpAction::Allow);
        assert!(verdict.rule_classes.is_empty());
    }

    /// Every `PiiType` slugs to a stable rule class — including
    /// `EmailAddress`, which the DEFAULT production policy never emits
    /// (`detect_email_addresses` is false) but a configured policy can,
    /// so the audit trail must still name it.
    #[test]
    fn rule_classes_slug_every_pii_type() {
        let verdict = DlpVerdict {
            risk_score: 2.0,
            action: DlpAction::Audit,
            pii_findings: vec![dlp_engine::pii::PiiMatch {
                pii_type: PiiType::EmailAddress,
                redacted: "xxx@xxx.xxx".into(),
                risk: 2.0,
                base_risk: 2.0,
                offset: 0,
                context_modifier: None,
            }],
            entropy_findings: vec![],
            policy_matches: vec![],
            summary: String::new(),
        };
        assert_eq!(rule_classes_of(&verdict), vec!["pii:email_address"]);
    }

    /// High-entropy tokens and content-policy keyword hits slug to their
    /// own rule classes (the multi-word keyword slug keeps its underscore).
    #[test]
    fn entropy_and_policy_findings_slug_to_rule_classes() {
        let scanner = EngineDlpScanner::new();
        // 28 distinct mixed-case alphanumeric characters: Shannon entropy
        // ~4.8 >= the 4.5 default threshold, base64-shaped per the
        // engine's looks_like_secret heuristic.
        let verdict = scanner.engine.scan(
            "INTERNAL ONLY — bearer Zk9mQ2vR7tL4pW8xYbN3cJ5fD6hG — confidential payroll",
            None,
        );
        assert!(
            !verdict.entropy_findings.is_empty(),
            "the token must trip the entropy scanner: {:?}",
            verdict.summary
        );
        assert!(
            !verdict.policy_matches.is_empty(),
            "the keywords must trip the content policy: {:?}",
            verdict.summary
        );
        let classes = rule_classes_of(&verdict);
        assert!(
            classes.contains(&"secret:high_entropy_token".to_string()),
            "{classes:?}"
        );
        assert!(
            classes.contains(&"policy:internal_only".to_string()),
            "multi-word keyword slugs lowercase and underscore: {classes:?}"
        );
        assert!(
            classes.contains(&"policy:confidential".to_string()),
            "{classes:?}"
        );
    }
}
