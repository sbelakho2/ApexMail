//! Deterministic reply classification — layer 1 of 3.
//!
//! This layer only decides what is provable from syntax and headers: delivery
//! status notifications, auto-reply headers, one-click unsubscribe headers and
//! explicit stop/remove requests. It never guesses semantics; everything it
//! cannot prove is left to [`super::ai`].
//!
//! Every verdict carries [`Evidence`] naming the exact header (name + value)
//! or the exact matched token, so a verdict can be audited and replayed
//! without the original message.
//!
//! # ReDoS / hostile input
//!
//! All input is capped at [`MAX_CLASSIFIER_INPUT_BYTES`] with a char-boundary
//! safe truncation before any scanning. The stop-token scan is a literal
//! substring search (no regex, no backtracking); the few bounded regexes used
//! for DSN status codes and return dates are compiled once and only run
//! against the capped text.

use std::sync::LazyLock;

use chrono::{DateTime, Duration, NaiveDate, Utc};
use regex::Regex;
use tracing::warn;

use super::types::{Evidence, ReplyDisposition, ReplyInput};

/// Maximum combined (subject + body) input size for the classifier (O-16.11).
/// Prevents ReDoS attacks via pathological inputs > 100 KB.
pub const MAX_CLASSIFIER_INPUT_BYTES: usize = 1024 * 100; // 100 KB

/// Default wait for an out-of-office reply with no parseable return date.
pub const DEFAULT_OOO_WAIT_DAYS: i64 = 7;

/// Explicit stop / remove / opt-out requests, in the languages the product
/// supports. These are unambiguous: a human writing one of these is asking
/// for no further email, so they short-circuit every semantic model.
///
/// Keep every entry lowercase; matching is done on a lowercased haystack.
pub const STOP_REQUEST_TOKENS: &[&str] = &[
    // English
    "unsubscribe",
    "remove me",
    "remove my email",
    "remove my address",
    "take me off",
    "stop emailing",
    "stop contacting me",
    "stop sending me",
    "opt out",
    "opt-out",
    "do not email",
    "do not contact",
    "don't email",
    "don't contact",
    // German
    "abbestellen",
    "abmelden",
    "austragen",
    "bitte entfernen",
    "bitte löschen",
    "keine e-mails mehr",
    "nicht mehr kontaktieren",
    "widerspruch",
    // French
    "désabonner",
    "désabonnez",
    "désinscrire",
    "désinscription",
    "désabonnement",
    "ne plus me contacter",
    "supprimez-moi",
    "retirez-moi",
    // Dutch
    "afmelden",
    "uitschrijven",
    "verwijder mij",
    "niet meer contacteren",
    "geen e-mails meer",
    "geen mails meer",
    // Spanish
    "darse de baja",
    "dar de baja",
    "cancelar suscripción",
    "cancelar suscripcion",
    "elimíneme",
    "elimineme",
    "no me contacten",
    "dejar de enviar",
    "no enviar más correos",
];

/// Subject conventions that mark an autoreply even without an auto-reply
/// header. Matched case-insensitively against the subject only.
pub const OOO_SUBJECT_TOKENS: &[&str] = &[
    "out of office",
    "out of the office",
    "automatic reply",
    "automatic response",
    "auto-reply",
    "auto reply",
    "autoreply",
    "autoreply:",
    "away from the office",
    "away from my desk",
    "annual leave",
    "maternity leave",
    "paternity leave",
    "abwesenheit",
    "abwesend",
    "absence du bureau",
    "absente du bureau",
    "afwezig",
    "fuera de la oficina",
    "ausente de la oficina",
];

/// Header names that prove an automated message. `Auto-Submitted` is handled
/// separately because the RFC 3834 value `no` explicitly means "not
/// automatic".
pub const OOO_HEADER_NAMES: &[&str] = &["x-autoreply", "x-autorespond", "x-auto-reply"];

/// A deterministic verdict: canonical disposition + exact evidence.
#[derive(Debug, Clone)]
pub struct DeterministicVerdict {
    pub disposition: ReplyDisposition,
    pub confidence: f64,
    pub reasoning: String,
    pub evidence: Vec<Evidence>,
    /// For OOO: the return date parsed from the body, when present.
    pub return_date: Option<DateTime<Utc>>,
}

impl DeterministicVerdict {
    fn new(
        disposition: ReplyDisposition,
        confidence: f64,
        reasoning: impl Into<String>,
        evidence: Vec<Evidence>,
    ) -> Self {
        Self {
            disposition,
            confidence,
            reasoning: reasoning.into(),
            evidence,
            return_date: None,
        }
    }
}

/// Char-boundary-safe truncation to `max` bytes.
pub(crate) fn truncate_utf8(value: &str, max: usize) -> &str {
    if value.len() <= max {
        return value;
    }
    let mut end = max;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

/// The capped, lowercased `subject + body` haystack used for token scans.
fn haystack(input: &ReplyInput) -> String {
    let subject = truncate_utf8(&input.subject, MAX_CLASSIFIER_INPUT_BYTES / 4);
    let body = truncate_utf8(&input.body, MAX_CLASSIFIER_INPUT_BYTES);
    if subject.is_empty() {
        body.to_lowercase()
    } else if body.is_empty() {
        subject.to_lowercase()
    } else {
        format!("{}\n{}", subject.to_lowercase(), body.to_lowercase())
    }
}

/// Layer-1 entry point. `None` means "not provable deterministically"; the
/// caller must hand the message to the AI layer (or the conservative
/// fallback), never guess here.
pub fn classify(input: &ReplyInput) -> Option<DeterministicVerdict> {
    if let Some(verdict) = dsn_verdict(input) {
        return Some(verdict);
    }
    if let Some(verdict) = unsubscribe_header_verdict(input) {
        return Some(verdict);
    }
    if let Some(verdict) = auto_reply_verdict(input) {
        return Some(verdict);
    }
    if let Some(verdict) = ooo_subject_verdict(input) {
        return Some(verdict);
    }
    stop_request_verdict(input)
}

// ---------------------------------------------------------------------------
// DSN / bounce detection
// ---------------------------------------------------------------------------

static ENHANCED_STATUS_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"(?i)\b([45]\.\d{1,3}\.\d{1,3})\b"));
static SMTP_STATUS_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"(?i)\b(5\d{2}|4\d{2})\b"));

fn compile(pattern: &str) -> Option<Regex> {
    match Regex::new(pattern) {
        Ok(regex) => Some(regex),
        Err(error) => {
            warn!(pattern, %error, "invalid deterministic classifier regex");
            None
        }
    }
}

/// Find `field:` line values in a `message/delivery-status` body (e.g.
/// `Action: failed`, `Final-Recipient: rfc822; user@example.com`,
/// `Status: 5.1.1`). Returns `(full_line, value)` for the first hit.
fn dsn_field(body: &str, field: &str) -> Option<(String, String)> {
    let prefix = format!("{}:", field.to_ascii_lowercase());
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.to_ascii_lowercase().starts_with(&prefix) {
            let value = trimmed[prefix.len()..].trim().to_string();
            return Some((trimmed.to_string(), value));
        }
    }
    None
}

fn dsn_verdict(input: &ReplyInput) -> Option<DeterministicVerdict> {
    let content_type = input.header("content-type").unwrap_or("");
    let content_type_lower = content_type.to_ascii_lowercase();
    let reports_delivery_status = content_type_lower.contains("multipart/report")
        || content_type_lower.contains("message/delivery-status")
        || content_type_lower.contains("report-type=delivery-status");

    let body = truncate_utf8(&input.body, MAX_CLASSIFIER_INPUT_BYTES);
    let final_recipient = dsn_field(body, "final-recipient");
    let action = dsn_field(body, "action");
    let status = dsn_field(body, "status");

    // A DSN needs machine-readable delivery-status syntax: either the
    // multipart/report envelope or the Final-Recipient field. Human prose
    // mentioning bounces never qualifies.
    let has_dsn_syntax = reports_delivery_status || final_recipient.is_some();
    if !has_dsn_syntax {
        return None;
    }

    let mut evidence = Vec::new();
    if !content_type.is_empty() {
        evidence.push(Evidence::header("content-type", content_type));
    }
    if let Some((line, _)) = &final_recipient {
        evidence.push(Evidence::dsn("final-recipient", line));
    }
    if let Some((line, _)) = &action {
        evidence.push(Evidence::dsn("action", line));
    }
    if let Some((line, _)) = &status {
        evidence.push(Evidence::dsn("status", line));
    }

    let enhanced = status
        .as_ref()
        .and_then(|(_, value)| ENHANCED_STATUS_RE.as_ref()?.captures(value))
        .and_then(|captures| captures.get(1))
        .map(|matched| matched.as_str().to_string());

    let action_value = action
        .as_ref()
        .map(|(_, value)| value.to_ascii_lowercase())
        .unwrap_or_default();

    // Permanent when the enhanced status says 5.x.x, or the action is
    // `failed` and the status (if any) is not explicitly transient.
    let is_hard = match enhanced.as_deref() {
        Some(code) if code.starts_with('5') => true,
        Some(code) if code.starts_with('4') => false,
        _ => {
            if action_value == "failed" {
                true
            } else {
                // No explicit status: look for an SMTP 5xx in Diagnostic-Code.
                let lowered = body.to_ascii_lowercase();
                lowered.contains("diagnostic-code:") && smtp_5xx_in(&lowered)
            }
        }
    };

    let (disposition, confidence, reasoning) = if is_hard {
        (
            ReplyDisposition::BounceHard,
            1.0,
            "delivery status notification with a permanent (5xx) failure",
        )
    } else {
        (
            ReplyDisposition::BounceSoft,
            1.0,
            "delivery status notification with a transient (4xx/delayed) failure",
        )
    };

    Some(DeterministicVerdict::new(
        disposition,
        confidence,
        reasoning,
        evidence,
    ))
}

fn smtp_5xx_in(lowered_body: &str) -> bool {
    SMTP_STATUS_RE
        .as_ref()
        .and_then(|regex| {
            regex
                .find_iter(lowered_body)
                .find(|m| m.as_str().starts_with('5'))
        })
        .is_some()
}

/// The original recipient named by a DSN (`Final-Recipient: rfc822; a@b`),
/// used to link a bounce back to the contact the sequence was addressed to
/// (the bounce's own `From:` is MAILER-DAEMON, not the prospect).
pub fn dsn_final_recipient(body: &str) -> Option<String> {
    let body = truncate_utf8(body, MAX_CLASSIFIER_INPUT_BYTES);
    let (_, value) = dsn_field(body, "final-recipient")?;
    // The field value is `type; address`; take the last segment and strip
    // angle brackets. Anything without an `@` is not an address.
    let value = value.rsplit(';').next().unwrap_or(&value).trim();
    let value = value.trim_matches(|c| c == '<' || c == '>').trim();
    if value.contains('@') && !value.contains(char::is_whitespace) {
        Some(value.to_ascii_lowercase())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// One-click / mailto unsubscribe headers
// ---------------------------------------------------------------------------

fn unsubscribe_header_verdict(input: &ReplyInput) -> Option<DeterministicVerdict> {
    if let Some(value) = input.header("list-unsubscribe-post") {
        let lower = value.to_ascii_lowercase();
        if lower.contains("list-unsubscribe=one-click") {
            return Some(DeterministicVerdict::new(
                ReplyDisposition::Unsubscribe,
                1.0,
                "one-click unsubscribe header (RFC 8058)",
                vec![Evidence::header("list-unsubscribe-post", value)],
            ));
        }
    }
    if let Some(value) = input.header("list-unsubscribe") {
        // A mailto: target is an explicit invitation to request removal; a
        // reply bearing it is a deterministic removal request.
        if value.to_ascii_lowercase().contains("mailto:") {
            return Some(DeterministicVerdict::new(
                ReplyDisposition::Unsubscribe,
                1.0,
                "unsubscribe mailto target present in List-Unsubscribe",
                vec![Evidence::header("list-unsubscribe", value)],
            ));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Auto-reply / OOO
// ---------------------------------------------------------------------------

fn auto_reply_verdict(input: &ReplyInput) -> Option<DeterministicVerdict> {
    if let Some(value) = input.header("auto-submitted") {
        let normalized = value.trim().to_ascii_lowercase();
        // RFC 3834: `no` explicitly means NOT an automatic submission.
        if !normalized.is_empty() && normalized != "no" {
            let mut verdict = DeterministicVerdict::new(
                ReplyDisposition::OutOfOffice,
                1.0,
                "Auto-Submitted header present (RFC 3834 automated message)",
                vec![Evidence::header("auto-submitted", value)],
            );
            verdict.return_date = extract_return_date(&input.body);
            return Some(verdict);
        }
    }
    for name in OOO_HEADER_NAMES {
        if let Some(value) = input.header(name) {
            if !value.trim().is_empty() {
                let mut verdict = DeterministicVerdict::new(
                    ReplyDisposition::OutOfOffice,
                    1.0,
                    format!("{name} header present"),
                    vec![Evidence::header(name, value)],
                );
                verdict.return_date = extract_return_date(&input.body);
                return Some(verdict);
            }
        }
    }
    None
}

fn ooo_subject_verdict(input: &ReplyInput) -> Option<DeterministicVerdict> {
    let subject = truncate_utf8(&input.subject, 4096).to_ascii_lowercase();
    if subject.is_empty() {
        return None;
    }
    for token in OOO_SUBJECT_TOKENS {
        if subject.contains(token) {
            let mut verdict = DeterministicVerdict::new(
                ReplyDisposition::OutOfOffice,
                0.9,
                format!("subject contains out-of-office convention '{token}'"),
                vec![Evidence::new("subject", "ooo_convention", *token)],
            );
            verdict.return_date = extract_return_date(&input.body);
            return Some(verdict);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Explicit stop / remove requests
// ---------------------------------------------------------------------------

fn stop_request_verdict(input: &ReplyInput) -> Option<DeterministicVerdict> {
    let text = haystack(input);
    let mut matched: Vec<Evidence> = Vec::new();
    for token in STOP_REQUEST_TOKENS {
        if text.contains(token) && !matched.iter().any(|e| e.value == *token) {
            matched.push(Evidence::token(token));
        }
        // Cap the audited evidence set: a hostile body containing the whole
        // dictionary must not grow the record without bound.
        if matched.len() >= 8 {
            break;
        }
    }
    if matched.is_empty() {
        return None;
    }
    Some(DeterministicVerdict::new(
        ReplyDisposition::Unsubscribe,
        0.95,
        format!(
            "explicit stop/remove request matched {} token(s)",
            matched.len()
        ),
        matched,
    ))
}

// ---------------------------------------------------------------------------
// OOO return-date extraction (bounded)
// ---------------------------------------------------------------------------

static ISO_DATE_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"\b(\d{4})-(\d{2})-(\d{2})\b"));
static DAY_FIRST_DATE_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"\b(\d{1,2})[./](\d{1,2})[./](\d{4})\b"));
static MONTH_FIRST_DATE_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r"(?i)\b(january|february|march|april|may|june|july|august|september|october|november|december)\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})\b",
    )
});
static DAY_FIRST_MONTH_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r"(?i)\b(\d{1,2})(?:st|nd|rd|th)?\s+(january|february|march|april|may|june|july|august|september|october|november|december),?\s+(\d{4})\b",
    )
});

/// Parse a stated return date out of the body. Only absolute dates are
/// accepted — relative phrases ("back on Monday") are deliberately left to
/// the policy's default wait, because resolving them needs a reference date
/// and getting it wrong would reschedule to the past or the wrong week.
pub fn extract_return_date(body: &str) -> Option<DateTime<Utc>> {
    let text = truncate_utf8(body, MAX_CLASSIFIER_INPUT_BYTES);

    if let Some(regex) = ISO_DATE_RE.as_ref() {
        if let Some(captures) = regex.captures(text) {
            if let (Some(year), Some(month), Some(day)) =
                (captures.get(1), captures.get(2), captures.get(3))
            {
                if let Some(date) = naive_date(year.as_str(), month.as_str(), day.as_str()) {
                    return Some(date.and_hms_opt(9, 0, 0)?.and_utc());
                }
            }
        }
    }
    if let Some(regex) = MONTH_FIRST_DATE_RE.as_ref() {
        if let Some(captures) = regex.captures(text) {
            if let (Some(month), Some(day), Some(year)) =
                (captures.get(1), captures.get(2), captures.get(3))
            {
                if let Some(month) = month_number(month.as_str()) {
                    if let Some(date) = naive_date(year.as_str(), &month.to_string(), day.as_str())
                    {
                        return Some(date.and_hms_opt(9, 0, 0)?.and_utc());
                    }
                }
            }
        }
    }
    if let Some(regex) = DAY_FIRST_MONTH_RE.as_ref() {
        if let Some(captures) = regex.captures(text) {
            if let (Some(day), Some(month), Some(year)) =
                (captures.get(1), captures.get(2), captures.get(3))
            {
                if let Some(month) = month_number(month.as_str()) {
                    if let Some(date) = naive_date(year.as_str(), &month.to_string(), day.as_str())
                    {
                        return Some(date.and_hms_opt(9, 0, 0)?.and_utc());
                    }
                }
            }
        }
    }
    // Day-first numeric (EU convention) is checked AFTER month-first textual
    // formats because 01/02/2026 is ambiguous; textual months are not.
    if let Some(regex) = DAY_FIRST_DATE_RE.as_ref() {
        if let Some(captures) = regex.captures(text) {
            if let (Some(day), Some(month), Some(year)) =
                (captures.get(1), captures.get(2), captures.get(3))
            {
                if let Some(date) = naive_date(year.as_str(), month.as_str(), day.as_str()) {
                    return Some(date.and_hms_opt(9, 0, 0)?.and_utc());
                }
            }
        }
    }
    None
}

fn naive_date(year: &str, month: &str, day: &str) -> Option<NaiveDate> {
    let year: i32 = year.parse().ok()?;
    let month: u32 = month.parse().ok()?;
    let day: u32 = day.parse().ok()?;
    // Reject implausible years rather than accepting a typo as fact.
    if !(2000..=2100).contains(&year) {
        return None;
    }
    NaiveDate::from_ymd_opt(year, month, day)
}

fn month_number(name: &str) -> Option<u32> {
    Some(match name.to_ascii_lowercase().as_str() {
        "january" => 1,
        "february" => 2,
        "march" => 3,
        "april" => 4,
        "may" => 5,
        "june" => 6,
        "july" => 7,
        "august" => 8,
        "september" => 9,
        "october" => 10,
        "november" => 11,
        "december" => 12,
        _ => return None,
    })
}

/// The OOO resume instant: the parsed return date plus one day (to land after
/// the stated return), or `now + DEFAULT_OOO_WAIT_DAYS`.
pub fn ooo_resume_at(return_date: Option<DateTime<Utc>>, now: DateTime<Utc>) -> DateTime<Utc> {
    match return_date {
        Some(date) => date + Duration::days(1),
        None => now + Duration::days(DEFAULT_OOO_WAIT_DAYS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reply_handler::types::ReplyInput;

    fn dsn_body(status: &str, action: &str) -> String {
        format!(
            "This is a MIME-encapsulated message.\n\n\
             --boundary\nContent-Type: message/delivery-status\n\n\
             Reporting-MTA: dns; mx.example.com\n\n\
             Final-Recipient: rfc822; prospect@example.com\n\
             Action: {action}\n\
             Status: {status}\n\n\
             --boundary--"
        )
    }

    // ── DSN / bounces ────────────────────────────────────────────────

    #[test]
    fn hard_bounce_with_5xx_status_and_dsn_headers() {
        let input = ReplyInput::new(
            "Undelivered Mail Returned to Sender",
            dsn_body("5.1.1", "failed"),
        )
        .with_header(
            "Content-Type",
            "multipart/report; report-type=delivery-status; boundary=boundary",
        )
        .with_header("From", "MAILER-DAEMON@mx.example.com");

        let verdict = classify(&input).expect("a DSN is deterministic");
        assert_eq!(verdict.disposition, ReplyDisposition::BounceHard);
        assert_eq!(verdict.confidence, 1.0);
        assert!(
            verdict
                .evidence
                .iter()
                .any(|e| e.kind == "dsn" && e.value.contains("Status: 5.1.1")),
            "the exact 5xx status must be auditable: {:?}",
            verdict.evidence
        );
        assert!(
            verdict
                .evidence
                .iter()
                .any(|e| e.kind == "dsn" && e.value.contains("Final-Recipient")),
            "the exact final recipient must be auditable"
        );
    }

    #[test]
    fn soft_bounce_with_4xx_status() {
        let input = ReplyInput::new("Delayed delivery", dsn_body("4.4.1", "delayed")).with_header(
            "Content-Type",
            "multipart/report; report-type=delivery-status",
        );
        let verdict = classify(&input).expect("a DSN is deterministic");
        assert_eq!(verdict.disposition, ReplyDisposition::BounceSoft);
        assert!(verdict.evidence.iter().any(|e| e.value.contains("4.4.1")));
    }

    #[test]
    fn dsn_with_final_recipient_but_no_content_type_is_still_a_bounce() {
        let body = "Final-Recipient: rfc822; gone@example.com\nAction: failed\nStatus: 5.0.0";
        let verdict = classify(&ReplyInput::new("Re: hello", body)).expect("syntax is enough");
        // No explicit 5.0.0 parse? It is 5.x -> hard.
        assert_eq!(verdict.disposition, ReplyDisposition::BounceHard);
    }

    #[test]
    fn human_prose_mentioning_bounce_does_not_classify_as_dsn() {
        let verdict = classify(&ReplyInput::new(
            "Re: your email",
            "I got a bounce notification but I am fine — let's talk next week",
        ));
        assert!(
            verdict.is_none(),
            "prose must not be treated as machine DSN syntax"
        );
    }

    #[test]
    fn smtp_550_in_diagnostic_code_is_a_hard_bounce() {
        let body = "Final-Recipient: rfc822; x@example.com\nAction: failed\n\
                    Diagnostic-Code: smtp; 550 5.1.1 User unknown";
        let verdict = classify(&ReplyInput::new("Returned mail", body)).expect("deterministic");
        assert_eq!(verdict.disposition, ReplyDisposition::BounceHard);
    }

    #[test]
    fn dsn_final_recipient_is_extracted_for_linking() {
        assert_eq!(
            dsn_final_recipient("Final-Recipient: rfc822; Prospect@Example.com\nAction: failed"),
            Some("prospect@example.com".to_string())
        );
        assert_eq!(
            dsn_final_recipient("final-recipient: <user@example.com>"),
            Some("user@example.com".to_string())
        );
        assert_eq!(
            dsn_final_recipient("Final-Recipient: rfc822; not-an-address"),
            None
        );
        assert_eq!(dsn_final_recipient("no dsn here"), None);
    }

    // ── Auto-Submitted / OOO ─────────────────────────────────────────

    #[test]
    fn auto_submitted_any_value_other_than_no_is_ooo() {
        for value in [
            "auto-replied",
            "auto-generated",
            "auto-notified",
            "AUTO-REPLIED",
        ] {
            let input = ReplyInput::new("Re: hello", "Thanks, got it!")
                .with_header("Auto-Submitted", value);
            let verdict = classify(&input).expect("auto-submitted is deterministic");
            assert_eq!(
                verdict.disposition,
                ReplyDisposition::OutOfOffice,
                "Auto-Submitted: {value} must be OOO"
            );
            assert_eq!(
                verdict.evidence[0],
                Evidence::header("auto-submitted", value)
            );
        }
    }

    #[test]
    fn auto_submitted_no_is_not_ooo() {
        let input = ReplyInput::new("Re: hello", "Sounds good, let's talk")
            .with_header("Auto-Submitted", "no");
        let verdict = classify(&input);
        assert!(verdict
            .as_ref()
            .map(|v| v.disposition != ReplyDisposition::OutOfOffice)
            .unwrap_or(true));
    }

    #[test]
    fn x_autoreply_and_x_autorespond_are_ooo() {
        for header in ["X-Autoreply", "X-Autorespond", "X-Auto-Reply"] {
            let input = ReplyInput::new("Re: hi", "I am away").with_header(header, "yes");
            let verdict = classify(&input).expect("auto-reply header is deterministic");
            assert_eq!(verdict.disposition, ReplyDisposition::OutOfOffice);
            assert!(verdict
                .evidence
                .iter()
                .any(|e| e.key == header.to_ascii_lowercase()));
        }
    }

    #[test]
    fn ooo_subject_conventions_are_ooo() {
        for subject in [
            "Automatic reply: your proposal",
            "Out of Office until Monday",
            "Abwesenheit: Ihre Anfrage",
            "Absence du bureau",
            "Auto-Reply: Re: pricing",
        ] {
            let verdict = classify(&ReplyInput::new(subject, "Limited access to email."))
                .unwrap_or_else(|| panic!("subject {subject:?} must be deterministic OOO"));
            assert_eq!(verdict.disposition, ReplyDisposition::OutOfOffice);
            assert!(!verdict.evidence.is_empty());
        }
    }

    #[test]
    fn auto_submitted_header_beats_vaguely_positive_body() {
        // §20 adversarial case: the naive semantic read is "positive", but the
        // header is machine-proven. Deterministic must win.
        let input = ReplyInput::new(
            "Re: your proposal",
            "This looks great, I would love to learn more and schedule a call!",
        )
        .with_header("Auto-Submitted", "auto-replied");
        let verdict = classify(&input).expect("deterministic wins");
        assert_eq!(verdict.disposition, ReplyDisposition::OutOfOffice);
        assert_ne!(verdict.disposition, ReplyDisposition::Positive);
    }

    #[test]
    fn ooo_return_date_is_extracted_when_stated() {
        let input = ReplyInput::new(
            "Automatic reply: Re: proposal",
            "I am out of the office and will return on 2026-09-21. For urgent matters call the office.",
        );
        let verdict = classify(&input).expect("OOO");
        assert_eq!(
            verdict.return_date.map(|d| d.date_naive()),
            NaiveDate::from_ymd_opt(2026, 9, 21)
        );
    }

    #[test]
    fn ooo_return_date_supports_textual_months() {
        for (body, expected) in [
            ("Back in the office on September 21, 2026.", (2026, 9, 21)),
            ("I will return 21 September 2026.", (2026, 9, 21)),
            ("Zurück am 21.09.2026.", (2026, 9, 21)),
        ] {
            let date = extract_return_date(body)
                .unwrap_or_else(|| panic!("date not parsed from {body:?}"));
            assert_eq!(
                date.date_naive(),
                NaiveDate::from_ymd_opt(expected.0, expected.1, expected.2).unwrap()
            );
        }
    }

    #[test]
    fn nonsense_return_dates_are_rejected() {
        assert!(extract_return_date("back on 2026-13-45").is_none());
        assert!(extract_return_date("back in 1800-01-01").is_none());
        assert!(extract_return_date("no date here").is_none());
    }

    // ── Unsubscribe headers ──────────────────────────────────────────

    #[test]
    fn one_click_unsubscribe_header_is_deterministic() {
        let input = ReplyInput::new("Re: newsletter", "Please stop")
            .with_header("List-Unsubscribe-Post", "List-Unsubscribe=One-Click");
        let verdict = classify(&input).expect("one-click is deterministic");
        assert_eq!(verdict.disposition, ReplyDisposition::Unsubscribe);
        assert_eq!(
            verdict.evidence[0],
            Evidence::header("list-unsubscribe-post", "List-Unsubscribe=One-Click")
        );
    }

    #[test]
    fn mailto_unsubscribe_target_is_deterministic() {
        let input = ReplyInput::new("Re: newsletter", "ok").with_header(
            "List-Unsubscribe",
            "<mailto:unsubscribe@apex.example?subject=unsub>, <https://apex.example/u>",
        );
        let verdict = classify(&input).expect("mailto target is deterministic");
        assert_eq!(verdict.disposition, ReplyDisposition::Unsubscribe);
        assert!(verdict.evidence[0].value.contains("mailto:"));
    }

    // ── Explicit stop tokens ─────────────────────────────────────────

    #[test]
    fn stop_request_tokens_cover_all_supported_languages() {
        let cases = [
            ("please unsubscribe me", "unsubscribe"),
            ("remove me from this list", "remove me"),
            ("stop emailing me", "stop emailing"),
            ("I want to opt out", "opt out"),
            ("Bitte abmelden Sie mich", "abmelden"),
            ("Bitte austragen", "austragen"),
            ("Veuillez me désabonner", "désabonner"),
            ("Ne plus me contacter", "ne plus me contacter"),
            ("Graag afmelden", "afmelden"),
            ("Uitschrijven alstublieft", "uitschrijven"),
            ("Por favor darse de baja", "darse de baja"),
            ("No me contacten más", "no me contacten"),
        ];
        for (body, token) in cases {
            let verdict = classify(&ReplyInput::new("Re: hello", body))
                .unwrap_or_else(|| panic!("{body:?} must be a deterministic stop request"));
            assert_eq!(
                verdict.disposition,
                ReplyDisposition::Unsubscribe,
                "body {body:?}"
            );
            assert!(
                verdict.evidence.iter().any(|e| e.value == token),
                "body {body:?} must carry token evidence {token:?}, got {:?}",
                verdict.evidence
            );
        }
    }

    #[test]
    fn a_body_with_every_stop_keyword_does_not_panic_and_is_unsubscribe() {
        let mut body = String::new();
        for token in STOP_REQUEST_TOKENS {
            body.push_str(token);
            body.push_str("; ");
        }
        let verdict = classify(&ReplyInput::new("Re: hi", &body)).expect("stop request");
        assert_eq!(verdict.disposition, ReplyDisposition::Unsubscribe);
        assert!(
            verdict.evidence.len() <= 8,
            "hostile keyword soup must not grow evidence without bound"
        );
        assert!(!verdict.evidence.is_empty());
    }

    // ── Hostile input ────────────────────────────────────────────────

    #[test]
    fn one_megabyte_body_is_capped_and_classified() {
        // The stop token sits inside the first 100 KB, so the capped scan
        // still finds it; the megabyte tail must not change the verdict.
        let mut body = String::from("please unsubscribe me. ");
        body.push_str(&"x".repeat(1024 * 1024));
        let verdict = classify(&ReplyInput::new("Re: huge", &body))
            .expect("a stop request in the first 100 KB is found");
        assert_eq!(verdict.disposition, ReplyDisposition::Unsubscribe);

        // A body that is purely padding must not be misclassified.
        let padding = "y".repeat(1024 * 1024);
        let none = classify(&ReplyInput::new("Re: huge", &padding));
        assert!(
            none.is_none() || none.unwrap().disposition != ReplyDisposition::Positive,
            "padding must never produce a positive guess"
        );
    }

    #[test]
    fn invalid_utf8_body_degrades_without_panicking() {
        let mut invalid = vec![0xff, 0xfe, 0x00, 0x41, 0x42];
        invalid.extend_from_slice(b" unsubscribe");
        let input = ReplyInput::from_bytes(b"Re: \xff", &invalid);
        // Lossy conversion retains ASCII around the replacement chars.
        let verdict = classify(&input);
        assert!(
            verdict.is_some(),
            "a lossily-decoded stop request must still be found"
        );
        assert_eq!(verdict.unwrap().disposition, ReplyDisposition::Unsubscribe);
    }

    #[test]
    fn deeply_nested_mime_body_does_not_panic() {
        let mut body = String::new();
        for depth in 0..2_000 {
            body.push_str(&format!(
                "--b{depth}\nContent-Type: multipart/mixed; boundary=b{}\n",
                depth + 1
            ));
        }
        body.push_str("Out of Office: back on 2026-10-01");
        let input = ReplyInput::new("Re: nested", &body);
        let verdict = classify(&input);
        // No nested boundary convention is deterministic; must not panic.
        assert!(verdict.is_none() || verdict.unwrap().disposition != ReplyDisposition::Positive);
    }

    #[test]
    fn emoji_only_subject_and_no_headers_is_not_guessed() {
        let input = ReplyInput::new("🎉🚀✨", "");
        assert!(
            classify(&input).is_none(),
            "an emoji-only message has no deterministic verdict"
        );
    }

    #[test]
    fn no_headers_and_empty_body_neither_panics_nor_guesses() {
        assert!(classify(&ReplyInput::new("", "")).is_none());
    }

    #[test]
    fn truncated_utf8_never_splits_a_multibyte_char() {
        let text = "é".repeat(1000);
        for max in 0..text.len() {
            let truncated = truncate_utf8(&text, max);
            assert!(truncated.is_char_boundary(truncated.len()));
        }
    }

    #[test]
    fn stop_token_evidence_is_exact() {
        let verdict = classify(&ReplyInput::new("Unsubscribe", "unsubscribe")).unwrap();
        assert!(verdict
            .evidence
            .iter()
            .all(|e| e.kind == "token" && e.key == "stop_request"));
        assert!(verdict.evidence.iter().any(|e| e.value == "unsubscribe"));
    }

    #[test]
    fn ooo_resume_at_is_after_the_stated_return_date() {
        let now = Utc::now();
        let stated = now + Duration::days(3);
        let resume = ooo_resume_at(Some(stated), now);
        assert!(resume > stated, "resume strictly after the return date");
        let default_resume = ooo_resume_at(None, now);
        assert_eq!(default_resume, now + Duration::days(DEFAULT_OOO_WAIT_DAYS));
    }

    #[test]
    fn disposition_vocabulary_is_the_canonical_eleven() {
        assert_eq!(ReplyDisposition::ALL.len(), 11);
        let strings: Vec<&str> = ReplyDisposition::ALL.iter().map(|d| d.as_str()).collect();
        assert!(strings.contains(&"ooo"));
        assert!(strings.contains(&"bounce_hard"));
        assert!(strings.contains(&"bounce_soft"));
        assert!(strings.contains(&"meeting_request"));
    }
}
