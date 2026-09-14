//! SMTP response parsing and classification.
//!
//! The relay must never reduce a recipient server's reply to "ok/not ok":
//! the exact stage at which a failure occurs decides whether the message is
//! retried, whether one recipient is failed, or whether the whole message is
//! rejected and a DSN is due.
//!
//! * 4xx anywhere → transient, retry with backoff.
//! * 5xx at `RCPT TO` → permanent for THAT recipient only.
//! * 5xx at `MAIL FROM` or after `DATA` → permanent for the WHOLE message.
//! * 5xx at greeting/EHLO/STARTTLS → this MX is unusable; try the next MX.
//! * Enhanced status codes (RFC 3463) are parsed when present and feed the
//!   DSN `Status:` field; when absent a status is synthesized from the reply
//!   code so a DSN never carries an empty status.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::dsn::{DsnAction, DsnInputs};

/// One parsed SMTP reply. `lines` keeps the individual reply lines (the
/// EHLO capability advertisement is parsed from them); `text` is the joined
/// free-text tail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmtpReply {
    /// 3-digit SMTP reply code.
    pub code: u16,
    /// Enhanced status code (RFC 3463), when the first text token is one.
    pub enhanced: Option<EnhancedStatusCode>,
    /// Joined reply text (all lines, excluding the reply codes).
    pub text: String,
    /// Raw reply text, one entry per line (excluding the reply codes).
    pub lines: Vec<String>,
}

impl SmtpReply {
    /// Parse a single-line reply (`"250 OK"`, `"250-OK"` accepted too).
    pub fn parse(line: &str) -> Option<Self> {
        Self::parse_multiline(std::slice::from_ref(&line.to_string()))
    }

    /// Parse a complete (possibly multiline) reply from its raw lines.
    /// Every line must carry the same 3-digit code; the continuation marker
    /// is `-` at offset 3, the final marker is a space.
    pub fn parse_multiline(lines: &[String]) -> Option<Self> {
        let first = lines.first()?;
        let code = parse_reply_code(first)?;
        let mut text_lines = Vec::with_capacity(lines.len());
        for line in lines {
            // RFC 5321 §4.2: every line of a multiline reply carries the SAME
            // reply code. A peer that changes the code mid-reply (e.g. a
            // `250-...` line followed by `550 ...`) is protocol-confused at
            // best and smuggling a failure past a first-line-only reader at
            // worst — the whole reply is unparseable.
            if parse_reply_code(line) != Some(code) {
                return None;
            }
            let rest = line.get(4..).unwrap_or("");
            text_lines.push(rest.trim().to_string());
        }
        let text = text_lines.join(" ");
        let enhanced = text
            .split_whitespace()
            .next()
            .and_then(EnhancedStatusCode::parse);
        Some(Self {
            code,
            enhanced,
            text,
            lines: text_lines,
        })
    }

    /// 2xx.
    pub fn is_positive(&self) -> bool {
        (200..300).contains(&self.code)
    }

    /// 354 (DATA intermediate).
    pub fn is_intermediate(&self) -> bool {
        self.code == 354
    }

    /// 4xx.
    pub fn is_transient(&self) -> bool {
        (400..500).contains(&self.code)
    }

    /// 5xx.
    pub fn is_permanent(&self) -> bool {
        (500..600).contains(&self.code)
    }

    /// DSN `Status:` field value: the enhanced code when the peer sent one,
    /// otherwise the closest standard status for the reply code.
    pub fn dsn_status(&self) -> String {
        if let Some(enhanced) = &self.enhanced {
            return enhanced.to_string();
        }
        match self.code {
            450 => "4.2.0",
            451 => "4.3.0",
            452 => "4.2.2",
            550 => "5.1.1",
            551 => "5.1.6",
            552 => "5.2.2",
            553 => "5.1.3",
            554 => "5.0.0",
            code if (400..500).contains(&code) => "4.0.0",
            code if (500..600).contains(&code) => "5.0.0",
            _ => "2.0.0",
        }
        .to_string()
    }

    /// Diagnostic code for a DSN (`Diagnostic-Code: smtp; 550 5.1.1 ...`).
    pub fn diagnostic(&self) -> String {
        if self.text.is_empty() {
            self.code.to_string()
        } else {
            format!("{} {}", self.code, self.text)
        }
    }

    /// The DSN inputs for a PERMANENT post-accept failure at this reply.
    /// `None` when the reply is not a 5xx — a DSN is only due for a permanent
    /// failure. This is the single place a permanent reply is converted into
    /// RFC 3464 fields; [`crate::dsn`] renders them.
    pub fn permanent_dsn_inputs(
        &self,
        final_recipient: String,
        remote_mta: Option<String>,
        arrival_date: DateTime<Utc>,
        original_envelope_id: Option<String>,
    ) -> Option<DsnInputs> {
        if !self.is_permanent() {
            return None;
        }
        Some(DsnInputs {
            final_recipient,
            action: DsnAction::Failed,
            status: self.dsn_status(),
            diagnostic_code: format!("smtp; {}", self.diagnostic()),
            remote_mta,
            arrival_date,
            original_envelope_id,
        })
    }
}

/// RFC 3463 enhanced status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnhancedStatusCode {
    pub class: u16,
    pub subject: u16,
    pub detail: u16,
}

impl EnhancedStatusCode {
    /// Parse `X.Y.Z` with numeric, non-empty parts of at most 3 digits.
    pub fn parse(token: &str) -> Option<Self> {
        let mut parts = token.split('.');
        let class = parse_part(parts.next()?)?;
        let subject = parse_part(parts.next()?)?;
        let detail = parse_part(parts.next()?)?;
        if parts.next().is_some() {
            return None;
        }
        if !(2..=5).contains(&class) {
            return None;
        }
        Some(Self {
            class,
            subject,
            detail,
        })
    }

    pub fn is_transient(&self) -> bool {
        self.class == 4
    }

    pub fn is_permanent(&self) -> bool {
        self.class == 5
    }
}

impl std::fmt::Display for EnhancedStatusCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.class, self.subject, self.detail)
    }
}

fn parse_part(part: &str) -> Option<u16> {
    if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    part.parse::<u16>().ok()
}

/// The 3-digit code at the start of a reply line, requiring the reply
/// separator (` ` or `-`) at offset 3 when the line is long enough.
fn parse_reply_code(line: &str) -> Option<u16> {
    let head = line.get(..3)?;
    if !head.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if let Some(separator) = line.as_bytes().get(3) {
        if *separator != b' ' && *separator != b'-' {
            return None;
        }
    }
    head.parse::<u16>().ok()
}

/// Where in the SMTP conversation a reply was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtpStage {
    Greeting,
    Ehlo,
    StartTls,
    MailFrom,
    RcptTo,
    Data,
    EndOfData,
}

impl SmtpStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Greeting => "greeting",
            Self::Ehlo => "EHLO",
            Self::StartTls => "STARTTLS",
            Self::MailFrom => "MAIL FROM",
            Self::RcptTo => "RCPT TO",
            Self::Data => "DATA",
            Self::EndOfData => "end-of-DATA",
        }
    }
}

impl std::fmt::Display for SmtpStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a reply means for delivery, given the stage it arrived at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyDisposition {
    /// 2xx.
    Accepted,
    /// 354 — send the message body.
    Intermediate,
    /// 4xx — retryable.
    Transient,
    /// 5xx at RCPT TO — permanent for this recipient.
    PermanentRecipient,
    /// 5xx at MAIL FROM or after DATA — permanent for the whole message.
    PermanentMessage,
    /// 5xx at greeting/EHLO/STARTTLS — this MX cannot carry the message.
    PeerRefusal,
    /// A code outside 2xx..5xx or an impossible stage reply.
    Unexpected,
}

/// Classify `reply` for the stage it was read at (see the module docs for
/// the policy table).
pub fn classify(stage: SmtpStage, reply: &SmtpReply) -> ReplyDisposition {
    if reply.is_positive() {
        return ReplyDisposition::Accepted;
    }
    if reply.is_intermediate() {
        return ReplyDisposition::Intermediate;
    }
    if reply.is_transient() {
        return ReplyDisposition::Transient;
    }
    if reply.is_permanent() {
        return match stage {
            SmtpStage::RcptTo => ReplyDisposition::PermanentRecipient,
            SmtpStage::MailFrom | SmtpStage::Data | SmtpStage::EndOfData => {
                ReplyDisposition::PermanentMessage
            }
            SmtpStage::Greeting | SmtpStage::Ehlo | SmtpStage::StartTls => {
                ReplyDisposition::PeerRefusal
            }
        };
    }
    ReplyDisposition::Unexpected
}

#[cfg(test)]
mod tests {
    use super::*;

    fn multiline(lines: &[&str]) -> SmtpReply {
        let owned: Vec<String> = lines.iter().map(|line| (*line).to_string()).collect();
        SmtpReply::parse_multiline(&owned).expect("reply must parse")
    }

    #[test]
    fn parses_single_line_reply() {
        let reply = SmtpReply::parse("250 2.0.0 OK").expect("parse");
        assert_eq!(reply.code, 250);
        assert_eq!(
            reply.enhanced,
            Some(EnhancedStatusCode {
                class: 2,
                subject: 0,
                detail: 0
            })
        );
        assert_eq!(reply.text, "2.0.0 OK");
    }

    #[test]
    fn parses_multiline_reply() {
        let reply = multiline(&[
            "250-fake.example greets us",
            "250-STARTTLS",
            "250-SIZE 10485760",
            "250 8BITMIME",
        ]);
        assert_eq!(reply.code, 250);
        assert!(reply.lines.iter().any(|line| line.starts_with("STARTTLS")));
        assert!(reply.lines.iter().any(|line| line.starts_with("SIZE")));
    }

    #[test]
    fn rejects_replies_without_a_code() {
        assert!(SmtpReply::parse("hello there").is_none());
        assert!(SmtpReply::parse("").is_none());
        assert!(SmtpReply::parse("25x nope").is_none());
    }

    #[test]
    fn enhanced_status_validation() {
        assert_eq!(
            EnhancedStatusCode::parse("5.1.1"),
            Some(EnhancedStatusCode {
                class: 5,
                subject: 1,
                detail: 1
            })
        );
        assert!(EnhancedStatusCode::parse("5.1").is_none());
        assert!(EnhancedStatusCode::parse("9.1.1").is_none());
        assert!(EnhancedStatusCode::parse("x.1.1").is_none());
        assert!(EnhancedStatusCode::parse("5.1.1.1").is_none());
    }

    #[test]
    fn classification_follows_the_policy_table() {
        let transient = SmtpReply::parse("450 4.2.1 busy").expect("parse");
        let permanent = SmtpReply::parse("550 5.1.1 no such user").expect("parse");
        let ok = SmtpReply::parse("250 OK").expect("parse");

        assert_eq!(
            classify(SmtpStage::RcptTo, &transient),
            ReplyDisposition::Transient
        );
        assert_eq!(
            classify(SmtpStage::RcptTo, &permanent),
            ReplyDisposition::PermanentRecipient
        );
        assert_eq!(
            classify(SmtpStage::MailFrom, &permanent),
            ReplyDisposition::PermanentMessage
        );
        assert_eq!(
            classify(SmtpStage::EndOfData, &permanent),
            ReplyDisposition::PermanentMessage
        );
        assert_eq!(
            classify(SmtpStage::Greeting, &permanent),
            ReplyDisposition::PeerRefusal
        );
        assert_eq!(classify(SmtpStage::Data, &ok), ReplyDisposition::Accepted);
        let intermediate = SmtpReply::parse("354 go ahead").expect("parse");
        assert_eq!(
            classify(SmtpStage::Data, &intermediate),
            ReplyDisposition::Intermediate
        );
    }

    #[test]
    fn dsn_status_prefers_enhanced_and_synthesizes_otherwise() {
        assert_eq!(
            SmtpReply::parse("550 5.1.1 nope")
                .expect("parse")
                .dsn_status(),
            "5.1.1"
        );
        assert_eq!(
            SmtpReply::parse("554 nope").expect("parse").dsn_status(),
            "5.0.0"
        );
        assert_eq!(
            SmtpReply::parse("450 try later")
                .expect("parse")
                .dsn_status(),
            "4.2.0"
        );
        assert_eq!(
            SmtpReply::parse("451 4.3.0 try later")
                .expect("parse")
                .dsn_status(),
            "4.3.0"
        );
    }

    #[test]
    fn diagnostic_includes_code_and_text() {
        let reply = SmtpReply::parse("550 5.1.1 user unknown").expect("parse");
        assert_eq!(reply.diagnostic(), "550 5.1.1 user unknown");
        assert_eq!(reply.dsn_status(), "5.1.1");
    }

    #[test]
    fn multiline_parsing_requires_one_code_on_every_line() {
        // Same code on every line: valid, including the 3-char bare form.
        assert!(multiline(&["250-a", "250-b", "250"]).code == 250);

        // A code change mid-reply is unparseable: a first-line-only reader
        // would wrongly accept the `550` tail as part of a 250.
        assert!(SmtpReply::parse_multiline(&[
            "250-fake".to_string(),
            "550 actually no".to_string()
        ])
        .is_none());
        assert!(
            SmtpReply::parse_multiline(&["250-fake".to_string(), "garbage".to_string()]).is_none()
        );

        // Invalid separators / missing lines are refused.
        assert!(SmtpReply::parse_multiline(&[]).is_none());
        assert!(SmtpReply::parse("").is_none());
        assert!(SmtpReply::parse("25").is_none());
        assert!(SmtpReply::parse("250x nope").is_none());
        assert!(SmtpReply::parse("+250 nope").is_none());
        assert!(SmtpReply::parse("250").is_some(), "a bare code is a reply");
    }

    #[test]
    fn multiline_text_is_joined_and_enhanced_status_reads_the_first_token() {
        // The enhanced status is the FIRST token of the reply text — a
        // multiline reply whose first line is a greeting leaves it unset.
        let reply = multiline(&["250-2.1.5 Ok", "250-SIZE 10485760", "250 8BITMIME"]);
        assert_eq!(reply.text, "2.1.5 Ok SIZE 10485760 8BITMIME");
        assert_eq!(
            reply.enhanced,
            Some(EnhancedStatusCode {
                class: 2,
                subject: 1,
                detail: 5
            })
        );
        // A first token that is not an enhanced code leaves it unset.
        let plain = multiline(&["250-fake.example greets us", "250 Ok"]);
        assert!(plain.enhanced.is_none());
        let empty_text = multiline(&["250-", "250 "]);
        assert_eq!(
            empty_text.text, " ",
            "line texts are joined with a space even when empty"
        );
        assert_eq!(empty_text.lines, vec!["", ""]);
    }

    #[test]
    fn dsn_status_synthesizes_every_documented_code() {
        for (line, expected) in [
            ("450 full", "4.2.0"),
            ("451 try later", "4.3.0"),
            ("452 too many", "4.2.2"),
            ("550 nope", "5.1.1"),
            ("551 nope", "5.1.6"),
            ("552 too large", "5.2.2"),
            ("553 bad name", "5.1.3"),
            ("554 nope", "5.0.0"),
            ("421 other 4xx", "4.0.0"),
            ("521 other 5xx", "5.0.0"),
            ("250 ok", "2.0.0"),
        ] {
            assert_eq!(
                SmtpReply::parse(line).expect("reply").dsn_status(),
                expected,
                "line {line:?}"
            );
        }
        // An enhanced code always wins over the synthesized one.
        assert_eq!(
            SmtpReply::parse("550 5.7.1 policy")
                .expect("reply")
                .dsn_status(),
            "5.7.1"
        );
    }

    #[test]
    fn diagnostic_without_text_is_just_the_code() {
        let reply = SmtpReply::parse("421").expect("parse");
        assert_eq!(reply.diagnostic(), "421");
        assert_eq!(reply.dsn_status(), "4.0.0");
    }

    #[test]
    fn classification_refuses_impossible_codes_and_stages() {
        for line in ["100 anything", "199 odd", "600 future"] {
            let reply = SmtpReply::parse(line).expect("parse");
            assert_eq!(
                classify(SmtpStage::RcptTo, &reply),
                ReplyDisposition::Unexpected,
                "line {line:?}"
            );
        }
        let permanent = SmtpReply::parse("554 nope").expect("parse");
        assert_eq!(
            classify(SmtpStage::Ehlo, &permanent),
            ReplyDisposition::PeerRefusal
        );
        assert_eq!(
            classify(SmtpStage::StartTls, &permanent),
            ReplyDisposition::PeerRefusal
        );
        // 354 is only meaningful at the DATA command, but the classifier
        // reports the shape, not the stage legality.
        let intermediate = SmtpReply::parse("354 go").expect("parse");
        assert_eq!(
            classify(SmtpStage::Greeting, &intermediate),
            ReplyDisposition::Intermediate
        );
        assert!(intermediate.is_intermediate());
        assert!(!intermediate.is_positive());
    }

    #[test]
    fn enhanced_status_classes_classify_transience() {
        let transient = EnhancedStatusCode::parse("4.2.1").expect("parse");
        assert!(transient.is_transient());
        assert!(!transient.is_permanent());
        assert_eq!(transient.to_string(), "4.2.1");
        let permanent = EnhancedStatusCode::parse("5.1.1").expect("parse");
        assert!(permanent.is_permanent());
        assert!(!permanent.is_transient());
        assert!(EnhancedStatusCode::parse("6.0.0").is_none());
        assert!(EnhancedStatusCode::parse("5.1.1111").is_none());
        assert!(EnhancedStatusCode::parse("5..1").is_none());
        assert!(EnhancedStatusCode::parse("").is_none());
    }

    #[test]
    fn stages_render_their_wire_names() {
        let pairs = [
            (SmtpStage::Greeting, "greeting"),
            (SmtpStage::Ehlo, "EHLO"),
            (SmtpStage::StartTls, "STARTTLS"),
            (SmtpStage::MailFrom, "MAIL FROM"),
            (SmtpStage::RcptTo, "RCPT TO"),
            (SmtpStage::Data, "DATA"),
            (SmtpStage::EndOfData, "end-of-DATA"),
        ];
        for (stage, expected) in pairs {
            assert_eq!(stage.as_str(), expected);
            assert_eq!(stage.to_string(), expected);
        }
    }

    #[test]
    fn permanent_dsn_inputs_map_every_field_and_refuse_non_permanent() {
        let reply = SmtpReply::parse("554 5.7.1 rejected").expect("parse");
        let arrival = Utc::now();
        let inputs = reply
            .permanent_dsn_inputs(
                "user@example.com".to_string(),
                None,
                arrival,
                Some("env-1".to_string()),
            )
            .expect("a 5xx yields DSN inputs");
        assert_eq!(inputs.action, DsnAction::Failed);
        assert_eq!(inputs.status, "5.7.1");
        assert_eq!(inputs.diagnostic_code, "smtp; 554 5.7.1 rejected");
        assert_eq!(inputs.remote_mta, None);
        assert_eq!(inputs.arrival_date, arrival);
        assert_eq!(inputs.original_envelope_id.as_deref(), Some("env-1"));

        for line in ["250 ok", "354 go", "451 later", "199 odd"] {
            let reply = SmtpReply::parse(line).expect("parse");
            assert!(
                reply
                    .permanent_dsn_inputs("u@example.com".to_string(), None, arrival, None)
                    .is_none(),
                "line {line:?} must not produce DSN inputs"
            );
        }
    }
}
