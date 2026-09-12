//! RFC 3464 Delivery Status Notification generation.
//!
//! A DSN is generated only when the ORIGINAL message had a non-null envelope
//! sender (`MAIL FROM:<...>`). A null-return-path message (`MAIL FROM:<>`)
//! is by definition a bounce or other automatic message: generating a DSN
//! for it would risk a mail loop, so [`DsnGenerator::generate`] refuses
//! outright ([`DsnError::NullReturnPath`], RFC 3464 §3). The generated DSN
//! itself is sent with a null envelope sender (it travels as
//! `envelope_from: None`).
//!
//! Layout (multipart/report; report-type=delivery-status):
//!
//! ```text
//! --boundary
//! Content-Type: text/plain; charset=utf-8          human-readable notice
//! --boundary
//! Content-Type: message/delivery-status            per-recipient fields
//! --boundary
//! Content-Type: message/rfc822                     original HEADERS only
//! --boundary--
//! ```
//!
//! Only the original headers are attached (RFC 3464 §6.1 permits headers-only
//! and it avoids echoing message bodies — and any backscatter payload — to
//! third parties). The attachment is capped at 32 KiB.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// DSN `Action:` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DsnAction {
    Failed,
    Delayed,
    Delivered,
}

impl DsnAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Failed => "failed",
            Self::Delayed => "delayed",
            Self::Delivered => "delivered",
        }
    }
}

/// The per-recipient inputs of one DSN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsnInputs {
    /// Envelope recipient the failure applies to.
    pub final_recipient: String,
    pub action: DsnAction,
    /// Enhanced status (`5.1.1`) or a synthesized equivalent.
    pub status: String,
    /// `Diagnostic-Code:` value, e.g. `smtp; 550 5.1.1 user unknown`.
    pub diagnostic_code: String,
    /// The MX that produced the failure, when one was reached.
    pub remote_mta: Option<String>,
    /// When the message arrived at the relay.
    pub arrival_date: DateTime<Utc>,
    /// Original `Message-ID`, when known.
    pub original_envelope_id: Option<String>,
}

impl DsnInputs {
    /// Build DSN inputs for a give-up after the retry ceiling (status 4.4.7
    /// per RFC 3463 for "delivery time expired").
    pub fn delivery_expired(
        final_recipient: String,
        arrival_date: DateTime<Utc>,
        diagnostic: String,
    ) -> Self {
        Self {
            final_recipient,
            action: DsnAction::Failed,
            status: "4.4.7".to_string(),
            diagnostic_code: diagnostic,
            remote_mta: None,
            arrival_date,
            original_envelope_id: None,
        }
    }
}

/// A generated DSN ready to be queued: null envelope sender, the original
/// envelope sender as recipient, and the raw MIME bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedDsn {
    /// Always `None` — DSNs are sent with `MAIL FROM:<>`.
    pub envelope_from: Option<String>,
    /// The original envelope sender the DSN reports back to.
    pub envelope_to: String,
    /// Raw RFC 5322 message bytes.
    pub message: Vec<u8>,
    /// `Status:` of the reported failure (for logging/records).
    pub status: String,
}

/// DSN construction failure.
#[derive(Debug, thiserror::Error)]
pub enum DsnError {
    #[error("refusing to generate a DSN for a null-return-path message (RFC 3464 §3)")]
    NullReturnPath,
    #[error("original envelope sender '{0}' is not a usable address")]
    InvalidSender(String),
    #[error("DSN requires a final recipient")]
    MissingRecipient,
}

/// Generator carrying the reporting MTA identity.
#[derive(Debug, Clone)]
pub struct DsnGenerator {
    reporting_mta: String,
}

impl DsnGenerator {
    pub fn new(reporting_mta: impl Into<String>) -> Self {
        Self {
            reporting_mta: reporting_mta.into(),
        }
    }

    pub fn reporting_mta(&self) -> &str {
        &self.reporting_mta
    }

    /// Generate the DSN for one permanent failure.
    ///
    /// `original_sender` is the ORIGINAL message's envelope sender; `None`
    /// (or empty) means a null return path and is refused.
    pub fn generate(
        &self,
        inputs: &DsnInputs,
        original_sender: Option<&str>,
        original_message: &[u8],
    ) -> Result<GeneratedDsn, DsnError> {
        let sender = original_sender
            .map(str::trim)
            .filter(|sender| !sender.is_empty())
            .ok_or(DsnError::NullReturnPath)?;
        if !is_usable_address(sender) {
            return Err(DsnError::InvalidSender(sender.to_string()));
        }
        if inputs.final_recipient.trim().is_empty() {
            return Err(DsnError::MissingRecipient);
        }

        let boundary = format!("apexmail-dsn-{}", Uuid::new_v4().simple());
        let message_id = format!("<{boundary}@{}>", self.reporting_mta);
        // Sanitize ONCE so no use of the diagnostic (header field or
        // human-readable part) can smuggle a line break into the message.
        let diagnostic = sanitize_header_value(&inputs.diagnostic_code);
        let mut message = String::new();

        message.push_str(&format!(
            "From: Mail Delivery Subsystem <MAILER-DAEMON@{}>\r\n",
            self.reporting_mta
        ));
        message.push_str(&format!("To: <{}>\r\n", sender));
        message.push_str("Subject: Delivery Status Notification (Failure)\r\n");
        message.push_str(&format!("Date: {}\r\n", Utc::now().to_rfc2822()));
        message.push_str(&format!("Message-ID: {message_id}\r\n"));
        message.push_str("MIME-Version: 1.0\r\n");
        message.push_str("Auto-Submitted: auto-replied\r\n");
        message.push_str(&format!(
            "Content-Type: multipart/report; report-type=delivery-status;\r\n\tboundary=\"{boundary}\"\r\n"
        ));
        message.push_str("\r\n");
        message.push_str("This is a MIME-encapsulated message.\r\n");

        // ── human-readable part ──────────────────────────────────────────
        message.push_str(&format!("\r\n--{boundary}\r\n"));
        message.push_str("Content-Type: text/plain; charset=utf-8\r\n");
        message.push_str("Content-Transfer-Encoding: 7bit\r\n\r\n");
        message.push_str(&format!(
            "This is the mail system at host {}.\r\n\r\n",
            self.reporting_mta
        ));
        message.push_str(
            "I'm sorry to have to inform you that your message could not\r\n\
             be delivered to one or more recipients.\r\n\r\n",
        );
        message.push_str(&format!("<{}>: {diagnostic}\r\n", inputs.final_recipient));

        // ── message/delivery-status part ─────────────────────────────────
        message.push_str(&format!("\r\n--{boundary}\r\n"));
        message.push_str("Content-Type: message/delivery-status\r\n\r\n");
        message.push_str(&format!("Reporting-MTA: dns; {}\r\n", self.reporting_mta));
        message.push_str(&format!(
            "Arrival-Date: {}\r\n",
            inputs.arrival_date.to_rfc2822()
        ));
        if let Some(original_id) = &inputs.original_envelope_id {
            message.push_str(&format!("Original-Envelope-Id: {original_id}\r\n"));
        }
        if let Some(remote_mta) = &inputs.remote_mta {
            message.push_str(&format!("Remote-MTA: dns; {remote_mta}\r\n"));
        }
        message.push_str("\r\n");
        message.push_str(&format!(
            "Final-Recipient: rfc822; {}\r\n",
            inputs.final_recipient
        ));
        message.push_str(&format!("Action: {}\r\n", inputs.action.as_str()));
        message.push_str(&format!("Status: {}\r\n", inputs.status));
        message.push_str(&format!("Diagnostic-Code: {diagnostic}\r\n"));

        // ── original headers (message/rfc822) ────────────────────────────
        let headers = extract_original_headers(original_message, MAX_RETURNED_HEADERS_BYTES);
        if !headers.is_empty() {
            message.push_str(&format!("\r\n--{boundary}\r\n"));
            message.push_str("Content-Type: message/rfc822\r\n\r\n");
            message.push_str(&headers);
            if !headers.ends_with("\r\n") {
                message.push_str("\r\n");
            }
        }

        message.push_str(&format!("\r\n--{boundary}--\r\n"));

        Ok(GeneratedDsn {
            envelope_from: None,
            envelope_to: sender.to_string(),
            message: message.into_bytes(),
            status: inputs.status.clone(),
        })
    }
}

/// Maximum number of original-header bytes attached to a DSN.
const MAX_RETURNED_HEADERS_BYTES: usize = 32 * 1024;

/// Take the header section (up to the first blank line) of the original
/// message, capped and CRLF-normalized. Never returns body content.
pub fn extract_original_headers(message: &[u8], budget: usize) -> String {
    let mut out = String::new();
    let mut index = 0usize;
    while index < message.len() && out.len() < budget {
        let (line_end, next_index) = match message[index..].iter().position(|byte| *byte == b'\n') {
            Some(offset) => {
                let end = index + offset;
                let line_end = if end > index && message[end - 1] == b'\r' {
                    end - 1
                } else {
                    end
                };
                (line_end, end + 1)
            }
            None => (message.len(), message.len()),
        };
        let line = &message[index..line_end];
        if line.is_empty() {
            break; // end of headers
        }
        let text = String::from_utf8_lossy(line);
        // The cap is soft by one line; a single header line is bounded by the
        // SMTP line limit anyway.
        if out.len() + text.len() + 2 > budget {
            break;
        }
        out.push_str(&text);
        out.push_str("\r\n");
        index = next_index;
    }
    out
}

/// Strip CR/LF (and collapse runs) so a diagnostic string can never inject
/// headers or extra lines into the DSN.
fn sanitize_header_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Loose address sanity check: exactly one `@`, non-empty local and domain,
/// no whitespace/control characters.
fn is_usable_address(address: &str) -> bool {
    if address.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    match address.rsplit_once('@') {
        Some((local, domain)) => !local.is_empty() && !domain.is_empty() && domain.contains('.'),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::SmtpReply;

    fn inputs() -> DsnInputs {
        DsnInputs {
            final_recipient: "user@example.com".to_string(),
            action: DsnAction::Failed,
            status: "5.1.1".to_string(),
            diagnostic_code: "smtp; 550 5.1.1 user unknown".to_string(),
            remote_mta: Some("mx.example.com".to_string()),
            arrival_date: Utc::now(),
            original_envelope_id: Some("msg-42".to_string()),
        }
    }

    #[test]
    fn generates_rfc3464_multipart_report() {
        let generator = DsnGenerator::new("relay.apexmail.ee");
        let original = b"From: sender@apexmail.ee\r\nTo: user@example.com\r\nSubject: hi\r\n\r\nbody text must not leak\r\n";
        let dsn = generator
            .generate(&inputs(), Some("sender@apexmail.ee"), original)
            .expect("DSN generation");
        let text = String::from_utf8(dsn.message.clone()).expect("utf8");
        assert_eq!(dsn.envelope_from, None);
        assert_eq!(dsn.envelope_to, "sender@apexmail.ee");
        assert!(text.contains("Content-Type: multipart/report; report-type=delivery-status"));
        assert!(text.contains("Content-Type: message/delivery-status"));
        assert!(text.contains("Content-Type: message/rfc822"));
        assert!(text.contains("Reporting-MTA: dns; relay.apexmail.ee"));
        assert!(text.contains("Final-Recipient: rfc822; user@example.com"));
        assert!(text.contains("Action: failed"));
        assert!(text.contains("Status: 5.1.1"));
        assert!(text.contains("Diagnostic-Code: smtp; 550 5.1.1 user unknown"));
        assert!(text.contains("Remote-MTA: dns; mx.example.com"));
        assert!(text.contains("Subject: hi"));
        assert!(!text.contains("body text must not leak"));
        assert!(text.trim_end().ends_with("--"));
    }

    #[test]
    fn null_return_path_is_refused() {
        let generator = DsnGenerator::new("relay.apexmail.ee");
        let error = generator
            .generate(&inputs(), None, b"From: x\r\n\r\n")
            .expect_err("null return path must refuse");
        assert!(matches!(error, DsnError::NullReturnPath));
        let error = generator
            .generate(&inputs(), Some("   "), b"From: x\r\n\r\n")
            .expect_err("blank sender must refuse");
        assert!(matches!(error, DsnError::NullReturnPath));
    }

    #[test]
    fn invalid_sender_is_refused() {
        let generator = DsnGenerator::new("relay.apexmail.ee");
        let error = generator
            .generate(&inputs(), Some("not-an-address"), b"")
            .expect_err("invalid sender");
        assert!(matches!(error, DsnError::InvalidSender(_)));
    }

    #[test]
    fn header_extraction_stops_at_body_and_caps_budget() {
        let message = b"From: a@b.c\r\nX-Long: 1234567890\r\n\r\nbody";
        let headers = extract_original_headers(message, 1024);
        assert!(headers.contains("From: a@b.c"));
        assert!(headers.contains("X-Long: 1234567890"));
        assert!(!headers.contains("body"));

        let capped = extract_original_headers(message, 12);
        assert!(capped.len() <= 12);
    }

    #[test]
    fn diagnostic_newlines_are_sanitized() {
        let generator = DsnGenerator::new("relay.apexmail.ee");
        let mut evil = inputs();
        evil.diagnostic_code = "smtp; 550 evil\r\nX-Injected: yes".to_string();
        let dsn = generator
            .generate(&evil, Some("sender@apexmail.ee"), b"")
            .expect("DSN");
        let text = String::from_utf8(dsn.message).expect("utf8");
        // No CRLF survives, so no header can be injected...
        assert!(!text.contains("\r\nX-Injected"));
        // ...the text is folded into the Diagnostic-Code value instead.
        assert!(text.contains("Diagnostic-Code: smtp; 550 evil X-Injected: yes"));
    }

    #[test]
    fn permanent_dsn_inputs_use_enhanced_status() {
        let reply = SmtpReply::parse("550 5.1.1 user unknown").expect("reply");
        let built = reply
            .permanent_dsn_inputs(
                "user@example.com".to_string(),
                Some("mx.example.com".to_string()),
                Utc::now(),
                None,
            )
            .expect("a 5xx produces DSN inputs");
        assert_eq!(built.status, "5.1.1");
        assert_eq!(built.diagnostic_code, "smtp; 550 5.1.1 user unknown");
        assert_eq!(built.action, DsnAction::Failed);

        // A transient reply must not produce DSN inputs.
        let transient = SmtpReply::parse("450 4.2.1 busy").expect("reply");
        assert!(transient
            .permanent_dsn_inputs("user@example.com".to_string(), None, Utc::now(), None)
            .is_none());
    }
}
