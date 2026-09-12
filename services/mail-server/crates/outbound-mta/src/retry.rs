//! Classified retry policy.
//!
//! Every delivery attempt ends in exactly one of three classes, decided here
//! and persisted by the ledger:
//!
//! * [`FailureDisposition::Retry`] — connection failures, timeouts, protocol
//!   errors and 4xx replies. Retried with exponential backoff until the
//!   bounded `max_attempts` ceiling.
//! * [`FailureDisposition::PermanentRecipient`] — a 5xx at `RCPT TO`: that
//!   recipient is failed (DSN due); other recipients of the same message are
//!   unaffected.
//! * [`FailureDisposition::PermanentMessage`] — a 5xx at `MAIL FROM`, after
//!   `DATA`, a null/no MX domain, or the retry ceiling itself: the whole
//!   message is rejected and never retried.
//!
//! `next_attempt_at` and `attempt` are persisted on the ledger row; the
//! backoff ladder is deterministic (base * multiplier^(attempt-1), capped)
//! so a restart recomputes the same schedule.

use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::response::SmtpReply;

/// Stage of an attempt that failed. Non-SMTP stages (resolve/connect) are
/// included so a failure can always name where it happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptStage {
    Resolve,
    Connect,
    Greeting,
    Ehlo,
    StartTls,
    MailFrom,
    RcptTo,
    EndOfData,
}

impl std::fmt::Display for AttemptStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AttemptStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Resolve => "MX resolution",
            Self::Connect => "connect",
            Self::Greeting => "greeting",
            Self::Ehlo => "EHLO",
            Self::StartTls => "STARTTLS",
            Self::MailFrom => "MAIL FROM",
            Self::RcptTo => "RCPT TO",
            Self::EndOfData => "end-of-DATA",
        }
    }
}

/// The classified failure of one delivery attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryFailure {
    /// Connection/timeout/4xx — retry with backoff.
    Transient {
        mx: Option<String>,
        stage: AttemptStage,
        message: String,
    },
    /// The submission requested a source IP that could not be bound AND
    /// verified. Refused before DATA; retryable (the IP may be attached
    /// later), never a silent send from the wrong address.
    SourceIpUnverified { requested: IpAddr, message: String },
    /// TLS is required by policy but the peer cannot negotiate it. Refused
    /// before DATA; retryable (the peer may begin advertising STARTTLS),
    /// never downgraded to cleartext.
    TlsRequiredUnavailable { mx: String, message: String },
    /// 5xx at RCPT TO — permanent for this recipient only.
    RecipientRejected {
        mx: String,
        recipient: String,
        reply: SmtpReply,
    },
    /// 5xx at MAIL FROM or after DATA — permanent for the whole message.
    MessageRejected { mx: String, reply: SmtpReply },
    /// No MX / Null MX / invalid recipient domain — permanent.
    DomainUndeliverable { domain: String, message: String },
    /// Every MX answered 5xx to greeting/EHLO/STARTTLS.
    AllMxRefused { message: String },
    /// The bounded attempt ceiling was reached.
    RetryCeilingExhausted { attempt: u32, message: String },
}

/// The retry decision for a classified failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureDisposition {
    /// Retry the same send unit with backoff.
    Retry,
    /// Permanently fail this one recipient (DSN due).
    PermanentRecipient(String),
    /// Permanently reject the whole message (DSN due).
    PermanentMessage,
}

impl DeliveryFailure {
    /// See the module docs for the policy this implements.
    pub fn disposition(&self) -> FailureDisposition {
        match self {
            Self::Transient { .. }
            | Self::SourceIpUnverified { .. }
            | Self::TlsRequiredUnavailable { .. } => FailureDisposition::Retry,
            Self::RecipientRejected { recipient, .. } => {
                FailureDisposition::PermanentRecipient(recipient.clone())
            }
            Self::MessageRejected { .. }
            | Self::DomainUndeliverable { .. }
            | Self::AllMxRefused { .. }
            | Self::RetryCeilingExhausted { .. } => FailureDisposition::PermanentMessage,
        }
    }

    /// The MX this failure happened at, when one was reached.
    pub fn mx(&self) -> Option<&str> {
        match self {
            Self::Transient { mx, .. } => mx.as_deref(),
            Self::TlsRequiredUnavailable { mx, .. } => Some(mx),
            Self::RecipientRejected { mx, .. } | Self::MessageRejected { mx, .. } => Some(mx),
            Self::SourceIpUnverified { .. }
            | Self::DomainUndeliverable { .. }
            | Self::AllMxRefused { .. }
            | Self::RetryCeilingExhausted { .. } => None,
        }
    }

    /// One-line operator-facing summary, persisted as `last_error`.
    pub fn summary(&self) -> String {
        match self {
            Self::Transient {
                mx,
                stage,
                message,
            } => match mx {
                Some(mx) => format!("transient failure at {mx} during {stage}: {message}"),
                None => format!("transient failure during {stage}: {message}"),
            },
            Self::SourceIpUnverified { requested, message } => format!(
                "source IP {requested} could not be bound and verified (refused before DATA): {message}"
            ),
            Self::TlsRequiredUnavailable { mx, message } => format!(
                "TLS is required but unavailable at {mx} (refused before DATA): {message}"
            ),
            Self::RecipientRejected {
                mx,
                recipient,
                reply,
            } => format!(
                "recipient {recipient} permanently rejected by {mx}: {}",
                reply.diagnostic()
            ),
            Self::MessageRejected { mx, reply } => {
                format!("message permanently rejected by {mx}: {}", reply.diagnostic())
            }
            Self::DomainUndeliverable { domain, message } => {
                format!("domain {domain} is undeliverable: {message}")
            }
            Self::AllMxRefused { message } => format!("all MX hosts refused the message: {message}"),
            Self::RetryCeilingExhausted { attempt, message } => {
                format!("retry ceiling reached after {attempt} attempts: {message}")
            }
        }
    }
}

/// Bounded exponential backoff: `base * multiplier^(attempts-1)`, capped at
/// `max_delay`. Attempt 1 failing schedules the first retry after `base`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Hard ceiling on delivery attempts (including the inline submission).
    pub max_attempts: u32,
    pub base_delay_secs: u64,
    pub max_delay_secs: u64,
    pub multiplier: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        // 5m, 10m, 20m, 40m, 80m, 160m, then capped at 4h. 12 attempts spans
        // roughly 24h before the unit is dead-lettered.
        Self {
            max_attempts: 12,
            base_delay_secs: 300,
            max_delay_secs: 4 * 60 * 60,
            multiplier: 2,
        }
    }
}

impl RetryPolicy {
    /// Backoff to apply after `attempts_made` failed attempts.
    pub fn backoff(&self, attempts_made: u32) -> Duration {
        if attempts_made == 0 {
            return Duration::from_secs(0);
        }
        // Cap the exponent so saturating_pow can never overflow/panic.
        let exponent = attempts_made.saturating_sub(1).min(32);
        let factor = (self.multiplier.max(1) as u64).saturating_pow(exponent);
        let seconds = self
            .base_delay_secs
            .saturating_mul(factor)
            .min(self.max_delay_secs);
        Duration::from_secs(seconds)
    }

    /// `Some(next)` when another attempt may run; `None` when the ceiling is
    /// reached and the unit must be dead-lettered.
    pub fn next_attempt_at(&self, attempts_made: u32, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        if attempts_made >= self.max_attempts {
            return None;
        }
        let delay = chrono::Duration::from_std(self.backoff(attempts_made)).ok()?;
        now.checked_add_signed(delay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(code: u16, text: &str) -> SmtpReply {
        SmtpReply::parse(&format!("{code} {text}")).expect("reply parses")
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.backoff(0), Duration::from_secs(0));
        assert_eq!(policy.backoff(1), Duration::from_secs(300));
        assert_eq!(policy.backoff(2), Duration::from_secs(600));
        assert_eq!(policy.backoff(3), Duration::from_secs(1200));
        assert_eq!(policy.backoff(4), Duration::from_secs(2400));
        assert_eq!(policy.backoff(5), Duration::from_secs(4800));
        assert_eq!(policy.backoff(6), Duration::from_secs(9600));
        // 300 * 2^6 = 19200 > 14400 cap.
        assert_eq!(policy.backoff(7), Duration::from_secs(14_400));
        assert_eq!(policy.backoff(100), Duration::from_secs(14_400));
    }

    #[test]
    fn ceiling_bounds_attempts_and_next_attempt_is_monotonic() {
        let policy = RetryPolicy {
            max_attempts: 3,
            base_delay_secs: 10,
            max_delay_secs: 100,
            multiplier: 2,
        };
        let now = Utc::now();
        assert!(policy.next_attempt_at(0, now).is_some());
        assert!(policy.next_attempt_at(1, now).is_some());
        assert!(policy.next_attempt_at(2, now).is_some());
        assert!(policy.next_attempt_at(3, now).is_none());
        assert!(policy.next_attempt_at(99, now).is_none());

        let first = policy.next_attempt_at(1, now).expect("some");
        let second = policy.next_attempt_at(2, now).expect("some");
        assert!(second > first);
    }

    #[test]
    fn disposition_table_matches_policy() {
        let transient = DeliveryFailure::Transient {
            mx: Some("mx.example".into()),
            stage: AttemptStage::Connect,
            message: "timed out".into(),
        };
        assert_eq!(transient.disposition(), FailureDisposition::Retry);

        let ip = DeliveryFailure::SourceIpUnverified {
            requested: "203.0.113.9".parse().expect("ip"),
            message: "EADDRNOTAVAIL".into(),
        };
        assert_eq!(ip.disposition(), FailureDisposition::Retry);

        let tls = DeliveryFailure::TlsRequiredUnavailable {
            mx: "mx.example".into(),
            message: "no STARTTLS".into(),
        };
        assert_eq!(tls.disposition(), FailureDisposition::Retry);

        let rcpt = DeliveryFailure::RecipientRejected {
            mx: "mx.example".into(),
            recipient: "user@example.com".into(),
            reply: reply(550, "5.1.1 no such user"),
        };
        assert_eq!(
            rcpt.disposition(),
            FailureDisposition::PermanentRecipient("user@example.com".into())
        );

        let message = DeliveryFailure::MessageRejected {
            mx: "mx.example".into(),
            reply: reply(554, "5.7.1 rejected"),
        };
        assert_eq!(message.disposition(), FailureDisposition::PermanentMessage);

        let no_mx = DeliveryFailure::DomainUndeliverable {
            domain: "example.com".into(),
            message: "no MX".into(),
        };
        assert_eq!(no_mx.disposition(), FailureDisposition::PermanentMessage);

        let exhausted = DeliveryFailure::RetryCeilingExhausted {
            attempt: 12,
            message: "too many".into(),
        };
        assert_eq!(
            exhausted.disposition(),
            FailureDisposition::PermanentMessage
        );
    }

    #[test]
    fn summaries_name_the_stage_and_mx() {
        let failure = DeliveryFailure::Transient {
            mx: Some("mx.example".into()),
            stage: AttemptStage::RcptTo,
            message: "greylisted".into(),
        };
        let summary = failure.summary();
        assert!(summary.contains("mx.example"));
        assert!(summary.contains("RCPT TO"));
    }
}
