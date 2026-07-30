use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageTimeline {
    pub request_id: String,
    pub message_id: String,
    pub stream: String,
    pub accepted_time: DateTime<Utc>,
    pub validation: ValidationResult,
    pub queue_time: Option<DateTime<Utc>>,
    pub scheduled_time: Option<DateTime<Utc>>,
    pub sending_ip: Option<String>,
    pub sending_pool: Option<String>,
    pub dkim_selector: Option<String>,
    pub attempt_count: u32,
    pub destination_mx: Option<String>,
    pub smtp_response: Option<SmtpResponse>,
    pub tls: Option<TlsInfo>,
    pub deferral_reason: Option<DeferralReason>,
    pub next_retry: Option<DateTime<Utc>>,
    pub final_state: Option<FinalDeliveryState>,
    pub webhook_attempts: Vec<WebhookAttempt>,
    pub suppression: Option<SuppressionDecision>,
    pub open_events: Vec<OpenEvent>,
    pub click_events: Vec<ClickEvent>,
    pub events: Vec<MessageEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub passed: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub completed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpResponse {
    pub code: u16,
    pub enhanced_code: Option<String>,
    pub message: String,
    pub received_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    pub version: String,
    pub cipher: String,
    pub verified: bool,
    pub certificate_issuer: Option<String>,
    pub certificate_expiry: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeferralReason {
    pub classification: BounceClassification,
    pub detail: String,
    pub suggested_action: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalDeliveryState {
    Delivered,
    Bounced,
    Deferred,
    Failed,
    Cancelled,
}

impl std::fmt::Display for FinalDeliveryState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Delivered => "delivered",
            Self::Bounced => "bounced",
            Self::Deferred => "deferred",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BounceClassification {
    InvalidMailbox,
    MailboxFull,
    PolicyRejection,
    ReputationRejection,
    AuthFailure,
    RateLimited,
    ContentRejection,
    BlocklistRejection,
    DomainFailure,
    Greylisting,
    Unknown,
}

impl BounceClassification {
    pub fn description(&self) -> &'static str {
        match self {
            Self::InvalidMailbox => "The recipient mailbox does not exist or cannot receive mail.",
            Self::MailboxFull => "The recipient mailbox has exceeded its storage quota.",
            Self::PolicyRejection => "The receiving server rejected the message based on its policy.",
            Self::ReputationRejection => "The message was rejected due to sender reputation.",
            Self::AuthFailure => "Authentication (SPF/DKIM/DMARC) failed for this message.",
            Self::RateLimited => "The sending rate exceeded the receiving server's threshold.",
            Self::ContentRejection => "The message content triggered a rejection rule on the receiving server.",
            Self::BlocklistRejection => "The sending IP or domain is listed on a blocklist.",
            Self::DomainFailure => "The recipient domain is invalid or does not accept email.",
            Self::Greylisting => "The receiving server has temporarily deferred the message (greylisting).",
            Self::Unknown => "The bounce reason could not be classified into a known category.",
        }
    }

    pub fn suggested_action(&self) -> &'static str {
        match self {
            Self::InvalidMailbox => "Remove the recipient from your list or verify the address.",
            Self::MailboxFull => "Retry later; the recipient may clear space. Review if persistent.",
            Self::PolicyRejection => "Review the receiving server's policies and adjust your configuration.",
            Self::ReputationRejection => "Improve sending practices, warm up IPs, and reduce complaint rates.",
            Self::AuthFailure => "Verify SPF, DKIM, and DMARC records are correctly configured.",
            Self::RateLimited => "Reduce sending rate to this domain and implement queue awareness.",
            Self::ContentRejection => "Review message content for spam triggers or blocked URLs.",
            Self::BlocklistRejection => "Request delisting and address the root cause of the listing.",
            Self::DomainFailure => "Verify the recipient domain is valid and accepting mail.",
            Self::Greylisting => "The message will be retried automatically. No action needed unless persistent.",
            Self::Unknown => "Investigate SMTP logs and consider contacting the receiving provider.",
        }
    }

    pub fn from_smtp_response(code: u16, message: &str) -> Self {
        match code {
            550 => {
                let lower = message.to_lowercase();
                if lower.contains("mailbox") && lower.contains("not found") {
                    Self::InvalidMailbox
                } else if lower.contains("full") || lower.contains("quota") {
                    Self::MailboxFull
                } else if lower.contains("block") || lower.contains("spam") || lower.contains("blacklist") {
                    Self::BlocklistRejection
                } else if lower.contains("domain") {
                    Self::DomainFailure
                } else {
                    Self::PolicyRejection
                }
            }
            551 | 552 => Self::MailboxFull,
            553 => Self::InvalidMailbox,
            554 => {
                let lower = message.to_lowercase();
                if lower.contains("block") || lower.contains("spam") {
                    Self::BlocklistRejection
                } else {
                    Self::PolicyRejection
                }
            }
            450 | 451 | 452 => Self::Greylisting,
            421 => Self::RateLimited,
            _ => Self::Unknown,
        }
    }
}

impl std::fmt::Display for BounceClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::InvalidMailbox => "invalid_mailbox",
            Self::MailboxFull => "mailbox_full",
            Self::PolicyRejection => "policy_rejection",
            Self::ReputationRejection => "reputation_rejection",
            Self::AuthFailure => "auth_failure",
            Self::RateLimited => "rate_limited",
            Self::ContentRejection => "content_rejection",
            Self::BlocklistRejection => "blocklist_rejection",
            Self::DomainFailure => "domain_failure",
            Self::Greylisting => "greylisting",
            Self::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookAttempt {
    pub attempt_number: u32,
    pub url: String,
    pub status_code: Option<u16>,
    pub response_body: Option<String>,
    pub success: bool,
    pub attempted_at: DateTime<Utc>,
    pub latency_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionDecision {
    pub suppressed: bool,
    pub reason: Option<String>,
    pub rule_id: Option<String>,
    pub checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenEvent {
    pub event_id: String,
    pub occurred_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub is_unique: bool,
    pub is_bot: bool,
    pub is_apple_privacy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickEvent {
    pub event_id: String,
    pub url: String,
    pub occurred_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub is_unique: bool,
    pub is_bot: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MessageEvent {
    Accepted {
        occurred_at: DateTime<Utc>,
    },
    Validated {
        passed: bool,
        occurred_at: DateTime<Utc>,
    },
    Queued {
        occurred_at: DateTime<Utc>,
    },
    DeliveryAttempt {
        attempt: u32,
        mx_host: String,
        occurred_at: DateTime<Utc>,
    },
    Deferred {
        reason: String,
        next_retry: DateTime<Utc>,
        occurred_at: DateTime<Utc>,
    },
    Delivered {
        smtp_code: u16,
        occurred_at: DateTime<Utc>,
    },
    Bounced {
        classification: BounceClassification,
        smtp_code: u16,
        occurred_at: DateTime<Utc>,
    },
    Failed {
        reason: String,
        occurred_at: DateTime<Utc>,
    },
    Cancelled {
        reason: String,
        occurred_at: DateTime<Utc>,
    },
    Suppressed {
        reason: String,
        occurred_at: DateTime<Utc>,
    },
    WebhookSent {
        attempt: u32,
        success: bool,
        occurred_at: DateTime<Utc>,
    },
    Opened {
        is_unique: bool,
        occurred_at: DateTime<Utc>,
    },
    Clicked {
        url: String,
        is_unique: bool,
        occurred_at: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageActivitySearchQuery {
    pub message_id: Option<String>,
    pub request_id: Option<String>,
    pub recipient: Option<String>,
    pub sender: Option<String>,
    pub domain: Option<String>,
    pub subject: Option<String>,
    pub tag: Option<String>,
    pub template: Option<String>,
    pub campaign: Option<String>,
    pub subaccount: Option<String>,
    pub ip: Option<String>,
    pub provider: Option<String>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub event_type: Option<String>,
    pub final_state: Option<FinalDeliveryState>,
    pub stream: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

pub const SEARCHABLE_FIELDS: &[&str] = &[
    "message_id",
    "request_id",
    "recipient",
    "sender",
    "domain",
    "subject",
    "tag",
    "template",
    "campaign",
    "subaccount",
    "ip",
    "provider",
    "date",
    "event_type",
    "stream",
    "final_state",
];

impl MessageActivitySearchQuery {
    pub fn searchable_field_names() -> &'static [&'static str] {
        SEARCHABLE_FIELDS
    }
}

impl MessageTimeline {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.final_state,
            Some(FinalDeliveryState::Delivered)
                | Some(FinalDeliveryState::Bounced)
                | Some(FinalDeliveryState::Failed)
                | Some(FinalDeliveryState::Cancelled)
        )
    }

    pub fn is_delivered(&self) -> bool {
        self.final_state == Some(FinalDeliveryState::Delivered)
    }

    pub fn total_attempts(&self) -> u32 {
        self.attempt_count
    }

    pub fn webhook_success_rate(&self) -> f64 {
        if self.webhook_attempts.is_empty() {
            return 1.0;
        }
        let successes = self
            .webhook_attempts
            .iter()
            .filter(|a| a.success)
            .count() as f64;
        successes / self.webhook_attempts.len() as f64
    }

    pub fn total_unique_opens(&self) -> u32 {
        self.open_events.iter().filter(|o| o.is_unique).count() as u32
    }

    pub fn total_unique_clicks(&self) -> u32 {
        self.click_events.iter().filter(|c| c.is_unique).count() as u32
    }

    pub fn plain_language_summary(&self) -> String {
        match &self.final_state {
            Some(FinalDeliveryState::Delivered) => {
                format!("Delivered to {} after {} attempt(s). Accepted by the recipient server, which does not guarantee inbox placement.",
                    self.destination_mx.as_deref().unwrap_or("unknown server"),
                    self.attempt_count)
            }
            Some(FinalDeliveryState::Bounced) => {
                let class = self
                    .deferral_reason
                    .as_ref()
                    .map(|d| d.classification);
                match class {
                    Some(c) => format!(
                        "Bounced permanently ({}) — {}. {}",
                        c,
                        c.description(),
                        c.suggested_action()
                    ),
                    None => format!(
                        "Bounced permanently after {} attempt(s). Check SMTP response for details.",
                        self.attempt_count
                    ),
                }
            }
            Some(FinalDeliveryState::Deferred) => {
                let next = self
                    .next_retry
                    .map(|n| n.to_rfc3339())
                    .unwrap_or_else(|| "unknown".into());
                format!(
                    "Delivery deferred after {} attempt(s). Next retry: {}. Reason: {}",
                    self.attempt_count,
                    next,
                    self.deferral_reason
                        .as_ref()
                        .map(|d| d.detail.as_str())
                        .unwrap_or("unknown")
                )
            }
            Some(FinalDeliveryState::Failed) => {
                format!(
                    "Message failed after {} attempt(s) without successful delivery.",
                    self.attempt_count
                )
            }
            Some(FinalDeliveryState::Cancelled) => {
                "Message was cancelled before final delivery.".to_string()
            }
            None => {
                if self.attempt_count > 0 {
                    "Delivery is in progress.".to_string()
                } else {
                    "Message accepted and awaiting queue processing.".to_string()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_timeline(state: Option<FinalDeliveryState>) -> MessageTimeline {
        MessageTimeline {
            request_id: "req_01".into(),
            message_id: "msg_01".into(),
            stream: "transactional".into(),
            accepted_time: Utc::now(),
            validation: ValidationResult {
                passed: true,
                errors: vec![],
                warnings: vec![],
                completed_at: Utc::now(),
            },
            queue_time: Some(Utc::now()),
            scheduled_time: None,
            sending_ip: Some("192.0.2.1".into()),
            sending_pool: Some("shared-1".into()),
            dkim_selector: Some("apexmail".into()),
            attempt_count: 1,
            destination_mx: Some("mx.example.com".into()),
            smtp_response: Some(SmtpResponse {
                code: 250,
                enhanced_code: Some("2.0.0".into()),
                message: "OK".into(),
                received_at: Utc::now(),
            }),
            tls: Some(TlsInfo {
                version: "TLSv1.3".into(),
                cipher: "TLS_AES_256_GCM_SHA384".into(),
                verified: true,
                certificate_issuer: Some("Let's Encrypt".into()),
                certificate_expiry: Some(Utc::now() + chrono::Duration::days(90)),
            }),
            deferral_reason: None,
            next_retry: None,
            final_state: state,
            webhook_attempts: vec![],
            suppression: None,
            open_events: vec![],
            click_events: vec![],
            events: vec![],
        }
    }

    #[test]
    fn test_is_terminal_delivered() {
        let timeline = make_timeline(Some(FinalDeliveryState::Delivered));
        assert!(timeline.is_terminal());
    }

    #[test]
    fn test_is_terminal_queued_is_not() {
        let timeline = make_timeline(None);
        assert!(!timeline.is_terminal());
    }

    #[test]
    fn test_plain_language_summary_delivered() {
        let timeline = make_timeline(Some(FinalDeliveryState::Delivered));
        let summary = timeline.plain_language_summary();
        assert!(summary.contains("Accepted by the recipient server"));
        assert!(summary.contains("not guarantee inbox placement"));
    }

    #[test]
    fn test_bounce_classification_from_smtp_550_mailbox_not_found() {
        let class = BounceClassification::from_smtp_response(550, "mailbox not found");
        assert_eq!(class, BounceClassification::InvalidMailbox);
    }

    #[test]
    fn test_bounce_classification_has_all_variants_in_description() {
        let variants = [
            BounceClassification::InvalidMailbox,
            BounceClassification::MailboxFull,
            BounceClassification::PolicyRejection,
            BounceClassification::ReputationRejection,
            BounceClassification::AuthFailure,
            BounceClassification::RateLimited,
            BounceClassification::ContentRejection,
            BounceClassification::BlocklistRejection,
            BounceClassification::DomainFailure,
            BounceClassification::Greylisting,
            BounceClassification::Unknown,
        ];
        for variant in &variants {
            assert!(!variant.description().is_empty());
            assert!(!variant.suggested_action().is_empty());
        }
    }
}
