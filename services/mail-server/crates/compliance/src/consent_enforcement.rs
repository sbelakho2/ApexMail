//! Send-time consent enforcement for GDPR, CASL, LGPD, PDPA, POPIA, CAN-SPAM,
//! and ePrivacy compliance.
//!
//! This module checks consent records and suppression lists at send-time
//! before any email is dispatched. It enforces framework-specific rules:
//!
//! - **GDPR / LGPD**: explicit opt-in required for marketing
//! - **CASL**: express consent required with specific identification
//! - **CAN-SPAM**: no prior consent required, but must honor opt-out
//! - **PDPA / POPIA**: consent-based, similar to GDPR
//!
//! Transactional emails (password reset, billing receipt, account notification)
//! bypass consent on a legitimate interest basis.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::str::FromStr;
use tracing::{debug, info, warn};

use crate::types::{ConsentRecord, ConsentType};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SendDecision {
    Allowed,
    Blocked(String),
    RequiresConfirmation(String),
}

impl SendDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }

    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked(_))
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Allowed => None,
            Self::Blocked(r) | Self::RequiresConfirmation(r) => Some(r),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegulatoryFramework {
    Gdpr,
    Casl,
    CanSpam,
    Lgpd,
    Pdpa,
    Popia,
    EPrivacy,
    Ccpa,
    Iso27001,
    Hipaa,
    Soc2,
}

impl RegulatoryFramework {
    pub fn requires_strict_consent(&self) -> bool {
        matches!(
            self,
            Self::Gdpr | Self::Casl | Self::Lgpd | Self::Pdpa | Self::Popia
        )
    }

    pub fn allows_transactional_bypass(&self) -> bool {
        matches!(
            self,
            Self::Gdpr
                | Self::Casl
                | Self::Lgpd
                | Self::Pdpa
                | Self::Popia
                | Self::CanSpam
                | Self::EPrivacy
                | Self::Ccpa
                | Self::Iso27001
                | Self::Hipaa
                | Self::Soc2
        )
    }

    pub fn requires_suppression_check(&self) -> bool {
        true
    }
}

impl std::fmt::Display for RegulatoryFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Gdpr => "gdpr",
            Self::Casl => "casl",
            Self::CanSpam => "can_spam",
            Self::Lgpd => "lgpd",
            Self::Pdpa => "pdpa",
            Self::Popia => "popia",
            Self::EPrivacy => "eprivacy",
            Self::Ccpa => "ccpa",
            Self::Iso27001 => "iso27001",
            Self::Hipaa => "hipaa",
            Self::Soc2 => "soc2",
        };
        f.write_str(s)
    }
}

impl FromStr for RegulatoryFramework {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "gdpr" => Ok(Self::Gdpr),
            "casl" => Ok(Self::Casl),
            "can_spam" | "canspam" => Ok(Self::CanSpam),
            "lgpd" => Ok(Self::Lgpd),
            "pdpa" => Ok(Self::Pdpa),
            "popia" => Ok(Self::Popia),
            "eprivacy" | "e_privacy" => Ok(Self::EPrivacy),
            "ccpa" => Ok(Self::Ccpa),
            "iso27001" | "iso_27001" => Ok(Self::Iso27001),
            "hipaa" => Ok(Self::Hipaa),
            "soc2" | "soc_2" => Ok(Self::Soc2),
            other => Err(format!("Unknown regulatory framework: {other}")),
        }
    }
}

pub struct ConsentEnforcer {
    db: PgPool,
}

impl ConsentEnforcer {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    pub async fn check_send_allowed(
        &self,
        tenant_id: &str,
        email: &str,
        frameworks: &[RegulatoryFramework],
    ) -> Result<SendDecision, String> {
        let normalized_email = email.trim().to_lowercase();

        let is_suppressed =
            self.check_suppression(tenant_id, &normalized_email).await?;
        if is_suppressed.is_some() {
            let reason = is_suppressed.unwrap();
            warn!(
                tenant_id = %tenant_id,
                email = %mail_common::pii::redact_email(&normalized_email),
                reason = %reason,
                "Send blocked: recipient in suppression list"
            );
            return Ok(SendDecision::Blocked(format!(
                "recipient is in suppression list: {reason}"
            )));
        }

        let consent = self
            .fetch_consent(tenant_id, &normalized_email)
            .await?;

        let has_active_marketing_consent = consent.as_ref().map_or(false, |c| {
            c.granted
                && c.consent_type == ConsentType::Marketing
                && !is_consent_expired(c.expires_at)
        });

        let has_revoked_marketing = consent.as_ref().map_or(false, |c| {
            !c.granted && c.consent_type == ConsentType::Marketing
        });

        let has_expired_marketing = consent.as_ref().map_or(false, |c| {
            c.granted && c.consent_type == ConsentType::Marketing && is_consent_expired(c.expires_at)
        });

        let has_pending_double_opt_in = self
            .check_double_opt_in_pending(tenant_id, &normalized_email)
            .await?;

        let strict_required = frameworks
            .iter()
            .any(|f| f.requires_strict_consent());

        if strict_required {
            if has_revoked_marketing {
                info!(
                    tenant_id = %tenant_id,
                    email = %mail_common::pii::redact_email(&normalized_email),
                    "Send blocked: marketing consent revoked under strict framework"
                );
                return Ok(SendDecision::Blocked(
                    "marketing consent has been revoked — recipient must re-subscribe \
                     via preference center"
                        .into(),
                ));
            }

            if !has_active_marketing_consent {
                if has_pending_double_opt_in {
                    return Ok(SendDecision::RequiresConfirmation(
                        "double opt-in pending — consent not yet confirmed".into(),
                    ));
                }

                if has_expired_marketing {
                    return Ok(SendDecision::RequiresConfirmation(
                        "marketing consent has expired — re-confirmation required".into(),
                    ));
                }

                debug!(
                    tenant_id = %tenant_id,
                    email = %mail_common::pii::redact_email(&normalized_email),
                    "Send blocked: no active marketing consent under strict framework"
                );
                return Ok(SendDecision::Blocked(
                    "no active marketing consent — recipient must opt in via preference center"
                        .into(),
                ));
            }
        }

        if has_revoked_marketing {
            info!(
                tenant_id = %tenant_id,
                email = %mail_common::pii::redact_email(&normalized_email),
                "Send blocked: marketing consent revoked (opt-out honored per CAN-SPAM)"
            );
            return Ok(SendDecision::Blocked(
                "marketing consent revoked — recipient has opted out".into(),
            ));
        }

        if has_pending_double_opt_in {
            return Ok(SendDecision::RequiresConfirmation(
                "double opt-in pending — consent not yet confirmed".into(),
            ));
        }

        if has_expired_marketing {
            return Ok(SendDecision::RequiresConfirmation(
                "marketing consent has expired — re-confirmation required".into(),
            ));
        }

        if !has_active_marketing_consent {
            debug!(
                tenant_id = %tenant_id,
                email = %mail_common::pii::redact_email(&normalized_email),
                "Send blocked: no marketing consent record found"
            );
            return Ok(SendDecision::Blocked(
                "no marketing consent on file — recipient must opt in".into(),
            ));
        }

        Ok(SendDecision::Allowed)
    }

    pub async fn check_send_allowed_with_transactional(
        &self,
        tenant_id: &str,
        email: &str,
        frameworks: &[RegulatoryFramework],
        is_transactional: bool,
        tags: &[String],
        subject: &str,
    ) -> Result<SendDecision, String> {
        let normalized_email = email.trim().to_lowercase();

        let is_suppressed =
            self.check_suppression(tenant_id, &normalized_email).await?;
        if is_suppressed.is_some() {
            let reason = is_suppressed.unwrap();
            warn!(
                tenant_id = %tenant_id,
                email = %mail_common::pii::redact_email(&normalized_email),
                reason = %reason,
                "Send blocked: recipient in suppression list"
            );
            return Ok(SendDecision::Blocked(format!(
                "recipient is in suppression list: {reason}"
            )));
        }

        let transactional = is_transactional_email(is_transactional, tags, subject);

        if transactional {
            let has_transactional_bypass = frameworks
                .iter()
                .all(|f| f.allows_transactional_bypass());
            if has_transactional_bypass {
                debug!(
                    tenant_id = %tenant_id,
                    email = %mail_common::pii::redact_email(&normalized_email),
                    "Transactional email allowed without marketing consent (legitimate interest)"
                );
                return Ok(SendDecision::Allowed);
            }
        }

        let consent = self
            .fetch_consent(tenant_id, &normalized_email)
            .await?;

        let has_active_marketing_consent = consent.as_ref().map_or(false, |c| {
            c.granted
                && c.consent_type == ConsentType::Marketing
                && !is_consent_expired(c.expires_at)
        });

        let has_revoked_marketing = consent.as_ref().map_or(false, |c| {
            !c.granted && c.consent_type == ConsentType::Marketing
        });

        let has_expired_marketing = consent.as_ref().map_or(false, |c| {
            c.granted && c.consent_type == ConsentType::Marketing && is_consent_expired(c.expires_at)
        });

        let has_pending_double_opt_in = self
            .check_double_opt_in_pending(tenant_id, &normalized_email)
            .await?;

        let strict_required = frameworks
            .iter()
            .any(|f| f.requires_strict_consent());

        if strict_required {
            if has_revoked_marketing {
                info!(
                    tenant_id = %tenant_id,
                    email = %mail_common::pii::redact_email(&normalized_email),
                    "Send blocked: marketing consent revoked under strict framework"
                );
                return Ok(SendDecision::Blocked(
                    "marketing consent has been revoked — recipient must re-subscribe \
                     via preference center"
                        .into(),
                ));
            }

            if !has_active_marketing_consent {
                if has_pending_double_opt_in {
                    return Ok(SendDecision::RequiresConfirmation(
                        "double opt-in pending — consent not yet confirmed".into(),
                    ));
                }

                if has_expired_marketing {
                    return Ok(SendDecision::RequiresConfirmation(
                        "marketing consent has expired — re-confirmation required".into(),
                    ));
                }

                debug!(
                    tenant_id = %tenant_id,
                    email = %mail_common::pii::redact_email(&normalized_email),
                    "Send blocked: no active marketing consent under strict framework"
                );
                return Ok(SendDecision::Blocked(
                    "no active marketing consent — recipient must opt in via preference center"
                        .into(),
                ));
            }
        }

        if has_revoked_marketing {
            info!(
                tenant_id = %tenant_id,
                email = %mail_common::pii::redact_email(&normalized_email),
                "Send blocked: marketing consent revoked (opt-out honored per CAN-SPAM)"
            );
            return Ok(SendDecision::Blocked(
                "marketing consent revoked — recipient has opted out".into(),
            ));
        }

        if has_pending_double_opt_in {
            return Ok(SendDecision::RequiresConfirmation(
                "double opt-in pending — consent not yet confirmed".into(),
            ));
        }

        if has_expired_marketing {
            return Ok(SendDecision::RequiresConfirmation(
                "marketing consent has expired — re-confirmation required".into(),
            ));
        }

        if !has_active_marketing_consent {
            debug!(
                tenant_id = %tenant_id,
                email = %mail_common::pii::redact_email(&normalized_email),
                "Send blocked: no marketing consent record found"
            );
            return Ok(SendDecision::Blocked(
                "no marketing consent on file — recipient must opt in".into(),
            ));
        }

        Ok(SendDecision::Allowed)
    }

    async fn check_suppression(
        &self,
        tenant_id: &str,
        email: &str,
    ) -> Result<Option<String>, String> {
        let result: Option<String> = sqlx::query_scalar(
            "SELECT reason FROM suppressions WHERE tenant_id = $1 AND LOWER(email) = $2 LIMIT 1",
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("suppression lookup failed: {e}"))?;

        if result.is_none() {
            let supp_list_reason: Option<String> = sqlx::query_scalar(
                "SELECT reason FROM suppression_list WHERE tenant_id = $1 AND LOWER(email) = $2 LIMIT 1",
            )
            .bind(tenant_id)
            .bind(email)
            .fetch_optional(&self.db)
            .await
            .map_err(|e| format!("suppression_list lookup failed: {e}"))?;
            return Ok(supp_list_reason);
        }

        Ok(result)
    }

    async fn fetch_consent(
        &self,
        tenant_id: &str,
        email: &str,
    ) -> Result<Option<ConsentRecord>, String> {
        let row: Option<(
            String,
            String,
            String,
            String,
            String,
            bool,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<DateTime<Utc>>,
            serde_json::Value,
        )> = sqlx::query_as(
            "SELECT id, tenant_id, subscriber_id, email, consent_type, granted,
                    granted_at, revoked_at, source, ip_address, user_agent,
                    proof_document, expires_at, metadata
             FROM consent_records
             WHERE tenant_id = $1 AND LOWER(email) = $2 AND consent_type = 'marketing'
             ORDER BY granted_at DESC NULLS LAST
             LIMIT 1",
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("consent lookup failed: {e}"))?;

        match row {
            Some((
                id,
                tid,
                subscriber_id,
                record_email,
                consent_type_str,
                granted,
                granted_at,
                revoked_at,
                source_str,
                ip_address,
                user_agent,
                proof_document,
                expires_at,
                metadata,
            )) => {
                let consent_type = match consent_type_str.as_str() {
                    "marketing" => ConsentType::Marketing,
                    "transactional" => ConsentType::Transactional,
                    "analytics" => ConsentType::Analytics,
                    "profiling" => ConsentType::Profiling,
                    "third_party" => ConsentType::ThirdParty,
                    "data_processing" => ConsentType::DataProcessing,
                    _ => ConsentType::Marketing,
                };
                let source = match source_str.as_str() {
                    "form" | "web_form" => crate::types::ConsentSource::Form,
                    "api" => crate::types::ConsentSource::Api,
                    "import" => crate::types::ConsentSource::Import,
                    "double_opt_in" => crate::types::ConsentSource::DoubleOptIn,
                    "preference_center" => crate::types::ConsentSource::PreferenceCenter,
                    "system" => crate::types::ConsentSource::System,
                    _ => crate::types::ConsentSource::Form,
                };

                Ok(Some(ConsentRecord {
                    id,
                    tenant_id: tid,
                    subscriber_id,
                    email: record_email,
                    consent_type,
                    granted,
                    granted_at,
                    revoked_at,
                    source,
                    ip_address,
                    user_agent,
                    proof_document,
                    expires_at,
                    metadata,
                }))
            }
            None => Ok(None),
        }
    }

    async fn check_double_opt_in_pending(
        &self,
        tenant_id: &str,
        email: &str,
    ) -> Result<bool, String> {
        let exists: Option<String> = sqlx::query_scalar(
            "SELECT token_hash FROM double_opt_in_tokens
             WHERE tenant_id = $1 AND LOWER(email) = $2 AND expires_at > NOW()
             LIMIT 1",
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("double_opt_in lookup failed: {e}"))?;

        Ok(exists.is_some())
    }
}

fn is_consent_expired(expires_at: Option<DateTime<Utc>>) -> bool {
    match expires_at {
        Some(expires) => expires < Utc::now(),
        None => false,
    }
}

/// Classify an email as transactional.
///
/// M7: the classification MUST come from an explicit caller declaration
/// (`declared_transactional`). Keyword heuristics over tags/subjects are no
/// longer sufficient to bypass consent — a "welcome" tag on a marketing blast
/// used to silently classify the send as transactional. Default (absent
/// declaration) is NON-transactional, i.e. consent is required.
///
/// The keyword hint is retained only for observability via
/// [`transactional_keyword_hint`].
pub fn is_transactional_email(declared_transactional: bool, tags: &[String], subject: &str) -> bool {
    let _ = (tags, subject);
    declared_transactional
}

/// Best-effort keyword hint (observability only — never an authorization
/// signal). Returns the first keyword found in the tags or subject.
pub fn transactional_keyword_hint(tags: &[String], subject: &str) -> Option<&'static str> {
    const TRANSACTIONAL_KEYWORDS: [&str; 25] = [
        "transactional",
        "password",
        "reset",
        "billing",
        "receipt",
        "invoice",
        "payment",
        "order",
        "confirmation",
        "account",
        "security",
        "verification",
        "notification",
        "login",
        "register",
        "signup",
        "signin",
        "welcome",
        "onboarding",
        "activation",
        "verify",
        "2fa",
        "mfa",
        "otp",
        "auth",
    ];

    for kw in TRANSACTIONAL_KEYWORDS {
        if tags.iter().any(|t| t.to_lowercase().contains(kw)) {
            return Some(kw);
        }
    }
    let subject_lower = subject.to_lowercase();
    TRANSACTIONAL_KEYWORDS
        .into_iter()
        .find(|kw| subject_lower.contains(kw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_decision_is_allowed() {
        assert!(SendDecision::Allowed.is_allowed());
        assert!(!SendDecision::Blocked("no consent".into()).is_allowed());
        assert!(!SendDecision::RequiresConfirmation("expired".into()).is_allowed());
    }

    #[test]
    fn test_send_decision_is_blocked() {
        assert!(SendDecision::Blocked("revoked".into()).is_blocked());
        assert!(!SendDecision::RequiresConfirmation("pending".into()).is_blocked());
        assert!(!SendDecision::Allowed.is_blocked());
    }

    #[test]
    fn test_send_decision_reason() {
        assert_eq!(SendDecision::Allowed.reason(), None);
        assert_eq!(
            SendDecision::Blocked("revoked".into()).reason(),
            Some("revoked")
        );
        assert_eq!(
            SendDecision::RequiresConfirmation("expired".into()).reason(),
            Some("expired")
        );
    }

    #[test]
    fn test_regulatory_framework_requires_strict_consent() {
        assert!(RegulatoryFramework::Gdpr.requires_strict_consent());
        assert!(RegulatoryFramework::Casl.requires_strict_consent());
        assert!(RegulatoryFramework::Lgpd.requires_strict_consent());
        assert!(RegulatoryFramework::Pdpa.requires_strict_consent());
        assert!(RegulatoryFramework::Popia.requires_strict_consent());
        assert!(!RegulatoryFramework::CanSpam.requires_strict_consent());
        assert!(!RegulatoryFramework::EPrivacy.requires_strict_consent());
        assert!(!RegulatoryFramework::Ccpa.requires_strict_consent());
    }

    #[test]
    fn test_regulatory_framework_allows_transactional_bypass() {
        // All frameworks allow transactional bypass
        assert!(RegulatoryFramework::Gdpr.allows_transactional_bypass());
        assert!(RegulatoryFramework::CanSpam.allows_transactional_bypass());
        assert!(RegulatoryFramework::Hipaa.allows_transactional_bypass());
    }

    #[test]
    fn test_regulatory_framework_display() {
        assert_eq!(RegulatoryFramework::Gdpr.to_string(), "gdpr");
        assert_eq!(RegulatoryFramework::Casl.to_string(), "casl");
        assert_eq!(RegulatoryFramework::CanSpam.to_string(), "can_spam");
    }

    #[test]
    fn test_regulatory_framework_from_str() {
        assert_eq!(
            "gdpr".parse::<RegulatoryFramework>().unwrap(),
            RegulatoryFramework::Gdpr
        );
        assert_eq!(
            "casl".parse::<RegulatoryFramework>().unwrap(),
            RegulatoryFramework::Casl
        );
        assert_eq!(
            "can_spam".parse::<RegulatoryFramework>().unwrap(),
            RegulatoryFramework::CanSpam
        );
        assert_eq!(
            "canspam".parse::<RegulatoryFramework>().unwrap(),
            RegulatoryFramework::CanSpam
        );
        assert_eq!(
            "LGPD".parse::<RegulatoryFramework>().unwrap(),
            RegulatoryFramework::Lgpd
        );
        assert!("unknown".parse::<RegulatoryFramework>().is_err());
    }

    // NOTE: these tests previously asserted that transactional *keywords*
    // (tags/subject) alone could classify a send as transactional and bypass
    // consent (M7 finding). They were updated to the fixed contract: only an
    // explicit caller declaration enables the transactional path.
    #[test]
    fn test_is_transactional_email_tags() {
        // Keywords alone must NOT classify the email as transactional.
        assert!(!is_transactional_email(
            false,
            &["transactional".into()],
            "Newsletter issue #42"
        ));
        assert!(!is_transactional_email(
            false,
            &["password-reset".into()],
            "Reset your password"
        ));
        assert!(!is_transactional_email(false, &["billing".into()], "Your invoice"));
        assert!(!is_transactional_email(
            false,
            &["receipt".into()],
            "Order confirmed"
        ));
        assert!(!is_transactional_email(
            false,
            &["marketing".into(), "newsletter".into()],
            "Weekly deals"
        ));
    }

    #[test]
    fn test_is_transactional_email_subject() {
        assert!(!is_transactional_email(false, &[], "Password reset request"));
        assert!(!is_transactional_email(false, &[], "Your billing receipt"));
        assert!(!is_transactional_email(false, &[], "Account notification"));
        assert!(!is_transactional_email(false, &[], "Login verification code"));
        assert!(!is_transactional_email(false, &[], "Big sale this weekend!"));
    }

    #[test]
    fn test_is_transactional_email_empty() {
        assert!(!is_transactional_email(false, &[], ""));
        assert!(!is_transactional_email(false, &[], "Hello World"));
    }

    /// M7: a 'welcome' tag alone must NOT be transactional — consent required.
    #[test]
    fn test_welcome_tag_alone_is_not_transactional() {
        assert!(!is_transactional_email(
            false,
            &["welcome".into()],
            "Welcome to our newsletter!"
        ));
    }

    /// M7: an explicit caller declaration makes the send transactional.
    #[test]
    fn test_explicit_declaration_is_transactional() {
        assert!(is_transactional_email(
            true,
            &["welcome".into()],
            "Welcome to our newsletter!"
        ));
        assert!(is_transactional_email(true, &[], ""));
    }

    /// The keyword hint is observability-only and still detects keywords.
    #[test]
    fn test_transactional_keyword_hint() {
        assert_eq!(
            transactional_keyword_hint(&["welcome".into()], "Hello"),
            Some("welcome")
        );
        assert_eq!(
            transactional_keyword_hint(&[], "Password reset request"),
            Some("password")
        );
        assert_eq!(transactional_keyword_hint(&[], "Big sale!"), None);
    }

    #[test]
    fn test_is_consent_expired() {
        assert!(is_consent_expired(Some(
            Utc::now() - chrono::Duration::days(1)
        )));
        assert!(is_consent_expired(Some(
            Utc::now() - chrono::Duration::hours(1)
        )));
        assert!(!is_consent_expired(Some(
            Utc::now() + chrono::Duration::days(1)
        )));
        assert!(!is_consent_expired(Some(
            Utc::now() + chrono::Duration::hours(1)
        )));
        assert!(!is_consent_expired(None));
    }

    #[test]
    fn test_all_frameworks_parse() {
        let frameworks = [
            "gdpr", "casl", "can_spam", "canspam", "lgpd", "pdpa", "popia",
            "eprivacy", "e_privacy", "ccpa", "iso27001", "iso_27001", "hipaa",
            "soc2", "soc_2",
        ];
        for f in &frameworks {
            assert!(
                f.parse::<RegulatoryFramework>().is_ok(),
                "Failed to parse framework: {f}"
            );
        }
    }

    #[test]
    fn test_requires_strict_consent_all_variants() {
        // Strict consent frameworks
        assert!(RegulatoryFramework::Gdpr.requires_strict_consent());
        assert!(RegulatoryFramework::Casl.requires_strict_consent());
        assert!(RegulatoryFramework::Lgpd.requires_strict_consent());
        assert!(RegulatoryFramework::Pdpa.requires_strict_consent());
        assert!(RegulatoryFramework::Popia.requires_strict_consent());

        // Non-strict frameworks
        assert!(!RegulatoryFramework::CanSpam.requires_strict_consent());
        assert!(!RegulatoryFramework::EPrivacy.requires_strict_consent());
        assert!(!RegulatoryFramework::Ccpa.requires_strict_consent());
        assert!(!RegulatoryFramework::Iso27001.requires_strict_consent());
        assert!(!RegulatoryFramework::Hipaa.requires_strict_consent());
        assert!(!RegulatoryFramework::Soc2.requires_strict_consent());
    }
}
