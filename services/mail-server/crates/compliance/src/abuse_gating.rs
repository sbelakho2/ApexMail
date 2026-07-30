use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountState {
    Sandbox,
    Restricted,
    Warming,
    Normal,
    ReviewRequired,
    Throttled,
    Suspended,
    Terminated,
}

impl AccountState {
    pub fn can_send(&self) -> bool {
        matches!(
            self,
            AccountState::Restricted | AccountState::Warming | AccountState::Normal
        )
    }

    pub fn can_send_unrestricted(&self) -> bool {
        matches!(self, AccountState::Normal)
    }

    pub fn is_active(&self) -> bool {
        !matches!(self, AccountState::Suspended | AccountState::Terminated)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskInputs {
    pub domain_age_days: i64,
    pub website_age_days: i64,
    pub is_disposable_email: bool,
    pub signup_ip_reputation: IpReputation,
    pub is_vpn_or_tor: bool,
    pub signup_velocity: SignupVelocity,
    pub similar_suspended_accounts: u32,
    pub payment_risk: PaymentRisk,
    pub url_reputation: UrlReputation,
    pub attachment_risk: AttachmentRisk,
    pub recipient_pattern_risk: RecipientPatternRisk,
    pub bounce_rate_pct: f64,
    pub complaint_rate_pct: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpReputation {
    Clean,
    LowRisk,
    MediumRisk,
    HighRisk,
    KnownAbusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignupVelocity {
    Normal,
    Elevated,
    Suspicious,
    Automated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentRisk {
    None,
    Low,
    Medium,
    High,
    Fraudulent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UrlReputation {
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentRisk {
    None,
    Low,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipientPatternRisk {
    Normal,
    Suspicious,
    Harvested,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountAssessment {
    pub state: AccountState,
    pub risk_score: u32,
    pub reasons: Vec<String>,
    pub production_approved: bool,
    pub daily_send_limit: Option<u64>,
    pub required_actions: Vec<String>,
    pub assessed_at: DateTime<Utc>,
}

impl RiskInputs {
    fn compute_risk_score(&self) -> u32 {
        let mut score: u32 = 0;
        if self.domain_age_days < 30 {
            score += 15;
        } else if self.domain_age_days < 90 {
            score += 5;
        }
        if self.website_age_days < 30 {
            score += 10;
        } else if self.website_age_days < 90 {
            score += 3;
        }
        if self.is_disposable_email {
            score += 20;
        }
        match self.signup_ip_reputation {
            IpReputation::Clean => {}
            IpReputation::LowRisk => score += 3,
            IpReputation::MediumRisk => score += 8,
            IpReputation::HighRisk => score += 15,
            IpReputation::KnownAbusive => score += 25,
        }
        if self.is_vpn_or_tor {
            score += 10;
        }
        match self.signup_velocity {
            SignupVelocity::Normal => {}
            SignupVelocity::Elevated => score += 5,
            SignupVelocity::Suspicious => score += 10,
            SignupVelocity::Automated => score += 15,
        }
        if self.similar_suspended_accounts > 0 {
            score += 10 * self.similar_suspended_accounts.min(5);
        }
        match self.payment_risk {
            PaymentRisk::None => {}
            PaymentRisk::Low => score += 5,
            PaymentRisk::Medium => score += 10,
            PaymentRisk::High => score += 20,
            PaymentRisk::Fraudulent => score += 30,
        }
        match self.url_reputation {
            UrlReputation::Clean => {}
            UrlReputation::Suspicious => score += 10,
            UrlReputation::Malicious => score += 20,
        }
        match self.attachment_risk {
            AttachmentRisk::None => {}
            AttachmentRisk::Low => score += 5,
            AttachmentRisk::High => score += 15,
        }
        match self.recipient_pattern_risk {
            RecipientPatternRisk::Normal => {}
            RecipientPatternRisk::Suspicious => score += 8,
            RecipientPatternRisk::Harvested => score += 15,
        }
        if self.bounce_rate_pct > 5.0 {
            score += 10;
        } else if self.bounce_rate_pct > 3.0 {
            score += 5;
        }
        if self.complaint_rate_pct > 0.1 {
            score += 15;
        } else if self.complaint_rate_pct > 0.05 {
            score += 5;
        }
        score
    }
}

pub fn check_account_state(inputs: &RiskInputs) -> AccountAssessment {
    let risk_score = inputs.compute_risk_score();
    let mut reasons = Vec::new();
    let mut required_actions = Vec::new();

    if inputs.is_disposable_email {
        reasons.push("Disposable email address detected.".into());
        required_actions.push("Provide a permanent email address.".into());
    }
    if matches!(inputs.signup_ip_reputation, IpReputation::HighRisk | IpReputation::KnownAbusive) {
        reasons.push("Signup IP has high-risk or known-abusive reputation.".into());
        required_actions.push("Manual review of signup IP required.".into());
    }
    if inputs.is_vpn_or_tor {
        reasons.push("VPN or Tor signup detected.".into());
    }
    if matches!(inputs.signup_velocity, SignupVelocity::Suspicious | SignupVelocity::Automated) {
        reasons.push(format!(
            "Suspicious signup velocity detected: {:?}",
            inputs.signup_velocity
        ));
        required_actions.push("Verify identity before proceeding.".into());
    }
    if inputs.similar_suspended_accounts > 0 {
        reasons.push(format!(
            "{} similar suspended account(s) found.",
            inputs.similar_suspended_accounts
        ));
        required_actions.push("Account linked to prior suspensions — manual review required.".into());
    }
    if matches!(inputs.payment_risk, PaymentRisk::High | PaymentRisk::Fraudulent) {
        reasons.push("High payment risk detected.".into());
        required_actions.push("Valid payment method required before production access.".into());
    }
    if matches!(inputs.url_reputation, UrlReputation::Malicious) {
        reasons.push("Malicious URL reputation detected.".into());
        required_actions.push("Remove or replace flagged URLs.".into());
    }
    if inputs.bounce_rate_pct > 5.0 {
        reasons.push(format!(
            "Bounce rate {:.1}% exceeds 5.0% threshold.",
            inputs.bounce_rate_pct
        ));
        required_actions.push("Address list hygiene review required.".into());
    }
    if inputs.complaint_rate_pct > 0.1 {
        reasons.push(format!(
            "Complaint rate {:.2}% exceeds 0.10% threshold.",
            inputs.complaint_rate_pct
        ));
        required_actions.push("Review sending practices and recipient consent.".into());
    }

    let hard_suspend = matches!(inputs.payment_risk, PaymentRisk::Fraudulent)
        || matches!(inputs.signup_ip_reputation, IpReputation::KnownAbusive);
    let state = if hard_suspend {
        AccountState::Suspended
    } else if risk_score >= 50 {
        AccountState::ReviewRequired
    } else if risk_score >= 30 {
        AccountState::Restricted
    } else if risk_score >= 15 {
        AccountState::Sandbox
    } else {
        AccountState::Sandbox
    };

    let daily_send_limit = match state {
        AccountState::Sandbox => Some(50),
        AccountState::Restricted => Some(1_000),
        AccountState::Warming => Some(5_000),
        AccountState::Normal => None,
        AccountState::ReviewRequired => Some(0),
        AccountState::Throttled => Some(100),
        AccountState::Suspended => Some(0),
        AccountState::Terminated => Some(0),
    };

    let production_approved = matches!(state, AccountState::Warming | AccountState::Normal);

    AccountAssessment {
        state,
        risk_score,
        reasons,
        production_approved,
        daily_send_limit,
        required_actions,
        assessed_at: Utc::now(),
    }
}

pub fn require_production_approval(assessment: &AccountAssessment) -> bool {
    if assessment.production_approved {
        return false;
    }
    matches!(
        assessment.state,
        AccountState::Sandbox
            | AccountState::Restricted
            | AccountState::ReviewRequired
            | AccountState::Throttled
            | AccountState::Suspended
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean_inputs() -> RiskInputs {
        RiskInputs {
            domain_age_days: 365,
            website_age_days: 365,
            is_disposable_email: false,
            signup_ip_reputation: IpReputation::Clean,
            is_vpn_or_tor: false,
            signup_velocity: SignupVelocity::Normal,
            similar_suspended_accounts: 0,
            payment_risk: PaymentRisk::None,
            url_reputation: UrlReputation::Clean,
            attachment_risk: AttachmentRisk::None,
            recipient_pattern_risk: RecipientPatternRisk::Normal,
            bounce_rate_pct: 1.0,
            complaint_rate_pct: 0.01,
        }
    }

    #[test]
    fn test_clean_account_goes_to_sandbox() {
        let inputs = clean_inputs();
        let assessment = check_account_state(&inputs);
        assert_eq!(assessment.state, AccountState::Sandbox);
        assert!(!assessment.production_approved);
        assert_eq!(assessment.risk_score, 0);
    }

    #[test]
    fn test_disposable_email_raises_risk() {
        let mut inputs = clean_inputs();
        inputs.is_disposable_email = true;
        let assessment = check_account_state(&inputs);
        assert!(assessment.risk_score >= 20);
        assert!(!assessment.production_approved);
        assert!(require_production_approval(&assessment));
    }

    #[test]
    fn test_known_abusive_ip_causes_suspension() {
        let mut inputs = clean_inputs();
        inputs.signup_ip_reputation = IpReputation::KnownAbusive;
        let assessment = check_account_state(&inputs);
        assert_eq!(assessment.state, AccountState::Suspended);
        assert!(!assessment.production_approved);
    }

    #[test]
    fn test_high_risk_multiple_factors_goes_to_review() {
        let mut inputs = clean_inputs();
        inputs.domain_age_days = 15;
        inputs.is_disposable_email = true;
        inputs.is_vpn_or_tor = true;
        inputs.similar_suspended_accounts = 2;
        let assessment = check_account_state(&inputs);
        assert!(matches!(assessment.state, AccountState::ReviewRequired | AccountState::Suspended));
        assert!(!assessment.production_approved);
    }

    #[test]
    fn test_low_volume_sandbox_daily_limit() {
        let inputs = clean_inputs();
        let assessment = check_account_state(&inputs);
        assert_eq!(assessment.daily_send_limit, Some(50));
    }

    #[test]
    fn test_fraudulent_payment_causes_suspension() {
        let mut inputs = clean_inputs();
        inputs.payment_risk = PaymentRisk::Fraudulent;
        let assessment = check_account_state(&inputs);
        assert_eq!(assessment.state, AccountState::Suspended);
    }

    #[test]
    fn test_restricted_state_has_limit() {
        let mut inputs = clean_inputs();
        inputs.domain_age_days = 20;
        inputs.is_vpn_or_tor = true;
        inputs.signup_velocity = SignupVelocity::Suspicious;
        let assessment = check_account_state(&inputs);
        match assessment.state {
            AccountState::Restricted => {
                assert_eq!(assessment.daily_send_limit, Some(1_000));
            }
            AccountState::ReviewRequired | AccountState::Suspended => {
                assert_eq!(assessment.daily_send_limit, Some(0));
            }
            _ => {}
        }
        assert!(!assessment.production_approved);
    }
}
