use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BillingTerm {
    IncludedEmails,
    BillableEmail,
    AttemptedEmail,
    AcceptedEmail,
    RejectedEmail,
    RetriedEmail,
    DuplicateRequest,
    TestEmail,
    Overage,
    PayAsYouGo,
    DynamicAllocation,
    MonthlyCommitment,
    AnnualCommitment,
    DedicatedIpFee,
    PrivateCloudFee,
    SetupFee,
    SupportFee,
    Tax,
    Credit,
    Refund,
}

impl BillingTerm {
    pub fn term_id(&self) -> &'static str {
        match self {
            Self::IncludedEmails => "BT-001",
            Self::BillableEmail => "BT-002",
            Self::AttemptedEmail => "BT-003",
            Self::AcceptedEmail => "BT-004",
            Self::RejectedEmail => "BT-005",
            Self::RetriedEmail => "BT-006",
            Self::DuplicateRequest => "BT-007",
            Self::TestEmail => "BT-008",
            Self::Overage => "BT-009",
            Self::PayAsYouGo => "BT-010",
            Self::DynamicAllocation => "BT-011",
            Self::MonthlyCommitment => "BT-012",
            Self::AnnualCommitment => "BT-013",
            Self::DedicatedIpFee => "BT-014",
            Self::PrivateCloudFee => "BT-015",
            Self::SetupFee => "BT-016",
            Self::SupportFee => "BT-017",
            Self::Tax => "BT-018",
            Self::Credit => "BT-019",
            Self::Refund => "BT-020",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::IncludedEmails => "Included emails",
            Self::BillableEmail => "Billable email",
            Self::AttemptedEmail => "Attempted email",
            Self::AcceptedEmail => "Accepted email",
            Self::RejectedEmail => "Rejected email",
            Self::RetriedEmail => "Retried email",
            Self::DuplicateRequest => "Duplicate request",
            Self::TestEmail => "Test email",
            Self::Overage => "Overage",
            Self::PayAsYouGo => "Pay-as-you-go",
            Self::DynamicAllocation => "Dynamic allocation",
            Self::MonthlyCommitment => "Monthly commitment",
            Self::AnnualCommitment => "Annual commitment",
            Self::DedicatedIpFee => "Dedicated IP fee",
            Self::PrivateCloudFee => "Private Cloud fee",
            Self::SetupFee => "Setup fee",
            Self::SupportFee => "Support fee",
            Self::Tax => "Tax",
            Self::Credit => "Credit",
            Self::Refund => "Refund",
        }
    }

    pub fn definition(&self) -> &'static str {
        match self {
            Self::IncludedEmails => "Emails within the plan's monthly allowance that do not incur additional per-unit charges.",
            Self::BillableEmail => "An accepted and delivered email that counts toward usage. Rejected, bounced, and suppressed emails are not billable.",
            Self::AttemptedEmail => "Any email submitted through the API or SMTP. Not all attempted emails become billable.",
            Self::AcceptedEmail => "An email that passes API validation, domain verification, and is accepted into the processing queue.",
            Self::RejectedEmail => "An email rejected at the API or SMTP layer due to validation failure, domain issues, or sender authorization. Not billable.",
            Self::RetriedEmail => "An email re-attempted after a transient delivery failure. Retries within the original submission do not create additional billable events.",
            Self::DuplicateRequest => "A request with a previously used idempotency key. Returns the original response without creating a new billable event.",
            Self::TestEmail => "Email sent through a designated test mode or to a verified test address. Not billable.",
            Self::Overage => "Emails sent beyond the included monthly allowance, billed at the plan's per-thousand rate.",
            Self::PayAsYouGo => "Pricing where the customer pays only for usage above the included volume, without a higher fixed plan tier.",
            Self::DynamicAllocation => "Automatic scaling of included volume between plan tiers based on actual usage, without requiring a manual plan change.",
            Self::MonthlyCommitment => "A monthly billing cycle with no long-term commitment. Cancel or downgrade at the end of any billing period.",
            Self::AnnualCommitment => "A 12-month contract with a discount applied. Early termination may incur fees.",
            Self::DedicatedIpFee => "Monthly charge per dedicated IP address. Billed regardless of sending volume. Includes reputation management.",
            Self::PrivateCloudFee => "Monthly platform fee for Private Cloud deployment (Dedicated Tenant or BYOC). Covers software license, operations, and support.",
            Self::SetupFee => "One-time fee for Private Cloud environment provisioning, architecture design, deployment, and integration validation.",
            Self::SupportFee => "Fee for support tiers above the plan's included level. Enterprise and Dedicated Tenant include premium support.",
            Self::Tax => "VAT, GST, or equivalent tax applied according to the customer's billing country and tax status.",
            Self::Credit => "A positive balance applied to future invoices. Credits result from service credits, refunds, or promotional allowances.",
            Self::Refund => "Return of paid funds. Subject to refund policy. Service credits are applied before refunds are issued.",
        }
    }

    pub fn billability(&self) -> BillingImpact {
        match self {
            Self::IncludedEmails => BillingImpact::Neutral,
            Self::BillableEmail => BillingImpact::Charged,
            Self::AttemptedEmail => BillingImpact::Conditional,
            Self::AcceptedEmail => BillingImpact::Threshold,
            Self::RejectedEmail => BillingImpact::NoCharge,
            Self::RetriedEmail => BillingImpact::NoCharge,
            Self::DuplicateRequest => BillingImpact::NoCharge,
            Self::TestEmail => BillingImpact::NoCharge,
            Self::Overage => BillingImpact::Charged,
            Self::PayAsYouGo => BillingImpact::Charged,
            Self::DynamicAllocation => BillingImpact::Charged,
            Self::MonthlyCommitment => BillingImpact::Neutral,
            Self::AnnualCommitment => BillingImpact::Neutral,
            Self::DedicatedIpFee => BillingImpact::Charged,
            Self::PrivateCloudFee => BillingImpact::Charged,
            Self::SetupFee => BillingImpact::Charged,
            Self::SupportFee => BillingImpact::Charged,
            Self::Tax => BillingImpact::Charged,
            Self::Credit => BillingImpact::Deduction,
            Self::Refund => BillingImpact::Deduction,
        }
    }

    pub fn all_terms() -> Vec<BillingTermDefinition> {
        use BillingTerm::*;
        [
            IncludedEmails, BillableEmail, AttemptedEmail, AcceptedEmail, RejectedEmail,
            RetriedEmail, DuplicateRequest, TestEmail, Overage, PayAsYouGo,
            DynamicAllocation, MonthlyCommitment, AnnualCommitment, DedicatedIpFee,
            PrivateCloudFee, SetupFee, SupportFee, Tax, Credit, Refund,
        ]
        .iter()
        .map(|term| BillingTermDefinition {
            id: term.term_id().to_string(),
            display_name: term.display_name().to_string(),
            definition: term.definition().to_string(),
            billability: term.billability(),
        })
        .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BillingImpact {
    Charged,
    NoCharge,
    Conditional,
    Neutral,
    Threshold,
    Deduction,
}

impl BillingImpact {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Charged => "Charged",
            Self::NoCharge => "No charge",
            Self::Conditional => "Conditional",
            Self::Neutral => "Neutral",
            Self::Threshold => "Counts toward threshold",
            Self::Deduction => "Deducted from balance",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingTermDefinition {
    pub id: String,
    pub display_name: String,
    pub definition: String,
    pub billability: BillingImpact,
}

pub fn validate_billing_terms_completeness() -> BillingTermValidation {
    let terms = BillingTerm::all_terms();
    let expected_count = 20;
    let all_have_ids = terms.iter().all(|t| !t.id.is_empty());
    let all_have_definitions = terms.iter().all(|t| !t.definition.is_empty());

    BillingTermValidation {
        total_terms: terms.len(),
        expected_count,
        all_present: terms.len() == expected_count,
        all_have_ids,
        all_have_definitions,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingTermValidation {
    pub total_terms: usize,
    pub expected_count: usize,
    pub all_present: bool,
    pub all_have_ids: bool,
    pub all_have_definitions: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_20_billing_terms_defined() {
        let terms = BillingTerm::all_terms();
        assert_eq!(terms.len(), 20, "All 20 billing terms must be defined");
    }

    #[test]
    fn test_all_terms_have_unique_ids() {
        let terms = BillingTerm::all_terms();
        let ids: Vec<&str> = terms.iter().map(|t| t.id.as_str()).collect();
        let mut unique = std::collections::HashSet::new();
        for id in &ids {
            assert!(unique.insert(id), "Duplicate term ID: {id}");
        }
    }

    #[test]
    fn test_all_terms_have_definitions() {
        let terms = BillingTerm::all_terms();
        for term in &terms {
            assert!(!term.definition.is_empty(), "Term {id} missing definition", id = term.id);
        }
    }

    #[test]
    fn test_failed_and_retried_not_billable() {
        assert_eq!(BillingTerm::RejectedEmail.billability(), BillingImpact::NoCharge);
        assert_eq!(BillingTerm::RetriedEmail.billability(), BillingImpact::NoCharge);
        assert_eq!(BillingTerm::DuplicateRequest.billability(), BillingImpact::NoCharge);
    }

    #[test]
    fn test_dynamic_allocation_distinct_from_overage() {
        assert_ne!(BillingTerm::Overage.term_id(), BillingTerm::DynamicAllocation.term_id());
        assert_ne!(BillingTerm::Overage.definition(), BillingTerm::DynamicAllocation.definition());
    }

    #[test]
    fn test_validate_billing_terms() {
        let validation = validate_billing_terms_completeness();
        assert!(validation.all_present);
        assert!(validation.all_have_ids);
        assert!(validation.all_have_definitions);
    }
}
