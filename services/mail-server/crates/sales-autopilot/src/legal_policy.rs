//! EU jurisdiction-policy engine — the legal hard gate.
//!
//! `sales_jurisdiction_policies` is a versioned, counsel-approved lookup keyed
//! by `(jurisdiction, channel, contact_type)`. This module resolves the
//! recipient's jurisdiction, finds the authoritative policy row, applies the
//! business rules and returns a [`ContactPolicyVerdict`] that the decision
//! engine consumes. It never decides law by itself: it applies an explicit,
//! auditable row, and **fails closed** whenever no authoritative row exists.
//!
//! Fail-closed contract (release gate — "Legal-policy denial is impossible to
//! bypass through another sales route"):
//!
//! * an unknown / unlisted / low-confidence jurisdiction resolves to the
//!   `UNKNOWN` policy key, and when no `UNKNOWN` row is authoritative the
//!   verdict is `ApprovalRequired` — never `Allowed`;
//! * a row that exists but is unapproved (`approved_by`/`approved_at` NULL) or
//!   not currently valid (`valid_from` in the future / `valid_until` past)
//!   is **not** authoritative and the lookup falls through to the unknown
//!   default, rather than trusting a stale permissive policy;
//! * a channel that has no configured policy for the resolved jurisdiction
//!   yields `ApprovalRequired`.
//!
//! The decision logic lives in pure functions ([`resolve_jurisdiction`],
//! [`decide_with_state`], [`policy_is_authoritative`]); the async [`evaluate`]
//! is a thin database wrapper so the rules can be unit-tested exhaustively
//! without a database.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::{ContactDecision, JurisdictionPolicy, SalesError};

/// Below this confidence the recipient's country is not trusted for policy
/// resolution and the lookup resolves to the `UNKNOWN` policy key instead.
pub const MIN_COUNTRY_CONFIDENCE: f32 = 0.6;

/// Policy key used for the 27 EU member states plus the EEA (IS, LI, NO).
pub const EU_POLICY_KEY: &str = "EU";

/// Policy key for an unknown, unrecognized or low-confidence jurisdiction.
pub const UNKNOWN_POLICY_KEY: &str = "UNKNOWN";

/// 27 EU member states + EEA/EFTA states (Iceland, Liechtenstein, Norway).
/// Switzerland is deliberately NOT in this list: it is EFTA but not EEA, so it
/// keeps its own `CH` key and needs its own counsel-approved policy row.
const EU_EEA_COUNTRIES: &[&str] = &[
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV",
    "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE", // EU-27
    "IS", "LI", "NO", // EEA
];

/// Everything the legal gate needs to decide one contact attempt.
#[derive(Debug, Clone, Serialize)]
pub struct ContactPolicyInput<'a> {
    pub tenant_id: &'a str,
    pub account_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    pub contact_point_id: Option<Uuid>,
    /// ISO country of the RECIPIENT, plus how sure we are.
    pub recipient_country: Option<String>,
    pub country_confidence: f32,
    /// b2b_professional | b2c | sole_trader | unknown
    pub contact_type: &'a str,
    /// email | phone | linkedin | other
    pub channel: &'a str,
    pub source: Option<&'a str>,
    pub purpose: Option<&'a str>,
    pub has_existing_relationship: bool,
    pub consent_status: Option<&'a str>,
    pub soft_opt_in: bool,
    pub legitimate_interest_assessed: bool,
}

/// The legal verdict for one contact attempt, plus the audit data the CP
/// renders and the footer renderer consumes.
#[derive(Debug, Clone, Serialize)]
pub struct ContactPolicyVerdict {
    pub decision: ContactDecision,
    pub basis: String,
    pub reason: String,
    pub policy_id: Option<Uuid>,
    pub policy_version: Option<i32>,
    pub required_disclosure: serde_json::Value,
}

/// The DPO-approved disclosure shape the footer renderer consumes. Every
/// outbound message must carry sender identity, purpose and an opt-out; the
/// privacy URL is policy-specific and stays `null` until counsel supplies one.
pub fn default_disclosure() -> serde_json::Value {
    serde_json::json!({
        "sender_identity": true,
        "purpose": true,
        "opt_out": true,
        "privacy_url": null,
    })
}

/// Merge a policy row's disclosure overrides over the conservative default so
/// every required key is always present in the returned object.
fn merge_disclosure(policy: Option<&serde_json::Value>) -> serde_json::Value {
    let mut base = default_disclosure();
    if let Some(serde_json::Value::Object(overrides)) = policy {
        if let serde_json::Value::Object(map) = &mut base {
            for (key, value) in overrides {
                map.insert(key.clone(), value.clone());
            }
        }
    }
    base
}

/// Resolve the policy key for a recipient country.
///
/// * `None`, an empty/non ISO-3166-1 alpha-2 value, or a confidence below
///   [`MIN_COUNTRY_CONFIDENCE`] resolves to `UNKNOWN` (fail closed);
/// * a recognized EU member state or EEA state resolves to `EU`;
/// * any other well-formed alpha-2 code keeps its own code, so a
///   counsel-approved country policy can be found; absent one, the caller
///   falls through to the `UNKNOWN` default (still `ApprovalRequired`).
pub fn resolve_jurisdiction(country: Option<&str>, confidence: f32) -> String {
    let Some(raw) = country else {
        return UNKNOWN_POLICY_KEY.to_string();
    };
    let code = raw.trim().to_ascii_uppercase();
    if code.len() != 2 || !code.chars().all(|c| c.is_ascii_alphabetic()) {
        return UNKNOWN_POLICY_KEY.to_string();
    }
    // `!(confidence >= MIN)` rather than `<` so NaN also fails closed.
    if !(confidence >= MIN_COUNTRY_CONFIDENCE) {
        return UNKNOWN_POLICY_KEY.to_string();
    }
    if EU_EEA_COUNTRIES.contains(&code.as_str()) {
        EU_POLICY_KEY.to_string()
    } else {
        code
    }
}

/// Normalize a caller-supplied contact type to the four values the policy
/// table's CHECK constraint allows. Anything unrecognized becomes `unknown`,
/// which resolves to the fail-closed default policy.
pub fn normalize_contact_type(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "b2b_professional" | "b2b" => "b2b_professional",
        "b2c" | "consumer" => "b2c",
        "sole_trader" | "sole-trader" | "sole_trader_b2b" => "sole_trader",
        _ => "unknown",
    }
}

/// Normalize a channel to the four values the policy table allows.
pub fn normalize_channel(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "email" => "email",
        "phone" => "phone",
        "linkedin" => "linkedin",
        _ => "other",
    }
}

/// Is this policy row currently usable as the authority for a decision?
///
/// A row that exists but is unapproved (either `approved_by` or `approved_at`
/// missing) or not currently valid is NOT authoritative; [`evaluate`] treats
/// it as if no row existed at all and falls through to the unknown default.
pub fn policy_is_authoritative(
    approved_by: Option<&str>,
    approved_at: Option<DateTime<Utc>>,
    valid_from: DateTime<Utc>,
    valid_until: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> bool {
    let approved =
        approved_by.is_some_and(|value| !value.trim().is_empty()) && approved_at.is_some();
    let valid = valid_from <= now && valid_until.is_none_or(|until| until > now);
    approved && valid
}

/// Values of `consent_status` that are an absolute prohibition: a withdrawn or
/// refused consent can never be overridden by a permissive policy basis.
fn consent_is_prohibited(status: Option<&str>) -> bool {
    matches!(
        status.map(|s| s.trim().to_ascii_lowercase()).as_deref(),
        Some("withdrawn" | "revoked" | "denied" | "withdrawn_consent" | "suppressed")
    )
}

/// Is consent affirmatively granted? Only a positive value supports a
/// `basis = consent` policy; anything else fails closed to ApprovalRequired.
fn consent_is_granted(status: Option<&str>) -> bool {
    matches!(
        status.map(|s| s.trim().to_ascii_lowercase()).as_deref(),
        Some("granted" | "given" | "consented" | "opt_in" | "explicit" | "yes" | "true")
    )
}

/// Unknown database values for `decision` fail closed to ApprovalRequired.
fn parse_contact_decision(raw: &str) -> ContactDecision {
    match raw.trim().to_ascii_lowercase().as_str() {
        "allowed" => ContactDecision::Allowed,
        "prohibited" => ContactDecision::Prohibited,
        _ => ContactDecision::ApprovalRequired,
    }
}

fn build_verdict(
    decision: ContactDecision,
    basis: &str,
    reason: impl Into<String>,
    policy: Option<&JurisdictionPolicy>,
) -> ContactPolicyVerdict {
    ContactPolicyVerdict {
        decision,
        basis: basis.to_string(),
        reason: reason.into(),
        policy_id: policy.map(|p| p.id),
        policy_version: policy.map(|p| p.version),
        required_disclosure: merge_disclosure(policy.map(|p| &p.required_disclosure)),
    }
}

/// The pure decision function. `policy` is the authoritative row for the
/// exact `(jurisdiction, channel, contact_type)` triple, or `None` when no
/// authoritative row exists (unknown jurisdiction, unapproved/expired row, or
/// unconfigured channel). `channel_configured_by_jurisdiction` distinguishes
/// "jurisdiction has policies but not for this channel" (still
/// `ApprovalRequired`) from "jurisdiction is entirely unlisted".
///
/// Business rules, in order:
///
/// 1. suppressed / `consent_status == "withdrawn"` → `Prohibited` (a
///    withdrawal is absolute; no basis can resurrect it);
/// 2. no authoritative policy row → `ApprovalRequired` (fail closed; this
///    covers unknown/unlisted jurisdictions, unapproved and expired rows);
/// 3. a policy that says `prohibited` or uses the `not_permitted` basis →
///    `Prohibited`;
/// 4. an `approval_required` policy stays `ApprovalRequired` unless the
///    policy's basis is `soft_opt_in` and the contact actually qualifies for
///    soft opt-in (existing customer relationship tested by the caller);
/// 5. an `allowed` policy with the `legitimate_interest` basis is only valid
///    for `b2b_professional` contacts AND when
///    `legitimate_interest_assessed` is true — an unassessed LI claim is not a
///    basis, so it downgrades to `ApprovalRequired`;
/// 6. an `allowed` policy with the `consent` basis requires an affirmative
///    consent status; a `soft_opt_in` basis requires `soft_opt_in == true`;
/// 7. any other basis value fails closed to `ApprovalRequired`.
pub fn decide_with_state(
    policy: Option<&JurisdictionPolicy>,
    channel_configured_by_jurisdiction: bool,
    input: &ContactPolicyInput<'_>,
) -> ContactPolicyVerdict {
    // Rule 1 — withdrawal/refusal is absolute.
    if consent_is_prohibited(input.consent_status) {
        return build_verdict(
            ContactDecision::Prohibited,
            "not_permitted",
            "consent was withdrawn or refused; contacting this person is prohibited",
            policy,
        );
    }

    // Rule 2 — fail closed without an authoritative, currently valid,
    // approved policy row.
    let Some(policy) = policy else {
        let reason = if channel_configured_by_jurisdiction {
            format!(
                "jurisdiction is listed but no approved policy is configured for channel '{}'; \
                 fail closed pending an explicit policy row",
                normalize_channel(input.channel)
            )
        } else {
            "no approved, currently valid jurisdiction policy exists for this contact; \
             fail closed (unknown/unlisted jurisdiction)"
                .to_string()
        };
        return build_verdict(
            ContactDecision::ApprovalRequired,
            "not_permitted",
            reason,
            None,
        );
    };

    // Rule 3 — explicit prohibition.
    if policy.decision == ContactDecision::Prohibited || policy.basis == "not_permitted" {
        return build_verdict(
            ContactDecision::Prohibited,
            "not_permitted",
            format!(
                "policy v{} prohibits contacting this contact type via this channel",
                policy.version
            ),
            Some(policy),
        );
    }

    let contact_type = normalize_contact_type(input.contact_type);
    let basis = policy.basis.as_str();

    // Rule 4 — approval_required policy; soft opt-in may lift it when the
    // policy explicitly names soft opt-in as the permitted basis.
    if policy.decision == ContactDecision::ApprovalRequired {
        if basis == "soft_opt_in" && input.soft_opt_in {
            return build_verdict(
                ContactDecision::Allowed,
                "soft_opt_in",
                "soft opt-in applies and the policy permits soft opt-in as a basis",
                Some(policy),
            );
        }
        return build_verdict(
            ContactDecision::ApprovalRequired,
            basis,
            format!(
                "policy v{} requires operator approval for this contact (basis '{}')",
                policy.version, basis
            ),
            Some(policy),
        );
    }

    // From here the policy says `allowed`; the basis still has to hold.
    match basis {
        // Rule 5 — legitimate interest.
        "legitimate_interest" => {
            if contact_type != "b2b_professional" {
                return build_verdict(
                    ContactDecision::ApprovalRequired,
                    basis,
                    "legitimate interest is only considered for b2b_professional contacts; \
                     this contact type requires explicit consent or approval",
                    Some(policy),
                );
            }
            if !input.legitimate_interest_assessed {
                return build_verdict(
                    ContactDecision::ApprovalRequired,
                    basis,
                    "legitimate interest has not been assessed (LIA missing); \
                     an unassessed LI claim is not a lawful basis",
                    Some(policy),
                );
            }
            build_verdict(
                ContactDecision::Allowed,
                basis,
                "legitimate interest assessed and recorded; b2b_professional contact",
                Some(policy),
            )
        }
        // Rule 6 — consent.
        "consent" => {
            if consent_is_granted(input.consent_status) {
                build_verdict(
                    ContactDecision::Allowed,
                    basis,
                    "affirmative consent on record",
                    Some(policy),
                )
            } else {
                build_verdict(
                    ContactDecision::ApprovalRequired,
                    basis,
                    "policy is consent-based but no affirmative consent status is recorded",
                    Some(policy),
                )
            }
        }
        // Rule 6 — soft opt-in.
        "soft_opt_in" => {
            if input.soft_opt_in {
                build_verdict(
                    ContactDecision::Allowed,
                    basis,
                    "soft opt-in conditions satisfied and permitted by policy",
                    Some(policy),
                )
            } else {
                build_verdict(
                    ContactDecision::ApprovalRequired,
                    basis,
                    "policy is soft-opt-in-based but the contact does not satisfy soft opt-in",
                    Some(policy),
                )
            }
        }
        "not_permitted" => build_verdict(
            ContactDecision::Prohibited,
            basis,
            "policy basis is 'not_permitted'",
            Some(policy),
        ),
        // Rule 7 — unknown basis value fails closed.
        other => build_verdict(
            ContactDecision::ApprovalRequired,
            other,
            format!("unrecognized policy basis '{other}'; fail closed"),
            Some(policy),
        ),
    }
}

/// Convenience wrapper for callers that only know whether a policy row exists
/// at all (a present authoritative row implies its channel is configured).
pub fn decide(
    policy: Option<&JurisdictionPolicy>,
    input: &ContactPolicyInput<'_>,
) -> ContactPolicyVerdict {
    decide_with_state(policy, policy.is_some(), input)
}

#[derive(sqlx::FromRow)]
struct PolicyRow {
    id: Uuid,
    jurisdiction: String,
    channel: String,
    contact_type: String,
    decision: String,
    basis: String,
    required_disclosure: serde_json::Value,
    version: i32,
    approved_by: Option<String>,
    approved_at: Option<DateTime<Utc>>,
    valid_from: DateTime<Utc>,
    valid_until: Option<DateTime<Utc>>,
}

impl PolicyRow {
    fn into_policy(self) -> JurisdictionPolicy {
        JurisdictionPolicy {
            id: self.id,
            jurisdiction: self.jurisdiction,
            channel: self.channel,
            contact_type: self.contact_type,
            decision: parse_contact_decision(&self.decision),
            basis: self.basis,
            required_disclosure: self.required_disclosure,
            version: self.version,
        }
    }
}

/// Resolve and apply the jurisdiction policy for one contact attempt.
///
/// FAIL CLOSED: an unknown or unlisted jurisdiction, an unapproved or expired
/// policy row, or a channel with no configured policy yields
/// `ApprovalRequired`, never `Allowed`.
pub async fn evaluate(
    db: &PgPool,
    input: &ContactPolicyInput<'_>,
) -> Result<ContactPolicyVerdict, SalesError> {
    let jurisdiction =
        resolve_jurisdiction(input.recipient_country.as_deref(), input.country_confidence);
    let contact_type = normalize_contact_type(input.contact_type);
    let channel = normalize_channel(input.channel);

    // Highest version for the exact triple, regardless of approval/validity:
    // an unapproved or expired top version must not silently delegate to an
    // older row — it falls through to the unknown default instead.
    let row: Option<PolicyRow> = sqlx::query_as(
        "SELECT id, jurisdiction, channel, contact_type, decision, basis, \
                required_disclosure, version, approved_by, approved_at, \
                valid_from, valid_until \
         FROM sales_jurisdiction_policies \
         WHERE jurisdiction = $1 AND channel = $2 AND contact_type = $3 \
         ORDER BY version DESC \
         LIMIT 1",
    )
    .bind(&jurisdiction)
    .bind(channel)
    .bind(contact_type)
    .fetch_optional(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    let now = Utc::now();
    let policy = row.and_then(|row| {
        let authoritative = policy_is_authoritative(
            row.approved_by.as_deref(),
            row.approved_at,
            row.valid_from,
            row.valid_until,
            now,
        );
        authoritative.then(|| row.into_policy())
    });

    // Distinguish "jurisdiction is listed but this channel is not configured"
    // from "jurisdiction is entirely unlisted" for the operator-facing reason.
    let channel_configured = if policy.is_some() {
        true
    } else {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS ( \
                 SELECT 1 FROM sales_jurisdiction_policies \
                 WHERE jurisdiction = $1 AND contact_type = $2 \
                   AND approved_by IS NOT NULL AND approved_at IS NOT NULL \
                   AND valid_from <= NOW() \
                   AND (valid_until IS NULL OR valid_until > NOW()) \
             )",
        )
        .bind(&jurisdiction)
        .bind(contact_type)
        .fetch_one(db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?
    };

    Ok(decide_with_state(
        policy.as_ref(),
        channel_configured,
        input,
    ))
}

/// Persist a legal verdict into `sales_contact_policy_decisions` (audit trail).
///
/// The audit row records the resolved jurisdiction, the exact policy row (and
/// version) that was applied, the full input, and the required disclosure, so
/// an operator can replay why a contact was allowed, denied or escalated.
pub async fn record(
    db: &PgPool,
    tenant_id: &str,
    input: &ContactPolicyInput<'_>,
    verdict: &ContactPolicyVerdict,
) -> Result<Uuid, SalesError> {
    let jurisdiction =
        resolve_jurisdiction(input.recipient_country.as_deref(), input.country_confidence);
    let inputs = serde_json::to_value(input)
        .map_err(|e| SalesError::Internal(anyhow::anyhow!("serializing policy input: {e}")))?;

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO sales_contact_policy_decisions ( \
             id, tenant_id, account_id, contact_id, contact_point_id, jurisdiction, \
             policy_id, policy_version, decision, basis, reason, required_disclosure, \
             inputs, created_at \
         ) VALUES ( \
             gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW() \
         ) RETURNING id",
    )
    .bind(tenant_id)
    .bind(input.account_id)
    .bind(input.contact_id)
    .bind(input.contact_point_id)
    .bind(&jurisdiction)
    .bind(verdict.policy_id)
    .bind(verdict.policy_version)
    .bind(verdict.decision.as_str())
    .bind(&verdict.basis)
    .bind(&verdict.reason)
    .bind(&verdict.required_disclosure)
    .bind(&inputs)
    .fetch_one(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_input() -> ContactPolicyInput<'static> {
        ContactPolicyInput {
            tenant_id: "tenant-a",
            account_id: None,
            contact_id: None,
            contact_point_id: None,
            recipient_country: Some("DE".into()),
            country_confidence: 0.95,
            contact_type: "b2b_professional",
            channel: "email",
            source: Some("public_registry"),
            purpose: Some("sales_outreach"),
            has_existing_relationship: false,
            consent_status: None,
            soft_opt_in: false,
            legitimate_interest_assessed: true,
        }
    }

    fn policy(decision: ContactDecision, basis: &str) -> JurisdictionPolicy {
        JurisdictionPolicy {
            id: Uuid::new_v4(),
            jurisdiction: EU_POLICY_KEY.into(),
            channel: "email".into(),
            contact_type: "b2b_professional".into(),
            decision,
            basis: basis.into(),
            required_disclosure: serde_json::json!({}),
            version: 7,
        }
    }

    #[test]
    fn eu_member_and_eea_states_resolve_to_eu_key() {
        for country in ["DE", "de", "FR", "SE", "is", "LI", "NO", "ie"] {
            assert_eq!(
                resolve_jurisdiction(Some(country), 0.9),
                EU_POLICY_KEY,
                "{country} must map to the EU policy key"
            );
        }
    }

    #[test]
    fn switzerland_is_not_eea_and_keeps_its_own_key() {
        // EFTA but not EEA: needs its own counsel-approved row; absent one the
        // evaluate() wrapper falls through to the UNKNOWN default.
        assert_eq!(resolve_jurisdiction(Some("CH"), 0.9), "CH");
    }

    #[test]
    fn unknown_or_unrecognized_country_resolves_to_unknown() {
        assert_eq!(resolve_jurisdiction(None, 1.0), UNKNOWN_POLICY_KEY);
        assert_eq!(resolve_jurisdiction(Some(""), 1.0), UNKNOWN_POLICY_KEY);
        assert_eq!(resolve_jurisdiction(Some("  "), 1.0), UNKNOWN_POLICY_KEY);
        assert_eq!(
            resolve_jurisdiction(Some("Germany"), 1.0),
            UNKNOWN_POLICY_KEY
        );
        assert_eq!(resolve_jurisdiction(Some("XYZ"), 1.0), UNKNOWN_POLICY_KEY);
        assert_eq!(resolve_jurisdiction(Some("12"), 1.0), UNKNOWN_POLICY_KEY);
    }

    #[test]
    fn low_or_nan_confidence_resolves_to_unknown() {
        assert_eq!(resolve_jurisdiction(Some("DE"), 0.59), UNKNOWN_POLICY_KEY);
        assert_eq!(
            resolve_jurisdiction(Some("DE"), MIN_COUNTRY_CONFIDENCE),
            EU_POLICY_KEY
        );
        assert_eq!(
            resolve_jurisdiction(Some("DE"), f32::NAN),
            UNKNOWN_POLICY_KEY
        );
    }

    #[test]
    fn non_eu_recognized_country_keeps_iso_code() {
        assert_eq!(resolve_jurisdiction(Some("us"), 0.9), "US");
        assert_eq!(resolve_jurisdiction(Some("GB"), 0.9), "GB");
    }

    #[test]
    fn unknown_country_with_no_policy_is_approval_required_never_allowed() {
        let verdict = decide(None, &base_input());
        assert_eq!(verdict.decision, ContactDecision::ApprovalRequired);
        assert_eq!(verdict.basis, "not_permitted");
        assert!(verdict.policy_id.is_none());
    }

    #[test]
    fn b2c_contact_can_never_use_legitimate_interest() {
        let mut input = base_input();
        input.contact_type = "b2c";
        input.legitimate_interest_assessed = true;
        let verdict = decide(
            Some(&policy(ContactDecision::Allowed, "legitimate_interest")),
            &input,
        );
        assert_eq!(verdict.decision, ContactDecision::ApprovalRequired);
        assert!(verdict.reason.contains("b2b_professional"));
    }

    #[test]
    fn b2b_li_without_assessment_is_not_a_basis() {
        let mut input = base_input();
        input.legitimate_interest_assessed = false;
        let verdict = decide(
            Some(&policy(ContactDecision::Allowed, "legitimate_interest")),
            &input,
        );
        assert_eq!(verdict.decision, ContactDecision::ApprovalRequired);
        assert!(verdict.reason.contains("not been assessed"));
    }

    #[test]
    fn b2b_li_assessed_is_allowed() {
        let verdict = decide(
            Some(&policy(ContactDecision::Allowed, "legitimate_interest")),
            &base_input(),
        );
        assert_eq!(verdict.decision, ContactDecision::Allowed);
        assert_eq!(verdict.basis, "legitimate_interest");
    }

    #[test]
    fn allowed_with_granted_consent_is_allowed() {
        let mut input = base_input();
        input.consent_status = Some("granted");
        let verdict = decide(Some(&policy(ContactDecision::Allowed, "consent")), &input);
        assert_eq!(verdict.decision, ContactDecision::Allowed);
    }

    #[test]
    fn allowed_without_consent_fails_closed() {
        let mut input = base_input();
        input.consent_status = None;
        let verdict = decide(Some(&policy(ContactDecision::Allowed, "consent")), &input);
        assert_eq!(verdict.decision, ContactDecision::ApprovalRequired);
    }

    #[test]
    fn withdrawn_consent_is_prohibited_even_under_a_permissive_policy() {
        for status in ["withdrawn", "revoked", "denied", "suppressed"] {
            let mut input = base_input();
            input.consent_status = Some(status);
            let verdict = decide(
                Some(&policy(ContactDecision::Allowed, "legitimate_interest")),
                &input,
            );
            assert_eq!(
                verdict.decision,
                ContactDecision::Prohibited,
                "consent status {status} must prohibit contact"
            );
        }
    }

    #[test]
    fn prohibited_policy_is_prohibited() {
        let verdict = decide(
            Some(&policy(ContactDecision::Prohibited, "not_permitted")),
            &base_input(),
        );
        assert_eq!(verdict.decision, ContactDecision::Prohibited);
    }

    #[test]
    fn approval_required_policy_escalates_even_for_b2b_li() {
        let verdict = decide(
            Some(&policy(
                ContactDecision::ApprovalRequired,
                "legitimate_interest",
            )),
            &base_input(),
        );
        assert_eq!(verdict.decision, ContactDecision::ApprovalRequired);
    }

    #[test]
    fn approval_required_policy_is_lifted_by_soft_opt_in_when_basis_permits() {
        let mut input = base_input();
        input.soft_opt_in = true;
        input.has_existing_relationship = true;
        let verdict = decide(
            Some(&policy(ContactDecision::ApprovalRequired, "soft_opt_in")),
            &input,
        );
        assert_eq!(verdict.decision, ContactDecision::Allowed);
        assert_eq!(verdict.basis, "soft_opt_in");
    }

    #[test]
    fn soft_opt_in_basis_without_soft_opt_in_fails_closed() {
        let mut input = base_input();
        input.soft_opt_in = false;
        let verdict = decide(
            Some(&policy(ContactDecision::Allowed, "soft_opt_in")),
            &input,
        );
        assert_eq!(verdict.decision, ContactDecision::ApprovalRequired);
    }

    #[test]
    fn unknown_basis_fails_closed() {
        let verdict = decide(
            Some(&policy(ContactDecision::Allowed, "vibes")),
            &base_input(),
        );
        assert_eq!(verdict.decision, ContactDecision::ApprovalRequired);
    }

    #[test]
    fn unconfigured_channel_is_approval_required() {
        let verdict = decide_with_state(None, true, &base_input());
        assert_eq!(verdict.decision, ContactDecision::ApprovalRequired);
        assert!(verdict.reason.contains("channel"));
    }

    #[test]
    fn unlisted_jurisdiction_is_approval_required() {
        let verdict = decide_with_state(None, false, &base_input());
        assert_eq!(verdict.decision, ContactDecision::ApprovalRequired);
        assert!(verdict.reason.contains("fail closed"));
    }

    #[test]
    fn expired_policy_row_is_not_authoritative() {
        let now = Utc::now();
        assert!(!policy_is_authoritative(
            Some("counsel"),
            Some(now),
            now - chrono::Duration::days(30),
            Some(now - chrono::Duration::days(1)),
            now,
        ));
        // No valid_until means valid indefinitely once approved.
        assert!(policy_is_authoritative(
            Some("counsel"),
            Some(now),
            now - chrono::Duration::days(30),
            None,
            now,
        ));
    }

    #[test]
    fn unapproved_or_future_policy_row_is_not_authoritative() {
        let now = Utc::now();
        assert!(!policy_is_authoritative(
            None,
            None,
            now - chrono::Duration::days(1),
            None,
            now,
        ));
        assert!(!policy_is_authoritative(
            Some(""),
            Some(now),
            now - chrono::Duration::days(1),
            None,
            now,
        ));
        assert!(!policy_is_authoritative(
            Some("counsel"),
            Some(now),
            now + chrono::Duration::days(1),
            None,
            now,
        ));
    }

    #[test]
    fn required_disclosure_always_has_the_footer_keys() {
        let verdict = decide(
            Some(&policy(ContactDecision::Allowed, "legitimate_interest")),
            &base_input(),
        );
        assert_eq!(verdict.required_disclosure["sender_identity"], true);
        assert_eq!(verdict.required_disclosure["purpose"], true);
        assert_eq!(verdict.required_disclosure["opt_out"], true);
        assert!(verdict.required_disclosure["privacy_url"].is_null());
    }

    #[test]
    fn policy_disclosure_overrides_merge_over_defaults() {
        let mut p = policy(ContactDecision::Allowed, "legitimate_interest");
        p.required_disclosure = serde_json::json!({ "privacy_url": "https://example.com/privacy" });
        let verdict = decide(Some(&p), &base_input());
        assert_eq!(
            verdict.required_disclosure["privacy_url"],
            "https://example.com/privacy"
        );
        assert_eq!(verdict.required_disclosure["opt_out"], true);
    }

    #[test]
    fn policy_version_and_id_are_carried_into_the_verdict() {
        let p = policy(ContactDecision::Allowed, "legitimate_interest");
        let verdict = decide(Some(&p), &base_input());
        assert_eq!(verdict.policy_id, Some(p.id));
        assert_eq!(verdict.policy_version, Some(7));
    }

    #[test]
    fn contact_type_and_channel_normalization() {
        assert_eq!(
            normalize_contact_type("B2B_Professional"),
            "b2b_professional"
        );
        assert_eq!(normalize_contact_type("b2b"), "b2b_professional");
        assert_eq!(normalize_contact_type("B2C"), "b2c");
        assert_eq!(normalize_contact_type("sole-trader"), "sole_trader");
        assert_eq!(normalize_contact_type("enterprise"), "unknown");
        assert_eq!(normalize_channel("EMAIL"), "email");
        assert_eq!(normalize_channel("Phone"), "phone");
        assert_eq!(normalize_channel("carrier_pigeon"), "other");
    }
}
