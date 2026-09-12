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
use serde::{Deserialize, Serialize};
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

/// Whether the recipient is a natural person, a legal person, or unknown.
///
/// Estonian Electronic Communications Act §103¹ distinguishes the two:
/// prior consent is generally required for natural persons, while
/// legal-person direct marketing may rely on legitimate interest with a
/// clear, easy, free refusal mechanism.
///
/// **Do not infer `LegalPerson` from a work email address or a B2B persona.**
/// A corporate-looking domain (`@company.com`), a `b2b_professional`
/// contact type or a job title are not evidence of legal personality; the
/// audit that produced this input explicitly forbids that inference. A caller
/// that has no evidence of the recipient's subscriber type MUST pass
/// [`SubscriberType::Unknown`] — the fail-closed default — and the engine will
/// never return `Allowed` for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SubscriberType {
    /// No evidence of the recipient's legal character; fail closed.
    #[default]
    Unknown,
    /// A human being, including a sole trader acting personally.
    NaturalPerson,
    /// A company or other legal entity.
    LegalPerson,
}

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
    /// Authoritative subscriber classification. Never inferred from the work
    /// email or the B2B persona; [`SubscriberType::Unknown`] when a caller has
    /// no evidence, which the engine refuses to allow.
    pub subscriber_type: SubscriberType,
    /// The `sales_consent_evidence` row that evidences consent. Only an
    /// ACTIVE row (not withdrawn) may be set; a withdrawn consent is carried
    /// as `consent_status = "withdrawn"` and prohibits contact. `None` means
    /// no usable evidence, never "assume granted".
    pub consent_evidence_id: Option<Uuid>,
    /// The recipient (or their organisation) has an existing customer
    /// relationship with the sender.
    pub existing_customer: bool,
    /// The marketed product is similar to what the existing customer already
    /// bought — the soft-opt-in precondition for the §103¹(2) exception.
    pub similar_product_basis: bool,
    /// When the collector offered a clear, easy, free opt-out at the point the
    /// details were collected. `None` fails the soft-opt-in exception closed.
    pub collection_opt_out_offered_at: Option<DateTime<Utc>>,
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

// ---------------------------------------------------------------------------
// Consent evidence — loaded from `sales_consent_evidence`, never taken on
// trust from a boolean.
// ---------------------------------------------------------------------------

/// One `sales_consent_evidence` row as loaded for evaluation. Kept as a plain
/// value so the selection/validity rules below are unit-testable without a
/// database.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ConsentEvidenceRow {
    pub id: Uuid,
    /// The contact the evidence belongs to. `Option` only so a malformed row
    /// can be rejected rather than panicking; the loader filters by contact.
    pub contact_id: Option<Uuid>,
    pub contact_point_id: Option<Uuid>,
    pub consent_text: String,
    pub consent_version: i32,
    /// The DB column is `NOT NULL`, but a nullable read keeps a malformed or
    /// legacy row visible to [`current_consent_state`], which rejects it.
    pub source: Option<String>,
    pub collected_at: DateTime<Utc>,
    pub withdrawn_at: Option<DateTime<Utc>>,
}

/// The consent state that governs one contact, derived from evidence rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentState {
    /// No usable, internally coherent evidence exists; fail closed.
    None,
    /// The newest usable evidence row is active (not withdrawn).
    Granted { evidence_id: Uuid },
    /// The newest usable evidence row was withdrawn.
    Withdrawn { evidence_id: Uuid },
}

impl ConsentState {
    /// The evidence row this state points at, for the audit link.
    pub fn evidence_id(self) -> Option<Uuid> {
        match self {
            Self::None => None,
            Self::Granted { evidence_id } | Self::Withdrawn { evidence_id } => Some(evidence_id),
        }
    }

    /// The `consent_status` value the legal input carries.
    pub fn status(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Granted { .. } => Some("granted"),
            Self::Withdrawn { .. } => Some("withdrawn"),
        }
    }
}

/// Is this row usable as evidence at all?
///
/// A consent record only counts when it says what was agreed to (non-empty
/// text), which version that was (`consent_version >= 1`), where it came from
/// (non-empty source), and when it was collected (not in the future). A
/// withdrawal recorded *before* the collection it supposedly withdraws is
/// internally incoherent and is discarded rather than trusted.
fn evidence_row_is_usable(row: &ConsentEvidenceRow, now: DateTime<Utc>) -> bool {
    let source_ok = row
        .source
        .as_deref()
        .is_some_and(|source| !source.trim().is_empty());
    let withdrawal_ok = row
        .withdrawn_at
        .is_none_or(|withdrawn_at| withdrawn_at >= row.collected_at);
    !row.consent_text.trim().is_empty()
        && row.consent_version >= 1
        && source_ok
        && row.collected_at <= now
        && withdrawal_ok
}

/// Choose the consent state that governs `contact_id` from evidence rows.
///
/// * rows for a DIFFERENT contact are ignored, so evidence belonging to
///   someone else can never be accepted as this contact's consent (the
///   caller's loader must scope by contact too; this is the second line of
///   defence);
/// * rows that fail [`evidence_row_is_usable`] are ignored, so empty text,
///   `consent_version = 0`, a future `collected_at`, a `withdrawn_at` before
///   `collected_at`, or a missing source all fall through to
///   [`ConsentState::None`] — fail closed, never "assume granted";
/// * among usable rows the newest by `collected_at` wins; on the exact same
///   timestamp a withdrawal wins over a grant, so a tie fails closed.
pub fn current_consent_state(
    rows: &[ConsentEvidenceRow],
    contact_id: Uuid,
    now: DateTime<Utc>,
) -> ConsentState {
    let newest = rows
        .iter()
        .filter(|row| row.contact_id == Some(contact_id))
        .filter(|row| evidence_row_is_usable(row, now))
        // `(collected_at, withdrawn)` ordering: a withdrawal sorts above a
        // grant at the same instant, and `max_by_key` picks it.
        .max_by_key(|row| (row.collected_at, row.withdrawn_at.is_some()));

    match newest {
        Some(row) if row.withdrawn_at.is_none() => ConsentState::Granted {
            evidence_id: row.id,
        },
        Some(row) => ConsentState::Withdrawn {
            evidence_id: row.id,
        },
        None => ConsentState::None,
    }
}

/// Load the consent state for one contact from `sales_consent_evidence`.
///
/// Evidence is scoped to the contact (a row for another contact can never be
/// read here) and, when a contact point is supplied, to person-level evidence
/// (`contact_point_id IS NULL`) or evidence collected for that exact point —
/// consent given for a different channel endpoint is not consent for email.
/// With no contact point, only person-level evidence is accepted (fail
/// closed).
pub async fn load_consent_state(
    db: &PgPool,
    tenant_id: &str,
    contact_id: Uuid,
    contact_point_id: Option<Uuid>,
) -> Result<ConsentState, SalesError> {
    let rows: Vec<ConsentEvidenceRow> = sqlx::query_as(
        "SELECT id, contact_id, contact_point_id, consent_text, consent_version, \
                source::text AS source, collected_at, withdrawn_at \
         FROM sales_consent_evidence \
         WHERE tenant_id = $1 AND contact_id = $2 \
           AND ( \
                 contact_point_id IS NULL \
                 OR contact_point_id = $3 \
           ) \
         ORDER BY collected_at DESC",
    )
    .bind(tenant_id)
    .bind(contact_id)
    .bind(contact_point_id)
    .fetch_all(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    Ok(current_consent_state(&rows, contact_id, Utc::now()))
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
/// # Rule table (Estonian Electronic Communications Act §103¹, EU/EEA policy)
///
/// The row the verdict is derived from is the authoritative
/// `(jurisdiction, channel, contact_type)` policy; the rules below are applied
/// on top of it. A reviewer can check each rule against the statute wording:
///
/// | # | Condition | Verdict |
/// |---|-----------|---------|
/// | 1 | `consent_status` is suppressed/withdrawn/revoked/denied (including a withdrawn `sales_consent_evidence` row) | `Prohibited` — withdrawal is absolute for natural AND legal persons |
/// | 2 | no authoritative, approved, currently-valid policy row | `ApprovalRequired` (fail closed) |
/// | 3 | policy `prohibited` or basis `not_permitted` | `Prohibited` |
/// | 4 | policy `approval_required`, basis `soft_opt_in`, and the §103¹(2) conditions below hold | `Allowed` (the one explicit lift) |
/// | 4b | any other `approval_required` row | `ApprovalRequired` |
/// | 5 | `subscriber_type == Unknown` in an EU/EEA jurisdiction | `ApprovalRequired`, never `Allowed` (for every basis below, including the soft-opt-in lift) |
/// | 6 | natural person, consent basis, ACTIVE `consent_evidence_id` | `Allowed` — prior consent is the only basis; the opt-out disclosure must still be present |
/// | 6b | natural person, consent basis, no active evidence, EU/EEA jurisdiction | `Prohibited` — §103¹ requires prior consent for natural persons |
/// | 6c | natural person, consent basis, no active evidence, other jurisdiction | `ApprovalRequired` |
/// | 7 | legal person, legitimate-interest basis, `legitimate_interest_assessed`, `b2b_professional`, disclosure guarantees opt-out | `Allowed` — legal-person direct marketing is permitted with a clear, easy, free refusal mechanism |
/// | 7b | natural person on the legitimate-interest basis in an EU/EEA jurisdiction | `ApprovalRequired` — LI cannot substitute for prior consent |
/// | 7c | legal person, legitimate-interest basis, any of the above missing | `ApprovalRequired` |
/// | 8 | soft opt-in (`existing_customer && similar_product_basis && collection_opt_out_offered_at.is_some()`) AND disclosure guarantees opt-out | `Allowed` |
/// | 8b | soft opt-in conditions incomplete | `ApprovalRequired` |
/// | 9 | any other basis value | `ApprovalRequired` |
///
/// # §103¹(2) soft-opt-in conditions
///
/// `existing_customer && similar_product_basis` AND an opt-out was offered at
/// collection (`collection_opt_out_offered_at.is_some()`). The in-message
/// refusal mechanism is guaranteed separately: every autonomous send is
/// rendered through the compliant footer and a verdict of `Allowed` is only
/// returned when the policy disclosure asserts `opt_out == true`. Absent the
/// collection-time evidence the exception fails closed to `ApprovalRequired`
/// — the mere fact that we could put an unsubscribe link in the message today
/// does not cure a collection that offered no refusal.
///
/// The legacy `soft_opt_in` boolean is **not** sufficient on its own any
/// more: it is subsumed by these explicit facts (and the loaders derive it
/// from them), so a stale `true` from a decision packet recorded before these
/// inputs existed cannot authorize a send.
///
/// # Subscriber classification
///
/// `subscriber_type` is authoritative input, never inferred from a work email
/// or a B2B persona (see [`SubscriberType`]). `Unknown` is the fail-closed
/// default and rule 5 refuses to allow on it inside the EU/EEA — including for
/// the soft-opt-in lift in rule 4. Outside the EU/EEA the policy row remains
/// the authority for how the recipient may be approached, so an unestablished
/// classification does not by itself change the verdict there. `consent_status`
/// remains the carrier for a withdrawn consent; the loader sets it from
/// `sales_consent_evidence.withdrawn_at`.
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

    let disclosure = merge_disclosure(Some(&policy.required_disclosure));
    // Every `Allowed` verdict below requires this: the statute's refusal
    // mechanism must actually be guaranteed by the disclosure the footer
    // renderer consumes. A policy row that turns it off can never authorize
    // an autonomous send.
    let opt_out_guaranteed = disclosure
        .get("opt_out")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    let contact_type = normalize_contact_type(input.contact_type);
    let basis = policy.basis.as_str();
    let subscriber = input.subscriber_type;
    let eu_jurisdiction = policy.jurisdiction.eq_ignore_ascii_case(EU_POLICY_KEY);
    let classification_known = subscriber != SubscriberType::Unknown;

    // Rule 8 — the §103¹(2) existing-customer similar-product exception.
    let soft_opt_in_conditions_met = input.existing_customer
        && input.similar_product_basis
        && input.collection_opt_out_offered_at.is_some();

    // Rule 5 — inside the EU/EEA an unestablished subscriber classification
    // is never Allowed, whatever basis the policy names (including the
    // soft-opt-in lift below). A work email address or B2B persona is not
    // evidence of legal personality; the caller must supply evidence or fail
    // closed.
    if eu_jurisdiction && !classification_known {
        return build_verdict(
            ContactDecision::ApprovalRequired,
            basis,
            "recipient subscriber type (natural person vs legal person) is not established in \
             an EU/EEA jurisdiction; a work email or B2B persona is not evidence of legal \
             personality — fail closed",
            Some(policy),
        );
    }

    // Rule 4 — approval_required policy; the soft-opt-in exception is the one
    // explicit lift, and only with the full evidence set.
    if policy.decision == ContactDecision::ApprovalRequired {
        if basis == "soft_opt_in" && soft_opt_in_conditions_met && opt_out_guaranteed {
            return build_verdict(
                ContactDecision::Allowed,
                "soft_opt_in",
                "soft opt-in conditions satisfied (existing customer, similar product, \
                 opt-out offered at collection) and permitted by policy",
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
        // Rule 7 — legitimate interest (legal persons only).
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
            if eu_jurisdiction && subscriber == SubscriberType::NaturalPerson {
                return build_verdict(
                    ContactDecision::ApprovalRequired,
                    basis,
                    "legitimate interest cannot substitute for the prior consent §103¹ requires \
                     for a natural person; a human must review this attempt",
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
            if !opt_out_guaranteed {
                return build_verdict(
                    ContactDecision::ApprovalRequired,
                    basis,
                    "legal-person direct marketing needs a clear, easy, free refusal mechanism; \
                     the policy disclosure does not guarantee one",
                    Some(policy),
                );
            }
            build_verdict(
                ContactDecision::Allowed,
                basis,
                "legitimate interest assessed and recorded; legal person contacted with a \
                 guaranteed refusal mechanism",
                Some(policy),
            )
        }
        // Rule 6 — consent.
        "consent" => {
            if input.consent_evidence_id.is_none() {
                return match subscriber {
                    // §103¹: prior consent is required for natural persons. No
                    // active evidence means direct marketing is prohibited,
                    // not merely unapproved.
                    SubscriberType::NaturalPerson if eu_jurisdiction => build_verdict(
                        ContactDecision::Prohibited,
                        basis,
                        "§103¹ requires prior consent for a natural person and no active \
                         consent evidence is on record",
                        Some(policy),
                    ),
                    _ => build_verdict(
                        ContactDecision::ApprovalRequired,
                        basis,
                        "policy is consent-based but no active consent evidence is on record",
                        Some(policy),
                    ),
                };
            }
            if !opt_out_guaranteed {
                return build_verdict(
                    ContactDecision::ApprovalRequired,
                    basis,
                    "consent evidence exists but the policy disclosure does not guarantee the \
                     required opt-out mechanism",
                    Some(policy),
                );
            }
            build_verdict(
                ContactDecision::Allowed,
                basis,
                "active, versioned consent evidence on record",
                Some(policy),
            )
        }
        // Rule 8 — soft opt-in.
        "soft_opt_in" => {
            if soft_opt_in_conditions_met && opt_out_guaranteed {
                build_verdict(
                    ContactDecision::Allowed,
                    basis,
                    "soft opt-in conditions satisfied (existing customer, similar product, \
                     opt-out offered at collection)",
                    Some(policy),
                )
            } else {
                build_verdict(
                    ContactDecision::ApprovalRequired,
                    basis,
                    "policy is soft-opt-in-based but the §103¹(2) conditions are not evidenced \
                     (existing customer, similar product, opt-out offered at collection)",
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
        // Rule 9 — unknown basis value fails closed.
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
            // The fail-closed default: no canonical subscriber-type evidence
            // exists today, and the B2B persona is deliberately NOT used as a
            // substitute.
            subscriber_type: SubscriberType::Unknown,
            consent_evidence_id: None,
            existing_customer: false,
            similar_product_basis: false,
            collection_opt_out_offered_at: None,
        }
    }

    /// A fixture that has active consent evidence for a natural person.
    fn consented_natural_person() -> (ContactPolicyInput<'static>, Uuid) {
        let evidence_id = Uuid::new_v4();
        let mut input = base_input();
        input.contact_type = "b2c";
        input.subscriber_type = SubscriberType::NaturalPerson;
        input.consent_evidence_id = Some(evidence_id);
        input.consent_status = Some("granted");
        (input, evidence_id)
    }

    /// A legal-person fixture that may rely on legitimate interest.
    fn legal_person() -> ContactPolicyInput<'static> {
        let mut input = base_input();
        input.subscriber_type = SubscriberType::LegalPerson;
        input
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
        let mut input = legal_person();
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
        let mut input = legal_person();
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
            &legal_person(),
        );
        assert_eq!(verdict.decision, ContactDecision::Allowed);
        assert_eq!(verdict.basis, "legitimate_interest");
    }

    #[test]
    fn allowed_with_granted_consent_is_allowed() {
        let (input, evidence_id) = consented_natural_person();
        let verdict = decide(Some(&policy(ContactDecision::Allowed, "consent")), &input);
        assert_eq!(verdict.decision, ContactDecision::Allowed);
        assert_eq!(input.consent_evidence_id, Some(evidence_id));
    }

    #[test]
    fn allowed_without_consent_fails_closed() {
        // A legal person on a consent-basis policy without evidence is not
        // prohibited (they may be reachable under legitimate interest), but
        // no autonomous send may proceed without either basis: fail closed.
        let mut input = legal_person();
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
        input.subscriber_type = SubscriberType::NaturalPerson;
        input.existing_customer = true;
        input.similar_product_basis = true;
        input.collection_opt_out_offered_at = Some(Utc::now());
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

    // -----------------------------------------------------------------------
    // §103¹ adversarial release tests
    // -----------------------------------------------------------------------

    #[test]
    fn subscriber_type_defaults_to_unknown() {
        assert_eq!(SubscriberType::default(), SubscriberType::Unknown);
    }

    #[test]
    fn natural_person_consent_matrix() {
        let policy = policy(ContactDecision::Allowed, "consent");

        // 1a. Active, versioned consent evidence → allowed.
        let (with_evidence, _) = consented_natural_person();
        assert_eq!(
            decide(Some(&policy), &with_evidence).decision,
            ContactDecision::Allowed
        );

        // 1b. No evidence → prohibited in an EU jurisdiction, never merely
        // "approval required".
        let mut without_evidence = base_input();
        without_evidence.subscriber_type = SubscriberType::NaturalPerson;
        without_evidence.contact_type = "b2c";
        without_evidence.consent_evidence_id = None;
        without_evidence.consent_status = None;
        let verdict = decide(Some(&policy), &without_evidence);
        assert_eq!(verdict.decision, ContactDecision::Prohibited);
        assert!(verdict.reason.contains("prior consent"));
        // The same input under a non-EU policy is a conservative approval,
        // not an autonomous send (the statute-specific prohibition is scoped
        // to the EU/EEA policy key).
        let mut us_policy = policy.clone();
        us_policy.jurisdiction = "US".into();
        let mut non_eu = without_evidence.clone();
        non_eu.recipient_country = Some("US".into());
        assert_eq!(
            decide_with_state(Some(&us_policy), true, &non_eu).decision,
            ContactDecision::ApprovalRequired
        );

        // 1c. Withdrawn consent, even with an evidence row still linked →
        // prohibited.
        let mut withdrawn = with_evidence.clone();
        withdrawn.consent_status = Some("withdrawn");
        assert_eq!(
            decide(Some(&policy), &withdrawn).decision,
            ContactDecision::Prohibited
        );
    }

    #[test]
    fn legal_person_needs_the_refusal_mechanism_in_the_disclosure() {
        // Legal person + assessed LI + the policy's disclosure guaranteeing an
        // opt-out → the §103¹ legal-person route is allowed.
        let allowed = decide(
            Some(&policy(ContactDecision::Allowed, "legitimate_interest")),
            &legal_person(),
        );
        assert_eq!(allowed.decision, ContactDecision::Allowed);
        assert_eq!(allowed.required_disclosure["opt_out"], true);

        // A policy row that turns the refusal mechanism off can never
        // authorize an autonomous send.
        let mut no_refusal = policy(ContactDecision::Allowed, "legitimate_interest");
        no_refusal.required_disclosure = serde_json::json!({ "opt_out": false });
        let verdict = decide(Some(&no_refusal), &legal_person());
        assert_eq!(verdict.decision, ContactDecision::ApprovalRequired);
        assert!(verdict.reason.contains("refusal"));

        // A natural person cannot use the legal-person legitimate-interest
        // route at all.
        let mut natural = legal_person();
        natural.subscriber_type = SubscriberType::NaturalPerson;
        let verdict = decide(
            Some(&policy(ContactDecision::Allowed, "legitimate_interest")),
            &natural,
        );
        assert_eq!(verdict.decision, ContactDecision::ApprovalRequired);
        assert!(verdict.reason.contains("natural person"));
    }

    #[test]
    fn soft_opt_in_requires_the_collection_time_opt_out() {
        let soft_policy = policy(ContactDecision::Allowed, "soft_opt_in");
        let mut customer = legal_person();
        customer.existing_customer = true;
        customer.similar_product_basis = true;
        customer.collection_opt_out_offered_at = Some(Utc::now());

        assert_eq!(
            decide(Some(&soft_policy), &customer).decision,
            ContactDecision::Allowed
        );

        // No opt-out offered at collection → the exception fails closed even
        // though the current message would carry one.
        let mut no_collection_opt_out = customer.clone();
        no_collection_opt_out.collection_opt_out_offered_at = None;
        let verdict = decide(Some(&soft_policy), &no_collection_opt_out);
        assert_eq!(verdict.decision, ContactDecision::ApprovalRequired);
        assert!(verdict.reason.contains("opt-out offered at collection"));

        // Not an existing customer, or not a similar product, also fails.
        let mut new_customer = customer.clone();
        new_customer.existing_customer = false;
        assert_eq!(
            decide(Some(&soft_policy), &new_customer).decision,
            ContactDecision::ApprovalRequired
        );
        let mut different_product = customer.clone();
        different_product.similar_product_basis = false;
        assert_eq!(
            decide(Some(&soft_policy), &different_product).decision,
            ContactDecision::ApprovalRequired
        );

        // The approval-required policy may only be lifted when the same full
        // evidence set is present.
        let approval_policy = policy(ContactDecision::ApprovalRequired, "soft_opt_in");
        assert_eq!(
            decide(Some(&approval_policy), &customer).decision,
            ContactDecision::Allowed
        );
        assert_eq!(
            decide(Some(&approval_policy), &no_collection_opt_out).decision,
            ContactDecision::ApprovalRequired
        );
    }

    #[test]
    fn unknown_subscriber_type_is_never_allowed_on_any_basis() {
        // Consent basis with evidence.
        let mut consent = base_input();
        consent.consent_evidence_id = Some(Uuid::new_v4());
        consent.consent_status = Some("granted");
        assert_ne!(
            decide(Some(&policy(ContactDecision::Allowed, "consent")), &consent).decision,
            ContactDecision::Allowed
        );

        // Legitimate interest, fully assessed.
        let mut li = base_input();
        li.legitimate_interest_assessed = true;
        assert_ne!(
            decide(
                Some(&policy(ContactDecision::Allowed, "legitimate_interest")),
                &li
            )
            .decision,
            ContactDecision::Allowed
        );

        // Soft opt-in with every condition satisfied.
        let mut soft = base_input();
        soft.existing_customer = true;
        soft.similar_product_basis = true;
        soft.collection_opt_out_offered_at = Some(Utc::now());
        assert_ne!(
            decide(
                Some(&policy(ContactDecision::Allowed, "soft_opt_in")),
                &soft
            )
            .decision,
            ContactDecision::Allowed
        );
        assert_ne!(
            decide(
                Some(&policy(ContactDecision::ApprovalRequired, "soft_opt_in")),
                &soft
            )
            .decision,
            ContactDecision::Allowed
        );

        // The identical facts with an established legal person are allowed,
        // proving the Unknown classification is the only blocker.
        let mut known = soft.clone();
        known.subscriber_type = SubscriberType::LegalPerson;
        assert_eq!(
            decide(
                Some(&policy(ContactDecision::Allowed, "soft_opt_in")),
                &known
            )
            .decision,
            ContactDecision::Allowed
        );

        // And a work-email-style B2B contact type is NOT accepted as proof of
        // legal personality.
        assert_eq!(consent.contact_type, "b2b_professional");
        assert_eq!(consent.subscriber_type, SubscriberType::Unknown);
    }

    #[test]
    fn suppressed_recipient_is_prohibited_regardless_of_consent() {
        let (mut input, _) = consented_natural_person();
        input.consent_status = Some("suppressed");
        // Even a permissive policy and live evidence cannot resurrect it.
        assert_eq!(
            decide(Some(&policy(ContactDecision::Allowed, "consent")), &input).decision,
            ContactDecision::Prohibited
        );
        // And suppression precedes the policy lookup entirely.
        assert_eq!(decide(None, &input).decision, ContactDecision::Prohibited);
    }

    #[test]
    fn withdrawn_evidence_prohibits_and_foreign_evidence_is_never_accepted() {
        let contact = Uuid::new_v4();
        let other_contact = Uuid::new_v4();
        let now = Utc::now();

        // Newest row is withdrawn → Withdrawn, never Granted.
        let withdrawal = evidence_row(
            Uuid::new_v4(),
            Some(contact),
            now - chrono::Duration::days(10),
            Some(now - chrono::Duration::days(1)),
        );
        let state = current_consent_state(std::slice::from_ref(&withdrawal), contact, now);
        assert!(matches!(state, ConsentState::Withdrawn { .. }));
        assert_eq!(state.status(), Some("withdrawn"));
        assert_eq!(state.evidence_id(), Some(withdrawal.id));

        // Evidence belonging to a DIFFERENT contact is never this contact's
        // consent — even if it is active.
        let foreign = evidence_row(
            Uuid::new_v4(),
            Some(other_contact),
            now - chrono::Duration::days(1),
            None,
        );
        assert_eq!(
            current_consent_state(std::slice::from_ref(&foreign), contact, now),
            ConsentState::None
        );

        // Re-consent after a withdrawal is allowed: the newest usable row wins.
        let re_consent = evidence_row(
            Uuid::new_v4(),
            Some(contact),
            now - chrono::Duration::hours(1),
            None,
        );
        let rows = vec![withdrawal, re_consent];
        let state = current_consent_state(&rows, contact, now);
        assert!(matches!(state, ConsentState::Granted { .. }));
        assert_eq!(state.status(), Some("granted"));

        // The pure decision treats evidence + withdrawn status as prohibited.
        let (mut input, _) = consented_natural_person();
        input.consent_status = Some("withdrawn");
        assert_eq!(
            decide(Some(&policy(ContactDecision::Allowed, "consent")), &input).decision,
            ContactDecision::Prohibited
        );
    }

    #[test]
    fn hostile_evidence_rows_fail_closed_without_panicking() {
        let contact = Uuid::new_v4();
        let now = Utc::now();
        let base = evidence_row(
            Uuid::new_v4(),
            Some(contact),
            now - chrono::Duration::days(1),
            None,
        );

        let mut empty_text = base.clone();
        empty_text.consent_text = "   \n\t ".into();
        let mut zero_version = base.clone();
        zero_version.consent_version = 0;
        let mut negative_version = base.clone();
        negative_version.consent_version = -3;
        let mut future_collection = base.clone();
        future_collection.collected_at = now + chrono::Duration::days(1);
        let mut withdrawal_before_collection = base.clone();
        withdrawal_before_collection.withdrawn_at = Some(now - chrono::Duration::days(2));
        let mut null_source = base.clone();
        null_source.source = None;
        let mut blank_source = base.clone();
        blank_source.source = Some("  ".into());

        let hostile = [
            empty_text,
            zero_version,
            negative_version,
            future_collection,
            withdrawal_before_collection,
            null_source,
            blank_source,
        ];
        for row in &hostile {
            let state = current_consent_state(std::slice::from_ref(row), contact, now);
            assert_eq!(
                state,
                ConsentState::None,
                "row {:?} must be rejected as unusable, not trusted",
                row.id
            );
            assert_eq!(state.status(), None);
            assert_eq!(state.evidence_id(), None);
        }

        // The decision layer consequence: a natural person with only hostile
        // evidence is prohibited, not allowed.
        let mut input = base_input();
        input.subscriber_type = SubscriberType::NaturalPerson;
        input.contact_type = "b2c";
        input.consent_evidence_id = None;
        assert_eq!(
            decide(Some(&policy(ContactDecision::Allowed, "consent")), &input).decision,
            ContactDecision::Prohibited
        );
    }

    /// Live-database coverage (soft-skips when no canonical test database is
    /// configured): the loader must scope evidence to the contact and the
    /// point, and must turn a newer withdrawn row into `Withdrawn`.
    #[tokio::test]
    async fn load_consent_state_is_scoped_to_contact_and_point() {
        let Some(db) = crate::test_db::canonical_test_pool(
            "legal_policy::tests::load_consent_state_is_scoped",
        )
        .await
        else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("consent-load");
        let contact_a = Uuid::new_v4();
        let contact_b = Uuid::new_v4();
        let point_a = Uuid::new_v4();
        let point_q = Uuid::new_v4();

        let insert_contact = |id: Uuid, tenant: String| {
            let db = db.clone();
            async move {
                sqlx::query(
                    "INSERT INTO sales_contacts (id, tenant_id, full_name) \
                     VALUES ($1, $2, 'Consent Fixture')",
                )
                .bind(id)
                .bind(&tenant)
                .execute(&db)
                .await
                .expect("insert contact");
            }
        };
        insert_contact(contact_a, tenant.clone()).await;
        insert_contact(contact_b, tenant.clone()).await;

        for (point, contact, value) in [
            (point_a, contact_a, format!("a-{contact_a}@example.com")),
            (point_q, contact_a, format!("q-{contact_a}@example.com")),
        ] {
            sqlx::query(
                "INSERT INTO sales_contact_points \
                     (id, tenant_id, contact_id, channel, value, normalized_value) \
                 VALUES ($1, $2, $3, 'email', $4, $4)",
            )
            .bind(point)
            .bind(&tenant)
            .bind(contact)
            .bind(&value)
            .execute(&db)
            .await
            .expect("insert contact point");
        }

        let insert_evidence = |id: Uuid,
                               tenant: String,
                               contact: Uuid,
                               point: Option<Uuid>,
                               collected_at: DateTime<Utc>,
                               withdrawn_at: Option<DateTime<Utc>>| {
            let db = db.clone();
            async move {
                sqlx::query(
                    "INSERT INTO sales_consent_evidence \
                         (id, tenant_id, contact_id, contact_point_id, consent_text, \
                          consent_version, source, collected_at, withdrawn_at) \
                     VALUES ($1, $2, $3, $4, 'I agree to marketing email.', 1, \
                             'form:test', $5, $6)",
                )
                .bind(id)
                .bind(&tenant)
                .bind(contact)
                .bind(point)
                .bind(collected_at)
                .bind(withdrawn_at)
                .execute(&db)
                .await
                .expect("insert consent evidence");
            }
        };

        let now = Utc::now();
        // Evidence for contact B must never answer for contact A.
        insert_evidence(
            Uuid::new_v4(),
            tenant.clone(),
            contact_b,
            None,
            now - chrono::Duration::minutes(5),
            None,
        )
        .await;
        assert_eq!(
            load_consent_state(&db, &tenant, contact_a, Some(point_a))
                .await
                .expect("load for A"),
            ConsentState::None
        );

        // Evidence bound to a DIFFERENT point of A is not consent for the
        // email point being contacted.
        insert_evidence(
            Uuid::new_v4(),
            tenant.clone(),
            contact_a,
            Some(point_q),
            now - chrono::Duration::hours(2),
            None,
        )
        .await;
        assert_eq!(
            load_consent_state(&db, &tenant, contact_a, Some(point_a))
                .await
                .expect("load for A"),
            ConsentState::None
        );

        // Person-level evidence (contact_point_id IS NULL) is accepted.
        let granted = Uuid::new_v4();
        insert_evidence(
            granted,
            tenant.clone(),
            contact_a,
            None,
            now - chrono::Duration::hours(1),
            None,
        )
        .await;
        assert_eq!(
            load_consent_state(&db, &tenant, contact_a, Some(point_a))
                .await
                .expect("load for A"),
            ConsentState::Granted {
                evidence_id: granted
            }
        );

        // A newer withdrawal flips the state (withdrawal wins by recency).
        let withdrawn = Uuid::new_v4();
        insert_evidence(withdrawn, tenant.clone(), contact_a, None, now, Some(now)).await;
        assert_eq!(
            load_consent_state(&db, &tenant, contact_a, Some(point_a))
                .await
                .expect("load for A"),
            ConsentState::Withdrawn {
                evidence_id: withdrawn
            }
        );

        // Cleanup is best-effort; the tenant is unique to this run.
        let _ = sqlx::query("DELETE FROM sales_consent_evidence WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&db)
            .await;
        let _ = sqlx::query("DELETE FROM sales_contact_points WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&db)
            .await;
        let _ = sqlx::query("DELETE FROM sales_contacts WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&db)
            .await;
    }

    /// Minimal well-formed evidence row factory for the tests above.
    fn evidence_row(
        id: Uuid,
        contact_id: Option<Uuid>,
        collected_at: DateTime<Utc>,
        withdrawn_at: Option<DateTime<Utc>>,
    ) -> ConsentEvidenceRow {
        ConsentEvidenceRow {
            id,
            contact_id,
            contact_point_id: None,
            consent_text: "I agree to receive marketing emails from ApexMail.".into(),
            consent_version: 1,
            source: Some("form:newsletter".into()),
            collected_at,
            withdrawn_at,
        }
    }
}
