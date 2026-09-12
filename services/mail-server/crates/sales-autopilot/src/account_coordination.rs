//! §38 — account-level contact coordination.
//!
//! Automation that independently contacts five people at one company does not
//! read as a person; it reads as a machine and it burns the account. Every
//! contact attempt must first win an account-level slot. This module owns the
//! rules and the operator-readable denial reasons (they land verbatim in a
//! Decision Packet's `block_reasons`).
//!
//! # Rule table
//!
//! | # | Rule | Source | Verdict |
//! |---|---|---|---|
//! | R1 | Stop the whole account after a strong objection | account flag / `complaint`/`unsubscribe` classification | `Denied`, unconditional — even for referrals |
//! | R2 | Cooldown after a negative reply | `sales_accounts.negative_reply_cooldown_hours` × `not_interested` classification time | `Deferred { until }`, unless referral |
//! | R3 | Priority persona ordering | requested persona vs personas of active enrollments | `Denied`, unless referral |
//! | R4 | Multi-threading only at defined tiers | `sales_accounts.multi_thread_allowed` | `Denied` when a second concurrent thread is requested at a non-multi-thread tier |
//! | R5 | Max simultaneous active contacts | `sales_accounts.max_active_contacts` | `Denied` at the cap |
//! | R6 | Promote a referred contact | `is_referral` | bypasses R2/R3; at the cap it still needs a multi-threading tier |
//!
//! Rule evaluation order in [`decide`]: R1 → R2 → R3 → R4 → R5 (with the R6
//! referral exceptions applied to R2/R3 and to R5 only at multi-thread tiers).
//! A referral never overrides a strong objection.
//!
//! Active contacts are enrollments in a non-terminal state
//! ([`ACTIVE_ENROLLMENT_STATES`]); terminal states (`completed`,
//! `suppressed`, `failed`) free their slot.
//!
//! `max_active_contacts <= 0` and an overflowing cooldown are hostile inputs:
//! both fail closed (deny / defer to `DateTime::MAX_UTC`) and never panic.

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::SalesError;

/// Enrollment states that occupy an account contact slot
/// (`sales_enrollments.state`, migration 200_sales_autopilot_v2_unification.sql:498-500).
///
/// A replied / meeting-booked contact is still a live conversation, so it
/// keeps its slot; `completed`, `suppressed` and `failed` are terminal.
pub const ACTIVE_ENROLLMENT_STATES: &[&str] = &[
    "pending",
    "active",
    "waiting",
    "paused",
    "replied",
    "meeting_booked",
];

/// Reply dispositions that stop the whole account (R1).
pub const STRONG_OBJECTION_DISPOSITIONS: &[&str] = &["complaint", "unsubscribe"];

/// Reply dispositions that start the negative-reply cooldown (R2).
pub const NEGATIVE_REPLY_DISPOSITIONS: &[&str] = &["not_interested"];

/// Account lifecycle value that stops all contact.
pub const STOPPED_LIFECYCLE: &str = "disqualified";

/// Account-level policy snapshot the pure [`decide`] function consumes.
///
/// `max_active_contacts` is `i32` (not unsigned) on purpose: a hostile or
/// corrupt value must be representable so the rules can fail closed instead
/// of wrapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountPolicy {
    /// `sales_accounts.max_active_contacts` (DB CHECK `>= 1`; a value `<= 0`
    /// is treated as "no contacts allowed", fail closed).
    pub max_active_contacts: i32,
    /// `sales_accounts.multi_thread_allowed`: may more than one contact be
    /// active simultaneously at this tier?
    pub multi_thread_allowed: bool,
    /// `sales_accounts.negative_reply_cooldown_hours`. `<= 0` disables the
    /// cooldown; an overflow fails closed to `DateTime::MAX_UTC`.
    pub negative_reply_cooldown_hours: i64,
    /// True when the requested contact is at least as high-priority as every
    /// currently active contact (computed from [`persona_rank`]). When no
    /// contact is active this is irrelevant and R3 does not fire.
    pub priority_persona_selected: bool,
}

impl Default for AccountPolicy {
    fn default() -> Self {
        Self {
            max_active_contacts: 2,
            multi_thread_allowed: false,
            negative_reply_cooldown_hours: 0,
            priority_persona_selected: true,
        }
    }
}

/// The outcome of a contact-slot request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinationVerdict {
    /// The attempt may proceed.
    Allowed,
    /// The attempt must not proceed; the string is operator-readable and is
    /// suitable for a Decision Packet `block_reasons` entry.
    Denied(String),
    /// The attempt must wait until the given instant (cooldown).
    Deferred { until: DateTime<Utc> },
}

impl CoordinationVerdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }

    /// Operator-readable reason for anything that is not `Allowed`.
    pub fn block_reason(&self) -> Option<String> {
        match self {
            Self::Allowed => None,
            Self::Denied(reason) => Some(reason.clone()),
            Self::Deferred { until } => Some(format!(
                "account contact cooldown active until {}",
                until.to_rfc3339()
            )),
        }
    }
}

/// Persona priority rank used by R3: C-level/founder/owner (4) >
/// head/director (3) > manager/lead (2) > senior/individual contributor (1) >
/// unknown (0).
pub fn persona_rank(persona: Option<&str>) -> u8 {
    let Some(raw) = persona.map(str::trim).filter(|value| !value.is_empty()) else {
        return 0;
    };
    let lower = raw.to_ascii_lowercase();
    const RANK_4: &[&str] = &[
        "ceo",
        "cto",
        "cfo",
        "coo",
        "cmo",
        "cro",
        "cio",
        "ciso",
        "founder",
        "co-founder",
        "owner",
        "president",
        "partner",
        "chief",
        "vice president",
        "vp",
        "executive",
        "c-level",
        "c-suite",
    ];
    const RANK_3: &[&str] = &["head", "director"];
    const RANK_2: &[&str] = &["manager", "lead"];
    const RANK_1: &[&str] = &[
        "senior",
        "staff",
        "principal",
        "specialist",
        "engineer",
        "analyst",
        "individual",
    ];
    if RANK_4.iter().any(|needle| lower.contains(needle)) {
        4
    } else if RANK_3.iter().any(|needle| lower.contains(needle)) {
        3
    } else if RANK_2.iter().any(|needle| lower.contains(needle)) {
        2
    } else if RANK_1.iter().any(|needle| lower.contains(needle)) {
        1
    } else {
        0
    }
}

/// Is the requested persona at least as high-priority as every active one?
/// An empty active set is always `true` (nobody owns the account yet).
pub fn is_priority_persona(requested: Option<&str>, active_personas: &[String]) -> bool {
    let requested_rank = persona_rank(requested);
    active_personas
        .iter()
        .all(|active| persona_rank(Some(active.as_str())) <= requested_rank)
}

/// Cooldown end instant for a negative reply. `hours <= 0` means no cooldown
/// (returns `None`); an arithmetic overflow fails closed to
/// `DateTime::MAX_UTC` rather than panicking.
fn cooldown_until(last_negative_reply_at: DateTime<Utc>, hours: i64) -> Option<DateTime<Utc>> {
    if hours <= 0 {
        return None;
    }
    match TimeDelta::try_hours(hours) {
        Some(delta) => Some(
            last_negative_reply_at
                .checked_add_signed(delta)
                .unwrap_or(DateTime::<Utc>::MAX_UTC),
        ),
        None => Some(DateTime::<Utc>::MAX_UTC),
    }
}

/// PURE coordination decision. No database, no clock beyond `now`, no panics.
///
/// See the module-level rule table for semantics. `active_contacts` is the
/// count of enrollments in [`ACTIVE_ENROLLMENT_STATES`].
pub fn decide(
    account: &AccountPolicy,
    active_contacts: usize,
    last_negative_reply_at: Option<DateTime<Utc>>,
    has_strong_objection: bool,
    is_referral: bool,
    now: DateTime<Utc>,
) -> CoordinationVerdict {
    // R1 — a strong objection stops the whole account, unconditionally.
    if has_strong_objection {
        return CoordinationVerdict::Denied(
            "account stopped: a strong objection (complaint/unsubscribe or disqualified \
             lifecycle) blocks every new contact attempt"
                .to_string(),
        );
    }

    // R6 exceptions: a referral skips the cooldown and persona ordering.
    if !is_referral {
        // R2 — negative-reply cooldown.
        if let Some(last) = last_negative_reply_at {
            if let Some(until) = cooldown_until(last, account.negative_reply_cooldown_hours) {
                if now < until {
                    return CoordinationVerdict::Deferred { until };
                }
            }
        }

        // R3 — priority persona ordering (only relevant when someone is
        // already active).
        if active_contacts > 0 && !account.priority_persona_selected {
            return CoordinationVerdict::Denied(
                "persona priority: an active contact on a higher-priority persona already \
                 owns this account; wait for their outcome or have an operator override"
                    .to_string(),
            );
        }
    }

    // R5 (guard) — a non-positive budget denies everything, referrals too.
    if account.max_active_contacts <= 0 {
        return CoordinationVerdict::Denied(
            "account contact budget is zero or negative; no contact attempts are permitted \
             until the account policy is corrected"
                .to_string(),
        );
    }
    let cap = account.max_active_contacts as usize;

    if !is_referral {
        // R4 — multi-threading only at defined tiers.
        if !account.multi_thread_allowed && active_contacts >= 1 {
            return CoordinationVerdict::Denied(
                "multi-threading not permitted at this account tier \
                 (multi_thread_allowed is false); one active contact at a time"
                    .to_string(),
            );
        }
        // R5 — contact cap.
        if active_contacts >= cap {
            return CoordinationVerdict::Denied(format!(
                "contact cap reached ({active_contacts} of {} active contacts); \
                 finish or release an existing thread before adding another",
                account.max_active_contacts
            ));
        }
        return CoordinationVerdict::Allowed;
    }

    // R6 — referral promotion. Past the cap only a multi-threading tier may
    // open an additional thread; otherwise the referral still has to wait for
    // a free slot, but at a non-multi-thread tier it cannot be a second
    // simultaneous thread at all.
    if !account.multi_thread_allowed && active_contacts >= 1 {
        return CoordinationVerdict::Denied(
            "referral cannot open a second concurrent thread: multi-threading is not \
             permitted at this account tier"
                .to_string(),
        );
    }
    if active_contacts >= cap && !account.multi_thread_allowed {
        return CoordinationVerdict::Denied(format!(
            "referral cannot be added at the contact cap ({active_contacts} of {} active): \
             this tier does not permit multi-threading",
            account.max_active_contacts
        ));
    }
    CoordinationVerdict::Allowed
}

// ---------------------------------------------------------------------------
// Database path
// ---------------------------------------------------------------------------

/// Count enrollments currently occupying a contact slot for an account.
pub async fn active_contact_count(
    db: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
) -> Result<usize, SalesError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_enrollments
         WHERE tenant_id = $1 AND account_id = $2 AND state = ANY($3)",
    )
    .bind(tenant_id)
    .bind(account_id)
    .bind(ACTIVE_ENROLLMENT_STATES)
    .fetch_one(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(count.max(0) as usize)
}

/// Read the account policy plus the objection/cooldown/persona state, then
/// run [`decide`]. The returned verdict is operator-readable.
///
/// This wrapper takes the account row `FOR UPDATE`, counts active contacts
/// and releases the lock — it does not itself reserve a slot. Callers that
/// must reserve a slot atomically (insert the enrollment before releasing the
/// lock) use [`request_contact_slot_in_tx`].
pub async fn request_contact_slot(
    db: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
    contact_id: Uuid,
    now: DateTime<Utc>,
) -> Result<CoordinationVerdict, SalesError> {
    let mut tx = db
        .begin()
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
    // Referral promotion requires first-party knowledge the account tables do
    // not carry; callers with it use `request_contact_slot_in_tx` or `decide`.
    let verdict =
        request_contact_slot_in_tx(&mut tx, tenant_id, account_id, contact_id, now, false).await?;
    tx.rollback()
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(verdict)
}

/// Transactional slot request. The caller owns the transaction and can insert
/// the enrollment before committing, which is what makes the account-level
/// cap safe under concurrency: the `FOR UPDATE` account lock serialises
/// simultaneous requests, each of which then re-counts committed enrollments.
///
/// `is_referral` promotes a referred contact (R6): it bypasses the cooldown
/// and persona ordering and, at a multi-threading tier, the contact cap.
///
/// # Referral input on the live path
///
/// There is no canonical column that marks a *contact* as referred:
/// `sales_reply_classifications.disposition = 'referral'` records an inbound
/// referral reply (and `enrollments::lock_on_reply` moves that enrollment to
/// `replied`), and `sales_contacts`/`sales_accounts`/`sales_enrollments` carry
/// no `is_referral`/`referred_by` field. The live enrollment path therefore
/// passes `false` and R6 can only fire for callers that hold first-party
/// referral knowledge (they call this function or the pure [`decide`]
/// directly). Adding a canonical referral column is the prerequisite for
/// enforcing referral promotion in the live path.
#[allow(clippy::too_many_arguments)]
pub async fn request_contact_slot_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    account_id: Uuid,
    contact_id: Uuid,
    now: DateTime<Utc>,
    is_referral: bool,
) -> Result<CoordinationVerdict, SalesError> {
    use sqlx::Row;

    if tenant_id.trim().is_empty() {
        return Err(SalesError::InvalidInput("tenant_id is required".into()));
    }

    // Lock the account first: this is the serialisation point for the cap.
    let account = sqlx::query(
        "SELECT max_active_contacts, multi_thread_allowed, negative_reply_cooldown_hours, lifecycle
         FROM sales_accounts
         WHERE id = $1 AND tenant_id = $2
         FOR UPDATE",
    )
    .bind(account_id)
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let Some(account) = account else {
        return Err(SalesError::InvalidInput(format!(
            "account {account_id} not found for tenant"
        )));
    };

    // SMALLINT in the schema; widen to i32 so hostile values stay representable.
    let max_active_contacts: i16 = account
        .try_get("max_active_contacts")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let max_active_contacts = i32::from(max_active_contacts);
    let multi_thread_allowed: bool = account
        .try_get("multi_thread_allowed")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    // INTEGER in the schema; widen to i64 for the checked cooldown arithmetic.
    let negative_reply_cooldown_hours: i32 = account
        .try_get("negative_reply_cooldown_hours")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let negative_reply_cooldown_hours = i64::from(negative_reply_cooldown_hours);
    let lifecycle: String = account
        .try_get("lifecycle")
        .map_err(|error| SalesError::Database(error.to_string()))?;

    // The requested contact must belong to the account.
    let persona: Option<String> = sqlx::query_scalar(
        "SELECT persona FROM sales_contacts
         WHERE id = $1 AND tenant_id = $2 AND account_id = $3",
    )
    .bind(contact_id)
    .bind(tenant_id)
    .bind(account_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let Some(requested_persona) = persona else {
        return Err(SalesError::InvalidInput(format!(
            "contact {contact_id} not found on account {account_id} for tenant"
        )));
    };

    // R1 inputs: lifecycle stop plus a strong-objection reply classification.
    let strong_objection: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1
            FROM sales_reply_classifications rc
            LEFT JOIN sales_enrollments e
                   ON e.id = rc.enrollment_id AND e.tenant_id = rc.tenant_id
            LEFT JOIN sales_contacts c
                   ON c.id = COALESCE(rc.contact_id, e.contact_id) AND c.tenant_id = rc.tenant_id
            WHERE rc.tenant_id = $1
              AND COALESCE(e.account_id, c.account_id) = $2
              AND rc.disposition = ANY($3)
         )",
    )
    .bind(tenant_id)
    .bind(account_id)
    .bind(STRONG_OBJECTION_DISPOSITIONS)
    .fetch_one(&mut **tx)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let has_strong_objection = strong_objection || lifecycle == STOPPED_LIFECYCLE;

    // R2 input: the most recent negative reply for the account.
    let last_negative_reply_at: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT MAX(rc.created_at)
         FROM sales_reply_classifications rc
         LEFT JOIN sales_enrollments e
                ON e.id = rc.enrollment_id AND e.tenant_id = rc.tenant_id
         LEFT JOIN sales_contacts c
                ON c.id = COALESCE(rc.contact_id, e.contact_id) AND c.tenant_id = rc.tenant_id
         WHERE rc.tenant_id = $1
           AND COALESCE(e.account_id, c.account_id) = $2
           AND rc.disposition = ANY($3)",
    )
    .bind(tenant_id)
    .bind(account_id)
    .bind(NEGATIVE_REPLY_DISPOSITIONS)
    .fetch_one(&mut **tx)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    // R3 input: personas of the currently active contacts.
    let active_personas: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT c.persona
         FROM sales_enrollments e
         JOIN sales_contacts c ON c.id = e.contact_id AND c.tenant_id = e.tenant_id
         WHERE e.tenant_id = $1 AND e.account_id = $2 AND e.state = ANY($3)",
    )
    .bind(tenant_id)
    .bind(account_id)
    .bind(ACTIVE_ENROLLMENT_STATES)
    .fetch_all(&mut **tx)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let active_personas: Vec<String> = active_personas.into_iter().flatten().collect();

    let active_contacts: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_enrollments
         WHERE tenant_id = $1 AND account_id = $2 AND state = ANY($3)",
    )
    .bind(tenant_id)
    .bind(account_id)
    .bind(ACTIVE_ENROLLMENT_STATES)
    .fetch_one(&mut **tx)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    let policy = AccountPolicy {
        max_active_contacts,
        multi_thread_allowed,
        negative_reply_cooldown_hours,
        priority_persona_selected: is_priority_persona(
            Some(requested_persona.as_str()),
            &active_personas,
        ),
    };

    Ok(decide(
        &policy,
        active_contacts.max(0) as usize,
        last_negative_reply_at,
        has_strong_objection,
        is_referral,
        now,
    ))
}

/// The live-path admission gate: hold the account reservation lock, then
/// evaluate every coordination rule.
///
/// This is what makes coordination a production gate rather than a library
/// feature. The explicit `SELECT ... FOR UPDATE` on `sales_accounts` is the
/// documented serialisation point (migration 206): while the caller's
/// transaction holds it, no concurrent enrollment for the same account can
/// re-count the active contacts between this decision and the enrollment
/// insert, so `max_active_contacts` cannot be exceeded by a race.
///
/// [`request_contact_slot_in_tx`] takes the same lock itself; doing it here
/// first keeps the lock in the caller's hands for the rest of the admission
/// work (the enrollment and the touch reservation) instead of only for the
/// count. `is_referral` carries the same meaning and the same live-path
/// limitation documented on [`request_contact_slot_in_tx`].
pub async fn request_contact_slot_locked_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    account_id: Uuid,
    contact_id: Uuid,
    now: DateTime<Utc>,
    is_referral: bool,
) -> Result<CoordinationVerdict, SalesError> {
    let locked: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM sales_accounts \
         WHERE id = $1 AND tenant_id = $2 \
         FOR UPDATE",
    )
    .bind(account_id)
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    if locked.is_none() {
        return Err(SalesError::InvalidInput(format!(
            "account {account_id} not found for tenant '{tenant_id}'; \
             contact slot coordination cannot be evaluated"
        )));
    }

    request_contact_slot_in_tx(tx, tenant_id, account_id, contact_id, now, is_referral).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn t0() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 11, 12, 0, 0).unwrap()
    }

    fn policy(max: i32, multi: bool, cooldown_hours: i64) -> AccountPolicy {
        AccountPolicy {
            max_active_contacts: max,
            multi_thread_allowed: multi,
            negative_reply_cooldown_hours: cooldown_hours,
            priority_persona_selected: true,
        }
    }

    fn denied_reason(verdict: &CoordinationVerdict) -> String {
        match verdict {
            CoordinationVerdict::Denied(reason) => reason.clone(),
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    // ---- R1: strong objection stops the whole account ---------------------

    #[test]
    fn strong_objection_denies_even_with_a_free_slot_and_even_for_referrals() {
        let account = policy(5, true, 0);
        let verdict = decide(&account, 0, None, true, false, t0());
        assert!(matches!(verdict, CoordinationVerdict::Denied(_)));
        assert!(denied_reason(&verdict).contains("strong objection"));

        let referred = decide(&account, 0, None, true, true, t0());
        assert!(matches!(referred, CoordinationVerdict::Denied(_)));
        assert!(denied_reason(&referred).contains("strong objection"));
    }

    #[test]
    fn stopped_lifecycle_constant_is_the_disqualified_value() {
        assert_eq!(STOPPED_LIFECYCLE, "disqualified");
    }

    // ---- R2: negative-reply cooldown --------------------------------------

    #[test]
    fn negative_reply_cooldown_defers_until_the_window_elapses() {
        let account = policy(5, true, 48);
        let last = t0() - chrono::Duration::hours(1);
        let verdict = decide(&account, 0, Some(last), false, false, t0());
        match verdict {
            CoordinationVerdict::Deferred { until } => {
                assert_eq!(until, last + chrono::Duration::hours(48));
                assert!(until > t0());
            }
            other => panic!("expected Deferred, got {other:?}"),
        }

        // After the cooldown, the attempt is allowed again.
        let later = last + chrono::Duration::hours(49);
        assert!(decide(&account, 0, Some(last), false, false, later).is_allowed());

        // Zero hours disables the cooldown.
        let no_cooldown = policy(5, true, 0);
        assert!(decide(&no_cooldown, 0, Some(last), false, false, t0()).is_allowed());
    }

    #[test]
    fn huge_cooldown_fails_closed_without_overflow() {
        let account = policy(5, true, i64::MAX);
        let last = t0() - chrono::Duration::days(1);
        match decide(&account, 0, Some(last), false, false, t0()) {
            CoordinationVerdict::Deferred { until } => {
                assert_eq!(until, DateTime::<Utc>::MAX_UTC);
            }
            other => panic!("expected Deferred, got {other:?}"),
        }
    }

    #[test]
    fn referral_bypasses_the_cooldown() {
        let account = policy(5, true, 72);
        let last = t0() - chrono::Duration::hours(1);
        assert!(decide(&account, 0, Some(last), false, true, t0()).is_allowed());
    }

    // ---- R3: priority persona ordering ------------------------------------

    #[test]
    fn lower_priority_persona_is_denied_only_while_someone_is_active() {
        let mut account = policy(5, true, 0);
        account.priority_persona_selected = false;
        let verdict = decide(&account, 1, None, false, false, t0());
        assert!(matches!(verdict, CoordinationVerdict::Denied(_)));
        assert!(denied_reason(&verdict).contains("persona priority"));

        // Nobody active: the ordering rule cannot fire.
        assert!(decide(&account, 0, None, false, false, t0()).is_allowed());

        // Referral promotion bypasses persona ordering.
        assert!(decide(&account, 1, None, false, true, t0()).is_allowed());

        // A cleared priority persona passes.
        account.priority_persona_selected = true;
        assert!(decide(&account, 1, None, false, false, t0()).is_allowed());
    }

    #[test]
    fn persona_rank_orders_decision_makers_above_individuals() {
        // CEO and VP are the same tier (4); tiers step down from there.
        assert_eq!(persona_rank(Some("CEO")), 4);
        assert_eq!(persona_rank(Some("VP Engineering")), 4);
        assert_eq!(persona_rank(Some("Head of Ops")), 3);
        assert_eq!(persona_rank(Some("Engineering Manager")), 2);
        assert_eq!(persona_rank(Some("Senior Engineer")), 1);
        assert!(persona_rank(Some("CEO")) > persona_rank(Some("Head of Ops")));
        assert!(persona_rank(Some("Head of Ops")) > persona_rank(Some("Engineering Manager")));
        assert!(persona_rank(Some("Engineering Manager")) > persona_rank(Some("Senior Engineer")));
        assert!(persona_rank(Some("Senior Engineer")) > persona_rank(None));
        assert_eq!(persona_rank(None), 0);
        assert_eq!(persona_rank(Some("   ")), 0);
        assert!(is_priority_persona(None, &[]));
        assert!(is_priority_persona(Some("VP"), &["Engineer".into()]));
        assert!(!is_priority_persona(Some("Engineer"), &["VP".into()]));
        assert!(is_priority_persona(Some("VP"), &["Director".into()]));
    }

    // ---- R4: multi-threading only at defined tiers ------------------------

    #[test]
    fn multi_threading_denied_when_the_tier_forbids_it() {
        let account = policy(5, false, 0);
        let verdict = decide(&account, 1, None, false, false, t0());
        assert!(matches!(verdict, CoordinationVerdict::Denied(_)));
        assert!(denied_reason(&verdict).contains("multi-threading"));

        // The first contact at the account is still fine.
        assert!(decide(&account, 0, None, false, false, t0()).is_allowed());

        // A multi-threading tier allows the second concurrent thread.
        let multi = policy(5, true, 0);
        assert!(decide(&multi, 1, None, false, false, t0()).is_allowed());
    }

    // ---- R5: max simultaneous active contacts -----------------------------

    #[test]
    fn contact_cap_denies_when_reached() {
        let account = policy(2, true, 0);
        assert!(decide(&account, 1, None, false, false, t0()).is_allowed());
        let verdict = decide(&account, 2, None, false, false, t0());
        assert!(matches!(verdict, CoordinationVerdict::Denied(_)));
        let reason = denied_reason(&verdict);
        assert!(
            reason.contains("cap"),
            "operator-readable cap reason: {reason}"
        );
        assert!(reason.contains("2 of 2"));
    }

    #[test]
    fn zero_or_negative_contact_budget_fails_closed() {
        for budget in [0, -1, i32::MIN] {
            let account = policy(budget, true, 0);
            let verdict = decide(&account, 0, None, false, false, t0());
            assert!(
                matches!(verdict, CoordinationVerdict::Denied(_)),
                "budget {budget} must fail closed"
            );
            // Even a referral cannot bypass a corrupt budget.
            let referred = decide(&account, 0, None, false, true, t0());
            assert!(matches!(referred, CoordinationVerdict::Denied(_)));
        }
    }

    // ---- R6: referral promotion -------------------------------------------

    #[test]
    fn referral_is_allowed_at_the_cap_when_the_tier_multi_threads() {
        let multi = policy(2, true, 0);
        assert!(decide(&multi, 2, None, false, true, t0()).is_allowed());
        assert!(decide(&multi, 3, None, false, true, t0()).is_allowed());

        let single_thread = policy(2, false, 0);
        let verdict = decide(&single_thread, 2, None, false, true, t0());
        assert!(matches!(verdict, CoordinationVerdict::Denied(_)));
        assert!(denied_reason(&verdict).contains("multi-threading"));
    }

    // ---- operator-readable reasons ----------------------------------------

    #[test]
    fn every_non_allowed_verdict_has_an_operator_readable_reason() {
        assert_eq!(CoordinationVerdict::Allowed.block_reason(), None);
        let denied = CoordinationVerdict::Denied("why".into());
        assert_eq!(denied.block_reason().as_deref(), Some("why"));
        let deferred = CoordinationVerdict::Deferred { until: t0() };
        let reason = deferred.block_reason().expect("deferred reason");
        assert!(reason.contains("cooldown"));
        assert!(reason.contains("2026"));
        assert!(!denied.is_allowed());
    }
}
