//! §7/§11 — always-on account change detection.
//!
//! The audit's point is blunt: *"Don't merely find companies that fit. Detect
//! when an already-good company has just become unusually likely to buy."*
//! This module owns:
//!
//! * the [`SignalType`] registry — every change class the engine watches,
//!   each with a documented half-life and default strength;
//! * [`record_signal`] / [`active_signals`] — the canonical `sales_signals`
//!   persistence path, honouring `expires_at`;
//! * [`signal_urgency`] — a pure exponential-decay function so a stale signal
//!   contributes less, and [`combined_urgency`] — a noisy-OR combination of
//!   several signals;
//! * [`email_stack`] — passive, lawful email-infrastructure signals.
//!
//! Opens and clicks are deliberately not signal types here: they are recorded
//! in `sales_outcomes` but must never become a purchase-intent input (Apple
//! Mail Privacy Protection and automated image fetching make them too weak to
//! optimize against).

pub mod email_stack;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::SalesError;

/// Half-life used for signal types not present in [`SIGNAL_TYPES`]. Unknown
/// types are still recorded (forward compatibility) but decay at this rate.
pub const DEFAULT_SIGNAL_HALF_LIFE_DAYS: f32 = 30.0;

/// Hard bound on `signal_urgency` inputs/outputs: urgency is always a
/// fraction in `0.0..=1.0`.
const MAX_SIGNAL_STRENGTH: f64 = 1.0;

/// The signal registry: stable string constants used as
/// `sales_signals.signal_type` values.
///
/// These are associated constants rather than an enum on purpose: the column
/// is TEXT and producers evolve faster than a database CHECK, while the
/// scoring code still needs a single compile-time vocabulary.
pub struct SignalType;

impl SignalType {
    /// Funding round or material financing event.
    pub const FUNDING: &'static str = "funding";
    /// A tracked person changed job (joiner/leaver at the account).
    pub const JOB_CHANGE: &'static str = "job_change";
    /// A new executive joined (C-level / VP).
    pub const NEW_EXECUTIVE: &'static str = "new_executive";
    /// New engineering roles posted.
    pub const NEW_ENGINEERING_JOBS: &'static str = "new_engineering_jobs";
    /// New security/compliance roles posted.
    pub const NEW_SECURITY_JOBS: &'static str = "new_security_jobs";
    /// A technology was added to the public stack.
    pub const TECHNOLOGY_ADOPTED: &'static str = "technology_adopted";
    /// A technology was removed from the public stack.
    pub const TECHNOLOGY_REMOVED: &'static str = "technology_removed";
    /// Website content changed materially.
    pub const WEBSITE_CHANGE: &'static str = "website_change";
    /// Pricing page changed.
    pub const PRICING_CHANGE: &'static str = "pricing_change";
    /// New product / feature launched.
    pub const PRODUCT_LAUNCH: &'static str = "product_launch";
    /// Geographic expansion (new region, entity or language).
    pub const GEOGRAPHIC_EXPANSION: &'static str = "geographic_expansion";
    /// Security/compliance page changed (new certification, trust center).
    pub const SECURITY_COMPLIANCE_CHANGE: &'static str = "security_compliance_page_change";
    /// The email stack changed between two observations (see
    /// [`email_stack::stack_changes`]).
    pub const EMAIL_STACK_CHANGE: &'static str = "email_stack_change";
    /// First-party site intent (visits to high-intent pages on our own site).
    pub const FIRST_PARTY_SITE_INTENT: &'static str = "first_party_site_intent";
    /// First-party product intent (trial/project activity in our product).
    pub const FIRST_PARTY_PRODUCT_INTENT: &'static str = "first_party_product_intent";
    /// Trial or signup event.
    pub const TRIAL_SIGNUP: &'static str = "trial_signup";
    /// A visit to ApexMail's migration/replatforming page — the strongest
    /// first-party intent signal we can lawfully observe.
    pub const APEXMAIL_MIGRATION_PAGE_VISIT: &'static str = "apexmail_migration_page_visit";

    /// All registry constants, for tests and operator documentation.
    pub fn all() -> &'static [&'static str] {
        &[
            Self::FUNDING,
            Self::JOB_CHANGE,
            Self::NEW_EXECUTIVE,
            Self::NEW_ENGINEERING_JOBS,
            Self::NEW_SECURITY_JOBS,
            Self::TECHNOLOGY_ADOPTED,
            Self::TECHNOLOGY_REMOVED,
            Self::WEBSITE_CHANGE,
            Self::PRICING_CHANGE,
            Self::PRODUCT_LAUNCH,
            Self::GEOGRAPHIC_EXPANSION,
            Self::SECURITY_COMPLIANCE_CHANGE,
            Self::EMAIL_STACK_CHANGE,
            Self::FIRST_PARTY_SITE_INTENT,
            Self::FIRST_PARTY_PRODUCT_INTENT,
            Self::TRIAL_SIGNUP,
            Self::APEXMAIL_MIGRATION_PAGE_VISIT,
        ]
    }
}

/// Registry entry: how fast a signal type goes stale and how strong a fresh
/// instance of it typically is.
#[derive(Debug, Clone, Copy)]
pub struct SignalTypeSpec {
    pub signal_type: &'static str,
    /// Half-life in days: urgency falls to 0.5 after this many days, 0.25
    /// after two half-lives, and so on.
    pub half_life_days: f32,
    /// Default strength in `0.0..=1.0` before decay, for producers that do
    /// not have a better calibrated value.
    pub default_strength: f32,
    pub description: &'static str,
}

/// The registry table. Half-lives are deliberately short for intent-like
/// events (a migration-page visit is stale within days) and longer for
/// structural changes (an adopted technology stays relevant for months).
pub const SIGNAL_TYPES: &[SignalTypeSpec] = &[
    SignalTypeSpec {
        signal_type: SignalType::FUNDING,
        half_life_days: 90.0,
        default_strength: 0.7,
        description: "funding round or material financing event",
    },
    SignalTypeSpec {
        signal_type: SignalType::JOB_CHANGE,
        half_life_days: 45.0,
        default_strength: 0.5,
        description: "tracked person changed job",
    },
    SignalTypeSpec {
        signal_type: SignalType::NEW_EXECUTIVE,
        half_life_days: 60.0,
        default_strength: 0.6,
        description: "new C-level / VP executive",
    },
    SignalTypeSpec {
        signal_type: SignalType::NEW_ENGINEERING_JOBS,
        half_life_days: 30.0,
        default_strength: 0.5,
        description: "new engineering roles posted",
    },
    SignalTypeSpec {
        signal_type: SignalType::NEW_SECURITY_JOBS,
        half_life_days: 30.0,
        default_strength: 0.5,
        description: "new security/compliance roles posted",
    },
    SignalTypeSpec {
        signal_type: SignalType::TECHNOLOGY_ADOPTED,
        half_life_days: 180.0,
        default_strength: 0.5,
        description: "technology added to the public stack",
    },
    SignalTypeSpec {
        signal_type: SignalType::TECHNOLOGY_REMOVED,
        half_life_days: 120.0,
        default_strength: 0.5,
        description: "technology removed from the public stack",
    },
    SignalTypeSpec {
        signal_type: SignalType::WEBSITE_CHANGE,
        half_life_days: 21.0,
        default_strength: 0.4,
        description: "material website content change",
    },
    SignalTypeSpec {
        signal_type: SignalType::PRICING_CHANGE,
        half_life_days: 45.0,
        default_strength: 0.6,
        description: "pricing page changed",
    },
    SignalTypeSpec {
        signal_type: SignalType::PRODUCT_LAUNCH,
        half_life_days: 30.0,
        default_strength: 0.5,
        description: "new product / feature launch",
    },
    SignalTypeSpec {
        signal_type: SignalType::GEOGRAPHIC_EXPANSION,
        half_life_days: 60.0,
        default_strength: 0.5,
        description: "geographic expansion",
    },
    SignalTypeSpec {
        signal_type: SignalType::SECURITY_COMPLIANCE_CHANGE,
        half_life_days: 120.0,
        default_strength: 0.6,
        description: "security/compliance page changed",
    },
    SignalTypeSpec {
        signal_type: SignalType::EMAIL_STACK_CHANGE,
        half_life_days: 90.0,
        default_strength: 0.6,
        description: "email stack changed between observations",
    },
    SignalTypeSpec {
        signal_type: SignalType::FIRST_PARTY_SITE_INTENT,
        half_life_days: 14.0,
        default_strength: 0.7,
        description: "first-party site intent",
    },
    SignalTypeSpec {
        signal_type: SignalType::FIRST_PARTY_PRODUCT_INTENT,
        half_life_days: 14.0,
        default_strength: 0.8,
        description: "first-party product intent",
    },
    SignalTypeSpec {
        signal_type: SignalType::TRIAL_SIGNUP,
        half_life_days: 7.0,
        default_strength: 0.9,
        description: "trial or signup event",
    },
    SignalTypeSpec {
        signal_type: SignalType::APEXMAIL_MIGRATION_PAGE_VISIT,
        half_life_days: 7.0,
        default_strength: 0.9,
        description: "visit to ApexMail's migration/replatforming page",
    },
];

/// Look up a registry entry. Unknown types return `None`; callers fall back
/// to [`DEFAULT_SIGNAL_HALF_LIFE_DAYS`].
pub fn signal_spec(signal_type: &str) -> Option<&'static SignalTypeSpec> {
    let needle = signal_type.trim();
    SIGNAL_TYPES.iter().find(|spec| spec.signal_type == needle)
}

/// Half-life in days for a signal type (registry value or the default).
pub fn half_life_days(signal_type: &str) -> f32 {
    signal_spec(signal_type)
        .map(|spec| spec.half_life_days)
        .unwrap_or(DEFAULT_SIGNAL_HALF_LIFE_DAYS)
}

/// Persisted signal row (`sales_signals`,
/// migration 200_sales_autopilot_v2_unification.sql:377-389).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Signal {
    pub id: Uuid,
    pub tenant_id: String,
    pub account_id: Uuid,
    pub signal_type: String,
    pub strength: f64,
    pub observed_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub evidence_id: Option<Uuid>,
    pub payload: serde_json::Value,
}

impl Signal {
    /// A signal is active when it has not expired as of `now`. The DB CHECK
    /// guarantees `strength` is in `0.0..=1.0`; readers still clamp.
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        match self.expires_at {
            Some(expires_at) => expires_at > now,
            None => true,
        }
    }

    /// Decayed urgency in `0.0..=1.0` at `now`.
    pub fn urgency(&self, now: DateTime<Utc>) -> f32 {
        signal_urgency(&self.signal_type, self.observed_at, now)
            * self.strength.clamp(0.0, 1.0) as f32
    }
}

/// A caller-supplied signal observation, for pure timing/urgency maths in
/// scoring without a database round-trip.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignalObservation {
    pub signal_type: String,
    /// Strength in `0.0..=1.0` (values outside are clamped by consumers).
    pub strength: f32,
    pub observed_at: DateTime<Utc>,
}

/// Pure exponential decay: urgency is `0.5^(age_days / half_life_days)`.
///
/// * a signal observed now (or in the future, which cannot happen through the
///   normal path but must not misbehave) has urgency `1.0`;
/// * after one half-life it is `0.5`, after two `0.25`, and it underflows to
///   `0.0` for very old signals;
/// * the result is always finite and in `0.0..=1.0`; a degenerate
///   (non-positive) half-life returns `0.0` for any past signal.
pub fn signal_urgency(signal_type: &str, observed_at: DateTime<Utc>, now: DateTime<Utc>) -> f32 {
    let age = now.signed_duration_since(observed_at);
    let age_days = age.num_seconds() as f64 / 86_400.0;
    if !age_days.is_finite() || age_days <= 0.0 {
        return 1.0;
    }
    let half_life = f64::from(half_life_days(signal_type));
    if !half_life.is_finite() || half_life <= 0.0 {
        return 0.0;
    }
    let urgency = 0.5f64.powf(age_days / half_life);
    if urgency.is_finite() {
        urgency.clamp(0.0, 1.0) as f32
    } else {
        0.0
    }
}

/// Noisy-OR combination of several observations: `1 - Π(1 - urgency_i)`.
///
/// Monotone in every observation, bounded `0.0..=1.0`, and never panics on
/// an empty slice (returns `0.0`) or on hostile strengths / future
/// timestamps (each observation is sanitised by [`signal_urgency`]).
pub fn combined_urgency(observations: &[SignalObservation], now: DateTime<Utc>) -> f32 {
    let mut survival = 1.0f64;
    for observation in observations {
        let strength = if observation.strength.is_finite() {
            f64::from(observation.strength.clamp(0.0, 1.0))
        } else {
            0.0
        };
        let urgency = f64::from(signal_urgency(
            &observation.signal_type,
            observation.observed_at,
            now,
        )) * strength;
        survival *= 1.0 - urgency.clamp(0.0, 1.0);
    }
    let combined = 1.0 - survival;
    if combined.is_finite() {
        combined.clamp(0.0, 1.0) as f32
    } else {
        0.0
    }
}

/// Record one signal in `sales_signals` and return its id.
///
/// `strength` must be finite and in `0.0..=1.0` (the column CHECK is the
/// backstop); the signal type may be any non-empty string, including types
/// newer than this build. `payload` defaults to `{}` when `null`.
#[allow(clippy::too_many_arguments)]
pub async fn record_signal(
    db: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
    signal_type: &str,
    strength: f64,
    evidence_id: Option<Uuid>,
    payload: serde_json::Value,
    expires_at: Option<DateTime<Utc>>,
) -> Result<Uuid, SalesError> {
    if tenant_id.trim().is_empty() {
        return Err(SalesError::InvalidInput("tenant_id is required".into()));
    }
    if signal_type.trim().is_empty() {
        return Err(SalesError::InvalidInput(
            "signal_type must not be empty".into(),
        ));
    }
    if !strength.is_finite() || !(0.0..=MAX_SIGNAL_STRENGTH).contains(&strength) {
        return Err(SalesError::InvalidInput(format!(
            "signal strength must be in 0.0..=1.0, got {strength}"
        )));
    }
    let payload = if payload.is_null() {
        serde_json::json!({})
    } else {
        payload
    };

    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_signals (
            id, tenant_id, account_id, signal_type, strength, observed_at,
            expires_at, evidence_id, payload, created_at
         ) VALUES ($1, $2, $3, $4, $5, NOW(), $6, $7, $8, NOW())",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(account_id)
    .bind(signal_type.trim())
    .bind(strength)
    .bind(expires_at)
    .bind(evidence_id)
    .bind(payload)
    .execute(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(id)
}

/// Every non-expired signal for one account, newest first.
///
/// A `NULL` `expires_at` means "no known expiry" and stays active; an expiry
/// at or before `now` is inactive. Ordering is deterministic
/// (`observed_at DESC, id`).
pub async fn active_signals(
    db: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
    now: DateTime<Utc>,
) -> Result<Vec<Signal>, SalesError> {
    use sqlx::Row;

    let rows = sqlx::query(
        "SELECT id, tenant_id, account_id, signal_type, strength, observed_at,
                expires_at, evidence_id, payload
         FROM sales_signals
         WHERE tenant_id = $1 AND account_id = $2
           AND (expires_at IS NULL OR expires_at > $3)
         ORDER BY observed_at DESC, id",
    )
    .bind(tenant_id)
    .bind(account_id)
    .bind(now)
    .fetch_all(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    rows.into_iter()
        .map(|row| {
            Ok(Signal {
                id: row
                    .try_get("id")
                    .map_err(|e| SalesError::Database(e.to_string()))?,
                tenant_id: row
                    .try_get("tenant_id")
                    .map_err(|e| SalesError::Database(e.to_string()))?,
                account_id: row
                    .try_get("account_id")
                    .map_err(|e| SalesError::Database(e.to_string()))?,
                signal_type: row
                    .try_get("signal_type")
                    .map_err(|e| SalesError::Database(e.to_string()))?,
                strength: row
                    .try_get("strength")
                    .map_err(|e| SalesError::Database(e.to_string()))?,
                observed_at: row
                    .try_get("observed_at")
                    .map_err(|e| SalesError::Database(e.to_string()))?,
                expires_at: row
                    .try_get("expires_at")
                    .map_err(|e| SalesError::Database(e.to_string()))?,
                evidence_id: row
                    .try_get("evidence_id")
                    .map_err(|e| SalesError::Database(e.to_string()))?,
                payload: row
                    .try_get("payload")
                    .map_err(|e| SalesError::Database(e.to_string()))?,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 11, 12, 0, 0).unwrap()
    }

    #[test]
    fn registry_is_complete_and_sane() {
        assert!(!SignalType::all().is_empty());
        let mut seen = std::collections::BTreeSet::new();
        for signal_type in SignalType::all() {
            assert!(
                seen.insert(*signal_type),
                "duplicate signal type {signal_type}"
            );
            let spec = signal_spec(signal_type).expect("every constant has a registry row");
            assert!(spec.half_life_days > 0.0);
            assert!((0.0..=1.0).contains(&spec.default_strength));
            assert!(!spec.description.is_empty());
            assert_eq!(half_life_days(signal_type), spec.half_life_days);
        }
        assert_eq!(SIGNAL_TYPES.len(), seen.len());
        // The registry covers every signal class the audit names.
        for required in [
            SignalType::FUNDING,
            SignalType::JOB_CHANGE,
            SignalType::NEW_EXECUTIVE,
            SignalType::NEW_ENGINEERING_JOBS,
            SignalType::NEW_SECURITY_JOBS,
            SignalType::TECHNOLOGY_ADOPTED,
            SignalType::TECHNOLOGY_REMOVED,
            SignalType::WEBSITE_CHANGE,
            SignalType::PRICING_CHANGE,
            SignalType::PRODUCT_LAUNCH,
            SignalType::GEOGRAPHIC_EXPANSION,
            SignalType::SECURITY_COMPLIANCE_CHANGE,
            SignalType::EMAIL_STACK_CHANGE,
            SignalType::FIRST_PARTY_SITE_INTENT,
            SignalType::FIRST_PARTY_PRODUCT_INTENT,
            SignalType::TRIAL_SIGNUP,
            SignalType::APEXMAIL_MIGRATION_PAGE_VISIT,
        ] {
            assert!(signal_spec(required).is_some(), "missing {required}");
        }
    }

    #[test]
    fn unknown_signal_type_uses_default_half_life() {
        assert_eq!(
            half_life_days("some_future_type"),
            DEFAULT_SIGNAL_HALF_LIFE_DAYS
        );
        assert!(signal_spec("some_future_type").is_none());
    }

    #[test]
    fn urgency_decays_monotonically_with_half_life() {
        let t0 = now();
        assert_eq!(signal_urgency(SignalType::FUNDING, t0, t0), 1.0);
        // A future observation cannot have negative age.
        assert_eq!(
            signal_urgency(SignalType::FUNDING, t0, t0 - Duration::days(1)),
            1.0
        );

        let half_life = f64::from(half_life_days(SignalType::FUNDING));
        let one = signal_urgency(
            SignalType::FUNDING,
            t0 - Duration::seconds((half_life * 86_400.0) as i64),
            t0,
        );
        let two = signal_urgency(
            SignalType::FUNDING,
            t0 - Duration::seconds((2.0 * half_life * 86_400.0) as i64),
            t0,
        );
        assert!((one - 0.5).abs() < 0.01, "one half-life ≈ 0.5, got {one}");
        assert!(
            (two - 0.25).abs() < 0.01,
            "two half-lives ≈ 0.25, got {two}"
        );

        // Monotone non-increasing as the observation gets older.
        let mut previous = 1.0f32;
        for day in 0..400 {
            let urgency = signal_urgency(
                SignalType::FIRST_PARTY_SITE_INTENT,
                t0 - Duration::days(day),
                t0,
            );
            assert!(urgency.is_finite());
            assert!((0.0..=1.0).contains(&urgency));
            assert!(urgency <= previous + 1e-6, "urgency rose at day {day}");
            previous = urgency;
        }
        assert!(previous < 0.001, "400 days must be effectively stale");
    }

    #[test]
    fn combined_urgency_is_bounded_and_monotone() {
        let t0 = now();
        assert_eq!(combined_urgency(&[], t0), 0.0);

        let one = SignalObservation {
            signal_type: SignalType::TRIAL_SIGNUP.to_string(),
            strength: 0.8,
            observed_at: t0 - Duration::days(1),
        };
        let single = combined_urgency(std::slice::from_ref(&one), t0);
        assert!(single > 0.0 && single <= 1.0);

        let two = combined_urgency(&[one.clone(), one.clone()], t0);
        assert!(two > single, "a second observation must not lower urgency");
        assert!(two <= 1.0);

        // Hostile strengths: NaN/inf/out-of-range must never produce NaN.
        for strength in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -5.0, 42.0] {
            let hostility = SignalObservation {
                signal_type: SignalType::FUNDING.to_string(),
                strength,
                observed_at: t0,
            };
            let combined = combined_urgency(&[hostility], t0);
            assert!(combined.is_finite());
            assert!((0.0..=1.0).contains(&combined));
        }

        // 10 000 signals: bounded, finite, no panic.
        let many: Vec<SignalObservation> = (0..10_000)
            .map(|i| SignalObservation {
                signal_type: if i % 2 == 0 {
                    SignalType::FUNDING.to_string()
                } else {
                    "unknown_type".to_string()
                },
                strength: 1.0,
                observed_at: t0,
            })
            .collect();
        let combined = combined_urgency(&many, t0);
        assert!(combined.is_finite());
        assert!((0.0..=1.0).contains(&combined));
        assert!((combined - 1.0).abs() < 1e-6);
    }

    #[test]
    fn signal_activity_respects_expiry_and_strength() {
        let t0 = now();
        let mut signal = Signal {
            id: Uuid::new_v4(),
            tenant_id: "t".into(),
            account_id: Uuid::new_v4(),
            signal_type: SignalType::FUNDING.to_string(),
            strength: 0.5,
            observed_at: t0,
            expires_at: None,
            evidence_id: None,
            payload: serde_json::json!({}),
        };
        assert!(signal.is_active(t0));
        assert!((signal.urgency(t0) - 0.5).abs() < 1e-6);

        signal.expires_at = Some(t0 - Duration::hours(1));
        assert!(!signal.is_active(t0));

        signal.expires_at = Some(t0 + Duration::hours(1));
        assert!(signal.is_active(t0));
        assert!(!signal.is_active(t0 + Duration::hours(2)));
    }

    #[test]
    fn record_signal_input_validation_is_pure() {
        // Validation happens before any database access, so these calls do not
        // need a reachable database (they fail on the argument check).
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let db = sqlx::PgPool::connect_lazy("postgresql://unused").expect("lazy pool");
            let account = Uuid::new_v4();
            let error = record_signal(
                &db,
                "",
                account,
                SignalType::FUNDING,
                0.5,
                None,
                serde_json::json!({}),
                None,
            )
            .await
            .expect_err("empty tenant");
            assert!(matches!(error, SalesError::InvalidInput(_)));

            let error = record_signal(
                &db,
                "tenant",
                account,
                "  ",
                0.5,
                None,
                serde_json::json!({}),
                None,
            )
            .await
            .expect_err("empty signal type");
            assert!(matches!(error, SalesError::InvalidInput(_)));

            for strength in [f64::NAN, f64::INFINITY, -0.1, 1.5] {
                let error = record_signal(
                    &db,
                    "tenant",
                    account,
                    SignalType::FUNDING,
                    strength,
                    None,
                    serde_json::json!({}),
                    None,
                )
                .await
                .expect_err("hostile strength");
                assert!(matches!(error, SalesError::InvalidInput(_)));
            }
        });
    }
}
