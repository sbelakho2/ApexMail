//! Adaptive sender health and circuit breakers.
//!
//! `sales_sender_health` holds one rolling window per sender identity. This
//! module turns that window into a health score and a breaker state, and
//! exposes the pre-send gate the dispatcher must consult before queueing any
//! sales message.
//!
//! ## Health score formula
//!
//! ```text
//! health = maturity * ( 1.0
//!     - 0.60 * clamp01(complaint_rate  / 0.003)   // heaviest negative
//!     - 0.30 * clamp01(hard_bounce_rate / 0.05)
//!     - 0.15 * clamp01(deferral_rate    / 0.10)
//!     - 0.10 * clamp01(soft_bounce_rate / 0.10)
//!     - 0.05 * clamp01(unsubscribe_rate / 0.02)
//!     - 0.25 * clamp01(auth_failures    / 3.0) )
//!
//! maturity = 1.0 - 0.15 * (1 - clamp01(warmup_day / 30))   // 0.85 at day 0
//! ```
//!
//! `clamp01(x) = x.clamp(0.0, 1.0)`. Complaint rate is the heaviest negative
//! because a single complaint is worth orders of magnitude more reputation
//! damage than a deferral. The rate terms are evaluated only once
//! `volume >= thresholds.min_volume_for_rates`; below that the sender keeps a
//! clean score and a `warming`/`healthy` state, so one complaint out of two
//! sends never trips a breaker.
//!
//! ## Breaker mapping (severity order)
//!
//! * complaint rate over threshold → `quarantined`
//! * hard-bounce rate over threshold or any auth failure → `paused`
//! * deferral rate over threshold → `throttled`
//! * warmup day below maturity (and no breaker) → `warming`
//! * otherwise → `healthy`
//!
//! `state` is persisted to `sales_sender_health.state`; the matching `status`
//! on `sales_sender_identities` is updated only for rows already in an active
//! lifecycle (`active`/`throttled`/`paused`/`quarantined`), never for
//! `provisioning`/`retired`.
//!
//! ## Reply-classification breaker
//!
//! [`reply_classification_healthy`] is the "AI classifier outage must stop
//! subsequent touches" breaker. There is no separate classifier-health table,
//! so it is derived from the canonical reply stream: if the newest of the most
//! recent N classifications is older than the max age **while sends continued
//! after it**, the classification path is presumed broken and returns `false`.
//! With no inbound traffic at all — or a quiet period with no sends — it
//! returns `true`. When it returns `false`, the caller must fall back to
//! verified static content; it must never let a model hallucinate a reply
//! interpretation while the classifier is down.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::types::SalesError;

/// Sender-health thresholds, named so the control plane can display exactly
/// why a breaker tripped.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct HealthThresholds {
    /// A sender below this score must not send, even with no active breaker.
    pub min_health_to_send: f64,
    /// Complaint rate at or above which the sender is quarantined.
    pub complaint_rate_quarantine: f64,
    /// Hard-bounce rate at or above which the sender is paused.
    pub bounce_rate_pause: f64,
    /// Deferral rate at or above which the sender is throttled.
    pub deferral_rate_throttle: f64,
    /// Never trip a rate breaker on a tiny sample: one bounce out of two sends
    /// is noise, not a reputation signal.
    pub min_volume_for_rates: i64,
}

impl Default for HealthThresholds {
    fn default() -> Self {
        Self {
            min_health_to_send: 0.35,
            complaint_rate_quarantine: 0.003,
            bounce_rate_pause: 0.05,
            deferral_rate_throttle: 0.10,
            min_volume_for_rates: 50,
        }
    }
}

/// Days of warmup after which a sending domain/identity is considered mature.
pub const WARMUP_MATURITY_DAYS: i32 = 30;

/// How much of the score an entirely immature sender loses: `maturity` ranges
/// from 0.85 (warmup day 0) to 1.0 (day 30+).
const WARMUP_IMMATURITY_PENALTY: f64 = 0.15;

/// Scale constants for the formula documented in the module docs.
const COMPLAINT_WEIGHT: f64 = 0.60;
const HARD_BOUNCE_WEIGHT: f64 = 0.30;
const DEFERRAL_WEIGHT: f64 = 0.15;
const SOFT_BOUNCE_WEIGHT: f64 = 0.10;
const UNSUBSCRIBE_WEIGHT: f64 = 0.05;
const AUTH_FAILURE_WEIGHT: f64 = 0.25;
const COMPLAINT_RATE_SCALE: f64 = 0.003;
const HARD_BOUNCE_RATE_SCALE: f64 = 0.05;
const DEFERRAL_RATE_SCALE: f64 = 0.10;
const SOFT_BOUNCE_RATE_SCALE: f64 = 0.10;
const UNSUBSCRIBE_RATE_SCALE: f64 = 0.02;
const AUTH_FAILURE_SCALE: f64 = 3.0;

/// Volume allowed as a fraction of the normal rate for each breaker state.
/// `warming` and `healthy` send at full rate; `throttled` sends at a quarter;
/// `paused`/`quarantined` are already denied by [`gate`], and `0.0` is a
/// second line of defence if a caller skips the gate.
pub const THROTTLE_FRACTION: f64 = 0.25;

/// Default rolling window length (`sales_sender_health.window_secs` default).
pub const DEFAULT_WINDOW_SECS: i32 = 86400;

/// How many recent classification rows define the observed reply stream.
pub const REPLY_CLASSIFICATION_SAMPLE: i64 = 20;

/// If the newest classification is older than this while sends continued, the
/// classification path is presumed broken.
pub const MAX_REPLY_CLASSIFICATION_AGE_HOURS: i64 = 48;

/// Result of one health assessment; `rates` is the CP-facing breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthAssessment {
    pub sender_identity_id: Uuid,
    pub health_score: f64,
    /// warming | healthy | throttled | paused | quarantined
    pub state: String,
    pub reasons: Vec<String>,
    /// volume/hardBounceRate/softBounceRate/complaintRate/deferralRate/
    /// unsubscribeRate/authFailures.
    pub rates: serde_json::Value,
}

/// One operational event recorded into a sender's current window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SenderHealthEvent {
    Delivered,
    HardBounce,
    SoftBounce,
    Complaint,
    Unsubscribe,
    Deferral,
    AuthFailure,
}

impl SenderHealthEvent {
    /// `(volume, hard_bounces, soft_bounces, complaints, unsubscribes,
    /// deferrals, auth_failures)` increments for this event.
    ///
    /// A hard/soft bounce and a deferral are all outcomes of a send attempt,
    /// so they count toward `volume` (which makes the corresponding rate
    /// bounded by 1.0). Complaints, unsubscribes and auth failures are events
    /// *about* sends, not sends, and do not add volume.
    fn increments(self) -> (i64, i64, i64, i64, i64, i64, i64) {
        match self {
            Self::Delivered => (1, 0, 0, 0, 0, 0, 0),
            Self::HardBounce => (1, 1, 0, 0, 0, 0, 0),
            Self::SoftBounce => (1, 0, 1, 0, 0, 0, 0),
            Self::Complaint => (0, 0, 0, 1, 0, 0, 0),
            Self::Unsubscribe => (0, 0, 0, 0, 1, 0, 0),
            Self::Deferral => (1, 0, 0, 0, 0, 1, 0),
            Self::AuthFailure => (0, 0, 0, 0, 0, 0, 1),
        }
    }
}

fn clamp01(value: f64) -> f64 {
    value.clamp(0.0, 1.0)
}

fn rate(count: i64, volume: i64) -> f64 {
    if volume > 0 {
        count as f64 / volume as f64
    } else {
        0.0
    }
}

fn warmup_maturity(warmup_day: Option<i32>) -> f64 {
    match warmup_day {
        Some(day) => {
            let progress = clamp01(day as f64 / WARMUP_MATURITY_DAYS as f64);
            1.0 - WARMUP_IMMATURITY_PENALTY * (1.0 - progress)
        }
        // No warmup tracking means the sender is past warmup.
        None => 1.0,
    }
}

/// The health score and breaker state of one sender, as pure functions of its
/// current window. See the module docs for the exact formula and mapping.
///
/// Returns `(health_score, state, reasons)`. Rate terms are ignored below
/// `HealthThresholds::default().min_volume_for_rates`.
pub fn compute_health(
    volume: i64,
    hard_bounces: i64,
    soft_bounces: i64,
    complaints: i64,
    unsubscribes: i64,
    deferrals: i64,
    auth_failures: i64,
    warmup_day: Option<i32>,
) -> (f64, String, Vec<String>) {
    let thresholds = HealthThresholds::default();
    let rates_meaningful = volume >= thresholds.min_volume_for_rates.max(0);

    let complaint_rate = rate(complaints, volume);
    let hard_bounce_rate = rate(hard_bounces, volume);
    let soft_bounce_rate = rate(soft_bounces, volume);
    let deferral_rate = rate(deferrals, volume);
    let unsubscribe_rate = rate(unsubscribes, volume);

    let mut reasons: Vec<String> = Vec::new();
    let mut penalty = 0.0;

    if rates_meaningful {
        let complaint_component = COMPLAINT_WEIGHT * clamp01(complaint_rate / COMPLAINT_RATE_SCALE);
        let bounce_component =
            HARD_BOUNCE_WEIGHT * clamp01(hard_bounce_rate / HARD_BOUNCE_RATE_SCALE);
        let deferral_component = DEFERRAL_WEIGHT * clamp01(deferral_rate / DEFERRAL_RATE_SCALE);
        let soft_component =
            SOFT_BOUNCE_WEIGHT * clamp01(soft_bounce_rate / SOFT_BOUNCE_RATE_SCALE);
        let unsubscribe_component =
            UNSUBSCRIBE_WEIGHT * clamp01(unsubscribe_rate / UNSUBSCRIBE_RATE_SCALE);
        penalty += complaint_component
            + bounce_component
            + deferral_component
            + soft_component
            + unsubscribe_component;

        if complaint_rate > thresholds.complaint_rate_quarantine {
            reasons.push(format!(
                "complaint rate {:.3}% over quarantine threshold {:.3}%",
                complaint_rate * 100.0,
                thresholds.complaint_rate_quarantine * 100.0
            ));
        }
        if hard_bounce_rate > thresholds.bounce_rate_pause {
            reasons.push(format!(
                "hard-bounce rate {:.2}% over pause threshold {:.2}%",
                hard_bounce_rate * 100.0,
                thresholds.bounce_rate_pause * 100.0
            ));
        }
        if deferral_rate > thresholds.deferral_rate_throttle {
            reasons.push(format!(
                "deferral rate {:.2}% over throttle threshold {:.2}%",
                deferral_rate * 100.0,
                thresholds.deferral_rate_throttle * 100.0
            ));
        }
    } else {
        reasons.push(format!(
            "volume {volume} below {} — rate breakers not evaluated (tiny-volume safeguard)",
            thresholds.min_volume_for_rates
        ));
    }

    // Auth failures are not a rate: one broken signature/DNS record stops the
    // sender regardless of sample size.
    penalty += AUTH_FAILURE_WEIGHT * clamp01(auth_failures as f64 / AUTH_FAILURE_SCALE);
    if auth_failures > 0 {
        reasons.push(format!(
            "auth failures: {auth_failures} — sending identity authentication is failing"
        ));
    }

    let maturity = warmup_maturity(warmup_day);
    if let Some(day) = warmup_day {
        if day < WARMUP_MATURITY_DAYS {
            reasons.push(format!("warming up: day {day} of {WARMUP_MATURITY_DAYS}"));
        }
    }

    let score = clamp01(maturity * (1.0 - clamp01(penalty)));

    let (state, breaker_reasons) = breaker_state(
        volume,
        hard_bounces,
        complaints,
        deferrals,
        auth_failures,
        warmup_day,
        &thresholds,
    );
    reasons.extend(breaker_reasons);

    (score, state, reasons)
}

/// The pure breaker mapping. Severity order: quarantine (complaints) beats
/// pause (hard bounces / auth failures) beats throttle (deferrals) beats
/// warming/healthy. Rate breakers are skipped entirely below
/// `thresholds.min_volume_for_rates`; auth failures never are.
pub fn breaker_state(
    volume: i64,
    hard_bounces: i64,
    complaints: i64,
    deferrals: i64,
    auth_failures: i64,
    warmup_day: Option<i32>,
    thresholds: &HealthThresholds,
) -> (String, Vec<String>) {
    let mut reasons = Vec::new();
    let rates_meaningful = volume >= thresholds.min_volume_for_rates.max(0);

    let complaint_rate = rate(complaints, volume);
    let hard_bounce_rate = rate(hard_bounces, volume);
    let deferral_rate = rate(deferrals, volume);

    if rates_meaningful && complaint_rate > thresholds.complaint_rate_quarantine {
        reasons.push(format!(
            "quarantined: complaint rate {:.3}% exceeds {:.3}%",
            complaint_rate * 100.0,
            thresholds.complaint_rate_quarantine * 100.0
        ));
        return ("quarantined".to_string(), reasons);
    }

    if auth_failures > 0 {
        reasons.push(
            "paused: authentication failures detected — SPF/DKIM/DMARC path is broken".to_string(),
        );
        return ("paused".to_string(), reasons);
    }

    if rates_meaningful && hard_bounce_rate > thresholds.bounce_rate_pause {
        reasons.push(format!(
            "paused: hard-bounce rate {:.2}% exceeds {:.2}%",
            hard_bounce_rate * 100.0,
            thresholds.bounce_rate_pause * 100.0
        ));
        return ("paused".to_string(), reasons);
    }

    if rates_meaningful && deferral_rate > thresholds.deferral_rate_throttle {
        reasons.push(format!(
            "throttled: deferral rate {:.2}% exceeds {:.2}%",
            deferral_rate * 100.0,
            thresholds.deferral_rate_throttle * 100.0
        ));
        return ("throttled".to_string(), reasons);
    }

    if warmup_day.is_some_and(|day| day < WARMUP_MATURITY_DAYS) {
        return ("warming".to_string(), reasons);
    }

    ("healthy".to_string(), reasons)
}

/// Volume the caller may send as a fraction of its normal rate for `state`.
///
/// `healthy`/`warming` send at full rate; `throttled` at
/// [`THROTTLE_FRACTION`]; every other state is `0.0` (already denied by
/// [`gate`], kept as a defence in depth).
pub fn throttle_factor(state: &str) -> f64 {
    match state {
        "healthy" | "warming" => 1.0,
        "throttled" => THROTTLE_FRACTION,
        _ => 0.0,
    }
}

/// The `sales_sender_identities.status` value matching a health state.
fn identity_status_for(state: &str) -> &'static str {
    match state {
        "quarantined" => "quarantined",
        "paused" => "paused",
        "throttled" => "throttled",
        _ => "active",
    }
}

fn rates_json(
    volume: i64,
    hard_bounces: i64,
    soft_bounces: i64,
    complaints: i64,
    unsubscribes: i64,
    deferrals: i64,
    auth_failures: i64,
) -> serde_json::Value {
    serde_json::json!({
        "volume": volume,
        "hardBounceRate": rate(hard_bounces, volume),
        "softBounceRate": rate(soft_bounces, volume),
        "complaintRate": rate(complaints, volume),
        "deferralRate": rate(deferrals, volume),
        "unsubscribeRate": rate(unsubscribes, volume),
        "authFailures": auth_failures,
    })
}

/// Recompute one sender's health from its current window and persist it.
///
/// Persists `health_score` and `state` to `sales_sender_health` (creating the
/// row on first assessment) and mirrors the state onto
/// `sales_sender_identities.status` for identities in an active lifecycle.
///
/// The whole reassessment runs in one transaction so a caller (the outcome
/// projector) can compose it with its own per-event applied marker.
pub async fn assess_and_persist(
    db: &PgPool,
    tenant_id: &str,
    sender_identity_id: Uuid,
    thresholds: &HealthThresholds,
) -> Result<HealthAssessment, SalesError> {
    let mut tx = db
        .begin()
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
    let assessment =
        assess_and_persist_tx(&mut tx, tenant_id, sender_identity_id, thresholds).await?;
    tx.commit()
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
    Ok(assessment)
}

/// [`assess_and_persist`] on a caller-owned transaction. The caller decides
/// the commit boundary — the outcome projector commits it in the same
/// transaction as the per-event applied marker, so the marker and the
/// aggregate move together or not at all.
pub async fn assess_and_persist_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    sender_identity_id: Uuid,
    thresholds: &HealthThresholds,
) -> Result<HealthAssessment, SalesError> {
    let window: Option<(i64, i64, i64, i64, i64, i64, i64, Option<i32>)> = sqlx::query_as(
        "SELECT volume, hard_bounces, soft_bounces, complaints, unsubscribes, \
                deferrals, auth_failures, warmup_day \
         FROM sales_sender_health \
         WHERE tenant_id = $1 AND sender_identity_id = $2",
    )
    .bind(tenant_id)
    .bind(sender_identity_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    let (
        volume,
        hard_bounces,
        soft_bounces,
        complaints,
        unsubscribes,
        deferrals,
        auth_failures,
        warmup_day,
    ) = window.unwrap_or((0, 0, 0, 0, 0, 0, 0, None));

    let (health_score, _default_state, mut reasons) = compute_health(
        volume,
        hard_bounces,
        soft_bounces,
        complaints,
        unsubscribes,
        deferrals,
        auth_failures,
        warmup_day,
    );
    // Re-run the breaker mapping with the caller-supplied thresholds so the
    // persisted state reflects configured policy, not just the defaults.
    let (state, breaker_reasons) = breaker_state(
        volume,
        hard_bounces,
        complaints,
        deferrals,
        auth_failures,
        warmup_day,
        thresholds,
    );
    reasons.extend(breaker_reasons);

    sqlx::query(
        "INSERT INTO sales_sender_health ( \
             id, tenant_id, sender_identity_id, health_score, state, updated_at \
         ) VALUES (gen_random_uuid(), $1, $2, $3, $4, NOW()) \
         ON CONFLICT (sender_identity_id) DO UPDATE \
         SET health_score = EXCLUDED.health_score, \
             state = EXCLUDED.state, \
             updated_at = NOW()",
    )
    .bind(tenant_id)
    .bind(sender_identity_id)
    .bind(health_score)
    .bind(&state)
    .execute(&mut **tx)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    // Mirror the breaker onto the identity for active-lifecycle rows only:
    // `provisioning`/`retired` identities are not touched by health.
    sqlx::query(
        "UPDATE sales_sender_identities \
         SET status = $3, updated_at = NOW() \
         WHERE id = $1 AND tenant_id = $2 \
           AND status IN ('active', 'throttled', 'paused', 'quarantined')",
    )
    .bind(sender_identity_id)
    .bind(tenant_id)
    .bind(identity_status_for(&state))
    .execute(&mut **tx)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    if matches!(state.as_str(), "paused" | "quarantined") {
        tracing::warn!(
            tenant_id,
            sender_identity_id = %sender_identity_id,
            state = %state,
            health_score,
            "sender breaker tripped"
        );
    }

    Ok(HealthAssessment {
        sender_identity_id,
        health_score,
        state,
        reasons,
        rates: rates_json(
            volume,
            hard_bounces,
            soft_bounces,
            complaints,
            unsubscribes,
            deferrals,
            auth_failures,
        ),
    })
}

/// Record an operational event into the current window, then re-assess.
///
/// If the window has expired (`window_start + window_secs <= NOW()`), the
/// counters restart at the event so rates always describe the current window.
///
/// The counter update and the reassessment run in one transaction, so the
/// event is either fully folded in or not at all.
pub async fn record_event(
    db: &PgPool,
    tenant_id: &str,
    sender_identity_id: Uuid,
    event: SenderHealthEvent,
    thresholds: &HealthThresholds,
) -> Result<HealthAssessment, SalesError> {
    let mut tx = db
        .begin()
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
    let assessment =
        record_event_tx(&mut tx, tenant_id, sender_identity_id, event, thresholds).await?;
    tx.commit()
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
    Ok(assessment)
}

/// [`record_event`] on a caller-owned transaction. The outcome projector
/// commits it in the same transaction as the per-event applied marker, so the
/// marker and the aggregate counter move together or not at all — that is
/// what makes "was THIS event applied?" answerable without a sender-wide
/// watermark.
pub async fn record_event_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    sender_identity_id: Uuid,
    event: SenderHealthEvent,
    thresholds: &HealthThresholds,
) -> Result<HealthAssessment, SalesError> {
    let (volume_inc, hard_inc, soft_inc, complaint_inc, unsub_inc, deferral_inc, auth_inc) =
        event.increments();

    sqlx::query(
        "INSERT INTO sales_sender_health (id, tenant_id, sender_identity_id) \
         VALUES (gen_random_uuid(), $1, $2) \
         ON CONFLICT (sender_identity_id) DO NOTHING",
    )
    .bind(tenant_id)
    .bind(sender_identity_id)
    .execute(&mut **tx)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    let expired = "sales_sender_health.window_start \
                   + make_interval(secs => sales_sender_health.window_secs) <= NOW()";

    let sql = format!(
        "UPDATE sales_sender_health SET \
             volume = CASE WHEN {expired} THEN $3 ELSE volume + $3 END, \
             hard_bounces = CASE WHEN {expired} THEN $4 ELSE hard_bounces + $4 END, \
             soft_bounces = CASE WHEN {expired} THEN $5 ELSE soft_bounces + $5 END, \
             complaints = CASE WHEN {expired} THEN $6 ELSE complaints + $6 END, \
             unsubscribes = CASE WHEN {expired} THEN $7 ELSE unsubscribes + $7 END, \
             deferrals = CASE WHEN {expired} THEN $8 ELSE deferrals + $8 END, \
             auth_failures = CASE WHEN {expired} THEN $9 ELSE auth_failures + $9 END, \
             window_start = CASE WHEN {expired} THEN NOW() ELSE window_start END, \
             updated_at = NOW() \
         WHERE tenant_id = $1 AND sender_identity_id = $2"
    );

    sqlx::query(&sql)
        .bind(tenant_id)
        .bind(sender_identity_id)
        .bind(volume_inc)
        .bind(hard_inc)
        .bind(soft_inc)
        .bind(complaint_inc)
        .bind(unsub_inc)
        .bind(deferral_inc)
        .bind(auth_inc)
        .execute(&mut **tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

    assess_and_persist_tx(tx, tenant_id, sender_identity_id, thresholds).await
}

/// The pre-send gate: `Err(PolicyDenied)` when this sender must not send.
///
/// Denies when the persisted state is `quarantined`/`paused`, when the health
/// score is below [`HealthThresholds::min_health_to_send`], or when no health
/// row exists at all — a sender that has never been assessed sends nothing
/// (fail closed). `throttled` is NOT a denial: the caller reduces volume via
/// [`throttle_factor`].
pub async fn gate(
    db: &PgPool,
    tenant_id: &str,
    sender_identity_id: Uuid,
) -> Result<(), SalesError> {
    gate_with_thresholds(
        db,
        tenant_id,
        sender_identity_id,
        &HealthThresholds::default(),
    )
    .await
}

/// [`gate`] with explicit thresholds, for callers that tune them per tenant.
pub async fn gate_with_thresholds(
    db: &PgPool,
    tenant_id: &str,
    sender_identity_id: Uuid,
    thresholds: &HealthThresholds,
) -> Result<(), SalesError> {
    let row: Option<(String, f64)> = sqlx::query_as(
        "SELECT state, health_score FROM sales_sender_health \
         WHERE tenant_id = $1 AND sender_identity_id = $2",
    )
    .bind(tenant_id)
    .bind(sender_identity_id)
    .fetch_optional(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    let Some((state, health_score)) = row else {
        return Err(SalesError::PolicyDenied(format!(
            "sender identity {sender_identity_id} has never been health-assessed; \
             fail closed until it is"
        )));
    };

    if matches!(state.as_str(), "quarantined" | "paused") {
        return Err(SalesError::PolicyDenied(format!(
            "sender identity {sender_identity_id} is {state}; sending is blocked"
        )));
    }

    if health_score < thresholds.min_health_to_send {
        return Err(SalesError::PolicyDenied(format!(
            "sender identity {sender_identity_id} health {health_score:.3} is below \
             the minimum {:.3}",
            thresholds.min_health_to_send
        )));
    }

    Ok(())
}

/// Global circuit breaker for the reply-classification path.
///
/// Returns `false` when the path is known-broken: the newest of the most
/// recent [`REPLY_CLASSIFICATION_SAMPLE`] classification rows is older than
/// [`MAX_REPLY_CLASSIFICATION_AGE_HOURS`] while sends continued after it. With
/// no inbound traffic (no classification rows at all) or a quiet period with
/// no further sends it returns `true` — there is nothing to classify, so a
/// quiet tenant is not blocked.
///
/// While this returns `false`, subsequent touches must stop and any automated
/// reply handling must fall back to verified static content — never let a
/// model invent an interpretation of a reply the classifier never saw.
pub async fn reply_classification_healthy(db: &PgPool) -> Result<bool, SalesError> {
    let sample: (i64, Option<DateTime<Utc>>) = sqlx::query_as(
        "SELECT COUNT(*)::bigint, MAX(created_at) FROM ( \
             SELECT created_at FROM sales_reply_classifications \
             ORDER BY created_at DESC LIMIT $1 \
         ) recent",
    )
    .bind(REPLY_CLASSIFICATION_SAMPLE)
    .fetch_one(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    let (count, newest) = sample;
    if count == 0 {
        // Never any inbound traffic: nothing to classify, not an outage.
        return Ok(true);
    }
    let Some(newest) = newest else {
        return Ok(true);
    };

    let max_age = ChronoDuration::hours(MAX_REPLY_CLASSIFICATION_AGE_HOURS);
    if Utc::now() - newest <= max_age {
        return Ok(true);
    }

    // Stale classification stream: only an outage if the engine kept sending
    // after the last classification (i.e. replies would have been expected).
    let sends_after: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 FROM sales_step_executions \
             WHERE state = 'sent' AND executed_at IS NOT NULL AND executed_at > $1 \
         )",
    )
    .bind(newest)
    .fetch_one(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    Ok(!sends_after)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_thresholds() -> HealthThresholds {
        HealthThresholds::default()
    }

    #[test]
    fn thresholds_have_the_documented_defaults() {
        let t = default_thresholds();
        assert!((t.min_health_to_send - 0.35).abs() < f64::EPSILON);
        assert!((t.complaint_rate_quarantine - 0.003).abs() < f64::EPSILON);
        assert!((t.bounce_rate_pause - 0.05).abs() < f64::EPSILON);
        assert!((t.deferral_rate_throttle - 0.10).abs() < f64::EPSILON);
        assert_eq!(t.min_volume_for_rates, 50);
    }

    #[test]
    fn tiny_volume_never_trips_a_rate_breaker() {
        // 1 complaint out of 2 sends is 50% — 166x the quarantine threshold —
        // yet the tiny-volume safeguard must keep the sender sendable.
        let (score, state, reasons) = compute_health(2, 0, 0, 1, 0, 0, 0, None);
        assert_eq!(state, "healthy");
        assert!(score > 0.9, "score {score} should be clean on tiny volume");
        assert!(reasons.iter().any(|r| r.contains("tiny-volume")));
    }

    #[test]
    fn tiny_volume_with_warmup_stays_warming() {
        let (_, state, _) = compute_health(2, 0, 0, 1, 0, 0, 0, Some(3));
        assert_eq!(state, "warming");
    }

    #[test]
    fn high_complaint_rate_quarantines_once_volume_is_meaningful() {
        let (score, state, reasons) = compute_health(1000, 0, 0, 4, 0, 0, 0, None);
        assert_eq!(state, "quarantined");
        assert!(reasons.iter().any(|r| r.contains("complaint rate")));
        assert!(
            score < 0.5,
            "complaint-heavy sender must score low, got {score}"
        );
    }

    #[test]
    fn complaint_rate_at_threshold_does_not_trip() {
        // 3/1000 == the 0.003 threshold exactly; "over threshold" is strict.
        let (_, state, _) = compute_health(1000, 0, 0, 3, 0, 0, 0, None);
        assert_eq!(state, "healthy");
    }

    #[test]
    fn high_hard_bounce_rate_pauses() {
        let (score, state, reasons) = compute_health(1000, 60, 0, 0, 0, 0, 0, None);
        assert_eq!(state, "paused");
        assert!(reasons.iter().any(|r| r.contains("hard-bounce")));
        assert!(score < 0.75);
    }

    #[test]
    fn high_deferral_rate_throttles() {
        let (_, state, reasons) = compute_health(1000, 0, 0, 0, 0, 150, 0, None);
        assert_eq!(state, "throttled");
        assert!(reasons.iter().any(|r| r.contains("deferral")));
    }

    #[test]
    fn any_auth_failure_pauses_regardless_of_volume() {
        let (_, state, reasons) = compute_health(1, 0, 0, 0, 0, 0, 1, Some(2));
        assert_eq!(state, "paused");
        assert!(reasons.iter().any(|r| r.contains("auth failures")));
    }

    #[test]
    fn clean_sender_is_healthy() {
        let (score, state, _) = compute_health(500, 2, 3, 0, 1, 5, 0, None);
        assert_eq!(state, "healthy");
        assert!(score > 0.9, "clean sender scored only {score}");
    }

    #[test]
    fn a_single_complaint_weighs_heaviest_but_stays_below_quarantine() {
        // One complaint in a meaningful sample is a large score penalty yet
        // still below the strict quarantine threshold.
        let (score, state, _) = compute_health(500, 0, 0, 1, 0, 0, 0, None);
        assert_eq!(state, "healthy");
        assert!(
            score < 0.7,
            "complaint must dominate the score, got {score}"
        );
    }

    #[test]
    fn immature_warmup_day_reports_warming() {
        let (score, state, reasons) = compute_health(500, 0, 0, 0, 0, 0, 0, Some(0));
        assert_eq!(state, "warming");
        assert!(reasons.iter().any(|r| r.contains("warming up")));
        assert!(score < 1.0, "day-0 sender should not score a perfect 1.0");
    }

    #[test]
    fn health_score_is_always_within_unit_interval() {
        for (volume, hb, sb, c, u, d, a) in [
            (0, 0, 0, 0, 0, 0, 0),
            (1000, 1000, 1000, 1000, 1000, 1000, 10),
            (50, 50, 50, 50, 50, 50, 100),
        ] {
            let (score, _, _) = compute_health(volume, hb, sb, c, u, d, a, Some(0));
            assert!((0.0..=1.0).contains(&score), "score {score} out of range");
        }
    }

    #[test]
    fn breaker_state_mapping_is_exhaustive() {
        let t = default_thresholds();
        // complaint beats everything (including an auth failure)
        assert_eq!(
            breaker_state(1000, 100, 10, 10, 1, None, &t).0,
            "quarantined"
        );
        // auth failure beats a deferral throttle
        assert_eq!(breaker_state(1000, 0, 0, 150, 1, None, &t).0, "paused");
        // hard bounce pause
        assert_eq!(breaker_state(1000, 60, 0, 0, 0, None, &t).0, "paused");
        // deferral throttle
        assert_eq!(breaker_state(1000, 0, 0, 150, 0, None, &t).0, "throttled");
        // warmup only when nothing worse tripped
        assert_eq!(breaker_state(10, 0, 0, 0, 0, Some(1), &t).0, "warming");
        // clean
        assert_eq!(breaker_state(1000, 1, 1, 0, 0, Some(90), &t).0, "healthy");
    }

    #[test]
    fn breaker_skips_rates_below_min_volume() {
        let t = default_thresholds();
        // Would quarantine at volume >= 50; at 10 it must not.
        assert_eq!(breaker_state(10, 0, 5, 0, 0, None, &t).0, "healthy");
        // A custom higher floor keeps even a large-looking sample safe.
        let strict = HealthThresholds {
            min_volume_for_rates: 10_000,
            ..t
        };
        assert_eq!(
            breaker_state(9999, 0, 500, 0, 0, None, &strict).0,
            "healthy"
        );
    }

    #[test]
    fn throttle_factor_matrix() {
        assert!((throttle_factor("healthy") - 1.0).abs() < f64::EPSILON);
        assert!((throttle_factor("warming") - 1.0).abs() < f64::EPSILON);
        assert!((throttle_factor("throttled") - 0.25).abs() < f64::EPSILON);
        assert!(throttle_factor("paused").abs() < f64::EPSILON);
        assert!(throttle_factor("quarantined").abs() < f64::EPSILON);
        assert!(throttle_factor("nonsense").abs() < f64::EPSILON);
    }

    #[test]
    fn identity_status_mirrors_the_breaker() {
        assert_eq!(identity_status_for("quarantined"), "quarantined");
        assert_eq!(identity_status_for("paused"), "paused");
        assert_eq!(identity_status_for("throttled"), "throttled");
        assert_eq!(identity_status_for("warming"), "active");
        assert_eq!(identity_status_for("healthy"), "active");
    }

    #[test]
    fn event_increments_are_sane() {
        let (vol, hb, sb, c, u, d, a) = SenderHealthEvent::Delivered.increments();
        assert_eq!((vol, hb, sb, c, u, d, a), (1, 0, 0, 0, 0, 0, 0));
        let (vol, hb, ..) = SenderHealthEvent::HardBounce.increments();
        assert_eq!((vol, hb), (1, 1));
        let (vol, _, sb, ..) = SenderHealthEvent::SoftBounce.increments();
        assert_eq!((vol, sb), (1, 1));
        let (_, _, _, c, ..) = SenderHealthEvent::Complaint.increments();
        assert_eq!(c, 1);
        let (.., a) = SenderHealthEvent::AuthFailure.increments();
        assert_eq!(a, 1);
        let (vol, _, _, _, _, d, _) = SenderHealthEvent::Deferral.increments();
        assert_eq!((vol, d), (1, 1));
    }

    #[test]
    fn rates_json_reports_expected_keys() {
        let rates = rates_json(100, 5, 2, 1, 3, 10, 0);
        assert_eq!(rates["volume"], 100);
        assert!((rates["hardBounceRate"].as_f64().unwrap_or_default() - 0.05).abs() < 1e-12);
        assert!((rates["complaintRate"].as_f64().unwrap_or_default() - 0.01).abs() < 1e-12);
        assert_eq!(rates["authFailures"], 0);
    }
}
