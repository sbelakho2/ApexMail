//! Warmup admission at the SMTP-effect boundary (P0 ownership fix).
//!
//! # Why the relay owns this
//!
//! The relay owns DURABLE retries: a transient SMTP/DNS/network failure
//! persists the send in `outbound_relay_ledger` and the daemon redelivers it
//! later — possibly on another UTC day. When the outer worker held the only
//! warmup reservation, it released the slot when its inline submission
//! returned a transient error, while the relay still owed a real
//! reputation-affecting delivery from that same warming IP. Under enough
//! deferrals the IP's intended daily ceiling could be exceeded even though
//! every individual worker invocation obeyed the cap.
//!
//! The component that can actually transmit DATA must be the component that
//! admits the warming IP for the day. [`WarmupGate`] runs at the very top of
//! [`crate::Relay::deliver`], BEFORE any connection is opened, for every
//! attempt — inline submissions and daemon retries alike. A refused or
//! unavailable admission defers the send (nothing hit the wire), and the
//! next attempt re-evaluates against the then-current day counter.
//!
//! # Accounting
//!
//! * Counter: `apexmail:warmup:ip:{ip}:{utc_day}` — the SAME key family the
//!   quota tooling reads, so per-attempt relay admission and any external
//!   observer agree on one number.
//! * Marker: `apexmail:warmup:relay:{ip}:{utc_day}:{send_unit}` — a
//!   re-attempt of the SAME send unit within the same day is admitted
//!   without a second increment (the earlier attempt already consumed the
//!   day's slot by reaching the wire); the first attempt of a NEW day
//!   naturally uses the new day's counter.
//! * The limit is the canonical [`mail_common::warmup`] schedule for the
//!   IP's warmup day, exactly as the worker computed it.
//! * Redis unavailability fails CLOSED: the send is deferred with a named
//!   reason, never sent unaccounted.
#![deny(unsafe_code)]

use std::net::IpAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};

/// Bounded admission verdict for one delivery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarmupAdmission {
    /// The attempt may proceed; the day's counter was incremented (or a
    /// same-day marker for this send unit already admitted it).
    Admitted,
    /// The warming IP is at its canonical daily cap: defer, retry later.
    AtCap,
}

/// The admission contract. Implementations must be atomic per attempt
/// (counter increment + marker under one script) and fail closed on store
/// errors.
#[async_trait::async_trait]
pub trait WarmupAdmit: Send + Sync {
    async fn admit(
        &self,
        send_unit: &str,
        source_ip: IpAddr,
        db: &sqlx::PgPool,
    ) -> Result<WarmupAdmission, String>;
}

/// Atomic INCR-with-cap + same-day marker. KEYS[1] = counter,
/// KEYS[2] = send-unit marker; ARGV[1] = cap (-1 = unlimited),
/// ARGV[2] = TTL seconds. Returns 1 = admitted (new), 2 = admitted
/// (same-day marker already held), 0 = at cap.
const ADMIT_LUA: &str = r#"
if redis.call('EXISTS', KEYS[2]) == 1 then
    return 2
end
local cap = tonumber(ARGV[1])
if cap >= 0 then
    local current = tonumber(redis.call('GET', KEYS[1]) or '0')
    if current >= cap then
        return 0
    end
end
local new = redis.call('INCR', KEYS[1])
if new == 1 then
    redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
end
redis.call('SET', KEYS[2], '1', 'EX', tonumber(ARGV[2]))
return 1
"#;

/// Counter + marker live slightly beyond the warmup day so a retry racing
/// midnight is still judged by the day it was counted against.
const KEY_TTL_SECS: u64 = 48 * 60 * 60;

fn counter_key(ip: &str, utc_day: &str) -> String {
    format!("apexmail:warmup:ip:{ip}:{utc_day}")
}

fn marker_key(ip: &str, utc_day: &str, send_unit: &str) -> String {
    format!("apexmail:warmup:relay:{ip}:{utc_day}:{send_unit}")
}

/// How the production gate reads one dedicated IP's lifecycle facts.
#[derive(Debug, Clone, PartialEq, Eq)]
struct IpLifecycle {
    status: String,
    warmup_started_at: Option<DateTime<Utc>>,
}

async fn load_lifecycle(
    db: &sqlx::PgPool,
    source_ip: IpAddr,
) -> Result<Option<IpLifecycle>, String> {
    let row: Option<(String, Option<DateTime<Utc>>)> = sqlx::query_as(
        // ip_address is TEXT on the canonical chain (the control plane stores
        // the bare address): compare directly. Cast through inet when the
        // stored value parses so a stored "203.0.113.9/32" can never alias
        // a different requested address.
        "SELECT status, warmup_started_at FROM dedicated_ips \
         WHERE host($1::inet) = CASE WHEN ip_address ~ '/' \
              THEN host(ip_address::inet) ELSE ip_address END LIMIT 1",
    )
    .bind(source_ip.to_string())
    .fetch_optional(db)
    .await
    .map_err(|error| format!("warmup lifecycle lookup failed: {error}"))?;
    Ok(row.map(|(status, warmup_started_at)| IpLifecycle {
        status,
        warmup_started_at,
    }))
}

/// Redis-backed production gate over the canonical lifecycle table and the
/// canonical warmup schedule.
pub struct RedisWarmupGate {
    redis: deadpool_redis::Pool,
}

impl RedisWarmupGate {
    pub fn new(redis: deadpool_redis::Pool) -> Self {
        Self { redis }
    }
}

#[async_trait::async_trait]
impl WarmupAdmit for RedisWarmupGate {
    async fn admit(
        &self,
        send_unit: &str,
        source_ip: IpAddr,
        db: &sqlx::PgPool,
    ) -> Result<WarmupAdmission, String> {
        // The IP's lifecycle facts come from the same table the control
        // plane transitions; a vanished IP defers (its route must be
        // re-selected upstream, never silently re-routed here).
        let Some(lifecycle) = load_lifecycle(db, source_ip).await? else {
            return Err(format!(
                "dedicated IP {source_ip} no longer exists — its route must be re-selected"
            ));
        };
        // Graduated/active IPs carry no quota: admission is free. Only a
        // `warming` IP consumes the canonical daily schedule.
        if lifecycle.status != "warming" {
            return Ok(WarmupAdmission::Admitted);
        }
        let started = lifecycle.warmup_started_at.ok_or_else(|| {
            format!(
                "warming IP {source_ip} has no warmup_started_at — refusing to admit unanchored"
            )
        })?;
        let now = Utc::now();
        let utc_day = now.format("%Y-%m-%d").to_string();
        let day_index = (now - started).num_days().max(0) as u32;
        let limit = mail_common::warmup::limit_for_day(day_index);
        let cap = if limit == u64::MAX {
            -1
        } else {
            limit.min(i64::MAX as u64) as i64
        };

        let mut conn = self
            .redis
            .get()
            .await
            .map_err(|error| format!("warmup admission store unavailable: {error}"))?;
        let ip = source_ip.to_string();
        let verdict: i64 = redis::Script::new(ADMIT_LUA)
            .key(counter_key(&ip, &utc_day))
            .key(marker_key(&ip, &utc_day, send_unit))
            .arg(cap)
            .arg(KEY_TTL_SECS)
            .invoke_async(&mut *conn)
            .await
            .map_err(|error| format!("warmup admission store unavailable: {error}"))?;
        match verdict {
            0 => Ok(WarmupAdmission::AtCap),
            1 | 2 => Ok(WarmupAdmission::Admitted),
            other => Err(format!("warmup admission script returned {other}")),
        }
    }
}

/// The relay's warmup gate: installed (`Some`) the relay admits every
/// warming-IP delivery attempt itself; absent, the relay is running where a
/// caller-side authority already owns admission (embedded tests, and the
/// inline worker path until that caller is migrated).
#[derive(Clone)]
pub struct WarmupGate {
    inner: Option<Arc<dyn WarmupAdmit>>,
}

impl WarmupGate {
    /// No relay-side admission (caller-side authority).
    pub fn none() -> Self {
        Self { inner: None }
    }

    /// Relay-side admission at the SMTP-effect boundary.
    pub fn new(admit: Arc<dyn WarmupAdmit>) -> Self {
        Self { inner: Some(admit) }
    }

    pub fn is_installed(&self) -> bool {
        self.inner.is_some()
    }

    /// Admit one attempt. `Ok(None)` = no gate installed or no dedicated IP
    /// requested (proceed); `Ok(Some(verdict))` = gate decided;
    /// `Err(reason)` = fail-closed defer with the named reason.
    pub async fn admit(
        &self,
        send_unit: &str,
        source_ip: Option<IpAddr>,
        db: Option<&sqlx::PgPool>,
    ) -> Result<Option<WarmupAdmission>, String> {
        let (Some(gate), Some(ip)) = (self.inner.as_ref(), source_ip) else {
            return Ok(None);
        };
        let Some(db) = db else {
            // A gate without its lifecycle store cannot judge the cap —
            // fail closed rather than send unaccounted.
            return Err(
                "warmup admission is installed but the ledger is not Postgres-backed — \
                 refusing to send unaccounted"
                    .to_string(),
            );
        };
        gate.admit(send_unit, ip, db).await.map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_families_are_stable() {
        assert_eq!(
            counter_key("203.0.113.9", "2026-09-17"),
            "apexmail:warmup:ip:203.0.113.9:2026-09-17"
        );
        assert_eq!(
            marker_key("203.0.113.9", "2026-09-17", "email_queue:1:a@b.test"),
            "apexmail:warmup:relay:203.0.113.9:2026-09-17:email_queue:1:a@b.test"
        );
    }

    #[test]
    fn uninstalled_gate_is_transparent() {
        let gate = WarmupGate::none();
        assert!(!gate.is_installed());
    }
}
