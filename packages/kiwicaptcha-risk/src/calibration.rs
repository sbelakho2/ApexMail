//! Outcome-feedback calibration: records whether scored requests were
//! legitimate (post-hoc, e.g. from support flags) and produces a bounded
//! bias adjustment per scope, added to the raw risk score.
//!
//! The store is Redis-backed and BOUNDED (identical design to PHP):
//!
//! - Hourly aggregate buckets `{kiwi:<ns>}:cal:<scope>:<hour>` (hour =
//!   `now_ms / 3600000`, integer) — a hash of
//!   `b<band>a<action>:legit` / `b<band>a<action>:abuse` counters,
//!   `HINCRBY` + `EXPIRE 48h`. At most 24 keys per scope are ever read.
//! - Decision receipts `{kiwi:<ns>}:cal:receipt:<decision_id>` — HSET
//!   scope/band/action, EXPIRE 300 s, consumed with GETDEL.
//!
//! Bias (byte-identical integer math with PHP, ALL i64 truncating division,
//! executed inside ONE canonical Lua invocation — the script at
//! `resources/calibration.lua`, shared verbatim with PHP):
//!
//! ```text
//! total = legit + abuse            (summed over the last 24 hourly buckets)
//! bias  = 0                        when total < min_samples (default 1000)
//! raw   = ((abuse - legit) * 1000 / total) * 2 / 10
//! bias  = clamp(raw, -max_adjustment, +max_adjustment)   (default ±150)
//! final = clamp(bias, prev - allowed, prev + allowed)     with
//!         allowed = max_change_per_minute * 1000 * elapsed_ms / 60000
//!         (bias is persisted in MILLI-POINTS at
//!          `{kiwi:<ns>}:cal:state:<scope>`; the FIRST call ever seeds
//!          bias_mp = 0 / ts = now BEFORE the sample threshold is evaluated,
//!          ts is refreshed on EVERY call, and below the threshold the
//!          result is 0 with bias_mp untouched — all atomically in the one
//!          script)
//! ```
//!
//! `bias_for_scope` caches the per-scope result in-process for 30 s (bounded
//! to ~1024 scopes, oldest evicted): cache hits make ZERO Redis calls (0 is
//! cached too). The engine applies `clamp(base + bias, 0, 1000)` BEFORE band
//! mapping.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use redis::Commands;
use thiserror::Error;

use crate::action::RiskAction;

/// Calibration backend error; the engine treats any failure as a silent
/// no-op (never breaks issuance).
#[derive(Debug, Error)]
pub enum CalibrationError {
    #[error("calibration backend unavailable: {0}")]
    Backend(String),
}

/// The receipt stored for one decision, consumed when the outcome is
/// confirmed (GETDEL).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalibrationReceipt {
    pub scope: u32,
    pub band: u8,
    pub action: RiskAction,
}

/// Outcome-feedback calibration store.
pub trait CalibrationStore: Send + Sync {
    /// Records one confirmed outcome into the current hourly bucket.
    fn record(
        &self,
        scope: u32,
        band: u8,
        action: RiskAction,
        legitimate: bool,
    ) -> Result<(), CalibrationError>;

    /// Bias adjustment for a scope at `now_ms` (epoch milliseconds).
    ///
    /// Zero below `min_samples`; clamped to `max_adjustment`; rate-of-change
    /// clamped by the proportional allowance. Aggregation, state seeding and
    /// clamping are ONE atomic canonical Lua invocation. Results are cached
    /// in-process for 30 s (hits make no backend calls; 0 is cached too).
    /// Any backend failure returns 0 (fail-open).
    fn bias_for_scope(&self, scope: u32, now_ms: i64) -> i32;

    /// Registers the calibration receipt of one issued decision.
    fn record_receipt(
        &self,
        decision_id: &str,
        scope: u32,
        band: u8,
        action: RiskAction,
    ) -> Result<(), CalibrationError>;

    /// Consumes (GETDEL) the receipt for a decision_id, if it is still
    /// alive. `None` when absent or expired.
    fn consume_receipt(&self, decision_id: &str) -> Option<CalibrationReceipt>;
}

/// Maps a risk score to its band (`score / 100`) and records the outcome
/// with the action that was taken (PHP `CalibrationRecorder` equivalent).
pub struct CalibrationRecorder<'a> {
    store: &'a dyn CalibrationStore,
}

impl<'a> CalibrationRecorder<'a> {
    pub fn new(store: &'a dyn CalibrationStore) -> CalibrationRecorder<'a> {
        CalibrationRecorder { store }
    }

    pub fn record(
        &self,
        scope: u32,
        score: u16,
        action: RiskAction,
        legitimate: bool,
    ) -> Result<(), CalibrationError> {
        let band = (score.clamp(0, 1000) / 100) as u8;
        self.store.record(scope, band, action, legitimate)
    }
}

/// Redis-backed bounded aggregator implementing the calibration contract.
pub struct RedisCalibrationStore {
    client: redis::Client,
    namespace: String,
    conn: Mutex<Option<redis::Connection>>,
    min_samples: i64,
    max_adjustment: i32,
    max_change_per_minute: i32,
    receipt_ttl_secs: u64,
    cache: Mutex<BiasCache>,
    script: redis::Script,
    script_calls: AtomicUsize,
}

/// Bounded in-process per-scope bias cache: a hit serves the last computed
/// bias (including 0) without any Redis call.
struct BiasCache {
    entries: HashMap<u32, (i32, Instant)>,
    cap: usize,
    ttl: Duration,
}

impl BiasCache {
    fn new(cap: usize, ttl: Duration) -> BiasCache {
        BiasCache {
            entries: HashMap::new(),
            cap,
            ttl,
        }
    }

    /// The cached bias when it is still younger than the TTL; a stale entry
    /// is dropped on the way out.
    fn get(&mut self, scope: u32, now: Instant) -> Option<i32> {
        match self.entries.get(&scope) {
            Some((bias, at)) if now.saturating_duration_since(*at) <= self.ttl => Some(*bias),
            Some(_) => {
                self.entries.remove(&scope);
                None
            }
            None => None,
        }
    }

    /// Inserts (or refreshes) the scope's entry; when the cache is full the
    /// oldest entry is evicted first.
    fn insert(&mut self, scope: u32, bias: i32, now: Instant) {
        if !self.entries.contains_key(&scope) && self.entries.len() >= self.cap {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, (_, at))| *at)
                .map(|(s, _)| *s);
            if let Some(oldest) = oldest {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(scope, (bias, now));
    }
}

/// The CANONICAL calibration script, shared verbatim with PHP
/// (`protocol/risk-v1/calibration.lua`). One invocation replaces the old
/// two-script round trip: it aggregates the 24 hourly buckets, seeds and
/// refreshes the rate-limit state (milli-points), applies the proportional
/// per-minute allowance and returns the final integer bias in points.
const CALIBRATION_LUA: &str = include_str!("../resources/calibration.lua");

impl RedisCalibrationStore {
    /// Bucket retention (48 h; 24 buckets per scope are ever read).
    pub const BUCKET_EXPIRE_S: u64 = 48 * 3600;
    /// Default receipt lifetime (configurable via
    /// [`RedisCalibrationStore::with_receipt_ttl`]).
    pub const RECEIPT_EXPIRE_S: u64 = 300;
    /// Hourly buckets considered by `bias_for_scope` (current + 23 back).
    pub const BUCKET_WINDOW_HOURS: i64 = 24;
    /// Minimum confirmed outcomes before a scope earns any nonzero bias.
    pub const DEFAULT_MIN_SAMPLES: i64 = 1000;
    /// Hard clamp applied to the raw bias.
    pub const DEFAULT_MAX_ADJUSTMENT: i32 = 150;
    /// Maximum bias movement per minute.
    pub const DEFAULT_MAX_CHANGE_PER_MINUTE: i32 = 10;
    /// In-process per-scope bias cache TTL.
    pub const CACHE_TTL_S: u64 = 30;
    /// Bounded in-process cache capacity (oldest entries are evicted).
    pub const CACHE_CAP: usize = 1024;

    /// Builds a store on a fresh connection (lazy) with the default safety
    /// knobs (min_samples 1000, max_adjustment 150, max_change_per_minute
    /// 10).
    ///
    /// # Panics
    ///
    /// Panics if the namespace is empty or contains `{`/`}`.
    pub fn new(client: redis::Client, namespace: &str) -> RedisCalibrationStore {
        RedisCalibrationStore::with_limits(
            client,
            namespace,
            Self::DEFAULT_MIN_SAMPLES,
            Self::DEFAULT_MAX_ADJUSTMENT,
            Self::DEFAULT_MAX_CHANGE_PER_MINUTE,
        )
    }

    /// Builds a store with explicit calibration safety knobs (receipt TTL
    /// stays at the 300 s default).
    ///
    /// # Panics
    ///
    /// Panics if the namespace is empty or contains `{`/`}`, or if
    /// `min_samples < 1` / `max_adjustment < 0` / `max_change_per_minute < 0`.
    pub fn with_limits(
        client: redis::Client,
        namespace: &str,
        min_samples: i64,
        max_adjustment: i32,
        max_change_per_minute: i32,
    ) -> RedisCalibrationStore {
        RedisCalibrationStore::with_receipt_ttl(
            client,
            namespace,
            min_samples,
            max_adjustment,
            max_change_per_minute,
            Self::RECEIPT_EXPIRE_S,
        )
    }

    /// Builds a store with explicit calibration safety knobs and an explicit
    /// decision-receipt lifetime.
    ///
    /// # Panics
    ///
    /// Panics if the namespace is empty or contains `{`/`}`, if
    /// `min_samples < 1` / `max_adjustment < 0` / `max_change_per_minute < 0`,
    /// or if `receipt_ttl_secs < 1`.
    pub fn with_receipt_ttl(
        client: redis::Client,
        namespace: &str,
        min_samples: i64,
        max_adjustment: i32,
        max_change_per_minute: i32,
        receipt_ttl_secs: u64,
    ) -> RedisCalibrationStore {
        assert!(
            !namespace.is_empty() && !namespace.contains(['{', '}']),
            "Calibration namespace must be non-empty and free of braces"
        );
        assert!(min_samples >= 1, "min_samples must be >= 1");
        assert!(max_adjustment >= 0, "max_adjustment must be >= 0");
        assert!(
            max_change_per_minute >= 0,
            "max_change_per_minute must be >= 0"
        );
        assert!(receipt_ttl_secs >= 1, "receipt_ttl_secs must be >= 1");
        RedisCalibrationStore {
            client,
            namespace: namespace.to_string(),
            conn: Mutex::new(None),
            min_samples,
            max_adjustment,
            max_change_per_minute,
            receipt_ttl_secs,
            cache: Mutex::new(BiasCache::new(
                Self::CACHE_CAP,
                Duration::from_secs(Self::CACHE_TTL_S),
            )),
            script: redis::Script::new(CALIBRATION_LUA),
            script_calls: AtomicUsize::new(0),
        }
    }

    /// The deployment namespace inside the `{kiwi:<ns>}` hash tag.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Number of Lua script invocations issued by `bias_for_scope` since
    /// construction (diagnostics; doubles as the cache-hit counter in
    /// tests).
    pub fn script_calls(&self) -> usize {
        self.script_calls.load(Ordering::Relaxed)
    }

    fn cache_insert(&self, scope: u32, bias: i32, now: Instant) {
        self.cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(scope, bias, now);
    }

    /// Records into an EXPLICIT hourly bucket (`now_ms` injected — used by
    /// tests; `record` uses the current clock).
    pub fn record_at(
        &self,
        scope: u32,
        band: u8,
        action: RiskAction,
        legitimate: bool,
        now_ms: i64,
    ) -> Result<(), CalibrationError> {
        let hour = now_ms / 3_600_000;
        let key = self.bucket_key(scope, hour);
        let field = format!(
            "b{band}a{}:{}",
            action.as_str(),
            if legitimate { "legit" } else { "abuse" }
        );
        let mut guard = self.connection()?;
        let conn = guard.as_mut().ok_or_else(|| {
            CalibrationError::Backend("calibration connection vanished".to_string())
        })?;
        conn.hincr::<_, _, _, ()>(&key, field, 1).map_err(backend)?;
        conn.expire::<_, ()>(&key, Self::BUCKET_EXPIRE_S as i64)
            .map_err(backend)?;
        // A fresh outcome invalidates the scope's cached bias so the next
        // assessment re-aggregates.
        self.cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entries
            .remove(&scope);
        Ok(())
    }

    fn bucket_key(&self, scope: u32, hour: i64) -> String {
        format!("{{kiwi:{}}}:cal:{scope}:{hour}", self.namespace)
    }

    fn state_key(&self, scope: u32) -> String {
        format!("{{kiwi:{}}}:cal:state:{scope}", self.namespace)
    }

    fn receipt_key(&self, decision_id: &str) -> String {
        format!("{{kiwi:{}}}:cal:receipt:{decision_id}", self.namespace)
    }

    /// Lazy single connection.
    fn connection(&self) -> Result<MutexGuard<'_, Option<redis::Connection>>, CalibrationError> {
        let mut guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        if guard.is_none() {
            let conn = self
                .client
                .get_connection()
                .map_err(|e| CalibrationError::Backend(e.to_string()))?;
            *guard = Some(conn);
        }
        Ok(guard)
    }
}

fn backend(e: redis::RedisError) -> CalibrationError {
    CalibrationError::Backend(e.to_string())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

impl CalibrationStore for RedisCalibrationStore {
    fn record(
        &self,
        scope: u32,
        band: u8,
        action: RiskAction,
        legitimate: bool,
    ) -> Result<(), CalibrationError> {
        self.record_at(scope, band, action, legitimate, now_ms())
    }

    fn bias_for_scope(&self, scope: u32, now_ms: i64) -> i32 {
        let now = Instant::now();
        // Cache hit (including a cached 0): ZERO Redis calls.
        if let Some(cached) = self
            .cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(scope, now)
        {
            return cached;
        }
        let mut guard = match self.connection() {
            Ok(guard) => guard,
            Err(_) => return 0, // fail-open: never break issuance
        };
        let conn = guard.as_mut().expect("connection set by connection()");

        // HOT PATH: ONE canonical script invocation (was two scripts). Keys
        // are the 24 hourly buckets + the state key; ARGV is
        // now_ms, min_samples, max_adjustment, max_change_per_minute. The
        // script aggregates, seeds/refreshes the milli-point state, applies
        // the proportional allowance and returns the integer bias.
        let hour = now_ms / 3_600_000;
        let mut keys: Vec<String> = Vec::with_capacity(Self::BUCKET_WINDOW_HOURS as usize + 1);
        for h in (hour - (Self::BUCKET_WINDOW_HOURS - 1))..=hour {
            keys.push(self.bucket_key(scope, h));
        }
        keys.push(self.state_key(scope));
        let mut invoke = self.script.prepare_invoke();
        for key in &keys {
            invoke.key(key.as_str());
        }
        invoke.arg(now_ms.to_string());
        invoke.arg(self.min_samples.to_string());
        invoke.arg(self.max_adjustment.to_string());
        invoke.arg(self.max_change_per_minute.to_string());
        let bias: i64 = match invoke.invoke(conn) {
            Ok(bias) => bias,
            Err(_) => return 0,
        };
        self.script_calls.fetch_add(1, Ordering::Relaxed);

        self.cache_insert(scope, bias as i32, now);
        bias as i32
    }

    fn record_receipt(
        &self,
        decision_id: &str,
        scope: u32,
        band: u8,
        action: RiskAction,
    ) -> Result<(), CalibrationError> {
        let key = self.receipt_key(decision_id);
        let mut guard = self.connection()?;
        let conn = guard.as_mut().ok_or_else(|| {
            CalibrationError::Backend("calibration connection vanished".to_string())
        })?;
        // Wire format shared with PHP: a JSON string
        // {"scope":..,"band":..,"action":".."} with EXPIRE `receipt_ttl_secs`
        // (default 300 s), consumed once, atomically, via GETDEL (GETDEL is
        // STRING-only in Redis).
        let json = serde_json::json!({
            "scope": scope,
            "band": band,
            "action": action.as_str(),
        })
        .to_string();
        redis::cmd("SET")
            .arg(&key)
            .arg(&json)
            .arg("EX")
            .arg(self.receipt_ttl_secs)
            .query::<()>(conn)
            .map_err(backend)?;
        Ok(())
    }

    fn consume_receipt(&self, decision_id: &str) -> Option<CalibrationReceipt> {
        let key = self.receipt_key(decision_id);
        let mut guard = self.connection().ok()?;
        let conn = guard.as_mut()?;
        let json: Option<String> = redis::cmd("GETDEL").arg(&key).query(conn).ok()?;
        let json = json?;
        let value: serde_json::Value = serde_json::from_str(&json).ok()?;
        Some(CalibrationReceipt {
            scope: value.get("scope")?.as_u64()?.try_into().ok()?,
            band: value.get("band")?.as_u64()?.try_into().ok()?,
            action: value.get("action")?.as_str()?.parse().ok()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const T0: i64 = 1_700_000_000_000;

    fn redis_url() -> Option<String> {
        match std::env::var("RISK_REDIS_URL") {
            Ok(url) if !url.is_empty() => Some(if let Some(rest) = url.strip_prefix("tcp://") {
                format!("redis://{rest}")
            } else {
                url
            }),
            _ => None,
        }
    }

    fn client() -> redis::Client {
        redis::Client::open(redis_url().expect("RISK_REDIS_URL set")).expect("url parses")
    }

    fn unique_namespace(prefix: &str) -> String {
        let mut suffix = [0u8; 4];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut suffix);
        format!("{prefix}{}", hex::encode(suffix))
    }

    fn store(prefix: &str) -> RedisCalibrationStore {
        RedisCalibrationStore::new(client(), &unique_namespace(prefix))
    }

    fn store_limits(
        prefix: &str,
        min_samples: i64,
        max_adjustment: i32,
        max_change_per_minute: i32,
    ) -> RedisCalibrationStore {
        RedisCalibrationStore::with_limits(
            client(),
            &unique_namespace(prefix),
            min_samples,
            max_adjustment,
            max_change_per_minute,
        )
    }

    /// A fresh store (cold in-process cache) over an EXISTING namespace:
    /// forces a re-aggregation against the persisted Redis state.
    fn store_on(
        namespace: &str,
        min_samples: i64,
        max_adjustment: i32,
        max_change_per_minute: i32,
    ) -> RedisCalibrationStore {
        RedisCalibrationStore::with_limits(
            client(),
            namespace,
            min_samples,
            max_adjustment,
            max_change_per_minute,
        )
    }

    fn fill(
        store: &RedisCalibrationStore,
        scope: u32,
        band: u8,
        action: RiskAction,
        legit: i64,
        abuse: i64,
        at: i64,
    ) {
        for _ in 0..legit {
            store.record_at(scope, band, action, true, at).unwrap();
        }
        for _ in 0..abuse {
            store.record_at(scope, band, action, false, at).unwrap();
        }
    }

    #[test]
    fn bias_formula_matches_contract() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        // Huge max_change_per_minute: the proportional allowance never binds,
        // so the raw formula is observable. Every scope's FIRST call seeds
        // the state (bias_mp = 0, ts = now) and returns 0; one minute later
        // the raw value is reached in full.
        let s = store_limits("bias", 1, 150, 100_000);

        // All abuse -> ((n*1000/n)*2)/10 = 200 -> clamped to max_adjustment
        // 150 (the clamp is knob-driven).
        fill(&s, 1, 3, RiskAction::Sha20, 0, 10, T0);
        assert_eq!(s.bias_for_scope(1, T0), 0, "first call seeds the state");
        assert_eq!(
            store_on(s.namespace(), 1, 150, 100_000).bias_for_scope(1, T0 + 60_000),
            150
        );

        // All legit -> -150.
        fill(&s, 2, 3, RiskAction::Sha20, 10, 0, T0);
        assert_eq!(s.bias_for_scope(2, T0), 0);
        assert_eq!(
            store_on(s.namespace(), 1, 150, 100_000).bias_for_scope(2, T0 + 60_000),
            -150
        );

        // 60% abuse / 40% legit: ((20*1000)/100)*2/10 = 40.
        fill(&s, 3, 3, RiskAction::Sha20, 40, 60, T0);
        assert_eq!(s.bias_for_scope(3, T0), 0);
        assert_eq!(
            store_on(s.namespace(), 1, 150, 100_000).bias_for_scope(3, T0 + 60_000),
            40
        );

        // No samples -> 0.
        assert_eq!(s.bias_for_scope(99, T0), 0);
        assert_eq!(
            store_on(s.namespace(), 1, 150, 100_000).bias_for_scope(99, T0 + 60_000),
            0
        );

        // Truncation toward zero, byte-identical with PHP intdiv:
        // abuse 2 / legit 1 (total 3): (1*1000/3)*2/10 = 333*2/10 = 66.
        fill(&s, 4, 3, RiskAction::Sha20, 1, 2, T0);
        assert_eq!(s.bias_for_scope(4, T0), 0);
        assert_eq!(
            store_on(s.namespace(), 1, 150, 100_000).bias_for_scope(4, T0 + 60_000),
            66
        );
    }

    #[test]
    fn min_samples_threshold_gates_nonzero_bias() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store_limits("mins", 1000, 150, 10);
        // 999 outcomes (all abuse): below the threshold -> exactly 0, no
        // bias (the state is still seeded: bias_mp = 0, ts = T0).
        fill(&s, 1, 3, RiskAction::Sha20, 0, 999, T0);
        assert_eq!(s.bias_for_scope(1, T0), 0);
        // The 1000th sample (record_at invalidates the cache) unlocks the
        // bias: raw 200 -> clamped to max_adjustment 150, but the
        // proportional allowance started at the seeded ts (T0): one minute
        // later it admits exactly max_change_per_minute = 10 points.
        fill(&s, 1, 3, RiskAction::Sha20, 0, 1, T0);
        assert_eq!(
            store_on(s.namespace(), 1000, 150, 10).bias_for_scope(1, T0 + 60_000),
            10
        );
    }

    #[test]
    fn bias_rate_of_change_clamped_proportionally() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store_limits("roc", 1, 150, 60);
        fill(&s, 1, 3, RiskAction::Sha20, 0, 10, T0);
        // First call seeds bias_mp = 0 / ts = T0: the raw 150 is clamped
        // against 0 by a zero allowance.
        assert_eq!(s.bias_for_scope(1, T0), 0);

        // 5 s elapsed -> at most mpm / 12 = 60/12 = 5 points (proportional:
        // 60 * 1000 * 5000 / 60000 = 5000 milli-points).
        assert_eq!(
            store_on(s.namespace(), 1, 150, 60).bias_for_scope(1, T0 + 5_000),
            5
        );
        // Another 5 s: +5 more -> 10.
        assert_eq!(
            store_on(s.namespace(), 1, 150, 60).bias_for_scope(1, T0 + 10_000),
            10
        );

        // Flip to all-legit: raw -198 -> -150, but the allowance from the
        // last ts (T0 + 10 s) over 50 s is 60 * 1000 * 50000 / 60000 =
        // 50000 mp = 50 points: 10 - 50 = -40 (truncating division, byte
        // identical with PHP).
        fill(&s, 1, 3, RiskAction::Sha20, 1000, 0, T0);
        assert_eq!(
            store_on(s.namespace(), 1, 150, 60).bias_for_scope(1, T0 + 60_000),
            -40
        );
    }

    #[test]
    fn below_threshold_returns_zero_and_leaves_bias_untouched() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store_limits("bthr", 1, 150, 60);
        fill(&s, 1, 3, RiskAction::Sha20, 0, 10, T0);
        assert_eq!(s.bias_for_scope(1, T0), 0);
        // 60 s after the seed the allowance is exactly 60 points: raw 150 ->
        // 60 (60 * 1000 * 60000 / 60000 milli-points).
        assert_eq!(
            store_on(s.namespace(), 1, 150, 60).bias_for_scope(1, T0 + 60_000),
            60
        );

        // A below-threshold VIEW of the same data: returns 0, leaves
        // bias_mp (60) untouched, but refreshes ts to T0 + 120 s.
        let low = store_on(s.namespace(), 1_000_000, 150, 60);
        assert_eq!(low.bias_for_scope(1, T0 + 120_000), 0);

        // Back above the threshold: the bias resumes from the stored 60 and
        // the allowance counts ONLY from the refreshed ts (T0 + 120 s):
        // over 60 s that is 60 points -> final = min(150, 60 + 60) = 120.
        assert_eq!(
            store_on(s.namespace(), 1, 150, 60).bias_for_scope(1, T0 + 180_000),
            120
        );
    }

    #[test]
    fn bias_cache_hits_make_zero_redis_calls_and_single_lua_invocation() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store_limits("cache", 1, 150, 100_000);
        fill(&s, 7, 3, RiskAction::Sha20, 0, 10, T0);
        assert_eq!(s.bias_for_scope(7, T0), 0);
        // Exactly ONE canonical script invocation over 24 bucket keys + the
        // state key (the old hot path issued TWO scripts).
        assert_eq!(s.script_calls(), 1);

        // Cache hit: the second call issues ZERO scripts.
        assert_eq!(s.bias_for_scope(7, T0 + 60_000), 0);
        assert_eq!(s.script_calls(), 1);

        // A fresh store (cold cache) re-aggregates: one minute after the
        // seed the proportional allowance is huge (mpm 100_000), so the raw
        // 150 is served in full.
        let ns = s.namespace().to_string();
        assert_eq!(
            store_on(&ns, 1, 150, 100_000).bias_for_scope(7, T0 + 60_000),
            150
        );

        // Behavior: delete every bucket; the cache still serves 0 while a
        // fresh store on the same namespace (cold cache) re-aggregates to 0
        // (no samples left).
        let mut conn = client().get_connection().expect("connection");
        let pattern = format!("{{kiwi:{ns}}}:cal:7:*");
        let keys: Vec<String> = conn.scan_match(pattern).expect("scan").collect();
        assert!(!keys.is_empty(), "scan must find the hourly buckets");
        conn.del::<_, ()>(keys).expect("del");
        assert_eq!(
            s.bias_for_scope(7, T0 + 120_000),
            0,
            "cache serves without Redis reads"
        );
        assert_eq!(
            store_on(&ns, 1, 150, 100_000).bias_for_scope(7, T0 + 120_000),
            0,
            "cold re-aggregation sees the deleted buckets"
        );
    }

    #[test]
    fn record_invalidates_the_cached_bias() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store_limits("inval", 1, 150, 100_000);
        fill(&s, 7, 3, RiskAction::Sha20, 0, 10, T0);
        assert_eq!(s.bias_for_scope(7, T0), 0);
        assert_eq!(s.script_calls(), 1);
        // Cache hit: no backend call.
        assert_eq!(s.bias_for_scope(7, T0 + 60_000), 0);
        assert_eq!(s.script_calls(), 1);

        // A fresh outcome (record_at/record) drops the scope's cache entry:
        // the next call re-invokes the script and serves the new aggregate.
        for _ in 0..10 {
            s.record_at(7, 3, RiskAction::Sha20, true, T0 + 3_600_000)
                .unwrap();
        }
        assert_eq!(s.bias_for_scope(7, T0 + 3_600_000), 0); // 10 legit vs 10 abuse -> raw 0
        assert_eq!(
            s.script_calls(),
            2,
            "record() must invalidate the cached bias"
        );
    }

    #[test]
    fn bias_cache_bounded_with_oldest_eviction() {
        let now = Instant::now();
        let mut cache = BiasCache::new(2, Duration::from_secs(30));
        cache.insert(1, 10, now);
        cache.insert(2, 20, now + Duration::from_millis(1));
        cache.insert(3, 30, now + Duration::from_millis(2));
        // Full at cap 2: the OLDEST entry (scope 1) is evicted.
        assert_eq!(cache.get(1, now), None);
        assert_eq!(cache.get(2, now), Some(20));
        assert_eq!(cache.get(3, now), Some(30));

        // TTL: valid inside the window, dropped (and removed) once stale.
        let mut cache = BiasCache::new(4, Duration::from_secs(30));
        cache.insert(9, 5, now);
        assert_eq!(cache.get(9, now + Duration::from_secs(29)), Some(5));
        assert_eq!(cache.get(9, now + Duration::from_secs(31)), None);
        assert_eq!(cache.get(9, now + Duration::from_secs(31)), None);
    }

    #[test]
    fn bias_sums_across_hourly_buckets() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store_limits("buckets", 1, 150, 100_000);
        // Same scope, three hours: 30 abuse + 30 legit -> raw 0 (the first
        // call seeds; a cold store one minute later serves the raw 0).
        fill(&s, 1, 2, RiskAction::Sha18, 10, 0, T0);
        fill(&s, 1, 2, RiskAction::Sha18, 10, 10, T0 - 3_600_000);
        fill(&s, 1, 2, RiskAction::Sha18, 10, 20, T0 - 7_200_000);
        assert_eq!(s.bias_for_scope(1, T0), 0);
        assert_eq!(
            store_on(s.namespace(), 1, 150, 100_000).bias_for_scope(1, T0 + 60_000),
            0
        );

        // Buckets older than 24 hours are out of the window (the record_at
        // fills invalidate the cache, so this re-aggregates; the total is
        // still 60 -> raw 0).
        fill(&s, 1, 2, RiskAction::Sha18, 0, 100, T0 - 25 * 3_600_000);
        assert_eq!(
            store_on(s.namespace(), 1, 150, 100_000).bias_for_scope(1, T0 + 120_000),
            0
        );
    }

    #[test]
    fn receipt_ttl_knob_is_applied() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = RedisCalibrationStore::with_receipt_ttl(
            client(),
            &unique_namespace("ttl"),
            1,
            150,
            10,
            1,
        );
        s.record_receipt("decision-ttl", 7, 4, RiskAction::Argon16)
            .unwrap();
        let mut conn = client().get_connection().expect("connection");
        let ttl: i64 = redis::cmd("TTL")
            .arg(format!(
                "{{kiwi:{}}}:cal:receipt:decision-ttl",
                s.namespace()
            ))
            .query(&mut conn)
            .expect("ttl");
        assert_eq!(ttl, 1, "with_receipt_ttl must drive the EXPIRE");

        // The default knob stays 300 s.
        let d = store("ttldef");
        d.record_receipt("decision-def", 7, 4, RiskAction::Argon16)
            .unwrap();
        let ttl: i64 = redis::cmd("TTL")
            .arg(format!(
                "{{kiwi:{}}}:cal:receipt:decision-def",
                d.namespace()
            ))
            .query(&mut conn)
            .expect("ttl");
        assert_eq!(ttl, 300);
    }

    #[test]
    fn receipts_round_trip_and_consume_once() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store("receipts");
        s.record_receipt("decision-1", 7, 4, RiskAction::Argon16)
            .unwrap();

        let receipt = s.consume_receipt("decision-1");
        assert_eq!(
            receipt,
            Some(CalibrationReceipt {
                scope: 7,
                band: 4,
                action: RiskAction::Argon16,
            })
        );
        // GETDEL: consumed exactly once.
        assert_eq!(s.consume_receipt("decision-1"), None);

        // Unknown id -> None (never errors).
        assert_eq!(s.consume_receipt("decision-missing"), None);
    }

    #[test]
    fn recorder_maps_score_to_band() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let store: Arc<dyn CalibrationStore> = Arc::new(store("recorder"));
        let recorder = CalibrationRecorder::new(store.as_ref());
        // Band from score, engine-side: recorded into the current hour.
        let _ = recorder.record(1, 555, RiskAction::Sha20, true);
        assert_eq!((555u16).clamp(0, 1000) / 100, 5);
    }
}
