//! Outcome-feedback calibration: records whether scored requests were
//! legitimate (post-hoc, e.g. from support flags) and produces a bounded
//! bias adjustment per scope, added to the raw risk score.
//!
//! The store is Redis-backed and BOUNDED (identical design to PHP):
//!
//! - Hourly aggregate buckets `{kiwi:<ns>}:cal:<scope>:<hour>` (hour =
//!   `now_ms / 3600000`, integer) — a hash of flat fields
//!   `legit_count` / `legit_score_sum` / `abuse_count` / `abuse_score_sum`
//!   (EXACT scores, not band-quantized), written by
//!   `HINCRBYFLOAT` + `EXPIRE 48h`. At most 24 keys per scope are ever read.
//! - Decision receipts `{kiwi:<ns>}:cal:receipt:<decision_id>` — a STRING
//!   JSON `{"scope":..,"band":..,"action":"..","score":..,"sampled":0|1}`,
//!   EXPIRE `receipt_ttl_secs`, consumed ONCE by the atomic confirm script.
//!
//! Bias (byte-identical integer math with PHP, ALL i64 truncating division,
//! executed inside ONE canonical Lua invocation — the script at
//! `resources/calibration.lua`, shared verbatim with PHP):
//!
//! CLASS-NORMALIZED exact score calibration (volume-independent): each
//! confirmed observation carries its original risk score (0..1000):
//!
//! ```text
//! fp_mean = Σ legit_scores / legit_count      (0 when no legit samples)
//! fn_mean = (abuse_count × 1000 − Σ abuse_scores) / abuse_count
//!                                             (0 when no abuse samples)
//! error   = fn_mean × fn_cost − fp_mean × fp_cost
//! raw     = clamp(error × 2 / 10, −max_adjustment, +max_adjustment)
//!                                                  (default ±150)
//! ```
//!
//! Class normalization removes label-volume dominance; the
//! `false_positive_cost` / `false_negative_cost` knobs price false
//! positives against false negatives explicitly (defaults 1.0 / 2.0). A
//! perfectly separating classifier contributes ~zero pressure when the
//! costs are equal; abuse predicted at low risk pushes the bias UP,
//! legitimate traffic predicted at high risk pushes it DOWN. The target is
//! 0 below `min_samples` (default 1000).
//!
//! RANDOM-SAMPLE RESOLUTION GATE (mode 1 only): while
//! `sample_total >= min_samples` AND `sample_resolved < sample_total ×
//! minimum_resolution_ratio` (default 0.80), the target is SUSPENDED at 0 —
//! the label-reporting process must demonstrably resolve a minimum
//! fraction of the server-selected sample before the model may move. The
//! two counters are namespace-wide strings:
//! `{kiwi:<ns>}:cal:sample:total` (INCR at assessment time for every
//! sampled decision) and `{kiwi:<ns>}:cal:sample:resolved` (INCR by
//! `confirm.lua` on a sampled confirmation).
//!
//! The rate limiter is PROPORTIONAL to elapsed time and applies to the
//! PATH, not just the target: internal bias is stored in MILLI-POINTS at
//! `{kiwi:<ns>}:cal:state:<scope>` (1 point = 1000 units) and
//! `allowed = max_change_per_minute × 1000 × elapsed_ms / 60000`. The
//! FIRST call ever seeds bias_mp = 0 / ts = now BEFORE the sample threshold
//! is evaluated; `ts` is refreshed on EVERY call (below threshold too) so a
//! long quiet period cannot accumulate movement allowance; below the
//! threshold the stored bias still moves toward 0 through the same rate
//! limiter (never an instant snap) — all atomically in the one script. The
//! rate-limit clock is Redis TIME (the script derives `now` itself), so
//! app-node clock skew cannot move the shared state.
//!
//! Confirmation is ATOMIC via `resources/confirm.lua` (one script
//! invocation: GET receipt → validate mode/weight → DEL → HINCRBYFLOAT
//! into the bucket → EXPIRE): there is no crash window between consuming
//! the receipt and recording the outcome, and ALL arguments are validated
//! BEFORE the receipt is deleted (an invalid mode/weight is an error reply
//! that leaves the receipt untouched). The script returns a SHARED status:
//! 0 = missing / already confirmed / corrupt receipt; 1 = FIRST
//! confirmation and calibration recorded; 2 = FIRST confirmation but
//! deliberately unsampled (random-sample mode: the decision was not in the
//! server-selected sample, so it does NOT enter calibration — but the
//! confirmation is still consumed and the caller may apply first-party
//! reputation exactly once). In random-sample mode an unsampled decision
//! is discarded (deleted, never counted) so a label can never select
//! itself into the calibration population; weighted mode applies the
//! caller's inverse sampling probability as a float weight. KEYS[3] of the
//! script is the sampled-RESOLVED counter
//! (`{kiwi:<ns>}:cal:sample:resolved`), INCRed on a sampled confirmation
//! in random-sample mode.
//!
//! `bias_for_scope` caches the per-scope result in-process for 30 s (bounded
//! to ~1024 scopes, oldest evicted): cache hits make ZERO Redis calls (0 is
//! cached too). Recording a confirmed outcome (status 1 or 2) invalidates
//! the scope's entry so the next assessment re-aggregates. The engine
//! applies `clamp(base + bias, 0, 1000)` BEFORE band mapping.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use redis::Commands;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::action::RiskAction;

/// Calibration backend error; the engine treats any failure as a silent
/// no-op (never breaks issuance).
#[derive(Debug, Error)]
pub enum CalibrationError {
    #[error("calibration backend unavailable: {0}")]
    Backend(String),
}

/// Outcome-confirmation sampling strategy (wire ints shared with PHP:
/// 0 complete, 1 random_sample, 2 weighted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamplingMode {
    /// Every confirmed outcome is recorded (weight 1.0).
    Complete,
    /// Only decisions whose receipt was registered with `sampled: 1` are
    /// recorded; the confirm script discards the rest (a label can never
    /// select itself into the calibration population).
    RandomSample,
    /// Every decision is sampled; the caller supplies the inverse sampling
    /// probability as the confirm weight so the population stays unbiased.
    Weighted,
}

impl SamplingMode {
    /// The ARGV[1] wire int shared with `resources/confirm.lua`.
    fn as_int(self) -> u8 {
        match self {
            SamplingMode::Complete => 0,
            SamplingMode::RandomSample => 1,
            SamplingMode::Weighted => 2,
        }
    }
}

/// Outcome-feedback calibration store.
pub trait CalibrationStore: Send + Sync {
    /// Registers the calibration receipt of one issued decision: a STRING
    /// JSON `{"scope":..,"band":..,"action":"..","score":..,"sampled":0|1}`
    /// with EXPIRE `receipt_ttl_secs`. `score` is the decision's EXACT risk
    /// score (0..1000); `sampled` is the [`CalibrationStore::sample`] flag.
    fn record_receipt(
        &self,
        decision_id: &str,
        scope: u32,
        band: u8,
        action: RiskAction,
        score: u32,
        sampled: bool,
    ) -> Result<(), CalibrationError>;

    /// Confirms the outcome of one decision ATOMICALLY (one canonical Lua
    /// invocation — `resources/confirm.lua`): consumes the receipt and
    /// records the exact score into the scope's current hourly bucket, or
    /// discards an unsampled receipt in random-sample mode.
    ///
    /// Returns the SHARED accepted-outcome status (wire contract with PHP):
    ///
    /// - `0` — nothing consumed: receipt missing, already confirmed,
    ///   corrupt, or (mode 1) discarded as deliberately unsampled.
    /// - `1` — FIRST confirmation; the exact score was recorded into the
    ///   scope bucket (+ the sampled-resolved counter in random-sample
    ///   mode).
    /// - `2` — FIRST confirmation; deliberately unsampled in random-sample
    ///   mode (consumed, never calibrated, resolved counter untouched).
    ///
    /// Statuses 1 and 2 both mean "first confirmation" — the caller may
    /// apply the first-party reputation event exactly once (engine
    /// contract); status 0 must NOT book any reputation event (a retry
    /// must never amplify). `weight` is the HINCRBYFLOAT weight (default
    /// 1.0; the inverse sampling probability in weighted mode). Any
    /// backend failure — including a Lua error reply for an invalid mode
    /// or weight, which happens BEFORE the receipt is deleted — is an
    /// error (the engine treats calibration as best-effort).
    fn confirm_outcome(
        &self,
        decision_id: &str,
        legitimate: bool,
        weight: Option<f64>,
    ) -> Result<u8, CalibrationError>;

    /// Assessment-time accounting hook: the engine calls this for every
    /// decision whose receipt was registered with `sampled: true`; in
    /// random-sample mode the store INCRs the namespace-wide sampled-TOTAL
    /// counter `{kiwi:<ns>}:cal:sample:total` (the denominator of the
    /// resolution gate). PHP parity: the PHP store performs the same INCR
    /// inside its `sample()` when mode is random_sample and the decision
    /// is sampled. Other modes are no-ops. Default: no-op.
    fn mark_sampled(&self) -> Result<(), CalibrationError> {
        Ok(())
    }

    /// Reserves the once-only correction slot for a decision: SET NX
    /// `{kiwi:<ns>}:cal:corrected:<hex(sha256(decision_id))>` EX
    /// `receipt_ttl_secs`. `Ok(true)` = this call WON the slot (the engine
    /// may record its compensating event); `Ok(false)` = already
    /// corrected. Default: never granted (stores without a namespace
    /// cannot enforce the guard and therefore refuse corrections).
    fn reserve_correction(&self, decision_id: &str) -> Result<bool, CalibrationError> {
        let _ = decision_id;
        Ok(false)
    }

    /// The sampling flag stamped on every new receipt: Complete/Weighted
    /// always sample; RandomSample samples with probability
    /// `sampling_probability_ppm / 1_000_000`.
    fn sample(&self) -> bool;

    /// Bias adjustment for a scope at `now_ms` (epoch milliseconds).
    ///
    /// Zero below `min_samples`; clamped to `max_adjustment`; rate-of-change
    /// clamped by the proportional allowance. Aggregation, state seeding and
    /// clamping are ONE atomic canonical Lua invocation. Results are cached
    /// in-process for 30 s (hits make no backend calls; 0 is cached too).
    /// Any backend failure returns 0 (fail-open).
    fn bias_for_scope(&self, scope: u32, now_ms: i64) -> i32;
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
    mode: SamplingMode,
    sampling_probability_ppm: u32,
    minimum_resolution_ratio: f64,
    false_positive_cost: f64,
    false_negative_cost: f64,
    cache: Mutex<BiasCache>,
    script: redis::Script,
    confirm_script: redis::Script,
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

/// The CANONICAL atomic confirm script, shared verbatim with PHP
/// (`protocol/risk-v1/confirm.lua`). One invocation consumes the receipt
/// (DEL) and records the exact score into the bucket (HINCRBYFLOAT +
/// EXPIRE) — or discards an unsampled receipt in random-sample mode.
const CONFIRM_LUA: &str = include_str!("../resources/confirm.lua");

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
    /// Default confirmation sampling strategy.
    pub const DEFAULT_MODE: SamplingMode = SamplingMode::RandomSample;
    /// Default random-sample probability (100_000 ppm = 10 %).
    pub const DEFAULT_SAMPLING_PROBABILITY_PPM: u32 = 100_000;
    /// Default minimum resolution ratio for the random-sample gate:
    /// resolved/total must reach this before the bias may move (0 disables
    /// the gate).
    pub const DEFAULT_MIN_RESOLUTION_RATIO: f64 = 0.80;
    /// Default false-positive cost (fp_mean weight in the bias formula).
    pub const DEFAULT_FALSE_POSITIVE_COST: f64 = 1.0;
    /// Default false-negative cost (fn_mean weight; false negatives are
    /// priced twice as high as false positives).
    pub const DEFAULT_FALSE_NEGATIVE_COST: f64 = 2.0;
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
        RedisCalibrationStore::with_options(
            client,
            namespace,
            min_samples,
            max_adjustment,
            max_change_per_minute,
            receipt_ttl_secs,
            Self::DEFAULT_MODE,
            Self::DEFAULT_SAMPLING_PROBABILITY_PPM,
            Self::DEFAULT_MIN_RESOLUTION_RATIO,
            Self::DEFAULT_FALSE_POSITIVE_COST,
            Self::DEFAULT_FALSE_NEGATIVE_COST,
        )
    }

    /// Builds a store with every calibration knob explicit: the safety
    /// limits, the receipt lifetime, the confirmation sampling strategy
    /// (`mode` + `sampling_probability_ppm`, default RandomSample / 100_000
    /// — preserved by the [`RedisCalibrationStore::with_limits`] and
    /// [`RedisCalibrationStore::with_receipt_ttl`] shorthands) and the
    /// round-6 cost/resolution knobs: `minimum_resolution_ratio` (0..1,
    /// default 0.80 — 0 disables the random-sample resolution gate),
    /// `false_positive_cost` (default 1.0) and `false_negative_cost`
    /// (default 2.0).
    ///
    /// # Panics
    ///
    /// Panics if the namespace is empty or contains `{`/`}`, if
    /// `min_samples < 1` / `max_adjustment < 0` / `max_change_per_minute < 0`,
    /// if `receipt_ttl_secs < 1`, if `minimum_resolution_ratio` is outside
    /// 0..=1, or if either cost is not > 0.
    #[allow(clippy::too_many_arguments)]
    pub fn with_options(
        client: redis::Client,
        namespace: &str,
        min_samples: i64,
        max_adjustment: i32,
        max_change_per_minute: i32,
        receipt_ttl_secs: u64,
        mode: SamplingMode,
        sampling_probability_ppm: u32,
        minimum_resolution_ratio: f64,
        false_positive_cost: f64,
        false_negative_cost: f64,
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
        assert!(
            (0.0..=1.0).contains(&minimum_resolution_ratio),
            "minimum_resolution_ratio must be within 0..=1"
        );
        assert!(false_positive_cost > 0.0, "false_positive_cost must be > 0");
        assert!(false_negative_cost > 0.0, "false_negative_cost must be > 0");
        RedisCalibrationStore {
            client,
            namespace: namespace.to_string(),
            conn: Mutex::new(None),
            min_samples,
            max_adjustment,
            max_change_per_minute,
            receipt_ttl_secs,
            mode,
            sampling_probability_ppm,
            minimum_resolution_ratio,
            false_positive_cost,
            false_negative_cost,
            cache: Mutex::new(BiasCache::new(
                Self::CACHE_CAP,
                Duration::from_secs(Self::CACHE_TTL_S),
            )),
            script: redis::Script::new(CALIBRATION_LUA),
            confirm_script: redis::Script::new(CONFIRM_LUA),
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

    /// Seeds an EXPLICIT hourly bucket with one exact-score observation
    /// (flat fields `legit_count` / `legit_score_sum` /
    /// `abuse_count` / `abuse_score_sum`, `HINCRBYFLOAT` + `EXPIRE 48h` —
    /// the exact wire shape `resources/confirm.lua` produces; `now_ms`
    /// injected so tests can pin the hour). Ops/tests seeding: the
    /// production confirm path is [`CalibrationStore::confirm_outcome`].
    pub fn record_at(
        &self,
        scope: u32,
        score: u32,
        legitimate: bool,
        now_ms: i64,
    ) -> Result<(), CalibrationError> {
        let hour = now_ms / 3_600_000;
        let key = self.bucket_key(scope, hour);
        let (count_field, sum_field) = if legitimate {
            ("legit_count", "legit_score_sum")
        } else {
            ("abuse_count", "abuse_score_sum")
        };
        let mut guard = self.connection()?;
        let conn = guard.as_mut().ok_or_else(|| {
            CalibrationError::Backend("calibration connection vanished".to_string())
        })?;
        redis::cmd("HINCRBYFLOAT")
            .arg(&key)
            .arg(count_field)
            .arg(1.0)
            .query::<()>(conn)
            .map_err(backend)?;
        redis::cmd("HINCRBYFLOAT")
            .arg(&key)
            .arg(sum_field)
            .arg(score as f64)
            .query::<()>(conn)
            .map_err(backend)?;
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

    /// Namespace-wide sampled-decisions TOTAL counter (denominator of the
    /// random-sample resolution gate; KEYS[26] of calibration.lua).
    fn sample_total_key(&self) -> String {
        format!("{{kiwi:{}}}:cal:sample:total", self.namespace)
    }

    /// Namespace-wide sampled-decisions RESOLVED counter (numerator of the
    /// random-sample resolution gate; KEYS[27] of calibration.lua and
    /// KEYS[3] of confirm.lua).
    fn sample_resolved_key(&self) -> String {
        format!("{{kiwi:{}}}:cal:sample:resolved", self.namespace)
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
        // are the 24 hourly buckets + the rate-limit state + the two
        // random-sample resolution counters; ARGV is
        // now_ms (informational — the script's rate-limit clock is Redis
        // TIME), min_samples, max_adjustment, max_change_per_minute,
        // minimum_resolution_ratio (float), sampling mode (0/1/2),
        // false_positive_cost, false_negative_cost. The script aggregates,
        // seeds/refreshes the milli-point state, applies the proportional
        // allowance and the resolution gate, and returns the integer bias.
        let hour = now_ms / 3_600_000;
        let mut keys: Vec<String> = Vec::with_capacity(Self::BUCKET_WINDOW_HOURS as usize + 3);
        for h in (hour - (Self::BUCKET_WINDOW_HOURS - 1))..=hour {
            keys.push(self.bucket_key(scope, h));
        }
        keys.push(self.state_key(scope));
        keys.push(self.sample_total_key());
        keys.push(self.sample_resolved_key());
        let mut invoke = self.script.prepare_invoke();
        for key in &keys {
            invoke.key(key.as_str());
        }
        invoke.arg(now_ms.to_string());
        invoke.arg(self.min_samples.to_string());
        invoke.arg(self.max_adjustment.to_string());
        invoke.arg(self.max_change_per_minute.to_string());
        invoke.arg(self.minimum_resolution_ratio.to_string());
        invoke.arg(self.mode.as_int().to_string());
        invoke.arg(self.false_positive_cost.to_string());
        invoke.arg(self.false_negative_cost.to_string());
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
        score: u32,
        sampled: bool,
    ) -> Result<(), CalibrationError> {
        let key = self.receipt_key(decision_id);
        let mut guard = self.connection()?;
        let conn = guard.as_mut().ok_or_else(|| {
            CalibrationError::Backend("calibration connection vanished".to_string())
        })?;
        // Wire format shared with PHP: a JSON string
        // {"scope":..,"band":..,"action":"..","score":..,"sampled":0|1}
        // with EXPIRE `receipt_ttl_secs` (default 300 s), consumed once,
        // atomically, by the confirm script (GETDEL would lose the exact
        // score; the script DELs and increments in the same invocation).
        let json = serde_json::json!({
            "scope": scope,
            "band": band,
            "action": action.as_str(),
            "score": score.clamp(0, 1000),
            "sampled": sampled as u8,
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

    fn confirm_outcome(
        &self,
        decision_id: &str,
        legitimate: bool,
        weight: Option<f64>,
    ) -> Result<u8, CalibrationError> {
        let receipt_key = self.receipt_key(decision_id);
        let mut guard = self.connection()?;
        let conn = guard.as_mut().ok_or_else(|| {
            CalibrationError::Backend("calibration connection vanished".to_string())
        })?;

        // Key discovery: the bucket key needs the receipt's scope, which
        // only the receipt itself carries. The pre-read GET is
        // NON-destructive — the confirm script re-checks the receipt under
        // the same key, so a concurrent consumption simply yields status 0
        // (the outcome is recorded exactly once) and a receipt deleted in
        // between is a no-op, never a double record.
        let raw: Option<String> = redis::cmd("GET")
            .arg(&receipt_key)
            .query(conn)
            .map_err(backend)?;
        let Some(raw) = raw else {
            return Ok(0);
        };
        let value: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(value) => value,
            Err(_) => return Ok(0), // malformed: script would discard it
        };
        let Some(scope) = value.get("scope").and_then(|v| v.as_u64()) else {
            return Ok(0);
        };
        let Ok(scope) = u32::try_from(scope) else {
            return Ok(0);
        };
        let bucket_key = self.bucket_key(scope, now_ms() / 3_600_000);

        // ONE canonical script invocation: GET receipt -> validate mode +
        // weight -> DEL -> (discard or) HINCRBYFLOAT the exact score into
        // the bucket + EXPIRE -> (random-sample) INCR the resolved counter.
        // KEYS = receipt, bucket, resolved counter; ARGV = mode int, weight
        // (float; default 1.0), legitimate 1/0, bucket TTL. Returns the
        // SHARED status: 0 none consumed, 1 recorded, 2 consumed-but-
        // unsampled. Invalid mode/weight -> error_reply BEFORE the DEL, so
        // the receipt survives a validation failure.
        let resolved_key = self.sample_resolved_key();
        let mut invoke = self.confirm_script.prepare_invoke();
        invoke.key(receipt_key.as_str());
        invoke.key(bucket_key.as_str());
        invoke.key(resolved_key.as_str());
        invoke.arg(self.mode.as_int().to_string());
        invoke.arg(weight.unwrap_or(1.0).to_string());
        invoke.arg(if legitimate { "1" } else { "0" });
        invoke.arg(Self::BUCKET_EXPIRE_S.to_string());
        let status: i64 = invoke.invoke(conn).map_err(backend)?;
        if status != 0 {
            // A FIRST confirmation (status 1 or 2) invalidates the scope's
            // cached bias so the next assessment re-aggregates — status 2
            // is a consumed outcome too (unsampled: no calibration, but the
            // cache entry would otherwise go stale relative to the
            // namespace counters the gate reads).
            self.cache
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .entries
                .remove(&scope);
        }
        Ok(status as u8)
    }

    fn mark_sampled(&self) -> Result<(), CalibrationError> {
        if self.mode != SamplingMode::RandomSample {
            return Ok(());
        }
        let mut guard = self.connection()?;
        let conn = guard.as_mut().ok_or_else(|| {
            CalibrationError::Backend("calibration connection vanished".to_string())
        })?;
        redis::cmd("INCR")
            .arg(self.sample_total_key())
            .query::<i64>(conn)
            .map_err(backend)?;
        Ok(())
    }

    fn reserve_correction(&self, decision_id: &str) -> Result<bool, CalibrationError> {
        let mut digest = Sha256::new();
        digest.update(decision_id.as_bytes());
        let key = format!(
            "{{kiwi:{}}}:cal:corrected:{}",
            self.namespace,
            hex::encode(digest.finalize())
        );
        let mut guard = self.connection()?;
        let conn = guard.as_mut().ok_or_else(|| {
            CalibrationError::Backend("calibration connection vanished".to_string())
        })?;
        let set: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(self.receipt_ttl_secs)
            .query(conn)
            .map_err(backend)?;
        Ok(set.is_some())
    }

    fn sample(&self) -> bool {
        match self.mode {
            SamplingMode::Complete | SamplingMode::Weighted => true,
            SamplingMode::RandomSample => {
                rand::random::<u32>() % 1_000_000 < self.sampling_probability_ppm
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A store with every knob explicit on a fresh namespace.
    #[allow(clippy::too_many_arguments)]
    fn store_full(
        prefix: &str,
        min_samples: i64,
        max_adjustment: i32,
        max_change_per_minute: i32,
        receipt_ttl_secs: u64,
        mode: SamplingMode,
        ppm: u32,
        minimum_resolution_ratio: f64,
        false_positive_cost: f64,
        false_negative_cost: f64,
    ) -> RedisCalibrationStore {
        RedisCalibrationStore::with_options(
            client(),
            &unique_namespace(prefix),
            min_samples,
            max_adjustment,
            max_change_per_minute,
            receipt_ttl_secs,
            mode,
            ppm,
            minimum_resolution_ratio,
            false_positive_cost,
            false_negative_cost,
        )
    }

    /// A store with every knob explicit over an EXISTING namespace (cold
    /// cache): re-aggregates the persisted Redis state with the SAME knobs
    /// the seeding store used (gate thresholds, costs and mode are ARGV,
    /// so a mismatched cold store would compute a different bias).
    #[allow(clippy::too_many_arguments)]
    fn store_full_on(
        namespace: &str,
        min_samples: i64,
        max_adjustment: i32,
        max_change_per_minute: i32,
        receipt_ttl_secs: u64,
        mode: SamplingMode,
        ppm: u32,
        minimum_resolution_ratio: f64,
        false_positive_cost: f64,
        false_negative_cost: f64,
    ) -> RedisCalibrationStore {
        RedisCalibrationStore::with_options(
            client(),
            namespace,
            min_samples,
            max_adjustment,
            max_change_per_minute,
            receipt_ttl_secs,
            mode,
            ppm,
            minimum_resolution_ratio,
            false_positive_cost,
            false_negative_cost,
        )
    }

    /// A store in an explicit sampling mode on a fresh namespace (default
    /// resolution gate 0.80 and default costs).
    fn store_mode(prefix: &str, mode: SamplingMode, ppm: u32) -> RedisCalibrationStore {
        store_full(
            prefix,
            1,
            150,
            10,
            300,
            mode,
            ppm,
            RedisCalibrationStore::DEFAULT_MIN_RESOLUTION_RATIO,
            RedisCalibrationStore::DEFAULT_FALSE_POSITIVE_COST,
            RedisCalibrationStore::DEFAULT_FALSE_NEGATIVE_COST,
        )
    }

    fn fill(
        store: &RedisCalibrationStore,
        scope: u32,
        score: u32,
        legit: i64,
        abuse: i64,
        at: i64,
    ) {
        for _ in 0..legit {
            store.record_at(scope, score, true, at).unwrap();
        }
        for _ in 0..abuse {
            store.record_at(scope, score, false, at).unwrap();
        }
    }

    fn hget_f64(conn: &mut redis::Connection, key: &str, field: &str) -> f64 {
        let v: Option<String> = redis::cmd("HGET")
            .arg(key)
            .arg(field)
            .query(conn)
            .expect("hget");
        v.map(|s| s.parse().expect("float")).unwrap_or(0.0)
    }

    fn bucket_key(ns: &str, scope: u32) -> String {
        format!("{{kiwi:{ns}}}:cal:{scope}:{}", now_ms() / 3_600_000)
    }

    fn receipt_key(ns: &str, id: &str) -> String {
        format!("{{kiwi:{ns}}}:cal:receipt:{id}")
    }

    fn sample_total_key(ns: &str) -> String {
        format!("{{kiwi:{ns}}}:cal:sample:total")
    }

    fn sample_resolved_key(ns: &str) -> String {
        format!("{{kiwi:{ns}}}:cal:sample:resolved")
    }

    /// The Redis TIME clock in epoch milliseconds — the distributed clock
    /// authority the calibration script derives its rate-limit window from.
    fn redis_time_ms(conn: &mut redis::Connection) -> i64 {
        let t: Vec<i64> = redis::cmd("TIME").query(conn).expect("TIME");
        t[0] * 1000 + t[1] / 1000
    }

    /// Local epoch ms for bucket-hour selection (the Rust side computes the
    /// hourly window; the script's rate-limit clock is Redis TIME).
    fn now() -> i64 {
        now_ms()
    }

    /// Seeds the state for every scope of a store (each first call returns
    /// 0 and stamps ts = Redis now); the callers then sleep and query with
    /// a COLD store so the proportional allowance has real elapsed time.
    fn seed_all(store: &RedisCalibrationStore, scopes: &[u32]) {
        for &scope in scopes {
            assert_eq!(
                store.bias_for_scope(scope, now()),
                0,
                "the first call ever seeds bias_mp = 0 / ts = now"
            );
        }
    }

    /// Cold-store query of one scope with the huge-allowance config (mpm
    /// 100_000): after any real sleep the raw target is served in full.
    fn query_raw(ns: &str, scope: u32) -> i32 {
        store_on(ns, 1, 150, 100_000).bias_for_scope(scope, now())
    }

    #[test]
    fn bias_formula_is_class_normalized_exact_score_sensitive() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        // Huge max_change_per_minute: the proportional allowance never
        // binds, so the raw class-normalized formula is observable. Every
        // scope's FIRST call seeds the state (bias_mp = 0, ts = Redis now)
        // and returns 0; after a short real sleep the raw value is reached
        // in full.
        let s = store_limits("bias", 1, 150, 100_000);

        // Perfect separator (legit@100, abuse@900): with the default costs
        // (fn 2x fp) a balanced classifier nets error = 100*2 - 100*1 = 100
        // -> raw 20 (the cost-knob test shows 1/1 costs zero it out).
        fill(&s, 1, 100, 10, 0, now());
        fill(&s, 1, 900, 0, 10, now());
        // Abuse predicted at LOW score (100): under-predicted threat ->
        // fn_mean = 900 -> error 1800 -> raw 360 -> clamped 150.
        fill(&s, 2, 100, 0, 10, now());
        // Legit traffic predicted at HIGH score (900): over-predicted ->
        // fp_mean = 900 -> error -900 -> raw -180 -> clamped -150.
        fill(&s, 3, 900, 10, 0, now());
        // Class normalization kills label-volume dominance: 60 legit@900
        // + 40 abuse@100 has fp_mean = fn_mean = 900 -> error 900 -> 150
        // (the volume-based formula would have read -36 here).
        fill(&s, 4, 900, 60, 0, now());
        fill(&s, 4, 100, 0, 40, now());
        // 1 legit@100 + 2 abuse@100: fp 100, fn 900 -> error 1700 -> 150.
        fill(&s, 5, 100, 1, 2, now());
        // Positive truncation toward zero, byte-identical with PHP
        // trunc_div: 1 legit@100 + 2 abuse@600/601 -> fn 399.5 -> error
        // 699 -> raw 139.8 -> 139.
        fill(&s, 6, 100, 1, 0, now());
        fill(&s, 6, 600, 0, 1, now());
        fill(&s, 6, 601, 0, 1, now());
        // Negative truncation: 1 legit@402 + 2 abuse@850/851 -> fn 149.5,
        // error -103 -> raw -20.6 -> -20 (trunc toward zero).
        fill(&s, 7, 402, 1, 0, now());
        fill(&s, 7, 850, 0, 1, now());
        fill(&s, 7, 851, 0, 1, now());
        // No samples -> 0.
        seed_all(&s, &[1, 2, 3, 4, 5, 6, 7, 99]);
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(
            query_raw(s.namespace(), 1),
            20,
            "balanced separator with default costs"
        );
        assert_eq!(query_raw(s.namespace(), 2), 150);
        assert_eq!(query_raw(s.namespace(), 3), -150);
        assert_eq!(
            query_raw(s.namespace(), 4),
            150,
            "class normalization is volume-independent"
        );
        assert_eq!(query_raw(s.namespace(), 5), 150);
        assert_eq!(
            query_raw(s.namespace(), 6),
            139,
            "positive truncation toward zero"
        );
        assert_eq!(
            query_raw(s.namespace(), 7),
            -20,
            "negative truncation toward zero"
        );
        assert_eq!(query_raw(s.namespace(), 99), 0);
    }

    #[test]
    fn min_samples_threshold_gates_nonzero_bias() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store_limits("mins", 1000, 150, 60);
        // 999 outcomes (all abuse@score 100): below the threshold -> exactly
        // 0 (the state is still seeded: bias_mp = 0, ts = Redis now).
        fill(&s, 1, 100, 0, 999, now());
        assert_eq!(s.bias_for_scope(1, now()), 0);
        // The 1000th sample (record_at invalidates the cache) unlocks the
        // bias: raw 360 -> clamped 150, but the proportional allowance
        // started at the seeded ts: with mpm 60 the allowed points equal
        // the real elapsed seconds, so the query serves exactly
        // trunc(elapsed_ms / 1000) points.
        fill(&s, 1, 100, 0, 1, now());
        let mut conn = client().get_connection().expect("connection");
        let t0 = redis_time_ms(&mut conn);
        std::thread::sleep(Duration::from_millis(2500));
        let t1 = redis_time_ms(&mut conn);
        let expected = (t1 - t0) / 1000;
        assert!((2..=3).contains(&expected), "sanity: expected {expected}");
        assert_eq!(
            store_on(s.namespace(), 1000, 150, 60).bias_for_scope(1, now()),
            expected as i32,
            "the allowance is proportional to the REAL elapsed time"
        );
    }

    #[test]
    fn bias_rate_of_change_clamped_proportionally() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store_limits("roc", 1, 150, 60);
        let ns = s.namespace().to_string();
        let mut conn = client().get_connection().expect("connection");

        // Abuse predicted at LOW score (raw target +150): the first call
        // seeds bias_mp = 0 / ts = now, so the raw is clamped against a
        // zero allowance; with mpm 60 the bias then grows at exactly one
        // point per real second — never an instant jump to 150.
        fill(&s, 21, 100, 0, 10, now());
        assert_eq!(s.bias_for_scope(21, now()), 0);
        let t0 = redis_time_ms(&mut conn);
        std::thread::sleep(Duration::from_millis(2500));
        let t1 = redis_time_ms(&mut conn);
        let expected = (t1 - t0) / 1000;
        assert_eq!(
            store_on(&ns, 1, 150, 60).bias_for_scope(21, now()),
            expected as i32,
            "the allowance must bind: raw 150, served ~2-3 points"
        );

        // Legit traffic predicted at HIGH score (10 legit@900 + 10
        // abuse@900 -> fp 900, fn 100 -> target -140): the same rate moves
        // DOWN, proving the direction follows the raw target.
        fill(&s, 22, 900, 10, 0, now());
        fill(&s, 22, 900, 0, 10, now());
        assert_eq!(s.bias_for_scope(22, now()), 0);
        let t0 = redis_time_ms(&mut conn);
        std::thread::sleep(Duration::from_millis(2500));
        let t1 = redis_time_ms(&mut conn);
        let expected = (t1 - t0) / 1000;
        assert_eq!(
            store_on(&ns, 1, 150, 60).bias_for_scope(22, now()),
            -expected as i32,
            "the allowance moves toward the target (-140), not toward +150"
        );
    }

    #[test]
    fn below_threshold_decays_toward_zero_at_allowed_rate() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store_limits("bthr", 1, 150, 60);
        let ns = s.namespace().to_string();
        let mut conn = client().get_connection().expect("connection");
        fill(&s, 31, 100, 0, 10, now());

        // Step 1: above the threshold (min 1), the bias accumulates at the
        // allowed rate: expected = trunc(elapsed_ms / 1000) points.
        assert_eq!(s.bias_for_scope(31, now()), 0);
        let t0 = redis_time_ms(&mut conn);
        std::thread::sleep(Duration::from_millis(2500));
        let t1 = redis_time_ms(&mut conn);
        let prev = (t1 - t0) / 1000;
        assert_eq!(
            store_on(&ns, 1, 150, 60).bias_for_scope(31, now()),
            prev as i32,
            "above the threshold the bias accumulates at the allowed rate"
        );

        // Step 2: a below-threshold VIEW (min 1_000_000) back-to-back: the
        // TARGET is 0, but the stored bias is UNCHANGED (the elapsed
        // allowance is ~0) — it decays through the rate limiter, never an
        // instant snap to 0.
        let below = store_on(&ns, 1_000_000, 150, 60);
        let t2 = redis_time_ms(&mut conn);
        let bias = below.bias_for_scope(31, now());
        let elapsed2 = t2 - t1;
        assert!(
            i64::from(bias) >= prev - 1 && i64::from(bias) <= prev,
            "below the threshold the stored bias must hold ~prev ({prev}), got {bias} (elapsed {elapsed2} ms)"
        );
        assert!(
            bias > 0,
            "below the threshold the bias must not snap to 0 instantly"
        );

        // Step 3: ts is refreshed on every call (below threshold too), and
        // a ~2.5 s allowance exceeds the remaining stored bias: the decay
        // closes onto the 0 target.
        std::thread::sleep(Duration::from_millis(2500));
        let t3 = redis_time_ms(&mut conn);
        assert_eq!(
            store_on(&ns, 1_000_000, 150, 60).bias_for_scope(31, now()),
            0,
            "the decay reaches the 0 target once the allowance exceeds the stored bias"
        );

        // Step 4: back above the threshold the bias resumes from 0 through
        // the same rate limiter (the allowance counts only from the ts the
        // step-3 call refreshed: ~2.5 s of real elapsed).
        std::thread::sleep(Duration::from_millis(2500));
        let t4 = redis_time_ms(&mut conn);
        let expected = (t4 - t3) / 1000;
        assert_eq!(
            store_on(&ns, 1, 150, 60).bias_for_scope(31, now()),
            expected as i32,
            "above the threshold the bias resumes at the allowed rate"
        );
    }

    #[test]
    fn bias_cache_hits_make_zero_redis_calls_and_single_lua_invocation() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store_limits("cache", 1, 150, 100_000);
        let ns = s.namespace().to_string();
        fill(&s, 7, 100, 0, 10, now());
        assert_eq!(s.bias_for_scope(7, now()), 0);
        // Exactly ONE canonical script invocation over 24 bucket keys + the
        // state key + the two sample counters (the old hot path issued TWO
        // scripts).
        assert_eq!(s.script_calls(), 1);

        // Cache hit: the second call issues ZERO scripts.
        assert_eq!(s.bias_for_scope(7, now()), 0);
        assert_eq!(s.script_calls(), 1);

        // A fresh store (cold cache) re-aggregates: after a short real
        // sleep the proportional allowance (mpm 100_000) is huge, so the
        // raw 150 is served in full.
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(query_raw(&ns, 7), 150);

        // Behavior: delete every bucket; the cache still serves 0 while a
        // fresh store on the same namespace (cold cache) re-aggregates to 0
        // (no samples left).
        let mut conn = client().get_connection().expect("connection");
        let pattern = format!("{{kiwi:{ns}}}:cal:7:*");
        let keys: Vec<String> = conn.scan_match(pattern).expect("scan").collect();
        assert!(!keys.is_empty(), "scan must find the hourly buckets");
        conn.del::<_, ()>(keys).expect("del");
        // The rate-limit state must be cleared too: below the threshold the
        // stored bias now decays toward 0 at the allowed rate instead of
        // snapping, so a surviving state key would keep the old value.
        conn.del::<_, ()>(format!("{{kiwi:{ns}}}:cal:state:7"))
            .expect("del state");
        assert_eq!(
            s.bias_for_scope(7, now()),
            0,
            "cache serves without Redis reads"
        );
        assert_eq!(
            query_raw(&ns, 7),
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
        // 90 legit@100 + 10 abuse@100 -> fp_mean 100, fn_mean 900 -> error
        // 1700 -> raw 340 -> clamped 150.
        fill(&s, 7, 100, 90, 10, now());
        assert_eq!(s.bias_for_scope(7, now()), 0);
        assert_eq!(s.script_calls(), 1);
        // Cache hit: no backend call.
        assert_eq!(s.bias_for_scope(7, now()), 0);
        assert_eq!(s.script_calls(), 1);

        // A fresh outcome (record_at) drops the scope's cache entry: the
        // next call re-invokes the script. 90 legit@900 are added to the
        // SAME hour: fp_mean = (9000 + 81000) / 180 = 500, fn_mean 900 ->
        // error 1300 -> raw 260 -> clamped 150 (after the sleep the huge
        // allowance serves it in full).
        for _ in 0..90 {
            s.record_at(7, 900, true, now()).unwrap();
        }
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(s.bias_for_scope(7, now()), 150);
        assert_eq!(
            s.script_calls(),
            2,
            "record() must invalidate the cached bias"
        );
    }

    #[test]
    fn confirm_invalidates_the_cached_bias_and_feeds_the_bias() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store_full(
            "cinv",
            1,
            150,
            100_000,
            300,
            SamplingMode::Complete,
            0,
            0.80,
            1.0,
            2.0,
        );
        let ns = s.namespace().to_string();
        fill(&s, 7, 100, 0, 10, now());
        assert_eq!(s.bias_for_scope(7, now()), 0);
        assert_eq!(s.script_calls(), 1);
        // Cache hit: no backend call.
        assert_eq!(s.bias_for_scope(7, now()), 0);
        assert_eq!(s.script_calls(), 1);

        // A confirm on the same scope drops the cache entry: the next call
        // MUST re-invoke the script, which serves the aggregate in full
        // (10 abuse@100 -> 150; the state was seeded at the first call, so
        // after the sleep the allowance is huge).
        s.record_receipt("c-1", 7, 4, RiskAction::Sha16, 100, true)
            .unwrap();
        assert_eq!(s.confirm_outcome("c-1", false, None).unwrap(), 1);
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(s.bias_for_scope(7, now()), 150);
        assert_eq!(
            s.script_calls(),
            2,
            "confirm_outcome must invalidate the cached bias"
        );

        // The confirmed exact score feeds the bias in the CURRENT hour: a
        // fresh scope (fresh state) seeded at the real now, queried after a
        // real sleep by the same store (the confirm already dropped the
        // cache) -> full raw 180 -> clamped 150.
        s.record_receipt("c-2", 8, 4, RiskAction::Sha16, 100, true)
            .unwrap();
        assert_eq!(s.confirm_outcome("c-2", false, None).unwrap(), 1);
        assert_eq!(s.bias_for_scope(8, now()), 0, "first call seeds the state");
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(
            store_full_on(
                &ns,
                1,
                150,
                100_000,
                300,
                SamplingMode::Complete,
                0,
                0.80,
                1.0,
                2.0,
            )
            .bias_for_scope(8, now()),
            150,
            "the confirmed abuse@100 must push the bias up"
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
        let ns = s.namespace().to_string();
        let t = now();
        // Same scope, three hours: 30 abuse@100 -> fn_mean 900 -> raw 360
        // -> clamped 150 (the first call seeds; a cold store after a real
        // sleep serves the raw in full).
        fill(&s, 1, 100, 0, 10, t);
        fill(&s, 1, 100, 0, 10, t - 3_600_000);
        fill(&s, 1, 100, 0, 10, t - 7_200_000);
        assert_eq!(s.bias_for_scope(1, now()), 0);
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(query_raw(&ns, 1), 150);

        // Buckets older than 24 hours are out of the window (the record_at
        // fills invalidate the cache, so this re-aggregates; the total is
        // still 30 -> raw 150).
        fill(&s, 1, 100, 0, 100, t - 25 * 3_600_000);
        assert_eq!(query_raw(&ns, 1), 150);
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
        s.record_receipt("decision-ttl", 7, 4, RiskAction::Argon16, 900, true)
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
        d.record_receipt("decision-def", 7, 4, RiskAction::Argon16, 900, true)
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
    fn receipts_carry_score_and_sampled() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store("rcarries");
        s.record_receipt("decision-1", 7, 4, RiskAction::Argon16, 900, true)
            .unwrap();
        s.record_receipt("decision-2", 8, 9, RiskAction::Deny, 1000, false)
            .unwrap();
        let mut conn = client().get_connection().expect("connection");
        let json1: String = conn
            .get(receipt_key(s.namespace(), "decision-1"))
            .expect("get");
        let value: serde_json::Value = serde_json::from_str(&json1).expect("json");
        assert_eq!(value["scope"], 7);
        assert_eq!(value["band"], 4);
        assert_eq!(value["action"], "argon16");
        assert_eq!(value["score"], 900);
        assert_eq!(value["sampled"], 1);
        let json2: String = conn
            .get(receipt_key(s.namespace(), "decision-2"))
            .expect("get");
        let value: serde_json::Value = serde_json::from_str(&json2).expect("json");
        assert_eq!(value["score"], 1000);
        assert_eq!(value["sampled"], 0);
    }

    #[test]
    fn complete_mode_records_every_confirm() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store_mode("complete", SamplingMode::Complete, 0);
        assert!(s.sample(), "Complete mode always samples");
        s.record_receipt("d-1", 7, 4, RiskAction::Argon16, 900, s.sample())
            .unwrap();
        assert_eq!(s.confirm_outcome("d-1", true, None).unwrap(), 1);
        let mut conn = client().get_connection().expect("connection");
        let key = bucket_key(s.namespace(), 7);
        assert_eq!(hget_f64(&mut conn, &key, "legit_count"), 1.0);
        assert_eq!(hget_f64(&mut conn, &key, "legit_score_sum"), 900.0);
        assert_eq!(hget_f64(&mut conn, &key, "abuse_count"), 0.0);
    }

    #[test]
    fn random_sample_discards_unsampled_confirms() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store_mode("rand", SamplingMode::RandomSample, 0);
        assert!(!s.sample(), "ppm 0 never samples");

        // Unsampled: consumed with status 2 (receipt deleted, NO bucket
        // fields, no resolved-counter increment) — a FIRST confirmation
        // that never enters calibration.
        s.record_receipt("d-unsampled", 7, 4, RiskAction::Argon16, 900, false)
            .unwrap();
        assert_eq!(
            s.confirm_outcome("d-unsampled", true, None).unwrap(),
            2,
            "an unsampled receipt must be consumed as status 2"
        );
        let mut conn = client().get_connection().expect("connection");
        let exists: i64 = redis::cmd("EXISTS")
            .arg(receipt_key(s.namespace(), "d-unsampled"))
            .query(&mut conn)
            .expect("exists");
        assert_eq!(exists, 0, "the discarded receipt must be deleted");
        let fields: Vec<(String, String)> =
            conn.hgetall(bucket_key(s.namespace(), 7)).expect("hgetall");
        assert!(
            fields.is_empty(),
            "a status-2 confirm must not touch the bucket"
        );
        let resolved: Option<i64> = redis::cmd("GET")
            .arg(sample_resolved_key(s.namespace()))
            .query(&mut conn)
            .expect("get");
        assert_eq!(
            resolved.unwrap_or(0),
            0,
            "a status-2 confirm must not resolve a sample"
        );

        // Sampled: recorded with status 1.
        s.record_receipt("d-sampled", 7, 4, RiskAction::Argon16, 900, true)
            .unwrap();
        assert_eq!(s.confirm_outcome("d-sampled", true, None).unwrap(), 1);
        assert_eq!(
            hget_f64(&mut conn, &bucket_key(s.namespace(), 7), "legit_count"),
            1.0
        );
    }

    #[test]
    fn weighted_mode_applies_the_weight() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store_mode("weighted", SamplingMode::Weighted, 0);
        assert!(s.sample(), "Weighted mode always samples");
        s.record_receipt("d-w", 7, 4, RiskAction::Argon16, 500, s.sample())
            .unwrap();
        // Inverse sampling probability 10: the outcome counts 10-fold.
        assert_eq!(s.confirm_outcome("d-w", true, Some(10.0)).unwrap(), 1);
        let mut conn = client().get_connection().expect("connection");
        let key = bucket_key(s.namespace(), 7);
        assert_eq!(hget_f64(&mut conn, &key, "legit_count"), 10.0);
        assert_eq!(hget_f64(&mut conn, &key, "legit_score_sum"), 5000.0);
    }

    #[test]
    fn confirm_outcome_records_and_consumes_once() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store_mode("confirm", SamplingMode::Complete, 0);
        s.record_receipt("decision-1", 7, 4, RiskAction::Argon16, 900, true)
            .unwrap();
        assert_eq!(
            s.confirm_outcome("decision-1", true, None).unwrap(),
            1,
            "first confirmation records calibration"
        );

        // Consumed exactly once: the second confirm is status 0.
        assert_eq!(s.confirm_outcome("decision-1", true, None).unwrap(), 0);

        // Unknown id -> status 0 (never errors).
        assert_eq!(
            s.confirm_outcome("decision-missing", true, None).unwrap(),
            0
        );

        let mut conn = client().get_connection().expect("connection");
        let exists: i64 = redis::cmd("EXISTS")
            .arg(receipt_key(s.namespace(), "decision-1"))
            .query(&mut conn)
            .expect("exists");
        assert_eq!(exists, 0, "the consumed receipt must be deleted");
        let key = bucket_key(s.namespace(), 7);
        assert_eq!(hget_f64(&mut conn, &key, "legit_count"), 1.0);
        assert_eq!(hget_f64(&mut conn, &key, "legit_score_sum"), 900.0);
    }

    #[test]
    fn concurrent_double_confirm_records_once() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let ns = unique_namespace("race");
        let make = || {
            store_full_on(
                &ns,
                1,
                150,
                10,
                300,
                SamplingMode::Complete,
                0,
                0.80,
                1.0,
                2.0,
            )
        };
        let s = make();
        s.record_receipt("race-1", 7, 4, RiskAction::Sha16, 500, true)
            .unwrap();
        // Two INDEPENDENT stores on the same namespace: no shared
        // connection, so the race exercises the script's atomicity (the
        // GET+DEL+increment has no crash window; the loser sees no receipt
        // and reports status 0).
        let a = make();
        let b = make();
        std::thread::scope(|scope| {
            let ha = scope.spawn(move || a.confirm_outcome("race-1", true, None));
            let hb = scope.spawn(move || b.confirm_outcome("race-1", true, None));
            let ra = ha.join().expect("thread").expect("confirm");
            let rb = hb.join().expect("thread").expect("confirm");
            let recorded = [ra, rb].iter().filter(|r| **r == 1).count();
            assert_eq!(recorded, 1, "exactly one concurrent confirm may record");
        });
        let mut conn = client().get_connection().expect("connection");
        let key = bucket_key(&ns, 7);
        assert_eq!(hget_f64(&mut conn, &key, "legit_count"), 1.0);
        assert_eq!(hget_f64(&mut conn, &key, "legit_score_sum"), 500.0);
    }

    #[test]
    fn sample_respects_sampling_probability() {
        // Pure logic: no Redis connection is ever made.
        let client = redis::Client::open("redis://127.0.0.1:6399").expect("url parses");
        let make = |mode: SamplingMode, ppm: u32| {
            RedisCalibrationStore::with_options(
                client.clone(),
                "smp",
                1,
                150,
                10,
                300,
                mode,
                ppm,
                0.80,
                1.0,
                2.0,
            )
        };
        // Wire ints shared with PHP (confirm.lua ARGV[1]).
        assert_eq!(SamplingMode::Complete.as_int(), 0);
        assert_eq!(SamplingMode::RandomSample.as_int(), 1);
        assert_eq!(SamplingMode::Weighted.as_int(), 2);
        // Complete/Weighted always sample; RandomSample follows the ppm.
        assert!(make(SamplingMode::Complete, 0).sample());
        assert!(make(SamplingMode::Weighted, 0).sample());
        assert!(!make(SamplingMode::RandomSample, 0).sample());
        assert!(make(SamplingMode::RandomSample, 1_000_000).sample());
    }

    #[test]
    fn confirm_validates_arguments_before_deleting_the_receipt() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store_mode("cval", SamplingMode::Complete, 0);
        let ns = s.namespace().to_string();
        let mut conn = client().get_connection().expect("connection");
        let bucket = bucket_key(&ns, 7);
        let resolved = sample_resolved_key(&ns);
        let script = redis::Script::new(CONFIRM_LUA);

        // Invalid mode: the script must error BEFORE the receipt is
        // deleted.
        s.record_receipt("cv-1", 7, 4, RiskAction::Argon16, 900, true)
            .unwrap();
        let mut inv = script.prepare_invoke();
        inv.key(receipt_key(&ns, "cv-1"));
        inv.key(&bucket);
        inv.key(&resolved);
        inv.arg("9");
        inv.arg("1.0");
        inv.arg("1");
        inv.arg("172800");
        assert!(
            inv.invoke::<i64>(&mut conn).is_err(),
            "an invalid mode must be an error reply"
        );
        let exists: i64 = redis::cmd("EXISTS")
            .arg(receipt_key(&ns, "cv-1"))
            .query(&mut conn)
            .expect("exists");
        assert_eq!(
            exists, 1,
            "a validation failure must not delete the receipt"
        );

        // Invalid weight in weighted mode: 0 is rejected.
        s.record_receipt("cv-2", 7, 4, RiskAction::Argon16, 900, true)
            .unwrap();
        let mut inv = script.prepare_invoke();
        inv.key(receipt_key(&ns, "cv-2"));
        inv.key(&bucket);
        inv.key(&resolved);
        inv.arg("2");
        inv.arg("0");
        inv.arg("1");
        inv.arg("172800");
        assert!(inv.invoke::<i64>(&mut conn).is_err());
        let exists: i64 = redis::cmd("EXISTS")
            .arg(receipt_key(&ns, "cv-2"))
            .query(&mut conn)
            .expect("exists");
        assert_eq!(exists, 1);

        // Non-numeric weight is rejected too.
        s.record_receipt("cv-3", 7, 4, RiskAction::Argon16, 900, true)
            .unwrap();
        let mut inv = script.prepare_invoke();
        inv.key(receipt_key(&ns, "cv-3"));
        inv.key(&bucket);
        inv.key(&resolved);
        inv.arg("2");
        inv.arg("abc");
        inv.arg("1");
        inv.arg("172800");
        assert!(inv.invoke::<i64>(&mut conn).is_err());
        let exists: i64 = redis::cmd("EXISTS")
            .arg(receipt_key(&ns, "cv-3"))
            .query(&mut conn)
            .expect("exists");
        assert_eq!(exists, 1);

        // The surviving receipt still confirms normally afterwards.
        assert_eq!(s.confirm_outcome("cv-1", true, None).unwrap(), 1);
        assert_eq!(hget_f64(&mut conn, &bucket, "legit_count"), 1.0);
    }

    #[test]
    fn resolution_gate_holds_until_ratio_met() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store_full(
            "gate",
            10,
            150,
            100_000,
            300,
            SamplingMode::RandomSample,
            0,
            0.80,
            1.0,
            2.0,
        );
        let ns = s.namespace().to_string();
        let mut conn = client().get_connection().expect("connection");
        // 10 abuse@100 -> raw 360 -> clamped 150 once the gate opens.
        fill(&s, 9, 100, 0, 10, now());
        for _ in 0..10 {
            s.mark_sampled().unwrap();
        }
        assert_eq!(s.bias_for_scope(9, now()), 0, "first call seeds the state");
        let total: i64 = redis::cmd("GET")
            .arg(sample_total_key(&ns))
            .query(&mut conn)
            .expect("get");
        assert_eq!(total, 10, "mark_sampled must INCR the total counter");

        // 7 sampled confirms: resolved 7 < total 10 * 0.80 = 8 -> the gate
        // holds the target at 0 even after a real sleep.
        for i in 0..7 {
            let id = format!("g-{i}");
            s.record_receipt(&id, 9, 4, RiskAction::Argon16, 100, true)
                .unwrap();
            assert_eq!(
                s.confirm_outcome(&id, false, None).unwrap(),
                1,
                "sampled confirms record calibration AND the resolved counter"
            );
        }
        let resolved: i64 = redis::cmd("GET")
            .arg(sample_resolved_key(&ns))
            .query(&mut conn)
            .expect("get");
        assert_eq!(resolved, 7);
        // The gate HOLD is elapsed-independent (the target is 0), so this
        // query also refreshes the rate-limit ts...
        let hold = store_full_on(
            &ns,
            10,
            150,
            100_000,
            300,
            SamplingMode::RandomSample,
            0,
            0.80,
            1.0,
            2.0,
        );
        assert_eq!(
            hold.bias_for_scope(9, now()),
            0,
            "resolved/total below the ratio must suspend the bias"
        );

        // The 8th confirm reaches resolved/total = 0.80: the gate opens.
        s.record_receipt("g-7", 9, 4, RiskAction::Argon16, 100, true)
            .unwrap();
        assert_eq!(s.confirm_outcome("g-7", false, None).unwrap(), 1);
        let resolved: i64 = redis::cmd("GET")
            .arg(sample_resolved_key(&ns))
            .query(&mut conn)
            .expect("get");
        assert_eq!(resolved, 8);
        // ...and only then a real sleep gives the proportional allowance
        // real elapsed time: the raw 150 is served in full.
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(
            store_full_on(
                &ns,
                10,
                150,
                100_000,
                300,
                SamplingMode::RandomSample,
                0,
                0.80,
                1.0,
                2.0,
            )
            .bias_for_scope(9, now()),
            150,
            "the bias is released once resolved/total >= minimum_resolution_ratio"
        );
    }

    #[test]
    fn resolution_gate_skips_below_min_samples() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store_full(
            "gate2",
            10,
            150,
            100_000,
            300,
            SamplingMode::RandomSample,
            0,
            0.80,
            1.0,
            2.0,
        );
        let ns = s.namespace().to_string();
        // 10 abuse@100 -> raw 150 target.
        fill(&s, 10, 100, 0, 10, now());
        // Only 5 sampled decisions: the total counter stays BELOW
        // min_samples, so the resolution gate is skipped entirely.
        for _ in 0..5 {
            s.mark_sampled().unwrap();
        }
        assert_eq!(s.bias_for_scope(10, now()), 0, "first call seeds the state");
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(
            store_full_on(
                &ns,
                10,
                150,
                100_000,
                300,
                SamplingMode::RandomSample,
                0,
                0.80,
                1.0,
                2.0,
            )
            .bias_for_scope(10, now()),
            150,
            "total < min_samples must skip the resolution gate"
        );
    }

    #[test]
    fn cost_knobs_change_the_bias() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        // Default costs (fp 1.0, fn 2.0): 10 legit@250 + 10 abuse@900 ->
        // error = 100*2 - 250*1 = -50 -> raw -10.
        let d = store_full(
            "costd",
            1,
            150,
            100_000,
            300,
            SamplingMode::Complete,
            0,
            0.80,
            1.0,
            2.0,
        );
        fill(&d, 1, 250, 10, 0, now());
        fill(&d, 1, 900, 0, 10, now());
        // fn-heavy pricing (fp 3.0, fn 1.0): the SAME data -> error =
        // 100*1 - 250*3 = -650 -> raw -130 (false positives cost 3x).
        let c = store_full(
            "costc",
            1,
            150,
            100_000,
            300,
            SamplingMode::Complete,
            0,
            0.80,
            3.0,
            1.0,
        );
        fill(&c, 2, 250, 10, 0, now());
        fill(&c, 2, 900, 0, 10, now());
        // Equal costs (1.0/1.0): a perfectly separating classifier
        // (legit@100 + abuse@900) contributes EXACTLY zero pressure.
        let e = store_full(
            "coste",
            1,
            150,
            100_000,
            300,
            SamplingMode::Complete,
            0,
            0.80,
            1.0,
            1.0,
        );
        fill(&e, 3, 100, 10, 0, now());
        fill(&e, 3, 900, 0, 10, now());

        assert_eq!(d.bias_for_scope(1, now()), 0, "seeds");
        assert_eq!(c.bias_for_scope(2, now()), 0, "seeds");
        assert_eq!(e.bias_for_scope(3, now()), 0, "seeds");
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(
            store_full_on(
                d.namespace(),
                1,
                150,
                100_000,
                300,
                SamplingMode::Complete,
                0,
                0.80,
                1.0,
                2.0
            )
            .bias_for_scope(1, now()),
            -10,
            "default costs"
        );
        assert_eq!(
            store_full_on(
                c.namespace(),
                1,
                150,
                100_000,
                300,
                SamplingMode::Complete,
                0,
                0.80,
                3.0,
                1.0
            )
            .bias_for_scope(2, now()),
            -130,
            "fp 3x / fn 1x"
        );
        assert_eq!(
            store_full_on(
                e.namespace(),
                1,
                150,
                100_000,
                300,
                SamplingMode::Complete,
                0,
                0.80,
                1.0,
                1.0
            )
            .bias_for_scope(3, now()),
            0,
            "equal costs zero a balanced separator"
        );
    }

    #[test]
    fn sampled_counters_follow_the_mode() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let mut conn = client().get_connection().expect("connection");

        // Complete mode: mark_sampled never touches the counters.
        let c = store_mode("totc", SamplingMode::Complete, 0);
        c.mark_sampled().unwrap();
        c.mark_sampled().unwrap();
        let total: Option<i64> = redis::cmd("GET")
            .arg(sample_total_key(c.namespace()))
            .query(&mut conn)
            .expect("get");
        assert_eq!(
            total.unwrap_or(0),
            0,
            "complete mode must not INCR the total"
        );

        // Random-sample mode: mark_sampled INCRs the total only; a sampled
        // confirm INCRs the resolved counter; an unsampled confirm (status
        // 2) consumes WITHOUT resolving.
        let r = store_mode("totr", SamplingMode::RandomSample, 0);
        for _ in 0..5 {
            r.mark_sampled().unwrap();
        }
        let total: i64 = redis::cmd("GET")
            .arg(sample_total_key(r.namespace()))
            .query(&mut conn)
            .expect("get");
        assert_eq!(total, 5);
        let resolved: Option<i64> = redis::cmd("GET")
            .arg(sample_resolved_key(r.namespace()))
            .query(&mut conn)
            .expect("get");
        assert_eq!(
            resolved.unwrap_or(0),
            0,
            "mark_sampled must not INCR the resolved counter"
        );

        r.record_receipt("r-1", 7, 4, RiskAction::Argon16, 900, true)
            .unwrap();
        assert_eq!(r.confirm_outcome("r-1", true, None).unwrap(), 1);
        let resolved: i64 = redis::cmd("GET")
            .arg(sample_resolved_key(r.namespace()))
            .query(&mut conn)
            .expect("get");
        assert_eq!(resolved, 1, "a sampled confirmation resolves the sample");

        r.record_receipt("r-2", 7, 4, RiskAction::Argon16, 900, false)
            .unwrap();
        assert_eq!(r.confirm_outcome("r-2", true, None).unwrap(), 2);
        let resolved: i64 = redis::cmd("GET")
            .arg(sample_resolved_key(r.namespace()))
            .query(&mut conn)
            .expect("get");
        assert_eq!(
            resolved, 1,
            "an unsampled confirmation (status 2) must not resolve"
        );

        // Weighted mode: no-op like complete.
        let w = store_mode("totw", SamplingMode::Weighted, 0);
        w.mark_sampled().unwrap();
        let total: Option<i64> = redis::cmd("GET")
            .arg(sample_total_key(w.namespace()))
            .query(&mut conn)
            .expect("get");
        assert_eq!(
            total.unwrap_or(0),
            0,
            "weighted mode must not INCR the total"
        );
    }
}
