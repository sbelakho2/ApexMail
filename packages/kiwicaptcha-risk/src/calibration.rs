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
//! EXACT SCORE calibration (not prevalence adaptation): each confirmed
//! observation carries its original risk score (0..1000):
//!
//! ```text
//! fn_pressure = Σ abuse × 1000 − Σ abuse_scores   (abuse_count × 1000 − abuse_score_sum)
//! fp_pressure = Σ legit_scores                    (legit_score_sum)
//! total       = legit_count + abuse_count          (summed over the last 24 buckets)
//! raw         = (fn_pressure − fp_pressure) × 2 / (total × 10)
//! bias        = clamp(raw, −max_adjustment, +max_adjustment)   (default ±150)
//! ```
//!
//! A perfectly separating classifier (legit at low scores, abuse at high
//! scores) contributes ~zero pressure and stays near bias 0; abuse
//! predicted at low risk pushes the bias UP, legitimate traffic predicted
//! at high risk pushes it DOWN. The target is 0 below `min_samples`
//! (default 1000).
//!
//! The rate limiter is PROPORTIONAL to elapsed time and applies to the
//! PATH, not just the target: internal bias is stored in MILLI-POINTS at
//! `{kiwi:<ns>}:cal:state:<scope>` (1 point = 1000 units) and
//! `allowed = max_change_per_minute × 1000 × elapsed_ms / 60000`. The
//! FIRST call ever seeds bias_mp = 0 / ts = now BEFORE the sample threshold
//! is evaluated; `ts` is refreshed on EVERY call (below threshold too) so a
//! long quiet period cannot accumulate movement allowance; below the
//! threshold the stored bias still moves toward 0 through the same rate
//! limiter (never an instant snap) — all atomically in the one script.
//!
//! Confirmation is ATOMIC via `resources/confirm.lua` (one script
//! invocation: GET receipt → DEL → HINCRBYFLOAT into the bucket → EXPIRE):
//! there is no crash window between consuming the receipt and recording
//! the outcome. In random-sample mode an unsampled decision is discarded
//! (deleted, never counted) so a label can never select itself into the
//! calibration population; weighted mode applies the caller's inverse
//! sampling probability as a float weight.
//!
//! `bias_for_scope` caches the per-scope result in-process for 30 s (bounded
//! to ~1024 scopes, oldest evicted): cache hits make ZERO Redis calls (0 is
//! cached too). Recording a confirmed outcome invalidates the scope's entry
//! so the next assessment re-aggregates. The engine applies
//! `clamp(base + bias, 0, 1000)` BEFORE band mapping.

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
    /// `Ok(Some(scope))` when the outcome was recorded, `Ok(None)` when the
    /// receipt is missing/already consumed/discarded. `weight` is the
    /// HINCRBYFLOAT weight (default 1.0; the inverse sampling probability
    /// in weighted mode). Any backend failure is an error (the engine
    /// treats calibration as best-effort).
    fn confirm_outcome(
        &self,
        decision_id: &str,
        legitimate: bool,
        weight: Option<f64>,
    ) -> Result<Option<u32>, CalibrationError>;

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
        )
    }

    /// Builds a store with every calibration knob explicit: the safety
    /// limits, the receipt lifetime and the confirmation sampling strategy
    /// (`mode` + `sampling_probability_ppm`, default RandomSample / 100_000
    /// — preserved by the [`RedisCalibrationStore::with_limits`] and
    /// [`RedisCalibrationStore::with_receipt_ttl`] shorthands).
    ///
    /// # Panics
    ///
    /// Panics if the namespace is empty or contains `{`/`}`, if
    /// `min_samples < 1` / `max_adjustment < 0` / `max_change_per_minute < 0`,
    /// or if `receipt_ttl_secs < 1`.
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
            mode,
            sampling_probability_ppm,
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
    ) -> Result<Option<u32>, CalibrationError> {
        let receipt_key = self.receipt_key(decision_id);
        let mut guard = self.connection()?;
        let conn = guard.as_mut().ok_or_else(|| {
            CalibrationError::Backend("calibration connection vanished".to_string())
        })?;

        // Key discovery: the bucket key needs the receipt's scope, which
        // only the receipt itself carries. The pre-read GET is
        // NON-destructive — the confirm script re-checks the receipt under
        // the same key, so a concurrent consumption simply yields 0 (the
        // outcome is recorded exactly once) and a receipt deleted in
        // between is a no-op, never a double record.
        let raw: Option<String> = redis::cmd("GET")
            .arg(&receipt_key)
            .query(conn)
            .map_err(backend)?;
        let Some(raw) = raw else {
            return Ok(None);
        };
        let value: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(value) => value,
            Err(_) => return Ok(None), // malformed: script would discard it
        };
        let Some(scope) = value.get("scope").and_then(|v| v.as_u64()) else {
            return Ok(None);
        };
        let Ok(scope) = u32::try_from(scope) else {
            return Ok(None);
        };
        let bucket_key = self.bucket_key(scope, now_ms() / 3_600_000);

        // ONE canonical script invocation: GET receipt -> DEL -> (discard
        // or) HINCRBYFLOAT the exact score into the bucket + EXPIRE. ARGV =
        // mode int, weight (float; default 1.0), legitimate 1/0,
        // bucket TTL.
        let mut invoke = self.confirm_script.prepare_invoke();
        invoke.key(receipt_key.as_str());
        invoke.key(bucket_key.as_str());
        invoke.arg(self.mode.as_int().to_string());
        invoke.arg(weight.unwrap_or(1.0).to_string());
        invoke.arg(if legitimate { "1" } else { "0" });
        invoke.arg(Self::BUCKET_EXPIRE_S.to_string());
        let recorded: i64 = invoke.invoke(conn).map_err(backend)?;
        if recorded != 0 {
            // A recorded outcome invalidates the scope's cached bias so the
            // next assessment re-aggregates (same as the old record path).
            self.cache
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .entries
                .remove(&scope);
        }
        Ok(if recorded == 0 {
            None
        } else {
            Some(recorded as u32)
        })
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

    /// A store in an explicit sampling mode on a fresh namespace.
    fn store_mode(prefix: &str, mode: SamplingMode, ppm: u32) -> RedisCalibrationStore {
        RedisCalibrationStore::with_options(
            client(),
            &unique_namespace(prefix),
            1,
            150,
            10,
            300,
            mode,
            ppm,
        )
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

    #[test]
    fn bias_formula_is_exact_score_sensitive() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        // Huge max_change_per_minute: the proportional allowance never binds,
        // so the raw formula is observable. Every scope's FIRST call seeds
        // the state (bias_mp = 0, ts = now) and returns 0; one minute later
        // the raw value is reached in full.
        let s = store_limits("bias", 1, 150, 100_000);

        // Perfect separator: legit predicted at score 100 (fp = 10*100 =
        // 1000) + abuse predicted at score 900 (fn = 10*1000 - 10*900 =
        // 1000) -> exactly zero pressure on both sides -> bias stays ~0.
        fill(&s, 1, 100, 10, 0, T0);
        fill(&s, 1, 900, 0, 10, T0);
        assert_eq!(s.bias_for_scope(1, T0), 0, "first call seeds the state");
        assert_eq!(
            store_on(s.namespace(), 1, 150, 100_000).bias_for_scope(1, T0 + 60_000),
            0,
            "a perfectly separating classifier contributes no bias"
        );

        // Abuse predicted at LOW score (100): the engine under-predicted
        // the threat -> bias moves UP: fn = 10*1000 - 10*100 = 9000;
        // raw = (9000*2)/(10*10) = 180 -> clamped to max_adjustment 150.
        fill(&s, 2, 100, 0, 10, T0);
        assert_eq!(s.bias_for_scope(2, T0), 0);
        assert_eq!(
            store_on(s.namespace(), 1, 150, 100_000).bias_for_scope(2, T0 + 60_000),
            150
        );

        // Legit traffic predicted at HIGH score (900): the engine
        // over-predicted -> bias moves DOWN: fp = 10*900 = 9000 -> -180 ->
        // clamped -150.
        fill(&s, 3, 900, 10, 0, T0);
        assert_eq!(s.bias_for_scope(3, T0), 0);
        assert_eq!(
            store_on(s.namespace(), 1, 150, 100_000).bias_for_scope(3, T0 + 60_000),
            -150
        );

        // Mixed: 60 legit@900 (fp 54000) + 40 abuse@100 (fn 36000):
        // (-18000*2)/(100*10) = -36.
        fill(&s, 4, 900, 60, 0, T0);
        fill(&s, 4, 100, 0, 40, T0);
        assert_eq!(s.bias_for_scope(4, T0), 0);
        assert_eq!(
            store_on(s.namespace(), 1, 150, 100_000).bias_for_scope(4, T0 + 60_000),
            -36
        );

        // No samples -> 0.
        assert_eq!(s.bias_for_scope(99, T0), 0);
        assert_eq!(
            store_on(s.namespace(), 1, 150, 100_000).bias_for_scope(99, T0 + 60_000),
            0
        );

        // Truncation toward zero, byte-identical with PHP trunc_div:
        // abuse 2 @score 100 (fn 1800) / legit 1 @score 100 (fp 100)
        // (total 3): (1700*2)/(3*10) = 3400/30 = 113.33 -> 113.
        fill(&s, 5, 100, 1, 2, T0);
        assert_eq!(s.bias_for_scope(5, T0), 0);
        assert_eq!(
            store_on(s.namespace(), 1, 150, 100_000).bias_for_scope(5, T0 + 60_000),
            113
        );
    }

    #[test]
    fn min_samples_threshold_gates_nonzero_bias() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store_limits("mins", 1000, 150, 10);
        // 999 outcomes (all abuse@score 100): below the threshold -> exactly
        // 0, no bias (the state is still seeded: bias_mp = 0, ts = T0).
        fill(&s, 1, 100, 0, 999, T0);
        assert_eq!(s.bias_for_scope(1, T0), 0);
        // The 1000th sample (record_at invalidates the cache) unlocks the
        // bias: raw 180 -> clamped to max_adjustment 150, but the
        // proportional allowance started at the seeded ts (T0): one minute
        // later it admits exactly max_change_per_minute = 10 points.
        fill(&s, 1, 100, 0, 1, T0);
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
        fill(&s, 1, 100, 0, 10, T0);
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

        // Flip to legit predicted at HIGH score: 1000 legit@900 (fp 900000)
        // vs the 10 abuse@100 (fn 9000): raw = (-891000*2)/(1010*10) = -176
        // -> clamped -150, but the allowance from the last ts (T0 + 10 s)
        // over 50 s is 60 * 1000 * 50000 / 60000 = 50000 mp = 50 points:
        // 10 - 50 = -40 (truncating division, byte identical with PHP).
        fill(&s, 1, 900, 1000, 0, T0);
        assert_eq!(
            store_on(s.namespace(), 1, 150, 60).bias_for_scope(1, T0 + 60_000),
            -40
        );
    }

    #[test]
    fn below_threshold_decays_toward_zero_at_allowed_rate() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store_limits("bthr", 1, 150, 60);
        fill(&s, 1, 100, 0, 10, T0);
        assert_eq!(s.bias_for_scope(1, T0), 0);
        // 60 s after the seed the allowance is exactly 60 points: raw 150 ->
        // 60 (60 * 1000 * 60000 / 60000 milli-points).
        assert_eq!(
            store_on(s.namespace(), 1, 150, 60).bias_for_scope(1, T0 + 60_000),
            60
        );

        // A below-threshold VIEW of the same data: the TARGET is 0, but the
        // stored bias (60000 mp) only moves toward it through the rate
        // limiter — 30 s later it is 60 - 30 = 30, NOT an instant snap to 0.
        let low = store_on(s.namespace(), 1_000_000, 150, 60);
        assert_eq!(low.bias_for_scope(1, T0 + 90_000), 30);

        // ts is refreshed on EVERY call (below threshold too): the next call
        // 60 s later allows exactly 60 more points, closing the decay
        // (30 - 60 clamped to the 0 target).
        assert_eq!(
            store_on(s.namespace(), 1_000_000, 150, 60).bias_for_scope(1, T0 + 150_000),
            0
        );

        // Back above the threshold: the bias resumes from 0 and the
        // allowance counts ONLY from the refreshed ts (T0 + 150 s): over
        // 60 s that is 60 points -> final = min(150, 0 + 60) = 60.
        assert_eq!(
            store_on(s.namespace(), 1, 150, 60).bias_for_scope(1, T0 + 210_000),
            60
        );
    }

    #[test]
    fn bias_cache_hits_make_zero_redis_calls_and_single_lua_invocation() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store_limits("cache", 1, 150, 100_000);
        fill(&s, 7, 100, 0, 10, T0);
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
        // 10 abuse@100 (fn 9000) + 90 legit@100 (fp 9000) -> raw 0:
        // a 1:9 abuse:legit ratio at the same score balances the pressures.
        fill(&s, 7, 100, 90, 10, T0);
        assert_eq!(s.bias_for_scope(7, T0), 0);
        assert_eq!(s.script_calls(), 1);
        // Cache hit: no backend call.
        assert_eq!(s.bias_for_scope(7, T0 + 60_000), 0);
        assert_eq!(s.script_calls(), 1);

        // A fresh outcome (record_at) drops the scope's cache entry: the
        // next call re-invokes the script and serves the new aggregate.
        for _ in 0..90 {
            s.record_at(7, 900, true, T0 + 3_600_000).unwrap();
        }
        // 90 legit@100 + 90 legit@900 (fp 90000) vs 10 abuse@100 (fn 9000):
        // raw = (-81000*2)/(190*10) = -85.26 -> -85.
        assert_eq!(s.bias_for_scope(7, T0 + 3_600_000), -85);
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
        let s = RedisCalibrationStore::with_options(
            client(),
            &unique_namespace("cinv"),
            1,
            150,
            100_000,
            300,
            SamplingMode::Complete,
            0,
        );
        fill(&s, 7, 100, 0, 10, T0);
        assert_eq!(s.bias_for_scope(7, T0), 0);
        assert_eq!(s.script_calls(), 1);
        // Cache hit: no backend call.
        assert_eq!(s.bias_for_scope(7, T0 + 60_000), 0);
        assert_eq!(s.script_calls(), 1);

        // A confirm on the same scope drops the cache entry even though it
        // lands in the CURRENT hour (outside the T0 window): the next call
        // MUST re-invoke the script, which now serves the T0-window
        // aggregate in full (10 abuse@100 -> raw 180 -> clamped 150; the
        // state was seeded at T0, so the allowance is huge).
        s.record_receipt("c-1", 7, 4, RiskAction::Sha16, 100, true)
            .unwrap();
        assert_eq!(s.confirm_outcome("c-1", false, None).unwrap(), Some(7));
        assert_eq!(s.bias_for_scope(7, T0 + 60_000), 150);
        assert_eq!(
            s.script_calls(),
            2,
            "confirm_outcome must invalidate the cached bias"
        );

        // The confirmed exact score feeds the bias in the CURRENT window:
        // a fresh scope (fresh state) seeded at the real now, queried one
        // minute later by a COLD store (the in-process cache is
        // Instant-based, so synthetic deltas must cross store instances) ->
        // full raw 180 -> 150.
        let s2 = store_on(s.namespace(), 1, 150, 100_000);
        s2.record_receipt("c-2", 8, 4, RiskAction::Sha16, 100, true)
            .unwrap();
        assert_eq!(s2.confirm_outcome("c-2", false, None).unwrap(), Some(8));
        let now = now_ms();
        assert_eq!(
            store_on(s.namespace(), 1, 150, 100_000).bias_for_scope(8, now),
            0,
            "first call seeds the state"
        );
        assert_eq!(
            store_on(s.namespace(), 1, 150, 100_000).bias_for_scope(8, now + 60_000),
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
        // Same scope, three hours: 30 abuse@100 -> fn 27000 -> raw 180 ->
        // clamped 150 (the first call seeds; a cold store one minute later
        // serves the raw in full).
        fill(&s, 1, 100, 0, 10, T0);
        fill(&s, 1, 100, 0, 10, T0 - 3_600_000);
        fill(&s, 1, 100, 0, 10, T0 - 7_200_000);
        assert_eq!(s.bias_for_scope(1, T0), 0);
        assert_eq!(
            store_on(s.namespace(), 1, 150, 100_000).bias_for_scope(1, T0 + 60_000),
            150
        );

        // Buckets older than 24 hours are out of the window (the record_at
        // fills invalidate the cache, so this re-aggregates; the total is
        // still 30 -> raw 150).
        fill(&s, 1, 100, 0, 100, T0 - 25 * 3_600_000);
        assert_eq!(
            store_on(s.namespace(), 1, 150, 100_000).bias_for_scope(1, T0 + 120_000),
            150
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
        assert_eq!(s.confirm_outcome("d-1", true, None).unwrap(), Some(7));
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

        // Unsampled: discarded atomically (receipt deleted, no bucket
        // fields, returns None).
        s.record_receipt("d-unsampled", 7, 4, RiskAction::Argon16, 900, false)
            .unwrap();
        assert_eq!(
            s.confirm_outcome("d-unsampled", true, None).unwrap(),
            None,
            "an unsampled receipt must be discarded"
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
            "a discarded confirm must not touch the bucket"
        );

        // Sampled: recorded.
        s.record_receipt("d-sampled", 7, 4, RiskAction::Argon16, 900, true)
            .unwrap();
        assert_eq!(s.confirm_outcome("d-sampled", true, None).unwrap(), Some(7));
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
        assert_eq!(s.confirm_outcome("d-w", true, Some(10.0)).unwrap(), Some(7));
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
            Some(7)
        );

        // Consumed exactly once: the second confirm is a no-op.
        assert_eq!(s.confirm_outcome("decision-1", true, None).unwrap(), None);

        // Unknown id -> None (never errors).
        assert_eq!(
            s.confirm_outcome("decision-missing", true, None).unwrap(),
            None
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
        let s = RedisCalibrationStore::with_options(
            client(),
            &ns,
            1,
            150,
            10,
            300,
            SamplingMode::Complete,
            0,
        );
        s.record_receipt("race-1", 7, 4, RiskAction::Sha16, 500, true)
            .unwrap();
        // Two INDEPENDENT stores on the same namespace: no shared
        // connection, so the race exercises the script's atomicity (the
        // GETDEL+increment has no crash window; the loser sees no receipt).
        let a = RedisCalibrationStore::with_options(
            client(),
            &ns,
            1,
            150,
            10,
            300,
            SamplingMode::Complete,
            0,
        );
        let b = RedisCalibrationStore::with_options(
            client(),
            &ns,
            1,
            150,
            10,
            300,
            SamplingMode::Complete,
            0,
        );
        std::thread::scope(|scope| {
            let ha = scope.spawn(move || a.confirm_outcome("race-1", true, None));
            let hb = scope.spawn(move || b.confirm_outcome("race-1", true, None));
            let ra = ha.join().expect("thread").expect("confirm");
            let rb = hb.join().expect("thread").expect("confirm");
            let recorded = [ra, rb].iter().filter(|r| r.is_some()).count();
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
            RedisCalibrationStore::with_options(client.clone(), "smp", 1, 150, 10, 300, mode, ppm)
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
}
