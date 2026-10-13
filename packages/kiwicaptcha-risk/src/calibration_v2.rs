//! Calibration v2: the hardened generation of the outcome-feedback
//! calibration (change.md Part 5, calibration hardening). The estimator
//! is provenance-weighted, per-source capped, and takes the plain mean of the
//! clipped boundary distance distribution before averaging:
//!
//! - Labels carry a provenance class — [`ProvenanceClass`]: human review
//!   (weight 1.0, the default for app-reported labels), security event
//!   (0.8) and payment network (1.2). The class weight scales every
//!   bucket contribution, so higher-trust channels dominate the estimate
//!   when they disagree with a low-trust flood.
//! - Every label names its reporting source (a bounded id 0..7, the app
//!   path that reported it). One source may admit at most
//!   [`RedisCalibrationStoreV2::DEFAULT_PER_SOURCE_WINDOW_CAP`] labels
//!   per scope per hourly bucket (enforced atomically inside
//!   `resources/confirm_v2.lua`); a label beyond the cap stays a real,
//!   exactly-once outcome (status 3) but contributes nothing to the
//!   estimator.
//! - The estimator averages clipped boundary distances as a plain
//!   weighted mean over the per-distance mass histogram the confirm
//!   script writes. No tail is trimmed: the error signal lives in the
//!   small tail of misclassified samples, so a trim would erase exactly
//!   the movement the estimator exists to make. The caps and the
//!   provenance weights carry the flood resistance.
//!
//! Everything else is inherited from the v1 generation by composition:
//! the same receipts, outcome ledgers, sampling knobs, resolution gate,
//! hourly buckets and milli-point rate-limit state. The store composes a
//! [`crate::calibration::RedisCalibrationStore`] (the `with_*` builder
//! precedent) and shares its key layout, so the two generations address
//! identical keys and an upgrade never orphans state.
//!
//! ## Versioning: v2 is the default for new ledgers only
//!
//! Calibration v2 is the version new deployments use. Concretely:
//!
//! - Registration: a v2 store stamps every new receipt with `"cv": 2`
//!   (the JSON is stored verbatim by the same canonical
//!   `register_decision.lua`). A v1 store keeps producing receipts
//!   without the field.
//! - Confirmation: the version is discovered at first touch of the
//!   ledger — the receipt is read, and `cv == 2` routes to
//!   `resources/confirm_v2.lua` while every older receipt keeps
//!   confirming through the v1 script with byte-identical v1 semantics
//!   (existing v1 ledgers keep v1). The same discovery routes a ledger
//!   whose writer generation is 3 to `resources/correction_v2.lua`.
//! - Estimation: the v2 store's `bias_for_scope` runs
//!   `resources/calibration_v2.lua`, which reads only the v2 fields the
//!   v2 confirm wrote (a rollback to the v1 estimator keeps working: the
//!   v1 script reads the generation-1 fields every v2 confirmation also
//!   writes, and ignores the v2 fields).
//!
//! The estimator wakes on admitted v2 samples alone (`n2` counts only
//! confirmed labels the caps admitted), so the min_samples gate, the
//! volume caps compose: a single-window forged flood through the
//! reporting paths admits at most `sources x cap` samples, so its
//! influence on the mean is bounded by the capped mass it can inject
//! and the movement stays within the documented tolerance (the
//! done-when test below measures exactly this).
//! A flood that persists for days and exceeds the honest population's
//! mass is bounded by the caps' inflow rate and by the proportional
//! rate limiter; label statistics cannot reject labels that carry the
//! only ground truth the system has, so the provenance weights exist to
//! let the higher-trust channels outvote the low-trust volume.
//!
//! `bias_for_scope` caches per scope for 30 s (bounded, oldest evicted),
//! the same policy as the v1 store; a confirm or correct invalidates the
//! scope's entry. Any backend failure returns 0 (fail-open), identical
//! with v1.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::action::RiskAction;
use crate::calibration::{
    backend, BiasCache, CalibrationError, CalibrationStore, RedisCalibrationStore, SamplingMode,
};

/// The provenance class of a confirmed label: who asserted the outcome.
///
/// The weights are frozen cross-language constants (documented in
/// `resources/calibration_v2.lua`, mirrored by the PHP
/// `AggregateCalibratorV2`): a payment-network assertion (a chargeback
/// or a cleared payment) is the strongest signal and carries 1.2x the
/// mass of a human review; a security-event assertion (an automated
/// ban pipeline) carries 0.8x. App-reported labels default to human
/// review; an automatic success signal must never feed the calibrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceClass {
    /// A person reviewed the outcome (support flag, manual review).
    HumanReview,
    /// An automated security pipeline asserted the outcome.
    SecurityEvent,
    /// The payment network asserted the outcome (chargeback, refund).
    PaymentNetwork,
}

impl ProvenanceClass {
    /// The frozen class weight (the mass multiplier of every bucket
    /// contribution).
    pub const fn weight(self) -> f64 {
        match self {
            ProvenanceClass::HumanReview => 1.0,
            ProvenanceClass::SecurityEvent => 0.8,
            ProvenanceClass::PaymentNetwork => 1.2,
        }
    }

    /// The argv wire int shared with `resources/confirm_v2.lua`.
    pub const fn as_int(self) -> u8 {
        match self {
            ProvenanceClass::HumanReview => 0,
            ProvenanceClass::SecurityEvent => 1,
            ProvenanceClass::PaymentNetwork => 2,
        }
    }

    /// The inverse of [`ProvenanceClass::as_int`], for decoding.
    pub const fn from_int(value: u8) -> Option<ProvenanceClass> {
        match value {
            0 => Some(ProvenanceClass::HumanReview),
            1 => Some(ProvenanceClass::SecurityEvent),
            2 => Some(ProvenanceClass::PaymentNetwork),
            _ => None,
        }
    }
}

/// The canonical v2 estimator script, shared verbatim with PHP
/// (`protocol/risk-v1/calibration_v2.lua`): the provenance-weighted,
/// per-source-capped, weighted-mean bias over the same 24 hourly buckets
/// and the same milli-point rate-limit state the v1 estimator uses.
const CALIBRATION_V2_LUA: &str = include_str!("../resources/calibration_v2.lua");

/// The canonical v2 confirm script, shared verbatim with PHP
/// (`protocol/risk-v1/confirm_v2.lua`): the v1 confirm contract plus the
/// provenance class, the reporting source and the per-source window cap.
const CONFIRM_V2_LUA: &str = include_str!("../resources/confirm_v2.lua");

/// The canonical v2 correction script, shared verbatim with PHP
/// (`protocol/risk-v1/correction_v2.lua`): reverses and redoes the v2
/// legs (the distance histogram mass and the admitted counter) for a
/// counted generation-3 ledger.
const CORRECTION_V2_LUA: &str = include_str!("../resources/correction_v2.lua");

/// The generation marker a v2 registration stamps into the receipt JSON
/// (`"cv": 2`); the confirm path discovers it at first touch.
const RECEIPT_GENERATION_V2: i64 = 2;

/// The outcome-feedback calibration store, generation 2: a composed
/// wrapper over [`RedisCalibrationStore`] (the same client, namespace,
/// key layout and knobs) that swaps the estimator and the label intake
/// for the hardened v2 scripts. Attach it with
/// [`crate::RiskEngine::with_calibration`] exactly like the v1 store —
/// the engine composition selects the version by which store is built
/// in, while the per-ledger version is discovered at the receipt.
pub struct RedisCalibrationStoreV2 {
    inner: RedisCalibrationStore,
    mode: SamplingMode,
    min_samples: i64,
    max_adjustment: i32,
    max_change_per_minute: i32,
    minimum_resolution_ratio: f64,
    false_positive_cost: f64,
    false_negative_cost: f64,
    per_source_window_cap: i64,
    cache: Mutex<BiasCache>,
    script: redis::Script,
    confirm_script: redis::Script,
    correction_script: redis::Script,
    script_calls: AtomicUsize,
}

impl RedisCalibrationStoreV2 {
    /// Default per-source window cap: one reporting source may admit at
    /// most 100 labels per scope per hourly bucket. With the eight
    /// bounded source slots a single-window burst through every path
    /// admits at most 800 labels — below the inherited default
    /// min_samples of 1000, so a forged-label burst cannot wake the
    /// estimator on its own.
    pub const DEFAULT_PER_SOURCE_WINDOW_CAP: i64 = 100;
    /// The reporting-source slot count (ids 0..7). The bound keeps the
    /// bucket hash cardinality fixed no matter what callers pass.
    pub const MAX_REPORTING_SOURCES: u8 = 8;
    /// In-process per-scope bias cache TTL (as the v1 store).
    pub const CACHE_TTL_S: u64 = RedisCalibrationStore::CACHE_TTL_S;
    /// Bounded in-process cache capacity (as the v1 store).
    pub const CACHE_CAP: usize = RedisCalibrationStore::CACHE_CAP;

    /// Builds the v2 store over a fresh inner v1 store with the default
    /// knobs (identical defaults, identical namespace contract).
    ///
    /// # Panics
    ///
    /// Panics if the namespace is empty or contains `{`/`}` (the inner
    /// store's contract).
    pub fn new(client: redis::Client, namespace: &str) -> RedisCalibrationStoreV2 {
        RedisCalibrationStoreV2::with_limits(
            client,
            namespace,
            RedisCalibrationStore::DEFAULT_MIN_SAMPLES,
            RedisCalibrationStore::DEFAULT_MAX_ADJUSTMENT,
            RedisCalibrationStore::DEFAULT_MAX_CHANGE_PER_MINUTE,
        )
    }

    /// Builds the v2 store with explicit calibration safety knobs; the
    /// composed inner store carries the identical knobs so both
    /// generations agree on the rate-limit and gate contract.
    ///
    /// # Panics
    ///
    /// Panics under the inner store's constructor contract (see
    /// [`RedisCalibrationStore::with_limits`]).
    pub fn with_limits(
        client: redis::Client,
        namespace: &str,
        min_samples: i64,
        max_adjustment: i32,
        max_change_per_minute: i32,
    ) -> RedisCalibrationStoreV2 {
        RedisCalibrationStoreV2::with_options(
            client,
            namespace,
            min_samples,
            max_adjustment,
            max_change_per_minute,
            RedisCalibrationStore::RECEIPT_EXPIRE_S,
            RedisCalibrationStore::DEFAULT_MODE,
            RedisCalibrationStore::DEFAULT_SAMPLING_PROBABILITY_PPM,
            RedisCalibrationStore::DEFAULT_MIN_RESOLUTION_RATIO,
            RedisCalibrationStore::DEFAULT_FALSE_POSITIVE_COST,
            RedisCalibrationStore::DEFAULT_FALSE_NEGATIVE_COST,
            Self::DEFAULT_PER_SOURCE_WINDOW_CAP,
        )
    }

    /// Builds the v2 store with every knob explicit. The first eleven
    /// arguments mirror [`RedisCalibrationStore::with_options`] one for
    /// one (the inner store is constructed from exactly these values);
    /// `per_source_window_cap` is the v2 volume cap: the maximum number
    /// of labels one reporting source may admit per scope per hourly
    /// bucket (>= 1).
    ///
    /// # Panics
    ///
    /// Panics under the inner store's constructor contract, or when
    /// `per_source_window_cap < 1`.
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
        per_source_window_cap: i64,
    ) -> RedisCalibrationStoreV2 {
        assert!(
            per_source_window_cap >= 1,
            "per_source_window_cap must be >= 1"
        );
        let inner = RedisCalibrationStore::with_options(
            client,
            namespace,
            min_samples,
            max_adjustment,
            max_change_per_minute,
            receipt_ttl_secs,
            RedisCalibrationStore::OUTCOME_EXPIRE_S,
            mode,
            sampling_probability_ppm,
            minimum_resolution_ratio,
            false_positive_cost,
            false_negative_cost,
        );
        RedisCalibrationStoreV2 {
            inner,
            mode,
            min_samples,
            max_adjustment,
            max_change_per_minute,
            minimum_resolution_ratio,
            false_positive_cost,
            false_negative_cost,
            per_source_window_cap,
            cache: Mutex::new(BiasCache::new(
                Self::CACHE_CAP,
                Duration::from_secs(Self::CACHE_TTL_S),
            )),
            script: redis::Script::new(CALIBRATION_V2_LUA),
            confirm_script: redis::Script::new(CONFIRM_V2_LUA),
            correction_script: redis::Script::new(CORRECTION_V2_LUA),
            script_calls: AtomicUsize::new(0),
        }
    }

    /// Arms the scope-HMAC key on the composed inner store (the raw
    /// scope must never appear in Redis keys — shared derivation).
    pub fn with_scope_key(mut self, key: [u8; 32]) -> Self {
        self.inner = self.inner.with_scope_key(key);
        self
    }

    /// Overrides the connect and command (read/write) timeouts on the
    /// composed inner store (shared IO policy).
    pub fn with_io_timeouts(mut self, connection_timeout_ms: u64, command_timeout_ms: u64) -> Self {
        self.inner = self
            .inner
            .with_io_timeouts(connection_timeout_ms, command_timeout_ms);
        self
    }

    /// Re-derives every key from the raw namespace under an explicit key
    /// version (a deliberate migration, as the v1 store).
    pub fn with_namespace_version(
        mut self,
        namespace_version: crate::namespace::NamespaceVersion,
    ) -> Self {
        self.inner = self.inner.with_namespace_version(namespace_version);
        self
    }

    /// The encoded deployment namespace (the inner store's).
    pub fn namespace(&self) -> &str {
        self.inner.namespace()
    }

    /// The raw configured deployment discriminator (the inner store's).
    pub fn raw_namespace(&self) -> &str {
        self.inner.raw_namespace()
    }

    /// The configured per-source window cap.
    pub fn per_source_window_cap(&self) -> i64 {
        self.per_source_window_cap
    }

    /// Number of Lua script invocations issued by `bias_for_scope` since
    /// construction (diagnostics, as the v1 store).
    pub fn script_calls(&self) -> usize {
        self.script_calls.load(Ordering::Relaxed)
    }

    /// The sampling mode the store was built with (the wire int the
    /// scripts expect and the weighted-mode guard's input).
    fn mode_int(&self) -> u8 {
        self.mode.as_int()
    }

    /// The v2 estimate for a scope: one canonical
    /// `calibration_v2.lua` invocation over the 24 hourly buckets and
    /// the shared rate-limit state (argv identical with the v1 read).
    fn bias_uncached(&self, scope: u32, now_ms: i64) -> i32 {
        let hour = now_ms / 3_600_000;
        let mut keys: Vec<String> =
            Vec::with_capacity(RedisCalibrationStore::BUCKET_WINDOW_HOURS as usize + 1);
        for h in (hour - (RedisCalibrationStore::BUCKET_WINDOW_HOURS - 1))..=hour {
            keys.push(self.inner.bucket_key(scope, h));
        }
        keys.push(self.inner.state_key(scope));
        let mut invoke = self.script.prepare_invoke();
        for key in &keys {
            invoke.key(key.as_str());
        }
        invoke.arg(now_ms.to_string());
        invoke.arg(self.min_samples().to_string());
        invoke.arg(self.max_adjustment().to_string());
        invoke.arg(self.max_change_per_minute().to_string());
        invoke.arg(self.min_resolution_ratio().to_string());
        invoke.arg(self.mode_int().to_string());
        invoke.arg(self.fp_cost().to_string());
        invoke.arg(self.fn_cost().to_string());
        let result: Result<i64, CalibrationError> = self
            .inner
            .with_connection(|conn| invoke.invoke(conn).map_err(backend));
        let bias = match result {
            Ok(bias) => bias,
            Err(_) => return 0, // fail-open: never break issuance
        };
        self.script_calls.fetch_add(1, Ordering::Relaxed);
        bounded_bias(bias, self.max_adjustment())
    }

    // The knob views below are the store's own construction values:
    // the v2 estimator takes the identical argv so the two generations
    // can never disagree about the gates or the clamps.

    fn min_samples(&self) -> i64 {
        self.min_samples
    }

    fn max_adjustment(&self) -> i32 {
        self.max_adjustment
    }

    fn max_change_per_minute(&self) -> i32 {
        self.max_change_per_minute
    }

    fn min_resolution_ratio(&self) -> f64 {
        self.minimum_resolution_ratio
    }

    fn fp_cost(&self) -> f64 {
        self.false_positive_cost
    }

    fn fn_cost(&self) -> f64 {
        self.false_negative_cost
    }

    fn cache_insert(&self, scope: u32, bias: i32, now: Instant) {
        self.cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(scope, bias, now);
    }

    fn invalidate(&self, scope: u32) {
        self.cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entries
            .remove(&scope);
        // The inner store shares the namespace: keep its cache coherent
        // too, so a mixed-generation deployment never serves a stale v1
        // aggregate after a v2 label lands.
        self.inner.invalidate_bias_cache(scope);
    }

    /// Discovers the receipt generation at first touch: a `Some` pair
    /// of scope and hour routes the confirmation to the v2 script;
    /// `None` — an older or already-consumed receipt — keeps the v1
    /// The per-identity trust-cap counter key (shared tag, expiring with
    /// the bucket window): the identity dimension of the trust-granting
    /// reputation cap.
    fn trust_cap_key(&self, identity: &str) -> String {
        format!("{{kiwi:{}}}:trustcap:{}", self.inner.namespace(), identity)
    }

    /// path.
    fn v2_receipt(&self, decision_id: &str) -> Result<Option<(u32, i64)>, CalibrationError> {
        if !crate::redis::RedisRiskStateStore::valid_key_component(decision_id) {
            return Err(CalibrationError::InvalidIdentifier(hex::encode(
                decision_id,
            )));
        }
        let raw: Option<String> = self.inner.with_connection(|conn| {
            redis::cmd("GET")
                .arg(self.inner.receipt_key(decision_id))
                .query(conn)
                .map_err(backend)
        })?;
        let Some(raw) = raw else {
            return Ok(None);
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
            return Ok(None);
        };
        if value.get("cv").and_then(|v| v.as_i64()) != Some(RECEIPT_GENERATION_V2) {
            return Ok(None);
        }
        let scope = value
            .get("scope")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let hour = value.get("decision_hour").and_then(|v| v.as_i64());
        Ok(match (scope, hour) {
            (Some(scope), Some(hour)) => Some((scope, hour)),
            _ => None,
        })
    }

    /// Confirms the outcome of one decision with the label's provenance
    /// class and reporting source named explicitly. `source` is the
    /// bounded source id (below [`Self::MAX_REPORTING_SOURCES`]);
    /// `weight` is the inverse sampling probability in weighted mode;
    /// `identity` is the pseudonym whose reputation this label would
    /// credit (the per-identity trust cap of trust-granting labels).
    ///
    /// Returns the shared accepted-outcome status: 0 nothing consumed,
    /// 1 first confirmation with calibration recorded, 2 first
    /// confirmation deliberately unsampled, 3 first confirmation with
    /// calibration withheld by the per-source window cap, 4 first
    /// confirmation whose trust-granting reputation credit is withheld
    /// by the per-source or per-identity trust cap. Reputation is
    /// authorized on 1 and 2 (and on 3 only for abuse labels); 4 never
    /// authorizes it.
    ///
    /// # Errors
    ///
    /// [`CalibrationError::WeightRequired`] in weighted mode without a
    /// weight; [`CalibrationError::InvalidIdentifier`] for an unsafe
    /// decision id, source or identity; [`CalibrationError::Backend`]
    /// on a backend failure.
    pub fn confirm_outcome_with_provenance(
        &self,
        decision_id: &str,
        legitimate: bool,
        provenance: ProvenanceClass,
        source: u8,
        weight: Option<f64>,
        identity: Option<&str>,
    ) -> Result<u8, CalibrationError> {
        if source >= Self::MAX_REPORTING_SOURCES {
            return Err(CalibrationError::Backend(format!(
                "reporting source id must be below {}",
                Self::MAX_REPORTING_SOURCES
            )));
        }
        if matches!(self.mode, SamplingMode::Weighted) && weight.is_none() {
            return Err(CalibrationError::WeightRequired(decision_id.to_string()));
        }
        let Some((scope, hour)) = self.v2_receipt(decision_id)? else {
            // No v2 receipt under this id: route through the v1 path so
            // an older ledger keeps exactly its v1 semantics.
            return self.inner.confirm_outcome(decision_id, legitimate, weight);
        };
        if let Some(identity) = identity {
            if !crate::redis::RedisRiskStateStore::valid_key_component(identity) {
                return Err(CalibrationError::InvalidIdentifier(hex::encode(identity)));
            }
        }
        let bucket_key = self.inner.bucket_key(scope, hour);
        let ledger_key = self.inner.outcome_ledger_key(decision_id);
        let identity_key = identity.map(|id| self.trust_cap_key(id));
        let mut invoke = self.confirm_script.prepare_invoke();
        invoke.key(self.inner.receipt_key(decision_id).as_str());
        invoke.key(bucket_key.as_str());
        invoke.key(ledger_key.as_str());
        if let Some(key) = identity_key.as_deref() {
            invoke.key(key);
        }
        invoke.arg(self.mode_int().to_string());
        invoke.arg(weight.unwrap_or(1.0).to_string());
        invoke.arg(if legitimate { "1" } else { "0" });
        invoke.arg(RedisCalibrationStore::BUCKET_EXPIRE_S.to_string());
        invoke.arg(self.inner.outcome_ttl_secs().to_string());
        invoke.arg(scope.to_string());
        invoke.arg(hour.to_string());
        invoke.arg(provenance.as_int().to_string());
        invoke.arg(source.to_string());
        invoke.arg(self.per_source_window_cap.to_string());
        let status: i64 = self
            .inner
            .with_connection(|conn| invoke.invoke(conn).map_err(backend))?;
        if status != 0 {
            self.invalidate(scope);
        }
        Ok(status as u8)
    }

    /// Corrects a decision's outcome with the v2 routing: a generation-3
    /// ledger goes through `correction_v2.lua` (which reverses and redoes
    /// the histogram mass and the admitted counter), every older ledger
    /// through the v1 correction script.
    fn correct_outcome_routed(
        &self,
        decision_id: &str,
        legitimate: bool,
        weight: Option<f64>,
    ) -> Result<bool, CalibrationError> {
        if !crate::redis::RedisRiskStateStore::valid_key_component(decision_id) {
            return Err(CalibrationError::InvalidIdentifier(hex::encode(
                decision_id,
            )));
        }
        let ledger_key = self.inner.outcome_ledger_key(decision_id);
        let raw: Option<String> = self.inner.with_connection(|conn| {
            redis::cmd("GET")
                .arg(&ledger_key)
                .query(conn)
                .map_err(backend)
        })?;
        let Some(raw) = raw else {
            return Ok(false);
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
            return Ok(false);
        };
        if value.get("v").and_then(|v| v.as_i64()) != Some(3) {
            return self.inner.correct_outcome(decision_id, legitimate, weight);
        }
        let Some(scope) = value
            .get("scope")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok())
        else {
            return Ok(false);
        };
        let Some(hour) = value.get("hour").and_then(|v| v.as_i64()) else {
            return Ok(false);
        };
        let bucket_key = self.inner.bucket_key(scope, hour);
        let mut invoke = self.correction_script.prepare_invoke();
        invoke.key(ledger_key.as_str());
        invoke.key(bucket_key.as_str());
        invoke.arg(if legitimate { "L" } else { "A" });
        invoke.arg(weight.unwrap_or(1.0).to_string());
        invoke.arg(RedisCalibrationStore::BUCKET_EXPIRE_S.to_string());
        invoke.arg(self.inner.outcome_ttl_secs().to_string());
        invoke.arg(scope.to_string());
        invoke.arg(hour.to_string());
        let applied: i64 = self
            .inner
            .with_connection(|conn| invoke.invoke(conn).map_err(backend))?;
        if applied != 0 {
            self.invalidate(scope);
        }
        Ok(applied != 0)
    }
}

/// Maps a raw calibration_v2.lua reply to a bounded integer bias (the
/// same defense-in-depth clamp as the v1 store; the script guards its
/// own output).
fn bounded_bias(bias: i64, max_adjustment: i32) -> i32 {
    bias.clamp(-(max_adjustment as i64), max_adjustment as i64) as i32
}

impl CalibrationStore for RedisCalibrationStoreV2 {
    fn record_receipt(
        &self,
        decision_id: &str,
        scope: u32,
        band: u8,
        action: RiskAction,
        score: u32,
        sampled: bool,
        decision_hour: i64,
        weight: f64,
    ) -> Result<bool, CalibrationError> {
        if !crate::redis::RedisRiskStateStore::valid_key_component(decision_id) {
            return Err(CalibrationError::InvalidIdentifier(hex::encode(
                decision_id,
            )));
        }
        // A v2 receipt is the v1 receipt JSON plus the generation field;
        // register_decision.lua stores the JSON verbatim and validates
        // the shared fields, so both generations register through the
        // same canonical atomic script.
        let json = serde_json::json!({
            "scope": scope,
            "band": band,
            "action": action.as_str(),
            "decision_hour": decision_hour,
            "score": score.clamp(0, 1000),
            "sampled": sampled as u8,
            "cv": RECEIPT_GENERATION_V2,
        })
        .to_string();
        let receipt_key = self.inner.receipt_key(decision_id);
        let bucket_key = self.inner.bucket_key(scope, decision_hour);
        let ledger_key = self.inner.outcome_ledger_key(decision_id);
        let mut invoke = self.inner.register_script().prepare_invoke();
        invoke.key(receipt_key.as_str());
        invoke.key(bucket_key.as_str());
        invoke.key(ledger_key.as_str());
        invoke.arg(json.as_str());
        invoke.arg(self.inner.receipt_ttl_secs().to_string());
        invoke.arg(if sampled { "1" } else { "0" });
        invoke.arg(RedisCalibrationStore::BUCKET_EXPIRE_S.to_string());
        invoke.arg(self.inner.outcome_ttl_secs().to_string());
        invoke.arg(scope.to_string());
        invoke.arg(decision_hour.to_string());
        invoke.arg(score.clamp(0, 1000).to_string());
        invoke.arg(weight.to_string());
        let registered: i64 = self
            .inner
            .with_connection(|conn| invoke.invoke(conn).map_err(backend))?;
        Ok(registered != 0)
    }

    fn confirm_outcome(
        &self,
        decision_id: &str,
        legitimate: bool,
        weight: Option<f64>,
    ) -> Result<u8, CalibrationError> {
        // App-reported labels default to the human-review class on the
        // default reporting source (slot 0); the explicit provenance
        // surface is confirm_outcome_with_provenance.
        self.confirm_outcome_with_provenance(
            decision_id,
            legitimate,
            ProvenanceClass::HumanReview,
            0,
            weight,
            None,
        )
    }

    fn confirm_outcome_for(
        &self,
        decision_id: &str,
        legitimate: bool,
        weight: Option<f64>,
        identity: Option<&str>,
    ) -> Result<u8, CalibrationError> {
        self.confirm_outcome_with_provenance(
            decision_id,
            legitimate,
            ProvenanceClass::HumanReview,
            0,
            weight,
            identity,
        )
    }

    fn correct_outcome(
        &self,
        decision_id: &str,
        legitimate: bool,
        weight: Option<f64>,
    ) -> Result<bool, CalibrationError> {
        self.correct_outcome_routed(decision_id, legitimate, weight)
    }

    fn sample(&self) -> bool {
        self.inner.sample()
    }

    fn sampling_metrics(
        &self,
        scope: u32,
        now_ms: i64,
    ) -> Result<crate::calibration::SamplingMetrics, CalibrationError> {
        self.inner.sampling_metrics(scope, now_ms)
    }

    fn bias_for_scope(&self, scope: u32, now_ms: i64) -> i32 {
        let now = Instant::now();
        // Cache hit (including a cached 0): no Redis calls.
        if let Some(cached) = self
            .cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(scope, now)
        {
            return cached;
        }
        let bias = self.bias_uncached(scope, now_ms);
        self.cache_insert(scope, bias, now);
        bias
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::RiskEventKind;
    use crate::network::{CidrNetworkClassifier, NetworkFlags};
    use crate::outcomes::{KiwiOutcomes, Outcome, OutcomeHandle};
    use crate::policy::RiskPolicy;
    use crate::redis::RedisRiskStateStore;
    use crate::resources::ResourcePressure;
    use crate::RiskContext;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

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

    /// Local epoch ms for bucket-hour selection (the script's rate-limit
    /// clock is Redis time).
    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    /// The current decision hour.
    fn hour() -> i64 {
        now() / 3_600_000
    }

    /// A v2 store in complete sampling mode with a fast estimator (the
    /// proportional allowance never binds) on a fresh namespace.
    fn v2_fast(prefix: &str, min_samples: i64, cap: i64) -> RedisCalibrationStoreV2 {
        v2_on_ns(client(), &unique_namespace(prefix), min_samples, cap)
    }

    /// A v2 store over an explicit namespace (cold in-process cache).
    fn v2_on_ns(
        client: redis::Client,
        ns: &str,
        min_samples: i64,
        cap: i64,
    ) -> RedisCalibrationStoreV2 {
        RedisCalibrationStoreV2::with_options(
            client,
            ns,
            min_samples,
            150,
            100_000,
            300,
            SamplingMode::Complete,
            1_000_000,
            0.0,
            1.0,
            2.0,
            cap,
        )
        .with_io_timeouts(2_000, 2_000)
    }

    /// A cold v1 view over an existing namespace (the rollback reader
    /// and the legacy-registration writer).
    fn v1_on(client: redis::Client, ns: &str, min_samples: i64) -> RedisCalibrationStore {
        RedisCalibrationStore::with_limits(client, ns, min_samples, 150, 100_000)
            .with_io_timeouts(2_000, 2_000)
    }

    fn conn() -> redis::Connection {
        client().get_connection().expect("connection")
    }

    fn hget_f64(key: &str, field: &str) -> f64 {
        let v: Option<String> = redis::cmd("HGET")
            .arg(key)
            .arg(field)
            .query(&mut conn())
            .expect("hget");
        v.map(|s| s.parse().expect("float")).unwrap_or(0.0)
    }

    fn hget_i64(key: &str, field: &str) -> i64 {
        let v: Option<i64> = redis::cmd("HGET")
            .arg(key)
            .arg(field)
            .query(&mut conn())
            .expect("hget");
        v.unwrap_or(0)
    }

    /// Registers a v2 receipt (cv: 2) through the composed store.
    fn register_v2(s: &RedisCalibrationStoreV2, id: &str, scope: u32, score: u32) {
        assert!(s
            .record_receipt(id, scope, 6, RiskAction::Argon16, score, true, hour(), 1.0)
            .unwrap());
    }

    /// The exact byte identity of the three v2 script copies (the
    /// protocol canonical and both package resources).
    #[test]
    fn v2_script_copies_are_byte_identical() {
        let manifest = env!("CARGO_MANIFEST_DIR");
        for name in ["calibration_v2.lua", "confirm_v2.lua", "correction_v2.lua"] {
            let canonical = std::fs::read(format!("{manifest}/../../protocol/risk-v1/{name}"))
                .expect("protocol copy present");
            let php = std::fs::read(format!(
                "{manifest}/../../packages/kiwicaptcha-risk-php/resources/{name}"
            ))
            .expect("php resource copy present");
            assert_eq!(canonical, php, "{name} copies must be byte-identical");
            let rust = std::fs::read(format!("{manifest}/resources/{name}"))
                .expect("rust resource copy present");
            assert_eq!(canonical, rust, "{name} copies must be byte-identical");
        }
    }

    #[test]
    fn provenance_weights_are_the_frozen_constants() {
        assert_eq!(ProvenanceClass::HumanReview.weight(), 1.0);
        assert_eq!(ProvenanceClass::SecurityEvent.weight(), 0.8);
        assert_eq!(ProvenanceClass::PaymentNetwork.weight(), 1.2);
        for (id, class) in [
            (0u8, ProvenanceClass::HumanReview),
            (1, ProvenanceClass::SecurityEvent),
            (2, ProvenanceClass::PaymentNetwork),
        ] {
            assert_eq!(ProvenanceClass::from_int(id), Some(class));
            assert_eq!(class.as_int(), id);
        }
        assert_eq!(ProvenanceClass::from_int(3), None);
    }

    #[test]
    fn v1_and_v2_stores_share_the_key_layout() {
        // No live Redis needed: only the key derivations are compared,
        // so a ledger created by either generation is confirmable and
        // correctable by the other. The store constructors parse the
        // URL without connecting; hermetic-skip when it is unset.
        let Some(url) = redis_url() else {
            eprintln!("skipping calibration v2 test: RISK_REDIS_URL not set");
            return;
        };
        let ns = unique_namespace("keys");
        let v1 =
            RedisCalibrationStore::new(redis::Client::open(url.clone()).expect("url parses"), &ns);
        let v2 = RedisCalibrationStoreV2::new(redis::Client::open(url).expect("url parses"), &ns);
        assert_eq!(v1.namespace(), v2.namespace());
        assert_eq!(v1.bucket_key(7, 12345), v2.inner.bucket_key(7, 12345));
        assert_eq!(v1.state_key(7), v2.inner.state_key(7));
        assert_eq!(v1.receipt_key("d-1"), v2.inner.receipt_key("d-1"));
        assert_eq!(
            v1.outcome_ledger_key("d-1"),
            v2.inner.outcome_ledger_key("d-1")
        );
        assert_eq!(RedisCalibrationStoreV2::DEFAULT_PER_SOURCE_WINDOW_CAP, 100);
    }

    #[test]
    fn provenance_class_weights_scale_the_bucket_contribution() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration v2 test: RISK_REDIS_URL not set");
            return;
        };
        let s = v2_fast("pv2w", 1, 1_000_000);
        register_v2(&s, "pv2-hr", 1, 900);
        assert_eq!(
            s.confirm_outcome_with_provenance(
                "pv2-hr",
                true,
                ProvenanceClass::HumanReview,
                0,
                None,
                None
            )
            .unwrap(),
            1
        );
        register_v2(&s, "pv2-se", 1, 900);
        assert_eq!(
            s.confirm_outcome_with_provenance(
                "pv2-se",
                true,
                ProvenanceClass::SecurityEvent,
                1,
                None,
                None
            )
            .unwrap(),
            1
        );
        register_v2(&s, "pv2-pn", 1, 900);
        assert_eq!(
            s.confirm_outcome_with_provenance(
                "pv2-pn",
                true,
                ProvenanceClass::PaymentNetwork,
                2,
                None,
                None
            )
            .unwrap(),
            1
        );
        let bucket = s.inner.bucket_key(1, hour());
        // The generation-1 count field carries the class-scaled mass.
        assert!((hget_f64(&bucket, "legit_count") - 3.0).abs() < 1e-9);
        // The per-class distance masses: 1.0 + 0.8 + 1.2 at distance 300
        // (score 900 against the boundary 600).
        assert!((hget_f64(&bucket, "lh2_300") - 3.0).abs() < 1e-9);
        // The admitted counter is unweighted.
        assert_eq!(hget_i64(&bucket, "n2"), 3);
        // The source counters landed on their own slots.
        assert_eq!(hget_i64(&bucket, "sc0"), 1);
        assert_eq!(hget_i64(&bucket, "sc1"), 1);
        assert_eq!(hget_i64(&bucket, "sc2"), 1);
        // The ledger carries the generation and the class.
        let ledger: String = redis::cmd("GET")
            .arg(s.inner.outcome_ledger_key("pv2-pn"))
            .query(&mut conn())
            .expect("ledger");
        assert!(ledger.contains("\"v\":3"), "generation-3 writer: {ledger}");
        assert!(ledger.contains("\"pc\":2"), "provenance class: {ledger}");
    }

    /// The per-identity trust cap: trust-granting confirmations beyond
    /// the cap withhold the reputation credit (status 4) while the
    /// ledger flip stands.
    #[test]
    fn trust_granting_reputation_is_capped_per_identity() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration v2 test: RISK_REDIS_URL not set");
            return;
        };
        let s = v2_fast("tci", 1, 2);
        let identity = "ab".repeat(16);
        let mut statuses = Vec::new();
        // Three sources, one L label each, all crediting the same
        // identity: the volume cap never binds (one label per source),
        // so the third status isolates the identity trust cap.
        for i in 0..3u32 {
            let id = format!("tci-{i}");
            register_v2(&s, &id, 1, 900);
            statuses.push(
                s.confirm_outcome_with_provenance(
                    &id,
                    true,
                    ProvenanceClass::HumanReview,
                    i as u8,
                    None,
                    Some(&identity),
                )
                .unwrap(),
            );
        }
        assert_eq!(statuses, vec![1, 1, 4], "the third trust grant is capped");
        // The identity counter is real state.
        let key = format!("{{kiwi:{}}}:trustcap:{identity}", s.inner.namespace());
        assert_eq!(hget_i64(&key, "n"), 3);
    }

    /// The per-source trust cap: beyond the cap, trust-granting labels
    /// report status 4 (reputation withheld) even when the volume cap
    /// would have reported 3.
    #[test]
    fn trust_granting_reputation_is_capped_per_source() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration v2 test: RISK_REDIS_URL not set");
            return;
        };
        let s = v2_fast("tcs", 1, 2);
        let mut statuses = Vec::new();
        // Two abuse labels fill the volume cap, then three L labels:
        // volume reports 3 from the third label on, but the trust cap
        // (tcs counter, L only) reports 4 from the fifth label.
        for i in 0..5u32 {
            let id = format!("tcs-{i}");
            register_v2(&s, &id, 1, 900);
            let legitimate = i >= 2;
            statuses.push(
                s.confirm_outcome_with_provenance(
                    &id,
                    legitimate,
                    ProvenanceClass::HumanReview,
                    7,
                    None,
                    None,
                )
                .unwrap(),
            );
        }
        assert_eq!(statuses, vec![1, 1, 3, 3, 4]);
        let bucket = s.inner.bucket_key(1, hour());
        assert_eq!(hget_i64(&bucket, "tcs7"), 3);
    }

    /// Regression: a fractional receipt score can never split one
    /// histogram sample across fractional distance slots — the score is
    /// floored before the fields are named.
    #[test]
    fn histogram_fields_floor_a_fractional_receipt_score() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration v2 test: RISK_REDIS_URL not set");
            return;
        };
        let s = v2_fast("flr", 1, 1_000_000);
        let id = "flr-frac";
        register_v2(&s, id, 1, 0);
        // Rewrite the receipt with a fractional score (the typed writer
        // floors before it gets here; a direct script caller does not).
        let receipt_key = s.inner.receipt_key(id);
        let raw: String = redis::cmd("GET")
            .arg(&receipt_key)
            .query(&mut conn())
            .expect("receipt");
        let patched = raw.replace("\"score\":0", "\"score\":899.5");
        let _: redis::Value = redis::cmd("SET")
            .arg(&receipt_key)
            .arg(&patched)
            .query(&mut conn())
            .expect("receipt rewrite");
        assert_eq!(
            s.confirm_outcome_with_provenance(
                id,
                true,
                ProvenanceClass::HumanReview,
                0,
                None,
                None
            )
            .unwrap(),
            1
        );
        let bucket = s.inner.bucket_key(1, hour());
        // floor(899.5) - 600 = 299: the mass lands on the integer slot.
        assert!((hget_f64(&bucket, "lh2_299") - 1.0).abs() < 1e-9);
        for field in ["lh2_299.5", "lh2_300"] {
            assert_eq!(hget_f64(&bucket, field), 0.0, "{field} must stay empty");
        }
    }

    #[test]
    fn per_source_window_cap_withholds_calibration_and_books_the_outcome() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration v2 test: RISK_REDIS_URL not set");
            return;
        };
        // Cap 2, min_samples 3: four forged labels through source 1 —
        // the first two are admitted (below min_samples: no movement
        // yet), the last two are capped out. The estimator must stay at
        // 0 because capped labels contribute no admitted count, even
        // though their distance mass would have crossed the threshold.
        let s = v2_fast("pv2c", 3, 2);
        for i in 0..4 {
            let id = format!("cap-{i}");
            register_v2(&s, &id, 1, 1000);
            let status = s
                .confirm_outcome_with_provenance(
                    &id,
                    true,
                    ProvenanceClass::HumanReview,
                    1,
                    None,
                    None,
                )
                .unwrap();
            // Beyond the caps a trust-granting label reports 4: the
            // volume cap would say 3, but the trust cap of the same
            // width binds on the L stream and withholds the reputation
            // credit outright.
            assert_eq!(status, if i < 2 { 1 } else { 4 });
        }
        let bucket = s.inner.bucket_key(1, hour());
        assert_eq!(hget_i64(&bucket, "sc1"), 4);
        assert_eq!(hget_i64(&bucket, "sc1c"), 2);
        assert_eq!(hget_i64(&bucket, "n2"), 2);
        assert!((hget_f64(&bucket, "legit_count") - 2.0).abs() < 1e-9);
        assert_eq!(
            s.bias_for_scope(1, now()),
            0,
            "capped labels must not feed the estimator"
        );
        // Source 0 is unaffected by source 1's cap.
        register_v2(&s, "cap-other", 1, 1000);
        assert_eq!(
            s.confirm_outcome_with_provenance(
                "cap-other",
                true,
                ProvenanceClass::HumanReview,
                0,
                None,
                None
            )
            .unwrap(),
            1
        );
        // A capped label still flipped its ledger exactly once (the
        // outcome is real; only its calibration weight is withheld).
        let ledger: String = redis::cmd("GET")
            .arg(s.inner.outcome_ledger_key("cap-3"))
            .query(&mut conn())
            .expect("ledger");
        assert!(ledger.contains("\"o\":\"L\""), "{ledger}");
        assert!(ledger.contains("\"c\":0"), "{ledger}");
        assert!(ledger.contains("\"v\":3"), "{ledger}");
    }

    #[test]
    fn v1_ledgers_keep_v1_semantics_and_new_ledgers_are_v2() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration v2 test: RISK_REDIS_URL not set");
            return;
        };
        let ns = unique_namespace("pv2v");
        let s = v2_on_ns(client(), &ns, 1, 1_000_000);
        // A ledger that predates the v2 deployment: registered by the
        // v1 store (no cv field in its receipt).
        let legacy = RedisCalibrationStore::with_limits(client(), &ns, 1, 150, 100_000)
            .with_io_timeouts(2_000, 2_000);
        assert!(legacy
            .record_receipt(
                "legacy-1",
                1,
                6,
                RiskAction::Argon16,
                900,
                true,
                hour(),
                1.0
            )
            .unwrap());
        // The v2 store confirms it: version discovered at the receipt,
        // the v1 script runs, the v1 semantics hold.
        assert_eq!(s.confirm_outcome("legacy-1", true, None).unwrap(), 1);
        let bucket = s.inner.bucket_key(1, hour());
        assert!((hget_f64(&bucket, "legit_count") - 1.0).abs() < 1e-9);
        assert_eq!(
            hget_i64(&bucket, "n2"),
            0,
            "a v1 confirmation never feeds the v2 estimator"
        );
        let ledger: String = redis::cmd("GET")
            .arg(s.inner.outcome_ledger_key("legacy-1"))
            .query(&mut conn())
            .expect("ledger");
        assert!(
            ledger.contains("\"v\":2") && !ledger.contains("\"pc\""),
            "the legacy ledger keeps its v1 writer generation: {ledger}"
        );
        // A v2 receipt confirms through the v2 script.
        register_v2(&s, "fresh-1", 1, 900);
        assert_eq!(s.confirm_outcome("fresh-1", true, None).unwrap(), 1);
        assert_eq!(hget_i64(&bucket, "n2"), 1);
        let ledger: String = redis::cmd("GET")
            .arg(s.inner.outcome_ledger_key("fresh-1"))
            .query(&mut conn())
            .expect("ledger");
        assert!(ledger.contains("\"v\":3"), "{ledger}");
        assert!(ledger.contains("\"pc\":0"), "{ledger}");
    }

    #[test]
    fn v2_correction_reverses_and_redoes_the_v2_legs() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration v2 test: RISK_REDIS_URL not set");
            return;
        };
        let s = v2_fast("pv2k", 1, 1_000_000);
        register_v2(&s, "corr-1", 1, 900);
        assert_eq!(
            s.confirm_outcome_with_provenance(
                "corr-1",
                true,
                ProvenanceClass::PaymentNetwork,
                0,
                None,
                None
            )
            .unwrap(),
            1
        );
        // The correction flips the outcome and reverses the v2 mass
        // (class weight 1.2 recorded on the ledger) before redoing it
        // with the same class weight. The score stays 900, so the
        // corrected abuse label carries distance 0 (900 is on the far
        // side of the boundary for an abuse label).
        assert!(s.correct_outcome("corr-1", false, None).unwrap());
        let bucket = s.inner.bucket_key(1, hour());
        assert!((hget_f64(&bucket, "legit_count")).abs() < 1e-9);
        assert!((hget_f64(&bucket, "abuse_count") - 1.2).abs() < 1e-9);
        assert!((hget_f64(&bucket, "lh2_300")).abs() < 1e-9);
        assert!((hget_f64(&bucket, "ah2_0") - 1.2).abs() < 1e-9);
        assert_eq!(hget_i64(&bucket, "n2"), 1, "the sample stays admitted");
        // Both means are 0 after the flip (the sample now sits on the
        // correct side of the boundary): the target bias is 0.
        assert_eq!(s.bias_for_scope(1, now()), 0);
        // The flip is exactly once.
        assert!(!s.correct_outcome("corr-1", false, None).unwrap());
    }

    #[test]
    fn sub_ten_percent_error_mass_moves_the_bias() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration v2 test: RISK_REDIS_URL not set");
            return;
        };
        let ns = unique_namespace("pv2t");
        let s = v2_on_ns(client(), &ns, 1, 1_000_000);
        // 900 honest legit labels at score 100 (distance 0) and 100
        // forged "legitimate" labels at score 1000 (distance 400): the
        // forged mass is a tenth of the population, and the plain mean
        // must SEE it. fp_mean = 400 x 100 / 1000 = 40, error -40,
        // raw = trunc(-80 / 10) = -8.
        for i in 0..900 {
            let id = format!("honest-{i}");
            register_v2(&s, &id, 1, 100);
            assert_eq!(s.confirm_outcome(&id, true, None).unwrap(), 1);
        }
        for i in 0..100 {
            let id = format!("forge-{i}");
            register_v2(&s, &id, 1, 1000);
            assert_eq!(s.confirm_outcome(&id, true, None).unwrap(), 1);
        }
        assert_eq!(
            s.bias_for_scope(1, now()),
            0,
            "the first read seeds the state"
        );
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert_eq!(
            v2_on_ns(client(), &ns, 1, 1_000_000).bias_for_scope(1, now()),
            -8,
            "a tenth of the population misclassified is visible in the bias, never trimmed away"
        );
        // 100 more forged labels: fp_mean = 400 x 200 / 1100 = 72.72,
        // raw = trunc(-14.54) = -14.
        for i in 100..200 {
            let id = format!("forge-{i}");
            register_v2(&s, &id, 1, 1000);
            assert_eq!(s.confirm_outcome(&id, true, None).unwrap(), 1);
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert_eq!(
            v2_on_ns(client(), &ns, 1, 1_000_000).bias_for_scope(1, now()),
            -14
        );
    }

    #[test]
    fn the_estimator_sees_two_and_five_percent_error_rates() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration v2 test: RISK_REDIS_URL not set");
            return;
        };
        // Two percent: 980 honest at distance 0 plus 20 forged at
        // distance 400. fp_mean = 8000 / 1000 = 8, error -8,
        // raw = trunc(-1.6) = -1.
        let ns2 = unique_namespace("pv22");
        let s2 = v2_on_ns(client(), &ns2, 1, 1_000_000);
        for i in 0..980 {
            let id = format!("honest2-{i}");
            register_v2(&s2, &id, 1, 100);
            assert_eq!(s2.confirm_outcome(&id, true, None).unwrap(), 1);
        }
        for i in 0..20 {
            let id = format!("forge2-{i}");
            register_v2(&s2, &id, 1, 1000);
            assert_eq!(s2.confirm_outcome(&id, true, None).unwrap(), 1);
        }
        assert_eq!(s2.bias_for_scope(1, now()), 0);
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert_eq!(
            v2_on_ns(client(), &ns2, 1, 1_000_000).bias_for_scope(1, now()),
            -1,
            "a two-percent error rate registers"
        );

        // Five percent: 950 honest plus 50 forged (1000 total).
        // fp_mean = 20000 / 1000 = 20, error -20, raw = trunc(-4) = -4.
        let ns5 = unique_namespace("pv25");
        let s5 = v2_on_ns(client(), &ns5, 1, 1_000_000);
        for i in 0..950 {
            let id = format!("honest5-{i}");
            register_v2(&s5, &id, 1, 100);
            assert_eq!(s5.confirm_outcome(&id, true, None).unwrap(), 1);
        }
        for i in 0..50 {
            let id = format!("forge5-{i}");
            register_v2(&s5, &id, 1, 1000);
            assert_eq!(s5.confirm_outcome(&id, true, None).unwrap(), 1);
        }
        assert_eq!(s5.bias_for_scope(1, now()), 0);
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert_eq!(
            v2_on_ns(client(), &ns5, 1, 1_000_000).bias_for_scope(1, now()),
            -4,
            "a five-percent error rate registers"
        );
    }

    #[test]
    fn payment_network_mass_outvotes_human_review_mass() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration v2 test: RISK_REDIS_URL not set");
            return;
        };
        // Two misclassified legit labels at distances 100 and 300. With
        // uniform human-review mass the mean is 200 (raw -40);
        // naming the 300-distance label payment_network pulls its mass
        // to 1.2 and the estimate to (100 + 360) / 2.2 = 209.09
        // (raw -41): the higher-trust channel dominates the blend.
        let ns_uniform = unique_namespace("pv2u");
        let uniform = v2_on_ns(client(), &ns_uniform, 1, 1_000_000);
        register_v2(&uniform, "u-near", 1, 700);
        assert_eq!(uniform.confirm_outcome("u-near", true, None).unwrap(), 1);
        register_v2(&uniform, "u-far", 1, 900);
        assert_eq!(uniform.confirm_outcome("u-far", true, None).unwrap(), 1);
        // The first-ever read seeds the rate-limit state (target served
        // only through the proportional allowance); a cold view after a
        // short real sleep serves the raw estimate in full.
        assert_eq!(uniform.bias_for_scope(1, now()), 0);
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            v2_on_ns(client(), &ns_uniform, 1, 1_000_000).bias_for_scope(1, now()),
            -40
        );
        let ns_weighted = unique_namespace("pv2p");
        let weighted = v2_on_ns(client(), &ns_weighted, 1, 1_000_000);
        register_v2(&weighted, "w-near", 1, 700);
        assert_eq!(weighted.confirm_outcome("w-near", true, None).unwrap(), 1);
        register_v2(&weighted, "w-far", 1, 900);
        assert_eq!(
            weighted
                .confirm_outcome_with_provenance(
                    "w-far",
                    true,
                    ProvenanceClass::PaymentNetwork,
                    0,
                    None,
                    None
                )
                .unwrap(),
            1
        );
        assert_eq!(weighted.bias_for_scope(1, now()), 0);
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            v2_on_ns(client(), &ns_weighted, 1, 1_000_000).bias_for_scope(1, now()),
            -41
        );
    }

    #[test]
    fn the_rate_limit_state_is_shared_across_generations() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration v2 test: RISK_REDIS_URL not set");
            return;
        };
        let ns = unique_namespace("pv2s");
        // The v1 estimator stores a +150 bias (10 abuse@100: fn_mean
        // 500, error 1000, raw 200 clamped 150).
        let v1 = v1_on(client(), &ns, 1);
        for i in 0..10 {
            assert!(v1
                .record_receipt(
                    &format!("s1-{i}"),
                    1,
                    1,
                    RiskAction::Sha20,
                    100,
                    false,
                    hour(),
                    1.0
                )
                .unwrap());
            v1.record_at(1, 100, false, now()).unwrap();
        }
        // The first-ever read seeds the state and returns 0 (the
        // seeding contract); a cold v1 view after a short real sleep
        // serves the raw target in full.
        assert_eq!(v1.bias_for_scope(1, now()), 0);
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            v1_on(client(), &ns, 1).bias_for_scope(1, now()),
            150,
            "the v1 target is +150"
        );
        // The v2 estimator reads the same state key: with a tight
        // allowance it continues from the stored value instead of
        // jumping from a fresh zero (a fresh state would answer
        // only ~1 point of allowance).
        std::thread::sleep(Duration::from_millis(300));
        let v2 = RedisCalibrationStoreV2::with_options(
            client(),
            &ns,
            1,
            150,
            60,
            300,
            SamplingMode::Complete,
            1_000_000,
            0.0,
            1.0,
            2.0,
            1_000_000,
        )
        .with_io_timeouts(2_000, 2_000);
        let bias = v2.bias_for_scope(1, now());
        assert!(
            (100..=150).contains(&bias),
            "the v2 read must continue from the v1-stored bias, got {bias}"
        );
    }

    fn test_policy() -> RiskPolicy {
        RiskPolicy::from_config(
            3,
            &serde_json::json!({
                "version": 3,
                "weights": {
                    "source_fast": 190, "source_slow": 110, "subnet_fast": 80,
                    "issue_debt": 150, "bad_proof": 220, "malformed": 260,
                    "replay": 320, "action_failure": 120, "scope_switch": 60,
                    "global_pressure": 170, "network_risk": 100,
                    "trust_credit": 130, "principal_credit": 100
                },
                "scopes": {
                    "1": { "base_risk": 100, "minimum": "allow", "post_solve_check": true, "degraded": "sha20" }
                },
                "global_floors": { "0": "allow", "1": "sha16", "2": "sha18", "3": "sha20", "4": "sha20" }
            }),
        )
        .expect("config parses")
    }

    /// The done-when (change.md Part 5): 100_000 forged
    /// ConfirmedLegitimate labels through every public report path —
    /// the typed outcomes API, the engine's confirmed-outcome feedback
    /// path and the direct store confirmation — move the calibration
    /// bias at most 1 point. The measured shift is printed.
    #[test]
    fn hundred_thousand_forged_labels_move_the_bias_at_most_one_point() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration v2 test: RISK_REDIS_URL not set");
            return;
        };
        let ns = unique_namespace("pv2done");
        // Default knobs except the estimator speed: min_samples 1000,
        // the per-source cap 100, complete sampling (every forged
        // confirmation is a candidate label), and a huge proportional
        // allowance so the measurement captures the estimator's raw
        // move rather than the rate limiter's.
        let reporter = v2_on_ns(
            client(),
            &ns,
            1000,
            RedisCalibrationStoreV2::DEFAULT_PER_SOURCE_WINDOW_CAP,
        );
        let direct = v2_on_ns(
            client(),
            &ns,
            1000,
            RedisCalibrationStoreV2::DEFAULT_PER_SOURCE_WINDOW_CAP,
        );
        let before = direct.bias_for_scope(1, now());

        // The engine composition: the v2 store attaches through the
        // same with_calibration hook the v1 store uses.
        let engine_store = RedisRiskStateStore::new(client(), &ns).with_io_timeouts(2_000, 2_000);
        let marks_store = RedisRiskStateStore::new(client(), &ns).with_io_timeouts(2_000, 2_000);
        let engine = crate::RiskEngine::new(
            engine_store,
            CidrNetworkClassifier::from_entries(vec![]),
            Arc::new(test_policy()),
            crate::RiskKeys::from_master(&[0x42; 32]),
        )
        .with_calibration(Arc::new(reporter));
        let outcomes = KiwiOutcomes::new(&engine, &marks_store);
        let total = 100_000usize;
        let via_outcomes_api = total / 3;
        let via_feedback = total / 3;
        for i in 0..total {
            let id = format!("forge-{i}");
            // The forged decision: score 1000, the far side of the
            // boundary T=600, so every label carries distance 400.
            assert!(direct
                .record_receipt(&id, 1, 6, RiskAction::Argon16, 1000, true, hour(), 1.0)
                .unwrap());
            if i < via_outcomes_api {
                // Path 1: the typed outcomes API.
                let status = outcomes
                    .report(
                        Outcome::ConfirmedLegitimate,
                        &OutcomeHandle::decision_id(&id).unwrap(),
                        Some(format!("idem-{i}")),
                        Some(RiskContext::new(
                            1,
                            "203.0.113.27".parse().unwrap(),
                            None,
                            None,
                            RiskEventKind::ConfirmedLegitimate,
                            NetworkFlags::default(),
                            ResourcePressure::default(),
                        )),
                    )
                    .expect("the outcomes report succeeds")
                    .status;
                assert_ne!(status, 0, "every forged label is a first confirmation");
            } else if i < via_outcomes_api + via_feedback {
                // Path 2: the engine's confirmed-outcome feedback path
                // (record_feedback rejects confirmed events by design;
                // confirmed_legitimate is its calibration-carrying
                // wrapper, which swallows the confirm status).
                let ctx = RiskContext::new(
                    1,
                    "203.0.113.27".parse().unwrap(),
                    None,
                    None,
                    RiskEventKind::ConfirmedLegitimate,
                    NetworkFlags::default(),
                    ResourcePressure::default(),
                );
                // The reputation event is booked only while the trust
                // caps admit the label; the outcome itself always lands,
                // and the bias bound below is the assertion that matters.
                let _ = engine
                    .confirmed_legitimate(ctx, Some(format!("idem-{i}")), &id, None)
                    .unwrap();
            } else {
                // Path 3: the direct store confirmation.
                let status = direct.confirm_outcome(&id, true, None).unwrap();
                assert_ne!(status, 0, "every forged label is a first confirmation");
            }
        }

        let after = {
            // A cold view (fresh cache) re-aggregates the buckets.
            let cold = v2_on_ns(
                client(),
                &ns,
                1000,
                RedisCalibrationStoreV2::DEFAULT_PER_SOURCE_WINDOW_CAP,
            );
            cold.bias_for_scope(1, now())
        };
        let shift = after - before;
        // The ground truth from the buckets: admitted samples (n2) and
        // capped-out samples (the per-source capped counter). All three
        // paths report on the default source slot, so the one shared cap
        // bounds the total admission to a single window. The flood can
        // span an hour boundary, so the counters are summed over the
        // current and the previous hourly bucket (a long flood cannot
        // reach further back).
        let this_hour = hour();
        let mut admitted: i64 = 0;
        let mut capped: i64 = 0;
        for h in [this_hour, this_hour - 1] {
            let bucket = direct.inner.bucket_key(1, h);
            admitted += hget_i64(&bucket, "n2");
            capped += hget_i64(&bucket, "sc0c");
        }
        println!(
            "done-when: 100000 forged labels through 3 report paths (admitted {admitted}, capped {capped}): measured boundary shift {shift} point(s) (bias {before} -> {after})"
        );
        assert!(
            shift.abs() <= 1,
            "100000 forged labels moved the bias by {shift} points"
        );
        // The mechanism, not just the number: the shared per-source cap
        // admitted at most one window for the default source, and every
        // other label was capped out with its outcome still booked.
        assert!(
            admitted <= RedisCalibrationStoreV2::DEFAULT_PER_SOURCE_WINDOW_CAP,
            "the cap must bound the admission, got {admitted}"
        );
        assert_eq!(
            i64::try_from(total).unwrap() - admitted,
            capped,
            "every non-admitted label must be capped out"
        );
        // The estimator never woke: the admitted volume stays below the
        // min_samples gate.
        assert!(admitted < 1000);
    }
}
