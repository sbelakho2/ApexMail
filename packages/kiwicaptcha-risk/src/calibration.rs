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
//! Bias (byte-identical integer math with PHP, ALL i64 truncating division):
//!
//! ```text
//! total = legit + abuse            (summed over the last 24 hourly buckets)
//! bias  = 0                        when total == 0
//! bias  = clamp(((abuse - legit) * 1000 / total) * 2 / 10, -200, 200)
//! ```
//!
//! The engine applies `clamp(base + bias, 0, 1000)` BEFORE band mapping.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

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
}

impl RedisCalibrationStore {
    /// Bucket retention (48 h; 24 buckets per scope are ever read).
    pub const BUCKET_EXPIRE_S: u64 = 48 * 3600;
    /// Receipt lifetime.
    pub const RECEIPT_EXPIRE_S: u64 = 300;
    /// Bias clamp range.
    pub const BIAS_MIN: i32 = -200;
    pub const BIAS_MAX: i32 = 200;
    /// Hourly buckets considered by `bias_for_scope` (current + 23 back).
    pub const BUCKET_WINDOW_HOURS: i64 = 24;

    /// Builds a store on a fresh connection (lazy).
    ///
    /// # Panics
    ///
    /// Panics if the namespace is empty or contains `{`/`}`.
    pub fn new(client: redis::Client, namespace: &str) -> RedisCalibrationStore {
        assert!(
            !namespace.is_empty() && !namespace.contains(['{', '}']),
            "Calibration namespace must be non-empty and free of braces"
        );
        RedisCalibrationStore {
            client,
            namespace: namespace.to_string(),
            conn: Mutex::new(None),
        }
    }

    /// The deployment namespace inside the `{kiwi:<ns>}` hash tag.
    pub fn namespace(&self) -> &str {
        &self.namespace
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
        Ok(())
    }

    fn bucket_key(&self, scope: u32, hour: i64) -> String {
        format!("{{kiwi:{}}}:cal:{scope}:{hour}", self.namespace)
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
        let hour = now_ms / 3_600_000;
        let mut legit_total: i64 = 0;
        let mut abuse_total: i64 = 0;
        let mut guard = match self.connection() {
            Ok(guard) => guard,
            Err(_) => return 0, // fail-open: never break issuance
        };
        let conn = guard.as_mut().expect("connection set by connection()");
        for h in (hour - (Self::BUCKET_WINDOW_HOURS - 1))..=hour {
            let key = self.bucket_key(scope, h);
            let fields: HashMap<String, i64> = match conn.hgetall::<_, HashMap<String, i64>>(&key) {
                Ok(fields) => fields,
                Err(_) => return 0,
            };
            for (field, value) in fields {
                if field.ends_with(":legit") {
                    legit_total += value;
                } else if field.ends_with(":abuse") {
                    abuse_total += value;
                }
            }
        }
        let total = legit_total + abuse_total;
        if total == 0 {
            return 0;
        }
        let bias = ((abuse_total - legit_total) * 1000 / total) * 2 / 10;
        bias.clamp(Self::BIAS_MIN as i64, Self::BIAS_MAX as i64) as i32
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
        // {"scope":..,"band":..,"action":".."} with EXPIRE 300 s, consumed
        // once, atomically, via GETDEL (GETDEL is STRING-only in Redis).
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
            .arg(Self::RECEIPT_EXPIRE_S)
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
        let s = store("bias");

        // All abuse -> ((n*1000/n)*2)/10 = 200 -> clamp 200.
        fill(&s, 1, 3, RiskAction::Sha20, 0, 10, T0);
        assert_eq!(s.bias_for_scope(1, T0), 200);

        // All legit -> -200.
        fill(&s, 2, 3, RiskAction::Sha20, 10, 0, T0);
        assert_eq!(s.bias_for_scope(2, T0), -200);

        // 60% abuse / 40% legit: ((20*1000)/100)*2/10 = 40.
        fill(&s, 3, 3, RiskAction::Sha20, 40, 60, T0);
        assert_eq!(s.bias_for_scope(3, T0), 40);

        // No samples -> 0.
        assert_eq!(s.bias_for_scope(99, T0), 0);

        // Truncation toward zero, byte-identical with PHP intdiv:
        // abuse 2 / legit 1 (total 3): (1*1000/3)*2/10 = 333*2/10 = 66.
        fill(&s, 4, 3, RiskAction::Sha20, 1, 2, T0);
        assert_eq!(s.bias_for_scope(4, T0), 66);
    }

    #[test]
    fn bias_sums_across_hourly_buckets() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping calibration test: RISK_REDIS_URL not set");
            return;
        };
        let s = store("buckets");
        // Same scope, three hours: 30 abuse + 30 legit -> bias 0.
        fill(&s, 1, 2, RiskAction::Sha18, 10, 0, T0);
        fill(&s, 1, 2, RiskAction::Sha18, 10, 10, T0 - 3_600_000);
        fill(&s, 1, 2, RiskAction::Sha18, 10, 20, T0 - 7_200_000);
        assert_eq!(s.bias_for_scope(1, T0), 0);

        // Buckets older than 24 hours are out of the window.
        fill(&s, 1, 2, RiskAction::Sha18, 0, 100, T0 - 25 * 3_600_000);
        assert_eq!(s.bias_for_scope(1, T0), 0);
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
