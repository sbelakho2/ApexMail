//! Outcome-feedback calibration: records whether scored requests were
//! legitimate (post-hoc, e.g. from support flags) and produces a bounded
//! bias adjustment per scope, added to the raw risk score.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::action::RiskAction;

/// One calibration sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalibrationEntry {
    pub scope: u16,
    pub band: u8,
    pub action: RiskAction,
    pub legitimate: bool,
    /// Epoch milliseconds.
    pub ts_ms: u64,
}

/// Outcome-feedback calibration store.
pub trait CalibrationStore {
    fn record(&self, entry: CalibrationEntry);
    /// Bias adjustment for a scope at `now_ms` (epoch milliseconds).
    fn bias_for_scope(&self, scope: u16, now_ms: u64) -> i16;
}

/// Aggregate calibrator implementing the bounded adjustment rules:
///
/// - retention: 24 h (samples are pruned on every record/bias read)
/// - minimum sample gate: 1000 per scope before any bias is computed
/// - bias range: -100..+150
/// - max change: 10 points per elapsed minute of application
/// - hysteresis: a new direction must hold for 10 minutes before it applies
///
/// Raw bias is derived from the legitimate rate:
/// `raw = round((0.5 - rate) * 300)`, clamped to the bias range (rate 0 ->
/// +150, rate 1 -> -100, rate 0.5 -> 0).
pub struct AggregateCalibrator {
    state: Mutex<CalibrationState>,
}

impl Default for AggregateCalibrator {
    fn default() -> AggregateCalibrator {
        AggregateCalibrator::new()
    }
}

impl AggregateCalibrator {
    pub const RETENTION_MS: u64 = 86_400_000;
    pub const MIN_SAMPLES: usize = 1000;
    pub const BIAS_MIN: i16 = -100;
    pub const BIAS_MAX: i16 = 150;
    pub const MAX_CHANGE_PER_MIN: i16 = 10;
    pub const HYSTERESIS_MS: u64 = 600_000;

    pub fn new() -> AggregateCalibrator {
        AggregateCalibrator {
            state: Mutex::new(CalibrationState::default()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Sample {
    ts_ms: u64,
    legitimate: bool,
}

#[derive(Debug, Clone, Copy)]
struct Applied {
    ts_ms: u64,
    bias: i16,
}

#[derive(Debug, Clone, Copy)]
struct Direction {
    ts_ms: u64,
    dir: std::cmp::Ordering,
}

#[derive(Default)]
struct CalibrationState {
    samples: HashMap<u16, Vec<Sample>>,
    applied: HashMap<u16, Applied>,
    direction: HashMap<u16, Direction>,
}

impl CalibrationStore for AggregateCalibrator {
    fn record(&self, entry: CalibrationEntry) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        prune(&mut state, entry.ts_ms);
        state.samples.entry(entry.scope).or_default().push(Sample {
            ts_ms: entry.ts_ms,
            legitimate: entry.legitimate,
        });
    }

    fn bias_for_scope(&self, scope: u16, now_ms: u64) -> i16 {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        prune(&mut state, now_ms);
        let samples = match state.samples.get(&scope) {
            Some(s) if s.len() >= Self::MIN_SAMPLES => s.clone(),
            _ => return 0,
        };

        let legit = samples.iter().filter(|s| s.legitimate).count();
        let rate = legit as f64 / samples.len() as f64;
        let raw = (((0.5 - rate) * 300.0).round() as i64)
            .clamp(Self::BIAS_MIN as i64, Self::BIAS_MAX as i64) as i16;

        let prev = state.applied.get(&scope).map_or(0, |a| a.bias);
        let dir = raw.cmp(&prev);

        if dir == std::cmp::Ordering::Equal {
            return prev;
        }

        let current = state.direction.get(&scope).copied();
        match current {
            None => {
                state
                    .direction
                    .insert(scope, Direction { ts_ms: now_ms, dir });
                return prev;
            }
            Some(cur) if cur.dir != dir => {
                state
                    .direction
                    .insert(scope, Direction { ts_ms: now_ms, dir });
                return prev;
            }
            Some(cur) => {
                if now_ms.saturating_sub(cur.ts_ms) < Self::HYSTERESIS_MS {
                    return prev;
                }
            }
        }

        let last_applied_ts = state
            .applied
            .get(&scope)
            .map_or(now_ms.saturating_sub(Self::HYSTERESIS_MS), |a| a.ts_ms);
        let elapsed_min = ((now_ms.saturating_sub(last_applied_ts) as f64) / 60_000.0).max(1.0);
        let allowed = (Self::MAX_CHANGE_PER_MIN as f64 * elapsed_min) as i64;
        let delta = ((raw as i64 - prev as i64).clamp(-allowed, allowed)) as i16;
        let next = prev
            .saturating_add(delta)
            .clamp(Self::BIAS_MIN, Self::BIAS_MAX);

        state.applied.insert(
            scope,
            Applied {
                ts_ms: now_ms,
                bias: next,
            },
        );
        next
    }
}

fn prune(state: &mut CalibrationState, now_ms: u64) {
    let cutoff = now_ms.saturating_sub(AggregateCalibrator::RETENTION_MS);
    state.samples.retain(|_scope, list| {
        list.retain(|s| s.ts_ms > cutoff);
        !list.is_empty()
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(scope: u16, ts_ms: u64, legitimate: bool) -> CalibrationEntry {
        CalibrationEntry {
            scope,
            band: 0,
            action: RiskAction::Allow,
            legitimate,
            ts_ms,
        }
    }

    fn fill(cal: &AggregateCalibrator, scope: u16, ts_ms: u64, legit: bool, n: usize) {
        for i in 0..n {
            cal.record(entry(scope, ts_ms + i as u64, legit));
        }
    }

    #[test]
    fn sample_gate() {
        let cal = AggregateCalibrator::new();
        fill(&cal, 1, 1_000_000, false, 999);
        assert_eq!(cal.bias_for_scope(1, 1_000_000), 0);
        fill(&cal, 1, 1_000_000, false, 1);
        // 1000 samples arm the direction; the value still needs the
        // hysteresis window and the per-minute change cap.
        assert_eq!(cal.bias_for_scope(1, 1_000_000), 0);
        assert_ne!(
            cal.bias_for_scope(1, 1_000_000 + AggregateCalibrator::HYSTERESIS_MS),
            0
        );
    }

    #[test]
    fn bias_bounds() {
        let t0 = 1_000_000u64;
        // All-abuse: rate 0 -> raw +150 (capped by BIAS_MAX).
        let cal = AggregateCalibrator::new();
        fill(&cal, 1, t0, false, 1000);
        assert_eq!(cal.bias_for_scope(1, t0), 0); // arm
                                                  // First jump capped at 100 (10/min x 10 min), then +10/min to 150.
        assert_eq!(
            cal.bias_for_scope(1, t0 + AggregateCalibrator::HYSTERESIS_MS),
            100
        );
        assert_eq!(
            cal.bias_for_scope(1, t0 + AggregateCalibrator::HYSTERESIS_MS + 5 * 60_000),
            150
        );

        // All-legit: rate 1 -> raw -150 -> clamped to -100.
        let cal = AggregateCalibrator::new();
        fill(&cal, 2, t0, true, 1000);
        assert_eq!(cal.bias_for_scope(2, t0), 0); // arm
        assert_eq!(
            cal.bias_for_scope(2, t0 + AggregateCalibrator::HYSTERESIS_MS),
            -100
        );
    }

    #[test]
    fn direction_must_hold_for_hysteresis_window() {
        let cal = AggregateCalibrator::new();
        let t0 = 1_000_000u64;
        fill(&cal, 1, t0, false, 1000); // raw = +150

        // First read arms the direction but does not apply.
        assert_eq!(cal.bias_for_scope(1, t0), 0);
        // Inside the window: still held.
        assert_eq!(
            cal.bias_for_scope(1, t0 + AggregateCalibrator::HYSTERESIS_MS - 1),
            0
        );
        // Window passed: applies with the max-change cap (10 * 10 min = 100).
        assert_eq!(
            cal.bias_for_scope(1, t0 + AggregateCalibrator::HYSTERESIS_MS),
            100
        );
    }

    #[test]
    fn max_change_per_minute() {
        let cal = AggregateCalibrator::new();
        let t0 = 1_000_000u64;
        fill(&cal, 1, t0, false, 1000); // raw = +150

        assert_eq!(cal.bias_for_scope(1, t0), 0); // arm
                                                  // Apply at t0 + 10 min: allowed = 10 * 10 = 100.
        assert_eq!(
            cal.bias_for_scope(1, t0 + AggregateCalibrator::HYSTERESIS_MS),
            100
        );
        // One minute later: allowed = 10 -> 110.
        assert_eq!(
            cal.bias_for_scope(1, t0 + AggregateCalibrator::HYSTERESIS_MS + 60_000),
            110
        );
        // Two more minutes: 10/min -> 120, 130.
        assert_eq!(
            cal.bias_for_scope(1, t0 + AggregateCalibrator::HYSTERESIS_MS + 120_000),
            120
        );
        assert_eq!(
            cal.bias_for_scope(1, t0 + AggregateCalibrator::HYSTERESIS_MS + 180_000),
            130
        );

        // Bias never exceeds the +150 cap.
        let mut t = t0 + AggregateCalibrator::HYSTERESIS_MS + 180_000;
        let mut bias = 130;
        for _ in 0..10 {
            t += 60_000;
            bias = cal.bias_for_scope(1, t);
        }
        assert_eq!(bias, 150);
    }

    #[test]
    fn direction_reversal_restarts_hysteresis() {
        let cal = AggregateCalibrator::new();
        let t0 = 1_000_000u64;
        // 1000 abuse-only samples: raw +150.
        fill(&cal, 2, t0, false, 1000);
        assert_eq!(cal.bias_for_scope(2, t0), 0); // arm
                                                  // Apply after the window (capped at 100).
        assert_eq!(
            cal.bias_for_scope(2, t0 + AggregateCalibrator::HYSTERESIS_MS),
            100
        );
        // Add 1000 legit samples -> rate 0.5 -> raw 0, direction flips down.
        let flip = t0 + AggregateCalibrator::HYSTERESIS_MS + 1;
        fill(&cal, 2, flip, true, 1000);
        // Flip arms a new direction window; no change yet.
        assert_eq!(cal.bias_for_scope(2, flip), 100);
        // Inside the new window: still held at 100.
        assert_eq!(
            cal.bias_for_scope(2, flip + AggregateCalibrator::HYSTERESIS_MS - 1),
            100
        );
        // After the window the direction applies: raw 0 from prev 100 ->
        // delta -100 (allowed = 10/min x 10 min).
        assert_eq!(
            cal.bias_for_scope(2, flip + AggregateCalibrator::HYSTERESIS_MS),
            0
        );
    }

    #[test]
    fn retention_prunes_old_samples() {
        let cal = AggregateCalibrator::new();
        let t0 = 1_000_000u64;
        fill(&cal, 1, t0, false, 1000);
        assert_eq!(cal.bias_for_scope(1, t0), 0); // arm
        assert_eq!(
            cal.bias_for_scope(1, t0 + AggregateCalibrator::HYSTERESIS_MS),
            100
        );
        // 25 hours later everything is pruned: back below the gate.
        let late = t0 + 25 * 3_600_000;
        assert_eq!(cal.bias_for_scope(1, late), 0);
        // Recording one fresh sample keeps only the fresh one.
        cal.record(entry(1, late + 1, false));
        assert_eq!(cal.bias_for_scope(1, late + 1), 0);
        // And the retained sample list is small again.
        let state = cal.state.lock().unwrap();
        assert!(state.samples.get(&1).map_or(0, |s| s.len()) <= 2);
    }
}
