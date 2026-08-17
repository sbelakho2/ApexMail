//! Per-process, bounded, TTL'd map of the LAST score-selected action per
//! scope, giving the SCOPE action selection enter/exit hysteresis: a score
//! hovering at a band boundary (449/451/449…) can no
//! longer flip the challenge profile on every request.
//!
//! Rules (byte-identical with the PHP `ScopeActionHysteresis`):
//!   - thresholds reuse the plain band boundaries: `ENTER[i] = upper[i] +
//!     10`, `EXIT[i] = lower[i] − 10`;
//!   - with a previous ladder action at band `i` the action escalates to
//!     band `i+1` only when `score >= ENTER[i]`, de-escalates to band
//!     `i−1` only when `score < EXIT[i]`, and otherwise STAYS in band `i`;
//!   - a fresh scope (no previous action, or an expired entry) uses the
//!     plain band mapping;
//!   - the hard actions (StepUp/Deny) are NOT hysteresis-affected: when
//!     the previous or the plain action is StepUp/Deny the plain mapping
//!     wins;
//!   - entries expire after [`TTL_MS`] (300 s); the map is bounded at
//!     [`MAX_SCOPES`] (1024), the least-recently-used entry evicted when a NEW scope
//!     arrives at capacity (expired entries are purged first).
//!
//! The map is intentionally PER-PROCESS (one engine per process in server
//! deployments): multi-worker deployments may see slight per-process
//! differences — an acceptable UX-smoothing trade-off. The authoritative
//! global state stays in Redis.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::action::RiskAction;

#[derive(Debug, Clone, Copy)]
struct Entry {
    action: RiskAction,
    updated_ms: u64,
}

/// See the module docs for the exact hysteresis rules.
#[derive(Debug, Default)]
pub struct ScopeActionHysteresis {
    inner: Mutex<HashMap<u32, Entry>>,
}

impl ScopeActionHysteresis {
    /// Entry lifetime: 300 s.
    pub const TTL_MS: u64 = 300_000;

    /// Bounded map: at most 1024 scopes; the least-recently-used entry is evicted.
    pub const MAX_SCOPES: usize = 1024;

    /// The hysteresis ladder (ranks 0..6): StepUp and Deny are hard actions
    /// and never participate in the hold logic.
    const LADDER: [RiskAction; 7] = [
        RiskAction::Allow,
        RiskAction::Sha16,
        RiskAction::Sha18,
        RiskAction::Sha20,
        RiskAction::Argon16,
        RiskAction::Argon32,
        RiskAction::Argon64,
    ];

    /// Plain band boundaries `(lower, upper)` per ladder rank, mirroring
    /// [`RiskAction::action_for_score`] (pinned by a parity test).
    const BANDS: [(u16, u16); 7] = [
        (0, 150),
        (150, 300),
        (300, 450),
        (450, 600),
        (600, 750),
        (750, 850),
        (850, 930),
    ];

    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Selects the scope's action with enter/exit hysteresis and remembers
    /// the selection as the scope's new LAST ACTION (the score-selected
    /// action — a later Deny/StepUp hard override never poisons the
    /// profile).
    pub fn select(&self, scope: u32, score: u16, plain: RiskAction, now_ms: u64) -> RiskAction {
        let mut map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let previous = map
            .get(&scope)
            .copied()
            .filter(|e| now_ms.saturating_sub(e.updated_ms) <= Self::TTL_MS);
        let action = match previous {
            Some(prev)
                if (prev.action.rank() as usize) < Self::LADDER.len()
                    && (plain.rank() as usize) < Self::LADDER.len() =>
            {
                let rank = prev.action.rank() as usize;
                let (lower, upper) = Self::BANDS[rank];
                if rank < Self::LADDER.len() - 1 && score >= upper + 10 {
                    Self::LADDER[rank + 1]
                } else if rank > 0 && score < lower - 10 {
                    Self::LADDER[rank - 1]
                } else {
                    prev.action
                }
            }
            _ => plain,
        };
        if !map.contains_key(&scope) && map.len() >= Self::MAX_SCOPES {
            Self::evict(&mut map, now_ms);
        }
        map.insert(
            scope,
            Entry {
                action,
                updated_ms: now_ms,
            },
        );
        action
    }

    /// Current number of tracked scopes (tests/metrics).
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty()
    }

    /// Purges expired entries; when still at capacity, evicts the single
    /// oldest entry.
    fn evict(map: &mut HashMap<u32, Entry>, now_ms: u64) {
        map.retain(|_, e| now_ms.saturating_sub(e.updated_ms) <= Self::TTL_MS);
        if map.len() < Self::MAX_SCOPES {
            return;
        }
        let oldest = map
            .iter()
            .min_by_key(|(_, e)| e.updated_ms)
            .map(|(scope, _)| *scope);
        if let Some(scope) = oldest {
            map.remove(&scope);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_700_000_000_000;

    #[test]
    fn bands_mirror_action_for_score() {
        for (rank, (lower, upper)) in ScopeActionHysteresis::BANDS.iter().enumerate() {
            assert_eq!(
                RiskAction::action_for_score(*lower),
                ScopeActionHysteresis::LADDER[rank],
                "lower boundary of rank {rank}"
            );
            if rank < ScopeActionHysteresis::LADDER.len() - 1 {
                assert_eq!(
                    RiskAction::action_for_score(upper - 1),
                    ScopeActionHysteresis::LADDER[rank],
                    "inside band of rank {rank}"
                );
                assert_eq!(
                    RiskAction::action_for_score(*upper),
                    ScopeActionHysteresis::LADDER[rank + 1],
                    "upper boundary of rank {rank} enters the next band"
                );
            }
        }
    }

    #[test]
    fn oscillating_score_produces_stable_action() {
        // The audit's exact example: 49/51/49/51 — entirely inside the
        // Allow band [0,150): no flip-flop possible, always Allow.
        let h = ScopeActionHysteresis::new();
        for (i, score) in [49u16, 51, 49, 51].iter().enumerate() {
            assert_eq!(
                h.select(
                    1,
                    *score,
                    RiskAction::action_for_score(*score),
                    T0 + i as u64
                ),
                RiskAction::Allow
            );
        }

        // The REAL boundary oscillation (the 450 edge): 449 is Sha18,
        // 451 would be Sha20 under the plain mapping — the previous action
        // must hold Sha18 (451 < ENTER[Sha18] = 460) so the profile NEVER
        // flips.
        let h = ScopeActionHysteresis::new();
        for (i, score) in [449u16, 451, 449, 451, 449, 451].iter().enumerate() {
            assert_eq!(
                h.select(
                    1,
                    *score,
                    RiskAction::action_for_score(*score),
                    T0 + i as u64
                ),
                RiskAction::Sha18,
                "iteration {i}: an oscillating boundary score must not flip the profile"
            );
        }
    }

    #[test]
    fn sustained_crossing_enters_the_higher_action() {
        let h = ScopeActionHysteresis::new();
        let mut now = T0;
        // 449 -> Sha18; a brief tick to 455 (plain Sha20) is still inside
        // [EXIT[Sha18]=290, ENTER[Sha18]=460): held.
        assert_eq!(h.select(1, 449, RiskAction::Sha18, now), RiskAction::Sha18);
        now += 1;
        assert_eq!(h.select(1, 455, RiskAction::Sha20, now), RiskAction::Sha18);
        now += 1;
        // Sustained crossing: 480 >= ENTER[Sha18]=460 -> Sha20, then held.
        assert_eq!(h.select(1, 480, RiskAction::Sha20, now), RiskAction::Sha20);
        now += 1;
        assert_eq!(h.select(1, 480, RiskAction::Sha20, now), RiskAction::Sha20);
        now += 1;
        // Still inside [EXIT[Sha20]=440, ENTER[Sha20]=610): held even at
        // 590 (plain Argon16) — escalation needs a sustained crossing.
        assert_eq!(
            h.select(1, 590, RiskAction::Argon16, now),
            RiskAction::Sha20
        );
        now += 1;
        assert_eq!(
            h.select(1, 590, RiskAction::Argon16, now),
            RiskAction::Sha20
        );
        now += 1;
        // 620 >= ENTER[Sha20]=610 -> Argon16, then held.
        assert_eq!(
            h.select(1, 620, RiskAction::Argon16, now),
            RiskAction::Argon16
        );
        now += 1;
        assert_eq!(
            h.select(1, 620, RiskAction::Argon16, now),
            RiskAction::Argon16
        );
    }

    #[test]
    fn sustained_drop_exits_the_higher_action() {
        let h = ScopeActionHysteresis::new();
        let mut now = T0;
        // Climb to Sha20 (480), then drop: 441 is still >= EXIT[Sha20]=440
        // -> held; 439 < 440 -> Sha18; 250 < EXIT[Sha18]=290 -> Sha16, then
        // held (250 >= EXIT[Sha16]=140).
        assert_eq!(h.select(1, 480, RiskAction::Sha20, now), RiskAction::Sha20);
        now += 1;
        assert_eq!(h.select(1, 441, RiskAction::Sha20, now), RiskAction::Sha20);
        now += 1;
        assert_eq!(h.select(1, 439, RiskAction::Sha18, now), RiskAction::Sha18);
        now += 1;
        assert_eq!(h.select(1, 250, RiskAction::Sha16, now), RiskAction::Sha16);
        now += 1;
        assert_eq!(h.select(1, 250, RiskAction::Sha16, now), RiskAction::Sha16);
        now += 1;
        // Below EXIT[Sha16]=140 -> Allow.
        assert_eq!(h.select(1, 100, RiskAction::Allow, now), RiskAction::Allow);
    }

    #[test]
    fn fresh_scope_uses_plain_mapping() {
        // Every score on a fresh scope must equal RiskAction::action_for_score.
        for score in 0..=1000u16 {
            let fresh = ScopeActionHysteresis::new();
            assert_eq!(
                fresh.select(1, score, RiskAction::action_for_score(score), T0),
                RiskAction::action_for_score(score),
                "fresh scope must use the plain mapping at score {score}"
            );
        }
    }

    #[test]
    fn hard_override_actions_are_not_hysteresis_affected() {
        let h = ScopeActionHysteresis::new();
        let mut now = T0;
        // Deny (plain, score 980) then a 500: the previous action is Deny —
        // NOT hysteresis-affected, the plain mapping applies (Sha20).
        assert_eq!(h.select(1, 980, RiskAction::Deny, now), RiskAction::Deny);
        now += 1;
        assert_eq!(h.select(1, 500, RiskAction::Sha20, now), RiskAction::Sha20);
        now += 1;
        // StepUp (plain, score 930) then a 500: plain mapping again.
        assert_eq!(
            h.select(1, 930, RiskAction::StepUp, now),
            RiskAction::StepUp
        );
        now += 1;
        assert_eq!(h.select(1, 500, RiskAction::Sha20, now), RiskAction::Sha20);
        now += 1;
        // A ladder previous action with a HARD plain action: the hard
        // action wins immediately (never held in the lower band).
        assert_eq!(h.select(1, 500, RiskAction::Sha20, now), RiskAction::Sha20);
        now += 1;
        assert_eq!(h.select(1, 980, RiskAction::Deny, now), RiskAction::Deny);
        now += 1;
        assert_eq!(
            h.select(1, 930, RiskAction::StepUp, now),
            RiskAction::StepUp
        );
    }

    #[test]
    fn ttl_expiry_forgets_the_scope() {
        // Inside TTL the previous action holds (no flip).
        let h = ScopeActionHysteresis::new();
        assert_eq!(h.select(1, 449, RiskAction::Sha18, T0), RiskAction::Sha18);
        assert_eq!(
            h.select(
                1,
                451,
                RiskAction::Sha20,
                T0 + ScopeActionHysteresis::TTL_MS - 1
            ),
            RiskAction::Sha18,
            "inside TTL the previous action must hold"
        );

        // Past TTL (300 s since the last decision): the entry is gone, the
        // scope is fresh again and the plain mapping applies (Sha20).
        let h = ScopeActionHysteresis::new();
        assert_eq!(h.select(1, 449, RiskAction::Sha18, T0), RiskAction::Sha18);
        assert_eq!(
            h.select(
                1,
                451,
                RiskAction::Sha20,
                T0 + ScopeActionHysteresis::TTL_MS + 1
            ),
            RiskAction::Sha20,
            "after TTL the boundary score must fall back to the plain mapping"
        );
        assert_eq!(h.len(), 1, "the fresh selection re-inserts one entry");
    }

    #[test]
    fn bounded_map_evicts_the_oldest_entry() {
        let h = ScopeActionHysteresis::new();
        for scope in 1..=ScopeActionHysteresis::MAX_SCOPES as u32 {
            h.select(scope, 100, RiskAction::Allow, T0 + scope as u64);
        }
        assert_eq!(h.len(), ScopeActionHysteresis::MAX_SCOPES);

        // A NEW scope at capacity evicts the least-recently-used entry (scope 1).
        let new_scope = ScopeActionHysteresis::MAX_SCOPES as u32 + 1;
        h.select(new_scope, 100, RiskAction::Allow, T0 + 100_000);
        assert_eq!(
            h.len(),
            ScopeActionHysteresis::MAX_SCOPES,
            "the map must stay bounded"
        );
        // Scope 1 was evicted: it is fresh again (plain mapping at 449 =
        // Sha18), while the new scope is tracked.
        assert_eq!(
            h.select(1, 449, RiskAction::Sha18, T0 + 100_001),
            RiskAction::Sha18,
            "the least-recently-used entry must be evicted"
        );
        assert_eq!(h.len(), ScopeActionHysteresis::MAX_SCOPES);
    }

    #[test]
    fn expired_entries_are_purged_before_eviction() {
        let h = ScopeActionHysteresis::new();
        for scope in 1..=ScopeActionHysteresis::MAX_SCOPES as u32 {
            h.select(scope, 100, RiskAction::Allow, T0 + scope as u64);
        }
        // All entries expired long ago: the purge alone makes room.
        let new_scope = ScopeActionHysteresis::MAX_SCOPES as u32 + 1;
        h.select(new_scope, 100, RiskAction::Allow, T0 + 10_000_000);
        assert_eq!(h.len(), 1, "expired entries are purged before eviction");
        assert_eq!(
            h.select(1, 100, RiskAction::Allow, T0 + 10_000_001),
            RiskAction::Allow
        );
    }
}
