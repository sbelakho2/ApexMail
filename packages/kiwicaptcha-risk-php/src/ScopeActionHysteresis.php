<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * Per-process, bounded, TTL'd map of the LAST score-selected action per
 * scope, giving the SCOPE action selection enter/exit hysteresis: a score hovering at a band boundary (449/451/449…) can no longer flip the
 * challenge profile on every request.
 *
 * Rules (byte-identical on the Rust side):
 *   - thresholds reuse the plain band boundaries: ENTER[i] = upper[i] + 10,
 *     EXIT[i] = lower[i] − 10;
 *   - with a previous ladder action at band i the action escalates to band
 *     i+1 only when score >= ENTER[i], de-escalates to band i−1 only when
 *     score < EXIT[i], and otherwise STAYS in band i;
 *   - a fresh scope (no previous action, or an expired entry) uses the
 *     plain band mapping;
 *   - the hard actions (StepUp/Deny) are NOT hysteresis-affected: when the
 *     previous or the plain action is StepUp/Deny the plain mapping wins;
 *   - entries expire after TTL_MS (300 s); the map is bounded at
 *     MAX_SCOPES (1024), the least-recently-used entry evicted when a NEW scope arrives
 *     at capacity (expired entries are purged first).
 *
 * The map is intentionally PER-PROCESS (the engine service is a per-worker
 * singleton, so the instance lives for the worker's lifetime): multi-worker
 * deployments may see slight per-process differences — an acceptable
 * UX-smoothing trade-off. The authoritative global state stays in Redis.
 */
final class ScopeActionHysteresis
{
    /** Entry lifetime: 300 s. */
    public const TTL_MS = 300_000;

    /** Bounded map: at most 1024 scopes; the least-recently-used entry is evicted. */
    public const MAX_SCOPES = 1024;

    /**
     * The hysteresis ladder (ranks 0..6): StepUp and Deny are hard actions
     * and never participate in the hold logic.
     *
     * @var list<RiskAction>
     */
    private const LADDER = [
        RiskAction::Allow,
        RiskAction::Sha16,
        RiskAction::Sha18,
        RiskAction::Sha20,
        RiskAction::Argon16,
        RiskAction::Argon32,
        RiskAction::Argon64,
    ];

    /**
     * Plain band boundaries [lower, upper) per ladder rank, mirroring
     * RiskAction::actionForScore() (pinned by a parity test).
     *
     * @var array<int, array{0: int, 1: int}>
     */
    private const BANDS = [
        0 => [0, 150],
        1 => [150, 300],
        2 => [300, 450],
        3 => [450, 600],
        4 => [600, 750],
        5 => [750, 850],
        6 => [850, 930],
    ];

    /** @var array<int, array{action: RiskAction, updated: int}> */
    private array $lastActions = [];

    /**
     * Selects the scope's action with enter/exit hysteresis and remembers
     * the selection as the scope's new LAST ACTION (the score-selected
     * action — a later Deny/StepUp hard override never poisons the
     * profile).
     */
    public function select(int $scope, int $score, RiskAction $plain, int $nowMs): RiskAction
    {
        $action = $plain;
        $previous = $this->lastAction($scope, $nowMs);
        $rank = $previous?->rank() ?? -1;
        $topRank = count(self::LADDER) - 1;
        if ($rank >= 0 && $rank <= $topRank && $plain->rank() <= $topRank) {
            [$lower, $upper] = self::BANDS[$rank];
            if ($rank < $topRank && $score >= $upper + 10) {
                $action = self::LADDER[$rank + 1];
            } elseif ($rank > 0 && $score < $lower - 10) {
                $action = self::LADDER[$rank - 1];
            } else {
                $action = $previous;
            }
        }
        $this->remember($scope, $action, $nowMs);
        return $action;
    }

    /**
     * The scope's last action when its entry is still within TTL; expired
     * entries are evicted on access.
     */
    public function lastAction(int $scope, int $nowMs): ?RiskAction
    {
        $entry = $this->lastActions[$scope] ?? null;
        if ($entry === null) {
            return null;
        }
        if ($nowMs - $entry['updated'] > self::TTL_MS) {
            unset($this->lastActions[$scope]);
            return null;
        }
        return $entry['action'];
    }

    /**
     * Remembers the scope's last action: expired entries are purged first
     * and, when the map is at capacity, the single oldest entry is
     * evicted.
     */
    public function remember(int $scope, RiskAction $action, int $nowMs): void
    {
        $isNew = !isset($this->lastActions[$scope]);
        if ($isNew && count($this->lastActions) >= self::MAX_SCOPES) {
            $this->evict($nowMs);
        }
        $this->lastActions[$scope] = ['action' => $action, 'updated' => $nowMs];
    }

    /** Current number of tracked scopes (tests/metrics). */
    public function count(): int
    {
        return count($this->lastActions);
    }

    private function evict(int $nowMs): void
    {
        foreach (array_keys($this->lastActions) as $scope) {
            if ($nowMs - $this->lastActions[$scope]['updated'] > self::TTL_MS) {
                unset($this->lastActions[$scope]);
            }
        }
        if (count($this->lastActions) < self::MAX_SCOPES) {
            return;
        }
        $oldestScope = null;
        $oldestUpdated = PHP_INT_MAX;
        foreach ($this->lastActions as $scope => $entry) {
            if ($entry['updated'] < $oldestUpdated) {
                $oldestUpdated = $entry['updated'];
                $oldestScope = $scope;
            }
        }
        unset($this->lastActions[$oldestScope]);
    }
}
