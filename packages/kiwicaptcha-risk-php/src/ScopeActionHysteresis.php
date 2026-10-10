<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * Per-process, bounded, TTL'd map of the last score-selected action per
 * scope and client pseudonym, giving the scope action selection enter/exit
 * hysteresis: a score hovering at a band boundary (449/451/449…) can no
 * longer flip the challenge profile on every request.
 *
 * Rules (mirrored on the Rust side; the representations differ):
 *   - entries are keyed by scope and client: the client key is the
 *     session pseudonym when present, else the source pseudonym.
 *   - Thresholds reuse the plain band boundaries: enter[i] = upper[i] + 10
 *     and exit[i] = lower[i] − 10.
 *   - A request whose own score clears the target band margin selects the
 *     plain action directly: escalation when score >= lower[plain] + 10,
 *     drop when score <= upper[plain] − 10.
 *   - Otherwise a previous ladder action at band i escalates when
 *     score >= enter[i] and de-escalates when score < exit[i]. The edge
 *     fallback targets the plain band of the score just inside the
 *     margin: actionForScore(score − 10) when escalating and
 *     actionForScore(score + 10) when dropping. A sustained edge
 *     crossing can therefore clear several ladder bands at once
 *     instead of stepping one band at a time.
 *   - A fresh key (no previous action, or an expired entry) uses the
 *     plain band mapping.
 *   - The hard actions (StepUp/Deny) are not hysteresis-affected: when the
 *     previous or the plain action is StepUp/Deny the plain mapping wins.
 *   - Entries expire after TTL_MS (300 s); the map is bounded at 1024
 *     entries, the least-recently-used entry evicted when a new key
 *     arrives at capacity (expired entries are purged first).
 *
 * Keying is per client, so one client's band history never steers another
 * client's action. The map lives on the engine instance, which is normally
 * rebuilt per request, so under PHP-FPM (long-lived workers) smoothing does
 * not cross requests; a worker that reuses one engine instance across
 * requests keeps the map. The authoritative global state stays in Redis.
 */
final class ScopeActionHysteresis
{
    /** Entry lifetime: 300 s. */
    public const TTL_MS = 300_000;

    /** Bounded map: at most 1024 entries; the least-recently-used entry is evicted. */
    public const MAX_ENTRIES = 1024;

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

    /** @var array<string, array{action: RiskAction, updated: int}> */
    private array $lastActions = [];

    /**
     * Selects the action for one client in one scope with enter/exit
     * hysteresis and remembers the selection as that key's new last
     * action. The stored action is the score-selected one: a later
     * Deny/StepUp hard override never poisons the profile.
     */
    public function select(int $scope, string $clientKey, int $score, RiskAction $plain, int $nowMs): RiskAction
    {
        $action = $plain;
        $previous = $this->lastAction($scope, $clientKey, $nowMs);
        $rank = $previous?->rank() ?? -1;
        $topRank = count(self::LADDER) - 1;
        if ($rank >= 0 && $rank <= $topRank && $plain->rank() <= $topRank) {
            $plainRank = $plain->rank();
            if ($plainRank > $rank && $score >= self::BANDS[$plainRank][0] + 10) {
                // The score clears the target band margin: jump.
                $action = $plain;
            } elseif ($plainRank < $rank && $score <= self::BANDS[$plainRank][1] - 10) {
                // The score clears the target band exit margin: jump.
                $action = $plain;
            } else {
                [$lower, $upper] = self::BANDS[$rank];
                if ($rank < $topRank && $score >= $upper + 10) {
                    // Edge escalation: the plain band of the score just
                    // below the margin (score - 10), which can clear
                    // several ladder bands at once — never a fixed +/- 1
                    // band step. score >= upper + 10 >= 160, so the
                    // subtraction cannot underflow.
                    $action = RiskAction::actionForScore($score - 10);
                } elseif ($rank > 0 && $score < $lower - 10) {
                    // Edge drop: the plain band of the score just above
                    // the margin (score + 10). score < lower - 10 <= 140,
                    // so the addition cannot overflow.
                    $action = RiskAction::actionForScore($score + 10);
                } else {
                    $action = $previous;
                }
            }
        }
        $this->remember($scope, $clientKey, $action, $nowMs);

        return $action;
    }

    /**
     * The client's last action in the scope when its entry is still within
     * TTL; expired entries are evicted on access.
     */
    public function lastAction(int $scope, string $clientKey, int $nowMs): ?RiskAction
    {
        $key = self::key($scope, $clientKey);
        $entry = $this->lastActions[$key] ?? null;
        if ($entry === null) {
            return null;
        }
        if ($nowMs - $entry['updated'] > self::TTL_MS) {
            unset($this->lastActions[$key]);

            return null;
        }

        return $entry['action'];
    }

    /**
     * Remembers the client's last action: expired entries are purged first
     * and, when the map is at capacity, the single oldest entry is
     * evicted.
     */
    public function remember(int $scope, string $clientKey, RiskAction $action, int $nowMs): void
    {
        $key = self::key($scope, $clientKey);
        $isNew = !isset($this->lastActions[$key]);
        if ($isNew && count($this->lastActions) >= self::MAX_ENTRIES) {
            $this->evict($nowMs);
        }
        $this->lastActions[$key] = ['action' => $action, 'updated' => $nowMs];
    }

    /** Current number of tracked entries (tests/metrics). */
    public function count(): int
    {
        return count($this->lastActions);
    }

    private static function key(int $scope, string $clientKey): string
    {
        return $scope . ':' . $clientKey;
    }

    private function evict(int $nowMs): void
    {
        foreach (array_keys($this->lastActions) as $key) {
            if ($nowMs - $this->lastActions[$key]['updated'] > self::TTL_MS) {
                unset($this->lastActions[$key]);
            }
        }
        if (count($this->lastActions) < self::MAX_ENTRIES) {
            return;
        }
        $oldestKey = null;
        $oldestUpdated = PHP_INT_MAX;
        foreach ($this->lastActions as $key => $entry) {
            if ($entry['updated'] < $oldestUpdated) {
                $oldestUpdated = $entry['updated'];
                $oldestKey = $key;
            }
        }
        unset($this->lastActions[$oldestKey]);
    }
}
