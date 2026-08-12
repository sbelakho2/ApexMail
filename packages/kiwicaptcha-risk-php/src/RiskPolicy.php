<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * Immutable policy snapshot used to turn a risk score into an action.
 *
 * Configuration shape:
 *   [
 *     'version' => int,
 *     'weights' => [...13 snake_case weights...],
 *     'scopes' => [
 *        <int scope> => [
 *          'base_risk' => int,
 *          'minimum' => 'allow'|'sha16'|...,        // RiskAction string
 *          'post_solve_check' => bool,
 *          'degraded' => 'allow'|...,               // RiskAction string
 *        ],
 *     ],
 *     'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
 *   ]   (index 0 must be 'allow'; levels 1..4 valid actions; missing
 *         levels 1..4 default from DEFAULT_GLOBAL_FLOORS)
 *
 * The `hash` is sha256 of the canonical JSON of the config (recursively
 * key-sorted, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE).
 */
final class RiskPolicy
{
    /** The policy contract version this implementation parses. */
    public const CONTRACT_VERSION = 3;

    public const DEFAULT_GLOBAL_FLOORS = [
        1 => RiskAction::Sha16,
        2 => RiskAction::Sha18,
        3 => RiskAction::Sha20,
        4 => RiskAction::Sha20,
    ];

    /**
     * @param array<int, array{base_risk:int, minimum:RiskAction, post_solve_check:bool, degraded:RiskAction}> $scopes
     * @param array<int, RiskAction> $globalFloors
     */
    private function __construct(
        public readonly int $version,
        public readonly string $hash,
        public readonly RiskWeights $weights,
        public readonly array $scopes,
        public readonly array $globalFloors,
    ) {
    }

    /**
     * Parses and VALIDATES a policy config. Rejects: a version that does
     * not match the requested (default: contract) version, base_risk
     * outside 0..1000, scope ids outside 1..4294967295, and global_floors
     * that are not exactly 5 actions (index 0 = Allow, entries 1..4 valid
     * actions). Enforced in the parser itself, not only in the Symfony
     * config layer.
     */
    public static function fromConfig(array $config, int $version = self::CONTRACT_VERSION): self
    {
        if (!isset($config['version']) || !is_int($config['version'])) {
            throw new \InvalidArgumentException('Policy config requires an int "version"');
        }
        if ($config['version'] !== $version) {
            throw new \InvalidArgumentException(sprintf(
                'Unsupported policy version %d (expected %d)',
                $config['version'],
                $version
            ));
        }
        if (!isset($config['weights']) || !is_array($config['weights'])) {
            throw new \InvalidArgumentException('Policy config requires a "weights" array');
        }
        if (!isset($config['scopes']) || !is_array($config['scopes'])) {
            throw new \InvalidArgumentException('Policy config requires a "scopes" array');
        }

        $scopes = [];
        foreach ($config['scopes'] as $scope => $spec) {
            $scope = (int) $scope;
            if ($scope < 1 || $scope > 4294967295) {
                throw new \InvalidArgumentException(
                    sprintf('Scope id %d must be within 1..4294967295', $scope)
                );
            }
            if (!isset($spec['base_risk'], $spec['minimum'], $spec['degraded']) || !array_key_exists('post_solve_check', $spec)) {
                throw new \InvalidArgumentException(
                    sprintf('Scope %d requires base_risk, minimum, post_solve_check and degraded', $scope)
                );
            }
            $baseRisk = $spec['base_risk'];
            if (!is_int($baseRisk) || $baseRisk < 0 || $baseRisk > 1000) {
                throw new \InvalidArgumentException(
                    sprintf('Scope %d base_risk must be an int within 0..1000', $scope)
                );
            }
            $scopes[$scope] = [
                'base_risk' => $baseRisk,
                'minimum' => RiskAction::from((string) $spec['minimum']),
                'post_solve_check' => (bool) $spec['post_solve_check'],
                'degraded' => RiskAction::from((string) $spec['degraded']),
            ];
        }

        // global_floors: exactly 5 actions (0..4), index 0 = Allow, entries
        // 1..4 valid actions. Missing levels 1..4 default from the contract
        // defaults; anything outside 0..4, or a level-0 action other than
        // Allow, is rejected.
        $floors = [0 => RiskAction::Allow];
        if (isset($config['global_floors'])) {
            if (!is_array($config['global_floors'])) {
                throw new \InvalidArgumentException('Policy config "global_floors" must be an array');
            }
            foreach ($config['global_floors'] as $level => $action) {
                $level = (int) $level;
                if ($level < 0 || $level > 4) {
                    throw new \InvalidArgumentException(
                        sprintf('Global floor level %d must be within 0..4', $level)
                    );
                }
                $parsed = is_string($action)
                    ? RiskAction::from($action)
                    : $action;
                if ($level === 0 && $parsed !== RiskAction::Allow) {
                    throw new \InvalidArgumentException('Global floor level 0 must be "allow"');
                }
                $floors[$level] = $parsed;
            }
        }
        $floors += self::DEFAULT_GLOBAL_FLOORS;
        ksort($floors);
        if (count($floors) !== 5) {
            throw new \InvalidArgumentException('global_floors must resolve to exactly 5 actions (levels 0..4)');
        }

        return new self(
            version: (int) $config['version'],
            hash: hash('sha256', self::canonicalJson($config)),
            weights: RiskWeights::fromArray($config['weights']),
            scopes: $scopes,
            globalFloors: $floors,
        );
    }

    public function baseRisk(int $scope): int
    {
        return $this->scopes[$scope]['base_risk'] ?? 100;
    }

    public function minimum(int $scope): RiskAction
    {
        return $this->scopes[$scope]['minimum'] ?? RiskAction::Allow;
    }

    /**
     * Full decision: band action, clamped to the scope minimum and the
     * global floor, then hard overrides with reasons.
     *
     * Argon re-escalation ordering: ladder → strongest(minimum, floor) →
     * capacity — the argon-capacity check is the LAST step, so the final
     * floor/minimum re-clamp can never reintroduce Argon. A final Argon
     * action with argonCapacity < 300 escalates to StepUp.
     *
     * Reasons: policy override reasons first, then the top signal
     * contributors (contribution = (v * w) / 1000, sorted by contribution
     * desc, ties in SignalVector order), deduped and capped at 4 total.
     *
     * @param int $cooldownUntilMs additional (store-provided) cooldown deadline; defaults to none
     */
    public function decide(
        int $scope,
        int $score,
        SignalVector $s,
        ResourcePressure $r,
        int $globalLevel,
        int $nowMs,
        int $cooldownUntilMs = 0,
    ): RiskDecision {
        $bandAction = RiskAction::actionForScore($score);
        $minimum = $this->minimum($scope);
        $floor = $this->globalFloors[min(4, max(0, $globalLevel))] ?? RiskAction::Allow;
        $action = $this->strongest($bandAction, $minimum, $floor);

        $reasons = [];
        $deny = false;

        if ($s->replay >= 700) {
            $reasons[] = RiskReason::ReplayTraffic;
            $deny = true;
        }
        if ($s->malformed >= 800) {
            $reasons[] = RiskReason::MalformedTraffic;
            $deny = true;
        }
        if ($s->sourceFast >= 950) {
            $reasons[] = RiskReason::HardRateLimit;
            $deny = true;
        }
        if ($r->issuanceCapacity < 100) {
            $reasons[] = RiskReason::CapacityPressure;
            $deny = true;
        }
        if ($s->networkRisk >= 900) {
            $reasons[] = RiskReason::LocalNetworkRisk;
            $deny = true;
        }
        $retryAfterMs = null;
        // The cooldown_until value from the store is the GLOBAL hysteresis
        // hold marker (the level-until deadline), NOT a per-source denial
        // window — treating it as such would deny every request while the
        // global level is merely elevated. Cooldown denial applies only at
        // EMERGENCY level, where the global controller intends a temporary
        // admission stop.
        if ($cooldownUntilMs > 0 && $nowMs < $cooldownUntilMs && $globalLevel >= 4) {
            $reasons[] = RiskReason::Cooldown;
            $deny = true;
            $retryAfterMs = $cooldownUntilMs - $nowMs;
        }

        if ($deny) {
            $action = RiskAction::Deny;
        } else {
            $action = $this->strongest($action, $minimum, $floor);
        }

        // Argon capacity is the LAST step: the floor/minimum re-clamp above
        // can never reintroduce Argon, and the capacity downgrade never
        // falls back below the ladder.
        if ($action->isArgon() && $r->argonCapacity < 300) {
            $action = RiskAction::StepUp;
            $reasons[] = RiskReason::CapacityPressure;
        }

        $reasons = [...$reasons, ...$this->contributorReasons($s)];
        $reasons = array_values(array_unique($reasons, SORT_REGULAR));
        $reasons = array_slice($reasons, 0, 4);

        return new RiskDecision(
            score: $score,
            action: $action,
            reasons: $reasons,
            policyVersion: $this->version,
            globalLevel: $globalLevel,
            retryAfterMs: $retryAfterMs,
            band: intdiv(max(0, min(1000, $score)), 100),
        );
    }

    /**
     * Degraded decision (state backend unavailable): the scope's degraded
     * action clamped to the scope minimum AND the global floor at
     * min(lastKnownLevel, 4) (global_floors index 0 = Allow). globalLevel
     * passes through from the caller (usually the store's last-known
     * level).
     */
    public function degradedDecision(int $scope, int $globalLevel = 0): RiskDecision
    {
        $spec = $this->scopes[$scope] ?? null;
        $degraded = $spec['degraded'] ?? RiskAction::Allow;
        $floor = $this->globalFloors[min(4, max(0, $globalLevel))] ?? RiskAction::Allow;
        $action = $this->strongest($degraded, $this->minimum($scope), $floor);

        return new RiskDecision(
            score: 0,
            action: $action,
            reasons: [RiskReason::CapacityPressure],
            policyVersion: $this->version,
            globalLevel: $globalLevel,
            band: 0,
        );
    }

    /**
     * Top-4 contributors: for the 11 positive signals in SignalVector order,
     * contribution = (v * w) / 1000 (integer division); contributions > 0
     * are kept in SignalVector order, then sorted by contribution desc
     * (stable — ties keep the SignalVector order).
     *
     * @return list<RiskReason>
     */
    private function contributorReasons(SignalVector $s): array
    {
        $w = $this->weights;
        $pairs = [
            [$s->sourceFast, $w->sourceFast, RiskReason::SourceBurst],
            [$s->sourceSlow, $w->sourceSlow, RiskReason::SourceSustained],
            [$s->subnetFast, $w->subnetFast, RiskReason::NetworkBurst],
            [$s->issueDebt, $w->issueDebt, RiskReason::ChallengeDebt],
            [$s->badProof, $w->badProof, RiskReason::InvalidProofs],
            [$s->malformed, $w->malformed, RiskReason::MalformedTraffic],
            [$s->replay, $w->replay, RiskReason::ReplayTraffic],
            [$s->actionFailure, $w->actionFailure, RiskReason::ActionFailures],
            [$s->scopeSwitch, $w->scopeSwitch, RiskReason::ScopeHopping],
            [$s->globalPressure, $w->globalPressure, RiskReason::GlobalAttack],
            [$s->networkRisk, $w->networkRisk, RiskReason::LocalNetworkRisk],
        ];
        $contributions = [];
        foreach ($pairs as [$value, $weight, $reason]) {
            $contribution = intdiv($value * $weight, 1000);
            if ($contribution > 0) {
                $contributions[] = [$reason, $contribution];
            }
        }
        usort($contributions, static fn (array $a, array $b): int => $b[1] <=> $a[1]);
        return array_map(static fn (array $pair): RiskReason => $pair[0], $contributions);
    }

    private function strongest(RiskAction ...$actions): RiskAction
    {
        $best = RiskAction::Allow;
        foreach ($actions as $action) {
            if ($action->rank() > $best->rank()) {
                $best = $action;
            }
        }
        return $best;
    }

    /** Recursively key-sorted, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE. */
    private static function canonicalJson(array $value): string
    {
        self::sortRecursive($value);
        return (string) json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    private static function sortRecursive(array &$value): void
    {
        ksort($value);
        foreach ($value as &$v) {
            if (is_array($v)) {
                self::sortRecursive($v);
            }
        }
    }
}
