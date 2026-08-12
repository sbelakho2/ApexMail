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
 *     'global_floors' => [1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
 *   ]
 *
 * The `hash` is sha256 of the canonical JSON of the config (recursively
 * key-sorted, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE).
 */
final class RiskPolicy
{
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

    public static function fromConfig(array $config): self
    {
        if (!isset($config['version']) || !is_int($config['version'])) {
            throw new \InvalidArgumentException('Policy config requires an int "version"');
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
            if (!isset($spec['base_risk'], $spec['minimum'], $spec['degraded']) || !array_key_exists('post_solve_check', $spec)) {
                throw new \InvalidArgumentException(
                    sprintf('Scope %d requires base_risk, minimum, post_solve_check and degraded', $scope)
                );
            }
            $scopes[$scope] = [
                'base_risk' => (int) $spec['base_risk'],
                'minimum' => RiskAction::from((string) $spec['minimum']),
                'post_solve_check' => (bool) $spec['post_solve_check'],
                'degraded' => RiskAction::from((string) $spec['degraded']),
            ];
        }

        $floors = [];
        foreach (($config['global_floors'] ?? self::DEFAULT_GLOBAL_FLOORS) as $level => $action) {
            $floors[(int) $level] = is_string($action)
                ? RiskAction::from($action)
                : $action;
        }
        ksort($floors);

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
        $floor = $this->globalFloors[$globalLevel] ?? RiskAction::Allow;
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
        if ($action->isArgon() && $r->argonCapacity < 300) {
            $action = RiskAction::Sha20;
            $reasons[] = RiskReason::CapacityPressure;
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
     * action clamped to at least the scope minimum. globalLevel passes
     * through from the caller (usually the store's last-known level).
     */
    public function degradedDecision(int $scope, int $globalLevel = 0): RiskDecision
    {
        $spec = $this->scopes[$scope] ?? null;
        $degraded = $spec['degraded'] ?? RiskAction::Allow;
        $action = $this->strongest($degraded, $this->minimum($scope));

        return new RiskDecision(
            score: 0,
            action: $action,
            reasons: [RiskReason::CapacityPressure],
            policyVersion: $this->version,
            globalLevel: $globalLevel,
            band: 0,
        );
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
