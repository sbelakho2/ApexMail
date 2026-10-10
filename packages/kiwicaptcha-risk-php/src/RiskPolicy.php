<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * Immutable policy snapshot used to turn a risk score into an action.
 *
 * Configuration shape:
 *   [
 *     'version' => int,
 *     'weights' => [...13 snake_case weights...].
 *     'scopes' => [
 *        <int scope> => [
 *          'base_risk' => int,
 *          'minimum' => 'allow'|'sha16'|...,        // RiskAction string
 *          'post_solve_check' => bool,
 *          'degraded' => 'allow'|...,               // RiskAction string
 *        ],
 *     ].
 *     'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
 *     with index 0 = 'allow' and levels 1..4 valid actions. Missing
 *     levels 1..4 default from the built-in default floors.
 *
 * The `hash` is sha256 of the canonical JSON of the config (recursively
 * key-sorted, with unescaped slashes and unescaped unicode).
 *
 * policy_version (the config's `version`, stamped on every decision):
 * bump it whenever the operator policy materially changes. A model
 * revision that materially affects security, e.g. changes how scores
 * are computed or how calibration moves the bias, requires a
 * policy_version bump too, so the decision's policy_version always
 * pins down both the operator policy and the security-relevant model
 * generation it was computed under.
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
        public readonly array $defaultScope,
        public readonly array $globalFloors,
    ) {
    }

    /**
     * Parses and validates a policy config. Rejects: a version that does
     * not match the requested (default: contract) version, base_risk
     * outside 0..1000, and scope ids outside 1..4294967295. Also
     * rejected: a missing / short / malformed global_floors (exactly 5
     * entries required, index 0 = Allow, entries 1..4 valid actions —
     * fail-closed, identical to the Rust parser). Enforced in the
     * parser itself, not only in the Symfony config layer.
     */
    /**
     * The unconfigured-scope row (`default_scope`): shaped exactly like a
     * scope row and validated the same way. The built-in default is
     * deliberately NOT Allow on any axis (100 / sha20 / false / sha20):
     * a scope the operator forgot to list must not be the weakest hole in
     * the policy.
     *
     * @return array{base_risk:int, minimum:RiskAction, post_solve_check:bool, degraded:RiskAction}
     */
    private static function parseDefaultScope(mixed $spec): array
    {
        if (!\is_array($spec)
            || !isset($spec['base_risk'], $spec['minimum'], $spec['degraded'])
            || !array_key_exists('post_solve_check', $spec)) {
            throw new \InvalidArgumentException('default_scope requires base_risk, minimum, post_solve_check and degraded');
        }
        if (!\is_int($spec['base_risk']) || $spec['base_risk'] < 0 || $spec['base_risk'] > 1000) {
            throw new \InvalidArgumentException('default_scope base_risk must be an int within 0..1000');
        }
        if (!\is_bool($spec['post_solve_check'])) {
            throw new \InvalidArgumentException('default_scope post_solve_check must be a bool');
        }

        return [
            'base_risk' => $spec['base_risk'],
            'minimum' => RiskAction::from((string) $spec['minimum']),
            'post_solve_check' => $spec['post_solve_check'],
            'degraded' => RiskAction::from((string) $spec['degraded']),
        ];
    }

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
            // The scope key is a canonical u32 and nothing else: a
            // non-integer key (or a non-canonical decimal string) is a
            // configuration error, never coerced — `(int)` casting
            // would collapse "1admin" and "01" onto scope 1, silently
            // overwriting policy rows (the rust parser rejects both
            // under the same grammar).
            if (!\is_int($scope)) {
                throw new \InvalidArgumentException(
                    sprintf('Scope id must be a canonical integer u32 (got %s); non-canonical keys like "1admin" or "01" are rejected, never coerced', var_export($scope, true))
                );
            }
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
                'post_solve_check' => self::requireBool($spec['post_solve_check'], $scope, 'post_solve_check'),
                'degraded' => RiskAction::from((string) $spec['degraded']),
            ];
        }

        // global_floors: required with exactly 5 entries (levels 0..4) —
        // the strict fail-closed semantics of the Rust parser (missing,
        // short or malformed floors reject the config instead of silently
        // defaulting). Index 0 must be Allow; entries 1..4 are valid
        // actions; keys outside 0..4 are rejected.
        if (!isset($config['global_floors']) || !is_array($config['global_floors'])) {
            throw new \InvalidArgumentException('Policy config requires a "global_floors" array');
        }
        if (count($config['global_floors']) !== 5) {
            throw new \InvalidArgumentException(sprintf(
                'global_floors requires exactly 5 entries (levels 0..4), got %d',
                count($config['global_floors'])
            ));
        }
        $floors = [];
        foreach ($config['global_floors'] as $level => $action) {
            if (!is_int($level) || $level < 0 || $level > 4) {
                throw new \InvalidArgumentException(sprintf(
                    'Global floor level %s must be within 0..4',
                    is_int($level) ? (string) $level : gettype($level)
                ));
            }
            // The action value is one of the literal action strings: a
            // non-string value (integer, boolean, array, object) is a
            // configuration error here exactly like the Rust parser's
            // `parse_action` JSON-string requirement, never a value that
            // travels deeper and fails at a call site.
            if (!is_string($action)) {
                throw new \InvalidArgumentException(sprintf(
                    'Global floor level %d action must be a string, got %s',
                    $level,
                    gettype($action),
                ));
            }
            $parsed = RiskAction::from($action);
            if ($level === 0 && $parsed !== RiskAction::Allow) {
                throw new \InvalidArgumentException('Global floor level 0 must be "allow"');
            }
            $floors[$level] = $parsed;
        }
        ksort($floors);

        return new self(
            version: (int) $config['version'],
            hash: hash('sha256', self::canonicalJson($config)),
            weights: RiskWeights::fromArray($config['weights']),
            scopes: $scopes,
            defaultScope: isset($config['default_scope'])
                ? self::parseDefaultScope($config['default_scope'])
                : ['base_risk' => 100, 'minimum' => RiskAction::Sha20, 'post_solve_check' => false, 'degraded' => RiskAction::Sha20],
            globalFloors: $floors,
        );
    }

    public function baseRisk(int $scope): int
    {
        return $this->scopes[$scope]['base_risk'] ?? $this->defaultScope['base_risk'];
    }

    public function minimum(int $scope): RiskAction
    {
        return $this->scopes[$scope]['minimum'] ?? $this->defaultScope['minimum'];
    }

    /**
     * Full decision: band action (with enter/exit hysteresis when the
     * engine's per-client map is passed), clamped to the scope
     * minimum and the global floor, then hard overrides with reasons.
     *
     * Argon re-escalation ordering: ladder → strongest(minimum, floor) →
     * capacity. The argon-capacity check is the last step, so the final
     * floor/minimum re-clamp can never reintroduce Argon. A final Argon
     * action with argonCapacity < 300 escalates to StepUp.
     *
     * Hysteresis: with $hysteresis the band selection uses the
     * (scope, clientKey) entry — the session pseudonym when present, else
     * the source pseudonym. The selection escalates to the next band only
     * at its enter threshold (upper + 10), de-escalates only below its
     * exit threshold (lower − 10), and jumps straight to the plain action
     * when the score clears the target band margin. Fresh keys and
     * StepUp/Deny use the plain mapping. The map stores the score-selected
     * action, so hard overrides never poison the profile. Passing null (the
     * default) keeps the plain band mapping.
     *
     * Reasons: policy override reasons first, then the top signal
     * contributors, contribution = (v * w) / 1000, sorted by
     * contribution desc with ties in SignalVector order, deduped and
     * capped at 4 total.
     *
     * @param int $cooldownUntilMs additional (store-provided) cooldown
     *                              deadline; defaults to none.
     * @param string|null $decisionId caller-supplied decision id (16-byte hex,
     *                                used when the consolidated assessment
     *                                registers the outcome atomically with
     *                                the observation, so the returned
     *                                decision carries the same id); null
     *                                draws a fresh random id.
     *
     * @param string $clientKey hysteresis client key: the session
     *                          pseudonym when present, else the source
     *                          pseudonym; required (non-empty) when
     *                          $hysteresis is set — an empty key would
     *                          collapse every client of the scope into
     *                          one shared entry
     */
    public function decide(
        int $scope,
        int $score,
        SignalVector $s,
        ResourcePressure $r,
        int $globalLevel,
        int $nowMs,
        int $cooldownUntilMs = 0,
        ?ScopeActionHysteresis $hysteresis = null,
        ?string $decisionId = null,
        string $clientKey = '',
    ): RiskDecision {
        if ($hysteresis !== null && $clientKey === '') {
            throw new \InvalidArgumentException('a non-empty clientKey is required when a ScopeActionHysteresis is supplied: an empty key would key every client of the scope to one shared entry');
        }
        $plain = RiskAction::actionForScore($score);
        $bandAction = $hysteresis !== null ? $hysteresis->select($scope, $clientKey, $score, $plain, $nowMs) : $plain;
        $minimum = $this->minimum($scope);
        $floor = $this->globalFloors[min(4, max(0, $globalLevel))] ?? RiskAction::Allow;
        $action = $this->strongest($bandAction, $minimum, $floor);

        $reasons = [];
        $deny = false;
        $velocityFloor = null;

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
            // Velocity alone must not hard-deny: a shared IPv4 address
            // (cgnat, an office, a campus) can exceed the saturation from
            // legitimate volume, and the history is shed with the /64
            // source identity so a single abusive host cannot speak for
            // the aggregate. Deny only when another hard signal
            // corroborates the source; otherwise floor the action at
            // Argon32 (the strongest non-interactive band) and let the
            // score/capacity logic decide — the argon-capacity check
            // below still re-escalates a saturated backend to StepUp.
            if ($s->badProof >= 300 || $s->malformed >= 300 || $s->replay >= 300) {
                $deny = true;
            } else {
                $velocityFloor = RiskAction::Argon32;
            }
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
        // The cooldown_until value from the store is the global hysteresis
        // hold marker (the level-until deadline), NOT a per-source denial
        // window — treating it as such would deny every request while the
        // global level is merely elevated. Cooldown denial applies only at
        // emergency level, where the global controller intends a temporary
        // admission stop.
        if ($cooldownUntilMs > 0 && $nowMs < $cooldownUntilMs && $globalLevel >= 4) {
            $reasons[] = RiskReason::Cooldown;
            $deny = true;
            // The retry hint is the u32 wire field: saturate instead of
            // emitting an unbounded value (the Rust mirror saturates the
            // same way), so a long hold never leaks a wrapped, much
            // earlier retry.
            $retryAfterMs = min(4294967295, $cooldownUntilMs - $nowMs);
        }

        if ($deny) {
            $action = RiskAction::Deny;
        } else {
            if ($velocityFloor !== null) {
                $action = $this->strongest($action, $velocityFloor);
            }
            $action = $this->strongest($action, $minimum, $floor);
        }

        // Argon capacity is the last step: the floor/minimum re-clamp above
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
            decisionId: $decisionId,
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
        $degraded = $spec['degraded'] ?? $this->defaultScope['degraded'];
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

    /** Recursively key-sorted, with unescaped slashes and unescaped unicode. */
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

    /**
     * A literal boolean, never a coerced truthiness: `(bool) "false"`
     * is true, so a string flag would silently arm the post-solve
     * check the rust parser (JSON as_bool) rejects under the same
     * contract.
     */
    private static function requireBool(mixed $value, int $scope, string $field): bool
    {
        if (!\is_bool($value)) {
            throw new \InvalidArgumentException(
                sprintf('Scope %d field "%s" must be a literal boolean (got %s); coerced truthiness is rejected', $scope, $field, get_debug_type($value))
            );
        }

        return $value;
    }
}
