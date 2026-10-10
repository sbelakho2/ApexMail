<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskReason;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\SignalVector;
use PHPUnit\Framework\TestCase;

final class RiskPolicyTest extends TestCase
{
    private function config(): array
    {
        return [
            'version' => 3,
            'weights' => (new \KiwiCaptcha\Risk\RiskWeights())->toArray(),
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20'],
                2 => ['base_risk' => 150, 'minimum' => 'sha16', 'post_solve_check' => true, 'degraded' => 'sha20'],
                3 => ['base_risk' => 200, 'minimum' => 'argon32', 'post_solve_check' => true, 'degraded' => 'argon16'],
            ],
            'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
        ];
    }

    private function healthy(): ResourcePressure
    {
        return new ResourcePressure(1000, 1000);
    }

    private function zeroVector(): SignalVector
    {
        return SignalVector::zero();
    }

    public function testFromConfigAndHash(): void
    {
        $config = $this->config();
        $policy = RiskPolicy::fromConfig($config);
        self::assertSame(3, $policy->version);
        $canonical = $config;
        $this->sortRecursive($canonical);
        self::assertSame(
            hash('sha256', (string) json_encode($canonical, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)),
            $policy->hash
        );
        self::assertSame(100, $policy->baseRisk(1));
        self::assertSame(150, $policy->baseRisk(2));
        self::assertSame(100, $policy->baseRisk(999));
        self::assertSame(RiskAction::Allow, $policy->minimum(1));
        self::assertSame(RiskAction::Sha16, $policy->minimum(2));
        // Unconfigured scopes use the conservative default_scope row
        // (sha20 minimum / sha20 degraded), never Allow.
        self::assertSame(RiskAction::Sha20, $policy->minimum(999));
    }

    private function sortRecursive(array &$value): void
    {
        ksort($value);
        foreach ($value as &$v) {
            if (is_array($v)) {
                $this->sortRecursive($v);
            }
        }
    }

    public function testScopeMinimumNeverViolated(): void
    {
        $policy = RiskPolicy::fromConfig($this->config());
        foreach ([1, 2, 3] as $scope) {
            for ($score = 0; $score <= 1000; $score += 25) {
                $d = $policy->decide($scope, $score, $this->zeroVector(), $this->healthy(), 0, 1_700_000_000_000);
                self::assertGreaterThanOrEqual(
                    $policy->minimum($scope)->rank(),
                    $d->action->rank(),
                    sprintf('scope %d score %d violated its minimum', $scope, $score)
                );
            }
        }
    }

    public function testGlobalFloorNeverViolated(): void
    {
        $policy = RiskPolicy::fromConfig($this->config());
        foreach ([1, 2, 3, 4] as $level) {
            $floor = $policy->globalFloors[$level];
            for ($score = 0; $score <= 1000; $score += 25) {
                $d = $policy->decide(1, $score, $this->zeroVector(), $this->healthy(), $level, 1_700_000_000_000);
                self::assertGreaterThanOrEqual(
                    $floor->rank(),
                    $d->action->rank(),
                    sprintf('global level %d score %d violated floor %s', $level, $score, $floor->value)
                );
            }
        }
    }

    public function testBandActionApplied(): void
    {
        $policy = RiskPolicy::fromConfig($this->config());
        $d = $policy->decide(1, 500, $this->zeroVector(), $this->healthy(), 0, 1_700_000_000_000);
        self::assertSame(RiskAction::Sha20, $d->action);
        self::assertSame(500, $d->score);
        self::assertSame(5, $d->band);
    }

    public function testReplayHardOverride(): void
    {
        $policy = RiskPolicy::fromConfig($this->config());
        $d = $policy->decide(1, 0, SignalVector::fromArray(['replay' => 700]), $this->healthy(), 0, 1_700_000_000_000);
        self::assertSame(RiskAction::Deny, $d->action);
        self::assertTrue($d->hasReason(RiskReason::ReplayTraffic));

        $d = $policy->decide(1, 0, SignalVector::fromArray(['replay' => 699]), $this->healthy(), 0, 1_700_000_000_000);
        self::assertNotSame(RiskAction::Deny, $d->action);
    }

    public function testMalformedHardOverride(): void
    {
        $policy = RiskPolicy::fromConfig($this->config());
        $d = $policy->decide(1, 0, SignalVector::fromArray(['malformed' => 800]), $this->healthy(), 0, 1_700_000_000_000);
        self::assertSame(RiskAction::Deny, $d->action);
        self::assertTrue($d->hasReason(RiskReason::MalformedTraffic));

        $d = $policy->decide(1, 0, SignalVector::fromArray(['malformed' => 799]), $this->healthy(), 0, 1_700_000_000_000);
        self::assertNotSame(RiskAction::Deny, $d->action);
    }

    public function testSourceFastHardOverride(): void
    {
        $policy = RiskPolicy::fromConfig($this->config());
        // Velocity alone must not hard-deny a shared address: the reason
        // is recorded and the action is floored at the strongest
        // non-interactive band.
        $d = $policy->decide(1, 0, SignalVector::fromArray(['source_fast' => 950]), $this->healthy(), 0, 1_700_000_000_000);
        self::assertSame(RiskAction::Argon32, $d->action);
        self::assertTrue($d->hasReason(RiskReason::HardRateLimit));

        // Corroboration (another hard signal at its floor) restores the
        // hard deny.
        $d = $policy->decide(
            1,
            0,
            SignalVector::fromArray(['source_fast' => 950, 'bad_proof' => 300]),
            $this->healthy(),
            0,
            1_700_000_000_000
        );
        self::assertSame(RiskAction::Deny, $d->action);
        self::assertTrue($d->hasReason(RiskReason::HardRateLimit));

        // A saturated backend re-escalates the velocity floor to the
        // interactive step-up flow instead of weakening it.
        $d = $policy->decide(
            1,
            0,
            SignalVector::fromArray(['source_fast' => 950]),
            new ResourcePressure(0, 1000),
            0,
            1_700_000_000_000
        );
        self::assertSame(RiskAction::StepUp, $d->action);
        self::assertTrue($d->hasReason(RiskReason::HardRateLimit));

        $d = $policy->decide(1, 0, SignalVector::fromArray(['source_fast' => 949]), $this->healthy(), 0, 1_700_000_000_000);
        self::assertNotSame(RiskAction::Deny, $d->action);
    }

    public function testIssuanceCapacityOverride(): void
    {
        $policy = RiskPolicy::fromConfig($this->config());
        $d = $policy->decide(1, 0, $this->zeroVector(), new ResourcePressure(1000, 99), 0, 1_700_000_000_000);
        self::assertSame(RiskAction::Deny, $d->action);
        self::assertTrue($d->hasReason(RiskReason::CapacityPressure));

        $d = $policy->decide(1, 0, $this->zeroVector(), new ResourcePressure(1000, 100), 0, 1_700_000_000_000);
        self::assertNotSame(RiskAction::Deny, $d->action);
    }

    public function testArgonCapacityEscalatesToStepUpLast(): void
    {
        $policy = RiskPolicy::fromConfig($this->config());
        // The argon-capacity check is the last step: a final Argon action
        // with argonCapacity < 300 escalates to StepUp (never Sha20, and
        // never reintroduced by the floor/minimum re-clamp).
        $d = $policy->decide(1, 600, $this->zeroVector(), new ResourcePressure(299, 1000), 0, 1_700_000_000_000);
        self::assertSame(RiskAction::StepUp, $d->action);
        self::assertTrue($d->hasReason(RiskReason::CapacityPressure));

        $d = $policy->decide(1, 600, $this->zeroVector(), new ResourcePressure(300, 1000), 0, 1_700_000_000_000);
        self::assertSame(RiskAction::Argon16, $d->action);
        self::assertFalse($d->hasReason(RiskReason::CapacityPressure));
    }

    public function testArgonCapacityCheckIsLastSoFloorsCannotReintroduceArgon(): void
    {
        // scope 3 has minimum argon32; with a global floor of argon16 and
        // low argon capacity, the final action must still step up (the
        // capacity check runs after the floor/minimum re-clamp).
        $config = $this->config();
        $config['global_floors'] = [0 => 'allow', 1 => 'argon16', 2 => 'argon32', 3 => 'argon64', 4 => 'argon64'];
        $policy = RiskPolicy::fromConfig($config);
        $d = $policy->decide(3, 0, $this->zeroVector(), new ResourcePressure(1, 1000), 1, 1_700_000_000_000);
        self::assertSame(RiskAction::StepUp, $d->action);
        self::assertTrue($d->hasReason(RiskReason::CapacityPressure));
    }

    public function testVersionMismatchThrows(): void
    {
        $config = $this->config();
        $config['version'] = 99;
        $this->expectException(\InvalidArgumentException::class);
        RiskPolicy::fromConfig($config);
    }

    public function testBaseRiskOutOfRangeThrows(): void
    {
        $config = $this->config();
        $config['scopes'][1]['base_risk'] = 1001;
        $this->expectException(\InvalidArgumentException::class);
        RiskPolicy::fromConfig($config);

        $config = $this->config();
        $config['scopes'][1]['base_risk'] = -1;
        $this->expectException(\InvalidArgumentException::class);
        RiskPolicy::fromConfig($config);
    }

    public function testScopeIdZeroThrows(): void
    {
        $config = $this->config();
        $config['scopes'][0] = ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20'];
        $this->expectException(\InvalidArgumentException::class);
        RiskPolicy::fromConfig($config);
    }

    public function testGlobalFloorsStrictFailClosedValidation(): void
    {
        // Missing global_floors entirely rejects the config (no silent
        // defaults — Rust parity).
        $config = $this->config();
        unset($config['global_floors']);
        try {
            RiskPolicy::fromConfig($config);
            self::fail('a missing global_floors must be rejected');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('global_floors', $e->getMessage());
        }

        // Short floors (4 entries) reject the config.
        $config = $this->config();
        $config['global_floors'] = [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20'];
        try {
            RiskPolicy::fromConfig($config);
            self::fail('a short global_floors must be rejected');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('5 entries', $e->getMessage());
        }

        // A non-array global_floors rejects the config.
        $config = $this->config();
        $config['global_floors'] = 'sha20';
        $this->expectException(\InvalidArgumentException::class);
        RiskPolicy::fromConfig($config);
    }

    public function testGlobalFloorsValidation(): void
    {
        // Level 0 must be Allow.
        $config = $this->config();
        $config['global_floors'] = [0 => 'sha16', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'];
        $this->expectException(\InvalidArgumentException::class);
        RiskPolicy::fromConfig($config);

        // Levels outside 0..4 are rejected.
        $config = $this->config();
        $config['global_floors'] = [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20', 5 => 'deny'];
        $this->expectException(\InvalidArgumentException::class);
        RiskPolicy::fromConfig($config);

        // A full explicit config parses and index 0 stays Allow.
        $config = $this->config();
        $config['global_floors'] = [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'];
        $policy = RiskPolicy::fromConfig($config);
        self::assertSame(RiskAction::Allow, $policy->globalFloors[0]);
        self::assertCount(5, $policy->globalFloors);
    }

    public function testSharedReasonVectorsMatchTheCrossLanguageContract(): void
    {
        // The shared reason vectors: identical inputs must surface the
        // identical ordered reason list in PHP and Rust, including the
        // contributor ordering and the stable tie order.
        $path = \dirname(__DIR__).'/../../protocol/risk-v1/fixtures.json';
        $fixtures = json_decode((string) file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
        $vectors = $fixtures['reason_vectors'] ?? null;
        self::assertIsArray($vectors);
        self::assertNotEmpty($vectors);

        foreach ($vectors as $vector) {
            $policy = RiskPolicy::fromConfig([
                'version' => 3,
                'weights' => RiskWeights::fromArray($vector['weights'])->toArray(),
                'scopes' => [1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow']],
                'global_floors' => [0 => 'allow', 1 => 'allow', 2 => 'allow', 3 => 'allow', 4 => 'allow'],
            ]);
            $decision = $policy->decide(
                1,
                (int) $vector['score'],
                SignalVector::fromArray($vector['signals']),
                new ResourcePressure(
                    argonCapacity: (int) $vector['argon_capacity'],
                    issuanceCapacity: (int) $vector['issuance_capacity'],
                ),
                (int) $vector['global_level'],
                1_700_000_000_000,
            );
            self::assertSame(
                $vector['expected_reasons'],
                array_map(static fn (RiskReason $reason): string => $reason->value, $decision->reasons),
                $vector['why'],
            );
            if (isset($vector['expected_action'])) {
                self::assertSame($vector['expected_action'], $decision->action->value, $vector['why']);
            }
        }
    }

    public function testGlobalFloorActionsMustBeStrings(): void
    {
        // The shared malformed value vectors: an integer, boolean, array
        // or object action is rejected here exactly like the Rust
        // parser's JSON-string requirement.
        $path = \dirname(__DIR__).'/../../protocol/risk-v1/fixtures.json';
        self::assertFileExists($path);
        $fixtures = json_decode((string) file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
        $vectors = $fixtures['malformed_policy_vectors']['malformed_global_floor_values'] ?? null;
        self::assertIsArray($vectors);
        self::assertNotEmpty($vectors);

        foreach ($vectors as $vector) {
            $config = $this->config();
            $config['global_floors'][(int) $vector['level']] = $vector['value'];
            try {
                RiskPolicy::fromConfig($config);
                self::fail(sprintf('the malformed global floor action at level %s must be rejected (%s)', $vector['level'], $vector['why']));
            } catch (\InvalidArgumentException $e) {
                self::assertStringContainsString('must be a string', $e->getMessage());
            }
        }
    }

    public function testGlobalFloorAppliedInDegradedMode(): void
    {
        $config = $this->config();
        $config['global_floors'] = [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'argon32'];
        $policy = RiskPolicy::fromConfig($config);

        // scope 1: degraded sha20 (3) < floor argon32 (5) at level 4.
        $d = $policy->degradedDecision(1, 4);
        self::assertSame(RiskAction::Argon32, $d->action);
        // At level 0 the floor is Allow: degraded sha20 wins.
        $d = $policy->degradedDecision(1, 0);
        self::assertSame(RiskAction::Sha20, $d->action);
    }

    public function testContributorReasonsTopFour(): void
    {
        $policy = RiskPolicy::fromConfig($this->config());
        // Contributions (weights: source_fast 190, replay 320, network_risk
        // 100, global_pressure 170):
        //   replay 700 -> 224, source_fast 950 -> 180, network_risk 900 ->
        //   90, global_pressure 500 -> 85, scope_switch 1000 -> 60.
        $vector = SignalVector::fromArray([
            'source_fast' => 950,
            'scope_switch' => 1000,
            'replay' => 700,
            'network_risk' => 900,
            'global_pressure' => 500,
        ]);
        $d = $policy->decide(1, 0, $vector, $this->healthy(), 0, 1_700_000_000_000);
        // Overrides first (replay >= 700, source_fast >= 950 and
        // network_risk >= 900 hard-deny), then contributors, deduped and
        // capped at 4 total.
        self::assertSame(RiskAction::Deny, $d->action);
        self::assertSame([
            RiskReason::ReplayTraffic,
            RiskReason::HardRateLimit,
            RiskReason::LocalNetworkRisk,
            RiskReason::SourceBurst,
        ], $d->reasons);

        // Non-deny case: contributors only, ordered by contribution desc
        // (ties in SignalVector order).
        $vector = SignalVector::fromArray([
            'source_fast' => 100,
            'source_slow' => 100,
            'replay' => 100,
            'network_risk' => 100,
        ]);
        $d = $policy->decide(1, 0, $vector, $this->healthy(), 0, 1_700_000_000_000);
        // source_fast 19, source_slow 11, replay 32, network_risk 10
        self::assertSame([
            RiskReason::ReplayTraffic,
            RiskReason::SourceBurst,
            RiskReason::SourceSustained,
            RiskReason::LocalNetworkRisk,
        ], $d->reasons);
    }

    public function testNetworkRiskOverride(): void
    {
        $policy = RiskPolicy::fromConfig($this->config());
        $d = $policy->decide(1, 0, SignalVector::fromArray(['network_risk' => 900]), $this->healthy(), 0, 1_700_000_000_000);
        self::assertSame(RiskAction::Deny, $d->action);
        self::assertTrue($d->hasReason(RiskReason::LocalNetworkRisk));

        $d = $policy->decide(1, 0, SignalVector::fromArray(['network_risk' => 899]), $this->healthy(), 0, 1_700_000_000_000);
        self::assertNotSame(RiskAction::Deny, $d->action);
    }

    public function testCooldownOverrideOnlyAtEmergencyLevel(): void
    {
        $policy = RiskPolicy::fromConfig($this->config());
        $now = 1_700_000_000_000;
        // Elevated-but-non-emergency level: the hysteresis hold is a level
        // marker, NOT a per-source denial window — no deny.
        $d = $policy->decide(1, 0, $this->zeroVector(), $this->healthy(), 2, $now, $now + 5000);
        self::assertNotSame(RiskAction::Deny, $d->action, 'level-2 hysteresis hold must not deny');
        self::assertNull($d->retryAfterMs);
        // Emergency level with a future hold -> Cooldown deny.
        $d = $policy->decide(1, 0, $this->zeroVector(), $this->healthy(), 4, $now, $now + 5000);
        self::assertSame(RiskAction::Deny, $d->action);
        self::assertTrue($d->hasReason(RiskReason::Cooldown));
        self::assertSame(5000, $d->retryAfterMs);
        // Hold expired -> no deny.
        $d = $policy->decide(1, 0, $this->zeroVector(), $this->healthy(), 4, $now, $now);
        self::assertNotSame(RiskAction::Deny, $d->action);
        self::assertNull($d->retryAfterMs);
    }

    public function testMultipleReasonsCappedAtFour(): void
    {
        $policy = RiskPolicy::fromConfig($this->config());
        $vector = SignalVector::fromArray([
            'replay' => 700,
            'malformed' => 800,
            'source_fast' => 950,
            'network_risk' => 900,
        ]);
        $now = 1_700_000_000_000;
        $d = $policy->decide(1, 0, $vector, new ResourcePressure(1000, 50), 0, $now, $now + 1000);
        self::assertSame(RiskAction::Deny, $d->action);
        self::assertLessThanOrEqual(4, count($d->reasons));
        self::assertSame(count($d->reasons), count(array_unique($d->reasons, SORT_REGULAR)));
    }

    public function testDegradedClampedToMinimum(): void
    {
        $policy = RiskPolicy::fromConfig($this->config());
        // scope 3: degraded argon16 (4) clamped to minimum argon32 (5)
        $d = $policy->degradedDecision(3);
        self::assertSame(RiskAction::Argon32, $d->action);
        self::assertTrue($d->hasReason(RiskReason::CapacityPressure));
        self::assertSame(0, $d->score);

        // scope 2: degraded sha20 (3) >= minimum sha16 (1)
        $d = $policy->degradedDecision(2);
        self::assertSame(RiskAction::Sha20, $d->action);

        // unknown scope degrades to the conservative default_scope row
        $d = $policy->degradedDecision(999);
        self::assertSame(RiskAction::Sha20, $d->action);
    }

    public function testDegradedGlobalLevelPassthrough(): void
    {
        $policy = RiskPolicy::fromConfig($this->config());
        self::assertSame(3, $policy->degradedDecision(1, 3)->globalLevel);
        self::assertSame(0, $policy->degradedDecision(1)->globalLevel);
        self::assertSame(3, $policy->version, 'policy version passes through decisions');
        self::assertSame(3, $policy->degradedDecision(1, 3)->policyVersion);
    }

    public function testDecisionJsonSerialization(): void
    {
        $policy = RiskPolicy::fromConfig($this->config());
        $d = $policy->decide(1, 500, $this->zeroVector(), $this->healthy(), 2, 1_700_000_000_000);
        $json = json_decode((string) json_encode($d), true);
        self::assertSame(500, $json['score']);
        self::assertSame('sha20', $json['action']);
        self::assertSame(3, $json['policy_version']);
        self::assertSame(17, $json['model_revision'], 'the decision carries the model revision in the public JSON');
        self::assertSame(2, $json['global_level']);
        self::assertNull($json['retry_after_ms']);
        self::assertSame(5, $json['band']);
        self::assertIsArray($json['reasons']);
    }

    /**
     * Absolute user-visible cap: the adaptive escalation is
     * bounded. The policy's maximum action across every scope, every
     * global floor and every possible score is the configured ladder top
     * (Deny) — and never above it, so there is no unbounded punishment
     * mode.
     */
    public function testMaxActionNeverExceedsTheLadderTop(): void
    {
        $policy = RiskPolicy::fromConfig($this->config());
        $maxRank = -1;
        foreach ([1, 2, 3, 999] as $scope) {
            foreach ([0, 1, 2, 3, 4] as $level) {
                for ($score = 0; $score <= 1000; $score += 1) {
                    $d = $policy->decide($scope, $score, $this->zeroVector(), $this->healthy(), $level, 1_700_000_000_000);
                    self::assertLessThanOrEqual(
                        RiskAction::Deny->rank(),
                        $d->action->rank(),
                        sprintf('scope %d level %d score %d exceeded the ladder top', $scope, $level, $score)
                    );
                    $maxRank = max($maxRank, $d->action->rank());
                }
            }
        }
        self::assertSame(RiskAction::Deny->rank(), $maxRank, 'the ladder top must actually be reachable');
        self::assertSame(RiskAction::Deny, RiskAction::actionForScore(1000), 'the cap action is Deny at the top score');
    }

    public function testSharedMalformedPolicyVectorsAreRejected(): void
    {
        $vectors = json_decode((string) file_get_contents(__DIR__ . '/../../../protocol/risk-v1/fixtures.json'), true, 8, JSON_THROW_ON_ERROR)['malformed_policy_vectors'] ?? null;
        self::assertIsArray($vectors, 'the shared malformed-policy vectors must load');

        $base = [
            'version' => RiskPolicy::CONTRACT_VERSION,
            'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            'weights' => [],
            'scopes' => [1 => ['base_risk' => 100, 'minimum' => 'sha20', 'post_solve_check' => false, 'degraded' => 'sha20']],
        ];
        foreach ($vectors['malformed_policy_scopes'] as $vector) {
            $config = $base;
            $config['scopes'] = [$vector['key'] => ['base_risk' => 100, 'minimum' => 'sha20', 'post_solve_check' => false, 'degraded' => 'sha20']];
            try {
                RiskPolicy::fromConfig($config);
                self::fail(sprintf('the malformed scope key %s must be rejected', var_export($vector['key'], true)));
            } catch (\InvalidArgumentException $e) {
                // A canonical-but-out-of-range integer key fails the
                // range message; every non-canonical spelling fails
                // the canonical-integer message.
                self::assertThat(
                    $e->getMessage(),
                    self::logicalOr(
                        self::stringContains('canonical integer u32'),
                        self::stringContains('must be within 1..4294967295')
                    ),
                    $vector['key']
                );
            }
        }
        foreach ($vectors['malformed_policy_flags'] as $vector) {
            $config = $base;
            $config['scopes'] = [1 => ['base_risk' => 100, 'minimum' => 'sha20', 'post_solve_check' => $vector['value'], 'degraded' => 'sha20']];
            try {
                RiskPolicy::fromConfig($config);
                self::fail(sprintf('the malformed flag %s must be rejected', var_export($vector['value'], true)));
            } catch (\InvalidArgumentException $e) {
                self::assertStringContainsString('literal boolean', $e->getMessage());
            }
        }
        // The shared malformed global-floor sets: the level keys are
        // exactly the five canonical spellings 0..4, each declared
        // exactly once. PHP's array key rules already reject non-integer
        // spellings, and the Rust parser must reject the identical
        // vectors through its literal level grammar — one shared asset,
        // one acceptance set.
        foreach ($vectors['malformed_global_floor_sets'] as $vector) {
            $config = $base;
            $config['global_floors'] = $vector['floors'];
            try {
                RiskPolicy::fromConfig($config);
                self::fail(sprintf('the malformed global_floors %s must be rejected (%s)', json_encode($vector['floors']), $vector['why']));
            } catch (\InvalidArgumentException $e) {
                // Every malformed set fails one of the canonical-level
                // rules: a non-canonical spelling fails the integer-key
                // message, a missing level fails the exact-count
                // message, and an out-of-range level fails the range
                // message.
                self::assertThat(
                    $e->getMessage(),
                    self::logicalOr(
                        self::stringContains('global_floors'),
                        self::stringContains('Global floor level'),
                    ),
                    $vector['why'],
                );
            }
        }
    }
}
