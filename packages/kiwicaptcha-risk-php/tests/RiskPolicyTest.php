<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskReason;
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
            'global_floors' => [1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
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
        self::assertSame(RiskAction::Allow, $policy->minimum(999));
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
        $d = $policy->decide(1, 0, SignalVector::fromArray(['source_fast' => 950]), $this->healthy(), 0, 1_700_000_000_000);
        self::assertSame(RiskAction::Deny, $d->action);
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
        // The argon-capacity check is the LAST step: a final Argon action
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
        // low argon capacity, the final action must STILL step up (the
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
        // Elevated-but-non-emergency level: the hysteresis hold is a LEVEL
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

        // unknown scope degrades to allow
        $d = $policy->degradedDecision(999);
        self::assertSame(RiskAction::Allow, $d->action);
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
        self::assertSame(17, $json['model_revision'], 'AUDIT #110: the decision carries the model revision in the public JSON');
        self::assertSame(2, $json['global_level']);
        self::assertNull($json['retry_after_ms']);
        self::assertSame(5, $json['band']);
        self::assertIsArray($json['reasons']);
    }

    /**
     * AUDIT #88 (b) — ABSOLUTE USER-VISIBLE CAP: the adaptive escalation is
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
}
