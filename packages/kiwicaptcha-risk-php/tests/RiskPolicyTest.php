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
        return new ResourcePressure(1000, 1000, 1000);
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
        $d = $policy->decide(1, 0, $this->zeroVector(), new ResourcePressure(1000, 99, 1000), 0, 1_700_000_000_000);
        self::assertSame(RiskAction::Deny, $d->action);
        self::assertTrue($d->hasReason(RiskReason::CapacityPressure));

        $d = $policy->decide(1, 0, $this->zeroVector(), new ResourcePressure(1000, 100, 1000), 0, 1_700_000_000_000);
        self::assertNotSame(RiskAction::Deny, $d->action);
    }

    public function testArgonDemotionOnLowArgonCapacity(): void
    {
        $policy = RiskPolicy::fromConfig($this->config());
        $d = $policy->decide(1, 600, $this->zeroVector(), new ResourcePressure(299, 1000, 1000), 0, 1_700_000_000_000);
        self::assertSame(RiskAction::Sha20, $d->action);
        self::assertTrue($d->hasReason(RiskReason::CapacityPressure));

        $d = $policy->decide(1, 600, $this->zeroVector(), new ResourcePressure(300, 1000, 1000), 0, 1_700_000_000_000);
        self::assertSame(RiskAction::Argon16, $d->action);
        self::assertFalse($d->hasReason(RiskReason::CapacityPressure));
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
        $d = $policy->decide(1, 0, $vector, new ResourcePressure(1000, 50, 1000), 0, $now, $now + 1000);
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
        self::assertSame(2, $json['global_level']);
        self::assertNull($json['retry_after_ms']);
        self::assertSame(5, $json['band']);
        self::assertIsArray($json['reasons']);
    }
}
