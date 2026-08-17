<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskReason;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\ScopeActionHysteresis;
use KiwiCaptcha\Risk\SignalVector;
use PHPUnit\Framework\TestCase;

/**
 * SCOPE ACTION HYSTERESIS.
 *
 * The policy's fixed score bands must not oscillate at their boundaries:
 * a score hovering at a threshold (449/451/449…) would flip the challenge
 * profile on every request. The engine keeps a per-process, bounded, TTL'd
 * map of the LAST action per scope; the band selection escalates to the
 * next band only at ENTER = upper + 10 and de-escalates only below
 * EXIT = lower − 10, staying in the current band in between. Fresh scopes
 * and the hard actions (StepUp/Deny) use the plain mapping. (The audit's
 * 49/51 example falls entirely inside the Allow band [0,150) — the
 * equivalent boundary-oscillation test uses 449/451 at the 450 edge.)
 */
final class ScopeActionHysteresisTest extends TestCase
{
    private const T0 = 1_700_000_000_000;

    private function policy(): RiskPolicy
    {
        return RiskPolicy::fromConfig([
            'version' => 3,
            'weights' => (new RiskWeights())->toArray(),
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20'],
                2 => ['base_risk' => 150, 'minimum' => 'sha16', 'post_solve_check' => true, 'degraded' => 'sha20'],
                3 => ['base_risk' => 200, 'minimum' => 'argon32', 'post_solve_check' => true, 'degraded' => 'argon16'],
            ],
            'global_floors' => [1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
        ]);
    }

    private function decide(RiskPolicy $policy, ScopeActionHysteresis $h, int $scope, int $score, int $nowMs, int $globalLevel = 0): \KiwiCaptcha\Risk\RiskDecision
    {
        return $policy->decide(
            $scope,
            $score,
            SignalVector::zero(),
            new ResourcePressure(1000, 1000),
            $globalLevel,
            $nowMs,
            0,
            $h,
        );
    }

    public function testOscillatingScoreProducesStableAction(): void
    {
        $policy = $this->policy();
        $h = new ScopeActionHysteresis();
        // The audit's exact example: 49/51/49/51 — entirely inside the
        // Allow band [0,150): no flip-flop possible, always Allow.
        $actions = [];
        foreach ([49, 51, 49, 51] as $i => $score) {
            $actions[] = $this->decide($policy, $h, 1, $score, self::T0 + $i)->action;
        }
        self::assertSame([RiskAction::Allow, RiskAction::Allow, RiskAction::Allow, RiskAction::Allow], $actions);

        // The REAL boundary oscillation (the 450 edge): 449 is Sha18,
        // 451 would be Sha20 under the plain mapping — the previous action
        // must hold Sha18 (451 < ENTER[Sha18] = 460) so the profile NEVER
        // flips.
        $h2 = new ScopeActionHysteresis();
        $actions = [];
        foreach ([449, 451, 449, 451, 449, 451] as $i => $score) {
            $actions[] = $this->decide($policy, $h2, 1, $score, self::T0 + $i)->action;
        }
        self::assertSame(
            array_fill(0, 6, RiskAction::Sha18),
            $actions,
            'an oscillating boundary score must not flip the challenge profile'
        );
    }

    public function testSustainedCrossingEntersTheHigherAction(): void
    {
        $policy = $this->policy();
        $h = new ScopeActionHysteresis();
        $now = self::T0;

        // 449 -> Sha18; a brief tick to 455 (plain Sha20) is still inside
        // [EXIT[Sha18]=290, ENTER[Sha18]=460): held.
        self::assertSame(RiskAction::Sha18, $this->decide($policy, $h, 1, 449, $now++)->action);
        self::assertSame(RiskAction::Sha18, $this->decide($policy, $h, 1, 455, $now++)->action);
        // Sustained crossing: 480 >= ENTER[Sha18]=460 -> Sha20, then held.
        self::assertSame(RiskAction::Sha20, $this->decide($policy, $h, 1, 480, $now++)->action);
        self::assertSame(RiskAction::Sha20, $this->decide($policy, $h, 1, 480, $now++)->action);
        // Still inside [EXIT[Sha20]=440, ENTER[Sha20]=610): held even at
        // 590 (plain Argon16) — escalation needs a sustained crossing.
        self::assertSame(RiskAction::Sha20, $this->decide($policy, $h, 1, 590, $now++)->action);
        self::assertSame(RiskAction::Sha20, $this->decide($policy, $h, 1, 590, $now++)->action);
        // 620 >= ENTER[Sha20]=610 -> Argon16, then held.
        self::assertSame(RiskAction::Argon16, $this->decide($policy, $h, 1, 620, $now++)->action);
        self::assertSame(RiskAction::Argon16, $this->decide($policy, $h, 1, 620, $now++)->action);
    }

    public function testSustainedDropExitsTheHigherAction(): void
    {
        $policy = $this->policy();
        $h = new ScopeActionHysteresis();
        $now = self::T0;

        // Climb to Sha20 (480), then drop: 441 is still >= EXIT[Sha20]=440
        // -> held; 439 < 440 -> Sha18; 250 < EXIT[Sha18]=290 -> Sha16, then
        // held (250 >= EXIT[Sha16]=140).
        self::assertSame(RiskAction::Sha20, $this->decide($policy, $h, 1, 480, $now++)->action);
        self::assertSame(RiskAction::Sha20, $this->decide($policy, $h, 1, 441, $now++)->action);
        self::assertSame(RiskAction::Sha18, $this->decide($policy, $h, 1, 439, $now++)->action);
        self::assertSame(RiskAction::Sha16, $this->decide($policy, $h, 1, 250, $now++)->action);
        self::assertSame(RiskAction::Sha16, $this->decide($policy, $h, 1, 250, $now++)->action);
        // Below EXIT[Sha16]=140 -> Allow.
        self::assertSame(RiskAction::Allow, $this->decide($policy, $h, 1, 100, $now++)->action);
    }

    public function testFreshScopeUsesPlainMapping(): void
    {
        $policy = $this->policy();
        // Every score on a fresh scope must equal RiskAction::actionForScore
        // (also pins the internal band table to the policy's bands).
        for ($score = 0; $score <= 1000; $score++) {
            $fresh = new ScopeActionHysteresis();
            self::assertSame(
                RiskAction::actionForScore($score),
                $fresh->select(1, $score, RiskAction::actionForScore($score), self::T0),
                "fresh scope must use the plain mapping at score $score"
            );
        }
    }

    public function testHardOverrideActionsAreNotHysteresisAffected(): void
    {
        $policy = $this->policy();
        $h = new ScopeActionHysteresis();
        $now = self::T0;

        // Deny (plain, score 980) then a 500: the previous action is Deny —
        // NOT hysteresis-affected, the plain mapping applies (Sha20).
        self::assertSame(RiskAction::Deny, $this->decide($policy, $h, 1, 980, $now++)->action);
        self::assertSame(RiskAction::Sha20, $this->decide($policy, $h, 1, 500, $now++)->action);

        // StepUp (plain, score 930) then a 500: plain mapping again.
        self::assertSame(RiskAction::StepUp, $this->decide($policy, $h, 1, 930, $now++)->action);
        self::assertSame(RiskAction::Sha20, $this->decide($policy, $h, 1, 500, $now++)->action);

        // A ladder previous action with a HARD plain action: the hard
        // action wins immediately (never held in the lower band).
        self::assertSame(RiskAction::Sha20, $this->decide($policy, $h, 1, 500, $now++)->action);
        self::assertSame(RiskAction::Deny, $this->decide($policy, $h, 1, 980, $now++)->action);
        self::assertSame(RiskAction::StepUp, $this->decide($policy, $h, 1, 930, $now++)->action);
    }

    public function testHysteresisNeverViolatesMinimumOrFloor(): void
    {
        $policy = $this->policy();
        foreach ([1, 2, 3] as $scope) {
            $h = new ScopeActionHysteresis();
            $now = self::T0;
            for ($score = 0; $score <= 1000; $score += 25) {
                $d = $this->decide($policy, $h, $scope, $score, $now++);
                self::assertGreaterThanOrEqual(
                    $policy->minimum($scope)->rank(),
                    $d->action->rank(),
                    sprintf('scope %d score %d: hysteresis violated its minimum', $scope, $score)
                );
                $d = $this->decide($policy, $h, $scope, $score, $now++, 3);
                self::assertGreaterThanOrEqual(
                    RiskAction::Sha20->rank(),
                    $d->action->rank(),
                    sprintf('scope %d score %d: hysteresis violated the global floor', $scope, $score)
                );
            }
        }
    }

    public function testTtlExpiryForgetsTheScope(): void
    {
        $h = new ScopeActionHysteresis();
        $h->remember(1, RiskAction::Sha20, self::T0);
        self::assertSame(RiskAction::Sha20, $h->lastAction(1, self::T0 + ScopeActionHysteresis::TTL_MS));
        self::assertNull($h->lastAction(1, self::T0 + ScopeActionHysteresis::TTL_MS + 1), 'an entry past TTL must expire');
        self::assertSame(0, $h->count(), 'expired entries are evicted on access');

        // An expired entry also resets the SELECTION: the scope is fresh
        // again and uses the plain mapping.
        $h->select(1, 449, RiskAction::actionForScore(449), self::T0);
        self::assertSame(
            RiskAction::Sha20,
            $h->select(1, 451, RiskAction::actionForScore(451), self::T0 + ScopeActionHysteresis::TTL_MS + 1),
            'after TTL the boundary score must fall back to the plain mapping'
        );
    }

    public function testBoundedMapEvictsTheOldestEntry(): void
    {
        $h = new ScopeActionHysteresis();
        $now = self::T0;
        for ($scope = 1; $scope <= ScopeActionHysteresis::MAX_SCOPES; $scope++) {
            $h->remember($scope, RiskAction::Sha16, $now + $scope);
        }
        self::assertSame(ScopeActionHysteresis::MAX_SCOPES, $h->count());

        // A NEW scope at capacity evicts the least-recently-used entry (scope 1).
        $h->remember(ScopeActionHysteresis::MAX_SCOPES + 1, RiskAction::Sha16, $now + 100_000);
        self::assertSame(ScopeActionHysteresis::MAX_SCOPES, $h->count(), 'the map must stay bounded');
        self::assertNull($h->lastAction(1, $now + 100_000), 'the least-recently-used entry must be evicted');
        self::assertNotNull($h->lastAction(ScopeActionHysteresis::MAX_SCOPES + 1, $now + 100_000));

        // Updates to EXISTING scopes never evict.
        $h->remember(2, RiskAction::Sha20, $now + 100_001);
        self::assertSame(ScopeActionHysteresis::MAX_SCOPES, $h->count());
        self::assertSame(RiskAction::Sha20, $h->lastAction(2, $now + 100_001));
    }

    public function testExpiredEntriesArePurgedBeforeEviction(): void
    {
        $h = new ScopeActionHysteresis();
        $now = self::T0;
        for ($scope = 1; $scope <= ScopeActionHysteresis::MAX_SCOPES; $scope++) {
            $h->remember($scope, RiskAction::Sha16, $now + $scope);
        }
        // All entries expired long ago: the purge alone makes room.
        $h->remember(ScopeActionHysteresis::MAX_SCOPES + 1, RiskAction::Sha16, $now + 10_000_000);
        self::assertSame(1, $h->count());
        self::assertSame(
            RiskAction::Sha16,
            $h->lastAction(ScopeActionHysteresis::MAX_SCOPES + 1, $now + 10_000_000)
        );
    }


    /**
     * Deterministic logical-clock boundary test for the
     * COOLDOWN hold gate (the real-Redis cooldown integration test can
     * legitimately zero-assert if the process is suspended across the
     * whole interval — this pure-function test pins the exact edges).
     * The gate: cooldown denial applies only while
     * nowMs < cooldownUntilMs AND globalLevel >= 4.
     */
    public function testCooldownHoldBoundariesCooldownMinusOneThroughPlusOne(): void
    {
        $policy = $this->policy();
        $h = new ScopeActionHysteresis();
        $cooldown = self::T0 + 10_000;

        $inside = $policy->decide(1, 100, SignalVector::zero(), new ResourcePressure(1000, 1000), 4, $cooldown - 1, $cooldown, $h);
        self::assertSame(RiskAction::Deny, $inside->action, 'cooldown - 1 ms: still inside the hold window -> Deny');
        self::assertContains(RiskReason::Cooldown, $inside->reasons);

        $exact = $policy->decide(1, 100, SignalVector::zero(), new ResourcePressure(1000, 1000), 4, $cooldown, $cooldown, $h);
        self::assertNotSame(RiskAction::Deny, $exact->action, 'cooldown + 0 ms: the hold expires AT the deadline');

        $after = $policy->decide(1, 100, SignalVector::zero(), new ResourcePressure(1000, 1000), 4, $cooldown + 1, $cooldown, $h);
        self::assertNotSame(RiskAction::Deny, $after->action, 'cooldown + 1 ms: fully outside the hold window');
    }

    public function testCooldownHoldRequiresEmergencyLevel(): void
    {
        $policy = $this->policy();
        $h = new ScopeActionHysteresis();
        $cooldown = self::T0 + 10_000;

        // Level 3 (below the emergency threshold) ignores the hold marker:
        // an elevated-but-not-emergency global level must not become a
        // blanket admission stop.
        $level3 = $policy->decide(1, 100, SignalVector::zero(), new ResourcePressure(1000, 1000), 3, $cooldown - 1, $cooldown, $h);
        self::assertNotSame(RiskAction::Deny, $level3->action);
        self::assertNotContains(RiskReason::Cooldown, $level3->reasons);
    }

}
