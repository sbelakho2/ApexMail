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
 * Scope action hysteresis.
 *
 * The policy's fixed score bands must not oscillate at their boundaries:
 * a score hovering at a threshold (449/451/449…) would flip the challenge
 * profile on every request. The engine keeps a per-process, bounded,
 * TTL'd map of the last action per scope and client pseudonym. The band
 * selection escalates to the next band only at enter = upper + 10,
 * de-escalates only below exit = lower − 10, and jumps straight to the
 * plain band when the request's own score clears the target margin.
 * Fresh keys and the hard actions (StepUp/Deny) use the plain mapping.
 * The canonical 49/51 example falls entirely inside the Allow band
 * [0,150), so the equivalent boundary-oscillation test uses 449/451 at
 * the 450 edge.
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
            'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
        ]);
    }

    private function decide(RiskPolicy $policy, ScopeActionHysteresis $h, int $scope, int $score, int $nowMs, int $globalLevel = 0, string $clientKey = 'client'): \KiwiCaptcha\Risk\RiskDecision
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
            null,
            $clientKey,
        );
    }

    public function testOscillatingScoreProducesStableAction(): void
    {
        $policy = $this->policy();
        $h = new ScopeActionHysteresis();
        // The canonical example: 49/51/49/51 — entirely inside the
        // Allow band [0,150): no flip-flop possible, always Allow.
        $actions = [];
        foreach ([49, 51, 49, 51] as $i => $score) {
            $actions[] = $this->decide($policy, $h, 1, $score, self::T0 + $i)->action;
        }
        self::assertSame([RiskAction::Allow, RiskAction::Allow, RiskAction::Allow, RiskAction::Allow], $actions);

        // The real boundary oscillation (the 450 edge): 449 is Sha18 and
        // 451 would be Sha20 under the plain mapping. The previous action
        // must hold Sha18 (451 < the Sha18 enter threshold of 460), so the
        // profile never flips.
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
        // the Sha18 band (exit 290, enter 460), so it is held.
        self::assertSame(RiskAction::Sha18, $this->decide($policy, $h, 1, 449, $now++)->action);
        self::assertSame(RiskAction::Sha18, $this->decide($policy, $h, 1, 455, $now++)->action);
        // Sustained crossing: 480 >= the Sha18 enter threshold (460) ->
        // Sha20, then held.
        self::assertSame(RiskAction::Sha20, $this->decide($policy, $h, 1, 480, $now++)->action);
        self::assertSame(RiskAction::Sha20, $this->decide($policy, $h, 1, 480, $now++)->action);
        // Still inside the Sha20 band (exit 440, enter 610): held even at
        // 590 (plain Argon16), since escalation needs a sustained crossing.
        self::assertSame(RiskAction::Sha20, $this->decide($policy, $h, 1, 590, $now++)->action);
        self::assertSame(RiskAction::Sha20, $this->decide($policy, $h, 1, 590, $now++)->action);
        // 620 >= the Sha20 enter threshold (610) -> Argon16, then held.
        self::assertSame(RiskAction::Argon16, $this->decide($policy, $h, 1, 620, $now++)->action);
        self::assertSame(RiskAction::Argon16, $this->decide($policy, $h, 1, 620, $now++)->action);
    }

    public function testSustainedDropExitsTheHigherAction(): void
    {
        $policy = $this->policy();
        $h = new ScopeActionHysteresis();
        $now = self::T0;

        // Climb to Sha20 (480), then drop: 441 is still >= the Sha20 exit
        // threshold (440) and is held; 439 < 440 -> Sha18; 250 < the Sha18
        // exit threshold (290) -> Sha16, then held (250 >= the Sha16 exit
        // threshold of 140).
        self::assertSame(RiskAction::Sha20, $this->decide($policy, $h, 1, 480, $now++)->action);
        self::assertSame(RiskAction::Sha20, $this->decide($policy, $h, 1, 441, $now++)->action);
        self::assertSame(RiskAction::Sha18, $this->decide($policy, $h, 1, 439, $now++)->action);
        self::assertSame(RiskAction::Sha16, $this->decide($policy, $h, 1, 250, $now++)->action);
        self::assertSame(RiskAction::Sha16, $this->decide($policy, $h, 1, 250, $now++)->action);
        // Below the Sha16 exit threshold (140) -> Allow.
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
                $fresh->select(1, 'client', $score, RiskAction::actionForScore($score), self::T0),
                "fresh scope must use the plain mapping at score $score"
            );
        }
    }

    public function testHardOverrideActionsAreNotHysteresisAffected(): void
    {
        $policy = $this->policy();
        $h = new ScopeActionHysteresis();
        $now = self::T0;

        // Deny (plain, score 980) then a 500: the previous action is Deny,
        // which is not hysteresis-affected, so the plain mapping applies
        // (Sha20).
        self::assertSame(RiskAction::Deny, $this->decide($policy, $h, 1, 980, $now++)->action);
        self::assertSame(RiskAction::Sha20, $this->decide($policy, $h, 1, 500, $now++)->action);

        // StepUp (plain, score 930) then a 500: plain mapping again.
        self::assertSame(RiskAction::StepUp, $this->decide($policy, $h, 1, 930, $now++)->action);
        self::assertSame(RiskAction::Sha20, $this->decide($policy, $h, 1, 500, $now++)->action);

        // A ladder previous action with a hard plain action: the hard
        // action wins immediately and is never held in the lower band.
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
        $h->remember(1, 'client', RiskAction::Sha20, self::T0);
        self::assertSame(RiskAction::Sha20, $h->lastAction(1, 'client', self::T0 + ScopeActionHysteresis::TTL_MS));
        self::assertNull($h->lastAction(1, 'client', self::T0 + ScopeActionHysteresis::TTL_MS + 1), 'an entry past TTL must expire');
        self::assertSame(0, $h->count(), 'expired entries are evicted on access');

        // An expired entry also resets the selection: the scope is fresh
        // again and uses the plain mapping.
        $h->select(1, 'client', 449, RiskAction::actionForScore(449), self::T0);
        self::assertSame(
            RiskAction::Sha20,
            $h->select(1, 'client', 451, RiskAction::actionForScore(451), self::T0 + ScopeActionHysteresis::TTL_MS + 1),
            'after TTL the boundary score must fall back to the plain mapping'
        );
    }

    public function testBoundedMapEvictsTheOldestEntry(): void
    {
        $h = new ScopeActionHysteresis();
        $now = self::T0;
        for ($scope = 1; $scope <= ScopeActionHysteresis::MAX_ENTRIES; $scope++) {
            $h->remember($scope, 'client', RiskAction::Sha16, $now + $scope);
        }
        self::assertSame(ScopeActionHysteresis::MAX_ENTRIES, $h->count());

        // A NEW key at capacity evicts the least-recently-used entry (scope 1).
        $h->remember(ScopeActionHysteresis::MAX_ENTRIES + 1, 'client', RiskAction::Sha16, $now + 100_000);
        self::assertSame(ScopeActionHysteresis::MAX_ENTRIES, $h->count(), 'the map must stay bounded');
        self::assertNull($h->lastAction(1, 'client', $now + 100_000), 'the least-recently-used entry must be evicted');
        self::assertNotNull($h->lastAction(ScopeActionHysteresis::MAX_ENTRIES + 1, 'client', $now + 100_000));

        // Updates to existing keys never evict.
        $h->remember(2, 'client', RiskAction::Sha20, $now + 100_001);
        self::assertSame(ScopeActionHysteresis::MAX_ENTRIES, $h->count());
        self::assertSame(RiskAction::Sha20, $h->lastAction(2, 'client', $now + 100_001));
    }

    public function testExpiredEntriesArePurgedBeforeEviction(): void
    {
        $h = new ScopeActionHysteresis();
        $now = self::T0;
        for ($scope = 1; $scope <= ScopeActionHysteresis::MAX_ENTRIES; $scope++) {
            $h->remember($scope, 'client', RiskAction::Sha16, $now + $scope);
        }
        // All entries expired long ago: the purge alone makes room.
        $h->remember(ScopeActionHysteresis::MAX_ENTRIES + 1, 'client', RiskAction::Sha16, $now + 10_000_000);
        self::assertSame(1, $h->count());
        self::assertSame(
            RiskAction::Sha16,
            $h->lastAction(ScopeActionHysteresis::MAX_ENTRIES + 1, 'client', $now + 10_000_000)
        );
    }

    public function testMultiBandEscalationJumpsImmediately(): void
    {
        // Regression: a bot on a fresh key after another client held
        // Allow in the same scope gets Argon64 at once.
        $h = new ScopeActionHysteresis();
        self::assertSame(RiskAction::Allow, $h->select(1, 'legit', 100, RiskAction::Allow, self::T0));
        self::assertSame(
            RiskAction::Argon64,
            $h->select(1, 'bot', 900, RiskAction::Argon64, self::T0 + 1),
            "a fresh client's own score clears every band margin"
        );
        // The same key jumps from Allow to Argon64 in one request too.
        self::assertSame(
            RiskAction::Argon64,
            $h->select(1, 'legit', 900, RiskAction::Argon64, self::T0 + 2)
        );
        // The escalation edge fallback (previous Allow, score 605): the
        // plain band of 605 - 10 = 595 is Sha20 — three ladder bands up in
        // one request, not the adjacent Sha16.
        $h2 = new ScopeActionHysteresis();
        self::assertSame(RiskAction::Allow, $h2->select(1, 'client', 100, RiskAction::Allow, self::T0));
        self::assertSame(RiskAction::Sha20, $h2->select(1, 'client', 605, RiskAction::Argon16, self::T0 + 1));
    }

    public function testLegitimateClientScoreAfterBotStaysAllow(): void
    {
        // Regression: the bot's Argon64 memory must not leak into a
        // different client's key in the same scope.
        $h = new ScopeActionHysteresis();
        self::assertSame(RiskAction::Argon64, $h->select(1, 'bot', 900, RiskAction::Argon64, self::T0));
        self::assertSame(
            RiskAction::Allow,
            $h->select(1, 'legit', 100, RiskAction::Allow, self::T0 + 1),
            'a client with no history maps 100 to Allow'
        );
        self::assertSame(RiskAction::Sha18, $h->select(1, 'other', 449, RiskAction::Sha18, self::T0 + 2));
    }

    public function testMultiBandDropJumpsImmediately(): void
    {
        $h = new ScopeActionHysteresis();
        self::assertSame(RiskAction::Argon64, $h->select(1, 'client', 900, RiskAction::Argon64, self::T0));
        self::assertSame(
            RiskAction::Allow,
            $h->select(1, 'client', 100, RiskAction::Allow, self::T0 + 1),
            'the score clears the target band exit margin'
        );
        // Just above the drop margin the edge fallback lands on the plain
        // band of score + 10 (151 -> Sha16), several ladder bands below the
        // previous Argon64, not the adjacent Argon32.
        $h2 = new ScopeActionHysteresis();
        self::assertSame(RiskAction::Argon64, $h2->select(1, 'client', 900, RiskAction::Argon64, self::T0));
        self::assertSame(RiskAction::Sha16, $h2->select(1, 'client', 141, RiskAction::Allow, self::T0 + 1));
    }

    public function testBoundaryHoverWithinTenHoldsOneBand(): void
    {
        // Enter edge of the Sha18 band: 459 holds, 460 escalates.
        $h = new ScopeActionHysteresis();
        self::assertSame(RiskAction::Sha18, $h->select(1, 'client', 449, RiskAction::Sha18, self::T0));
        self::assertSame(RiskAction::Sha18, $h->select(1, 'client', 451, RiskAction::Sha20, self::T0 + 1));
        self::assertSame(RiskAction::Sha18, $h->select(1, 'client', 455, RiskAction::Sha20, self::T0 + 2));
        self::assertSame(RiskAction::Sha18, $h->select(1, 'client', 459, RiskAction::Sha20, self::T0 + 3));
        self::assertSame(RiskAction::Sha20, $h->select(1, 'client', 460, RiskAction::Sha20, self::T0 + 4));
        // Exit edge of the Sha20 band: 441 holds, 440 drops.
        $h2 = new ScopeActionHysteresis();
        self::assertSame(RiskAction::Sha20, $h2->select(1, 'client', 480, RiskAction::Sha20, self::T0));
        self::assertSame(RiskAction::Sha20, $h2->select(1, 'client', 441, RiskAction::Sha18, self::T0 + 1));
        self::assertSame(RiskAction::Sha18, $h2->select(1, 'client', 440, RiskAction::Sha18, self::T0 + 2));
    }

    public function testDifferentClientsKeepIndependentHistories(): void
    {
        $h = new ScopeActionHysteresis();
        // Client a climbs to Sha20 under the 450 edge.
        self::assertSame(RiskAction::Sha18, $h->select(1, 'a', 449, RiskAction::Sha18, self::T0));
        self::assertSame(RiskAction::Sha20, $h->select(1, 'a', 480, RiskAction::Sha20, self::T0 + 1));
        // Client b on the same scope starts fresh: 100 -> Allow, then the
        // 449 edge uses the plain mapping.
        self::assertSame(RiskAction::Allow, $h->select(1, 'b', 100, RiskAction::Allow, self::T0 + 2));
        self::assertSame(RiskAction::Sha18, $h->select(1, 'b', 449, RiskAction::Sha18, self::T0 + 3));
        // Client a still holds its own Sha20 memory.
        self::assertSame(RiskAction::Sha20, $h->select(1, 'a', 449, RiskAction::Sha18, self::T0 + 4));
        self::assertSame(2, $h->count(), 'one entry per scope and client key');
    }

    public function testPolicyDecideHysteresisIsKeyedPerClient(): void
    {
        $policy = $this->policy();
        $h = new ScopeActionHysteresis();
        $legit = $this->decide($policy, $h, 1, 100, self::T0, 0, 'legit');
        self::assertSame(RiskAction::Allow, $legit->action);
        // The bot's own key jumps straight to Argon64.
        $bot = $this->decide($policy, $h, 1, 900, self::T0 + 1, 0, 'bot');
        self::assertSame(RiskAction::Argon64, $bot->action);
        // A client with no history keeps the plain mapping.
        $fresh = $this->decide($policy, $h, 1, 100, self::T0 + 2, 0, 'fresh');
        self::assertSame(RiskAction::Allow, $fresh->action);
    }


    /**
     * Deterministic logical-clock boundary test for the cooldown hold
     * gate (the real-Redis cooldown integration test can legitimately
     * zero-assert if the process is suspended across the whole interval;
     * this pure-function test pins the exact edges). The gate: cooldown
     * denial applies only while nowMs < cooldownUntilMs and globalLevel
     * >= 4.
     */
    public function testCooldownHoldBoundariesCooldownMinusOneThroughPlusOne(): void
    {
        $policy = $this->policy();
        $h = new ScopeActionHysteresis();
        $cooldown = self::T0 + 10_000;

        $inside = $policy->decide(1, 100, SignalVector::zero(), new ResourcePressure(1000, 1000), 4, $cooldown - 1, $cooldown, $h, clientKey: 'cooldown-client');
        self::assertSame(RiskAction::Deny, $inside->action, 'cooldown - 1 ms: still inside the hold window -> Deny');
        self::assertContains(RiskReason::Cooldown, $inside->reasons);

        $exact = $policy->decide(1, 100, SignalVector::zero(), new ResourcePressure(1000, 1000), 4, $cooldown, $cooldown, $h, clientKey: 'cooldown-client');
        self::assertNotSame(RiskAction::Deny, $exact->action, 'cooldown + 0 ms: the hold expires AT the deadline');

        $after = $policy->decide(1, 100, SignalVector::zero(), new ResourcePressure(1000, 1000), 4, $cooldown + 1, $cooldown, $h, clientKey: 'cooldown-client');
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
        $level3 = $policy->decide(1, 100, SignalVector::zero(), new ResourcePressure(1000, 1000), 3, $cooldown - 1, $cooldown, $h, clientKey: 'cooldown-client');
        self::assertNotSame(RiskAction::Deny, $level3->action);
        self::assertNotContains(RiskReason::Cooldown, $level3->reasons);
    }

}
