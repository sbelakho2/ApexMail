<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\RiskAction;
use PHPUnit\Framework\TestCase;

final class RiskActionTest extends TestCase
{
    public function testRankIsStrictlyMonotonic(): void
    {
        // (enum cases cannot be array keys in PHP — use ordered pairs)
        $ordered = [
            [RiskAction::Allow, 0],
            [RiskAction::Sha16, 1],
            [RiskAction::Sha18, 2],
            [RiskAction::Sha20, 3],
            [RiskAction::Argon16, 4],
            [RiskAction::Argon32, 5],
            [RiskAction::Argon64, 6],
            [RiskAction::StepUp, 7],
            [RiskAction::Deny, 8],
        ];
        $previous = -1;
        foreach ($ordered as [$action, $rank]) {
            self::assertSame($rank, $action->rank());
            self::assertGreaterThan($previous, $rank, 'rank() must be strictly monotonic');
            $previous = $rank;
        }
    }

    public function testEveryBandBoundary(): void
    {
        $cases = [
            [0, RiskAction::Allow],
            [149, RiskAction::Allow],
            [150, RiskAction::Sha16],
            [299, RiskAction::Sha16],
            [300, RiskAction::Sha18],
            [449, RiskAction::Sha18],
            [450, RiskAction::Sha20],
            [599, RiskAction::Sha20],
            [600, RiskAction::Argon16],
            [749, RiskAction::Argon16],
            [750, RiskAction::Argon32],
            [849, RiskAction::Argon32],
            [850, RiskAction::Argon64],
            [929, RiskAction::Argon64],
            [930, RiskAction::StepUp],
            [979, RiskAction::StepUp],
            [980, RiskAction::Deny],
            [1000, RiskAction::Deny],
        ];
        foreach ($cases as [$score, $action]) {
            self::assertSame($action, RiskAction::actionForScore($score), "score $score");
        }
    }

    public function testBandMonotonicityOverFullRange(): void
    {
        $previous = RiskAction::Allow;
        for ($score = 0; $score <= 1000; $score++) {
            $action = RiskAction::actionForScore($score);
            self::assertGreaterThanOrEqual($previous->rank(), $action->rank());
            $previous = $action;
        }
    }

    public function testNegativeScoreFallsInAllowBand(): void
    {
        self::assertSame(RiskAction::Allow, RiskAction::actionForScore(-100));
    }

    public function testArgonDetection(): void
    {
        foreach ([RiskAction::Argon16, RiskAction::Argon32, RiskAction::Argon64] as $a) {
            self::assertTrue($a->isArgon());
        }
        foreach ([RiskAction::Allow, RiskAction::Sha16, RiskAction::Sha20, RiskAction::StepUp, RiskAction::Deny] as $a) {
            self::assertFalse($a->isArgon());
        }
    }
}
