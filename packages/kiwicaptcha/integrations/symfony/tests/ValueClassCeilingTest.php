<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Economics\ValueClassCeiling;
use PHPUnit\Framework\TestCase;

/**
 * The value-class ceiling verdict: the shipped table stays pinned to
 * the solver's reference-costs.json (one calibration, two surfaces),
 * the calibrated defaults price inside their rung, and a scope
 * configured beyond the ceiling draws the documented escalation answer.
 */
final class ValueClassCeilingTest extends TestCase
{
    public function testThePricingTableIsPinnedToTheSolverReferenceCosts(): void
    {
        $path = \dirname(__DIR__, 4).'/kiwicaptcha-solver/reference-costs.json';
        if (!is_file($path)) {
            self::markTestSkipped('the solver reference-costs.json is not beside the bundle checkout');
        }
        $reference = json_decode((string) file_get_contents($path), true);
        self::assertIsArray($reference);
        $anchors = $reference['economics']['calibration']['anchor_usd_per_1000'] ?? null;
        self::assertIsArray($anchors, 'the solver table carries the measured-cost anchors');

        $byClass = [];
        foreach ($reference['value_classes'] as $class) {
            $byClass[$class['class']] = $class;
        }
        foreach (ValueClassCeiling::PRICING as $class => $row) {
            self::assertArrayHasKey($class, $byClass, "the solver table declares the $class class");
            self::assertSame($byClass[$class]['rung'], $row['rung']);
            self::assertSame($byClass[$class]['declared_abuse_value_usd_per_1000'], $row['declared_usd_per_1000']);
            self::assertSame($anchors[$row['rung']], $row['ceiling_usd_per_1000'], "the $class ceiling is the measured anchor");
        }
    }

    public function testEveryDefaultStakeIsIndependentAndDrawsEscalation(): void
    {
        // The declared stakes are independent (account resale class),
        // never anchor/10. At those stakes raw PoW cannot price any
        // class, so every default verdict is the escalation answer —
        // that is the honest result, and the one D3.3 now measures.
        foreach (ValueClassCeiling::PRICING as $class => $row) {
            [$status, $detail] = ValueClassCeiling::verdict($class, 'allow');
            self::assertSame('WARN', $status, "the shipped $class stake is beyond PoW: ".$detail);
            self::assertStringContainsString('Escalate', $detail);
        }
    }

    public function testABeyondCeilingScopeDrawsTheEscalationAdvice(): void
    {
        $beyond = ['critical' => ['rung' => 'argon64', 'declared_usd_per_1000' => 10.0, 'ceiling_usd_per_1000' => 0.00421]];
        [$status, $detail] = ValueClassCeiling::verdict('critical', 'allow', $beyond);
        self::assertSame('WARN', $status);
        self::assertStringContainsString('cannot price', $detail);
        self::assertStringContainsString('risk.scopes.<name>.minimum', $detail, 'the advice names the enforcement knob');
        self::assertStringContainsString('step_up', $detail);
        self::assertStringContainsString('deny', $detail);
    }

    public function testABeyondCeilingScopeWithTheStepUpMinimumVerifies(): void
    {
        $beyond = ['critical' => ['rung' => 'argon64', 'declared_usd_per_1000' => 10.0, 'ceiling_usd_per_1000' => 0.00421]];
        [$status, $detail] = ValueClassCeiling::verdict('critical', 'step_up', $beyond);
        self::assertSame('PASS', $status, $detail);
        self::assertStringContainsString('verified', $detail);

        [$statusDeny] = ValueClassCeiling::verdict('critical', 'deny', $beyond);
        self::assertSame('PASS', $statusDeny, 'the deny minimum carries the stake the same way');
    }

    public function testAnUnknownClassWarnsInsteadOfGuessing(): void
    {
        [$status, $detail] = ValueClassCeiling::verdict('tier-9', 'allow');
        self::assertSame('WARN', $status);
        self::assertStringContainsString('unknown value class', $detail);
    }
}
