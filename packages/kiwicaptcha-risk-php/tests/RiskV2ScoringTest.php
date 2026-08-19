<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\RiskV2Signals;
use KiwiCaptcha\Risk\RiskV2Weights;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\SignalVector;
use PHPUnit\Framework\TestCase;

/**
 * Risk-v2 evidence factors (honeypot, session client-context consistency):
 * fixed-point semantics byte-identical with the Rust mirror, purely
 * additive over the risk-v1 score, and never a hard denial on their own.
 */
final class RiskV2ScoringTest extends TestCase
{
    private const BASE = 100;

    private function scorer(): RiskScorer
    {
        return new RiskScorer();
    }

    private function v1Score(SignalVector $vector): int
    {
        return $this->scorer()->score(self::BASE, $vector, new RiskWeights());
    }

    public function testDefaultV2WeightsMatchTheCrossLanguageContract(): void
    {
        self::assertSame([
            'honeypot' => 200,
            'session_inconsistency' => 120,
            'tls' => 80,
        ], (new RiskV2Weights())->toArray());
    }

    public function testHoneypotRaisesTheAggregate(): void
    {
        $clean = SignalVector::zero();
        $after = $this->scorer()->scoreV2(
            self::BASE,
            $clean,
            new RiskWeights(),
            new RiskV2Signals(honeypot: 1000),
            new RiskV2Weights(),
        );
        self::assertGreaterThan($this->v1Score($clean), $after);
        self::assertSame(300, $after, '100 + 1000*200/1000');
    }

    public function testHoneypotHitWithCleanVectorStaysBelowDeny(): void
    {
        $after = $this->scorer()->scoreV2(
            self::BASE,
            SignalVector::zero(),
            new RiskWeights(),
            new RiskV2Signals(honeypot: 1000),
            new RiskV2Weights(),
        );
        self::assertLessThan(980, $after, 'a lone honeypot hit must stay below the Deny band');
        self::assertSame(300, $after);
        self::assertNotSame(RiskAction::Deny, RiskAction::actionForScore($after));
    }

    public function testHoneypotPlusElevatedSignalsCrossesDeny(): void
    {
        // bad_proof 1000 (220) + issue_debt 1000 (150) + global_pressure
        // 1000 (170) + source_fast 900 (171) = 711; base 100 -> 811 WITHOUT
        // the honeypot factor (Argon32, no hard-deny thresholds hit).
        $elevated = SignalVector::fromArray([
            'bad_proof' => 1000,
            'issue_debt' => 1000,
            'global_pressure' => 1000,
            'source_fast' => 900,
        ]);
        self::assertSame(811, $this->v1Score($elevated));
        self::assertLessThan(980, $this->v1Score($elevated));

        $after = $this->scorer()->scoreV2(
            self::BASE,
            $elevated,
            new RiskWeights(),
            new RiskV2Signals(honeypot: 1000),
            new RiskV2Weights(),
        );
        self::assertGreaterThanOrEqual(980, $after, 'honeypot + elevated signals must cross Deny');
        self::assertSame(1000, $after);
        self::assertSame(RiskAction::Deny, RiskAction::actionForScore($after));
    }

    public function testConsistentClientContextIsNeutral(): void
    {
        $vector = SignalVector::zero();
        $withV2 = $this->scorer()->scoreV2(
            self::BASE,
            $vector,
            new RiskWeights(),
            RiskV2Signals::zero(),
            new RiskV2Weights(),
        );
        self::assertSame($this->v1Score($vector), $withV2);
    }

    public function testChangedClientContextRaisesTheAggregate(): void
    {
        $clean = SignalVector::zero();
        $after = $this->scorer()->scoreV2(
            self::BASE,
            $clean,
            new RiskWeights(),
            new RiskV2Signals(sessionInconsistency: 1000),
            new RiskV2Weights(),
        );
        self::assertGreaterThan($this->v1Score($clean), $after);
        self::assertSame(220, $after, '100 + 1000*120/1000');
    }

    public function testAbsentClientContextIsNeutral(): void
    {
        $vector = SignalVector::zero();
        self::assertSame(
            $this->v1Score($vector),
            $this->scorer()->scoreV2(self::BASE, $vector, new RiskWeights(), RiskV2Signals::zero(), new RiskV2Weights())
        );
    }

    public function testConsistentTlsTagIsNeutral(): void
    {
        $vector = SignalVector::zero();
        $withV2 = $this->scorer()->scoreV2(
            self::BASE,
            $vector,
            new RiskWeights(),
            new RiskV2Signals(tlsInconsistency: 0),
            new RiskV2Weights(),
        );
        self::assertSame($this->v1Score($vector), $withV2, 'a consistent TLS tag must not change the score');
    }

    public function testChangedTlsTagRaisesTheAggregate(): void
    {
        $clean = SignalVector::zero();
        $after = $this->scorer()->scoreV2(
            self::BASE,
            $clean,
            new RiskWeights(),
            new RiskV2Signals(tlsInconsistency: 1000),
            new RiskV2Weights(),
        );
        self::assertGreaterThan($this->v1Score($clean), $after);
        self::assertSame(180, $after, '100 + 1000*80/1000');
    }

    public function testAbsentTlsTagIsNeutral(): void
    {
        $vector = SignalVector::zero();
        self::assertSame(
            $this->v1Score($vector),
            $this->scorer()->scoreV2(self::BASE, $vector, new RiskWeights(), RiskV2Signals::zero(), new RiskV2Weights())
        );
    }

    public function testV2ZeroSignalsMatchV1ScoreStream(): void
    {
        $scorer = $this->scorer();
        $w = new RiskWeights();
        $w2 = new RiskV2Weights();
        $prng = new SeededVector();
        for ($i = 0; $i < 1000; $i++) {
            $vector = SignalVector::fromArray($prng->vector());
            self::assertSame(
                $scorer->score(self::BASE, $vector, $w),
                $scorer->scoreV2(self::BASE, $vector, $w, RiskV2Signals::zero(), $w2),
                sprintf('iteration %d: v2 zero signals must not move the v1 score', $i)
            );
        }
    }

    public function testRiskV2SignalsValidation(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new RiskV2Signals(honeypot: 1001);
    }

    public function testRiskV2WeightsValidation(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new RiskV2Weights(sessionInconsistency: -1);
    }
}
