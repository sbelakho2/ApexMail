<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Marks\MarksEscalation;
use KiwiCaptcha\Risk\Marks\MarksView;
use KiwiCaptcha\Risk\Pricing\PriceInputs;
use KiwiCaptcha\Risk\Pricing\PriceModel;
use KiwiCaptcha\Risk\Pricing\ValueClass;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskReason;
use KiwiCaptcha\Risk\SignalVector;
use PHPUnit\Framework\TestCase;

/**
 * Continuous pricing (change.md 3.3.1 and 3.3.2): the property suite of
 * the PHP price model, mirroring the Rust pricing module tests one for
 * one. Both cores prove the identical invariants: monotone in risk,
 * sub-linear in trust, the trusted one-rung bound under full pressure,
 * the full ramp for unproven buckets, floor and cap clamps, and the
 * only-raises composition over the plain and marks stages.
 */
final class PriceModelTest extends TestCase
{
    private const T0 = 1_700_000_000_000;

    private function policy(): RiskPolicy
    {
        return RiskPolicy::fromConfig([
            'version' => 3,
            'weights' => [
                'source_fast' => 190, 'source_slow' => 110, 'subnet_fast' => 80,
                'issue_debt' => 150, 'bad_proof' => 220, 'malformed' => 260,
                'replay' => 320, 'action_failure' => 120, 'scope_switch' => 60,
                'global_pressure' => 170, 'network_risk' => 100,
                'trust_credit' => 130, 'principal_credit' => 100,
            ],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20'],
            ],
            'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
        ]);
    }

    private function healthy(): ResourcePressure
    {
        return new ResourcePressure(1000, 1000);
    }

    private function plain(int $score): \KiwiCaptcha\Risk\RiskDecision
    {
        return $this->policy()->decide(1, $score, SignalVector::zero(), $this->healthy(), 0, self::T0, 0);
    }

    private function inputs(ValueClass $class, int $trust): PriceInputs
    {
        return new PriceInputs($class, $trust);
    }

    public function testConstsTableIsPinned(): void
    {
        self::assertSame(1, PriceModel::version());
        self::assertSame(1000, PriceModel::CONSTS['score_saturation']);
        self::assertSame(10000, PriceModel::CONSTS['trust_saturation']);
        self::assertSame(2500, PriceModel::CONSTS['trust_half_scale']);
        self::assertSame(8000, PriceModel::CONSTS['trusted_bucket_credit']);
        self::assertSame(300, PriceModel::CONSTS['pressure_gain_saturation']);
        self::assertSame([800, 1000, 1200, 1400], PriceModel::CONSTS['value_weights']);
        self::assertSame([150, 300, 450, 600, 700, 790, 880, 970], PriceModel::CONSTS['band_edges']);
        self::assertSame(300, PriceModel::CONSTS['argon_capacity_floor']);
    }

    /**
     * Hand-computed pins of every curve piece, so a systematic error in
     * both cores cannot hide behind the shared corpus.
     */
    public function testHandComputedCurvePins(): void
    {
        // trust factor: none, half scale, clamped at saturation.
        self::assertSame(0, PriceModel::trustFactorMille(0));
        self::assertSame(500, PriceModel::trustFactorMille(2500));
        self::assertSame(666, PriceModel::trustFactorMille(5000));
        self::assertSame(761, PriceModel::trustFactorMille(8000));
        self::assertSame(800, PriceModel::trustFactorMille(10000));
        self::assertSame(800, PriceModel::trustFactorMille(PHP_INT_MAX));

        // pressure ramp: rest, quarter, half, three quarters, saturation.
        self::assertSame(0, PriceModel::pressureGain(0));
        self::assertSame(131, PriceModel::pressureGain(250));
        self::assertSame(225, PriceModel::pressureGain(500));
        self::assertSame(281, PriceModel::pressureGain(750));
        self::assertSame(297, PriceModel::pressureGain(914));
        self::assertSame(300, PriceModel::pressureGain(1000));
        self::assertSame(300, PriceModel::pressureGain(65535));

        // value weights.
        self::assertSame(800, PriceModel::valueWeight(ValueClass::Low));
        self::assertSame(1000, PriceModel::valueWeight(ValueClass::Standard));
        self::assertSame(1200, PriceModel::valueWeight(ValueClass::High));
        self::assertSame(1400, PriceModel::valueWeight(ValueClass::Critical));

        // work scores: trust gates the ramp, clamps hold at both ends.
        self::assertSame(0, PriceModel::workScore(0, ValueClass::Standard, 0, 0));
        self::assertSame(100, PriceModel::workScore(100, ValueClass::Standard, 10000, 0));
        self::assertSame(160, PriceModel::workScore(100, ValueClass::Standard, 10000, 1000));
        self::assertSame(171, PriceModel::workScore(100, ValueClass::Standard, 8000, 1000));
        self::assertSame(400, PriceModel::workScore(100, ValueClass::Standard, 0, 1000));
        self::assertSame(697, PriceModel::workScore(500, ValueClass::High, 4000, 600));
        self::assertSame(1000, PriceModel::workScore(65535, ValueClass::Critical, 0, 1000));

        // quantization corners of the band table.
        $cases = [
            [0, RiskAction::Allow], [149, RiskAction::Allow],
            [150, RiskAction::Sha16], [299, RiskAction::Sha16],
            [300, RiskAction::Sha18], [449, RiskAction::Sha18],
            [450, RiskAction::Sha20], [599, RiskAction::Sha20],
            [600, RiskAction::Argon16], [699, RiskAction::Argon16],
            [700, RiskAction::Argon32], [789, RiskAction::Argon32],
            [790, RiskAction::Argon64], [879, RiskAction::Argon64],
            [880, RiskAction::StepUp], [969, RiskAction::StepUp],
            [970, RiskAction::Deny], [1000, RiskAction::Deny],
        ];
        foreach ($cases as [$score, $expected]) {
            self::assertSame($expected, PriceModel::actionForWorkScore($score), "work score {$score}");
        }
        // The sha-to-argon edge is the policy's own decision boundary.
        self::assertSame(RiskAction::Argon16, PriceModel::actionForWorkScore(600));

        // Priced rungs at the pinned corners.
        self::assertSame(RiskAction::Sha16, PriceModel::price(100, ValueClass::Standard, 10000, 1000));
        self::assertSame(RiskAction::Sha18, PriceModel::price(100, ValueClass::Standard, 0, 1000));
        self::assertSame(RiskAction::Argon16, PriceModel::price(500, ValueClass::High, 4000, 600));
    }

    /**
     * Monotone in risk: raising the risk score never drops the priced
     * rung, for every class, trust and pressure on a dense grid.
     */
    public function testMonotoneInRisk(): void
    {
        foreach ([ValueClass::Low, ValueClass::Standard, ValueClass::High, ValueClass::Critical] as $class) {
            foreach ([0, 2500, 8000, 10000] as $trust) {
                foreach ([0, 250, 500, 1000] as $pressure) {
                    $last = RiskAction::Allow;
                    for ($risk = 0; $risk <= 1000; $risk += 7) {
                        $rung = PriceModel::price($risk, $class, $trust, $pressure);
                        self::assertGreaterThanOrEqual(
                            $last->rank(),
                            $rung->rank(),
                            "risk {$risk} dropped the rung"
                        );
                        $last = $rung;
                    }
                }
            }
        }
    }

    /**
     * Sub-linear in trust: the work score never rises with trust,
     * halving the trust never doubles the residual pressure gate, and
     * the trust factor's gain over equal steps diminishes (concave)
     * within one fixed-point unit of floor rounding.
     */
    public function testSubLinearInTrust(): void
    {
        for ($t = 1; $t <= 10000; $t++) {
            $gHalf = 1000 - PriceModel::trustFactorMille(intdiv($t, 2));
            $gFull = 1000 - PriceModel::trustFactorMille($t);
            self::assertLessThanOrEqual(
                2 * $gFull,
                $gHalf,
                "gate at half of {$t} is {$gHalf}, twice the full gate is {$gFull}"
            );
        }
        foreach ([1, 7, 125, 1000, 2500] as $delta) {
            for ($base = 0; $base <= 10000; $base += 137) {
                if ($base + 2 * $delta > 10000) {
                    continue;
                }
                $gain1 = PriceModel::trustFactorMille($base + $delta) - PriceModel::trustFactorMille($base);
                $gain2 = PriceModel::trustFactorMille($base + 2 * $delta) - PriceModel::trustFactorMille($base + $delta);
                self::assertGreaterThanOrEqual(
                    $gain2 - 1,
                    $gain1,
                    "the trust factor is not concave at {$base}"
                );
            }
        }
        // the work score itself never rises with trust, anywhere
        foreach ([ValueClass::Low, ValueClass::Standard, ValueClass::High, ValueClass::Critical] as $class) {
            foreach ([0, 375, 1000] as $pressure) {
                for ($risk = 0; $risk <= 1000; $risk += 50) {
                    $last = PriceModel::workScore($risk, $class, 0, $pressure);
                    for ($trust = 0; $trust <= 10000; $trust += 97) {
                        $score = PriceModel::workScore($risk, $class, $trust, $pressure);
                        self::assertLessThanOrEqual(
                            $last,
                            $score,
                            "work score rose with trust {$trust}"
                        );
                        $last = $score;
                    }
                }
            }
        }
    }

    /**
     * The 3.3.2 core property: a trusted bucket (credit at or above the
     * documented threshold) with full pressure prices within one rung of
     * its no-pressure price, for every risk and class.
     */
    public function testTrustedFullPressureMovesAtMostOneRung(): void
    {
        foreach ([8000, 9000, 10000] as $trust) {
            foreach ([ValueClass::Low, ValueClass::Standard, ValueClass::High, ValueClass::Critical] as $class) {
                for ($risk = 0; $risk <= 1000; $risk++) {
                    $calm = PriceModel::price($risk, $class, $trust, 0);
                    $storm = PriceModel::price($risk, $class, $trust, 1000);
                    self::assertLessThanOrEqual(
                        1,
                        $storm->rank() - $calm->rank(),
                        "trusted {$trust} risk {$risk} moved too many rungs under full pressure"
                    );
                }
            }
        }
    }

    /**
     * An unproven bucket takes the whole ramp: the untrusted work score
     * is exactly the calm score plus the ramp gain wherever the clamp
     * does not bite. The trusted residual must also stay under the
     * narrowest band gap, the structural half of the one-rung
     * invariant.
     */
    public function testUntrustedTakesTheFullRamp(): void
    {
        for ($risk = 0; $risk <= 700; $risk += 35) {
            $calm = PriceModel::workScore($risk, ValueClass::Standard, 0, 0);
            $storm = PriceModel::workScore($risk, ValueClass::Standard, 0, 1000);
            self::assertSame(300, $storm - $calm, "risk {$risk}");
        }
        $trustedResidual = intdiv(
            PriceModel::pressureGain(1000) * (1000 - PriceModel::trustFactorMille(8000)),
            1000
        );
        $edges = PriceModel::CONSTS['band_edges'];
        $narrowest = PHP_INT_MAX;
        for ($i = 1; $i < count($edges); $i++) {
            $narrowest = min($narrowest, $edges[$i] - $edges[$i - 1]);
        }
        self::assertSame(71, $trustedResidual);
        self::assertLessThan($narrowest, $trustedResidual);
    }

    /**
     * Floor and cap invariants: every output is a ladder rung, and every
     * input clamps at its domain bound instead of wrapping.
     */
    public function testFloorsAndCaps(): void
    {
        foreach ([0, 500, 1000, 65535] as $risk) {
            foreach ([0, 8000, 10000, PHP_INT_MAX] as $trust) {
                foreach ([0, 500, 1000, 65535] as $pressure) {
                    $rung = PriceModel::price($risk, ValueClass::Standard, $trust, $pressure);
                    self::assertLessThanOrEqual(RiskAction::Deny->rank(), $rung->rank());
                    self::assertSame(
                        $rung,
                        PriceModel::price(min($risk, 1000), ValueClass::Standard, min($trust, 10000), min($pressure, 1000)),
                        'the clamps must make over-domain inputs equal their clamped values'
                    );
                }
            }
        }
        self::assertSame(
            PriceModel::workScore(600, ValueClass::Standard, PHP_INT_MAX, 1000),
            PriceModel::workScore(600, ValueClass::Standard, 10000, 1000)
        );
    }

    /**
     * The stage only raises: for a grid of composed decisions and price
     * inputs, the priced decision's action never drops below the
     * composed action and the pass-through fields never change.
     */
    public function testPriceNeverLowersTheComposedAction(): void
    {
        $healthy = $this->healthy();
        for ($score = 0; $score <= 1000; $score += 61) {
            foreach (range(0, 4) as $level) {
                $composed = $this->policy()->decide(1, $score, SignalVector::zero(), $healthy, $level, self::T0, 0);
                foreach ([0, 8000, 10000] as $trust) {
                    foreach ([0, 500, 1000] as $pressure) {
                        foreach ([ValueClass::Low, ValueClass::Standard, ValueClass::High, ValueClass::Critical] as $class) {
                            $out = PriceModel::apply($composed, $this->inputs($class, $trust), $pressure, $healthy);
                            self::assertGreaterThanOrEqual(
                                $composed->action->rank(),
                                $out->action->rank(),
                                "score {$score} level {$level} lowered the action"
                            );
                            self::assertSame($composed->score, $out->score);
                            self::assertSame($composed->band, $out->band);
                            self::assertSame($composed->policyVersion, $out->policyVersion);
                            self::assertSame($composed->modelRevision, $out->modelRevision);
                            self::assertSame($composed->globalLevel, $out->globalLevel);
                            self::assertSame($composed->decisionId, $out->decisionId);
                        }
                    }
                }
            }
        }
    }

    /**
     * Sharp for marked identities: composing marks (the Argon64 floor)
     * and then the price keeps the action at or above the marks floor,
     * so the price never softens the decisive stage.
     */
    public function testPriceNeverSoftensTheMarksFloor(): void
    {
        $now = self::T0;
        $view = MarksView::fromParts(
            ['session' => ['kind' => 'accountBanned', 'count' => 1, 'first_ms' => $now, 'last_ms' => $now]],
            null,
        );
        $healthy = $this->healthy();
        for ($score = 0; $score <= 1000; $score += 37) {
            $composed = $this->policy()->decide(1, $score, SignalVector::zero(), $healthy, 0, $now, 0);
            $marked = MarksEscalation::apply($composed, $view, false, $now, MarksEscalation::DEFAULT_MARK_TTL_MS, $healthy);
            foreach ([0, 8000, 10000] as $trust) {
                foreach ([0, 1000] as $pressure) {
                    $out = PriceModel::apply($marked, $this->inputs(ValueClass::Low, $trust), $pressure, $healthy);
                    self::assertGreaterThanOrEqual(
                        RiskAction::Argon64->rank(),
                        $out->action->rank(),
                        "score {$score} trust {$trust} pressure {$pressure} softened the marks floor"
                    );
                }
            }
        }
    }

    /**
     * The stage prepends its reason exactly like the marks stage, and a
     * saturated backend re-escalates a priced argon rung to the
     * interactive step-up instead of demanding unservable work.
     */
    public function testApplyStageReasonsAndCapacity(): void
    {
        // plain Allow, priced Sha16: raised with the reason.
        $out = PriceModel::apply($this->plain(100), $this->inputs(ValueClass::Standard, 10000), 1000, $this->healthy());
        self::assertSame(RiskAction::Sha16, $out->action);
        self::assertTrue($out->hasReason(RiskReason::PricedEscalation));
        self::assertSame(100, $out->score);
        self::assertSame(1, $out->band);

        // priced rung below the composed action: identical pass-through.
        $composed = $this->plain(980);
        $out = PriceModel::apply($composed, $this->inputs(ValueClass::Low, 10000), 0, $this->healthy());
        self::assertSame($composed->action, $out->action);
        self::assertSame($composed->reasons, $out->reasons);

        // priced argon rung on a saturated backend: step-up with both reasons.
        $saturated = new ResourcePressure(299, 1000);
        $out = PriceModel::apply($this->plain(400), $this->inputs(ValueClass::Standard, 0), 1000, $saturated);
        self::assertSame(RiskAction::StepUp, $out->action);
        self::assertTrue($out->hasReason(RiskReason::PricedEscalation));
        self::assertTrue($out->hasReason(RiskReason::CapacityPressure));

        // priced deny on a saturated backend stays deny (capacity only
        // re-escalates argon rungs).
        $out = PriceModel::apply($this->plain(600), $this->inputs(ValueClass::Critical, 0), 1000, $saturated);
        self::assertSame(RiskAction::Deny, $out->action);
    }

    public function testFailClosedInputsPriceAsUnprovenStandard(): void
    {
        $inputs = PriceInputs::failClosed();
        self::assertSame(ValueClass::Standard, $inputs->valueClass);
        self::assertSame(0, $inputs->bucketTrust);
        self::assertSame(
            PriceModel::workScore(100, ValueClass::Standard, 0, 1000),
            PriceModel::workScore(100, $inputs->valueClass, $inputs->bucketTrust, 1000)
        );
    }

    public function testValueClassWireSpellingsRoundTrip(): void
    {
        foreach (ValueClass::cases() as $class) {
            self::assertSame($class, ValueClass::from($class->value));
        }
        $this->expectException(\ValueError::class);
        ValueClass::from('vip');
    }
}
