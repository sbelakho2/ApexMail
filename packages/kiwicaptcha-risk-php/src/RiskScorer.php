<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * Fixed-point risk scorer, byte-identical with the cross-language contract:
 *
 *   weighted(v, w) = (v * w) / 1000   (integer division)
 *   score(base, s, w) = base
 *       + weighted(source_fast) + weighted(source_slow) + weighted(subnet_fast)
 *       + weighted(issue_debt) + weighted(bad_proof) + weighted(malformed)
 *       + weighted(replay) + weighted(action_failure) + weighted(scope_switch)
 *       + weighted(global_pressure) + weighted(network_risk)
 *       - weighted(trust_credit) - weighted(principal_credit)
 *   clamped to [0, 1000].
 *
 * The SCORE is pure integer math (intdiv) — there is NO float boundary in
 * the scorer (no NaN/Inf can enter; the score is always a
 * bounded int in 0..1000). The only floats in the risk path live in the
 * calibration boundary, which is guarded separately (AggregateCalibrator
 * + calibration.lua).
 */
final class RiskScorer
{
    private static function weighted(int $value, int $weight): int
    {
        return intdiv($value * $weight, 1000);
    }

    public function score(int $base, SignalVector $s, RiskWeights $w): int
    {
        $risk = $base;
        $risk += self::weighted($s->sourceFast, $w->sourceFast);
        $risk += self::weighted($s->sourceSlow, $w->sourceSlow);
        $risk += self::weighted($s->subnetFast, $w->subnetFast);
        $risk += self::weighted($s->issueDebt, $w->issueDebt);
        $risk += self::weighted($s->badProof, $w->badProof);
        $risk += self::weighted($s->malformed, $w->malformed);
        $risk += self::weighted($s->replay, $w->replay);
        $risk += self::weighted($s->actionFailure, $w->actionFailure);
        $risk += self::weighted($s->scopeSwitch, $w->scopeSwitch);
        $risk += self::weighted($s->globalPressure, $w->globalPressure);
        $risk += self::weighted($s->networkRisk, $w->networkRisk);
        $risk -= self::weighted($s->trustCredit, $w->trustCredit);
        $risk -= self::weighted($s->principalCredit, $w->principalCredit);

        return max(0, min(1000, $risk));
    }

    /**
     * Risk-v2 scoring: the risk-v1 score PLUS the weighted risk-v2 evidence
     * factors (honeypot, session client-context inconsistency), clamped to
     * 0..1000. With zero risk-v2 signals this is EXACTLY score() — the v1
     * contract semantics (the 13 signals and their weights) are unchanged;
     * the v2 factors are purely additive.
     */
    public function scoreV2(int $base, SignalVector $s, RiskWeights $w, RiskV2Signals $v2, RiskV2Weights $w2): int
    {
        $risk = $this->score($base, $s, $w);
        $risk += self::weighted($v2->honeypot, $w2->honeypot);
        $risk += self::weighted($v2->sessionInconsistency, $w2->sessionInconsistency);

        return max(0, min(1000, $risk));
    }
}
