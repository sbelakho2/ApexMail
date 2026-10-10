<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Pricing;

use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskDecision;
use KiwiCaptcha\Risk\RiskReason;

/**
 * Continuous work pricing: the additive post-marks decision stage of
 * change.md 3.3.1 and 3.3.2 (the PHP mirror of the Rust pricing module).
 *
 * The stage prices one request as work = price of (risk, value class,
 * bucket trust, scope pressure) and quantizes the continuous score onto
 * the challenge ladder, so the ladder stays the output alphabet. The
 * score adds the value-weighted risk to the gated pressure gain,
 * clamped into 0..1000. The result is monotone in risk, sub-linear in
 * trust, and sharp for marked identities because the upstream marks
 * stage already floors their action at the maximum rung and the price
 * may only raise it.
 *
 * Pressure targets unproven identities only. The pressure gain enters
 * through the trust-factor residual gate over the session's credit in
 * its current ASN bucket. A trusted bucket therefore keeps its
 * individual price within one rung under a full-pressure storm, while
 * an unproven bucket takes the whole ramp. The floor logic of the
 * plain policy (scope minima, global floors, capacity step-ups) keeps
 * applying to every request underneath; the price never weakens any of
 * it.
 *
 * All arithmetic is int with truncating intdiv, so no float boundary can
 * diverge from the Rust core. The constants live in one table (CONSTS)
 * mirrored byte-identically by the Rust core's consts table, and the
 * shared corpus (protocol/risk-v1/pricing-vectors.json) records the
 * table plus the expected outputs, so the two cores can never drift
 * apart silently.
 */
final class PriceModel
{
    /**
     * The one consts table of the price model, mirrored byte-identically
     * by the Rust core's consts table. Every number the curve uses is
     * here and nowhere else, so a revision is one edit plus a version
     * bump.
     *
     * - version: the version stamp of the curve and band table.
     * - score_saturation: the fixed-point ceiling of scores and factors.
     * - trust_saturation: the raw bucket-trust ceiling (the trust plane's
     *   own saturation).
     * - trust_half_scale: the half-scale K of the sub-linear trust factor
     *   trust / (trust + K); at K the factor is one half.
     * - trusted_bucket_credit: the documented trust threshold. The
     *   residual pressure a trusted bucket may take (71 points at the
     *   threshold, 60 at full credit) is structurally below the
     *   narrowest gap of the band table. A trusted price therefore moves
     *   at most one rung.
     * - pressure_gain_saturation: the largest score gain the gate can add
     *   at pressure 1000.
     * - value_weights: per-mille value weights in ValueClass order.
     * - band_edges: the work-score band edges (exclusive upper bounds of
     *   the first eight rungs). The first four edges match
     *   RiskAction::actionForScore; the upper bands widen so the
     *   narrowest consecutive gap (90) exceeds the trusted residual (71)
     *   and the one-rung invariant is structural.
     * - argon_capacity_floor: below this capacity a priced argon rung
     *   re-escalates to the interactive step-up.
     */
    public const CONSTS = [
        'version' => 1,
        'score_saturation' => 1000,
        'trust_saturation' => 10000,
        'trust_half_scale' => 2500,
        'trusted_bucket_credit' => 8000,
        'pressure_gain_saturation' => 300,
        'value_weights' => [800, 1000, 1200, 1400],
        'band_edges' => [150, 300, 450, 600, 700, 790, 880, 970],
        'argon_capacity_floor' => 300,
    ];

    /** The version stamp of the pinned consts table. */
    public static function version(): int
    {
        return self::CONSTS['version'];
    }

    /** The per-mille value weight of a class. */
    public static function valueWeight(ValueClass $class): int
    {
        return $class->weight();
    }

    /**
     * The trust factor in per-mille: 1000 x trust / (trust + K), clamped
     * at the trust saturation first. Sub-linear and concave in trust:
     * 0 at no credit, 500 at K, 761 at the trusted threshold, 800 at
     * full credit. The residual 1000 - factor is the share of the
     * pressure ramp the identity still takes.
     */
    public static function trustFactorMille(int $trust): int
    {
        $trust = min(max(0, $trust), self::CONSTS['trust_saturation']);
        return intdiv(1000 * $trust, $trust + self::CONSTS['trust_half_scale']);
    }

    /**
     * The pressure ramp gain in score points: a monotone concave ramp
     * saturation x (2x - x^2) with x = pressure / 1000, that is
     * gain(p) = saturation x (2000p - p^2) / 1000000. The curve rises
     * fast for small pressure (a storm bites early) and flattens as it
     * approaches the saturation: 0 at rest, 225 at pressure 500, the
     * full 300 at pressure 1000.
     */
    public static function pressureGain(int $pressure): int
    {
        $p = min(max(0, $pressure), self::CONSTS['score_saturation']);
        $unit = 2000 * $p - $p * $p;
        return intdiv(self::CONSTS['pressure_gain_saturation'] * $unit, 1000000);
    }

    /**
     * The continuous work score of one request: the value-weighted risk
     * term plus the gated pressure term, clamped into 0..1000. Every
     * input is clamped to its domain first (risk and pressure at 1000,
     * bucket trust at the trust saturation).
     */
    public static function workScore(int $risk, ValueClass $valueClass, int $bucketTrust, int $pressure): int
    {
        $risk = min(max(0, $risk), self::CONSTS['score_saturation']);
        $riskTerm = intdiv($risk * self::valueWeight($valueClass), self::CONSTS['score_saturation']);
        $gate = self::CONSTS['score_saturation'] - self::trustFactorMille($bucketTrust);
        $gain = self::pressureGain($pressure);
        $pressureTerm = intdiv($gain * $gate, self::CONSTS['score_saturation']);
        return min(self::CONSTS['score_saturation'], $riskTerm + $pressureTerm);
    }

    /**
     * The quantization band table: maps a work score onto the ladder.
     * The edges are the exclusive upper bounds of the first eight rungs;
     * a score at or above the last edge denies. The first four edges are
     * RiskAction::actionForScore's own, so the boundary between the sha
     * and argon regimes (600) is the same number in both tables.
     */
    public static function actionForWorkScore(int $workScore): RiskAction
    {
        $edges = self::CONSTS['band_edges'];
        return match (true) {
            $workScore < $edges[0] => RiskAction::Allow,
            $workScore < $edges[1] => RiskAction::Sha16,
            $workScore < $edges[2] => RiskAction::Sha18,
            $workScore < $edges[3] => RiskAction::Sha20,
            $workScore < $edges[4] => RiskAction::Argon16,
            $workScore < $edges[5] => RiskAction::Argon32,
            $workScore < $edges[6] => RiskAction::Argon64,
            $workScore < $edges[7] => RiskAction::StepUp,
            default => RiskAction::Deny,
        };
    }

    /**
     * The priced rung: the continuous score quantized onto the ladder.
     */
    public static function price(int $risk, ValueClass $valueClass, int $bucketTrust, int $pressure): RiskAction
    {
        return self::actionForWorkScore(self::workScore($risk, $valueClass, $bucketTrust, $pressure));
    }

    /**
     * The price-floor stage: composes the plain decision (band, floors,
     * overrides, hysteresis, marks) with the priced rung. The price may
     * only raise: when the priced rung does not exceed the composed
     * action the decision passes through untouched, and when it does the
     * action rises to the priced rung. A priced argon rung on a
     * saturated backend re-escalates to the interactive step-up exactly
     * like the policy's own capacity check, so the floor never demands
     * memory-hard work the backend cannot serve.
     *
     * Pure; the decision's score, band, policy version, model revision,
     * global level and decision id pass through untouched. Stage reasons
     * prepend exactly like the policy's hard overrides, then deduplicate
     * and cap at 4.
     */
    public static function apply(
        RiskDecision $plain,
        PriceInputs $inputs,
        int $pressure,
        ResourcePressure $resources,
    ): RiskDecision {
        $priced = self::price($plain->score, $inputs->valueClass, $inputs->bucketTrust, $pressure);
        if ($priced->rank() <= $plain->action->rank()) {
            return $plain;
        }
        $action = $priced;
        $stageReasons = [RiskReason::PricedEscalation];
        if ($action->isArgon() && $resources->argonCapacity < self::CONSTS['argon_capacity_floor']) {
            // StepUp outranks every argon rung, so the capacity
            // re-escalation is still a raise over the composed action.
            $action = RiskAction::StepUp;
            $stageReasons[] = RiskReason::CapacityPressure;
        }

        $reasons = $stageReasons;
        foreach ($plain->reasons as $reason) {
            if (!in_array($reason, $reasons, true)) {
                $reasons[] = $reason;
            }
        }

        return new RiskDecision(
            score: $plain->score,
            action: $action,
            reasons: array_slice($reasons, 0, 4),
            policyVersion: $plain->policyVersion,
            globalLevel: $plain->globalLevel,
            retryAfterMs: $plain->retryAfterMs,
            band: $plain->band,
            decisionId: $plain->decisionId,
            modelRevision: $plain->modelRevision,
        );
    }
}
