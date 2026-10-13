<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Evidence;

use KiwiCaptcha\Risk\Pricing\PriceModel;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskDecision;
use KiwiCaptcha\Risk\RiskReason;

/**
 * Plane 2 evidence scoring. The interaction-anomaly and solve-anomaly
 * signals derive from the telemetry-v1 payload. They also use the
 * client-performance reference table. These are additive decision
 * factors. Execution-dimension evidence is supplementary. It is never
 * a browser boundary.
 */
final class EvidenceModel
{
    /**
     * The one consts table of the evidence model, mirrored
     * byte-identically by the Rust `EVIDENCE_CONSTS` and pinned by the
     * shared corpus. Every number the model uses is here and nowhere
     * else.
     */
    public const CONSTS = [
        'version' => 1,
        'score_saturation' => 1000,
        'sample_cap' => 32,
        'entropy_max' => 15,
        'entropy_min_samples' => 32,
        'entropy_weight' => 400,
        'focus_weight' => 200,
        'paste_weight' => 400,
        'paste_volume_floor' => 8,
        'paste_ratio_edge' => 900,
        'paste_anomaly_value' => 800,
        'human_band_edge' => 150,
        'agent_evidence_edge' => 400,
        'interaction_weight' => 500,
        'solve_weight' => 500,
        'solve_ratio_saturation_mille' => 1000,
        'band_edges' => [150, 300, 500, 700],
        'max_solve_ms' => 3600000,
    ];

    /** The band rungs in band_edges order; the stage never rises past
     * the first argon rung. */
    private const BAND_RUNGS = [
        RiskAction::Sha16,
        RiskAction::Sha18,
        RiskAction::Sha20,
        RiskAction::Argon16,
    ];

    /** The per-rung fastest-device reference table
     * (protocol/telemetry-v1/client-perf-p1.json); the fixture test
     * asserts this table equals the published file. */
    private const P1_MS = [
        'sha16' => 23,
        'sha18' => 27,
        'sha20' => 27,
        'argon16' => 86,
        'argon32' => 86,
        'argon64' => 86,
        'rsw75k' => 244,
        'rsw150k' => 432,
        'rsw300k' => 810,
    ];

    /**
     * The evidence inputs of one request: the interaction anomaly
     * (0..1000) when a valid payload is present, the solve anomaly
     * (0..1000) when solve facts are present, both null in the
     * neutral-unknown state (never negative).
     */
    public function __construct(
        public readonly ?int $interaction = null,
        public readonly ?int $solve = null,
    ) {
    }

    public function isEmpty(): bool
    {
        return $this->interaction === null && $this->solve === null;
    }

    /**
     * The interaction anomaly of one validated payload, or null for an
     * absent or rejected payload. Integer division everywhere,
     * identical with the Rust mirror.
     */
    public static function interactionAnomaly(?TelemetryPayloadV1 $payload): ?int
    {
        if ($payload === null) {
            return null;
        }
        $c = self::CONSTS;
        $scale = intdiv(min($payload->n, $c['sample_cap']) * 1000, $c['sample_cap']);
        $entropyTerm = $payload->n >= $c['entropy_min_samples']
            ? intdiv(($c['entropy_max'] - $payload->qe) * 1000, $c['entropy_max'])
            : 0;
        $focusTerm = ($payload->ec['fm'] > 0 && $payload->ft === 0) ? 1000 : 0;
        $inputVolume = $payload->ec['ke'] + $payload->ec['pa'];
        $pasteTerm = ($inputVolume >= $c['paste_volume_floor']
            && $payload->ec['pa'] > 0
            && $payload->pt >= $c['paste_ratio_edge']) ? $c['paste_anomaly_value'] : 0;
        $weightedMille = $entropyTerm * $c['entropy_weight']
            + $focusTerm * $c['focus_weight']
            + $pasteTerm * $c['paste_weight'];
        $anomaly = intdiv($weightedMille * $scale, 1000000);

        return min($anomaly, $c['score_saturation']);
    }

    /**
     * The fastest-device reference (milliseconds) for a rung key, or
     * null for a rung the table does not carry (the signal is then
     * neutral: an unknown rung must never fabricate evidence).
     */
    public static function p1Ms(string $rung): ?int
    {
        return self::P1_MS[$rung] ?? null;
    }

    /**
     * The solve anomaly (0..1000) of one solve: the measured solve time
     * against the fastest qualified-device reference for the rung,
     * clamped. A solve at or above the reference scores zero; each
     * per-mille of the reference the solve beats adds one point of
     * anomaly; an instant solve saturates. Absent facts and unknown
     * rungs score zero (neutral), never fabricated evidence.
     */
    public static function solveAnomaly(?int $solveMs, ?string $rung): int
    {
        if ($solveMs === null || $rung === null) {
            return 0;
        }
        $reference = self::p1Ms($rung);
        if ($reference === null) {
            return 0;
        }
        $c = self::CONSTS;
        $solveMs = min($solveMs, $c['max_solve_ms']);
        $ratioMille = intdiv($solveMs * 1000, $reference);
        if ($ratioMille >= $c['solve_ratio_saturation_mille']) {
            return 0;
        }

        return min($c['solve_ratio_saturation_mille'] - $ratioMille, $c['score_saturation']);
    }

    /**
     * Derives the stage inputs from the additive context pieces (payload
     * text plus solve facts). An invalid payload is the neutral-unknown
     * state, never an error and never a negative signal.
     */
    public static function inputs(?string $telemetryPayload, ?int $solveMs, ?string $solveRung): self
    {
        $payload = $telemetryPayload === null ? null : TelemetryPayloadV1::parse($telemetryPayload);
        $solve = ($solveMs !== null && $solveRung !== null)
            ? self::solveAnomaly($solveMs, $solveRung)
            : null;

        return new self(self::interactionAnomaly($payload), $solve);
    }

    /**
     * The evidence stage: composes the plain decision with the
     * interaction and solve evidence. Below the first band edge nothing
     * fired and the decision passes through untouched. At or above it
     * the evidence has fired: the stage reasons prepend (marks-style),
     * and the action rises to the band rung only when that exceeds the
     * composed action, so a deny is never softened and a stronger rung
     * never lowered. The stage never rises past the first argon rung,
     * and an argon band rung on a saturated backend re-escalates to the
     * interactive step-up exactly like the pricing stage's capacity
     * check.
     */
    public static function apply(RiskDecision $plain, self $inputs, ResourcePressure $resources): RiskDecision
    {
        $c = self::CONSTS;
        $combined = intdiv(max(0, $inputs->interaction ?? 0) * $c['interaction_weight'], 1000)
            + intdiv(max(0, $inputs->solve ?? 0) * $c['solve_weight'], 1000);
        $combined = min($combined, $c['score_saturation']);
        $index = null;
        foreach ($c['band_edges'] as $i => $edge) {
            if ($combined >= $edge) {
                $index = $i;
            }
        }
        if ($index === null) {
            return $plain;
        }
        $stageReasons = [];
        if (($inputs->interaction ?? 0) > 0) {
            $stageReasons[] = RiskReason::InteractionAnomaly;
        }
        if (($inputs->solve ?? 0) > 0) {
            $stageReasons[] = RiskReason::SolveAnomaly;
        }
        $rung = self::BAND_RUNGS[$index];
        $action = $plain->action;
        if ($rung->rank() > $action->rank()) {
            $action = $rung;
            if ($action->isArgon() && $resources->argonCapacity < PriceModel::CONSTS['argon_capacity_floor']) {
                $action = RiskAction::StepUp;
                $stageReasons[] = RiskReason::CapacityPressure;
            }
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
