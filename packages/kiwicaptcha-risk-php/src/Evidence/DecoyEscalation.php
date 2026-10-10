<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Evidence;

use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskDecision;
use KiwiCaptcha\Risk\RiskReason;

/**
 * Decoy escalation (change.md 3.2.2): the additive post-marks decision
 * stage that raises a session's price by one rung for the escalation
 * window after a confirmed decoy hit, plus the reader seam the engine
 * wires the stage through. The evidence stage composes right after it,
 * so the two raises stack before the pricing stage. Mirror of the Rust
 * `escalation` module.
 *
 * An escalation, never a block: the raise caps at the interactive
 * step-up, so a Deny never deepens. The window is carried by the store
 * record's TTL (DecoyEscalationStore writes the canonical 10-minute
 * record); the stage itself is a pure one-rung raise over whatever the
 * pipeline has already composed.
 *
 * The gate is part of the contract, never a deployment afterthought.
 * The canonical script (protocol/risk-v1/decoy_escalation.lua) refuses
 * the record op unless the caller passes the autofill-qualification
 * gate as open. The gate is open only when the qualification matrix
 * passes every required surface. Until then the write path writes
 * nothing, so a password manager can never trip the escalation on a
 * real user.
 */
final class DecoyEscalation
{
    /** The escalation window: 10 minutes in milliseconds. */
    public const ESCALATION_TTL_MS = 600000;

    /**
     * The decoy-escalation stage: raises the composed action by exactly
     * one ladder rung, capped at the interactive step-up. Pure; the
     * score, band, policy version, model revision, global level and
     * decision id pass through untouched. The stage reason prepends
     * exactly like the policy's hard overrides, then deduplicates and
     * caps at 4.
     */
    public static function apply(RiskDecision $plain, bool $live): RiskDecision
    {
        if (!$live) {
            return $plain;
        }
        $nextRank = $plain->action->rank() + 1;
        $next = $nextRank >= RiskAction::Deny->rank()
            ? RiskAction::StepUp
            : self::rungAtRank($nextRank);
        if ($next->rank() <= $plain->action->rank()) {
            return $plain;
        }
        $reasons = [RiskReason::DecoyEscalation];
        foreach ($plain->reasons as $reason) {
            if (!in_array($reason, $reasons, true)) {
                $reasons[] = $reason;
            }
        }

        return new RiskDecision(
            score: $plain->score,
            action: $next,
            reasons: array_slice($reasons, 0, 4),
            policyVersion: $plain->policyVersion,
            globalLevel: $plain->globalLevel,
            retryAfterMs: $plain->retryAfterMs,
            band: $plain->band,
            decisionId: $plain->decisionId,
            modelRevision: $plain->modelRevision,
        );
    }

    private static function rungAtRank(int $rank): RiskAction
    {
        return match ($rank) {
            0 => RiskAction::Allow,
            1 => RiskAction::Sha16,
            2 => RiskAction::Sha18,
            3 => RiskAction::Sha20,
            4 => RiskAction::Argon16,
            5 => RiskAction::Argon32,
            6 => RiskAction::Argon64,
            7 => RiskAction::StepUp,
            default => RiskAction::Deny,
        };
    }
}
