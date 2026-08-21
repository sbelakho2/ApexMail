<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * Ordered risk actions, fixed by the cross-language risk-v1 contract.
 *
 * The ordering Allow < Sha16 < Sha18 < Sha20 < Argon16 < Argon32 < Argon64
 * < StepUp < Deny is the escalation ladder. `rank()` is strictly monotonic
 * and is the only comparison that may be used to combine actions: score
 * bands, scope minima, global floors.
 */
enum RiskAction: string
{
    case Allow = 'allow';
    case Sha16 = 'sha16';
    case Sha18 = 'sha18';
    case Sha20 = 'sha20';
    case Argon16 = 'argon16';
    case Argon32 = 'argon32';
    case Argon64 = 'argon64';
    case StepUp = 'step_up';
    case Deny = 'deny';

    /** Strictly monotonic escalation rank: Allow = 0 … Deny = 8. */
    public function rank(): int
    {
        return match ($this) {
            self::Allow => 0,
            self::Sha16 => 1,
            self::Sha18 => 2,
            self::Sha20 => 3,
            self::Argon16 => 4,
            self::Argon32 => 5,
            self::Argon64 => 6,
            self::StepUp => 7,
            self::Deny => 8,
        };
    }

    /**
     * Default score bands (configurable in policy; hard floors apply on top).
     */
    public static function actionForScore(int $score): self
    {
        return match (true) {
            $score < 150 => self::Allow,
            $score < 300 => self::Sha16,
            $score < 450 => self::Sha18,
            $score < 600 => self::Sha20,
            $score < 750 => self::Argon16,
            $score < 850 => self::Argon32,
            $score < 930 => self::Argon64,
            $score < 980 => self::StepUp,
            default => self::Deny,
        };
    }

    public function isArgon(): bool
    {
        return $this === self::Argon16 || $this === self::Argon32 || $this === self::Argon64;
    }
}
