<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\ChallengeProfile;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\RiskAction;

/**
 * Maps a risk-v1 decision action to an actual challenge profile for
 * {@see \KiwiCaptcha\Issuer::issueWithProfile()}.
 *
 * Escalation-only, and bounded by the operator's configured algorithm
 * family: the app's own difficulty is the FLOOR, and a decision can never
 * weaken it. Within the configured family the action raises the difficulty:
 *
 *  - sha16/sha18/sha20  -> SHA-256 at 16/18/20 leading zero bits (only when
 *    the configured algorithm is sha256 and the action exceeds the app's
 *    difficulty_bits; no-op otherwise — an argon2id deployment is already
 *    at least as strong).
 *  - argon16/32/64      -> the audited Argon2id profiles (m = 16/32/64 MiB,
 *    t = 3, p = 1, target bits 1 — memory cost is the economic control, NOT
 *    the app's argon2_difficulty_bits). The core's issueWithProfile accepts
 *    a profile directly regardless of the app default, so a SHA-configured
 *    deployment can still issue Argon work via the risk ladder.
 *  - step_up            -> the strongest profile of the configured family
 *    (sha20 / argon64). The bundle cannot perform application-level step-up
 *    (MFA etc.); the hardest challenge is its closest approximation, and
 *    applications may additionally react to the decision themselves.
 *
 *  - allow              -> null: issue with the app's own configuration.
 *
 * `null` always means "no change" — the caller issues with the bundle's
 * configured parameters.
 */
final class RiskProfileResolver
{
    public function __construct(
        private readonly PoWAlgorithm $algorithm,
        private readonly int $shaFloorBits,
    ) {
    }

    public function profileFor(RiskAction $action): ?ChallengeProfile
    {
        return match ($action) {
            RiskAction::Allow => null,
            RiskAction::Sha16 => $this->sha(16),
            RiskAction::Sha18 => $this->sha(18),
            RiskAction::Sha20 => $this->sha(20),
            // Audited profiles: target bits 1, t=3, p=1, memory is the cost.
            RiskAction::Argon16 => ChallengeProfile::argon16(),
            RiskAction::Argon32 => ChallengeProfile::argon32(),
            RiskAction::Argon64 => ChallengeProfile::argon64(),
            // StepUp is handled by the controller (403 STEP_UP_REQUIRED) and
            // must never be mapped to a challenge profile.
            RiskAction::StepUp => throw new \LogicException('StepUp is handled by the controller, not mapped to a profile'),
            RiskAction::Deny => null, // handled by the caller before issuance
        };
    }

    private function sha(int $bits): ?ChallengeProfile
    {
        if ($this->algorithm !== PoWAlgorithm::Sha256 || $bits <= $this->shaFloorBits) {
            return null;
        }

        return ChallengeProfile::sha($bits);
    }
}
