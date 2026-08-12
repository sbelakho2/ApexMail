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
 *  - argon16/32/64      -> Argon2id at 16/32/64 MiB (t=3, p=1, the app's
 *    argon2_difficulty_bits as the target). When the configured algorithm
 *    is sha256 (no argon solver configured), the action escalates to the
 *    strongest SHA profile instead (sha20) — same intent (more work),
 *    different cost curve.
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
        private readonly int $argon2FloorBits,
    ) {
    }

    public function profileFor(RiskAction $action): ?ChallengeProfile
    {
        return match ($action) {
            RiskAction::Allow => null,
            RiskAction::Sha16 => $this->sha(16),
            RiskAction::Sha18 => $this->sha(18),
            RiskAction::Sha20 => $this->sha(20),
            RiskAction::Argon16 => $this->argon(16384),
            RiskAction::Argon32 => $this->argon(32768),
            RiskAction::Argon64 => $this->argon(65536),
            RiskAction::StepUp => $this->algorithm === PoWAlgorithm::Sha256 ? $this->sha(20) : $this->argon(65536),
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

    private function argon(int $mKib): ?ChallengeProfile
    {
        if ($this->algorithm !== PoWAlgorithm::Argon2id) {
            // SHA-only deployment: escalate to the strongest SHA profile
            // instead of a memory-hard one (the argon solver/config is not
            // part of this deployment's resource profile).
            return $this->sha(20);
        }

        return new ChallengeProfile(
            algorithm: PoWAlgorithm::Argon2id,
            targetBits: $this->argon2FloorBits,
            mKib: $mKib,
            t: 3,
            p: 1,
        );
    }
}
