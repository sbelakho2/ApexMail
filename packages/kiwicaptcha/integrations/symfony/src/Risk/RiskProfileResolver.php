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
 *  - argon16/32/64      -> the FIXED-ENVELOPE Argon2id ladder (audit #79):
 *    ALL three actions use the SAME server-controlled memory envelope
 *    (risk.argon_verification_memory_kib, default 16384 KiB, t=3, p=1) —
 *    the adaptive risk engine NEVER increases the server verification cost
 *    as its difficulty mechanism. Escalation happens purely in the TARGET
 *    DIFFICULTY: the expected nonce search space rises along
 *    risk.argon_escalation_target_bits ([1, 4, 8] by default — Argon16 ->
 *    1, Argon32 -> 4, Argon64 -> 8), so the server's per-verification
 *    memory cost is bounded by one value regardless of the decision. The
 *    core's issueWithProfile accepts a profile directly regardless of the
 *    app default, so a SHA-configured deployment can still issue Argon
 *    work via the risk ladder.
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
    /**
     * @param int   $argonEnvelopeMemoryKib the FIXED Argon2id memory envelope
     *                                      (risk.argon_verification_memory_kib)
     *                                      for ALL adaptive Argon actions —
     *                                      never the escalation mechanism
     * @param list<int> $argonTargetBits    the 3-rung target-bits ladder
     *                                      (risk.argon_escalation_target_bits):
     *                                      [Argon16, Argon32, Argon64]
     */
    public function __construct(
        private readonly PoWAlgorithm $algorithm,
        private readonly int $shaFloorBits,
        private readonly int $argonEnvelopeMemoryKib = 16384,
        private readonly array $argonTargetBits = [1, 4, 8],
    ) {
        if (\count($this->argonTargetBits) !== 3) {
            throw new \InvalidArgumentException(
                'argonTargetBits must have EXACTLY 3 entries (the Argon16/32/64 ladder)'
            );
        }
    }

    public function profileFor(RiskAction $action): ?ChallengeProfile
    {
        return match ($action) {
            RiskAction::Allow => null,
            RiskAction::Sha16 => $this->sha(16),
            RiskAction::Sha18 => $this->sha(18),
            RiskAction::Sha20 => $this->sha(20),
            // Fixed-envelope ladder (audit #79): the memory NEVER escalates
            // with risk — all three actions share the server-controlled
            // envelope at t=3, p=1; only the expected nonce search space
            // (target bits) rises along the configured ladder.
            RiskAction::Argon16 => $this->argon($this->argonTargetBits[0]),
            RiskAction::Argon32 => $this->argon($this->argonTargetBits[1]),
            RiskAction::Argon64 => $this->argon($this->argonTargetBits[2]),
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

    /**
     * One rung of the fixed-envelope Argon ladder: the configured envelope
     * memory at t=3, p=1 with the action's escalating target bits.
     */
    private function argon(int $targetBits): ChallengeProfile
    {
        return new ChallengeProfile(PoWAlgorithm::Argon2id, $targetBits, $this->argonEnvelopeMemoryKib, 3, 1);
    }
}
