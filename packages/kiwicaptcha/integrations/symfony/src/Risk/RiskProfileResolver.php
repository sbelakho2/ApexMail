<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\ChallengeProfile;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\RiskAction;

/**
 * Maps a risk-v1 decision action to an actual challenge profile for
 * {@see \KiwiCaptcha\Issuer::issueWithProfile()}.
 *
 * Escalation-only, and bounded by the operator's configured algorithm
 * family: the app's own difficulty is the floor, and a decision can never
 * weaken it. Within the configured family the action raises the difficulty:
 *
 *  - sha16/sha18/sha20  -> SHA-256 at 16/18/20 leading zero bits, only
 *    when the configured algorithm is sha256 and the action exceeds the
 *    app's difficulty_bits. It is a no-op otherwise, since an argon2id
 *    deployment is already at least as strong.
 *  - argon16/32/64      -> the fixed-envelope Argon2id ladder: all three
 *    actions use the same server-controlled memory envelope
 *    (risk.argon_verification_memory_kib, default 16384 KiB, t=3, p=1).
 *    The adaptive risk engine never increases the server verification cost
 *    as its difficulty mechanism; escalation happens purely in the target
 *    difficulty. The expected nonce search space rises along
 *    risk.argon_escalation_target_bits, a strictly increasing 3-rung
 *    ladder within 1..Config::MAX_ARGON2_TARGET_BITS ([1, 4, 8] by
 *    default, Argon16 -> 1, Argon32 -> 4, Argon64 -> 8). The server's
 *    per-verification memory cost is then bounded by one value
 *    regardless of the decision. The core's issueWithProfile accepts a profile directly
 *    regardless of the app default, so a SHA-configured deployment can
 *    still issue Argon work via the risk ladder.
 *  - step_up            -> never mapped to a challenge profile. StepUp is
 *    a controller-level application-defined step-up action (the controller
 *    answers it with its own application step-up flow, e.g. MFA); the
 *    resolver only issues challenges for the escalation actions above and
 *    throws for StepUp so a caller can never silently downgrade it to a
 *    challenge.
 *
 *  - allow              -> null: issue with the app's own configuration.
 *
 * `null` always means "no change" — the caller issues with the bundle's
 * configured parameters.
 *
 * The resolver is also the authoritative stage-strength comparison for
 * selective chaining, see {@see self::recordSatisfies()}. Whether a
 * verified challenge record already satisfies a reassessed action is
 * decided with the actual configured ladders (the fixed 16/18/20 SHA
 * rungs and the configured argon ladder), never with hard-coded
 * thresholds.
 */
final class RiskProfileResolver
{
    /**
     * Calibration note: the highest Argon rung (target 8, about 256
     * expected Argon2id evaluations at the fixed 16 MiB envelope) must
     * be calibrated against physical low-end mobile hardware: cheap and
     * mid-range Android, older and recent iPhone, battery-saver and
     * thermal-throttled states. Measure p50/p95/p99 solve time and
     * failure rate; desktop estimates do not transfer. The lab is
     * tools/client-perf (the client-performance harness): the emulation
     * tiers are runnable now and are the regression signal. The
     * physical-device tiers are the release boundary; see
     * tools/client-perf/README.md "Release qualification" for the
     * procedure. The rung must never be weakened based on
     * client-reported device capabilities, since bots lie. If it proves
     * too expensive for legitimate mobile users, adjust the
     * server-selected ladder globally or transition earlier to StepUp.
     *
     * @param int   $argonEnvelopeMemoryKib the fixed Argon2id memory envelope
     *                                      (risk.argon_verification_memory_kib)
     *                                      for all adaptive Argon actions,
     *                                      never the escalation mechanism.
     * @param list<int> $argonTargetBits    the 3-rung target-bits ladder
     *                                      (risk.argon_escalation_target_bits):
     *                                      [Argon16, Argon32, Argon64],
     *                                      strictly increasing within
     *                                      1..Config::MAX_ARGON2_TARGET_BITS.
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
        // Ladder validation (defense in depth — the config tree refuses
        // the same shape at compile time): the rungs must be strictly
        // increasing and bounded by the core's Argon2id widget ceiling.
        if ($this->argonTargetBits[0] < 1
            || $this->argonTargetBits[0] >= $this->argonTargetBits[1]
            || $this->argonTargetBits[1] >= $this->argonTargetBits[2]
            || $this->argonTargetBits[2] > Config::MAX_ARGON2_TARGET_BITS
        ) {
            throw new \InvalidArgumentException(sprintf(
                'argonTargetBits must satisfy 1 <= rung1 < rung2 < rung3 <= %d (the Argon16/32/64 ladder, bounded by Config::MAX_ARGON2_TARGET_BITS)',
                Config::MAX_ARGON2_TARGET_BITS,
            ));
        }
    }

    public function profileFor(RiskAction $action): ?ChallengeProfile
    {
        return match ($action) {
            RiskAction::Allow => null,
            RiskAction::Sha16 => $this->sha($this->shaRung(RiskAction::Sha16)),
            RiskAction::Sha18 => $this->sha($this->shaRung(RiskAction::Sha18)),
            RiskAction::Sha20 => $this->sha($this->shaRung(RiskAction::Sha20)),
            // Fixed-envelope ladder: the memory never escalates with
            // risk — all three actions share the server-controlled
            // envelope at t=3, p=1; only the expected nonce search space
            // (target bits) rises along the configured ladder.
            RiskAction::Argon16 => $this->argon($this->argonTargetBits[0]),
            RiskAction::Argon32 => $this->argon($this->argonTargetBits[1]),
            RiskAction::Argon64 => $this->argon($this->argonTargetBits[2]),
            // StepUp is handled by the controller (403 `STEP_UP_REQUIRED`)
            // and must never be mapped to a challenge profile.
            RiskAction::StepUp => throw new \LogicException('StepUp is handled by the controller, not mapped to a profile'),
            RiskAction::Deny => null, // handled by the caller before issuance
        };
    }

    /**
     * Whether a verified challenge record already satisfies a risk action
     * under the actual configured ladders, the authoritative
     * stage-strength comparison for selective chaining:
     *
     *  - Allow        -> true (the base: any solved challenge satisfies
     *                    the weakest action).
     *  - Sha16/18/20  -> the record's algorithm is SHA-256 and its target
     *                    bits >= the action's fixed SHA rung (16/18/20).
     *  - Argon16/32/64 -> the record's algorithm is Argon2id and its
     *                    target bits >= the action's configured argon rung
     *                    (risk.argon_escalation_target_bits).
     *  - StepUp/Deny  -> false (terminal application-level actions, never
     *                    satisfiable by a record; the chain logic never
     *                    reaches them).
     *
     * The comparison reuses the same ladder the profile mapping uses: a
     * solved challenge satisfies an action exactly when the action's rung
     * is at or below what the client actually solved.
     */
    public function recordSatisfies(ChallengeRecord $record, RiskAction $action): bool
    {
        return match ($action) {
            RiskAction::Allow => true,
            RiskAction::Sha16 => $record->algorithm === PoWAlgorithm::Sha256 && $record->targetBits >= $this->shaRung(RiskAction::Sha16),
            RiskAction::Sha18 => $record->algorithm === PoWAlgorithm::Sha256 && $record->targetBits >= $this->shaRung(RiskAction::Sha18),
            RiskAction::Sha20 => $record->algorithm === PoWAlgorithm::Sha256 && $record->targetBits >= $this->shaRung(RiskAction::Sha20),
            RiskAction::Argon16 => $record->algorithm === PoWAlgorithm::Argon2id && $record->targetBits >= $this->argonTargetBits[0],
            RiskAction::Argon32 => $record->algorithm === PoWAlgorithm::Argon2id && $record->targetBits >= $this->argonTargetBits[1],
            RiskAction::Argon64 => $record->algorithm === PoWAlgorithm::Argon2id && $record->targetBits >= $this->argonTargetBits[2],
            RiskAction::StepUp,
            RiskAction::Deny => false,
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

    /** The fixed SHA rung of a SHA action (16/18/20, not configurable). */
    private function shaRung(RiskAction $action): int
    {
        return match ($action) {
            RiskAction::Sha16 => 16,
            RiskAction::Sha18 => 18,
            RiskAction::Sha20 => 20,
            default => throw new \LogicException('not a SHA action'),
        };
    }
}
