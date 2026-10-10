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
 *    ladder within 1..Config::MAX_ARGON2_TARGET_BITS ([1, 2, 4] by
 *    default, Argon16 -> 1, Argon32 -> 2, Argon64 -> 4). The server's
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
     * Calibration note: the highest Argon rung (target 4, about 16
     * expected Argon2id evaluations at the fixed 16 MiB envelope). The
     * ladder was retuned from [1, 4, 8] to [1, 2, 4] after the
     * client-performance lab measured the 8-bit rung at ~16 s p95
     * on a mainstream desktop, above the absolute 5000 ms UX ceiling.
     * Calibrate the rung against physical low-end mobile hardware:
     * cheap and mid-range Android, older and recent iPhone,
     * battery-saver and thermal-throttled states. Measure p50/p95/p99
     * solve time and failure rate; desktop estimates do not transfer.
     * The lab is tools/client-perf (the client-performance harness):
     * the emulation tiers are runnable now and are the regression
     * signal. The physical-device tiers are the release boundary; see
     * tools/client-perf/README.md "Release qualification" for the
     * procedure. The rung must never be weakened based on
     * client-reported device capabilities, since bots lie. If it proves
     * too expensive for legitimate mobile users, adjust the
     * server-selected ladder globally or transition earlier to StepUp.
     *     * @param PoWAlgorithm $algorithm             the deployment's configured
     *                                            algorithm. This is the baseline family.
     * @param int          $difficultyBits        the configured SHA target bits.
     *                                            This is the application floor for
     *                                            the sha256 family.
     * @param int          $argonMKib             the configured Argon2id memory
     *                                            (argon_m_kib). Part of the
     *                                            application floor for the
     *                                            argon2id family.
     * @param int          $argonT                the configured Argon2id
     *                                            iterations (argon_t).
     * @param int          $argonP                the configured Argon2id
     *                                            parallelism (argon_p).
     * @param int          $argon2DifficultyBits  the configured Argon2id target
     *                                            bits (argon2_difficulty_bits).
     * @param int          $argonEnvelopeMemoryKib the fixed adaptive memory
     *                                            envelope
     *                                            (risk.argon_verification_memory_kib):
     *                                            the adaptive Argon ladder raises
     *                                            the nonce search space, never
     *                                            below this envelope.
     * @param list<int>    $argonTargetBits       the 3-rung target-bits ladder
     *                                            (risk.argon_escalation_target_bits).
     */
    public function __construct(
        private readonly PoWAlgorithm $algorithm,
        private readonly int $difficultyBits,
        private readonly int $argonMKib = 16384,
        private readonly int $argonT = 3,
        private readonly int $argonP = 1,
        private readonly int $argon2DifficultyBits = 1,
        private readonly int $argonEnvelopeMemoryKib = 16384,
        private readonly array $argonTargetBits = [1, 2, 4],
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

    /**
     * The application's own configured strength: the floor every
     * issuance, chain requirement and strength comparison preserves.
     */
    public function baseline(): ChallengeStrength
    {
        return match ($this->algorithm) {
            PoWAlgorithm::Sha256 => new ChallengeStrength(PoWAlgorithm::Sha256, 0, 0, 1, $this->difficultyBits),
            PoWAlgorithm::Argon2id => new ChallengeStrength(
                PoWAlgorithm::Argon2id,
                $this->argonMKib,
                $this->argonT,
                $this->argonP,
                $this->argon2DifficultyBits,
            ),
            // RSW has no adaptive-risk ordering: the bundle refuses
            // rsw + risk at configuration time, so a resolver can never
            // be constructed over an RSW deployment.
            PoWAlgorithm::Rsw => throw new \LogicException(
                'rsw has no adaptive-risk strength ordering; it cannot participate in profile escalation',
            ),
        };
    }

    /**
     * The complete required strength for an action: the monotonic
     * maximum of the application's configured baseline and the adaptive
     * requirement. Null for Allow (nothing beyond the baseline), and for
     * the terminal actions the caller handles before issuance.
     *
     * Cross-family rules (the ONE place the family order is defined):
     *
     *  - A SHA rung on an Argon baseline keeps the Argon baseline: the
     *    configured memory-hard floor already dominates the SHA rung, so
     *    demanding SHA would be a downgrade.
     *  - An Argon rung on a SHA baseline escalates into the adaptive
     *    Argon envelope, raised to the configured Argon parameters
     *    (argon_m_kib / argon_t / argon_p) so the deployment's own
     *    memory-hard floor is preserved.
     *  - Within a family the parameters are combined monotonically:
     *    mKib, t, p and targetBits are each at or above both the
     *    baseline and the adaptive rung.
     */
    public function requiredStrength(RiskAction $action): ?ChallengeStrength
    {
        $baseline = $this->baseline();

        return match ($action) {
            RiskAction::Allow => null,
            RiskAction::Sha16 => $this->shaRequirement($baseline, $this->shaRung($action)),
            RiskAction::Sha18 => $this->shaRequirement($baseline, $this->shaRung($action)),
            RiskAction::Sha20 => $this->shaRequirement($baseline, $this->shaRung($action)),
            RiskAction::Argon16 => $this->argonRequirement($baseline, $this->argonTargetBits[0]),
            RiskAction::Argon32 => $this->argonRequirement($baseline, $this->argonTargetBits[1]),
            RiskAction::Argon64 => $this->argonRequirement($baseline, $this->argonTargetBits[2]),
            // Terminal actions: handled by the controller before any
            // profile is selected; never satisfiable by a record.
            RiskAction::StepUp,
            RiskAction::Deny => null,
        };
    }

    /**
     * The profile to issue with, or null when issuing the configured
     * baseline already satisfies the action (the baseline is the floor:
     * increasing risk can never weaken the issued work).
     */
    public function profileFor(RiskAction $action): ?ChallengeProfile
    {
        if ($action === RiskAction::StepUp) {
            throw new \LogicException('StepUp is handled by the controller, not mapped to a profile');
        }
        if ($action === RiskAction::Deny) {
            return null;
        }
        $required = $this->requiredStrength($action);
        if ($required === null || $this->baseline()->dominates($required)) {
            return null;
        }

        return new ChallengeProfile(
            $required->algorithm,
            $required->targetBits,
            $required->mKib,
            $required->t,
            $required->p,
        );
    }

    /**
     * Whether a solved record satisfies an action: its complete strength
     * must dominate the action's required strength. The record's own
     * algorithm family decides; the resolver never compares raw numbers
     * across families.
     */
    public function recordSatisfies(ChallengeRecord $record, RiskAction $action): bool
    {
        return $this->strengthSatisfies(ChallengeStrength::fromRecord($record), $action);
    }

    /**
     * Whether a minted profile/challenge strength satisfies an action:
     * the same complete comparison as {@see recordSatisfies()}, usable
     * before a stored record exists.
     */
    public function strengthSatisfies(ChallengeStrength $strength, RiskAction $action): bool
    {
        if ($action === RiskAction::Allow) {
            return true;
        }
        if ($action === RiskAction::StepUp || $action === RiskAction::Deny) {
            return false;
        }
        $required = $this->requiredStrength($action);

        return $required !== null && $strength->dominates($required);
    }

    private function shaRequirement(ChallengeStrength $baseline, int $bits): ChallengeStrength
    {
        if ($baseline->algorithm === PoWAlgorithm::Sha256) {
            // Same family: the application floor and the fixed rung max.
            return new ChallengeStrength(PoWAlgorithm::Sha256, 0, 0, 1, max($baseline->targetBits, $bits));
        }
        // The configured memory-hard baseline already dominates the SHA
        // rung; requiring SHA work would downgrade the deployment, so the
        // requirement stays the baseline itself.
        return $baseline;
    }

    private function argonRequirement(ChallengeStrength $baseline, int $bits): ChallengeStrength
    {
        if ($baseline->algorithm === PoWAlgorithm::Argon2id) {
            // The application IS an Argon deployment: the adaptive rung
            // preserves its complete configured baseline (memory,
            // iterations, parallelism, target) and raises only what the
            // rung demands.
            return new ChallengeStrength(
                PoWAlgorithm::Argon2id,
                max($baseline->mKib, $this->argonEnvelopeMemoryKib),
                max($baseline->t, 3),
                max($baseline->p, 1),
                max($baseline->targetBits, $bits),
            );
        }

        // A SHA baseline escalates into the adaptive Argon envelope
        // alone: the core argon_m_kib/argon_t/argon_p/argon2_difficulty_bits
        // knobs are inert in a sha256 deployment, and borrowing them
        // would let a dormant setting (for example argon_p: 2, which the
        // core only validates for argon2id) build an invalid or
        // unexpectedly expensive profile the moment risk escalates. The
        // adaptive profile is exactly the configured envelope at t=3,
        // p=1 with the rung's target bits, the documented guarantee that
        // risk raises the nonce search space and never the server
        // verification cost.
        return new ChallengeStrength(
            PoWAlgorithm::Argon2id,
            $this->argonEnvelopeMemoryKib,
            3,
            1,
            $bits,
        );
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
