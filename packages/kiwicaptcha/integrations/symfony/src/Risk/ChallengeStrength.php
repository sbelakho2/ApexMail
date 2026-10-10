<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\Challenge;
use KiwiCaptcha\ChallengeProfile;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\PoWAlgorithm;

/**
 * The complete strength descriptor of a proof-of-work profile or a
 * solved record: the algorithm plus every parameter that determines the
 * work performed (memory, iterations, parallelism, target bits).
 *
 * This is the ONE cross-family strength comparison primitive. Comparing
 * only (algorithm, targetBits) is not sound: two Argon2id challenges at
 * the same target bits but different memory envelopes are not
 * interchangeable, and a memory-hard proof must never be judged by its
 * nonce search space alone. Every strength decision in the bundle goes
 * through {@see RiskProfileResolver::requiredStrength()} and
 * {@see self::dominates()}, so issuance, chaining, stage-2 recovery and
 * the validator's post-solve gate all share exactly one definition of
 * "at least as strong".
 *
 * Dominance requires the same algorithm family and every parameter at or
 * above the required value. Cross-family comparisons are handled by the
 * resolver before this check (the application baseline and the adaptive
 * envelope decide which family is required), never by comparing raw
 * numbers across families.
 */
final class ChallengeStrength
{
    public function __construct(
        public readonly PoWAlgorithm $algorithm,
        public readonly int $mKib,
        public readonly int $t,
        public readonly int $p,
        public readonly int $targetBits,
    ) {
    }

    public static function fromRecord(ChallengeRecord $record): self
    {
        return new self(
            $record->algorithm,
            $record->mKib,
            $record->t,
            $record->p,
            $record->targetBits,
        );
    }

    public static function fromChallenge(Challenge $challenge): self
    {
        return new self(
            $challenge->algorithm,
            $challenge->mKib,
            $challenge->t,
            $challenge->p,
            $challenge->targetBits,
        );
    }

    public static function fromProfile(ChallengeProfile $profile): self
    {
        return new self(
            $profile->algorithm,
            $profile->mKib,
            $profile->t,
            $profile->p,
            $profile->targetBits,
        );
    }

    /**
     * Whether this strength is at least as strong as the required one:
     * the same algorithm family and every work parameter at or above the
     * requirement. A different family never dominates (the resolver
     * already folds the application's baseline family into the
     * requirement, so a weaker family can never satisfy it).
     */
    public function dominates(self $required): bool
    {
        return $this->algorithm === $required->algorithm
            && $this->mKib >= $required->mKib
            && $this->t >= $required->t
            // Parallelism is NOT an ordered "more is stronger" dimension:
            // it changes resource scheduling and wall-clock behavior, not
            // the amount of work. The interoperable Argon profile requires
            // p === 1, so dominance demands exact equality; a future
            // multi-lane profile must model a real cost relation instead
            // of reading one off >=.
            && $this->p === $required->p
            && $this->targetBits >= $required->targetBits;
    }
}
