<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * A named difficulty profile for adaptive-risk issuance.
 *
 * Profiles carry the SAME parameter space as {@see Config} but only the
 * proof-of-work parameters (algorithm, difficulty, and for Argon2id the
 * memory/time/parallelism costs) — TTL and minimum-duration policy stay
 * owned by the issuer's Config. {@see Issuer::issueWithProfile()} clones the
 * issuer Config, overlays the profile, and delegates to the normal
 * {@see Issuer::issue()} path, so the wire format, signing, and storage are
 * identical to a regular issuance.
 *
 * Validation ({@see self::validate()}) enforces the exact bounds Config
 * (and issuance) enforce, so a profile can never mint a challenge the
 * verifier would reject:
 * - SHA-256: targetBits within 1..MAX_SHA_TARGET_BITS (20).
 * - Argon2id: targetBits within 1..MAX_ARGON2_TARGET_BITS (10),
 *   t within 3..MAX_ARGON_T (6), p === 1, mKib within 8..65536.
 */
final readonly class ChallengeProfile
{
    public function __construct(
        public PoWAlgorithm $algorithm,
        public int $targetBits,
        public int $mKib = 0,
        public int $t = 0,
        public int $p = 1,
    ) {
    }

    /** SHA-256 profile at the given difficulty (targetBits 1..20). */
    public static function sha(int $bits): self
    {
        return new self(PoWAlgorithm::Sha256, $bits);
    }

    /** Argon2id, 16 MiB, t=3, p=1, targetBits 1. */
    public static function argon16(): self
    {
        return new self(PoWAlgorithm::Argon2id, 1, 16384, 3, 1);
    }

    /** Argon2id, 32 MiB, t=3, p=1, targetBits 1. */
    public static function argon32(): self
    {
        return new self(PoWAlgorithm::Argon2id, 1, 32768, 3, 1);
    }

    /** Argon2id, 64 MiB, t=3, p=1, targetBits 1. */
    public static function argon64(): self
    {
        return new self(PoWAlgorithm::Argon2id, 1, 65536, 3, 1);
    }

    /**
     * Validate the profile against the same bounds Config/issuance enforce.
     *
     * @throws \InvalidArgumentException when any parameter is out of range
     */
    public function validate(): void
    {
        if ($this->algorithm === PoWAlgorithm::Sha256) {
            if ($this->targetBits < 1 || $this->targetBits > Config::MAX_SHA_TARGET_BITS) {
                throw new \InvalidArgumentException(
                    sprintf('SHA-256 target bits must be within 1..%d (got %d)', Config::MAX_SHA_TARGET_BITS, $this->targetBits)
                );
            }

            return;
        }

        if ($this->targetBits < 1 || $this->targetBits > Config::MAX_ARGON2_TARGET_BITS) {
            throw new \InvalidArgumentException(
                sprintf('Argon2id target bits must be within 1..%d (got %d)', Config::MAX_ARGON2_TARGET_BITS, $this->targetBits)
            );
        }
        if ($this->t < 3 || $this->t > Config::MAX_ARGON_T) {
            throw new \InvalidArgumentException(
                sprintf('Argon2id time cost t must be within 3..%d (got %d)', Config::MAX_ARGON_T, $this->t)
            );
        }
        if ($this->p !== 1) {
            throw new \InvalidArgumentException(
                sprintf('Argon2id parallelism p must be 1 (got %d) — libsodium (PHP) only supports p == 1', $this->p)
            );
        }
        if ($this->mKib < 8 * $this->p || $this->mKib > 65536) {
            throw new \InvalidArgumentException(
                sprintf('Argon2id memory m_kib must be within %d..65536 (got %d)', 8 * $this->p, $this->mKib)
            );
        }
    }
}
