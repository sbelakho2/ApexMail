<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Configuration for the challenge issuer.
 *
 * Mirrors the Rust crate's `ChallengeConfig` so both implementations produce
 * byte-identical challenges and verify them identically.
 *
 * Argon2id is validated stricter than the Rust crate: libsodium (the PHP
 * verifier's only Argon2id implementation) cannot represent t < 3 or p != 1,
 * so those parameter sets are rejected at construction — issuing them would
 * produce challenges that can never verify in PHP.
 */
final class Config
{
    /**
     * @param string   $secretKey           HMAC secret key (min 16 bytes recommended).
     * @param PoWAlgorithm $algorithm       Proof-of-work algorithm to issue.
     * @param int      $mKib                Argon2id memory cost in KiB (0 for SHA-256).
     * @param int      $t                   Argon2id time cost.
     * @param int      $p                   Argon2id parallelism.
     * @param int      $targetBits          Leading zero bits for SHA-256 challenges.
     * @param int      $argon2TargetBits    Leading zero bits for Argon2id challenges.
     * @param int      $ttlSecs             Challenge lifetime in seconds.
     * @param int|null $minDurationMs       Minimum solve duration (null = derive from difficulty).
     * @param int      $solverMaxHashes     Solver cap used by the widget (informational).
     */
    public function __construct(
        public readonly string $secretKey,
        public readonly PoWAlgorithm $algorithm = PoWAlgorithm::Sha256,
        public readonly int $mKib = 0,
        public readonly int $t = 3,
        public readonly int $p = 1,
        public readonly int $targetBits = 20,
        public readonly int $argon2TargetBits = 8,
        public readonly int $ttlSecs = 120,
        public readonly ?int $minDurationMs = null,
        public readonly int $solverMaxHashes = 5_000_000,
    ) {
        if (\strlen($secretKey) < 16) {
            throw new \InvalidArgumentException('KiwiCaptcha secret key must be at least 16 bytes');
        }
        if ($t < 1) {
            throw new \InvalidArgumentException('Argon2id time cost t must be >= 1');
        }
        if ($p < 1) {
            throw new \InvalidArgumentException('Argon2id parallelism p must be >= 1');
        }
        if ($algorithm === PoWAlgorithm::Argon2id && $mKib < 8 * $p) {
            throw new \InvalidArgumentException(
                sprintf('Argon2id requires m_kib >= 8 * p (got m_kib=%d, p=%d)', $mKib, $p)
            );
        }
        if ($mKib > 65536) {
            throw new \InvalidArgumentException('Argon2id m_kib exceeds the browser-solvable ceiling (65536)');
        }
        if ($targetBits < 0 || $targetBits > 24) {
            throw new \InvalidArgumentException('SHA-256 target bits must be within 0..24');
        }
        if ($algorithm === PoWAlgorithm::Argon2id && ($argon2TargetBits < 1 || $argon2TargetBits > 10)) {
            throw new \InvalidArgumentException(
                sprintf('Argon2id target bits must be within 1..10 (got %d)', $argon2TargetBits)
            );
        }
        if ($algorithm === PoWAlgorithm::Argon2id && $t < 3) {
            throw new \InvalidArgumentException(
                sprintf(
                    'Argon2id requires t >= 3 (got t=%d): libsodium (PHP) cannot represent t < 3, so issuance would succeed but PHP verification would always fail',
                    $t
                )
            );
        }
        if ($algorithm === PoWAlgorithm::Argon2id && $p !== 1) {
            throw new \InvalidArgumentException(
                sprintf(
                    'Argon2id requires p == 1 (got p=%d): libsodium (PHP) only supports p == 1, so issuance would succeed but PHP verification would always fail',
                    $p
                )
            );
        }
    }
}
