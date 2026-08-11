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
     * Hard ceiling for SHA-256 target bits. The browser/wasm solver caps at
     * 20 bits (MAX_SHA_HASHES = 5,000,000; Rust SOLVER_MAX_TARGET_BITS = 20;
     * ~99.1% solve probability at 20, ~25.9% at 24), so higher difficulties
     * would be unsolvable for legit clients and are rejected at
     * construction.
     */
    public const MAX_SHA_TARGET_BITS = 20;

    /** Ceiling for Argon2id target bits (browser-solvable range). */
    public const MAX_ARGON2_TARGET_BITS = 10;

    /**
     * @param string   $secretKey           HMAC secret key (min 16 bytes recommended).
     * @param PoWAlgorithm $algorithm       Proof-of-work algorithm to issue.
     * @param int      $mKib                Argon2id memory cost in KiB (0 for SHA-256).
     * @param int      $t                   Argon2id time cost.
     * @param int      $p                   Argon2id parallelism.
     * @param int      $targetBits          Leading zero bits for SHA-256 challenges (0..MAX_SHA_TARGET_BITS).
     * @param int      $argon2TargetBits    Leading zero bits for Argon2id challenges (1..MAX_ARGON2_TARGET_BITS).
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
        if ($targetBits < 0 || $targetBits > self::MAX_SHA_TARGET_BITS) {
            throw new \InvalidArgumentException(
                sprintf('SHA-256 target bits must be within 0..%d', self::MAX_SHA_TARGET_BITS)
            );
        }
        if ($algorithm === PoWAlgorithm::Argon2id && ($argon2TargetBits < 1 || $argon2TargetBits > self::MAX_ARGON2_TARGET_BITS)) {
            throw new \InvalidArgumentException(
                sprintf('Argon2id target bits must be within 1..%d (got %d)', self::MAX_ARGON2_TARGET_BITS, $argon2TargetBits)
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
