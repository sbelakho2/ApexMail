<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Configuration for the challenge issuer.
 *
 * Mirrors the Rust crate's `ChallengeConfig` so both implementations produce
 * byte-identical challenges and verify them identically.
 *
 * Argon2id parameter sets are validated against KiwiCaptcha's intentional
 * protocol profile: `t >= 3 && p == 1` (modern libsodium can represent
 * t >= 1 with OPSLIMIT_MIN=1, so the t >= 3 rule is NOT a libsodium
 * limitation — it is the profile KiwiCaptcha issues and verifies, with
 * p == 1 reflecting libsodium's raw Argon2id interface). Parameter sets
 * outside the profile are rejected at construction — issuing them would
 * produce challenges that can never verify in PHP.
 */
enum BindingMode: string
{
    /** Bind challenges to a nonce-bound HMAC tag of the client IP. */
    case Bound = 'bound';

    /** No client binding at all (maximum privacy; relay protection off). */
    case None = 'none';
}

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
     * @param int      $targetBits          Leading zero bits for SHA-256 challenges (1..MAX_SHA_TARGET_BITS).
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
        public readonly BindingMode $bindingMode = BindingMode::Bound,
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
        // 0 bits is rejected: it means "no work at all" and cannot be
        // distinguished from a misconfiguration (e.g. an uninitialized
        // integer default slipping into production).
        if ($targetBits < 1 || $targetBits > self::MAX_SHA_TARGET_BITS) {
            throw new \InvalidArgumentException(
                sprintf('SHA-256 target bits must be within 1..%d', self::MAX_SHA_TARGET_BITS)
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
                    'KiwiCaptcha intentionally requires t >= 3 for its supported protocol profile (got t=%d); p == 1 reflects libsodium\'s raw Argon2id interface — issuing other parameter sets would produce challenges that can never verify in PHP',
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
