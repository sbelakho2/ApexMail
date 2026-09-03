<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Configuration for the challenge issuer.
 *
 * Mirrors the Rust crate's `ChallengeConfig` so both implementations
 * produce byte-identical challenges and verify them identically.
 *
 * Argon2id parameter sets are validated against KiwiCaptcha's intentional
 * protocol profile: `t >= 3 && p == 1`. Modern libsodium can represent
 * t >= 1 with its minimum opslimit, so the t >= 3 rule is not a
 * libsodium limitation; it is the profile KiwiCaptcha issues and
 * verifies, with p == 1 reflecting libsodium's raw Argon2id interface.
 * Parameter sets outside the profile are rejected at construction;
 * issuing them would produce challenges that can never verify in PHP.
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
     * Hard ceiling for SHA-256 target bits. The browser/wasm solver caps
     * at 20 bits (5,000,000 hashes), so higher difficulties would be
     * unsolvable for legit clients and are rejected at construction.
     *
     * The ceiling is not the baseline: 18 is the ordinary default,
     * converged across the core, the Symfony bundle and the documented
     * examples. The 16-vs-18 choice is benchmark-driven: the
     * client-performance lab measures the SHA 16/18/20 ladder, and 18
     * is the benchmark-selected ordinary baseline (mean ≈ 262k hashes,
     * p99 ≈ 1.21M, exhaustion within the 5,000,000-hash cap
     * ≈ 5.2×10⁻⁹). SHA20 stays the elevated rung, reached via adaptive
     * risk escalation: at 20 a legitimate solve still fails within the
     * 5,000,000-hash cap with probability ≈ 0.8494% (about 1 in 118),
     * so 20 is never the default.
     */
    public const MAX_SHA_TARGET_BITS = 20;

    /** Ceiling for Argon2id target bits (browser-solvable range). */
    public const MAX_ARGON2_TARGET_BITS = 10;

    /**
     * Absolute protocol difficulty floor for a stored record's target
     * bits: validation rejects 0, since "no work at all" cannot be
     * distinguished from an uninitialized misconfiguration.
     */
    public const MIN_DIFFICULTY = 1;

    /**
     * Absolute protocol difficulty ceiling for a stored record's target
     * bits, the solver ceiling shared by both algorithms. The verifier's
     * validate_record guard accepts 1..20 for SHA-256 and Argon2id
     * records, so the leading-zero comparison is only ever run against a
     * bounded, validated difficulty. Issuance keeps the narrower
     * per-algorithm ceilings (20 and 10).
     */
    public const MAX_DIFFICULTY = 20;

    /**
     * Hard ceiling for a challenge's lifetime (expires_at - issued_at).
     * The verifier rejects any stored record with a longer lifetime as
     * malformed (it cannot have come from a KiwiCaptcha issuer), so
     * issuance must refuse to mint one in the first place.
     */
    public const MAX_TTL_SECS = 300;

    /**
     * The floor for the rsw sequential-squaring cost T. Below it the
     * challenge would finish too fast to carry meaningful sequential
     * cost, so issuance refuses the value at configuration time.
     */
    public const MIN_RSW_T = 10_000;

    /**
     * The ceiling for the rsw sequential-squaring cost T. The browser
     * BigInt solver completes 300,000 squarings in about a second on a
     * mid-range device, so the ceiling keeps a legitimate solve inside
     * the challenge lifetime while the sequential cost stays material.
     */
    public const MAX_RSW_T = 300_000;

    /**
     * The rsw canonical target_bits pin. The v2 canonical always carries
     * a target_bits value within the uniform protocol bounds 1..20, and
     * rsw has no leading-zero target, so issuance pins the protocol
     * floor. The rsw proof check never reads the field.
     */
    public const RSW_TARGET_BITS_PIN = 1;

    /**
     * Ceiling for Argon2id time cost at issuance (browser-solver policy):
     * the browser solver caps at 6, so higher values would be unsolvable
     * for legit clients and issuance refuses them. This is distinct from
     * the verifier's structural ceiling of 16 passes: a signed record
     * with t in 7..16 passes the verifier's structural gates but is
     * never issued.
     */
    public const MAX_ARGON_T = 6;

    /**
     * @param string   $secretKey           HMAC secret key (min 16 bytes recommended).
     * @param PoWAlgorithm $algorithm       Proof-of-work algorithm to issue.
     * @param int      $mKib                Argon2id memory cost in KiB (0 for SHA-256).
     * @param int      $t                   Argon2id time cost.
     * @param int      $p                   Argon2id parallelism.
     * @param int      $targetBits          Leading zero bits for SHA-256 challenges (1..20).
     * @param int      $argon2TargetBits    Leading zero bits for Argon2id challenges (1..10).
     * @param int      $ttlSecs             Challenge lifetime in seconds.
     * @param int|null $minDurationMs       Minimum solve duration (null = derive from difficulty).
     * @param int      $solverMaxHashes     Solver cap used by the widget (informational).
     * @param int      $policyVersion       Security-policy epoch stamped into every issued
     *                                      record (mirrors Rust
     *                                      ChallengeConfig.policy_version). The verifier
     *                                      rejects records issued under a different epoch
     *                                      (WrongPolicyVersion). Cosmetic configuration
     *                                      changes must not bump it.
     * @param string|null $issuer           Deployment identity stamped into every issued
     *                                      record (mirrors Rust
     *                                      ChallengeConfig.issuer), e.g. "dev", "staging",
     *                                      "prod". A verifier configured with an expected
     *                                      issuer rejects records issued by a different
     *                                      deployment (WrongIssuer): a compartment that
     *                                      holds even when deployments share secret keys.
     *                                      Null (default) stamps an unbound record.
     * @param int      $kid                 Signing key id stamped into every issued record
     *                                      (mirrors Rust ChallengeConfig.kid,
     *                                      default 1) and signed as the final v2 canonical
     *                                      field (`|<kid>`). The verifier selects the
     *                                      signature secret per kid via `secretsByKid`
     *                                      (UnknownKid when the record's kid is unknown or
     *                                      ahead of the newest configured kid, the
     *                                      rollback/forward guard).
     * @param string|null $executionKey     The ExecutionChallengeV1 keyed-PRF key (min 16
     *                                      bytes). Null (default) = execution challenges
     *                                      are never issued: issuance with the execution
     *                                      surface armed refuses (the issuer throws), so
     *                                      a deployment cannot arm the dimension without
     *                                      the key. The key never leaves the server: it
     *                                      only feeds the program generator; the browser
     *                                      digest uses the program blob itself as its
     *                                      content-derived key.
     * @param string|null $rswModulusN      The rsw modulus n = p*q as canonical
     *                                      standard base64 of exactly 256 bytes (top bit
     *                                      set, odd), the public half of the time-lock
     *                                      trapdoor. Required when algorithm is rsw;
     *                                      ignored otherwise (null default = the rsw
     *                                      algorithm is not configured).
     * @param string|null $rswLambda        The rsw secret lambda = lcm(p-1, q-1) as
     *                                      canonical standard base64 of 1..256 even
     *                                      bytes, the trapdoor that lets the server
     *                                      verify without the T squarings. Required
     *                                      when algorithm is rsw; ignored otherwise.
     * @param int      $rswT                The rsw sequential-squaring cost T
     *                                      (default 75,000; validated to 10,000..300,000
     *                                      when algorithm is rsw). The client performs T
     *                                      sequential modular squarings; the server
     *                                      verifies instantly through lambda.
     */
    public function __construct(
        public readonly string $secretKey,
        public readonly PoWAlgorithm $algorithm = PoWAlgorithm::Sha256,
        public readonly int $mKib = 0,
        public readonly int $t = 3,
        public readonly int $p = 1,
        public readonly int $targetBits = 18,
        public readonly int $argon2TargetBits = 8,
        public readonly int $ttlSecs = 120,
        public readonly ?int $minDurationMs = null,
        public readonly int $solverMaxHashes = 5_000_000,
        public readonly BindingMode $bindingMode = BindingMode::Bound,
        public readonly int $policyVersion = 1,
        public readonly ?string $issuer = null,
        public readonly int $kid = 1,
        public readonly ?string $executionKey = null,
        public readonly ?string $rswModulusN = null,
        public readonly ?string $rswLambda = null,
        public readonly int $rswT = 75_000,
    ) {
        if (\strlen($secretKey) < 16) {
            throw new \InvalidArgumentException('KiwiCaptcha secret key must be at least 16 bytes');
        }
        if ($executionKey !== null && \strlen($executionKey) < 16) {
            throw new \InvalidArgumentException('KiwiCaptcha execution key must be at least 16 bytes');
        }
        if ($kid < 1 || $kid > 4_294_967_295) {
            throw new \InvalidArgumentException(
                sprintf('signing key id (kid) must be within 1..4294967295 (got %d)', $kid)
            );
        }
        if ($issuer !== null && !self::isValidIdentifier($issuer, 128)) {
            throw new \InvalidArgumentException(
                'issuer must be 1-128 characters of [A-Za-z0-9._:-] when set'
            );
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
        if ($algorithm === PoWAlgorithm::Argon2id && ($t < 3 || $t > self::MAX_ARGON_T)) {
            throw new \InvalidArgumentException(
                sprintf(
                    'KiwiCaptcha intentionally requires t >= 3 for its supported protocol profile (got t=%d); p == 1 reflects libsodium\'s raw Argon2id interface — issuing other parameter sets would produce challenges that can never verify in PHP',
                    $t
                )
            );
        }
        // min_duration_ms must be 0 <= ms < ttl*1000: a floor at or above
        // the TTL makes every solution either TooFast or Expired — no
        // submission can ever be accepted (verification checks expiry
        // before the floor). The Rust schema is unsigned, so negatives are
        // rejected for cross-language record parity too.
        if (
            $minDurationMs !== null
            && (
                $minDurationMs < 0
                || $minDurationMs >= $ttlSecs * 1000
            )
        ) {
            throw new \InvalidArgumentException(
                'min_duration_ms must be >= 0 and less than the challenge TTL in ms (ttlSecs * 1000)'
            );
        }
        if ($ttlSecs < 1 || $ttlSecs > self::MAX_TTL_SECS) {
            throw new \InvalidArgumentException(
                sprintf('challenge TTL must be within 1..%d seconds (got %d) — the verifier rejects longer lifetimes as malformed', self::MAX_TTL_SECS, $ttlSecs)
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
        // The rsw algorithm is opt-in and requires the full trapdoor
        // configuration: the modulus and lambda are mandatory, valid and
        // consistent (validated by the shared Rsw decode), and the
        // sequential cost T must sit within the issuance bounds. With any
        // other algorithm the rsw fields are inert and unvalidated, so
        // the default deployment never touches them.
        if ($algorithm === PoWAlgorithm::Rsw) {
            if ($rswModulusN === null || $rswLambda === null) {
                throw new \InvalidArgumentException(
                    'the rsw algorithm requires rsw_modulus_n and rsw_lambda (base64, see Rsw)'
                );
            }
            try {
                new Rsw($rswModulusN, $rswLambda);
            } catch (\InvalidArgumentException $e) {
                throw new \InvalidArgumentException('invalid rsw trapdoor configuration: '.$e->getMessage());
            }
            if ($rswT < self::MIN_RSW_T || $rswT > self::MAX_RSW_T) {
                throw new \InvalidArgumentException(
                    sprintf(
                        'rsw_t (sequential squarings) must be within %d..%d (got %d)',
                        self::MIN_RSW_T,
                        self::MAX_RSW_T,
                        $rswT
                    )
                );
            }
        }
    }

    /**
     * The narrow security-identifier alphabet: the deployment-
     * bound identifiers (issuer, region, request_binding, scope) must match
     * `[A-Za-z0-9._:-]+` so no identifier can smuggle canonical separators
     * ('|'), whitespace, invisible characters, or multi-byte text into a
     * signed payload segment. Shared by Config (issuer), the Issuer
     * (region/scope/request_binding) and the ChallengeRecord parser
     * (region/request_binding/issuer).
     */
    public static function isValidIdentifier(string $value, int $maxBytes): bool
    {
        $len = \strlen($value);

        return $len >= 1
            && $len <= $maxBytes
            && \preg_match('/^[A-Za-z0-9._:-]+$/D', $value) === 1;
    }

    /**
     * Whether $value is a conforming decoy (honeypot) field name: 1..=64
     * bytes of `[A-Za-z0-9_-]` — the exact shape the widget driver
     * validates before rendering the hidden input. The alphabet excludes
     * `|` (and `.`/`:`), so a decoy name can never alter the structure of
     * the v2 canonical signing input. Mirrors the Rust
     * `valid_decoy_field_name`; shared by the Issuer's pool draw and the
     * Verifier's stored-record validation (the malformed-record fail
     * closed).
     */
    public static function isValidDecoyFieldName(string $value): bool
    {
        $len = \strlen($value);

        return $len >= 1
            && $len <= 64
            && \preg_match('/^[A-Za-z0-9_-]+$/D', $value) === 1;
    }
}
