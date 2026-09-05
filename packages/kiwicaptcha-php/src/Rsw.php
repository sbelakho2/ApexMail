<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * The RSW time-lock trapdoor and its shared arithmetic.
 *
 * The optional experimental rsw algorithm (Rivest-Shamir-Wagner style)
 * is a sequential time-lock: the client squares a challenge-derived
 * base T times modulo a 2048-bit composite n, and the server verifies
 * instantly because it holds the factorization. This class decodes and
 * validates the two operator-configured secrets — the public modulus n
 * and the secret lambda, the Carmichael value lcm(p-1, q-1) of the two
 * primes — and computes the expected final value through the trapdoor.
 *
 * The math: with base derived deterministically from the signed
 * challenge bytes, the client's T sequential squarings produce
 * base^(2^T) mod n. When e = 2^T mod lambda, Euler's theorem gives
 * base^(2^T) ≡ base^e (mod n) for every base, because lambda is a
 * multiple of both p-1 and q-1. The exponent e is never below 1: lambda
 * is even with odd cofactors for 1024-bit primes, so lambda never
 * divides a power of two. The verifier therefore computes base^e mod n
 * with one modular exponentiation, about 2048 squarings, while the
 * client without the factorization must perform the full T squarings.
 *
 * The server never reveals the factorization. The configuration holds
 * only n and lambda, never the primes: an operator who can generate the
 * primes keeps them offline, and a deployment that leaks its config
 * leaks the trapdoor but nothing else. n is public by design (the
 * client squares modulo n), so it also rides the challenge response;
 * lambda never leaves the server configuration.
 *
 * Validation first proves the shape: the modulus must be exactly 256
 * bytes with the top bit set and odd, and lambda must decode to 1..256
 * even bytes. Beyond the shape, three weak or inconsistent inputs are
 * refused: a modulus divisible by any prime at or below 1000, a
 * probable-prime modulus, and a lambda failing the deterministic
 * trapdoor consistency spot-check over the fixed small-prime base
 * set. No product of two 1024-bit primes has a small factor, and a
 * genuine modulus is composite. The spot-check requires base^lambda
 * == 1 modulo n per base; the equality is the exact condition under
 * which the trapdoor shortcut agrees with the client's sequential
 * squaring at every cost T. So a lambda that passes it for every base
 * of the set behaves as the trapdoor at every tested base. It is a
 * spot-check, not a proof: no fixed base set can establish that
 * lambda is the true Carmichael value of n without the factorization,
 * exactly like an RSA public key cannot be verified against its
 * private exponent. Only the first-party generator's p/q construction
 * (tools/rsw-keygen) is guaranteed to produce lambda = lcm(p-1, q-1),
 * so the residual assurance for a deployed pair is its provenance:
 * generate the pair with the shipped rsw-keygen tool and record the
 * modulus fingerprint. Both values are canonical standard base64 of
 * their big-endian bytes.
 *
 * gmp is required for the arithmetic. The optional algorithm is refused
 * at configuration time when the extension is missing, so the default
 * sha256/argon2id deployment never needs it.
 *
 * Performance: validating a pair dominates the Rsw cost. The canonical
 * decode, the small-factor trial division, the probable-prime probe and
 * the eight-base trapdoor spot-check measure ~12.2 ms per construction
 * on an Apple M5 Pro (arm64) under PHP 8.5.10. That is about 7.6x the
 * ~1.6 ms of one expectedProofHex() trapdoor exponentiation at the
 * 75_000-squaring default. A verification can pay the validation
 * twice. The Config and the Verifier each construct an Rsw from the
 * same configured pair, and the standalone php -S route rebuilds both
 * per request. On that route a request used to spend ~26 ms of pair
 * validation ahead of a single ~1.6 ms proof.
 *
 * The validation verdict is deterministic, so Rsw memoizes the decoded
 * pair per process. The cache key is the exact configured base64 pair,
 * and the cache holds at most {@see self::VALIDATED_PAIR_CACHE_MAX}
 * entries. The first construction of a distinct pair in a process still
 * runs the full validation with the identical rejections. Later
 * constructions of the same pair reuse the validated representation.
 * That mirrors the Rust ProductionVerifier, which decodes its trapdoor
 * once at build time. The per-request pair-validation cost is therefore
 * amortized to once per distinct configured pair per process. After the
 * warm-up request a standalone rsw verification pays only the trapdoor
 * exponentiation. Invalid pairs are never memoized. A weak input is
 * re-validated and refused with the identical message on every
 * construction.
 */
final class Rsw
{
    /** The modulus is a 2048-bit composite: exactly 256 bytes. */
    public const MODULUS_BYTES = 256;

    /**
     * The fixed 512-hex wire form of a final value: the 256-byte
     * big-endian residue, zero-padded. Both the solver output and the
     * trapdoor expectation render into this exact shape, so the
     * constant-time comparison runs over equal-length strings.
     */
    public const PROOF_HEX_LENGTH = 512;

    /** The decoded modulus n (2048-bit composite). */
    private readonly \GMP $n;

    /** The decoded secret lambda = lcm(p-1, q-1). */
    private readonly \GMP $lambda;

    /**
     * Redacted dump shape: the four constructor fields print under their
     * property names, with the secret lambda material — the raw
     * `lambdaB64` input and the decoded `lambda` — replaced by
     * '<redacted>'. The modulus half (`modulusB64` and the decoded `n`)
     * is public material (the client squares modulo n) and prints as
     * itself.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'modulusB64' => $this->modulusB64,
            'lambdaB64' => '<redacted>',
            'n' => $this->n,
            'lambda' => '<redacted>',
        ];
    }

    /**
     * The trial-division ceiling of the weak-modulus rejection: any
     * prime factor at or below this bound marks the modulus as
     * severely weak, because a genuine modulus is the product
     * of two primes of roughly 1024 bits.
     */
    private const SMALL_PRIME_LIMIT = 1000;

    /**
     * The fixed base set of the trapdoor consistency spot-check: the
     * primes 2, 3, 5, 7, 11, 13, 17 and 19. Each stays below the
     * trial-division ceiling, so a conforming modulus shares no factor
     * with any base and the exponent reduction of the trapdoor
     * applies.
     */
    private const SELFTEST_BASES = [2, 3, 5, 7, 11, 13, 17, 19];

    /**
     * The cap of the validated-pair cache: at most this many distinct
     * validated (n, lambda) pairs are retained per process. When the
     * cap is full, the earliest inserted validated pair is evicted;
     * cache hits do not alter eviction order. A deployment configures one pair, so the cap
     * engages only in a process that serves several distinct rsw
     * configurations. Eviction is deterministic and never changes a
     * verdict. It only re-runs the full validation of the evicted pair
     * on its next construction.
     */
    private const VALIDATED_PAIR_CACHE_MAX = 8;

    /**
     * The process-lifetime validated-pair memo: canonical base64
     * modulus and lambda joined by a NUL byte, mapped to the decoded
     * and fully validated GMP pair. A NUL byte can never appear in
     * base64, so the key cannot collide across pairs. The validation
     * pipeline is deterministic, so the memoized verdict of a pair
     * equals a fresh validation of the same pair. The memo amortizes
     * the expensive pair validation across the Config and Verifier
     * constructions of the same process. The standalone php -S route
     * rebuilds both per request. Only fully validated pairs are stored.
     * A rejected pair throws before the store, so every weak input is
     * re-validated and refused with the identical message on every
     * construction. See the class docblock for the measured motivation.
     *
     * @var array<string, array{\GMP, \GMP}>
     */
    private static array $validatedPairCache = [];

    /**
     * @param string $modulusB64 canonical standard base64 of the
     *                           2048-bit composite n, exactly 256 bytes
     *                           with the top bit set and odd.
     * @param string $lambdaB64   canonical standard base64 of the
     *                           secret lambda, 1..256 even bytes.
     *
     * @throws \InvalidArgumentException on a malformed modulus or
     *                           lambda, on a modulus with a small prime
     *                           factor or a probable-prime modulus, and
     *                           on a lambda that fails the trapdoor
     *                           consistency spot-check against the
     *                           modulus
     */
    public function __construct(
        private readonly string $modulusB64,
        private readonly string $lambdaB64,
    ) {
        if (!\extension_loaded('gmp')) {
            throw new \InvalidArgumentException(
                'the rsw algorithm requires the gmp extension for its modular arithmetic'
            );
        }
        [$this->n, $this->lambda] = self::validatedPair($modulusB64, $lambdaB64);
    }

    /**
     * Decode and fully validate a configured pair, reusing the memo
     * when the exact same base64 pair was validated earlier in this
     * process. The pipeline keeps the pre-memo constructor order, the
     * same weak-input rejections and the same messages. The verdict of
     * a memoized pair equals a fresh validation of it. A rejected pair
     * is never stored, so it re-runs the full pipeline on every
     * construction. The cache key is the exact configured pair, never a
     * transcoded or truncated form. Oldest entries evict first at
     * {@see self::VALIDATED_PAIR_CACHE_MAX}. A process serving several
     * distinct rsw configurations stays bounded.
     *
     * @return array{\GMP, \GMP} the decoded modulus and lambda.
     *
     * @throws \InvalidArgumentException on a malformed modulus or
     *                           lambda, on a modulus with a small prime
     *                           factor or a probable-prime modulus, and
     *                           on a lambda that fails the trapdoor
     *                           consistency spot-check against the
     *                           modulus
     */
    private static function validatedPair(string $modulusB64, string $lambdaB64): array
    {
        // A NUL byte separates the two canonical base64 strings: base64
        // never emits a NUL, so the key cannot collide across pairs.
        $key = $modulusB64."\0".$lambdaB64;
        if (isset(self::$validatedPairCache[$key])) {
            return self::$validatedPairCache[$key];
        }
        $n = self::decodeModulus($modulusB64);
        $lambda = self::decodeLambda($lambdaB64);
        self::rejectSmallPrimeFactor($n);
        if (gmp_prob_prime($n) !== 0) {
            throw new \InvalidArgumentException(
                'rsw_modulus_n must not itself be a probable prime (a genuine 2048-bit modulus is the product of two large primes)'
            );
        }
        if (!self::trapdoorConsistent($n, $lambda)) {
            throw new \InvalidArgumentException(
                'rsw_lambda is not a matching trapdoor for rsw_modulus_n (the lambda shortcut diverges from sequential squaring)'
            );
        }
        if (\count(self::$validatedPairCache) >= self::VALIDATED_PAIR_CACHE_MAX) {
            array_shift(self::$validatedPairCache);
        }

        return self::$validatedPairCache[$key] = [$n, $lambda];
    }

    /** The decoded modulus n. */
    public function modulus(): \GMP
    {
        return $this->n;
    }

    /**
     * The expected final value of a challenge as the fixed 512-hex wire
     * form: base^(2^T mod lambda) mod n, with base the
     * challenge-derived residue. One modular exponentiation replaces the
     * client's T sequential squarings.
     */
    public function expectedProofHex(string $prefix, string $nonce, int $t): string
    {
        $base = self::deriveBase($prefix, $nonce, $this->n);
        $exponent = \gmp_powm(gmp_init(2), $t, $this->lambda);
        $expected = \gmp_powm($base, $exponent, $this->n);

        return self::proofHex($expected);
    }

    /**
     * The challenge-derived base: the SHA-256 of the signed prefix bytes
     * concatenated with the nonce bytes, interpreted as a 256-bit
     * big-endian integer and reduced modulo n. The reduction is a no-op
     * for a conforming modulus (n is at least 2^2047 and the digest at
     * most 2^256-1), and it keeps the residue canonical for any n.
     */
    public static function deriveBase(string $prefix, string $nonce, \GMP $n): \GMP
    {
        $digest = hash('sha256', $prefix.$nonce, true);

        return \gmp_mod(gmp_init(bin2hex($digest), 16), $n);
    }

    /**
     * The fixed 512-hex wire form of a residue: 256 bytes of big-endian,
     * zero-padded to the full length.
     */
    public static function proofHex(\GMP $value): string
    {
        return str_pad(gmp_strval($value, 16), self::PROOF_HEX_LENGTH, '0', \STR_PAD_LEFT);
    }

    /**
     * Validate and decode the modulus: canonical standard base64 of
     * exactly 256 bytes with the top bit set (a genuine 2048-bit
     * composite) and odd (it is the product of two odd primes).
     *
     * @throws \InvalidArgumentException on a malformed modulus
     */
    public static function decodeModulus(string $modulusB64): \GMP
    {
        $bytes = self::canonicalBase64Bytes($modulusB64, 'rsw_modulus_n');
        if (\strlen($bytes) !== self::MODULUS_BYTES) {
            throw new \InvalidArgumentException(sprintf(
                'rsw_modulus_n must be the base64 of exactly %d bytes (a 2048-bit composite), got %d',
                self::MODULUS_BYTES,
                \strlen($bytes),
            ));
        }
        if ((\ord($bytes[0]) & 0x80) === 0) {
            throw new \InvalidArgumentException(
                'rsw_modulus_n must have its top bit set (a genuine 2048-bit composite)'
            );
        }
        if ((\ord($bytes[self::MODULUS_BYTES - 1]) & 1) === 0) {
            throw new \InvalidArgumentException(
                'rsw_modulus_n must be odd (the product of two odd primes)'
            );
        }

        return gmp_init(bin2hex($bytes), 16);
    }

    /**
     * Validate and decode the secret lambda = lcm(p-1, q-1): canonical
     * standard base64 of 1..256 bytes, even. The lcm relation to the
     * modulus cannot be verified without the primes.
     *
     * @throws \InvalidArgumentException on a malformed lambda
     */
    public static function decodeLambda(string $lambdaB64): \GMP
    {
        $bytes = self::canonicalBase64Bytes($lambdaB64, 'rsw_lambda');
        if ($bytes === '' || \strlen($bytes) > self::MODULUS_BYTES) {
            throw new \InvalidArgumentException(sprintf(
                'rsw_lambda must be the base64 of 1..%d bytes, got %d',
                self::MODULUS_BYTES,
                \strlen($bytes),
            ));
        }
        if ((\ord($bytes[\strlen($bytes) - 1]) & 1) === 1) {
            throw new \InvalidArgumentException(
                'rsw_lambda must be even (lcm(p-1, q-1) of two odd primes)'
            );
        }

        return gmp_init(bin2hex($bytes), 16);
    }

    /**
     * Strict canonical base64 decode: the value must be exactly the
     * canonical padded standard-base64 encoding of its bytes, the same
     * determinism the token wire enforces.
     *
     * @throws \InvalidArgumentException on a malformed value
     */
    private static function canonicalBase64Bytes(string $value, string $name): string
    {
        if ($value === '') {
            throw new \InvalidArgumentException($name.' must be non-empty base64');
        }
        $bytes = base64_decode($value, true);
        if ($bytes === false || base64_encode($bytes) !== $value) {
            throw new \InvalidArgumentException($name.' must be canonical standard base64');
        }

        return $bytes;
    }

    /**
     * Refuse a modulus divisible by any prime at or below
     * self::SMALL_PRIME_LIMIT. The parity check already ran, so the
     * factor 2 is skipped: a genuine modulus has no small factor at
     * all.
     *
     * @throws \InvalidArgumentException on a modulus with a small
     *                           prime factor
     */
    private static function rejectSmallPrimeFactor(\GMP $n): void
    {
        foreach (self::smallPrimes() as $prime) {
            if ($prime === 2) {
                continue;
            }
            if (gmp_cmp(gmp_mod($n, gmp_init((string) $prime)), gmp_init(0)) === 0) {
                throw new \InvalidArgumentException(sprintf(
                    'rsw_modulus_n must not be divisible by a small prime (a genuine 2048-bit modulus has none; found %d)',
                    $prime
                ));
            }
        }
    }

    /**
     * Does lambda act as the trapdoor of n? The check is a
     * deterministic consistency spot-check: per base of the fixed
     * `SELFTEST_BASES` set, base^lambda must equal 1 modulo n. Each
     * equality holds exactly when that base's order divides lambda,
     * which is precisely the condition that the lambda shortcut
     * base^(2^T mod lambda) matches the T sequential squarings of the
     * base at every cost T. Every genuine pair passes, because lambda
     * is the Carmichael value of the semiprime; a mismatched or
     * fabricated lambda fails the spot-check almost surely, so it is
     * refused at configuration time. Passing every base is not a
     * proof that lambda is exactly the Carmichael value: only the
     * first-party generator's p/q construction guarantees that, and
     * the pass verdict is the strongest consistency evidence a
     * configuration validator without the primes can hold.
     */
    private static function trapdoorConsistent(\GMP $n, \GMP $lambda): bool
    {
        foreach (self::SELFTEST_BASES as $base) {
            if (gmp_cmp(gmp_powm(gmp_init((string) $base), $lambda, $n), gmp_init(1)) !== 0) {
                return false;
            }
        }

        return true;
    }

    /**
     * The primes at or below self::SMALL_PRIME_LIMIT, sieve-generated
     * once.
     *
     * @return list<int>
     */
    private static function smallPrimes(): array
    {
        static $primes = null;
        if ($primes !== null) {
            return $primes;
        }
        $limit = self::SMALL_PRIME_LIMIT;
        $sieve = array_fill(0, $limit + 1, true);
        $sieve[0] = false;
        $sieve[1] = false;
        for ($p = 2; $p * $p <= $limit; ++$p) {
            if (!$sieve[$p]) {
                continue;
            }
            for ($m = $p * $p; $m <= $limit; $m += $p) {
                $sieve[$m] = false;
            }
        }
        $primes = [];
        foreach ($sieve as $candidate => $isPrime) {
            if ($isPrime) {
                $primes[] = $candidate;
            }
        }

        return $primes;
    }
}
