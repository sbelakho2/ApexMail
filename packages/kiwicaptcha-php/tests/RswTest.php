<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\DecodeError;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Rsw;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use KiwiCaptcha\Tests\Support\RswFixture;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;

/**
 * The optional rsw time-lock rung: sequential modular squaring over a
 * 2048-bit composite, verified instantly through the factorization
 * trapdoor. Everything here is opt-in — the default deployment keeps
 * the sha256/argon2id paths byte-identical, and these tests pin that
 * the rsw machinery stays inert until the operator configures the
 * modulus secrets and selects the algorithm.
 */
final class RswTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    private function requireGmp(): void
    {
        if (!\extension_loaded('gmp')) {
            self::markTestSkipped('the rsw tests need the gmp extension');
        }
    }

    private function rswConfig(int $t = Config::MIN_RSW_T, ?int $ttlSecs = null, ?int $minDurationMs = 0): Config
    {
        return new Config(
            secretKey: Vectors::SECRET,
            algorithm: PoWAlgorithm::Rsw,
            ttlSecs: $ttlSecs ?? 120,
            minDurationMs: $minDurationMs,
            rswModulusN: RswFixture::MODULUS_N_B64,
            rswLambda: RswFixture::LAMBDA_B64,
            rswT: $t,
        );
    }

    private function issue(Config $config, string $scope = 'login', string $ip = '198.51.100.7', ?int $now = null): array
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer($config, $storage, now: $now !== null ? static fn (): int => $now : null);
        $challenge = $issuer->issue($scope, $ip);
        $record = $storage->find($challenge->nonce);

        return [$challenge, $record, $storage];
    }

    private function solveToken(string $nonce, string $prefix, int $t, ?string $proof = null, int $counter = 0): string
    {
        $proof ??= RswFixture::sequentialProof($prefix, $nonce, $t);

        return SolutionToken::create($nonce, $counter, 5000, [], null, null, $proof)->encode();
    }

    public function testDefaultConfigStaysRswFree(): void
    {
        // The default deployment never configures the rsw fields: the
        // algorithm stays sha256, and no challenge response or record
        // ever carries an rsw artifact.
        $config = new Config(secretKey: Vectors::SECRET);
        self::assertNull($config->rswModulusN);
        self::assertNull($config->rswLambda);
        self::assertSame(75_000, $config->rswT);
        self::assertSame(PoWAlgorithm::Sha256, $config->algorithm);

        foreach ([PoWAlgorithm::Sha256, PoWAlgorithm::Argon2id] as $algorithm) {
            $issuing = $algorithm === PoWAlgorithm::Argon2id
                ? new Config(secretKey: Vectors::SECRET, algorithm: PoWAlgorithm::Argon2id, mKib: 64, t: 3, targetBits: 4, argon2TargetBits: 4)
                : new Config(secretKey: Vectors::SECRET, targetBits: 8);
            [$challenge, $record] = $this->issue($issuing);
            self::assertArrayNotHasKey('rsw_modulus', $challenge->toArray());
            self::assertNull($challenge->rswModulus);
            self::assertSame($algorithm, $record->algorithm);
        }
    }

    public function testRswConfigRequiresTheTrapdoorPair(): void
    {
        $this->requireGmp();

        try {
            new Config(
                secretKey: Vectors::SECRET,
                algorithm: PoWAlgorithm::Rsw,
                rswModulusN: RswFixture::MODULUS_N_B64,
            );
            self::fail('an rsw config with only the modulus must throw');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('rsw_modulus_n and rsw_lambda', $e->getMessage());
        }
    }

    public function testRswFieldsAreInertForSha256(): void
    {
        // An operator may pre-stage the modulus secrets before flipping
        // the algorithm: with sha256 selected the fields are carried but
        // never validated or issued.
        $config = new Config(
            secretKey: Vectors::SECRET,
            algorithm: PoWAlgorithm::Sha256,
            targetBits: 8,
            rswModulusN: 'not-even-base64',
            rswLambda: RswFixture::LAMBDA_B64,
            rswT: 1,
        );
        self::assertSame('not-even-base64', $config->rswModulusN);
        [$challenge] = $this->issue($config);
        self::assertSame(PoWAlgorithm::Sha256, $challenge->algorithm);
        self::assertNull($challenge->rswModulus);
    }

    public function testModulusShapeValidation(): void
    {
        $this->requireGmp();
        $valid = base64_decode(RswFixture::MODULUS_N_B64, true);

        $cases = [
            'even modulus' => substr($valid, 0, -1)."\x00",
            'short modulus' => substr($valid, 1),
            'long modulus' => $valid."\x01",
            'no top bit' => "\x01".substr($valid, 1),
        ];
        foreach ($cases as $label => $bytes) {
            try {
                new Config(
                    secretKey: Vectors::SECRET,
                    algorithm: PoWAlgorithm::Rsw,
                    rswModulusN: base64_encode($bytes),
                    rswLambda: RswFixture::LAMBDA_B64,
                );
                self::fail("a malformed modulus must throw: {$label}");
            } catch (\InvalidArgumentException $e) {
                self::assertStringContainsString('rsw_modulus_n', $e->getMessage());
            }
        }
        try {
            new Config(
                secretKey: Vectors::SECRET,
                algorithm: PoWAlgorithm::Rsw,
                rswModulusN: '!!!not-base64!!!',
                rswLambda: RswFixture::LAMBDA_B64,
            );
            self::fail('non-base64 modulus must throw');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('base64', $e->getMessage());
        }
    }

    public function testLambdaShapeValidation(): void
    {
        $this->requireGmp();
        $valid = base64_decode(RswFixture::LAMBDA_B64, true);

        foreach (['odd lambda' => substr($valid, 0, -1)."\x01", 'empty lambda' => ''] as $label => $value) {
            try {
                new Config(
                    secretKey: Vectors::SECRET,
                    algorithm: PoWAlgorithm::Rsw,
                    rswModulusN: RswFixture::MODULUS_N_B64,
                    rswLambda: $value === '' ? '' : base64_encode($value),
                );
                self::fail("a malformed lambda must throw: {$label}");
            } catch (\InvalidArgumentException $e) {
                self::assertStringContainsString('rsw_lambda', $e->getMessage());
            }
        }
    }

    public function testModulusWithASmallPrimeFactorIsRejected(): void
    {
        $this->requireGmp();
        $weak = gmp_mul(gmp_add(gmp_pow(gmp_init(2), 2046), 1), 3);
        self::assertSame(2048, \strlen(gmp_strval($weak, 2)), 'the test modulus is exactly 2048 bits');
        self::assertSame('1', gmp_strval(gmp_mod($weak, gmp_init(2))), 'the test modulus is odd');
        $bytes = hex2bin(str_pad(gmp_strval($weak, 16), 512, '0', \STR_PAD_LEFT));
        try {
            new Config(
                secretKey: Vectors::SECRET,
                algorithm: PoWAlgorithm::Rsw,
                rswModulusN: base64_encode($bytes),
                rswLambda: RswFixture::LAMBDA_B64,
            );
            self::fail('a modulus with a small prime factor must throw');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('found 3', $e->getMessage());
        }
    }

    public function testModulusOfTheWrongBitLengthIsRejected(): void
    {
        $this->requireGmp();
        $full = gmp_init(bin2hex(base64_decode(RswFixture::MODULUS_N_B64, true)), 16);
        $short = gmp_or(gmp_mod($full, gmp_pow(gmp_init(2), 1024)), gmp_pow(gmp_init(2), 1023));
        self::assertSame(1024, \strlen(gmp_strval($short, 2)));
        $bytes = hex2bin(str_pad(gmp_strval($short, 16), 256, '0', \STR_PAD_LEFT));
        try {
            new Config(
                secretKey: Vectors::SECRET,
                algorithm: PoWAlgorithm::Rsw,
                rswModulusN: base64_encode($bytes),
                rswLambda: RswFixture::LAMBDA_B64,
            );
            self::fail('a 1024-bit modulus must throw');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('exactly 256 bytes', $e->getMessage());
        }
    }

    public function testProbablePrimeModulusIsRejected(): void
    {
        $this->requireGmp();
        try {
            new Config(
                secretKey: Vectors::SECRET,
                algorithm: PoWAlgorithm::Rsw,
                rswModulusN: RswFixture::PROBABLE_PRIME_N_B64,
                rswLambda: RswFixture::LAMBDA_B64,
            );
            self::fail('a probable-prime modulus must throw');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('probable prime', $e->getMessage());
        }
    }

    public function testMismatchedLambdaIsRejected(): void
    {
        $this->requireGmp();
        $lambda = gmp_init(bin2hex(base64_decode(RswFixture::LAMBDA_B64, true)), 16);
        $shifted = gmp_sub($lambda, 2);
        $bytes = hex2bin(str_pad(gmp_strval($shifted, 16), 512, '0', \STR_PAD_LEFT));
        try {
            new Config(
                secretKey: Vectors::SECRET,
                algorithm: PoWAlgorithm::Rsw,
                rswModulusN: RswFixture::MODULUS_N_B64,
                rswLambda: base64_encode($bytes),
            );
            self::fail('a lambda that is not the trapdoor of the modulus must throw');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('rsw_lambda', $e->getMessage());
        }
    }

    public function testGoodFixturePairStillPassesTheStrengthenedValidation(): void
    {
        $this->requireGmp();
        $modulus = gmp_init(bin2hex(base64_decode(RswFixture::MODULUS_N_B64, true)), 16);
        self::assertSame(0, gmp_prob_prime($modulus), 'the fixture semiprime is composite');
        self::assertSame('1', gmp_strval(gmp_mod($modulus, gmp_init(2))), 'the fixture modulus is odd');
        // The 1024-bit fixture prime squared is a 2048-bit composite
        // with no small factor: gmp still reads it as composite, the
        // same verdict the Rust probable-prime test returns.
        $prime = gmp_init(bin2hex(base64_decode(RswFixture::PRIME_1024_B64, true)), 16);
        self::assertSame(0, gmp_prob_prime(gmp_mul($prime, $prime)), 'a prime square is composite');

        $config = $this->rswConfig();
        self::assertSame(RswFixture::MODULUS_N_B64, $config->rswModulusN);
        $rsw = new Rsw(RswFixture::MODULUS_N_B64, RswFixture::LAMBDA_B64);
        self::assertNotNull($rsw->modulus());
    }

    public function testWarmPairStillRejectsEveryWeakShapeWithTheIdenticalMessage(): void
    {
        // The validated-pair memo must never change a rejection: after
        // the valid fixture pair is constructed (and memoized) in this
        // process, every weak input of the rejection rows must fail
        // with the exact byte-identical message a cold construction
        // produced. Invalid pairs are never memoized, so each row runs
        // the full validation pipeline.
        $this->requireGmp();
        $rsw = new Rsw(RswFixture::MODULUS_N_B64, RswFixture::LAMBDA_B64);
        self::assertNotNull($rsw->modulus(), 'the warm-up pair must be valid');

        $modulusBytes = base64_decode(RswFixture::MODULUS_N_B64, true);
        $rows = [
            'even modulus' => [
                base64_encode(substr($modulusBytes, 0, -1)."\x00"),
                RswFixture::LAMBDA_B64,
                'rsw_modulus_n must be odd (the product of two odd primes)',
            ],
            'short modulus' => [
                base64_encode(substr($modulusBytes, 1)),
                RswFixture::LAMBDA_B64,
                'rsw_modulus_n must be the base64 of exactly 256 bytes (a 2048-bit composite), got 255',
            ],
            'no top bit' => [
                base64_encode("\x01".substr($modulusBytes, 1)),
                RswFixture::LAMBDA_B64,
                'rsw_modulus_n must have its top bit set (a genuine 2048-bit composite)',
            ],
            'odd lambda' => [
                RswFixture::MODULUS_N_B64,
                base64_encode(substr(base64_decode(RswFixture::LAMBDA_B64, true), 0, -1)."\x01"),
                'rsw_lambda must be even (lcm(p-1, q-1) of two odd primes)',
            ],
        ];
        foreach ($rows as $label => [$n, $lambda, $message]) {
            try {
                new Rsw($n, $lambda);
                self::fail("the warm pair must still reject {$label}");
            } catch (\InvalidArgumentException $e) {
                self::assertSame($message, $e->getMessage(), "{$label} must keep its exact message");
            }
        }

        // The three consistency rejections: the small-factor modulus,
        // the probable-prime modulus and the mismatched lambda.
        $weak = gmp_mul(gmp_add(gmp_pow(gmp_init(2), 2046), 1), 3);
        $bytes = hex2bin(str_pad(gmp_strval($weak, 16), 512, '0', \STR_PAD_LEFT));
        try {
            new Rsw(base64_encode($bytes), RswFixture::LAMBDA_B64);
            self::fail('the warm pair must still reject a small-factor modulus');
        } catch (\InvalidArgumentException $e) {
            self::assertSame(
                'rsw_modulus_n must not be divisible by a small prime (a genuine 2048-bit modulus has none; found 3)',
                $e->getMessage()
            );
        }
        try {
            new Rsw(RswFixture::PROBABLE_PRIME_N_B64, RswFixture::LAMBDA_B64);
            self::fail('the warm pair must still reject a probable-prime modulus');
        } catch (\InvalidArgumentException $e) {
            self::assertSame(
                'rsw_modulus_n must not itself be a probable prime (a genuine 2048-bit modulus is the product of two large primes)',
                $e->getMessage()
            );
        }
        $lambda = gmp_init(bin2hex(base64_decode(RswFixture::LAMBDA_B64, true)), 16);
        $shifted = hex2bin(str_pad(gmp_strval(gmp_sub($lambda, 2), 16), 512, '0', \STR_PAD_LEFT));
        try {
            new Rsw(RswFixture::MODULUS_N_B64, base64_encode($shifted));
            self::fail('the warm pair must still reject a mismatched lambda');
        } catch (\InvalidArgumentException $e) {
            self::assertSame(
                'rsw_lambda is not a matching trapdoor for rsw_modulus_n (the lambda shortcut diverges from sequential squaring)',
                $e->getMessage()
            );
        }
        // The Config entry point keeps its own prefix over the same
        // byte-identical inner message (the standalone deploy validates
        // through Config on every request).
        try {
            new Config(
                secretKey: Vectors::SECRET,
                algorithm: PoWAlgorithm::Rsw,
                rswModulusN: RswFixture::MODULUS_N_B64,
                rswLambda: base64_encode($shifted),
            );
            self::fail('the warm pair must still reject a mismatched lambda through Config');
        } catch (\InvalidArgumentException $e) {
            self::assertSame(
                'invalid rsw trapdoor configuration: rsw_lambda is not a matching trapdoor for rsw_modulus_n (the lambda shortcut diverges from sequential squaring)',
                $e->getMessage()
            );
        }
    }

    public function testRepeatedConstructionOfTheSamePairIsIdentical(): void
    {
        // The validated-pair memo reuses the decoded representation on
        // the second construction of the exact same configured pair:
        // the decoded modulus is the same integer and the trapdoor
        // expectations are byte-identical to the first (cold)
        // construction's, across the cost ladder including the 75_000
        // default.
        $this->requireGmp();
        $first = new Rsw(RswFixture::MODULUS_N_B64, RswFixture::LAMBDA_B64);
        $second = new Rsw(RswFixture::MODULUS_N_B64, RswFixture::LAMBDA_B64);
        self::assertSame(
            0,
            gmp_cmp($first->modulus(), $second->modulus()),
            'the memoized construction must decode the same modulus'
        );
        foreach ([1, 7, 25_000, 75_000] as $t) {
            $prefix = 'v2|fixture-prefix-'.$t.'|';
            $nonce = base64_encode(random_bytes(32));
            self::assertSame(
                $first->expectedProofHex($prefix, $nonce, $t),
                $second->expectedProofHex($prefix, $nonce, $t),
                "both constructions must compute the identical expectation for t={$t}"
            );
        }
    }

    public function testRswTBounds(): void
    {
        $this->requireGmp();
        foreach ([Config::MIN_RSW_T - 1, Config::MAX_RSW_T + 1] as $t) {
            try {
                new Config(
                    secretKey: Vectors::SECRET,
                    algorithm: PoWAlgorithm::Rsw,
                    rswModulusN: RswFixture::MODULUS_N_B64,
                    rswLambda: RswFixture::LAMBDA_B64,
                    rswT: $t,
                );
                self::fail("rsw_t {$t} must be rejected");
            } catch (\InvalidArgumentException $e) {
                self::assertStringContainsString('rsw_t', $e->getMessage());
            }
        }
        $config = $this->rswConfig(Config::MIN_RSW_T);
        self::assertSame(Config::MIN_RSW_T, $config->rswT);
    }

    public function testIssuanceCarriesTheCanonicalRswMapping(): void
    {
        $this->requireGmp();
        $config = $this->rswConfig(30_000);
        [$challenge, $record] = $this->issue($config, now: self::ISSUED_AT);

        self::assertSame(PoWAlgorithm::Rsw, $challenge->algorithm);
        // The canonical v2 slots carry the time-lock knobs: T rides the
        // time-cost slot, m_kib is 0, p is 1, and target_bits is pinned
        // to the protocol floor (rsw has no leading-zero target).
        self::assertSame(30_000, $challenge->t);
        self::assertSame(0, $challenge->mKib);
        self::assertSame(1, $challenge->p);
        self::assertSame(Config::RSW_TARGET_BITS_PIN, $challenge->targetBits);
        self::assertSame(RswFixture::MODULUS_N_B64, $challenge->rswModulus);
        self::assertArrayHasKey('rsw_modulus', $challenge->toArray());
        self::assertSame(2, $record->protocolVersion, 'rsw issuance stays protocol v2');
        self::assertNull($record->decoyField);
        self::assertNull($record->executionProgram);
        self::assertSame($challenge->prefix, $record->prefix);

        // The canonical payload really says rsw: the signed string is
        // the v2 grammar with the algorithm segment.
        $payload = base64_decode(explode('.', $challenge->challenge)[0], true);
        self::assertStringStartsWith('v2|', $payload);
        self::assertStringContainsString('|rsw|0|30000|1|1|', $payload);
        self::assertStringEndsWith('|1', $payload, 'the pin renders as the final canonical field only after kid');

        // The stored record JSON carries no rsw-specific key: every
        // authenticated parameter rides the existing v2 slots, and the
        // record round-trips the strict parser unchanged.
        $json = $record->toArray();
        foreach (array_keys($json) as $key) {
            self::assertContains($key, ChallengeRecord::WIRE_KEYS);
        }
        $reparsed = ChallengeRecord::fromArray($json);
        self::assertSame(PoWAlgorithm::Rsw, $reparsed->algorithm);
        self::assertSame(30_000, $reparsed->t);
    }

    public function testMinDurationFloorDerivesFromT(): void
    {
        $this->requireGmp();
        // The derived floor: the 50 ms absolute minimum or the
        // T-over-5e6-seconds estimate, whichever is larger.
        foreach ([Config::MIN_RSW_T => 50, 300_000 => 60, Config::MAX_RSW_T => 60] as $t => $expectedFloor) {
            $config = new Config(
                secretKey: Vectors::SECRET,
                algorithm: PoWAlgorithm::Rsw,
                rswModulusN: RswFixture::MODULUS_N_B64,
                rswLambda: RswFixture::LAMBDA_B64,
                rswT: $t,
            );
            [$challenge] = $this->issue($config);
            self::assertSame($expectedFloor, $challenge->minDurationMs);
        }
        // An operator override still wins over the derived floor.
        [$challenge] = $this->issue($this->rswConfig(Config::MAX_RSW_T, minDurationMs: 1234));
        self::assertSame(1234, $challenge->minDurationMs);
    }

    public function testSequentialSolveRoundTripVerifies(): void
    {
        $this->requireGmp();
        $config = $this->rswConfig(Config::MIN_RSW_T);
        [$challenge, $record, $storage] = $this->issue($config);

        $token = $this->solveToken($challenge->nonce, $challenge->prefix, $challenge->t);
        $outcome = (new Verifier($storage, rswModulusN: RswFixture::MODULUS_N_B64, rswLambda: RswFixture::LAMBDA_B64))
            ->verify($token, Vectors::SECRET, 'login', '198.51.100.7');

        self::assertTrue($outcome->isOk(), 'the client-style sequential solve must verify: '.$outcome->code());
        self::assertSame($record->nonce, $outcome->nonce());
    }

    public function testTrapdoorExpectationEqualsSequentialSquaring(): void
    {
        $this->requireGmp();
        $rsw = new Rsw(RswFixture::MODULUS_N_B64, RswFixture::LAMBDA_B64);
        foreach ([1, 2, 7, 10_000, 25_000] as $t) {
            [$challenge] = $this->issue($this->rswConfig(10_000));
            $sequential = RswFixture::sequentialProof($challenge->prefix, $challenge->nonce, $t);
            $expected = $rsw->expectedProofHex($challenge->prefix, $challenge->nonce, $t);
            self::assertSame($expected, $sequential, "the trapdoor shortcut must equal {$t} sequential squarings");
        }
    }

    public function testWrongFinalValueIsRejected(): void
    {
        $this->requireGmp();
        $config = $this->rswConfig();
        [$challenge, , $storage] = $this->issue($config);

        $wrong = RswFixture::sequentialProof($challenge->prefix, $challenge->nonce, $challenge->t);
        $wrong[0] = $wrong[0] === '0' ? '1' : '0';
        $outcome = (new Verifier($storage, rswModulusN: RswFixture::MODULUS_N_B64, rswLambda: RswFixture::LAMBDA_B64))
            ->verify($this->solveToken($challenge->nonce, $challenge->prefix, $challenge->t, $wrong), Vectors::SECRET, 'login', '198.51.100.7');

        self::assertSame(VerifyError::InsufficientWork, $outcome->error);
    }

    public function testMissingProofIsRejected(): void
    {
        $this->requireGmp();
        $config = $this->rswConfig();
        [$challenge, , $storage] = $this->issue($config);
        $token = SolutionToken::create($challenge->nonce, 0, 5000, [])->encode();

        $outcome = (new Verifier($storage, rswModulusN: RswFixture::MODULUS_N_B64, rswLambda: RswFixture::LAMBDA_B64))
            ->verify($token, Vectors::SECRET, 'login', '198.51.100.7');

        self::assertSame(VerifyError::InsufficientWork, $outcome->error);
    }

    public function testProofOfAnotherChallengeIsRejected(): void
    {
        $this->requireGmp();
        $config = $this->rswConfig();
        [$challengeA, , $storage] = $this->issue($config);
        [$challengeB] = $this->issue($config);

        $proofOfB = RswFixture::sequentialProof($challengeB->prefix, $challengeB->nonce, $challengeB->t);
        $outcome = (new Verifier($storage, rswModulusN: RswFixture::MODULUS_N_B64, rswLambda: RswFixture::LAMBDA_B64))
            ->verify($this->solveToken($challengeA->nonce, $challengeA->prefix, $challengeA->t, $proofOfB), Vectors::SECRET, 'login', '198.51.100.7');

        self::assertSame(VerifyError::InsufficientWork, $outcome->error);
    }

    public function testVerifierWithoutTheTrapdoorRefusesRswRecords(): void
    {
        $this->requireGmp();
        $config = $this->rswConfig();
        [$challenge, , $storage] = $this->issue($config);
        $token = $this->solveToken($challenge->nonce, $challenge->prefix, $challenge->t);

        $outcome = (new Verifier($storage))->verify($token, Vectors::SECRET, 'login', '198.51.100.7');

        self::assertSame(VerifyError::UnsupportedRswParams, $outcome->error);
    }

    public function testVerifierRefusesAPartialTrapdoorPairAtConstruction(): void
    {
        try {
            new Verifier(new ArrayStorage(), rswModulusN: RswFixture::MODULUS_N_B64);
            self::fail('a single rsw key at construction must throw');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('together', $e->getMessage());
        }
    }

    public function testSignedRswRecordOutsideTheTCeilingIsUnsupported(): void
    {
        $this->requireGmp();
        foreach ([Config::MIN_RSW_T - 1, Config::MAX_RSW_T + 1, 0, 1] as $t) {
            $record = $this->signedRswRecord($t);
            $storage = new ArrayStorage();
            $storage->store($record);
            $outcome = (new Verifier($storage, rswModulusN: RswFixture::MODULUS_N_B64, rswLambda: RswFixture::LAMBDA_B64, now: static fn (): int => self::ISSUED_AT))
                ->verify($this->solveToken($record->nonce, $record->prefix, Config::MIN_RSW_T), Vectors::SECRET, 'login', '198.51.100.7');

            self::assertSame(VerifyError::UnsupportedRswParams, $outcome->error, "signed t={$t} must be refused");
        }
    }

    public function testSignedRswRecordTargetBitsIsNeverConsulted(): void
    {
        // rsw has no leading-zero target: the canonical pin is 1, but a
        // conforming foreign record carrying any in-range target_bits
        // still verifies on the final value alone. The uniform
        // structural gate (1..20) is what validates the field.
        $this->requireGmp();
        $record = $this->signedRswRecord(Config::MIN_RSW_T, targetBits: 19);
        $storage = new ArrayStorage();
        $storage->store($record);
        $token = $this->solveToken($record->nonce, $record->prefix, $record->t);

        $outcome = (new Verifier($storage, rswModulusN: RswFixture::MODULUS_N_B64, rswLambda: RswFixture::LAMBDA_B64, now: static fn (): int => self::ISSUED_AT))
            ->verify($token, Vectors::SECRET, 'login', '198.51.100.7');

        self::assertTrue($outcome->isOk());
    }

    public function testTokenProofSegmentRoundTrips(): void
    {
        $proof = RswFixture::sequentialProof('prefix', base64_encode(random_bytes(32)), 10_000);
        $nonce = base64_encode(random_bytes(32));
        $encoded = SolutionToken::create($nonce, 0, 1234, ['wd' => true], null, null, $proof)->encode();
        $decoded = SolutionToken::decode($encoded);

        self::assertSame(0, $decoded->counter, 'an rsw token has no search counter');
        self::assertSame(1234, $decoded->durationMs);
        self::assertSame($proof, $decoded->rswProof);
        self::assertNull($decoded->executionDigest);
        self::assertSame(['wd' => true], $decoded->telemetry);

        // The four-segment shape stays untouched: no proof segment.
        $plain = SolutionToken::create($nonce, 3, 1234, [])->encode();
        self::assertNull(SolutionToken::decode($plain)->rswProof);
    }

    public function testTokenProofSegmentShapeIsExact(): void
    {
        $nonce = base64_encode(random_bytes(32));
        $proof = RswFixture::sequentialProof('prefix', $nonce, 10_000);
        self::assertSame(512, \strlen($proof));

        // An uppercase 512-hex tail is not the wire shape: the decode
        // falls through to the telemetry JSON parse and fails closed.
        $upper = strtoupper($proof);
        $wrapped = base64_encode("{$nonce}.0.1234.{}.{$upper}");
        try {
            SolutionToken::decode($wrapped);
            self::fail('an uppercase proof tail must be rejected');
        } catch (DecodeError $e) {
            self::assertSame('malformed', $e->getMessage());
        }
    }

    public function testProofOfTheWrongLengthIsNotAProof(): void
    {
        $nonce = base64_encode(random_bytes(32));
        // 511 hex chars: not digest-shaped (64) and not proof-shaped
        // (512), so the tail is telemetry and the JSON parse fails.
        $tail = str_repeat('0', 511);
        $wrapped = base64_encode("{$nonce}.0.1234.{{}}.{$tail}");
        try {
            SolutionToken::decode($wrapped);
            self::fail('a 511-hex tail must fail the decode');
        } catch (DecodeError $e) {
            self::assertSame('malformed', $e->getMessage());
        }
    }

    /**
     * A signed protocol-v2 rsw record with the given sequential cost T
     * (all other fields structurally valid, issued canonical pins
     * except where overridden).
     */
    private function signedRswRecord(int $t, int $targetBits = Config::RSW_TARGET_BITS_PIN): ChallengeRecord
    {
        $nonce = base64_encode(random_bytes(32));
        $salt = base64_encode(random_bytes(16));
        $bindingTag = Issuer::bindingTag($nonce, '198.51.100.7', Vectors::SECRET);
        $canonical = Issuer::canonicalPayload(
            $nonce,
            'login',
            $bindingTag,
            self::ISSUED_AT,
            self::ISSUED_AT + 120,
            PoWAlgorithm::Rsw,
            0,
            $t,
            1,
            $targetBits,
            $salt,
            0,
        );
        $challenge = base64_encode($canonical).'.'.Issuer::signPayloadV2($canonical, Vectors::SECRET);

        return new ChallengeRecord(
            nonce: $nonce,
            scope: 'login',
            bindingTag: $bindingTag,
            issuedAt: self::ISSUED_AT,
            expiresAt: self::ISSUED_AT + 120,
            algorithm: PoWAlgorithm::Rsw,
            mKib: 0,
            t: $t,
            p: 1,
            targetBits: $targetBits,
            salt: $salt,
            prefix: $challenge.'|'.$salt.'|',
            challenge: $challenge,
            minDurationMs: 0,
            issuedAtNs: self::ISSUED_AT * 1_000_000,
            protocolVersion: 2,
        );
    }

    public function testDebugInfoRedactsLambdaAndKeepsThePublicModulus(): void
    {
        $this->requireGmp();
        $rsw = new Rsw(RswFixture::MODULUS_N_B64, RswFixture::LAMBDA_B64);

        // __debugInfo must show the full four-field shape (modulusB64, n
        // and their names), with the secret lambda material replaced.
        self::assertSame(
            ['modulusB64', 'lambdaB64', 'n', 'lambda'],
            array_keys($rsw->__debugInfo()),
        );

        foreach ([
            static function () use ($rsw): string {
                ob_start();
                var_dump($rsw);
                return (string) ob_get_clean();
            },
            static fn (): string => print_r($rsw, true),
        ] as $capture) {
            $dump = $capture();
            self::assertStringNotContainsString(RswFixture::LAMBDA_B64, $dump);
            // The modulus (raw base64 and decoded) is public and prints.
            self::assertStringContainsString(RswFixture::MODULUS_N_B64, $dump);
            self::assertSame(2, substr_count($dump, '<redacted>'));
        }
    }
}
