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
}
