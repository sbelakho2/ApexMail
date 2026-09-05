<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Config;
use KiwiCaptcha\DecodeError;
use KiwiCaptcha\ExecutionChallengeGenerator;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use KiwiCaptcha\Tests\Support\ExecutionTraceFixture;
use KiwiCaptcha\Tests\Support\RswFixture;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;

/**
 * The token-shape matrix shared with the Rust core (token.rs and
 * verify.rs). For every PoW algorithm, with execution evidence off and
 * on, the token grammar must round-trip encode -> decode. An rsw final
 * value presented to a non-rsw record is rejected at the verifier; an
 * rsw record demands counter 0. The malformed composition tails (a
 * broken trace, or a broken 512-hex proof behind a real digest:trace
 * segment) fail the decode deterministically. PHP and Rust assert the
 * same outcomes row for row.
 */
final class TokenShapeMatrixTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    private const CLIENT_IP = '198.51.100.7';

    private const DIGEST = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    /** The canonical unpadded base64url trace of "check-trace-key_123456". */
    private const TRACE = 'Y2hlY2stdHJhY2Uta2V5XzEyMzQ1Ng';

    private function requireGmp(): void
    {
        if (!\extension_loaded('gmp')) {
            self::markTestSkipped('the rsw rows need the gmp extension');
        }
    }

    private function nonce(): string
    {
        return base64_encode(random_bytes(32));
    }

    /**
     * The decode-level matrix, algorithm by algorithm with execution
     * evidence off and on. The decoder itself is algorithm-agnostic
     * (the record decides at verification), so the rows assert the same
     * wire acceptance the Rust matrix pins: every accept row must
     * round-trip encode -> decode with exactly the fields it carried.
     */
    public function testDecodeMatrixAcceptsEveryAlgorithmShape(): void
    {
        $proof = str_repeat('b', 512);
        // (label, execution on, digest|null, trace|null, proof|null).
        // The trace parameter is the standard base64 the encoder
        // translates into its base64url wire form.
        $rows = [
            ['sha256-off', false, null, null, null],
            ['sha256-on', true, self::DIGEST, base64_encode('check-trace-key_123456'), null],
            ['argon2id-off', false, null, null, null],
            ['argon2id-on', true, self::DIGEST, base64_encode('check-trace-key_123456'), null],
            ['rsw-off', false, null, null, $proof],
            // The composition row: the rsw final value rides behind the
            // execution-evidence segment on one token.
            ['rsw-on', true, self::DIGEST, base64_encode('check-trace-key_123456'), $proof],
        ];
        foreach ($rows as [$label, $execOn, $digest, $trace, $rsw]) {
            $token = SolutionToken::create($this->nonce(), 0, 1234, ['wd' => true], $digest, $trace, $rsw);
            $encoded = $token->encode();
            $decoded = SolutionToken::decode($encoded);
            self::assertSame($digest, $decoded->executionDigest, $label);
            self::assertSame($digest !== null ? self::TRACE : null, $decoded->executionTrace, $label);
            self::assertSame($rsw, $decoded->rswProof, $label);
            self::assertSame(['wd' => true], $decoded->telemetry, $label);
            self::assertSame(0, $decoded->counter, $label);
            self::assertSame($encoded, $decoded->encode(), $label.' must re-encode byte-identically');
            if ($execOn && $rsw !== null) {
                // The composition keeps dotted telemetry whole too.
                $dotted = SolutionToken::create($this->nonce(), 0, 2, ['ua' => 'Mozilla/5.0 (X11; Linux x86_64)'], $digest, $trace, $rsw);
                $again = SolutionToken::decode($dotted->encode());
                self::assertSame('Mozilla/5.0 (X11; Linux x86_64)', $again->telemetry['ua']);
                self::assertSame($rsw, $again->rswProof);
                self::assertSame(self::DIGEST, $again->executionDigest);
                self::assertSame(self::TRACE, $again->executionTrace);
            }
        }
    }

    /**
     * The malformed composition tails fail the decode deterministically
     * (PHP and Rust reject the identical wire bytes): a broken trace on
     * the digest:trace segment, and a broken 512-hex rsw proof behind
     * it (bad alphabet or wrong length).
     */
    public function testDecodeMatrixRejectsMalformedCompositionTails(): void
    {
        $proof = str_repeat('a', 512);
        foreach (['aGk=', 'aGk+', 'aGk/', 'a:b', 'ab.cd', 'a b'] as $badTrace) {
            $plain = sprintf('%s.0.1234.{}.%s:%s.%s', $this->nonce(), self::DIGEST, $badTrace, $proof);
            try {
                SolutionToken::decode(base64_encode($plain));
                self::fail("a composed token with trace '{$badTrace}' must be rejected");
            } catch (DecodeError $e) {
                self::assertSame('malformed', $e->getMessage());
            }
        }
        $badProofs = [
            strtoupper($proof), // uppercase hex
            str_repeat('a', 511), // too short
            str_repeat('a', 513), // too long
            str_repeat('g', 512), // outside the hex alphabet
        ];
        foreach ($badProofs as $badProof) {
            $plain = sprintf('%s.0.1234.{}.%s:%s.%s', $this->nonce(), self::DIGEST, self::TRACE, $badProof);
            try {
                SolutionToken::decode(base64_encode($plain));
                self::fail('a composed token with a '.\strlen($badProof).'-char non-lowercase-hex proof must be rejected');
            } catch (DecodeError $e) {
                self::assertSame('malformed', $e->getMessage());
            }
        }
        // The digest-only composition with a malformed proof fails too.
        $plain = sprintf('%s.0.1234.{}.%s.%s', $this->nonce(), self::DIGEST, strtoupper($proof));
        try {
            SolutionToken::decode(base64_encode($plain));
            self::fail('a digest-only token with an uppercase proof tail must be rejected');
        } catch (DecodeError $e) {
            self::assertSame('malformed', $e->getMessage());
        }
    }

    /**
     * The verifier rows: an rsw final value is rsw evidence only, so a
     * sha256/argon2id record presented with one is rejected outright —
     * with the winning hash counter, so the rejection can only be the
     * proof-vocabulary gate, never the difficulty check.
     */
    public function testShaAndArgonRecordsRejectAPresentedRswProof(): void
    {
        [$sha, $shaStorage] = $this->issue($this->shaConfig());
        $shaCounter = $this->solveSha256($sha->prefix, $sha->salt, $sha->targetBits);
        $outcome = (new Verifier($shaStorage, now: static fn (): int => self::ISSUED_AT))
            ->verify(SolutionToken::create($sha->nonce, $shaCounter, 5000, [], null, null, str_repeat('0', 512))->encode(), Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::InsufficientWork, $outcome->error, 'a sha256 record must reject a presented rsw proof');

        [$argon, $argonStorage] = $this->issue($this->argonConfig());
        $argonCounter = $this->solveArgon2($argon->prefix, $argon->salt, $argon->targetBits);
        $outcome = (new Verifier($argonStorage, now: static fn (): int => self::ISSUED_AT))
            ->verify(SolutionToken::create($argon->nonce, $argonCounter, 5000, [], null, null, str_repeat('0', 512))->encode(), Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::InsufficientWork, $outcome->error, 'an argon2id record must reject a presented rsw proof');
    }

    /**
     * The verifier row: an rsw record demands counter 0 — even a
     * cryptographically correct final value under a nonzero counter is
     * rejected outright, never compared.
     */
    public function testRswRecordWithANonzeroCounterIsRejected(): void
    {
        $this->requireGmp();
        [$challenge, $storage] = $this->issue($this->rswConfig());
        $proof = RswFixture::sequentialProof($challenge->prefix, $challenge->nonce, $challenge->t);
        $token = SolutionToken::create($challenge->nonce, 1, 5000, [], null, null, $proof)->encode();
        // The decode keeps the counter (the verifier gate, not the
        // grammar, rejects the shape).
        self::assertSame(1, SolutionToken::decode($token)->counter);
        $outcome = (new Verifier($storage, now: static fn (): int => self::ISSUED_AT, rswModulusN: RswFixture::MODULUS_N_B64, rswLambda: RswFixture::LAMBDA_B64))
            ->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::InsufficientWork, $outcome->error, 'an rsw token with a nonzero counter must be rejected');
    }

    /**
     * The composition the mutually-exclusive decoder used to break:
     * the issuer arms an rsw challenge with the ExecutionChallengeV1
     * dimension, the solve presents the digest:trace evidence AND the
     * sequential final value on one token, and the verifier accepts it
     * end to end.
     */
    public function testRswExecutionCompositionIssuesSolvesAndVerifies(): void
    {
        $this->requireGmp();
        $config = new Config(
            secretKey: Vectors::SECRET,
            algorithm: PoWAlgorithm::Rsw,
            ttlSecs: 120,
            minDurationMs: 0,
            executionKey: '0123456789abcdef0123456789abcdef',
            rswModulusN: RswFixture::MODULUS_N_B64,
            rswLambda: RswFixture::LAMBDA_B64,
            rswT: Config::MIN_RSW_T,
        );
        $storage = new ArrayStorage(now: static fn (): int => self::ISSUED_AT);
        $issuer = new Issuer($config, $storage, now: static fn (): int => self::ISSUED_AT);
        $challenge = $issuer->issueWithExecutionField('login', self::CLIENT_IP, true, executionAction: 'login-action');
        self::assertNotNull($challenge->executionProgram, 'the composed challenge carries the execution program');
        $record = $storage->find($challenge->nonce);
        self::assertSame(4, $record->protocolVersion, 'the composed issuance stores protocol v4');
        self::assertSame(PoWAlgorithm::Rsw, $record->algorithm);

        // The solve: the sequential final value plus the real executed
        // trace and the digest over it, exactly like the browser
        // driver's worker.
        $proof = RswFixture::sequentialProof($challenge->prefix, $challenge->nonce, $challenge->t);
        $program = ExecutionChallengeGenerator::decode($challenge->executionProgram);
        self::assertNotNull($program);
        $trace = ExecutionTraceFixture::executedTraceFor($program);
        $digest = ExecutionChallengeGenerator::digestOverTrace($challenge->executionProgram, $challenge->nonce, $trace);
        self::assertNotNull($digest);
        $token = SolutionToken::create($challenge->nonce, 0, 5000, [], $digest, base64_encode($trace), $proof)->encode();

        // The composed wire decodes into all three fields.
        $decoded = SolutionToken::decode($token);
        self::assertSame($proof, $decoded->rswProof);
        self::assertSame($digest, $decoded->executionDigest);
        self::assertSame(rtrim(strtr(base64_encode($trace), '+/', '-_'), '='), $decoded->executionTrace);

        $outcome = (new Verifier($storage, now: static fn (): int => self::ISSUED_AT, rswModulusN: RswFixture::MODULUS_N_B64, rswLambda: RswFixture::LAMBDA_B64))
            ->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertTrue($outcome->isOk(), 'the rsw + execution composition must verify: '.$outcome->code());

        // The negative control: a fresh challenge, the same composition
        // under a nonzero counter — rejected at the verifier.
        $challenge2 = $issuer->issueWithExecutionField('login', self::CLIENT_IP, true, executionAction: 'login-action');
        $proof2 = RswFixture::sequentialProof($challenge2->prefix, $challenge2->nonce, $challenge2->t);
        $program2 = ExecutionChallengeGenerator::decode($challenge2->executionProgram);
        $trace2 = ExecutionTraceFixture::executedTraceFor($program2);
        $digest2 = ExecutionChallengeGenerator::digestOverTrace($challenge2->executionProgram, $challenge2->nonce, $trace2);
        $nonZero = SolutionToken::create($challenge2->nonce, 5, 5000, [], $digest2, base64_encode($trace2), $proof2)->encode();
        $outcome = (new Verifier($storage, now: static fn (): int => self::ISSUED_AT, rswModulusN: RswFixture::MODULUS_N_B64, rswLambda: RswFixture::LAMBDA_B64))
            ->verify($nonZero, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::InsufficientWork, $outcome->error);
    }

    private function shaConfig(): Config
    {
        return new Config(
            secretKey: Vectors::SECRET,
            algorithm: PoWAlgorithm::Sha256,
            ttlSecs: 120,
            minDurationMs: 0,
            targetBits: 8,
        );
    }

    private function argonConfig(): Config
    {
        return new Config(
            secretKey: Vectors::SECRET,
            algorithm: PoWAlgorithm::Argon2id,
            mKib: 8,
            t: 3,
            p: 1,
            targetBits: 4,
            argon2TargetBits: 4,
            ttlSecs: 120,
            minDurationMs: 0,
        );
    }

    private function rswConfig(int $t = Config::MIN_RSW_T): Config
    {
        return new Config(
            secretKey: Vectors::SECRET,
            algorithm: PoWAlgorithm::Rsw,
            ttlSecs: 120,
            minDurationMs: 0,
            rswModulusN: RswFixture::MODULUS_N_B64,
            rswLambda: RswFixture::LAMBDA_B64,
            rswT: $t,
        );
    }

    /**
     * Issue a challenge into a fresh storage and return both, so the
     * verifier shares the exact storage instance that holds the record.
     *
     * @return array{0: \KiwiCaptcha\Challenge, 1: ArrayStorage}
     */
    private function issue(Config $config): array
    {
        $storage = new ArrayStorage(now: static fn (): int => self::ISSUED_AT);
        $issuer = new Issuer($config, $storage, now: static fn (): int => self::ISSUED_AT);

        return [$issuer->issue('login', self::CLIENT_IP), $storage];
    }

    private function solveSha256(string $prefix, string $salt, int $targetBits): int
    {
        $saltBytes = base64_decode($salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $prefix.$counter.$saltBytes, true);
            ++$counter;
        } while (Verifier::leadingZeroBits($hash) < $targetBits);

        return $counter - 1;
    }

    private function solveArgon2(string $prefix, string $salt, int $targetBits): int
    {
        $saltBytes = base64_decode($salt, true);
        $counter = 0;
        do {
            $hash = sodium_crypto_pwhash(32, $prefix.$counter, $saltBytes, 3, 8 * 1024, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
            ++$counter;
        } while (Verifier::leadingZeroBits($hash) < $targetBits);

        return $counter - 1;
    }
}
