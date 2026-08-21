<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\VerificationAdmissionGate;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Protocol difficulty bounds: the explicit constants 1 (floor) and 20
 * (the solver ceiling) guard the verifier's validate_record for both
 * algorithms. A stored record whose target_bits is outside 1..20 is
 * malformed, and the check runs before any hash computation; the
 * leading-zero comparison only ever sees a validated difficulty. 0, 21,
 * 256 and 65535 are rejected; 1 and 20 are accepted.
 */
final class DifficultyBoundsTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    private function countingGate(): VerificationAdmissionGate
    {
        return new class implements VerificationAdmissionGate {
            public int $acquires = 0;

            public function acquire(): ?string
            {
                $this->acquires++;

                return 'lease';
            }

            public function release(string $lease): void
            {
            }
        };
    }

    /**
     * A signed protocol-v2 record (any algorithm) carrying the given
     * target_bits with a structurally consistent challenge/prefix.
     * Because the record is properly signed, a rejection at
     * MalformedRecord can only come from validate_record, the difficulty
     * guard, not from the signature check.
     */
    private function signedRecord(PoWAlgorithm $algorithm, int $targetBits, int $mKib = 0, int $t = 1): ChallengeRecord
    {
        $nonce = base64_encode(random_bytes(32));
        $salt = base64_encode(random_bytes(16));
        $canonical = Issuer::canonicalPayload(
            $nonce,
            'login',
            '',
            self::ISSUED_AT,
            self::ISSUED_AT + 120,
            $algorithm,
            $mKib,
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
            bindingTag: '',
            issuedAt: self::ISSUED_AT,
            expiresAt: self::ISSUED_AT + 120,
            algorithm: $algorithm,
            mKib: $mKib,
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

    private function tokenFor(string $nonce, int $counter): string
    {
        return SolutionToken::create($nonce, $counter, 5000, [])->encode();
    }

    public function testProtocolDifficultyConstants(): void
    {
        self::assertSame(1, Config::MIN_DIFFICULTY);
        self::assertSame(20, Config::MAX_DIFFICULTY);
    }

    /**
     * @dataProvider outOfRangeBits
     */
    public function testShaTargetBitsOutOfRangeRejectedBeforeAnyComputation(int $bits): void
    {
        $record = $this->signedRecord(PoWAlgorithm::Sha256, $bits);
        $storage = new ArrayStorage();
        $storage->store($record);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, 0), Vectors::SECRET);

        self::assertSame(VerifyError::MalformedRecord, $outcome->error, "target_bits=$bits must fail the difficulty guard");
        self::assertNull($storage->find($record->nonce), 'the out-of-range record is burned');
    }

    /**
     * @dataProvider outOfRangeBits
     */
    public function testArgon2TargetBitsOutOfRangeRejectedBeforeAnyHashComputation(int $bits): void
    {
        // The record is signed and structurally consistent: the only
        // reason for MalformedRecord is the difficulty guard firing, and
        // the counting gate proves no Argon2 hash was ever attempted.
        $record = $this->signedRecord(PoWAlgorithm::Argon2id, $bits, mKib: 8, t: 3);
        $storage = new ArrayStorage();
        $storage->store($record);
        $gate = $this->countingGate();

        $verifier = new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, 0), Vectors::SECRET);

        self::assertSame(VerifyError::MalformedRecord, $outcome->error, "target_bits=$bits must fail the difficulty guard");
        self::assertSame(0, $gate->acquires, "no hash may be computed for target_bits=$bits — the guard runs before any computation");
        self::assertNull($storage->find($record->nonce));
    }

    /** @return iterable<string, array{int}> */
    public static function outOfRangeBits(): iterable
    {
        yield 'zero' => [0];
        yield 'above solver ceiling' => [21];
        yield 'u16 far above' => [256];
        yield 'u16 max' => [65535];
    }

    /**
     * @dataProvider boundaryBits
     */
    public function testShaTargetBitsAtTheBoundsPassValidation(int $bits): void
    {
        // A signed record at the boundary: validate_record accepts it (1
        // and 20), so the flow reaches the signature check; a tampered
        // signature yields BadSignature, never MalformedRecord.
        $record = $this->signedRecord(PoWAlgorithm::Sha256, $bits);
        $storage = new ArrayStorage();
        $storage->store(new ChallengeRecord(
            nonce: $record->nonce,
            scope: $record->scope,
            bindingTag: $record->bindingTag,
            issuedAt: $record->issuedAt,
            expiresAt: $record->expiresAt,
            algorithm: $record->algorithm,
            mKib: $record->mKib,
            t: $record->t,
            p: $record->p,
            targetBits: $record->targetBits,
            salt: $record->salt,
            // The tampered challenge carries a rebuilt consistent prefix
            // (prefix = challenge|salt|), so the only failing check is
            // the signature re-check.
            prefix: 'tampered|'.$record->salt.'|',
            challenge: 'tampered',
            minDurationMs: $record->minDurationMs,
            issuedAtNs: $record->issuedAtNs,
            protocolVersion: $record->protocolVersion,
        ));

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, 0), Vectors::SECRET);

        self::assertSame(VerifyError::BadSignature, $outcome->error, "target_bits=$bits must pass the difficulty guard (the failure is the signature check, not validation)");
    }

    /**
     * @dataProvider boundaryBits
     */
    public function testArgon2TargetBitsAtTheBoundsPassValidation(int $bits): void
    {
        // Same boundary proof for Argon2id: the difficulty guard accepts
        // 1 and 20, so a tampered signature fails as BadSignature, and
        // the admission gate is never consulted (the signature check
        // precedes the computation phase).
        $record = $this->signedRecord(PoWAlgorithm::Argon2id, $bits, mKib: 8, t: 3);
        $storage = new ArrayStorage();
        $storage->store(new ChallengeRecord(
            nonce: $record->nonce,
            scope: $record->scope,
            bindingTag: $record->bindingTag,
            issuedAt: $record->issuedAt,
            expiresAt: $record->expiresAt,
            algorithm: $record->algorithm,
            mKib: $record->mKib,
            t: $record->t,
            p: $record->p,
            targetBits: $record->targetBits,
            salt: $record->salt,
            // Rebuilt consistent prefix — only the signature check can fail.
            prefix: 'tampered|'.$record->salt.'|',
            challenge: 'tampered',
            minDurationMs: $record->minDurationMs,
            issuedAtNs: $record->issuedAtNs,
            protocolVersion: $record->protocolVersion,
        ));
        $gate = $this->countingGate();

        $verifier = new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, 0), Vectors::SECRET);

        self::assertSame(VerifyError::BadSignature, $outcome->error, "target_bits=$bits must pass the difficulty guard");
        self::assertSame(0, $gate->acquires);
    }

    /** @return iterable<string, array{int}> */
    public static function boundaryBits(): iterable
    {
        yield 'minimum' => [1];
        yield 'solver ceiling' => [20];
    }

    public function testShaTargetBitsOneVerifiesEndToEnd(): void
    {
        // The full proof at the minimum boundary: validate, signature,
        // consume, derive, leading-zero comparison against the stored
        // 1-bit difficulty.
        $record = $this->signedRecord(PoWAlgorithm::Sha256, 1);
        $storage = new ArrayStorage();
        $storage->store($record);

        $saltBytes = base64_decode($record->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $record->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < 1);
        --$counter;

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify(
            $this->tokenFor($record->nonce, $counter),
            Vectors::SECRET,
            'login',
            null,
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertTrue($outcome->isOk(), sprintf('1-bit SHA must verify end to end, got %s', $outcome->code()));
    }

    public function testArgon2TargetBitsOneVerifiesEndToEnd(): void
    {
        $record = $this->signedRecord(PoWAlgorithm::Argon2id, 1, mKib: 8, t: 3);
        $storage = new ArrayStorage();
        $storage->store($record);

        $saltBytes = base64_decode($record->salt, true);
        $counter = 0;
        do {
            $hash = sodium_crypto_pwhash(
                32,
                $record->prefix.$counter,
                $saltBytes,
                3,
                8 * 1024,
                SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
            );
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < 1);
        --$counter;

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify(
            $this->tokenFor($record->nonce, $counter),
            Vectors::SECRET,
            'login',
            null,
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertTrue($outcome->isOk(), sprintf('1-bit Argon2id must verify end to end, got %s', $outcome->code()));
    }

    public function testLeadingZeroComparisonIsSafeAtTheSolverCeiling(): void
    {
        // A properly signed 20-bit SHA record: the comparison runs (one
        // cheap hash) and reports InsufficientWork for a provably wrong
        // counter, proving the guard admitted the ceiling and the
        // comparison itself is bounded and safe.
        $record = $this->signedRecord(PoWAlgorithm::Sha256, 20);
        $storage = new ArrayStorage();
        $storage->store($record);

        $wrongCounter = 0;
        $saltBytes = base64_decode($record->salt, true);
        while (Verifier::leadingZeroBits(hash('sha256', $record->prefix.$wrongCounter.$saltBytes, true)) >= 20) {
            ++$wrongCounter;
        }

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, $wrongCounter), Vectors::SECRET, 'login', null);

        self::assertSame(VerifyError::InsufficientWork, $outcome->error, 'the leading-zero comparison must run against the validated 20-bit ceiling');
    }
}
