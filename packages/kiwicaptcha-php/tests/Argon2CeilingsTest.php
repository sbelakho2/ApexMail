<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
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
 * Hard Argon2id verifier ceilings (audit #32): the verifier validates the
 * SIGNED parameters against the absolute process limits AFTER signature
 * authentication and BEFORE any allocation/computation — out-of-range
 * records are rejected with UnsupportedArgon2Params and the memory-hard
 * hash never runs.
 */
final class Argon2CeilingsTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    /**
     * A SIGNED protocol-v2 Argon2id record with the given parameters (all
     * other fields structurally valid). The v2 signature authenticates the
     * parameters, so the ceiling check — not the signature check — decides.
     */
    private function signedArgonRecord(int $mKib, int $t, int $p, int $targetBits = 4): ChallengeRecord
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
            PoWAlgorithm::Argon2id,
            $mKib,
            $t,
            $p,
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
            algorithm: PoWAlgorithm::Argon2id,
            mKib: $mKib,
            t: $t,
            p: $p,
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

    public function testMemoryBelowMinimumRejectedWithoutComputation(): void
    {
        // m_kib=1 < MIN_ARGON_MEMORY_KIB (8). The record is SIGNED, so the
        // signature authenticates before the ceiling check rejects it — and
        // the admission gate (consulted only later, at the computation
        // phase) is never reached: no Argon2 work happens.
        $record = $this->signedArgonRecord(mKib: 1, t: 3, p: 1);
        $storage = new ArrayStorage();
        $storage->store($record);
        $gate = $this->countingGate();

        $verifier = new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, 0), Vectors::SECRET);

        self::assertSame(VerifyError::UnsupportedArgon2Params, $outcome->error);
        self::assertSame(0, $gate->acquires, 'no computation may happen for below-ceiling memory');
        self::assertNull($storage->find($record->nonce), 'the unsupported record is burned');
    }

    public function testMemoryAboveMaximumRejectedWithoutComputation(): void
    {
        // m_kib=131072 > MAX_ARGON_MEMORY_KIB (65536): allocating 128 MiB
        // per hash is beyond the process ceiling.
        $record = $this->signedArgonRecord(mKib: 131072, t: 3, p: 1);
        $storage = new ArrayStorage();
        $storage->store($record);
        $gate = $this->countingGate();

        $verifier = new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, 0), Vectors::SECRET);

        self::assertSame(VerifyError::UnsupportedArgon2Params, $outcome->error);
        self::assertSame(0, $gate->acquires, 'no computation may happen for above-ceiling memory');
        self::assertNull($storage->find($record->nonce));
    }

    public function testTimeBelowMinimumRejectedWithoutComputation(): void
    {
        $record = $this->signedArgonRecord(mKib: 8, t: 1, p: 1);
        $storage = new ArrayStorage();
        $storage->store($record);
        $gate = $this->countingGate();

        $verifier = new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, 0), Vectors::SECRET);

        self::assertSame(VerifyError::UnsupportedArgon2Params, $outcome->error);
        self::assertSame(0, $gate->acquires);
        self::assertNull($storage->find($record->nonce));
    }

    public function testTimeAboveMaximumRejectedWithoutComputation(): void
    {
        // t=32 > MAX_ARGON_TIME (16): a single hash would run 32 passes.
        $record = $this->signedArgonRecord(mKib: 8, t: 32, p: 1);
        $storage = new ArrayStorage();
        $storage->store($record);
        $gate = $this->countingGate();

        $verifier = new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, 0), Vectors::SECRET);

        self::assertSame(VerifyError::UnsupportedArgon2Params, $outcome->error);
        self::assertSame(0, $gate->acquires);
        self::assertNull($storage->find($record->nonce));
    }

    public function testParallelismOutsideSodiumRepresentationRejected(): void
    {
        // p=4 is WITHIN the ceilings (MIN..MAX_PARALLELISM 1..4) but the
        // libsodium-backed verifier can only compute p == 1 — the proof
        // phase reports UnsupportedArgon2Params (authentic-but-unsupported),
        // never verifying wrong bytes. The gate IS consulted (the cheap
        // ceiling check passed) but the hash itself never runs.
        $record = $this->signedArgonRecord(mKib: 8, t: 3, p: 4);
        $storage = new ArrayStorage();
        $storage->store($record);
        $gate = $this->countingGate();

        $verifier = new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify(
            $this->tokenFor($record->nonce, 0),
            Vectors::SECRET,
            'login',
            '198.51.100.7',
        );

        self::assertSame(VerifyError::UnsupportedArgon2Params, $outcome->error);
        self::assertSame(1, $gate->acquires, 'the cheap ceiling check passes for p=4; only the compute step refuses');
        self::assertNull($storage->find($record->nonce));
    }

    public function testMinimalInCeilingRecordVerifiesEndToEnd(): void
    {
        $record = $this->signedArgonRecord(mKib: 8, t: 3, p: 1, targetBits: 1);
        $storage = new ArrayStorage();
        $storage->store($record);
        $counter = 0;
        do {
            $hash = sodium_crypto_pwhash(
                32,
                $record->prefix.$counter,
                base64_decode($record->salt, true),
                $record->t,
                $record->mKib * 1024,
                SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
            );
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $record->targetBits);
        --$counter;

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify(
            $this->tokenFor($record->nonce, $counter),
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertTrue($outcome->isOk(), sprintf('in-ceiling record must verify, got %s', $outcome->code()));
    }

    public function testMaxTimeBoundaryPassesTheCeilings(): void
    {
        // t=16 sits exactly AT MAX_ARGON_TIME: the ceiling check must pass
        // and the computation phase must run (gate acquired).
        $record = $this->signedArgonRecord(mKib: 8, t: 16, p: 1, targetBits: 1);
        $storage = new ArrayStorage();
        $storage->store($record);
        $gate = $this->countingGate();

        $verifier = new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, 0), Vectors::SECRET, 'login', '198.51.100.7');

        self::assertNotSame(VerifyError::UnsupportedArgon2Params, $outcome->error, 't=16 is within the ceiling');
        self::assertSame(1, $gate->acquires, 'the computation phase must run for in-ceiling parameters');
    }

    public function testMaxMemoryBoundaryPassesTheCeilings(): void
    {
        // m_kib=65536 sits exactly AT MAX_ARGON_MEMORY_KIB (64 MiB, the
        // browser-solvable ceiling): the ceiling check passes and the hash
        // runs (one 192 MiB Argon2id pass — fast).
        $record = $this->signedArgonRecord(mKib: 65536, t: 3, p: 1, targetBits: 1);
        $storage = new ArrayStorage();
        $storage->store($record);
        $gate = $this->countingGate();

        $verifier = new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, 0), Vectors::SECRET, 'login', '198.51.100.7');

        self::assertNotSame(VerifyError::UnsupportedArgon2Params, $outcome->error, 'm_kib=65536 is within the ceiling');
        self::assertSame(1, $gate->acquires);
    }

    public function testShaRecordsAreNeverSubjectToTheArgonCeilings(): void
    {
        $salt = base64_encode(random_bytes(16));
        $record = new ChallengeRecord(
            nonce: base64_encode(random_bytes(32)),
            scope: 'login',
            bindingTag: '',
            issuedAt: self::ISSUED_AT,
            expiresAt: self::ISSUED_AT + 120,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 131072,
            t: 32,
            p: 4,
            targetBits: 8,
            salt: $salt,
            prefix: 'challenge|'.$salt.'|',
            challenge: 'challenge',
            minDurationMs: 0,
            issuedAtNs: self::ISSUED_AT * 1_000_000,
            protocolVersion: 2,
        );
        $storage = new ArrayStorage();
        $storage->store($record);
        $gate = $this->countingGate();

        // Garbage signature: the SHA record with absurd argon params must
        // fail at the SIGNATURE check — the argon ceilings never apply.
        $verifier = new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($this->tokenFor($record->nonce, 0), Vectors::SECRET);

        self::assertSame(VerifyError::BadSignature, $outcome->error);
        self::assertSame(0, $gate->acquires);
    }
}
