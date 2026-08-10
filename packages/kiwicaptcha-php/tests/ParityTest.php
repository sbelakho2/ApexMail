<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\VerifyOutcome;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Cross-language parity tests: the PHP implementation must reproduce the Rust
 * crate's behavior byte-for-byte using the authoritative fixtures.
 */
final class ParityTest extends TestCase
{
    use VerifyFixtureTrait;

    private function shaConfig(): \KiwiCaptcha\Config
    {
        return new \KiwiCaptcha\Config(
            secretKey: Vectors::SECRET,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 0,
            t: 1,
            p: 1,
            targetBits: 8,
            argon2TargetBits: 8,
            ttlSecs: 120,
            minDurationMs: 0,
        );
    }

    public function testSha256VectorVerifies(): void
    {
        $storage = new ArrayStorage();
        $storage->store($this->recordFromVector(Vectors::SHA));

        $verifier = new Verifier($storage, now: static fn (): int => Vectors::NOW);
        $token = $this->tokenFor(Vectors::SHA);

        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', Vectors::CLIENT_IP);

        self::assertTrue($outcome->isOk(), sprintf('expected valid, got %s', $outcome->code()));
    }

    public function testArgon2VectorVerifiesViaSodium(): void
    {
        $storage = new ArrayStorage();
        $storage->store($this->recordFromVector(Vectors::ARGON2));

        $verifier = new Verifier($storage, now: static fn (): int => Vectors::NOW);
        $token = $this->tokenFor(Vectors::ARGON2);

        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', Vectors::CLIENT_IP);

        self::assertTrue($outcome->isOk(), sprintf('expected valid, got %s', $outcome->code()));
    }

    public function testSha256VectorRejectsWrongCounter(): void
    {
        $storage = new ArrayStorage();
        $storage->store($this->recordFromVector(Vectors::SHA));

        $verifier = new Verifier($storage, now: static fn (): int => Vectors::NOW);
        $token = $this->tokenFor(Vectors::SHA, counter: Vectors::SHA['counter'] + 1);

        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', Vectors::CLIENT_IP);

        self::assertSame(VerifyError::InsufficientWork, $outcome->error);
    }

    public function testWrongScopeRejected(): void
    {
        $storage = new ArrayStorage();
        $storage->store($this->recordFromVector(Vectors::SHA));

        $verifier = new Verifier($storage, now: static fn (): int => Vectors::NOW);

        $outcome = $verifier->verify($this->tokenFor(Vectors::SHA), Vectors::SECRET, 'signup', Vectors::CLIENT_IP);

        self::assertSame(VerifyError::WrongScope, $outcome->error);
    }

    public function testExpiredRejected(): void
    {
        $storage = new ArrayStorage();
        $storage->store($this->recordFromVector(Vectors::SHA));

        $verifier = new Verifier($storage, now: static fn (): int => Vectors::ISSUED_AT + 121);

        $outcome = $verifier->verify($this->tokenFor(Vectors::SHA), Vectors::SECRET, 'login', Vectors::CLIENT_IP);

        self::assertSame(VerifyError::Expired, $outcome->error);
    }

    public function testIpMismatchRejected(): void
    {
        $storage = new ArrayStorage();
        $storage->store($this->recordFromVector(Vectors::SHA));

        $verifier = new Verifier($storage, now: static fn (): int => Vectors::NOW);

        $outcome = $verifier->verify($this->tokenFor(Vectors::SHA), Vectors::SECRET, 'login', '198.51.100.9');

        self::assertSame(VerifyError::IpMismatch, $outcome->error);
    }

    public function testReplayRejected(): void
    {
        $storage = new ArrayStorage();
        $storage->store($this->recordFromVector(Vectors::SHA));

        $verifier = new Verifier($storage, now: static fn (): int => Vectors::NOW);
        $token = $this->tokenFor(Vectors::SHA);

        self::assertTrue($verifier->verify($token, Vectors::SECRET, 'login', Vectors::CLIENT_IP)->isOk());
        // Second use: record consumed => RecordNotFound.
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', Vectors::CLIENT_IP);
        self::assertSame(VerifyError::RecordNotFound, $outcome->error);
    }

    public function testTamperedChallengeRejected(): void
    {
        $storage = new ArrayStorage();
        $record = $this->recordFromVector(Vectors::SHA);
        // Tamper with the challenge string (invalidates the HMAC).
        $storage->store(new ChallengeRecord(
            nonce: $record->nonce,
            scope: $record->scope,
            ipHash: $record->ipHash,
            issuedAt: $record->issuedAt,
            expiresAt: $record->expiresAt,
            algorithm: $record->algorithm,
            mKib: $record->mKib,
            t: $record->t,
            p: $record->p,
            targetBits: $record->targetBits,
            salt: $record->salt,
            prefix: $record->prefix,
            challenge: $record->challenge.'00',
            minDurationMs: $record->minDurationMs,
        ));

        $verifier = new Verifier($storage, now: static fn (): int => Vectors::NOW);

        $outcome = $verifier->verify($this->tokenFor(Vectors::SHA), Vectors::SECRET, 'login', Vectors::CLIENT_IP);

        self::assertSame(VerifyError::BadSignature, $outcome->error);
    }

    public function testWrongSecretKeyRejected(): void
    {
        $storage = new ArrayStorage();
        $storage->store($this->recordFromVector(Vectors::SHA));

        $verifier = new Verifier($storage, now: static fn (): int => Vectors::NOW);

        $outcome = $verifier->verify($this->tokenFor(Vectors::SHA), str_repeat('f', 32), 'login', Vectors::CLIENT_IP);

        self::assertSame(VerifyError::BadSignature, $outcome->error);
    }

    public function testTooFastRejected(): void
    {
        $storage = new ArrayStorage();
        $storage->store($this->recordFromVector(Vectors::SHA));

        $verifier = new Verifier($storage, now: static fn (): int => Vectors::NOW);

        // duration_ms below the record floor (0 here, so use a high-difficulty
        // record instead to exercise the floor path).
        $record = $this->recordFromVector(Vectors::SHA);
        $recordWithFloor = new ChallengeRecord(
            nonce: $record->nonce,
            scope: $record->scope,
            ipHash: $record->ipHash,
            issuedAt: $record->issuedAt,
            expiresAt: $record->expiresAt,
            algorithm: $record->algorithm,
            mKib: $record->mKib,
            t: $record->t,
            p: $record->p,
            targetBits: $record->targetBits,
            salt: $record->salt,
            prefix: $record->prefix,
            challenge: $record->challenge,
            minDurationMs: 100,
        );
        $storage = new ArrayStorage();
        $storage->store($recordWithFloor);
        $verifier = new Verifier($storage, now: static fn (): int => Vectors::NOW);
        $token = $this->tokenFor(Vectors::SHA, durationMs: 50);

        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', Vectors::CLIENT_IP);

        self::assertSame(VerifyError::TooFast, $outcome->error);
    }

    public function testFullIssueAndVerifyRoundTrip(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->shaConfig(), $storage);
        $verifier = new Verifier($storage);

        $challenge = $issuer->issue('login', '198.51.100.77');
        self::assertSame('sha256', $challenge->algorithm->value);
        self::assertSame(8, $challenge->targetBits);
        self::assertNotSame('', $challenge->prefix);
        self::assertStringContainsString($challenge->challenge, $challenge->prefix);

        // Solve in pure PHP (8-bit difficulty — fast).
        $counter = 0;
        $saltBytes = base64_decode($challenge->salt, true);
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        $token = \KiwiCaptcha\SolutionToken::create($challenge->nonce, $counter, 5000, ['wd' => false])->encode();

        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.77');
        self::assertTrue($outcome->isOk(), sprintf('round-trip failed: %s', $outcome->code()));
    }

    public function testArgon2WithUnrepresentableParamsFailsClosed(): void
    {
        // t=1 cannot be expressed by libsodium; the verifier must fail closed
        // (MalformedRecord) instead of verifying wrong bytes.
        $config = new \KiwiCaptcha\Config(
            secretKey: Vectors::SECRET,
            algorithm: PoWAlgorithm::Argon2id,
            mKib: 64,
            t: 1,
            p: 1,
            targetBits: 4,
            argon2TargetBits: 4,
            ttlSecs: 120,
            minDurationMs: 0,
        );
        $storage = new ArrayStorage();
        $issuer = new Issuer($config, $storage);
        $verifier = new Verifier($storage);

        $challenge = $issuer->issue('login', '198.51.100.77');
        // Solve in PHP with the sodium-representable path — impossible for t=1,
        // so deriveHash must return null => MalformedRecord.
        $token = \KiwiCaptcha\SolutionToken::create($challenge->nonce, 1, 5000, [])->encode();
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.77');
        self::assertSame(VerifyError::MalformedRecord, $outcome->error);
    }

    public function testLeadingZeroBits(): void
    {
        self::assertSame(8, Verifier::leadingZeroBits("\x00\xff"));
        self::assertSame(12, Verifier::leadingZeroBits("\x00\x0f"));
        self::assertSame(0, Verifier::leadingZeroBits("\xff"));
        self::assertSame(0, Verifier::leadingZeroBits(''));
        // 0x10 = 0001 0000 => 3 leading zeros
        self::assertSame(3, Verifier::leadingZeroBits("\x10"));
    }

    public function testConstantTimeEquals(): void
    {
        self::assertTrue(Verifier::constantTimeEquals('abc', 'abc'));
        self::assertFalse(Verifier::constantTimeEquals('abc', 'abd'));
        self::assertFalse(Verifier::constantTimeEquals('abc', 'abcd'));
    }

    public function testHashIpMatchesRustVector(): void
    {
        self::assertSame(Vectors::IP_HASH, Issuer::hashIp(Vectors::CLIENT_IP, Vectors::SECRET));
    }
}
