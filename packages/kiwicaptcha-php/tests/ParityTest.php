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
        // Tamper with the signature embedded in the challenge string (flip
        // the first hex nibble, invalidating the HMAC). The prefix is
        // rebuilt consistently (prefix = challenge|salt|), so the record
        // still passes structural validation and the tampering is caught by
        // the constant-time signature re-check.
        $challenge = $record->challenge;
        $pos = strrpos($challenge, '.');
        self::assertNotFalse($pos);
        $signature = substr($challenge, $pos + 1);
        $flippedFirst = dechex(hexdec($signature[0]) ^ 0xf);
        $tampered = substr($challenge, 0, $pos + 1).$flippedFirst.substr($signature, 1);
        $storage->store(new ChallengeRecord(
            nonce: $record->nonce,
            scope: $record->scope,
            bindingTag: $record->ipHash(),
            issuedAt: $record->issuedAt,
            expiresAt: $record->expiresAt,
            algorithm: $record->algorithm,
            mKib: $record->mKib,
            t: $record->t,
            p: $record->p,
            targetBits: $record->targetBits,
            salt: $record->salt,
            prefix: $tampered.'|'.$record->salt.'|',
            challenge: $tampered,
            minDurationMs: $record->minDurationMs,
            protocolVersion: 1,
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
        // Server-measured timing: the record floor is 100ms and the receipt
        // (nowNs) arrives only 50ms after the record's issuedAtNs, so the
        // solve is rejected as TooFast — the client-reported duration_ms=50
        // is not consulted anymore.
        $record = $this->recordFromVector(Vectors::SHA);
        $issuedAtNs = Vectors::NOW * 1_000_000;
        $recordWithFloor = new ChallengeRecord(
            nonce: $record->nonce,
            scope: $record->scope,
            bindingTag: $record->ipHash(),
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
            issuedAtNs: $issuedAtNs,
            protocolVersion: 1,
        );
        $storage = new ArrayStorage();
        $storage->store($recordWithFloor);
        $verifier = new Verifier($storage, now: static fn (): int => Vectors::NOW);
        $token = $this->tokenFor(Vectors::SHA, durationMs: 50);

        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', Vectors::CLIENT_IP, nowNs: $issuedAtNs + 50_000);

        self::assertSame(VerifyError::TooFast, $outcome->error);
    }

    public function testFullIssueAndVerifyRoundTrip(): void
    {
        // Full loop: issue -> canonical payload -> signature -> stored v2
        // record -> solveable proof -> end-to-end verification through the
        // protocol-v2 Verifier.
        $storage = new ArrayStorage();
        $config = $this->shaConfig();
        $issuer = new Issuer($config, $storage, now: static fn (): int => Vectors::NOW);

        $challenge = $issuer->issue('login', '198.51.100.77');
        self::assertSame('sha256', $challenge->algorithm->value);
        self::assertSame(8, $challenge->targetBits);
        self::assertNotSame('', $challenge->prefix);
        self::assertStringContainsString($challenge->challenge, $challenge->prefix);

        // The stored record is protocol v2 and carries the nonce-bound
        // binding tag — NOT the legacy stable IP hash.
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        self::assertSame(2, $record->protocolVersion);
        $bindingTag = Issuer::bindingTag($challenge->nonce, '198.51.100.77', Vectors::SECRET);
        self::assertSame($bindingTag, $record->bindingTag);
        self::assertSame($bindingTag, $record->ipHash(), 'compat accessor must expose the binding tag');
        self::assertNotSame(Vectors::IP_HASH, $bindingTag, 'v2 binding is nonce-bound, never a stable IP-derived identifier');

        // The challenge is base64(canonical v2 payload) . "." . hex(hmac).
        [$payloadB64, $signature] = explode('.', $challenge->challenge, 2);
        $canonical = Issuer::canonicalPayload(
            $challenge->nonce,
            'login',
            $bindingTag,
            Vectors::NOW,
            Vectors::NOW + $config->ttlSecs,
            $challenge->algorithm,
            $config->mKib,
            $config->t,
            $config->p,
            $challenge->targetBits,
            $challenge->salt,
            $challenge->minDurationMs,
        );
        self::assertSame($canonical, base64_decode($payloadB64, true));
        self::assertSame(Issuer::signPayload($canonical, Vectors::SECRET), $signature);

        // Solve in pure PHP (8-bit difficulty — fast) and check the proof
        // against the stored record's prefix.
        $counter = 0;
        $saltBytes = base64_decode($challenge->salt, true);
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        $token = \KiwiCaptcha\SolutionToken::create($challenge->nonce, $counter, 5000, ['wd' => false])->encode();
        self::assertSame($counter, \KiwiCaptcha\SolutionToken::decode($token)->counter);
        $powHash = hash('sha256', $record->prefix.$counter.$saltBytes, true);
        self::assertGreaterThanOrEqual($challenge->targetBits, Verifier::leadingZeroBits($powHash));

        // End-to-end: the issued v2 record + solved token verify through the
        // v2 verifier (receipt 1s after the record's server-side issuance).
        $verifier = new Verifier($storage, now: static fn (): int => Vectors::NOW);
        $outcome = $verifier->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs + 1_000_000,
        );
        self::assertTrue($outcome->isOk(), sprintf('issue->solve->verify round trip must pass, got %s', $outcome->code()));
    }

    public function testArgon2WithUnrepresentableParamsFailsClosed(): void
    {
        // t=1 cannot be expressed by libsodium; the verifier must fail closed
        // (MalformedRecord) instead of verifying wrong bytes.
        // NOTE: Config now rejects Argon2id t<3 at construction, so this test
        // builds the record directly to exercise the verifier's fail-closed
        // path against a legacy/foreign record that slipped through.
        $config = new \KiwiCaptcha\Config(
            secretKey: Vectors::SECRET,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 0,
            t: 1,
            p: 1,
            targetBits: 4,
            argon2TargetBits: 4,
            ttlSecs: 120,
            minDurationMs: 0,
        );
        $storage = new ArrayStorage();
        $issuer = new Issuer($config, $storage, now: static fn (): int => Vectors::NOW);
        $challenge = $issuer->issue('login', '198.51.100.77');

        // Swap in Argon2id t=1 parameters outside the verifier's protocol
        // profile (validateRecord requires t 3..=6): the verifier must fail
        // closed (MalformedRecord) instead of verifying wrong bytes.
        $ipHash = Issuer::hashIp('198.51.100.77', Vectors::SECRET);
        $v1Payload = sprintf('%s|%s|%s|%d', $challenge->nonce, 'login', $ipHash, Vectors::NOW);
        $v1Challenge = base64_encode($v1Payload).'.'.Issuer::signPayload($v1Payload, Vectors::SECRET);

        $record = new ChallengeRecord(
            nonce: $challenge->nonce,
            scope: 'login',
            bindingTag: $ipHash,
            issuedAt: Vectors::NOW,
            expiresAt: Vectors::NOW + 120,
            algorithm: PoWAlgorithm::Argon2id,
            mKib: 64,
            t: 1,
            p: 1,
            targetBits: 4,
            salt: $challenge->salt,
            prefix: $challenge->prefix,
            challenge: $v1Challenge,
            minDurationMs: 0,
            protocolVersion: 1,
        );
        $storage = new ArrayStorage();
        $storage->store($record);
        $verifier = new Verifier($storage, now: static fn (): int => Vectors::NOW);

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
