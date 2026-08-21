<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Security-policy epoch and application transaction binding: the issued
 * record carries `policy_version` (Config, default 1) and
 * `request_binding` (issue-time nonce); both are part of the signed v2
 * canonical payload. A verifier configured with an expected policy
 * epoch rejects records issued under a different epoch
 * (WrongPolicyVersion), and a valid outcome exposes the consumed
 * record's request binding.
 */
final class SecurityPolicyTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    /** @return array{0: ArrayStorage, 1: ChallengeRecord, 2: string} */
    private function issue(
        int $policyVersion = 1,
        ?string $requestBinding = null,
        ?string $region = null,
    ): array {
        $storage = new ArrayStorage();
        $issuer = new Issuer(
            new Config(secretKey: Vectors::SECRET, targetBits: 8, policyVersion: $policyVersion),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
            region: $region,
        );
        $challenge = $issuer->issue('login', '198.51.100.7', $requestBinding);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        $counter = 0;
        $saltBytes = base64_decode($challenge->salt, true);
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        return [$storage, $record, SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode()];
    }

    public function testConfigPolicyVersionIsStampedOnTheRecord(): void
    {
        [, $record] = $this->issue(policyVersion: 3);

        self::assertSame(3, $record->policyVersion);
        self::assertSame(3, $record->toArray()['policy_version']);
        self::assertSame(3, ChallengeRecord::fromArray($record->toArray())->policyVersion);
    }

    public function testDefaultPolicyVersionIsOne(): void
    {
        [, $record] = $this->issue();

        self::assertSame(1, $record->policyVersion);
        self::assertSame(1, $record->toArray()['policy_version']);
    }

    public function testNullPolicyVersionSerializesAsDefaultEpoch(): void
    {
        // The ctor field is nullable; the Rust reader's policy_version is a
        // u32 and can never parse null, so the wire degrades to epoch 1.
        $record = new ChallengeRecord(
            nonce: '2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=',
            scope: 'login',
            bindingTag: 'tag123',
            issuedAt: self::ISSUED_AT,
            expiresAt: self::ISSUED_AT + 120,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 0,
            t: 1,
            p: 1,
            targetBits: 8,
            salt: 'c2FsdA==',
            prefix: 'prefix',
            challenge: 'challenge',
            minDurationMs: 0,
            policyVersion: null,
        );

        self::assertSame(1, $record->toArray()['policy_version']);
    }

    public function testRequestBindingIsCarriedOnRecordAndWire(): void
    {
        [, $record] = $this->issue(requestBinding: 'txn-9f3a');

        self::assertSame('txn-9f3a', $record->requestBinding);
        self::assertSame('txn-9f3a', $record->toArray()['request_binding']);
        self::assertSame('txn-9f3a', ChallengeRecord::fromArray($record->toArray())->requestBinding);
    }

    public function testUnboundRequestBindingIsNullOnTheWire(): void
    {
        [, $record] = $this->issue();

        self::assertNull($record->requestBinding);
        self::assertNull($record->toArray()['request_binding']);
    }

    public function testPolicyVersionAndRequestBindingAreSignedIntoTheCanonical(): void
    {
        [$storage, $record, $token] = $this->issue(policyVersion: 2, requestBinding: 'txn-abc');

        $canonical = Issuer::canonicalPayload(
            $record->nonce,
            $record->scope,
            $record->bindingTag,
            $record->issuedAt,
            $record->expiresAt,
            $record->algorithm,
            $record->mKib,
            $record->t,
            $record->p,
            $record->targetBits,
            $record->salt,
            $record->minDurationMs,
            $record->region,
            $record->policyVersion ?? 1,
            $record->requestBinding,
        );
        self::assertStringEndsWith('|2|txn-abc||1', $canonical, 'the canonical ends with policy_version|request_binding|issuer|kid (issuer empty when unset, kid default 1)');

        $signature = substr($record->challenge, strrpos($record->challenge, '.') + 1);
        self::assertSame(
            Issuer::signPayloadV2($canonical, Vectors::SECRET),
            $signature,
            'the v2 signature covers policy_version and request_binding',
        );

        // Round trip through the verifier recomputes the same canonical.
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            nowNs: $record->issuedAtNs + 1_000_000,
        );
        self::assertTrue($outcome->isOk(), sprintf('expected valid, got %s', $outcome->code()));
        self::assertSame('txn-abc', $outcome->requestBinding(), 'a valid outcome exposes the record request binding');
    }

    public function testMatchingPolicyVersionVerifies(): void
    {
        [$storage, $record, $token] = $this->issue(policyVersion: 2);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT, expectedPolicyVersion: 2);
        $outcome = $verifier->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertTrue($outcome->isOk(), sprintf('matching policy epoch must verify, got %s', $outcome->code()));
    }

    public function testMismatchedPolicyVersionRejectsAndBurns(): void
    {
        [$storage, $record, $token] = $this->issue(policyVersion: 2);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT, expectedPolicyVersion: 3);
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7');

        self::assertSame(VerifyError::WrongPolicyVersion, $outcome->error);
        self::assertNull($storage->find($record->nonce), 'a wrong-policy verification burns the record');
        self::assertNull($outcome->requestBinding());
    }

    public function testDefaultRecordRejectsWhenVerifierExpectsNewerEpoch(): void
    {
        // Default issuance (epoch 1) must fail closed under a verifier that
        // has rotated to epoch 2.
        [$storage, $record, $token] = $this->issue();

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT, expectedPolicyVersion: 2);
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7');

        self::assertSame(VerifyError::WrongPolicyVersion, $outcome->error);
        self::assertNull($storage->find($record->nonce));
    }

    public function testUnconfiguredVerifierAcceptsAnyEpoch(): void
    {
        [$storage, $record, $token] = $this->issue(policyVersion: 4);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertTrue($outcome->isOk(), sprintf('unconfigured verifier must accept any epoch, got %s', $outcome->code()));
    }

    public function testWrongPolicyVersionErrorValue(): void
    {
        self::assertSame('wrong_policy_version', VerifyError::WrongPolicyVersion->value);
        self::assertSame('challenge was issued under a different security-policy epoch', VerifyError::WrongPolicyVersion->description());
    }

    public function testFromArrayDefaultsPolicyVersionAndRequestBinding(): void
    {
        $data = $this->issue()[1]->toArray();
        unset($data['policy_version'], $data['request_binding']);

        $record = ChallengeRecord::fromArray($data);

        self::assertSame(1, $record->policyVersion);
        self::assertNull($record->requestBinding);
    }

    public function testIssueWithProfileCarriesConfigPolicyVersionAndBinding(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(
            new Config(secretKey: Vectors::SECRET, targetBits: 8, policyVersion: 7),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $issuer->issueWithProfile('login', '198.51.100.7', \KiwiCaptcha\ChallengeProfile::sha(8), null, 'txn-profile');

        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        self::assertSame(7, $record->policyVersion);
        self::assertSame('txn-profile', $record->requestBinding);
    }
}
