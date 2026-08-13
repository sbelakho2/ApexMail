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
 * Signing key ids (audit #91): the issued record carries a `kid` (wire key
 * ALWAYS present, default 1; the 22-key schema), the v2 canonical payload
 * ends with `|<kid>` (the FINAL field, after issuer), and a verifier
 * configured with a kid-keyed SECRET SET selects the signature secret per
 * kid — an unknown kid, or one beyond the newest configured kid (the
 * rollback/forward guard), fails with VerifyError::UnknownKid. An empty
 * set keeps the legacy single-secret path (the verify() $secretKey
 * parameter).
 */
final class KidSigningTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    private const SECRET_1 = '0123456789abcdef0123456789abcdef';

    private const SECRET_2 = 'fedcba9876543210fedcba9876543210';

    private function solve(string $prefix, string $salt, int $targetBits): int
    {
        $saltBytes = base64_decode($salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $targetBits);

        return $counter - 1;
    }

    /** @return array{0: ChallengeRecord, 1: string} issued+solved record/token */
    private function issue(int $kid = 1, string $secret = self::SECRET_1): array
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(
            new Config(secretKey: $secret, targetBits: 8, kid: $kid),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $issuer->issue('login', '198.51.100.7');
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        $counter = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits);

        return [$record, SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode()];
    }

    public function testConfigKidDefaultIsOneAndIsStampedOnRecordAndWire(): void
    {
        $config = new Config(secretKey: self::SECRET_1, targetBits: 8);

        self::assertSame(1, $config->kid);

        [$record] = $this->issue();
        self::assertSame(1, $record->kid);
        self::assertSame(1, $record->toArray()['kid'], 'the kid wire key is ALWAYS present');
        self::assertSame(1, ChallengeRecord::fromArray($record->toArray())->kid);
    }

    public function testConfigKidIsStampedAndRoundTrips(): void
    {
        [$record] = $this->issue(kid: 4);

        self::assertSame(4, $record->kid);
        self::assertSame(4, $record->toArray()['kid']);
        self::assertSame(4, ChallengeRecord::fromArray($record->toArray())->kid);
    }

    public function testConfigKidBounds(): void
    {
        foreach ([0, -1, 4_294_967_296] as $bad) {
            try {
                new Config(secretKey: self::SECRET_1, targetBits: 8, kid: $bad);
                self::fail("kid=$bad must be rejected at configuration");
            } catch (\InvalidArgumentException) {
                // expected
            }
        }

        $config = new Config(secretKey: self::SECRET_1, targetBits: 8, kid: 4_294_967_295);
        self::assertSame(4_294_967_295, $config->kid, 'the u32 wire ceiling is accepted');
    }

    public function testKidIsTheFinalFieldOfTheSignedCanonicalPayload(): void
    {
        [$record] = $this->issue(kid: 2);

        $canonical = base64_decode(explode('.', $record->challenge)[0], true);
        self::assertStringEndsWith('|2', (string) $canonical, 'the canonical must end with the kid segment');
        self::assertSame('2', explode('|', (string) $canonical)[17], 'kid is the 18th (final) canonical field, after issuer');
    }

    public function testLegacySingleSecretPathIgnoresKid(): void
    {
        // An EMPTY secretsByKid keeps the legacy path: the verify() secret
        // parameter authenticates any kid.
        [$record, $token] = $this->issue(kid: 3);

        $storage = new ArrayStorage();
        $storage->store($record);
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify(
            $token,
            self::SECRET_1,
            'login',
            '198.51.100.7',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertTrue($outcome->isOk(), sprintf('legacy path must verify any kid, got %s', $outcome->code()));
    }

    public function testSecretsByKidSelectsTheSignatureSecret(): void
    {
        [$record, $token] = $this->issue(kid: 2, secret: self::SECRET_2);

        $storage = new ArrayStorage();
        $storage->store($record);

        // The verifier holds BOTH secrets; the kid selects SECRET_2.
        $verifier = new Verifier(
            $storage,
            now: static fn (): int => self::ISSUED_AT,
            secretsByKid: [1 => self::SECRET_1, 2 => self::SECRET_2],
        );
        $outcome = $verifier->verify(
            $token,
            self::SECRET_1, // the legacy secret would NOT match; the kid-selected one must win
            'login',
            '198.51.100.7',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertTrue($outcome->isOk(), sprintf('the kid-selected secret must verify, got %s', $outcome->code()));
    }

    public function testUnknownKidIsRejectedAndBurned(): void
    {
        [$record, $token] = $this->issue(kid: 2, secret: self::SECRET_2);

        $storage = new ArrayStorage();
        $storage->store($record);

        $verifier = new Verifier(
            $storage,
            now: static fn (): int => self::ISSUED_AT,
            secretsByKid: [1 => self::SECRET_1],
        );
        $outcome = $verifier->verify($token, self::SECRET_1, 'login', '198.51.100.7');

        self::assertSame(VerifyError::UnknownKid, $outcome->error);
        self::assertNull($storage->find($record->nonce), 'an unknown-kid verification burns the record');
    }

    public function testFutureKeyedRecordIsRejectedByTheRollbackGuardEvenWhenSigned(): void
    {
        // The rollback/forward guard: a challenge signed with the CURRENT
        // secret but stamped with a kid AHEAD of the newest configured kid
        // must never verify on an older node — the guard fires BEFORE the
        // signature check.
        [$record, $token] = $this->issue(kid: 4, secret: self::SECRET_1);

        $storage = new ArrayStorage();
        $storage->store($record);

        $verifier = new Verifier(
            $storage,
            now: static fn (): int => self::ISSUED_AT,
            secretsByKid: [1 => self::SECRET_1, 2 => self::SECRET_2],
        );
        $outcome = $verifier->verify($token, self::SECRET_1, 'login', '198.51.100.7');

        self::assertSame(VerifyError::UnknownKid, $outcome->error, 'a future-keyed challenge must never verify on an older node');
        self::assertNull($storage->find($record->nonce));
    }

    public function testKidInTheSignedRangeButNotConfiguredIsUnknown(): void
    {
        // The map is not contiguous: kid 2 sits BELOW the max (3) but has no
        // configured secret — still unknown.
        [$record, $token] = $this->issue(kid: 2, secret: self::SECRET_2);

        $storage = new ArrayStorage();
        $storage->store($record);

        $verifier = new Verifier(
            $storage,
            now: static fn (): int => self::ISSUED_AT,
            secretsByKid: [1 => self::SECRET_1, 3 => self::SECRET_1],
        );
        $outcome = $verifier->verify($token, self::SECRET_1, 'login', '198.51.100.7');

        self::assertSame(VerifyError::UnknownKid, $outcome->error);
    }

    public function testMultiKeyDeploymentVerifiesEveryConfiguredKid(): void
    {
        $storage = new ArrayStorage();
        $issuer1 = new Issuer(
            new Config(secretKey: self::SECRET_1, targetBits: 8, kid: 1),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $issuer2 = new Issuer(
            new Config(secretKey: self::SECRET_2, targetBits: 8, kid: 2),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );

        $tokens = [];
        foreach ([$issuer1, $issuer2] as $i => $issuer) {
            $challenge = $issuer->issue('login', '198.51.100.7');
            $record = $storage->find($challenge->nonce);
            self::assertNotNull($record);
            self::assertSame($i + 1, $record->kid);
            $counter = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits);
            $tokens[] = [$record, SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode()];
        }

        $verifier = new Verifier(
            $storage,
            now: static fn (): int => self::ISSUED_AT,
            secretsByKid: [1 => self::SECRET_1, 2 => self::SECRET_2],
        );
        foreach ($tokens as [$record, $token]) {
            $outcome = $verifier->verify(
                $token,
                self::SECRET_1,
                'login',
                '198.51.100.7',
                nowNs: $record->issuedAtNs + 1_000_000,
            );
            self::assertTrue($outcome->isOk(), sprintf('kid %d must verify through the shared set, got %s', $record->kid, $outcome->code()));
        }
    }

    public function testAnOlderNodeRejectsTheNewerKidsChallenge(): void
    {
        // The rollback scenario end to end: the newer node (kid 2) issues,
        // an older node (only kid 1 configured) must reject with UnknownKid.
        $storage = new ArrayStorage();
        $newNode = new Issuer(
            new Config(secretKey: self::SECRET_2, targetBits: 8, kid: 2),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $newNode->issue('login', '198.51.100.7');
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        $counter = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits);
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();

        $oldNode = new Verifier(
            $storage,
            now: static fn (): int => self::ISSUED_AT,
            secretsByKid: [1 => self::SECRET_1],
        );
        $outcome = $oldNode->verify($token, self::SECRET_1, 'login', '198.51.100.7');

        self::assertSame(VerifyError::UnknownKid, $outcome->error, 'an older node must reject a future-keyed challenge');
    }

    public function testTamperingKidBreaksTheSignature(): void
    {
        // kid is signed into the canonical: a record rebuilt with a
        // DIFFERENT kid than the one its challenge was signed under must
        // fail the signature re-check (BadSignature), never verify.
        [$record, $token] = $this->issue(kid: 1);
        $tampered = new ChallengeRecord(
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
            prefix: $record->prefix,
            challenge: $record->challenge,
            minDurationMs: $record->minDurationMs,
            issuedAtNs: $record->issuedAtNs,
            protocolVersion: $record->protocolVersion,
            kid: 2,
        );
        $storage = new ArrayStorage();
        $storage->store($tampered);

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $outcome = $verifier->verify($token, self::SECRET_1, 'login', '198.51.100.7');

        self::assertSame(VerifyError::BadSignature, $outcome->error);
    }

    public function testSecretsByKidConstructionValidation(): void
    {
        foreach ([[0 => self::SECRET_1], [-1 => self::SECRET_1], ['a' => self::SECRET_1], [1 => 'tooshort']] as $bad) {
            try {
                new Verifier(new ArrayStorage(), secretsByKid: $bad);
                self::fail('invalid secretsByKid maps must be rejected at construction');
            } catch (\InvalidArgumentException) {
                // expected
            }
        }

        new Verifier(new ArrayStorage(), secretsByKid: [1 => self::SECRET_1]);
        self::assertTrue(true);
    }

    public function testUnknownKidErrorValue(): void
    {
        self::assertSame('unknown signing key id', VerifyError::UnknownKid->value);
    }

    public function testKidSurvivesTheWrappedRedisRoundTrip(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $client = new \KiwiCaptcha\Tests\Fixtures\FakePredisClient();
        $storage = new \KiwiCaptcha\Storage\RedisStorage($client);
        [$record] = $this->issue(kid: 2);
        $storage->store($record);

        $loaded = $storage->find($record->nonce);
        self::assertNotNull($loaded);
        self::assertSame(2, $loaded->kid);
    }
}
