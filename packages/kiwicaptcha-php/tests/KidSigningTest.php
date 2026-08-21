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
 * Signing key ids: the issued record carries a `kid` (wire key always
 * present, default 1; the 22-key schema), and the v2 canonical payload
 * ends with `|<kid>` (the final field, after issuer). A verifier
 * configured with a kid-keyed secret set selects the signature secret
 * per kid. An unknown kid, or one beyond the newest configured kid,
 * fails with VerifyError::UnknownKid; this is the rollback/forward
 * guard. An empty set keeps the legacy single-secret path, the
 * verify() $secretKey parameter.
 *
 * Compromise revocation: a verifier configured with a revokedKids set
 * rejects any record whose kid is in it with UnknownKid immediately,
 * before the signature check. Revocation therefore overrides the normal
 * rotation grace even when the kid's secret is still present in
 * secretsByKid.
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
        // An empty secretsByKid keeps the legacy path: the verify()
        // secret parameter authenticates any kid.
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

        // The verifier holds both secrets; the kid selects the second
        // secret.
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
        // The rollback/forward guard: a challenge signed with the
        // current secret but stamped with a kid ahead of the newest
        // configured kid must never verify on an older node; the guard
        // fires before the signature check.
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
        // The map is not contiguous: kid 2 sits below the max (3) but
        // has no configured secret; it is still unknown.
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
        // different kid than the one its challenge was signed under must
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
        self::assertSame('unknown_kid', VerifyError::UnknownKid->value);
        self::assertSame('unknown signing key id', VerifyError::UnknownKid->description());
    }

    public function testRevokedKidRejectedEvenWhenSecretPresent(): void
    {
        // A perfectly signed challenge under a revoked kid must fail
        // with UnknownKid: compromise revocation overrides the rotation
        // grace (kid 2's secret is in secretsByKid and the signature
        // would pass).
        [$record, $token] = $this->issue(kid: 2, secret: self::SECRET_2);

        $storage = new ArrayStorage();
        $storage->store($record);

        $verifier = new Verifier(
            $storage,
            now: static fn (): int => self::ISSUED_AT,
            secretsByKid: [1 => self::SECRET_1, 2 => self::SECRET_2],
            revokedKids: [2],
        );
        $outcome = $verifier->verify(
            $token,
            self::SECRET_1,
            'login',
            '198.51.100.7',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertSame(VerifyError::UnknownKid, $outcome->error, 'revocation must override the rotation grace');
        self::assertNull($storage->find($record->nonce), 'a revoked-kid verification burns the record');
    }

    public function testRevokedKidRejectedBeforeSignatureWork(): void
    {
        // The revocation gate fires before the signature check: the
        // stored record is tampered (scope swapped) so the signature
        // re-check would fail with BadSignature, yet the cheap revocation
        // gate wins and reports UnknownKid. If the gate ever deferred to
        // the signature comparison, this would surface BadSignature.
        [$record, $token] = $this->issue(kid: 2, secret: self::SECRET_2);
        $tampered = new ChallengeRecord(
            nonce: $record->nonce,
            scope: 'tampered',
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
            kid: $record->kid,
        );

        $storage = new ArrayStorage();
        $storage->store($tampered);

        $verifier = new Verifier(
            $storage,
            now: static fn (): int => self::ISSUED_AT,
            secretsByKid: [1 => self::SECRET_1, 2 => self::SECRET_2],
            revokedKids: [2],
        );
        $outcome = $verifier->verify($token, self::SECRET_1, 'login', '198.51.100.7');

        self::assertSame(VerifyError::UnknownKid, $outcome->error, 'revocation must beat the signature check');
    }

    public function testUnrevokedKidWithSecretStillVerifies(): void
    {
        // Revoking kid 1 must not affect kid 2: the secret is present and
        // the challenge verifies normally.
        [$record, $token] = $this->issue(kid: 2, secret: self::SECRET_2);

        $storage = new ArrayStorage();
        $storage->store($record);

        $verifier = new Verifier(
            $storage,
            now: static fn (): int => self::ISSUED_AT,
            secretsByKid: [1 => self::SECRET_1, 2 => self::SECRET_2],
            revokedKids: [1],
        );
        $outcome = $verifier->verify(
            $token,
            self::SECRET_1,
            'login',
            '198.51.100.7',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertTrue($outcome->isOk(), sprintf('an unrevoked kid must verify, got %s', $outcome->code()));
    }

    public function testLegacySingleSecretPathUnaffectedByRevocationDefaults(): void
    {
        // The new parameter defaults to []: the legacy single-secret path
        // (empty secretsByKid, no revocations) verifies any kid exactly as
        // on the single-secret path.
        [$record, $token] = $this->issue(kid: 3, secret: self::SECRET_1);

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

        self::assertTrue($outcome->isOk(), sprintf('the legacy path must verify any kid, got %s', $outcome->code()));
    }

    public function testRevocationAppliesInLegacySingleSecretMode(): void
    {
        // Revocation is kid-based and applies unconditionally: even without
        // a secretsByKid set, a revoked kid fails with UnknownKid before
        // the signature check.
        [$record, $token] = $this->issue(kid: 2, secret: self::SECRET_2);

        $storage = new ArrayStorage();
        $storage->store($record);

        $verifier = new Verifier(
            $storage,
            now: static fn (): int => self::ISSUED_AT,
            revokedKids: [2],
        );
        $outcome = $verifier->verify($token, self::SECRET_2, 'login', '198.51.100.7');

        self::assertSame(VerifyError::UnknownKid, $outcome->error);
    }

    public function testRevokedKidsConstructionValidation(): void
    {
        foreach ([[0], [-1], ['a'], [1.5], [null]] as $bad) {
            try {
                new Verifier(new ArrayStorage(), revokedKids: $bad);
                self::fail('invalid revokedKids must be rejected at construction');
            } catch (\InvalidArgumentException) {
                // expected
            }
        }

        new Verifier(new ArrayStorage(), revokedKids: [1, 2]);
        self::assertTrue(true);
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
