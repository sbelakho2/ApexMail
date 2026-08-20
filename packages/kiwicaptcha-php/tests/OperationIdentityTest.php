<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Storage\Psr6Storage;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Tests\Fixtures\ArrayPool;
use KiwiCaptcha\Tests\Fixtures\FakePredisClient;
use PHPUnit\Framework\TestCase;

/**
 * The operation-identity validation contract on the SHARED seam: every
 * storage implementing OperationIdentityAwareStorageInterface routes the
 * identity through OperationIdentity::validate(), so Redis, PSR-6 and the
 * array backend behave IDENTICALLY — a malformed identity (over-long, or
 * containing `%` / any non-alphabet character) is REJECTED with
 * InvalidArgumentException BEFORE the transition executes and the record
 * is left untouched; a valid identity (hex fingerprints, base64url,
 * UUIDs, HMAC digests — all `[A-Za-z0-9_-]`, 1..128 bytes) is recorded;
 * the null identity path stays unchanged. The narrow alphabet exists
 * because the identity is JSON-encoded and spliced into the Redis consume
 * Lua's string.gsub REPLACEMENT string, where `%` is the
 * replacement-template escape — the validated alphabet excludes it (and
 * every other gsub-special character) by construction.
 */
final class OperationIdentityTest extends TestCase
{
    private const VALID_HEX = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    private function makeRecord(string $nonce): ChallengeRecord
    {
        return new ChallengeRecord(
            nonce: $nonce,
            scope: 'login',
            bindingTag: 'abc123',
            issuedAt: 1_800_000_000,
            expiresAt: 1_800_000_120,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 0,
            t: 1,
            p: 1,
            targetBits: 8,
            salt: 'c2FsdA==',
            prefix: 'prefix',
            challenge: 'challenge',
            minDurationMs: 0,
            issuedAtNs: 123_456_789,
        );
    }

    /** @return array<string, \KiwiCaptcha\OperationIdentityAwareStorageInterface> */
    private function storages(): array
    {
        $redis = new RedisStorage(new FakePredisClient());
        $redis->store($this->makeRecord('redis-nonce-1'));

        $psr6 = new Psr6Storage(new ArrayPool());
        $psr6->store($this->makeRecord('psr6-nonce-1'));

        $array = new ArrayStorage();
        $array->store($this->makeRecord('array-nonce-1'));

        return ['redis' => $redis, 'psr6' => $psr6, 'array' => $array];
    }

    /** @param \KiwiCaptcha\OperationIdentityAwareStorageInterface $storage */
    private function assertUntouched(object $storage, string $nonce): void
    {
        self::assertNotNull($storage->find($nonce), 'a rejected identity must leave the record present');
        self::assertNull($storage->consumedState($nonce), 'a rejected identity must leave the record pending');
    }

    public function testOverlongIdentityIsRejectedOnEveryStorage(): void
    {
        foreach ($this->storages() as $name => $storage) {
            try {
                $storage->consumeWithOperationIdentity(str_contains($name, 'redis') ? 'redis-nonce-1' : ($name === 'psr6' ? 'psr6-nonce-1' : 'array-nonce-1'), str_repeat('x', 129));
                self::fail("an over-long identity must be rejected on $name");
            } catch (\InvalidArgumentException) {
                // expected: the 1..128-byte bound fires before the transition
            }
            $this->assertUntouched($storage, $name === 'redis' ? 'redis-nonce-1' : ($name === 'psr6' ? 'psr6-nonce-1' : 'array-nonce-1'));
        }
    }

    public function testGsubSpecialAndNonAlphabetIdentitiesAreRejectedOnEveryStorage(): void
    {
        foreach ($this->storages() as $name => $storage) {
            $nonce = $name === 'redis' ? 'redis-nonce-1' : ($name === 'psr6' ? 'psr6-nonce-1' : 'array-nonce-1');
            foreach (['deadbeef%deadbeef', 'deadbeef deadbeef', 'deadbeef=deadbeef', 'deadbeef/feed'] as $malformed) {
                try {
                    $storage->consumeWithOperationIdentity($nonce, $malformed);
                    self::fail("the identity '$malformed' must be rejected on $name");
                } catch (\InvalidArgumentException) {
                    // expected: the narrow alphabet excludes % and friends
                }
            }
            $this->assertUntouched($storage, $nonce);
        }
    }

    public function testValidHexIdentityIsRecordedOnEveryStorage(): void
    {
        foreach ($this->storages() as $name => $storage) {
            $nonce = $name === 'redis' ? 'redis-nonce-1' : ($name === 'psr6' ? 'psr6-nonce-1' : 'array-nonce-1');
            $consumed = $storage->consumeWithOperationIdentity($nonce, self::VALID_HEX);
            self::assertNotNull($consumed, "the identity-bearing consume must win the transition on $name");
            self::assertTrue($consumed->consumedNow);
            self::assertSame(self::VALID_HEX, $consumed->operationIdentity, "the winner exposes the identity it recorded on $name");
            if ($storage instanceof Psr6Storage) {
                // Psr6Storage::consumedState() is unavailable by design
                // (PSR-6 pools expose no atomic read-only inspection) —
                // the identity read-back is asserted through the consumed
                // transition response instead.
                continue;
            }
            $state = $storage->consumedState($nonce);
            self::assertNotNull($state);
            self::assertSame(self::VALID_HEX, $state->operationIdentity, "the recorded identity reads back on $name");
        }
    }

    public function testBase64urlAndUuidIdentitiesAreAccepted(): void
    {
        // The alphabet fits every identity shape the recovery contract
        // names: hex fingerprints, base64url, UUIDs (dashes) and HMAC
        // digests.
        $storage = new ArrayStorage();
        foreach (['base64url_ABC-xyz_0123456789', '123e4567-e89b-42d3-a456-426614174000'] as $i => $identity) {
            $storage->store($this->makeRecord('nonce-'.$i));
            $consumed = $storage->consumeWithOperationIdentity('nonce-'.$i, $identity);
            self::assertNotNull($consumed);
            self::assertSame($identity, $consumed->operationIdentity, "'$identity' fits the narrow alphabet");
        }
    }

    public function testNullIdentityPathIsUnchanged(): void
    {
        foreach ($this->storages() as $name => $storage) {
            $nonce = $name === 'redis' ? 'redis-nonce-1' : ($name === 'psr6' ? 'psr6-nonce-1' : 'array-nonce-1');
            $consumed = $storage->consumeWithOperationIdentity($nonce, null);
            self::assertNotNull($consumed, "the null identity must take the plain-consume path on $name");
            self::assertTrue($consumed->consumedNow);
            self::assertNull($consumed->operationIdentity, "a null identity records nothing on $name");
            self::assertNull($storage->consumedState($nonce)?->operationIdentity);
        }
    }
}
