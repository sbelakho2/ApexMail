<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Tests\Fixtures\ArrayPool;
use KiwiCaptcha\Tests\Fixtures\FakePredisClient;
use PHPUnit\Framework\TestCase;

/**
 * The operation-identity validation contract on the shared seam: every
 * storage implementing OperationIdentityAwareStorageInterface routes
 * the identity through OperationIdentity::validate(), so Redis, PSR-6
 * and the array backend behave identically. A malformed identity
 * (over-long, or containing `%` or any non-alphabet character) is
 * rejected with InvalidArgumentException before the transition executes
 * and the record is left untouched. A valid identity (hex fingerprints,
 * base64url, UUIDs, HMAC digests, all `[A-Za-z0-9_-]`, 1..128 bytes) is
 * recorded; the null identity path stays unchanged. The narrow alphabet
 * exists because the identity is JSON-encoded and spliced into the
 * Redis consume Lua's string.gsub replacement string, where `%` is the
 * replacement-template escape; the validated alphabet excludes it (and
 * every other gsub-special character) by construction.
 */
final class OperationIdentityTest extends TestCase
{

    /**
     * The wire nonce of a logical fixture label. The record decode
     * boundary requires the 44-char standard-base64 shape of 32 bytes.
     * That is the strict serde twin. Logical labels map to it here and
     * the storage keys stay readable at the call sites.
     */
    private static function wn(string $logical): string
    {
        return \KiwiCaptcha\Tests\Support\WireFixture::nonce($logical);
    }
    private const VALID_HEX = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    private function makeRecord(string $nonce): ChallengeRecord
    {
        return new ChallengeRecord(
            nonce: self::wn($nonce),
            scope: 'login',
            bindingTag: 'abc123',
            issuedAt: 1_800_000_000,
            expiresAt: 1_800_000_120,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 0,
            t: 1,
            p: 1,
            targetBits: 8,
            salt: \KiwiCaptcha\Tests\Support\WireFixture::SALT,
            prefix: \KiwiCaptcha\Tests\Support\WireFixture::prefix('challenge'),
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

        // Psr6Storage deliberately does not offer the identity-aware
        // consume (a PSR-6 pool cannot make the retained state
        // authoritative recovery evidence), so it is absent from this
        // capability matrix by contract.

        $array = new ArrayStorage();
        $array->store($this->makeRecord('array-nonce-1'));

        return ['redis' => $redis, 'array' => $array];
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
                $storage->consumeWithOperationIdentity(str_contains($name, 'redis') ? self::wn('redis-nonce-1') : self::wn('array-nonce-1'), str_repeat('x', 129));
                self::fail("an over-long identity must be rejected on $name");
            } catch (\InvalidArgumentException) {
                // expected: the 1..128-byte bound fires before the transition
            }
            $this->assertUntouched($storage, $name === 'redis' ? self::wn('redis-nonce-1') : self::wn('array-nonce-1'));
        }
    }

    public function testGsubSpecialAndNonAlphabetIdentitiesAreRejectedOnEveryStorage(): void
    {
        foreach ($this->storages() as $name => $storage) {
            $nonce = $name === 'redis' ? self::wn('redis-nonce-1') : self::wn('array-nonce-1');
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
            $nonce = $name === 'redis' ? self::wn('redis-nonce-1') : self::wn('array-nonce-1');
            $consumed = $storage->consumeWithOperationIdentity($nonce, self::VALID_HEX);
            self::assertNotNull($consumed, "the identity-bearing consume must win the transition on $name");
            self::assertTrue($consumed->consumedNow);
            self::assertSame(self::VALID_HEX, $consumed->operationIdentity, "the winner exposes the identity it recorded on $name");
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
            $consumed = $storage->consumeWithOperationIdentity(self::wn('nonce-'.$i), $identity);
            self::assertNotNull($consumed);
            self::assertSame($identity, $consumed->operationIdentity, "'$identity' fits the narrow alphabet");
        }
    }

    public function testNullIdentityPathIsUnchanged(): void
    {
        foreach ($this->storages() as $name => $storage) {
            $nonce = $name === 'redis' ? self::wn('redis-nonce-1') : self::wn('array-nonce-1');
            $consumed = $storage->consumeWithOperationIdentity($nonce, null);
            self::assertNotNull($consumed, "the null identity must take the plain-consume path on $name");
            self::assertTrue($consumed->consumedNow);
            self::assertNull($consumed->operationIdentity, "a null identity records nothing on $name");
            self::assertNull($storage->consumedState($nonce)?->operationIdentity);
        }
    }

    public function testAnEnvelopeWithoutTheIdentityMarkerRefusesTheIdentityConsume(): void
    {
        // The identity API's envelope contract: a non-empty identity must
        // land in the same write as the state flip, and an envelope that
        // carries no `"operation_identity":null` marker is not one the
        // API may write to. The consume transition reports the missing
        // splice and the storage refuses the result — the identity is
        // never silently dropped, and the flipped record never claims an
        // identity it does not carry.
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed; cannot test RedisStorage');
        }
        $client = new FakePredisClient();
        $storage = new RedisStorage($client, 'kiwi:');
        $envelope = json_encode(
            $this->makeRecord('markerless-nonce')->toArray() + ['state' => 'pending', 'consumed_result' => null],
            JSON_UNESCAPED_SLASHES,
        );
        $client->set('kiwi:'.self::wn('markerless-nonce'), $envelope, 'EX', 120);

        try {
            $storage->consumeWithOperationIdentity(self::wn('markerless-nonce'), self::VALID_HEX);
            self::fail('a non-empty identity on a markerless envelope must be refused');
        } catch (\KiwiCaptcha\Storage\StorageWriteException $e) {
            self::assertStringContainsString('operation_identity', $e->getMessage());
        }

        $after = json_decode((string) $client->store['kiwi:'.self::wn('markerless-nonce')], true);
        self::assertIsArray($after);
        self::assertArrayNotHasKey('operation_identity', $after, 'the refused consume must not leave the record claiming an identity');
        self::assertNull($storage->consumedState(self::wn('markerless-nonce'))?->operationIdentity, 'the retained state exposes no identity');

        // The plain consume on a markerless envelope stays legal: no
        // identity argument, nothing to splice.
        $secondEnvelope = json_encode(
            $this->makeRecord('markerless-nonce-2')->toArray() + ['state' => 'pending', 'consumed_result' => null],
            JSON_UNESCAPED_SLASHES,
        );
        $client->set('kiwi:'.self::wn('markerless-nonce-2'), $secondEnvelope, 'EX', 120);
        $consumed = $storage->consume(self::wn('markerless-nonce-2'));
        self::assertTrue($consumed?->consumedNow ?? false, 'the plain consume of a markerless envelope is unchanged');
        self::assertNull($consumed?->operationIdentity);
    }
}
