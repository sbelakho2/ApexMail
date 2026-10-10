<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\RedisStorage;
use PHPUnit\Framework\TestCase;

/**
 * Raw-envelope boundary of the real Redis Lua transitions, against the
 * running real-Redis instance: a key with no expiry (a persistent
 * foreign key) is refused by every mutating transition and left
 * byte-intact. An envelope without the `"operation_identity":null`
 * marker refuses the identity consume instead of silently dropping the
 * identity. The consume flip preserves the key's remaining lifetime
 * in milliseconds (PTTL/PX, floored at 1000 ms).
 *
 * Runs when `KC_REDIS_URL` or `TEST_REDIS_URL` is set (the shared
 * real-Redis env of the monorepo CI); skips otherwise, like every other
 * real-Redis suite.
 */
final class RawEnvelopeRefusalRealRedisTest extends TestCase
{
    /** @return \Predis\Client|null null when Redis is unreachable */
    private function redisOrSkip(): ?\Predis\Client
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $url = getenv('KC_REDIS_URL');
        if (!\is_string($url) || $url === '') {
            $url = getenv('TEST_REDIS_URL');
        }
        if (!\is_string($url) || $url === '') {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis raw-envelope suite runs in the CI Redis-service job');
        }
        try {
            $probe = new \Predis\Client($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
            $probe->ping();

            return $probe;
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at the configured KC_REDIS_URL/TEST_REDIS_URL');
        }
    }

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

    private function envelope(string $nonce, bool $withIdentityMarker = true): string
    {
        $data = $this->makeRecord($nonce)->toArray() + ['state' => 'pending', 'consumed_result' => null];
        if ($withIdentityMarker) {
            $data['operation_identity'] = null;
        }

        return (string) json_encode($data, JSON_UNESCAPED_SLASHES);
    }

    public function testAPersistentKeyIsRefusedByTheMutatingTransitionsAndLeftByteIntact(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        $prefix = 'raw-refusal-'.bin2hex(random_bytes(4)).'-';
        $storage = new RedisStorage($client, $prefix);
        $nonce = 'persistent-nonce';
        $key = $prefix.$nonce;
        $raw = $this->envelope($nonce);
        $client->set($key, $raw);

        self::assertNull($storage->consume($nonce), 'the consume transition refuses a persistent key');
        self::assertNull($storage->consumeWithOperationIdentity($nonce, 'order-42'), 'the identity consume refuses a persistent key');
        self::assertNull($storage->cancel($nonce), 'the cancel transition refuses a persistent key');
        self::assertFalse($storage->commitResult($nonce, true, null), 'the result commit refuses a persistent key');
        self::assertNull($storage->claimResumeDerivation($nonce), 'the resume claim refuses a persistent key');
        self::assertFalse($storage->releaseResumeDerivation($nonce, str_repeat('a', 32)), 'the claim release refuses a persistent key');

        self::assertSame(-1, $client->pttl($key), 'the persistent key still carries no expiry');
        self::assertSame($raw, $client->get($key), 'the refused transitions leave the persistent key byte-intact');
    }

    public function testAnEnvelopeWithoutTheIdentityMarkerRefusesTheIdentityConsume(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        $prefix = 'raw-refusal-'.bin2hex(random_bytes(4)).'-';
        $storage = new RedisStorage($client, $prefix);
        $nonce = 'markerless-nonce';
        $key = $prefix.$nonce;
        $client->set($key, $this->envelope($nonce, withIdentityMarker: false), 'EX', 120);

        try {
            $storage->consumeWithOperationIdentity($nonce, 'order-42');
            self::fail('a non-empty identity on a markerless envelope must be refused');
        } catch (\KiwiCaptcha\Storage\StorageWriteException $e) {
            self::assertStringContainsString('operation_identity', $e->getMessage());
        }

        $after = (string) $client->get($key);
        self::assertStringNotContainsString('"operation_identity"', $after, 'the refused consume must not leave the record claiming an identity');
        self::assertStringContainsString('"state":"consumed"', $after, 'the flip itself stays durable');
        self::assertNull($storage->consumedState($nonce)?->operationIdentity, 'the retained state exposes no identity');
    }

    public function testTheConsumeFlipPreservesTheRemainingLifetimeInMilliseconds(): void
    {
        // SET with a 2-second TTL, then consume after ~0.6s: the
        // remaining lifetime is ~1.4s, and the flip preserves it in
        // milliseconds. A whole-second EX write would truncate the
        // remainder to at most 1000 ms; the preserved PX lease must stay
        // above that.
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        $prefix = 'raw-refusal-'.bin2hex(random_bytes(4)).'-';
        $storage = new RedisStorage($client, $prefix);
        $nonce = 'ms-nonce';
        $key = $prefix.$nonce;
        $client->set($key, $this->envelope($nonce), 'EX', 2);
        usleep(600_000);

        $consumed = $storage->consume($nonce);
        self::assertTrue($consumed?->consumedNow ?? false, 'the expiry-bearing key is consumable');

        $pttl = (int) $client->pttl($key);
        self::assertGreaterThan(1_000, $pttl, sprintf('the flip preserves the millisecond remainder (PTTL %d ms must exceed the whole-second floor)', $pttl));
        self::assertLessThanOrEqual(1_400, $pttl, 'the preserved lease is the remaining lifetime, never extended');
    }

    public function testTheClaimLeaseIsEpochMicroseconds(): void
    {
        // The claim lease expiry is epoch microseconds: a claim TTL of 1
        // writes a true 1-second lease whose value sits on the
        // microsecond clock, an immediate second claim is refused inside
        // the live window, and the lease dies deterministically after it.
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        $prefix = 'raw-refusal-'.bin2hex(random_bytes(4)).'-';
        $storage = new RedisStorage($client, $prefix);
        $nonce = 'us-nonce';
        $key = $prefix.$nonce;
        $client->set($key, $this->envelope($nonce), 'EX', 120);
        $storage->consume($nonce);

        $owner = $storage->claimResumeDerivation($nonce, 1);
        self::assertIsString($owner, 'a consumed resultless record is claimable');
        $until = json_decode((string) $client->get($key), true)['resume_until'] ?? null;
        $nowUs = (int) (microtime(true) * 1_000_000);
        self::assertIsInt($until);
        self::assertGreaterThan($nowUs, $until, 'the lease expiry is on the microsecond clock');
        self::assertLessThanOrEqual($nowUs + 1_000_000, $until, 'the lease expiry is now + 1s in microseconds');
        self::assertNull($storage->claimResumeDerivation($nonce, 1), 'the live 1-second lease is refused');

        usleep(1_200_000);
        self::assertIsString($storage->claimResumeDerivation($nonce, 60), 'the lease dies deterministically once the microsecond deadline passes');
    }
}
