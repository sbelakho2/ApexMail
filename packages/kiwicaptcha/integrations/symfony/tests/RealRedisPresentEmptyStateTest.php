<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\MalformedChainedChallengeStateException;
use BelConsulting\KiwiCaptchaBundle\Risk\MalformedPostSolveDispositionException;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDisposition;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisPostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\IdempotencyClaim;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisSiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\StoredLookupKind;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SiteVerifyStoreAssert;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyCorruptException;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use PHPUnit\Framework\TestCase;

/**
 * The two boundaries of the shared present-key reader, against real
 * Redis:
 *
 *  1. PTTL, not TTL. A live key inside its final second reports TTL 0
 *     while PTTL is positive. That is a lifetime-bearing key and must
 *     never be classified as a stripped lifetime. Only a persistent key
 *     (PTTL -1) is corruption.
 *  2. Only Redis's missing sentinel means absent. A present empty value
 *     is damaged state. It proceeds to decoding and shape validation and
 *     fails closed with zero mutation: it is never healed into a fresh
 *     state machine, whether a fresh claim, a new pending disposition, a
 *     fresh chain or a restarted obligation.
 */
final class RealRedisPresentEmptyStateTest extends TestCase
{
    private \Predis\Client $client;

    protected function setUp(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $url = RedisTestUrl::resolve();
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis suites run in the CI Redis-service job');
        }
        $this->client = new \Predis\Client($url);
        try {
            $this->client->ping();
        } catch (\Throwable $e) {
            self::markTestSkipped('no Redis at '.$url.': '.$e->getMessage());
        }
    }

    public function testASubSecondLifetimeIsLiveNotStrippedCorruption(): void
    {
        $store = new RedisSiteVerifyIdempotencyStore($this->client, 'kiwicaptcha-emptystate');
        $backendId = hash_hmac('sha256', 'login|0|', 'emptystate');
        $uuid = 'a1b2c3d4-1111-4000-8000-00000000000a';
        $key = '{kiwi:kiwicaptcha-emptystate}:siteverify-idem:'.$backendId.':'.$uuid;
        $this->client->del([$key]);

        try {
            // A key whose lifetime is under one second: TTL reports 0,
            // PTTL reports a positive remainder. It is live.
            $this->client->set($key, '{"v":2,"response_hash":"'.str_repeat('a', 64).'","remoteip_fingerprint":"no-ip","binding":"","state":"complete","owner":null,"lease_expires_at":null,"result":{"success":true,"challenge_ts":null,"hostname":null}}', 'PX', 499);
            self::assertSame(0, (int) $this->client->ttl($key), 'precondition: TTL rounds to 0 at a sub-half-second remainder');
            self::assertGreaterThan(0, (int) $this->client->pttl($key), 'precondition: PTTL reports the real remainder');

            self::assertNotNull(
                SiteVerifyStoreAssert::completed($store->storedForOperation($backendId, $uuid, str_repeat('a', 64), 'no-ip', '')),
                'a sub-second lifetime-bearing record is live, never corrupt',
            );

            // The same key PERSISTed is genuinely lifetime-stripped.
            $this->client->persist($key);
            self::assertSame(-1, (int) $this->client->pttl($key));
            self::assertSame(
                StoredLookupKind::Corrupt,
                $store->storedForOperation($backendId, $uuid, str_repeat('a', 64), 'no-ip', '')->kind,
                'a persistent record must fail closed',
            );

            // The chain store's live read obeys the same boundary.
            $chains = new RedisChainedChallengeStateStore($this->client, 'kiwicaptcha-emptystate');
            $chainId = 'chain-'.bin2hex(random_bytes(8));
            $obligationId = bin2hex(random_bytes(32));
            $chains->createWithObligation($chainId, $obligationId, base64_encode(random_bytes(32)), 'login', null, 'sha20', 1, 300);
            $chainKey = '{kiwi:kiwicaptcha-emptystate}:chain:'.$chainId;
            $this->client->pexpire($chainKey, 499);
            self::assertSame(0, (int) $this->client->ttl($chainKey));
            self::assertNotNull($chains->read($chainId), 'a sub-second chain lifetime is live');
            $this->client->persist($chainKey);
            try {
                $chains->read($chainId);
                self::fail('a persistent chain must fail closed');
            } catch (MalformedChainedChallengeStateException) {
            }
            $this->client->del([$chainKey, '{kiwi:kiwicaptcha-emptystate}:chain-obligation:'.$obligationId]);
        } finally {
            $this->client->del([$key]);
        }
    }

    public function testAPersistInjectedBetweenThePreflightAndTheReserveScriptIsCorruptNotMissing(): void
    {
        // The reserve path has a PHP preflight read and then an atomic Lua
        // transition. The script itself must classify a present key whose
        // lifetime was stripped as corrupt, never missing: if the persist
        // lands in the preflight->EVAL window, 'missing' would let a
        // corrupted reservation look like an expired challenge.
        $chains = new RedisChainedChallengeStateStore($this->client, 'kiwicaptcha-emptystate');
        $chainId = 'chain-'.bin2hex(random_bytes(8));
        $obligationId = bin2hex(random_bytes(32));
        $chains->createWithObligation($chainId, $obligationId, base64_encode(random_bytes(32)), 'login', null, 'sha20', 1, 300);
        $chainKey = '{kiwi:kiwicaptcha-emptystate}:chain:'.$chainId;

        // The preflight read passes on the valid lifetime-bearing record.
        self::assertNotNull($chains->read($chainId));

        // The injected client strips the lifetime exactly when the reserve
        // script runs, after the preflight already saw a live record.
        $injecting = new class($this->client, $chainKey) extends \Predis\Client {
            public function __construct(
                private readonly \Predis\Client $inner,
                private readonly string $chainKey,
            ) {
            }

            public function __call($commandID, $arguments)
            {
                if (\is_string($commandID) && strtolower($commandID) === 'eval'
                    && isset($arguments[0]) && \is_string($arguments[0])
                    && str_contains($arguments[0], 'Chain reservation')
                ) {
                    $this->inner->persist($this->chainKey);
                }

                return $this->inner->{$commandID}(...$arguments);
            }
        };
        $injected = new RedisChainedChallengeStateStore($injecting, 'kiwicaptcha-emptystate');

        try {
            $injected->reserve($chainId, bin2hex(random_bytes(16)), 30);
            self::fail('a PERSISTed chain at the reservation boundary must throw, never answer missing');
        } catch (MalformedChainedChallengeStateException) {
        }
        self::assertSame(-1, (int) $this->client->pttl($chainKey));

        // And the raw script answer is the corruption verdict, not missing:
        // a second preflight-free caller sees the same classification.
        try {
            $injected->reserve($chainId, bin2hex(random_bytes(16)), 30);
            self::fail('the persistent chain stays corrupt');
        } catch (MalformedChainedChallengeStateException) {
        }
        $this->client->del([$chainKey, '{kiwi:kiwicaptcha-emptystate}:chain-obligation:'.$obligationId]);
    }

    public function testAPresentEmptySiteVerifyRecordFailsClosedAndIsNeverHealed(): void
    {
        $store = new RedisSiteVerifyIdempotencyStore($this->client, 'kiwicaptcha-emptystate');
        $backendId = hash_hmac('sha256', 'login|0|', 'emptystate');
        $uuid = 'a1b2c3d4-2222-4000-8000-00000000000b';
        $key = '{kiwi:kiwicaptcha-emptystate}:siteverify-idem:'.$backendId.':'.$uuid;
        $this->client->set($key, '', 'EX', 60);
        $before = $this->client->get($key);

        try {
            try {
                $store->claim($backendId, $uuid, str_repeat('a', 64), 300, 'no-ip');
                self::fail('an empty record must fail closed, never be re-claimed');
            } catch (SiteVerifyIdempotencyCorruptException) {
            }
            self::assertSame(
                StoredLookupKind::Corrupt,
                $store->storedForOperation($backendId, $uuid, str_repeat('a', 64), 'no-ip', '')->kind,
                'an empty record must fail closed on the read',
            );
            self::assertSame($before, $this->client->get($key), 'the empty value is untouched (zero mutation, never healed)');
        } finally {
            $this->client->del([$key]);
        }
    }

    public function testAPresentEmptyPostSolveRecordFailsClosedAndIsNeverHealed(): void
    {
        $store = new RedisPostSolveDispositionStore($this->client, 'kiwicaptcha-emptystate');
        $nonce = base64_encode(random_bytes(32));
        $key = '{kiwi:kiwicaptcha-emptystate}:postsolve:'.$nonce;
        $this->client->set($key, '', 'EX', 60);
        $before = $this->client->get($key);

        try {
            try {
                $store->read($nonce);
                self::fail('an empty disposition must fail closed on the read');
            } catch (MalformedPostSolveDispositionException) {
            }
            try {
                $store->claim($nonce, bin2hex(random_bytes(16)), 300);
                self::fail('an empty disposition must never be re-claimed');
            } catch (MalformedPostSolveDispositionException) {
            }
            self::assertSame($before, $this->client->get($key), 'the empty value is untouched');
        } finally {
            $this->client->del([$key]);
        }
    }

    public function testAPresentEmptyChainRecordFailsClosedAndIsNeverHealed(): void
    {
        $chains = new RedisChainedChallengeStateStore($this->client, 'kiwicaptcha-emptystate');
        $chainId = 'chain-'.bin2hex(random_bytes(8));
        $key = '{kiwi:kiwicaptcha-emptystate}:chain:'.$chainId;
        $this->client->set($key, '', 'EX', 60);
        $before = $this->client->get($key);

        try {
            try {
                $chains->read($chainId);
                self::fail('an empty chain must fail closed on the read');
            } catch (MalformedChainedChallengeStateException) {
            }
            self::assertSame($before, $this->client->get($key), 'the empty value is untouched');
        } finally {
            $this->client->del([$key]);
        }
    }

    public function testAPresentEmptyObligationMappingFailsClosedAndIsNeverHealed(): void
    {
        $chains = new RedisChainedChallengeStateStore($this->client, 'kiwicaptcha-emptystate');
        $obligationId = bin2hex(random_bytes(32));
        $key = '{kiwi:kiwicaptcha-emptystate}:chain-obligation:'.$obligationId;
        $this->client->set($key, '', 'EX', 60);
        $before = $this->client->get($key);

        try {
            try {
                $chains->obligationLookup($obligationId);
                self::fail('an empty obligation mapping must fail closed, never read as no-obligation');
            } catch (MalformedChainedChallengeStateException) {
            }
            self::assertSame($before, $this->client->get($key), 'the empty value is untouched');

            // The post-solve guard's PHP pre-read applies the same rule.
            $store = new RedisPostSolveDispositionStore($this->client, 'kiwicaptcha-emptystate');
            $nonce = base64_encode(random_bytes(32));
            try {
                $store->claim($nonce, bin2hex(random_bytes(16)), 300, null, $obligationId, null, null);
                self::fail('the post-solve guard must fail closed on an empty obligation mapping');
            } catch (MalformedPostSolveDispositionException) {
            }
        } finally {
            $this->client->del([$key]);
        }
    }

    public function testAGenuinelyMissingKeyKeepsItsHealingSemantics(): void
    {
        // The counterpart rule: a deleted key is genuinely absent, so a
        // fresh claim/disposition/chain may start exactly as before.
        $store = new RedisSiteVerifyIdempotencyStore($this->client, 'kiwicaptcha-emptystate');
        $backendId = hash_hmac('sha256', 'login|0|', 'emptystate');
        $uuid = 'a1b2c3d4-3333-4000-8000-00000000000c';
        $key = '{kiwi:kiwicaptcha-emptystate}:siteverify-idem:'.$backendId.':'.$uuid;
        $this->client->del([$key]);
        try {
            [$claim] = $store->claim($backendId, $uuid, str_repeat('a', 64), 300, 'no-ip');
            self::assertSame(IdempotencyClaim::Claimed, $claim);
            self::assertSame('pending', json_decode((string) $this->client->get($key), true, 8, JSON_THROW_ON_ERROR)['state']);
        } finally {
            $this->client->del([$key]);
        }

        $dispositions = new RedisPostSolveDispositionStore($this->client, 'kiwicaptcha-emptystate');
        $nonce = base64_encode(random_bytes(32));
        $recordKey = '{kiwi:kiwicaptcha-emptystate}:postsolve:'.$nonce;
        $this->client->del([$recordKey]);
        try {
            [$status] = $dispositions->claim($nonce, bin2hex(random_bytes(16)), 300);
            self::assertSame('claimed', $status, 'a missing disposition starts fresh');
            self::assertGreaterThan(0, (int) $this->client->pttl($recordKey), 'the fresh disposition carries a lifetime');
        } finally {
            $this->client->del([$recordKey]);
        }
    }
}
