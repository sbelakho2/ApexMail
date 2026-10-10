<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\IdempotencyClaim;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisSiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyCorruptException;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\StoredLookupKind;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SiteVerifyStoreAssert;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;

/**
 * The present-key lifetime boundary of the SiteVerify idempotency store,
 * against real Redis. A cached SiteVerify success is authorization-bearing
 * recovery state. A present record whose Redis lifetime was stripped
 * (`persist`, a bad restore, a foreign writer) must therefore never be
 * classified live. Every transition and the stored-success acceptance
 * fail closed with the typed corrupt exception; the controller answers
 * the 503 with zero mutation. The store must not convert a 300-second
 * replay window into unbounded replay authority.
 */
final class RealRedisSiteVerifyPersistenceGuardTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';
    private const SITEVERIFY_SECRET = 'compat-secret-42';

    /** @return \Predis\Client|null null when Redis is unreachable */
    private function redisOrSkip(): ?\Predis\Client
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $url = RedisTestUrl::resolve();
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis suites run in the CI Redis-service job');
        }
        try {
            $probe = new \Predis\Client($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
            $probe->ping();

            return $probe;
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at '.$url);
        }
    }

    /** @return array{0: string, 1: string} [token, nonce] */
    private function issueSha(RedisStorage $storage): array
    {
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        $challenge = $issuer->issue('login', '127.0.0.1');
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;
        usleep(($challenge->minDurationMs + 10) * 1000);

        return [SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode(), $challenge->nonce];
    }

    private function siteverifyRequest(array $fields): \Symfony\Component\HttpFoundation\Request
    {
        return \Symfony\Component\HttpFoundation\Request::create(
            '/kiwi-captcha/siteverify',
            'POST',
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'],
            http_build_query($fields),
        );
    }

    public function testAPersistedCompletedRecordNeverReplaysAsACachedSuccess(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $storage = new RedisStorage($probe);
        [$token, $nonce] = $this->issueSha($storage);
        $uuid = '7f1e6d20-1111-4000-8000-000000000001';
        $backendId = hash_hmac('sha256', 'login|0|', self::SITEVERIFY_SECRET);
        $idemKey = '{kiwi:kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid;
        $probe->del([$idemKey]);
        $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha');
        $fields = [
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '127.0.0.1',
            'idempotency_key' => $uuid,
        ];

        try {
            $controller = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 0.5);
            $first = $controller->siteverify($this->siteverifyRequest($fields));
            $firstBody = json_decode((string) $first->getContent(), true, 8, JSON_THROW_ON_ERROR);
            self::assertSame(200, $first->getStatusCode());
            self::assertTrue($firstBody['success'] ?? null, 'the first redemption succeeds and finalizes');
            self::assertNotNull(
                SiteVerifyStoreAssert::completed($store->storedForOperation($backendId, $uuid, hash('sha256', $token), SiteVerifyStoreAssert::fingerprint('127.0.0.1', self::SECRET), '')),
                'the completed canonical success is cached for retries',
            );
            self::assertGreaterThan(0, (int) $probe->ttl($idemKey), 'the cached success carries a bounded Redis lifetime');

            // The corruption: the Redis lifetime is accidentally stripped
            // (persist / bad restore / foreign writer).
            $probe->persist($idemKey);
            self::assertSame(-1, (int) $probe->ttl($idemKey), 'precondition: the key is now persistent');
            $before = $probe->get($idemKey);

            // The exact same operation retried: the cached success is
            // authorization-bearing replay authority and must NOT be
            // replayed from a persistent key — the retryable provider
            // internal error, never the stored success.
            $retry = $controller->siteverify($this->siteverifyRequest($fields));
            $retryBody = json_decode((string) $retry->getContent(), true, 8, JSON_THROW_ON_ERROR);
            self::assertSame(503, $retry->getStatusCode(), 'a persistent idempotency key must fail closed');
            self::assertSame(['internal-error'], $retryBody['error-codes'] ?? null);
            self::assertNotTrue($retryBody['success'] ?? true, 'the stored success must never be returned');
            self::assertSame($before, $probe->get($idemKey), 'the refusal performs zero mutation');
            self::assertSame(-1, (int) $probe->ttl($idemKey), 'no lifetime is manufactured by the refusal');
        } finally {
            $probe->del([$idemKey, 'kiwicaptcha:'.$nonce]);
        }
    }

    public function testAPersistedPendingRecordFailsClosedOnEveryTransitionAndRead(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha-persist-guard');
        $backendId = hash_hmac('sha256', 'login|0|', 'persist-guard');
        $uuid = '7f1e6d20-2222-4000-8000-000000000002';
        $key = '{kiwi:kiwicaptcha-persist-guard}:siteverify-idem:'.$backendId.':'.$uuid;
        $hash = hash('sha256', 'canonical-response');
        $fingerprint = hash('sha256', 'ip:127.0.0.1');
        $probe->del([$key]);

        try {
            [$claim, $owner] = $store->claim($backendId, $uuid, $hash, 300, $fingerprint);
            self::assertSame(IdempotencyClaim::Claimed, $claim);
            self::assertIsString($owner);

            $probe->persist($key);
            self::assertSame(-1, (int) $probe->ttl($key), 'precondition: the pending record is now persistent');
            $before = $probe->get($key);

            // The exact retry: the claim refuses with the typed corrupt
            // exception — never pending_same / complete_same.
            try {
                $store->claim($backendId, $uuid, $hash, 300, $fingerprint);
                self::fail('the claim must fail closed on a persistent record');
            } catch (SiteVerifyIdempotencyCorruptException) {
            }

            // pending -> takeover: refused, zero mutation.
            try {
                $store->takeover($backendId, $uuid, $hash, 300, $fingerprint, -1);
                self::fail('the takeover must fail closed on a persistent record');
            } catch (SiteVerifyIdempotencyCorruptException) {
            }

            // renew: refused, zero mutation.
            try {
                $store->renew($backendId, $uuid, (string) $owner);
                self::fail('the renewal must fail closed on a persistent record');
            } catch (SiteVerifyIdempotencyCorruptException) {
            }

            // finalize: refused, zero mutation — never a completed success
            // from a lifetime-stripped entry.
            try {
                $store->finalize($backendId, $uuid, $hash, (string) $owner, ['success' => true, 'challenge_ts' => null, 'hostname' => null]);
                self::fail('the finalize must fail closed on a persistent record');
            } catch (SiteVerifyIdempotencyCorruptException) {
            }

            // The operation-bound acceptance read also refuses.
            self::assertSame(
                StoredLookupKind::Corrupt,
                $store->storedForOperation($backendId, $uuid, $hash, $fingerprint, '')->kind,
                'the operation-bound read must fail closed on a persistent record',
            );

            self::assertSame($before, $probe->get($key), 'every refusal performed zero mutation');
            self::assertSame(-1, (int) $probe->ttl($key), 'no lifetime is manufactured by any refusal');
        } finally {
            $probe->del([$key]);
        }
    }

    public function testAPersistedPendingRecordNeverBecomesAStoredSuccessThroughTheController(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $storage = new RedisStorage($probe);
        [$token, $nonce] = $this->issueSha($storage);
        $uuid = '7f1e6d20-3333-4000-8000-000000000003';
        $backendId = hash_hmac('sha256', 'login|0|', self::SITEVERIFY_SECRET);
        $idemKey = '{kiwi:kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid;
        $probe->del([$idemKey]);
        $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha');
        $hash = hash('sha256', $token);
        $fingerprint = hash_hmac('sha256', 'siteverify-idem-ip-v1|127.0.0.1', self::SECRET);
        $fields = [
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '127.0.0.1',
            'idempotency_key' => $uuid,
        ];

        try {
            // Seed the exact pending claim the first redemption would have
            // created, then strip its lifetime.
            [$claim] = $store->claim($backendId, $uuid, $hash, 300, $fingerprint);
            self::assertSame(IdempotencyClaim::Claimed, $claim);
            $probe->persist($idemKey);
            $before = $probe->get($idemKey);

            $controller = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 0.5);
            $response = $controller->siteverify($this->siteverifyRequest($fields));
            $body = json_decode((string) $response->getContent(), true, 8, JSON_THROW_ON_ERROR);
            self::assertSame(503, $response->getStatusCode());
            self::assertSame(['internal-error'], $body['error-codes'] ?? null);
            self::assertSame($before, $probe->get($idemKey), 'the controller path performs zero mutation');
        } finally {
            $probe->del([$idemKey, 'kiwicaptcha:'.$nonce]);
        }
    }
}
