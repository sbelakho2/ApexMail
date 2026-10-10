<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\IdempotencyClaim;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisSiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;

/**
 * The SiteVerify schema upgrade path, against real Redis: the
 * immediately preceding release already wrote the full operation
 * identity (response_hash, remoteip_fingerprint, binding) into a
 * versionless record and compared all three before answering. A credible
 * upgrade must therefore replay its completed records byte-for-byte and
 * treat its in-flight record as non-authoritative pending — never as an
 * unconditional conflict (which the HTTP path would surface as a 400
 * before stored() is ever reached). Records missing any identity
 * component, or with any differing component, keep conflicting.
 */
final class RealRedisSiteVerifyUpgradeTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';
    private const SITEVERIFY_SECRET = 'compat-secret-42';

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

    private function controller(RedisStorage $storage, RedisSiteVerifyIdempotencyStore $store, float $waitSecs = 0.5): SiteVerifyController
    {
        return new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, $waitSecs);
    }

    /**
     * The exact completed record the preceding release's writer emitted:
     * no `v` member, all seven fields, the full operation identity, the
     * canonical result. Every value is what that writer would have
     * stored for this operation.
     *
     * @param array<string, mixed> $result
     */
    private function legacyCompletedBytes(string $responseHash, string $fingerprint, string $binding, array $result): string
    {
        return (string) json_encode([
            'response_hash' => $responseHash,
            'remoteip_fingerprint' => $fingerprint,
            'binding' => $binding,
            'state' => 'complete',
            'owner' => null,
            'result' => $result,
            'lease_expires_at' => null,
        ], JSON_THROW_ON_ERROR);
    }

    public function testACompletedLegacyRecordFromTheImmediatelyPrecedingReleaseReplaysIdentically(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $storage = new RedisStorage($probe);
        [$token, $nonce] = $this->issueSha($storage);
        $uuid = '8e2f7a40-1111-4000-8000-0000000000a1';
        $backendId = hash_hmac('sha256', 'login|0|', self::SITEVERIFY_SECRET);
        $idemKey = '{kiwi:kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid;
        $probe->del([$idemKey]);
        $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha');

        // The preceding release's canonical success result, as its store
        // held it.
        $result = ['success' => true, 'challenge_ts' => null, 'hostname' => null];
        ksort($result);
        $legacyBytes = $this->legacyCompletedBytes(
            hash('sha256', $token),
            hash_hmac('sha256', 'siteverify-idem-ip-v1|127.0.0.1', self::SECRET),
            '',
            $result,
        );
        $probe->set($idemKey, $legacyBytes, 'EX', 300);
        $before = $probe->get($idemKey);

        try {
            $controller = $this->controller($storage, $store);
            $fields = [
                'secret' => self::SITEVERIFY_SECRET,
                'response' => $token,
                'remoteip' => '127.0.0.1',
                'idempotency_key' => $uuid,
            ];
            $retry = $controller->siteverify($this->siteverifyRequest($fields));
            self::assertSame(200, $retry->getStatusCode(), 'the legacy record must replay, never conflict');
            self::assertSame(
                (string) json_encode($result, JSON_THROW_ON_ERROR),
                (string) $retry->getContent(),
                'the cached response is byte-equivalent to the stored canonical result',
            );
            self::assertSame($before, $probe->get($idemKey), 'the read-only replay performs zero mutation');

            // A changed remoteip is a different operation: conflict (400).
            $changedIp = $controller->siteverify($this->siteverifyRequest(['secret' => self::SITEVERIFY_SECRET, 'response' => $token, 'remoteip' => '203.0.113.9', 'idempotency_key' => $uuid]));
            self::assertSame(400, $changedIp->getStatusCode(), 'a changed remoteip still conflicts');

            // A changed response (a different token string) conflicts even
            // before any verification.
            $changedResponse = $controller->siteverify($this->siteverifyRequest(['secret' => self::SITEVERIFY_SECRET, 'response' => 'someone-elses-token', 'remoteip' => '127.0.0.1', 'idempotency_key' => $uuid]));
            self::assertSame(400, $changedResponse->getStatusCode(), 'a changed response hash still conflicts');

            self::assertSame($before, $probe->get($idemKey), 'every conflict performed zero mutation');
        } finally {
            $probe->del([$idemKey, 'kiwicaptcha:'.$nonce]);
        }
    }

    public function testALegacyRecordMissingAnIdentityComponentStillConflicts(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $storage = new RedisStorage($probe);
        [$token, $nonce] = $this->issueSha($storage);
        $uuid = '8e2f7a40-2222-4000-8000-0000000000a2';
        $backendId = hash_hmac('sha256', 'login|0|', self::SITEVERIFY_SECRET);
        $idemKey = '{kiwi:kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid;
        $probe->del([$idemKey]);
        $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha');

        // An even older writer that carried no fingerprint at all: the
        // operation identity is underspecified, so the retry conflicts.
        $legacy = (string) json_encode([
            'response_hash' => hash('sha256', $token),
            'state' => 'complete',
            'owner' => null,
            'result' => ['success' => true, 'challenge_ts' => null, 'hostname' => null],
            'lease_expires_at' => null,
        ], JSON_THROW_ON_ERROR);
        $probe->set($idemKey, $legacy, 'EX', 300);
        $before = $probe->get($idemKey);

        try {
            $controller = $this->controller($storage, $store);
            $response = $controller->siteverify($this->siteverifyRequest([
                'secret' => self::SITEVERIFY_SECRET,
                'response' => $token,
                'remoteip' => '127.0.0.1',
                'idempotency_key' => $uuid,
            ]));
            self::assertSame(400, $response->getStatusCode(), 'an identity-less legacy record conflicts');
            self::assertSame($before, $probe->get($idemKey), 'the conflict performed zero mutation');
        } finally {
            $probe->del([$idemKey, 'kiwicaptcha:'.$nonce]);
        }
    }

    public function testACrashedLegacyPendingRecordIsTakenOverAndMigratedWithoutWaitingForExpiry(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $storage = new RedisStorage($probe);
        [$token, $nonce] = $this->issueSha($storage);
        $uuid = '8e2f7a40-4444-4000-8000-0000000000a4';
        $backendId = hash_hmac('sha256', 'login|0|', self::SITEVERIFY_SECRET);
        $idemKey = '{kiwi:kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid;
        $probe->del([$idemKey]);
        $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha');

        // The exact preceding-release pending bytes: no `v` member, the
        // full operation identity, an owner whose lease expired long ago,
        // and a healthy remaining key lifetime. The predecessor worker
        // crashed.
        $legacy = (string) json_encode([
            'response_hash' => hash('sha256', $token),
            'remoteip_fingerprint' => hash_hmac('sha256', 'siteverify-idem-ip-v1|127.0.0.1', self::SECRET),
            'binding' => '',
            'state' => 'pending',
            'owner' => str_repeat('b', 32),
            'result' => null,
            'lease_expires_at' => time() - 60,
        ], JSON_THROW_ON_ERROR);
        $probe->set($idemKey, $legacy, 'EX', 300);

        try {
            $controller = $this->controller($storage, $store);
            $response = $controller->siteverify($this->siteverifyRequest([
                'secret' => self::SITEVERIFY_SECRET,
                'response' => $token,
                'remoteip' => '127.0.0.1',
                'idempotency_key' => $uuid,
            ]));
            self::assertSame(200, $response->getStatusCode(), 'HEAD takes over the crashed legacy claim without waiting for key expiry');
            $body = json_decode((string) $response->getContent(), true, 8, JSON_THROW_ON_ERROR);
            self::assertTrue($body['success'] ?? null);

            // The migrated record is the canonical v2 completion.
            $record = json_decode((string) $probe->get($idemKey), true, 8, JSON_THROW_ON_ERROR);
            self::assertSame(2, $record['v'] ?? null, 'the takeover upgraded the record to canonical v2');
            self::assertSame('complete', $record['state'] ?? null);
        } finally {
            $probe->del([$idemKey, 'kiwicaptcha:'.$nonce]);
        }
    }

    public function testAnUnderspecifiedLegacyPendingRecordIsNeverMigrated(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $storage = new RedisStorage($probe);
        [$token, $nonce] = $this->issueSha($storage);
        $uuid = '8e2f7a40-5555-4000-8000-0000000000a5';
        $backendId = hash_hmac('sha256', 'login|0|', self::SITEVERIFY_SECRET);
        $idemKey = '{kiwi:kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid;
        $probe->del([$idemKey]);
        $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha');

        // An even older writer with no fingerprint at all: the operation
        // identity is underspecified, so the record is never mutated even
        // with an expired lease.
        $legacy = (string) json_encode([
            'response_hash' => hash('sha256', $token),
            'state' => 'pending',
            'owner' => str_repeat('c', 32),
            'result' => null,
            'lease_expires_at' => time() - 60,
        ], JSON_THROW_ON_ERROR);
        $probe->set($idemKey, $legacy, 'EX', 300);
        $before = $probe->get($idemKey);

        try {
            // The store-level takeover refuses.
            [$takeover] = $store->takeover($backendId, $uuid, hash('sha256', $token), 300, hash_hmac('sha256', 'siteverify-idem-ip-v1|127.0.0.1', self::SECRET), null, '');
            self::assertSame(IdempotencyClaim::StillPending, $takeover, 'an underspecified legacy pending record is never taken over');
            self::assertSame($before, $probe->get($idemKey), 'and never mutated');
        } finally {
            $probe->del([$idemKey, 'kiwicaptcha:'.$nonce]);
        }
    }

    public function testALegacyIdentityCompletePendingRecordIsNonAuthoritativePending(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $storage = new RedisStorage($probe);
        [$token, $nonce] = $this->issueSha($storage);
        $uuid = '8e2f7a40-3333-4000-8000-0000000000a3';
        $backendId = hash_hmac('sha256', 'login|0|', self::SITEVERIFY_SECRET);
        $idemKey = '{kiwi:kiwicaptcha}:siteverify-idem:'.$backendId.':'.$uuid;
        $probe->del([$idemKey]);
        $store = new RedisSiteVerifyIdempotencyStore($probe, 'kiwicaptcha');

        // The preceding release is still working this operation: pending,
        // with its owner/lease, and the full identity.
        $legacy = (string) json_encode([
            'response_hash' => hash('sha256', $token),
            'remoteip_fingerprint' => hash_hmac('sha256', 'siteverify-idem-ip-v1|127.0.0.1', self::SECRET),
            'binding' => '',
            'state' => 'pending',
            'owner' => str_repeat('a', 32),
            'result' => null,
            'lease_expires_at' => time() + 120,
        ], JSON_THROW_ON_ERROR);
        $probe->set($idemKey, $legacy, 'EX', 300);
        $before = $probe->get($idemKey);

        try {
            $controller = $this->controller($storage, $store, 0.05);
            $response = $controller->siteverify($this->siteverifyRequest([
                'secret' => self::SITEVERIFY_SECRET,
                'response' => $token,
                'remoteip' => '127.0.0.1',
                'idempotency_key' => $uuid,
            ]));
            self::assertNotSame(400, $response->getStatusCode(), 'an identity-complete legacy pending record is not a conflicting request');
            self::assertSame(503, $response->getStatusCode(), 'the waiter answers the retryable provider error while the incumbent owner holds the entry');
            self::assertSame($before, $probe->get($idemKey), 'the waiter never mutates or takes over a legacy record');
        } finally {
            $probe->del([$idemKey, 'kiwicaptcha:'.$nonce]);
        }
    }
}
