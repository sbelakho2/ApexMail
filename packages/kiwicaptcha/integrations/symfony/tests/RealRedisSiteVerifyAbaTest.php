<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\IdempotencyClaim;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisSiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\StoredLookup;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\StoredLookupKind;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;

/**
 * The claim -> stored ABA, deterministically. A same-key read must be
 * bound to the operation that produced the earlier CompleteSame or
 * PendingSame. When the key expires and a different operation reuses it
 * (same backend, same UUID, different response/remoteip/binding), the
 * earlier request must never receive the new operation's result. These
 * tests simulate the reuse explicitly (delete or replace the key)
 * rather than depending on timing. They cover the CompleteSame path,
 * the PendingSame polling loop and the ownership-loss recovery path.
 */
final class RealRedisSiteVerifyAbaTest extends TestCase
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

    private function request(array $fields): \Symfony\Component\HttpFoundation\Request
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

    /**
     * An idempotency-store decorator. The claim answers a scripted
     * pre-existing state, so the controller takes the CompleteSame,
     * PendingSame or Claimed path under test. Meanwhile the first
     * operation-bound read performs the ABA: it deletes the key and
     * claims plus finalizes a different operation under the same UUID,
     * then delegates. Every later call delegates untouched.
     */
    private function abaDecorator(
        SiteVerifyIdempotencyStore $inner,
        IdempotencyClaim $claimAnswer,
        callable $performAba,
        bool $renewSucceeds = true,
    ): SiteVerifyIdempotencyStore {
        return new class($inner, $claimAnswer, $performAba, $renewSucceeds) implements SiteVerifyIdempotencyStore {
            private bool $abaPerformed = false;

            public function __construct(
                private readonly SiteVerifyIdempotencyStore $inner,
                private readonly IdempotencyClaim $claimAnswer,
                private readonly \Closure $performAba,
                private readonly bool $renewSucceeds,
            ) {
            }

            public function leaseSeconds(): int
            {
                return $this->inner->leaseSeconds();
            }

            public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
            {
                if ($this->claimAnswer === IdempotencyClaim::Claimed) {
                    return $this->inner->claim($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds, $binding);
                }

                return [$this->claimAnswer, null];
            }

            public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
            {
                return $this->inner->takeover($backendId, $idempotencyKey, $responseHash, $ttlSeconds, $remoteipFingerprint, $leaseSeconds, $binding);
            }

            public function renew(string $backendId, string $idempotencyKey, string $owner): bool
            {
                return $this->renewSucceeds && $this->inner->renew($backendId, $idempotencyKey, $owner);
            }

            public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): bool
            {
                return $this->inner->finalize($backendId, $idempotencyKey, $responseHash, $owner, $canonicalResponse);
            }

            public function storedForOperation(string $backendId, string $idempotencyKey, string $responseHash, string $remoteipFingerprint, ?string $binding = null): StoredLookup
            {
                if (!$this->abaPerformed) {
                    $this->abaPerformed = true;
                    ($this->performAba)();
                }

                return $this->inner->storedForOperation($backendId, $idempotencyKey, $responseHash, $remoteipFingerprint, $binding);
            }
        };
    }

    private function issueShaToken(ArrayStorage $storage, string $scope = 'login', string $ip = '127.0.0.1'): string
    {
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        $challenge = $issuer->issue($scope, $ip);
        $salt = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$salt, true);
            ++$counter;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;
        usleep(($challenge->minDurationMs + 10) * 1000);

        return SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
    }

    /** @return array<string, mixed> */
    private function success(): array
    {
        return ['success' => true, 'challenge_ts' => null, 'hostname' => null];
    }

    public function testACompletedOperationIsNeverReplacedByAReusedKeysResult(): void
    {
        $probe = $this->redisOrSkip();
        if ($probe === null) {
            return;
        }
        $namespace = 'aba-'.bin2hex(random_bytes(4));
        $backendId = hash_hmac('sha256', 'login|0|', 'aba');
        $uuid = 'abababab-1111-4000-8000-000000000a01';
        $key = '{kiwi:'.$namespace.'}:siteverify-idem:'.$backendId.':'.$uuid;
        $probe->del([$key]);

        // Redis: the ABA is a key deletion plus a reuse.
        $redis = new RedisSiteVerifyIdempotencyStore($probe, $namespace);
        [$claimA, $ownerA] = $redis->claim($backendId, $uuid, str_repeat('a', 64), 300, 'no-ip', null, '');
        self::assertSame(IdempotencyClaim::Claimed, $claimA);
        self::assertTrue($redis->finalize($backendId, $uuid, str_repeat('a', 64), (string) $ownerA, $this->success()));
        $readA = $redis->storedForOperation($backendId, $uuid, str_repeat('a', 64), 'no-ip', '');
        self::assertSame(StoredLookupKind::CompleteSame, $readA->kind, 'redis: A reads its own completion');
        self::assertSame($this->success(), $readA->result);

        $probe->del([$key]);
        [$claimB, $ownerB] = $redis->claim($backendId, $uuid, str_repeat('b', 64), 300, 'no-ip', null, '');
        self::assertSame(IdempotencyClaim::Claimed, $claimB, 'redis: B reuses the key');
        self::assertTrue($redis->finalize($backendId, $uuid, str_repeat('b', 64), (string) $ownerB, $this->success()));
        $resumedA = $redis->storedForOperation($backendId, $uuid, str_repeat('a', 64), 'no-ip', '');
        self::assertSame(StoredLookupKind::Changed, $resumedA->kind, 'redis: A must never read B\'s operation');
        self::assertNull($resumedA->result, 'redis: no result crosses the operations');
        $readB = $redis->storedForOperation($backendId, $uuid, str_repeat('b', 64), 'no-ip', '');
        self::assertSame(StoredLookupKind::CompleteSame, $readB->kind, 'redis');
        self::assertSame($this->success(), $readB->result, 'redis');
        $probe->del([$key]);

        // Array: the ABA is the key lifetime lapsing plus a reuse.
        $now = 1_700_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        $array = new ArraySiteVerifyIdempotencyStore($clock);
        [$claimA, $ownerA] = $array->claim($backendId, $uuid, str_repeat('a', 64), 10, 'no-ip', null, '');
        self::assertSame(IdempotencyClaim::Claimed, $claimA);
        self::assertTrue($array->finalize($backendId, $uuid, str_repeat('a', 64), (string) $ownerA, $this->success()));
        $readA = $array->storedForOperation($backendId, $uuid, str_repeat('a', 64), 'no-ip', '');
        self::assertSame(StoredLookupKind::CompleteSame, $readA->kind, 'array: A reads its own completion');
        self::assertSame($this->success(), $readA->result);

        $now += 301; // A's key lifetime lapses (finalize keeps the 300s retention)
        [$claimB, $ownerB] = $array->claim($backendId, $uuid, str_repeat('b', 64), 10, 'no-ip', null, '');
        self::assertSame(IdempotencyClaim::Claimed, $claimB, 'array: B reuses the key');
        self::assertTrue($array->finalize($backendId, $uuid, str_repeat('b', 64), (string) $ownerB, $this->success()));
        $resumedA = $array->storedForOperation($backendId, $uuid, str_repeat('a', 64), 'no-ip', '');
        self::assertSame(StoredLookupKind::Changed, $resumedA->kind, 'array: A must never read B\'s operation');
        self::assertNull($resumedA->result, 'array: no result crosses the operations');
        $readB = $array->storedForOperation($backendId, $uuid, str_repeat('b', 64), 'no-ip', '');
        self::assertSame(StoredLookupKind::CompleteSame, $readB->kind, 'array');
        self::assertSame($this->success(), $readB->result, 'array');
    }

    public function testTheControllerNeverServesAnotherOperationsResultOnACompleteSameAba(): void
    {
        $storage = new ArrayStorage();
        $inner = new ArraySiteVerifyIdempotencyStore();
        $backendId = hash_hmac('sha256', 'login|0|', self::SITEVERIFY_SECRET);
        $uuid = 'abababab-2222-4000-8000-000000000a02';
        $aba = function () use ($inner, $backendId, $uuid): void {
            // The key expired and a different operation reused it.
            [$claimB, $ownerB] = $inner->claim($backendId, $uuid, hash('sha256', 'token-B'), 300, 'no-ip', null, '');
            self::assertSame(IdempotencyClaim::Claimed, $claimB);
            self::assertTrue($inner->finalize($backendId, $uuid, hash('sha256', 'token-B'), (string) $ownerB, ['success' => true, 'challenge_ts' => null, 'hostname' => null]));
        };
        $store = $this->abaDecorator($inner, IdempotencyClaim::CompleteSame, $aba);
        $controller = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 0.5);
        $tokenA = $this->issueShaToken($storage);

        $response = $controller->siteverify($this->request([
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $tokenA,
            'remoteip' => '127.0.0.1',
            'idempotency_key' => $uuid,
        ]));
        self::assertSame(503, $response->getStatusCode(), 'a reused key must answer the retryable provider error');
        $body = json_decode((string) $response->getContent(), true, 8, JSON_THROW_ON_ERROR);
        self::assertNotTrue($body['success'] ?? null, 'B\'s success must never cross to A');
        self::assertSame(['internal-error'], $body['error-codes'] ?? null);
    }

    public function testThePendingSameWaiterNeverServesAnotherOperationsResult(): void
    {
        $storage = new ArrayStorage();
        $inner = new ArraySiteVerifyIdempotencyStore();
        $backendId = hash_hmac('sha256', 'login|0|', self::SITEVERIFY_SECRET);
        $uuid = 'abababab-3333-4000-8000-000000000a03';
        $aba = function () use ($inner, $backendId, $uuid): void {
            [$claimB, $ownerB] = $inner->claim($backendId, $uuid, hash('sha256', 'token-B'), 300, 'no-ip', null, '');
            self::assertSame(IdempotencyClaim::Claimed, $claimB);
            self::assertTrue($inner->finalize($backendId, $uuid, hash('sha256', 'token-B'), (string) $ownerB, ['success' => true, 'challenge_ts' => null, 'hostname' => null]));
        };
        $store = $this->abaDecorator($inner, IdempotencyClaim::PendingSame, $aba);
        $controller = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 5.0);
        $tokenA = $this->issueShaToken($storage);

        $start = microtime(true);
        $response = $controller->siteverify($this->request([
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $tokenA,
            'remoteip' => '127.0.0.1',
            'idempotency_key' => $uuid,
        ]));
        $elapsed = microtime(true) - $start;
        self::assertSame(503, $response->getStatusCode(), 'the operation-bound waiter refuses the reused key');
        $body = json_decode((string) $response->getContent(), true, 8, JSON_THROW_ON_ERROR);
        self::assertNotTrue($body['success'] ?? null, 'B\'s success must never satisfy the pending waiter for A');
        self::assertLessThan(3.0, $elapsed, 'the Changed verdict must be immediate, not a wait-loop timeout');
    }

    public function testTheOwnershipLossRecoveryNeverServesAnotherOperationsResult(): void
    {
        $storage = new ArrayStorage();
        $inner = new ArraySiteVerifyIdempotencyStore();
        $backendId = hash_hmac('sha256', 'login|0|', self::SITEVERIFY_SECRET);
        $uuid = 'abababab-4444-4000-8000-000000000a04';
        $aba = function () use ($inner, $backendId, $uuid): void {
            [$claimB, $ownerB] = $inner->claim($backendId, $uuid, hash('sha256', 'token-B'), 300, 'no-ip', null, '');
            self::assertSame(IdempotencyClaim::Claimed, $claimB);
            self::assertTrue($inner->finalize($backendId, $uuid, hash('sha256', 'token-B'), (string) $ownerB, ['success' => true, 'challenge_ts' => null, 'hostname' => null]));
        };
        // The owner loses its lease while verifying, and the key was
        // reused before the recovery read: the local result is not
        // authoritative and the reused key is not this operation's.
        $store = $this->abaDecorator($inner, IdempotencyClaim::Claimed, $aba, renewSucceeds: false);
        $controller = new SiteVerifyController(new Verifier($storage), self::SECRET, [self::SITEVERIFY_SECRET => 'login'], $storage, null, null, $store, null, 0.5);

        $token = $this->issueShaToken($storage);

        $response = $controller->siteverify($this->request([
            'secret' => self::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '127.0.0.1',
            'idempotency_key' => $uuid,
        ]));
        self::assertSame(503, $response->getStatusCode(), 'a lost owner reading a reused key answers the retryable error');
        $body = json_decode((string) $response->getContent(), true, 8, JSON_THROW_ON_ERROR);
        self::assertNotTrue($body['success'] ?? null, 'the reused key\'s success must never become the displaced owner\'s answer');
    }
}
