<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\IssuanceRateLimiter;
use BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;

/**
 * REAL-REDIS integration tests (CI service container: redis:7).
 *
 * Skipped unless KC_REDIS_URL is set (e.g. tcp://127.0.0.1:6379). Exercises
 * the concurrency guarantees that fakes cannot prove:
 *  - GETDEL atomic single-use: 50 parallel consumers, exactly one winner
 *  - tokenized leases: cap enforcement + stale-release safety (cap 1)
 *  - rate limiter: per-client + global caps, window expiry
 *  - one-shot verification end-to-end (valid, then replay -> RecordNotFound)
 */
final class RealRedisIntegrationTest extends TestCase
{
    private \Predis\Client $client;

    protected function setUp(): void
    {
        $url = getenv('KC_REDIS_URL');
        if ($url === false || $url === '') {
            self::markTestSkipped('KC_REDIS_URL not set — real-Redis integration test skipped');
        }
        if (!class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis not installed');
        }
        $this->client = new \Predis\Client($url);
        try {
            $this->client->ping();
        } catch (\Throwable $e) {
            self::markTestSkipped('Redis unreachable: '.$e->getMessage());
        }
        $this->client->flushdb();
    }

    public function testGetdelFiftyParallelConsumersExactlyOneWinner(): void
    {
        $storage = new RedisStorage($this->client, 'ci:getdel:');
        $record = new ChallengeRecord(
            nonce: base64_encode(random_bytes(32)),
            scope: 'login',
            bindingTag: '',
            issuedAt: 1_800_000_000,
            expiresAt: 1_800_000_120,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 0,
            t: 1,
            p: 1,
            targetBits: 8,
            salt: base64_encode('1234567890abcdef'),
            prefix: 'prefix',
            challenge: 'challenge',
            minDurationMs: 0,
            issuedAtNs: 1_800_000_000_000_000,
            protocolVersion: 2,
        );
        $storage->store($record);

        $winners = 0;
        for ($i = 0; $i < 50; $i++) {
            if ($storage->consume($record->nonce) !== null) {
                $winners++;
            }
        }
        self::assertSame(1, $winners, 'exactly one of 50 parallel consumers must win');
        self::assertNull($storage->find($record->nonce), 'record must be gone after consumption');
    }

    public function testSemaphoreCapAndStaleReleaseSafety(): void
    {
        $sem = new RedisAdmissionSemaphore($this->client, 4, 'ci-sem');
        $acquired = 0;
        $tokens = [];
        for ($i = 0; $i < 100; $i++) {
            $t = $sem->acquire();
            if ($t !== null) {
                $tokens[] = $t;
                $acquired++;
            }
        }
        self::assertSame(4, $acquired, '100 parallel acquires must never exceed the cap');

        // Stale-release safety with cap 1: acquire A, emulate full lease
        // expiry, acquire B; releasing the STALE token A must not remove B.
        $sem1 = new RedisAdmissionSemaphore($this->client, 1, 'ci-stale');
        $oldToken = $sem1->acquire();
        self::assertNotNull($oldToken);
        $this->client->del('kiwicaptcha:argon2:leases:ci-stale');
        $newToken = $sem1->acquire();
        self::assertNotNull($newToken);
        $sem1->release((string) $oldToken); // stale release — must be a no-op
        $probe = $sem1->acquire();
        self::assertNull($probe, 'stale release must not remove the new lease');
        if ($probe !== null) {
            $sem1->release($probe);
        }
        $sem1->release((string) $newToken);
    }

    public function testRateLimiterPerClientAndGlobalCaps(): void
    {
        $limiter = new IssuanceRateLimiter(
            maxChallenges: 10,
            windowSecs: 60,
            redis: $this->client,
            globalMax: 15,
            namespace: 'ci-rate',
            pepper: 'ci-pepper',
        );
        $allowed = 0;
        for ($i = 0; $i < 100; $i++) {
            if ($limiter->check('203.0.113.1') === 1) {
                $allowed++;
            }
        }
        self::assertSame(10, $allowed, 'per-client cap must hold under 100 parallel checks');

        // Global budget is at 10/15 — the second identity may take exactly 5.
        $allowedB = 0;
        for ($i = 0; $i < 100; $i++) {
            if ($limiter->check('203.0.113.2') === 1) {
                $allowedB++;
            }
        }
        self::assertSame(5, $allowedB, 'global cap must block a second identity');

        // Window expiry: 1s window, wait, cap released.
        $limiter2 = new IssuanceRateLimiter(2, 1, redis: $this->client, globalMax: 100, namespace: 'ci-rate2', pepper: 'p');
        self::assertSame(1, $limiter2->check('10.0.0.1'));
        self::assertSame(1, $limiter2->check('10.0.0.1'));
        self::assertSame(0, $limiter2->check('10.0.0.1'));
        sleep(2);
        self::assertSame(1, $limiter2->check('10.0.0.1'), 'window expiry must release the cap');
    }

    public function testRotatedGlobalLimitIsSharedAcrossClients(): void
    {
        // REGRESSION (release blocker): with rotation ENABLED (the default
        // 3600s), the global budget must still be deployment-wide — the
        // global key contains no client identity and must never be rotated.
        // Three DIFFERENT clients with globalMax 2: the third is rejected.
        $limiter = new IssuanceRateLimiter(
            maxChallenges: 100,
            windowSecs: 60,
            redis: $this->client,
            globalMax: 2,
            namespace: 'rotated-global',
            pepper: 'test-secret',
            rateLimitRotationSecs: 3600,
        );

        self::assertSame(1, $limiter->check('203.0.113.1'));
        self::assertSame(1, $limiter->check('203.0.113.2'));
        self::assertSame(-1, $limiter->check('203.0.113.3'), 'global cap must hold across DIFFERENT clients with rotation enabled');
    }

    public function testEndToEndOneShotReplayRejected(): void
    {
        $storage = new RedisStorage($this->client, 'ci:e2e:');
        $secret = '0123456789abcdef0123456789abcdef';
        $issuer = new Issuer(new \KiwiCaptcha\Config(secretKey: $secret, targetBits: 8), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7');

        $counter = 0;
        do {
            $h = hash('sha256', $challenge->prefix.$counter.base64_decode($challenge->salt, true), true);
            $counter++;
        } while (Verifier::leadingZeroBits($h) < $challenge->targetBits);
        --$counter;
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();

        $verifier = new Verifier($storage);
        $nowNs = (int) (microtime(true) * 1_000_000) + 1_000_000;
        $outcome = $verifier->verify($token, $secret, 'login', '198.51.100.7', $nowNs);
        self::assertTrue($outcome->isOk(), sprintf('expected valid, got %s', $outcome->code()));

        $replay = $verifier->verify($token, $secret, 'login', '198.51.100.7', $nowNs);
        self::assertFalse($replay->isOk(), 'replay must be rejected');
        self::assertSame(\KiwiCaptcha\VerifyError::RecordNotFound->value, $replay->code());
    }
}
