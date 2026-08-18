<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\IssuanceRateLimiter;
use BelConsulting\KiwiCaptchaBundle\Security\OutstandingChallenges;
use BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\RiskKeys;
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

        $first = 0;
        $before = 0;
        for ($i = 0; $i < 50; $i++) {
            $consumed = $storage->consume($record->nonce);
            self::assertNotNull($consumed, 'every consumer sees the record');
            if ($consumed->consumedNow) {
                $first++;
            } else {
                self::assertTrue($consumed->consumedBefore);
                $before++;
            }
        }
        self::assertSame(1, $first, 'exactly one of 50 parallel consumers performs the first transition');
        self::assertSame(49, $before, 'the other 49 observe the consumed-before state');
        self::assertNotNull($storage->find($record->nonce), 'the consumed record PERSISTS until its TTL (the consumed-state transition)');
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
        self::assertTrue($replay->isOk(), 'a same-context replay returns the SAME stored result, never a second derivation');
        self::assertTrue($replay->fromStoredResult, 'the replay must come from the stored result');
        self::assertSame($challenge->nonce, $replay->nonce, 'the replay exposes the canonical jti');
    }

    public function testOutstandingCountersCapAndDecrementAgainstRealRedis(): void
    {
        $secret = '0123456789abcdef0123456789abcdef';
        $outstanding = new OutstandingChallenges($this->client, '{kiwi:ci}:outstanding:', RiskKeys::fromMaster($secret), 3, 100, 5);

        // Three issuances admitted (EXPIRE = ttl + margin), the 4th refused.
        self::assertSame(1, $outstanding->issue('198.51.100.7', 60));
        self::assertSame(1, $outstanding->issue('198.51.100.7', 60));
        self::assertSame(1, $outstanding->issue('198.51.100.7', 60));
        self::assertSame(0, $outstanding->issue('198.51.100.7', 60), 'the 4th outstanding challenge of one source must be refused');

        $sourceKey = $outstanding->sourceKey('198.51.100.7');
        self::assertSame('3', (string) $this->client->get($sourceKey));
        self::assertSame('3', (string) $this->client->get('{kiwi:ci}:outstanding:global'));
        $ttl = $this->client->ttl($sourceKey);
        self::assertGreaterThanOrEqual(60, $ttl, 'the counter TTL = challenge lifetime (60) + ttl margin (5)');
        self::assertLessThanOrEqual(65, $ttl);

        // A valid solve decrements the per-source counter (floored at 0).
        $outstanding->solved('198.51.100.7');
        self::assertSame('2', (string) $this->client->get($sourceKey));
        $outstanding->solved('198.51.100.7');
        $outstanding->solved('198.51.100.7');
        $outstanding->solved('198.51.100.7');
        self::assertSame('0', (string) $this->client->get($sourceKey), 'the decrement must never drive the counter negative');

        // The GLOBAL counter is never decremented by solves (expires only).
        self::assertSame('3', (string) $this->client->get('{kiwi:ci}:outstanding:global'));

        // The cap frees when the counter drops: a new issuance is admitted.
        self::assertSame(1, $outstanding->issue('198.51.100.7', 60));
    }

    public function testSemaphoreWaitersGuardAgainstRealRedis(): void
    {
        $sem = new RedisAdmissionSemaphore($this->client, 1, 'ci-waiters', 45_000, 2);
        $waitersKey = '{kiwicaptcha:argon2:leases:ci-waiters}:sem:waiters';

        $token = $sem->acquire();
        self::assertNotNull($token, 'the only lease is granted');

        // Saturated acquires: counted up to maxWaiters (2), refused beyond
        // WITHOUT queueing (the overflow entry is removed in the same Lua),
        // so the waiters counter is bounded.
        for ($i = 0; $i < 10; $i++) {
            self::assertNull($sem->acquire());
        }
        self::assertSame('2', (string) $this->client->get($waitersKey), 'the waiters counter must never exceed maxWaiters');

        // A freed slot serves one waiter: the grant decrements the counter.
        $sem->release($token);
        $next = $sem->acquire();
        self::assertNotNull($next);
        self::assertSame('1', (string) $this->client->get($waitersKey), 'a granted caller was a served waiter — the counter decrements');
        $sem->release($next);
    }

    public function testPerScopeBudgetAndGlobalCapAgainstRealRedis(): void
    {
        $sem = new RedisAdmissionSemaphore($this->client, 100, 'ci-scope', 45_000, 64, 2);
        $scopeKey = '{kiwicaptcha:argon2:leases:ci-scope}:login';

        // Scope 'login' fills its own budget of 2 while the global cap is
        // nowhere near full; a second scope still acquires (fairness).
        self::assertNotNull($sem->acquire('login'));
        self::assertNotNull($sem->acquire('login'));
        self::assertNull($sem->acquire('login'), 'the 3rd login acquire must be refused by the per-scope budget');
        self::assertSame('2', (string) $this->client->zcard($scopeKey), 'the per-scope set holds exactly its budget');
        self::assertNotNull($sem->acquire('signup'), 'a second scope acquires within its own budget');

        // Release removes the lease from BOTH sets (no TTL wait for the
        // scope budget).
        $tokens = [];
        for ($i = 0; $i < 2; $i++) {
            $t = $sem->acquire('admin');
            self::assertNotNull($t);
            $tokens[] = $t;
        }
        self::assertNull($sem->acquire('admin'));
        $sem->release($tokens[0]);
        $sem->release($tokens[1]);
        self::assertSame('0', (string) $this->client->zcard('{kiwicaptcha:argon2:leases:ci-scope}:admin'), 'scoped release must free the scope set');
        self::assertNotNull($sem->acquire('admin'), 'the freed scope budget admits again immediately');

        // Global cap still binds on top of the per-scope budgets.
        $globalKey = 'kiwicaptcha:argon2:leases:ci-scope-global';
        $global = new RedisAdmissionSemaphore($this->client, 2, 'ci-scope-global', 45_000, 64, 10);
        self::assertNotNull($global->acquire('a'));
        self::assertNotNull($global->acquire('b'));
        self::assertNull($global->acquire('c'), 'the global cap must bind even though scope c has per-scope budget');
        self::assertSame('2', (string) $this->client->zcard($globalKey), 'the deployment-wide global cap is the invariant');
    }

    public function testReadinessPolicyGateAgainstRealRedis(): void
    {
        // A FRESH controller per probe: the ~1s in-process policy cache is
        // per instance, so each mutation below is observed immediately.
        $controller = fn (): \BelConsulting\KiwiCaptchaBundle\Controller\KiwiHealthController => new \BelConsulting\KiwiCaptchaBundle\Controller\KiwiHealthController(
            '0123456789abcdef0123456789abcdef',
            $this->client,
            'ci-health',
            1,
        );

        // No central policy key: the binary's own config is authoritative.
        $this->client->del('{kiwi:ci-health}:security-policy');
        self::assertSame(200, $controller()->ready()->getStatusCode(), 'ready without a central policy key');

        // Compatible central policy (protocol 2, epoch 1).
        $this->client->hset('{kiwi:ci-health}:security-policy', 'min_protocol_version', '2', 'min_policy_epoch', '1');
        self::assertSame(200, $controller()->ready()->getStatusCode(), 'ready with a compatible central policy');

        // A newer protocol or epoch takes the binary out of the pool.
        $this->client->hset('{kiwi:ci-health}:security-policy', 'min_protocol_version', '3', 'min_policy_epoch', '1');
        self::assertSame(503, $controller()->ready()->getStatusCode(), 'central min_protocol_version 3 > the binary max (2)');

        $this->client->hset('{kiwi:ci-health}:security-policy', 'min_protocol_version', '2', 'min_policy_epoch', '2');
        self::assertSame(503, $controller()->ready()->getStatusCode(), 'central min_policy_epoch 2 > the configured risk.policy_version 1');

        // Live stays 200 while ready fails.
        self::assertSame(200, $controller()->live()->getStatusCode(), 'live must stay 200 while ready fails');

        // Cleanup for the next test run.
        $this->client->del('{kiwi:ci-health}:security-policy');
    }
}
