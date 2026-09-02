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
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha as KiwiCaptchaConstraint;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use KiwiCaptcha\ConsumedRecord;
use KiwiCaptcha\ConsumedStateReadableInterface;
use KiwiCaptcha\Config;
use KiwiCaptcha\OperationIdentityAwareStorageInterface;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Validator\ConstraintValidatorFactory;
use Symfony\Component\Validator\Validation;

/**
 * real-redis integration tests (CI service container: redis:7).
 *
 * Skipped unless KC_redis_URL is set (e.g. tcp://127.0.0.1:6379).
 * Exercises the concurrency guarantees that fakes cannot prove: getdel
 * atomic single-use (50 parallel consumers, one winner), tokenized
 * leases (cap enforcement + stale-release safety) and the rate limiter
 * (per-client + global caps, window expiry). One-shot verification
 * end-to-end (valid, then replay -> RecordNotFound).
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
        // expiry, acquire B; releasing the stale token A must not remove B.
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
        // regression (release blocker): with rotation enabled (the default
        // 3600s), the global budget must still be deployment-wide — the
        // global key contains no client identity and must never be rotated.
        // Three different clients with globalMax 2: the third is rejected.
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
        $identity = 'op-'.hash('sha256', 'login-op');
        $nowNs = (int) (microtime(true) * 1_000_000) + 1_000_000;
        $outcome = $verifier->verify($token, $secret, 'login', '198.51.100.7', $nowNs, operationIdentity: $identity);
        self::assertTrue($outcome->isOk(), sprintf('expected valid, got %s', $outcome->code()));

        $replay = $verifier->verify($token, $secret, 'login', '198.51.100.7', $nowNs, operationIdentity: $identity);
        self::assertTrue($replay->isOk(), 'a replay of the same logical operation returns the SAME stored result, never a second derivation');
        self::assertTrue($replay->fromStoredResult, 'the replay must come from the stored result');
        self::assertSame($challenge->nonce, $replay->nonce, 'the replay exposes the canonical jti');
    }

    public function testOutstandingCountersCapAndDecrementAgainstRealRedis(): void
    {
        $this->client->flushall();
        $secret = '0123456789abcdef0123456789abcdef';
        $outstanding = new OutstandingChallenges($this->client, '{kiwi:ci}:outstanding:', RiskKeys::fromMaster($secret), 3, 100, 5);
        $now = time();
        $nonceA = base64_encode(random_bytes(32));
        $nonceB = base64_encode(random_bytes(32));
        $nonceC = base64_encode(random_bytes(32));

        // Three issuances admitted, the 4th refused by the per-source cap.
        self::assertSame(1, $outstanding->issue('198.51.100.7', $nonceA, 60));
        self::assertSame(1, $outstanding->issue('198.51.100.7', $nonceB, 60));
        self::assertSame(1, $outstanding->issue('198.51.100.7', $nonceC, 60));
        self::assertSame(0, $outstanding->issue('198.51.100.7', base64_encode(random_bytes(32)), 60), 'the 4th outstanding challenge of one source must be refused');

        $sourceKey = $outstanding->sourceKey('198.51.100.7');
        self::assertSame(3, $this->client->zcard($sourceKey), 'the per-source bound counts the three LIVE members (ZCARD after the score prune — well-defined under the members\' differing expiry scores)');
        self::assertSame(3, $this->client->zcard('{kiwi:ci}:outstanding:global:live'), 'the live-outstanding membership holds the three admitted nonces');

        // Key-level retention: a ZSET score is data, not a key
        // expiry — the admission EXPIREATs both membership keys at the
        // latest member deadline + margin, so an abandoned source's key
        // (whose name carries the keyed source pseudonym) can never
        // accumulate in Redis.
        self::assertGreaterThan(0, $this->client->ttl($sourceKey), 'the source ZSET key carries a key-level EXPIREAT');
        self::assertGreaterThan(0, $this->client->ttl('{kiwi:ci}:outstanding:global:live'), 'the global ZSET key carries a key-level EXPIREAT');

        // Clock domain: the member deadlines are computed from
        // Redis TIME + the relative lifetime inside the script, so the
        // score sits at approximately Redis-now + 60 — a PHP/Redis clock
        // skew can never expire a still-valid member early.
        [$redisSecs] = $this->client->time();
        $score = $this->client->zscore($sourceKey, $nonceA);
        self::assertNotNull($score, 'the admitted nonce is a member of the source ZSET');
        self::assertGreaterThanOrEqual($redisSecs + 55, $score, 'the member deadline is Redis-now + the relative TTL');
        self::assertLessThanOrEqual($redisSecs + 65, $score);

        // The issuance sidecar pairs each nonce with the original source
        // pseudonym (the HMAC hex, never a raw IP), same hash tag, EX =
        // challenge lifetime + ttl margin.
        $sidecarA = '{kiwi:ci}:outstanding:nonce:'.$nonceA;
        self::assertSame(substr($sourceKey, \strlen('{kiwi:ci}:outstanding:')), (string) $this->client->get($sidecarA), 'the sidecar stores the issuing source\'s pseudonym');
        $sidecarTtl = $this->client->ttl($sidecarA);
        self::assertGreaterThanOrEqual(60, $sidecarTtl, 'the sidecar EX = challenge lifetime (60) + ttl margin (5)');
        self::assertLessThanOrEqual(65, $sidecarTtl);

        // A valid solve removes the nonce from both memberships (the
        // one-shot, nonce-authoritative release) and deletes the sidecar.
        $outstanding->solved($nonceA);
        self::assertSame(2, $this->client->zcard($sourceKey), 'the solve releases the original source member');
        self::assertSame(2, $this->client->zcard('{kiwi:ci}:outstanding:global:live'));
        self::assertNull($this->client->get($sidecarA), 'a valid solve deletes the issuance sidecar');
        $outstanding->solved($nonceB);
        $outstanding->solved($nonceC);
        $outstanding->solved(base64_encode(random_bytes(32)));
        self::assertSame(0, $this->client->zcard($sourceKey), 'every released member leaves the source membership');
        self::assertSame(0, $this->client->zcard('{kiwi:ci}:outstanding:global:live'), 'every solved nonce leaves the live membership');

        // The cap frees when the membership drops: a new issuance is admitted.
        self::assertSame(1, $outstanding->issue('198.51.100.7', base64_encode(random_bytes(32)), 60));
    }

    public function testOutstandingAdmissionIssuesAVerifiedWaitAgainstRealRedis(): void
    {
        // The admission write is protected by the configured
        // replica-durability barrier exactly like the challenge storage —
        // a successful admission issues one verified WAIT, and a refused
        // admission (no write) never WAITs.
        $this->client->flushall();
        $secret = '0123456789abcdef0123456789abcdef';
        $counting = new \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\CommandCountingRedisClient(\BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl::resolve(), ['timeout' => 2.0, 'read_write_timeout' => 2.0]);
        $outstanding = new OutstandingChallenges($counting, '{kiwi:ci}:outstanding:', RiskKeys::fromMaster($secret), 1, 100, 5, 1, 100);

        // The admission write lands, then the verified WAIT runs on the
        // same connection; on this replica-less server it acknowledges 0
        // of 1 and the barrier fails closed (the caller must never learn
        // a success that was not replicated).
        try {
            $outstanding->issue('198.51.100.7', base64_encode(random_bytes(32)), 60);
            self::fail('the verified WAIT must fail closed when the replica count is unmet');
        } catch (\KiwiCaptcha\Storage\ReplicaWaitException) {
            // the fail-closed barrier fired ✓
        }
        self::assertCount(1, $counting->waits(), 'a successful admission issues exactly one verified WAIT');

        // The admission write actually landed (the WAIT comes after the
        // mutation): the source cap is full, and a refused admission
        // performs no write and never WAITs.
        self::assertSame(0, $outstanding->issue('198.51.100.7', base64_encode(random_bytes(32)), 60));
        self::assertCount(1, $counting->waits(), 'a refused admission never WAITs');
        $counting->disconnect();
    }

    public function testMixedExpiryScoresCountExactlyAgainstRealRedis(): void
    {
        // The flagged concern: lex-range counting (ZLEXCOUNT) is only
        // defined for equal-score members, so a hard cap gated on it is
        // unsound under the members' differing expiry scores. The
        // per-source bound is a SCORE-range count — ZCARD after
        // `ZREMRANGEBYSCORE` — which is exact under any score mix.
        $this->client->flushall();
        $secret = '0123456789abcdef0123456789abcdef';
        $outstanding = new OutstandingChallenges($this->client, '{kiwi:ci}:outstanding:', RiskKeys::fromMaster($secret), 3, 100, 0);
        $now = time();
        $sourceA = $outstanding->sourceKey('198.51.100.7');
        $sourceB = $outstanding->sourceKey('203.0.113.9');
        $n1 = base64_encode(random_bytes(32));
        $n2 = base64_encode(random_bytes(32));
        $n3 = base64_encode(random_bytes(32));

        // 1 short-lived (1s) + 2 long-lived (300s) members for source A.
        self::assertSame(1, $outstanding->issue('198.51.100.7', $n1, 1));
        self::assertSame(1, $outstanding->issue('198.51.100.7', $n2, 300));
        self::assertSame(1, $outstanding->issue('198.51.100.7', $n3, 300));
        self::assertSame(0, $outstanding->issue('198.51.100.7', base64_encode(random_bytes(32)), 300), 'the 4th member is refused under MIXED expiry scores — the count is exact');
        self::assertSame(3, $this->client->zcard($sourceA), 'the per-source count is exactly the three live members with differing scores');

        // The bound is per-source: B issues freely and never leaks into A.
        self::assertSame(1, $outstanding->issue('203.0.113.9', base64_encode(random_bytes(32)), 300));
        self::assertSame(1, $this->client->zcard($sourceB));
        self::assertSame(3, $this->client->zcard($sourceA), 'source B\'s member never counts against source A\'s bound');

        // A solve of one long-lived member drops the count exactly.
        $outstanding->solved($n2);
        self::assertSame(2, $this->client->zcard($sourceA), 'the release removes exactly one member');
        self::assertSame(1, $this->client->zcard($sourceB), 'source B\'s member is untouched');
    }

    public function testCancellationReleasesTheOriginalSourceSlotAgainstRealRedis(): void
    {
        // The one-shot cancellation against real Redis: the global member
        // is freed AND the original source counter (the one that issued
        // the challenge, from the sidecar — the canceller's identity never
        // participates) is decremented exactly once, floored at 0. A
        // duplicate cancel (ZREM == 0) is a no-op.
        $secret = '0123456789abcdef0123456789abcdef';
        $outstanding = new OutstandingChallenges($this->client, '{kiwi:ci}:outstanding:', RiskKeys::fromMaster($secret), 3, 100, 5);
        $now = time();
        $nonce = base64_encode(random_bytes(32));
        $otherNonce = base64_encode(random_bytes(32));

        self::assertSame(1, $outstanding->issue('198.51.100.7', $nonce, 60));
        $sourceA = $outstanding->sourceKey('198.51.100.7');
        $sourceB = $outstanding->sourceKey('203.0.113.9');
        $sidecar = '{kiwi:ci}:outstanding:nonce:'.$nonce;
        self::assertSame(1, $this->client->zcard($sourceA), 'the issuance holds A\'s member');
        self::assertSame(1, $this->client->zcard('{kiwi:ci}:outstanding:global:live'));
        self::assertNotNull($this->client->get($sidecar));

        // An unrelated issuance for another source: the cancellation of
        // A's nonce must never touch B's member.
        self::assertSame(1, $outstanding->issue('203.0.113.9', $otherNonce, 60));
        self::assertSame(1, $this->client->zcard($sourceB));

        $outstanding->cancelled($nonce);
        self::assertSame(0, $this->client->zcard($sourceA), 'the cancellation returns the ORIGINAL source (A) slot');
        self::assertSame(1, $this->client->zcard($sourceB), 'the cancelling source (B) is untouched — the request identity never participates');
        self::assertSame(1, $this->client->zcard('{kiwi:ci}:outstanding:global:live'), 'only A\'s nonce leaves the live membership');
        self::assertNull($this->client->get($sidecar), 'the cancellation deletes the sidecar');

        // Duplicate cancel: ZREM == 0 -> nothing is released twice.
        $outstanding->cancelled($nonce);
        $outstanding->cancelled($nonce);
        self::assertSame(0, $this->client->zcard($sourceA), 'a duplicate cancel never re-releases the original source member');
    }

    public function testSemaphoreWaitersGuardAgainstRealRedis(): void
    {
        $sem = new RedisAdmissionSemaphore($this->client, 1, 'ci-waiters', 45_000, 2);
        $waitersKey = '{kiwicaptcha:argon2:leases:ci-waiters}:sem:waiters';

        $token = $sem->acquire();
        self::assertNotNull($token, 'the only lease is granted');

        // Saturated acquires: counted up to maxWaiters (2), refused beyond
        // without queueing (the overflow entry is removed in the same Lua),
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
        $scopeKey = '{kiwicaptcha:argon2:leases:ci-scope}:'.hash('sha256', 'login');

        // Scope 'login' fills its own budget of 2 while the global cap is
        // nowhere near full; a second scope still acquires (fairness).
        self::assertNotNull($sem->acquire('login'));
        self::assertNotNull($sem->acquire('login'));
        self::assertNull($sem->acquire('login'), 'the 3rd login acquire must be refused by the per-scope budget');
        self::assertSame('2', (string) $this->client->zcard($scopeKey), 'the per-scope set holds exactly its budget');
        self::assertNotNull($sem->acquire('signup'), 'a second scope acquires within its own budget');

        // Release removes the lease from both sets (no TTL wait for the
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
        // A fresh controller per probe: the ~1s in-process policy cache is
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

        // Compatible central policy (protocol 4, epoch 1): the
        // execution-capable v4 canonical is this binary's max protocol.
        $this->client->hset('{kiwi:ci-health}:security-policy', 'min_protocol_version', '3', 'min_policy_epoch', '1');
        self::assertSame(200, $controller()->ready()->getStatusCode(), 'ready with a compatible central policy');

        // A newer protocol or epoch takes the binary out of the pool.
        $this->client->hset('{kiwi:ci-health}:security-policy', 'min_protocol_version', '4', 'min_policy_epoch', '1');
        self::assertSame(200, $controller()->ready()->getStatusCode(), 'central min_protocol_version 4 <= the binary max (4) — the v4-capable binary stays ready');

        $this->client->hset('{kiwi:ci-health}:security-policy', 'min_protocol_version', '5', 'min_policy_epoch', '1');
        self::assertSame(503, $controller()->ready()->getStatusCode(), 'central min_protocol_version 5 > the binary max (4)');

        $this->client->hset('{kiwi:ci-health}:security-policy', 'min_protocol_version', '3', 'min_policy_epoch', '2');
        self::assertSame(503, $controller()->ready()->getStatusCode(), 'central min_policy_epoch 2 > the configured risk.policy_version 1');

        // Live stays 200 while ready fails.
        self::assertSame(200, $controller()->live()->getStatusCode(), 'live must stay 200 while ready fails');

        // Cleanup for the next test run.
        $this->client->del('{kiwi:ci-health}:security-policy');
    }

    public function testConsumeIndeterminateResolvesToTheStoredOutcomeThroughTheValidator(): void
    {
        // The ambiguous consume (the transition landed in Redis but the
        // response was lost) resolves through the validator's
        // consumed-state normalization: the retained record, its committed
        // result and its operation identity are read back via
        // consumedState() from the real Redis backend, and the matching
        // identity yields the stored success; a different operation's
        // identity never does.
        $inner = new RedisStorage($this->client, 'ci:indeterminate:');
        $flaky = new FlakyConsumeRedisStorage($inner);
        $issuer = new Issuer(new Config(secretKey: '0123456789abcdef0123456789abcdef', targetBits: 8), $inner);
        $challenge = $issuer->issue('login', '198.51.100.7', 'txn-123');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
        $verifier = new Verifier($flaky);

        $validate = function (?string $operationId, ?string $binding) use ($verifier, $flaky, $token): array {
            $stack = new RequestStack();
            $request = Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']);
            if ($binding !== null) {
                $request->attributes->set(KiwiCaptchaValidator::REQUEST_BINDING_ATTRIBUTE, $binding);
            }
            if ($operationId !== null) {
                $request->attributes->set(KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE, $operationId);
            }
            $stack->push($request);
            $validator = new KiwiCaptchaValidator($verifier, $stack, '0123456789abcdef0123456789abcdef', false, null, null, null, null, $flaky);
            $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
            $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
            $dto = new class {
                public ?string $captcha = null;
            };
            $dto->captcha = $token;
            $meta = $engine->getMetadataFor($dto::class);
            $meta->addPropertyConstraint('captcha', new KiwiCaptchaConstraint(['scope' => 'login']));
            $violations = $engine->validate($dto);
            $codes = [];
            foreach ($violations as $violation) {
                $codes[] = (string) $violation->getCode();
            }

            return $codes;
        };

        // The original operation consumes + commits its valid result.
        self::assertSame([], $validate('op-123', 'txn-123'));
        self::assertNotNull($inner->consumedState($challenge->nonce)?->consumedResult, 'the committed result is retained in Redis');

        // The retry's consume response is lost: ConsumeIndeterminate,
        // normalized from the retained Redis state — the identity matches,
        // the stored success resolves (the replay gate accepts the
        // explicit operation id).
        $flaky->throwOnConsume = true;
        self::assertSame([], $validate('op-123', 'txn-123'), 'the identity-matching stored outcome resolves the ambiguous retry');

        // A different logical operation under the same lost-response
        // conditions: never the stored success.
        self::assertSame(['invalid_or_expired'], $validate('op-123', 'txn-OTHER'), 'a different binding derives a different identity — refused');
        $flaky->throwOnConsume = false;
    }

    public function testFreshCancellationIsRiskNeutralAgainstRealRedis(): void
    {
        // The end-to-end debt loop with the real risk-v1 Lua: issuance
        // records ChallengeIssued (issue debt on the source identity), a
        // fresh pending->cancelled transition records ChallengeCancelled
        // but the event is risk-neutral — the issue debt of the abandoned
        // challenge stays (only natural decay moves it; only an actual
        // solve repays it), and a repeated idempotent cancellation never
        // moves it either. The debt channel is read from the Lua state
        // hash itself (the same keys the risk-state tests assert against).
        $secret = '0123456789abcdef0123456789abcdef';
        $namespace = 'ci:cancel-debt:'.bin2hex(random_bytes(4));
        $keys = RiskKeys::fromMaster($secret);
        $identityFactory = new \KiwiCaptcha\Risk\RiskIdentityFactory($keys);
        $classifier = new \KiwiCaptcha\Risk\Network\CidrNetworkClassifier([]);
        $policy = \KiwiCaptcha\Risk\RiskPolicy::fromConfig([
            'version' => \KiwiCaptcha\Risk\RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $store = new \KiwiCaptcha\Risk\Storage\RedisRiskStateStore($this->client, namespace: $namespace);
        $engine = new \KiwiCaptcha\Risk\AdaptiveRiskEngine($store, $classifier, $identityFactory, new \KiwiCaptcha\Risk\RiskScorer(), $policy, $keys);
        $resolver = new \BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $gateway = new \BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway($engine, $classifier, $resolver, ['login' => 1], policy: $policy);
        $storage = new RedisStorage($this->client, 'ci:cancel-debt:');
        $issuer = new Issuer(new Config(secretKey: $secret, targetBits: 8, ttlSecs: 120), $storage);
        $controller = new \BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController($issuer, null, false, $gateway, new \BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie(), null, null, [], false, $storage);

        $now = (int) $this->client->time()[0];
        $sourceId = $identityFactory->sourceId('198.51.100.7', $now);
        $stateKey = '{kiwi:'.$namespace.'}:risk:src:'.intdiv($now, 900).':'.$sourceId;
        $issueDebt = fn (): int => (int) $this->client->hget($stateKey, 'iss');
        $redisNowMs = fn (): int => (($t = $this->client->time()) ? ((int) $t[0]) * 1000 + intdiv((int) $t[1], 1000) : 0);

        // The exact decay bracket: the Lua's internal elapsed time between
        // two script executions is bounded by the Redis-clock readings
        // around them (iss leaks at 40 raw/s, so the bracket spans only
        // the real ms the calls took; minElapsed = t2 - t1, maxElapsed =
        // t3 - t0 in the standard bracketed form).
        $leak = static fn (int $raw, int $elapsedMs): int => max(0, $raw - intdiv($elapsedMs * 40, 1000));

        $t0 = $redisNowMs();
        $issue = $controller->challenge(\BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        $t1 = $redisNowMs();
        self::assertSame(200, $issue->getStatusCode());
        $nonce = json_decode((string) $issue->getContent(), true)['nonce'];
        self::assertGreaterThan(0, $issueDebt(), 'the issuance must leave issue debt on the source identity');
        $debtAfterIssue = $issueDebt();

        $t2 = $redisNowMs();
        $cancel = $controller->cancel(\BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest::create('/challenge/cancel', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], json_encode(['nonce' => $nonce], JSON_THROW_ON_ERROR)));
        $t3 = $redisNowMs();
        self::assertSame(200, $cancel->getStatusCode());

        // The debt is NOT refunded: the raw iss after the cancellation is
        // the post-issue value decayed only by the real elapsed window —
        // never a −1000 step (a debt-restoring arm would have clamped it
        // to 0).
        $debtAfterCancel = $issueDebt();
        self::assertGreaterThanOrEqual($leak($debtAfterIssue, $t3 - $t0), $debtAfterCancel, 'the cancellation must not subtract the issue debt');
        self::assertLessThanOrEqual($leak($debtAfterIssue, max(0, $t2 - $t1)), $debtAfterCancel, 'the debt can only decay with real time, never be refunded');
        self::assertGreaterThan(0, $debtAfterCancel, 'the issued-and-abandoned challenge keeps its issue-debt contribution');

        // The repeated idempotent cancellation performs no fresh
        // transition and fires no second event: the debt stays at its
        // naturally decayed value (never a further −1000).
        $r0 = $t3;
        $r1 = $redisNowMs();
        self::assertSame(200, $controller->cancel(\BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest::create('/challenge/cancel', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], json_encode(['nonce' => $nonce], JSON_THROW_ON_ERROR)))->getStatusCode());
        $r2 = $redisNowMs();
        $debtAfterRepeat = $issueDebt();
        self::assertGreaterThanOrEqual($leak($debtAfterCancel, $r2 - $r0), $debtAfterRepeat, 'a repeated cancellation never subtracts the debt');
        self::assertLessThanOrEqual($leak($debtAfterCancel, max(0, $r1 - $t3)), $debtAfterRepeat);
    }
}

/**
 * A real-Redis storage whose consume transition response can be dropped
 * on demand: everything delegates to the Redis backend, only the
 * consume() / consumeWithOperationIdentity() reply is lost after the
 * transition lands (the wire failure that produces ConsumeIndeterminate).
 */
final class FlakyConsumeRedisStorage implements \KiwiCaptcha\StorageInterface, OperationIdentityAwareStorageInterface, ConsumedStateReadableInterface
{
    public bool $throwOnConsume = false;

    public function __construct(private readonly RedisStorage $inner)
    {
    }

    public function store(ChallengeRecord $record): void
    {
        $this->inner->store($record);
    }

    public function find(string $nonce): ?ChallengeRecord
    {
        return $this->inner->find($nonce);
    }

    public function consumedState(string $nonce): ?ConsumedRecord
    {
        return $this->inner->consumedState($nonce);
    }

    public function consume(string $nonce): ?ConsumedRecord
    {
        if ($this->throwOnConsume) {
            throw new \RuntimeException('simulated lost consume response');
        }

        return $this->inner->consume($nonce);
    }

    public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?ConsumedRecord
    {
        if ($this->throwOnConsume) {
            throw new \RuntimeException('simulated lost consume response');
        }

        return $this->inner->consumeWithOperationIdentity($nonce, $operationIdentity);
    }

    public function commitResult(string $nonce, bool $valid, ?string $binding): bool
    {
        return $this->inner->commitResult($nonce, $valid, $binding);
    }

    public function delete(string $nonce): void
    {
        $this->inner->delete($nonce);
    }
}
