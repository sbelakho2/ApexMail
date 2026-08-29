<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;

/**
 * Redis-backed Argon2id admission gate — the audit's tokenized-lease design.
 *
 * Each acquire() mints a unique lease token stored as a sorted-set member
 * scored at its expiry; release() removes exactly that token. Expired leases
 * are reaped by the acquire script (zremrangebyscore up to the server time),
 * and a stale release can never remove a newer lease. Exercised against an
 * in-memory Predis stand-in emulating the Lua scripts with a configurable
 * server clock.
 */
final class RedisAdmissionSemaphoreTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    /** Lease lifetime in ms — must mirror the semaphore's own constant. */
    private const LEASE_MS = 45_000;

    private function leases(FakePredisClient $client, string $namespace = 'default'): int
    {
        return $client->zcard('kiwicaptcha:argon2:leases:'.$namespace);
    }

    private function requirePredis(): FakePredisClient
    {
        // The bundle itself does not depend on predis; the dev toolchain has
        // it via the core package's copied vendor (path repo). Load it when
        // available and skip otherwise, mirroring the core's RedisStorageTest.
        $nested = \dirname(__DIR__).'/vendor/kiwicaptcha/kiwicaptcha-php/vendor/autoload.php';
        if (!\class_exists(\Predis\Client::class) && is_file($nested)) {
            require_once $nested;
        }
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed; cannot test RedisAdmissionSemaphore');
        }

        return new FakePredisClient();
    }

    public function testAcquireReturnsTokenAndReleaseRemovesIt(): void
    {
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 2);

        $token = $semaphore->acquire();
        self::assertIsString($token);
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $token, 'lease token must be 16 random bytes in hex');
        self::assertSame(1, $this->leases($client));

        $semaphore->release($token);
        self::assertSame(0, $this->leases($client), 'release must remove exactly the lease');
    }

    public function testCapIsEnforced(): void
    {
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 2);

        $a = $semaphore->acquire();
        $b = $semaphore->acquire();
        self::assertNotNull($a);
        self::assertNotNull($b);
        self::assertNull($semaphore->acquire(), 'cap saturated: third acquire must be refused');

        $semaphore->release($a);
        self::assertIsString($semaphore->acquire(), 'slot freed: acquire succeeds again');
        self::assertSame(2, $this->leases($client));
    }

    public function testExpiredLeasesAreReapedByTheNextAcquire(): void
    {
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 1);

        $a = $semaphore->acquire();
        self::assertSame(1, $this->leases($client));

        // The lease expires after lease_MS: advancing the server clock past
        // it makes the next acquire prune it before admitting.
        $client->setTimeMs($client->timeMs() + self::LEASE_MS + 1);

        $b = $semaphore->acquire();
        self::assertNotNull($b, 'expired lease must be reaped so the cap recovers');
        self::assertSame(1, $this->leases($client), 'only the NEW lease remains');
        self::assertNotSame($a, $b, 'a fresh lease token must be minted');
    }

    public function testStaleReleaseCannotRemoveANewLease(): void
    {
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 1);

        $tokenA = $semaphore->acquire();
        self::assertIsString($tokenA);

        // Let token A expire, then acquire token B — A is pruned, B takes
        // the only slot.
        $client->setTimeMs($client->timeMs() + self::LEASE_MS + 1);
        $tokenB = $semaphore->acquire();
        self::assertIsString($tokenB);
        self::assertSame(1, $this->leases($client));

        // The stale release of the expired token A must be a no-op: it can
        // never remove B's live lease.
        $semaphore->release($tokenA);
        self::assertSame(1, $this->leases($client), 'stale release must not remove the new lease (B)');
        self::assertContains($tokenB, $client->zmembers('kiwicaptcha:argon2:leases:default'));
    }

    public function testWrongTokenReleaseIsANoOp(): void
    {
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 1);

        $token = $semaphore->acquire();
        self::assertSame(1, $this->leases($client));

        $semaphore->release(str_repeat('0', 32));
        self::assertSame(1, $this->leases($client), 'releasing a token that is not in the lease set changes nothing');

        $semaphore->release($token);
        self::assertSame(0, $this->leases($client));
    }

    public function testDoubleReleaseIsANoOp(): void
    {
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 2);

        $token = $semaphore->acquire();
        $semaphore->release($token);
        $semaphore->release($token);

        self::assertSame(0, $this->leases($client), 'releasing the same token twice must not leak a negative permit');
        self::assertIsString($semaphore->acquire());
    }

    public function testNamespacesDoNotCompete(): void
    {
        $client = $this->requirePredis();
        $first = new RedisAdmissionSemaphore($client, 1, 'deployment-a');
        $second = new RedisAdmissionSemaphore($client, 1, 'deployment-b');

        self::assertIsString($first->acquire());
        self::assertSame(1, $this->leases($client, 'deployment-a'));

        // The second deployment has its own lease set: the first's full cap
        // must not block it.
        self::assertIsString($second->acquire(), 'independent namespaces must not compete');
        self::assertSame(1, $this->leases($client, 'deployment-b'));

        // Sanitization: hostile namespace characters collapse to underscores.
        $hostile = new RedisAdmissionSemaphore($client, 1, 'my/ns:weird');
        self::assertIsString($hostile->acquire());
        self::assertSame(1, $this->leases($client, 'my_ns_weird'));
    }

    public function testDisabledCapReturnsSentinelTokenAndReleaseNoOps(): void
    {
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 0);

        self::assertSame('disabled', $semaphore->acquire());
        self::assertSame(0, $this->leases($client), 'disabled cap must never touch Redis');

        $semaphore->release('disabled');
        self::assertSame(0, $this->leases($client));
    }

    public function testUnscopedAcquireAndReleaseDeclareNoEmptyKeys(): void
    {
        // P3 topology hardening: an unscoped acquire/release must never
        // declare '' as a KEYS argument (an empty string has its own hash
        // slot and breaks the EVAL on Redis Cluster) — the global lease
        // set key is the same-slot placeholder, gated by the ARGV flags.
        $client = new FakePredisClient();
        $semaphore = new RedisAdmissionSemaphore($client, 3, 'empty-key-guard');

        $token = $semaphore->acquire();
        self::assertNotNull($token);
        $evals = array_values(array_filter($client->calls, static fn (array $c): bool => $c[0] === 'EVAL'));
        self::assertNotSame([], $evals, 'the acquire must issue one EVAL');
        foreach ($evals as $call) {
            $args = $call[1];
            $numKeys = (int) $args[1];
            foreach (array_slice($args, 2, $numKeys) as $key) {
                self::assertNotSame('', $key, 'no acquire EVAL key may be an empty string');
            }
        }

        $semaphore->release($token);
        $evals = array_values(array_filter($client->calls, static fn (array $c): bool => $c[0] === 'EVAL'));
        $last = $evals[count($evals) - 1];
        $args = $last[1];
        $numKeys = (int) $args[1];
        foreach (array_slice($args, 2, $numKeys) as $key) {
            self::assertNotSame('', $key, 'no release EVAL key may be an empty string');
        }
    }

    public function testCapacityAndUsageExposeLiveSlots(): void
    {
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 3, 'usage-probe');

        self::assertSame(3, $semaphore->capacity());
        self::assertSame(0, $semaphore->usage());

        $token = $semaphore->acquire();
        self::assertNotNull($token);
        self::assertSame(1, $semaphore->usage(), 'usage = live lease-set members');

        $semaphore->release($token);
        self::assertSame(0, $semaphore->usage());
        self::assertSame(0, (new RedisAdmissionSemaphore($client, 0))->usage(), 'disabled cap reports 0 usage');
    }

    public function testUsageReportsNullWhenBackendUnavailable(): void
    {
        // usage() must distinguish "unknown" from "zero": a backend failure
        // returns null (never 0 — 0 means the gate is verifiably empty, null
        // means it cannot be measured; the resource-pressure provider treats
        // null conservatively as saturated).
        $broken = new class extends \Predis\Client {
            public function __call($commandID, $arguments)
            {
                if (strtoupper((string) $commandID) === 'EVAL') {
                    throw new \RuntimeException('connection refused');
                }

                return null;
            }
        };
        $semaphore = new RedisAdmissionSemaphore($broken, 2, 'usage-unknown');
        self::assertNull($semaphore->usage(), 'a backend failure must report null (unknown), never 0');
        self::assertSame(2, $semaphore->capacity(), 'the configured cap stays readable without the backend');
    }

    public function testUsageIsAtomicLiveAndReapsExpiredLeases(): void
    {
        // usage() must be atomic-live: ONE Lua script (time -> prune ->
        // zcard), so an expired-but-unreaped lease is counted exactly as the
        // next acquire would count it — zcard alone would overcount while a
        // crashed worker's lease sits un-reaped between acquires.
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 1, 'usage-live');

        $token = $semaphore->acquire();
        self::assertSame(1, $semaphore->usage());

        // The lease expires (worker crashed, no release): usage() itself
        // reaps it — the live count drops without any acquire.
        $client->setTimeMs($client->timeMs() + self::LEASE_MS + 1);
        self::assertSame(0, $semaphore->usage(), 'usage must prune expired leases atomically');
        self::assertSame(0, $this->leases($client), 'the expired lease is gone from the set');
        self::assertIsString($semaphore->acquire(), 'the freed slot admits again');
    }

    public function testGateRejectsSaturatedVerificationWithoutBurningTheRecord(): void
    {
        $client = $this->requirePredis();
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(
            secretKey: self::SECRET,
            algorithm: PoWAlgorithm::Argon2id,
            mKib: 64,
            t: 3,
            p: 1,
            argon2TargetBits: 4,
        ), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);

        $token = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $gate = new RedisAdmissionSemaphore($client, 1);
        $verifier = new Verifier($storage, $gate);

        $outsideLease = $gate->acquire();
        self::assertIsString($outsideLease, 'saturate the cap from outside');

        $outcome = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::CapacityExceeded, $outcome->error);
        self::assertNotNull($storage->find($challenge->nonce), 'capacity exhaustion must NOT burn the challenge record (client can retry)');

        // Free a slot: the same challenge now verifies.
        $gate->release($outsideLease);
        self::assertSame(0, $this->leases($client));
        $outcome = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk(), sprintf('expected valid after release, got %s', $outcome->code()));
    }

    public function testSha256VerificationNeverConsultsTheGate(): void
    {
        $client = $this->requirePredis();
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);

        $token = $this->solveSha256($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $gate = new RedisAdmissionSemaphore($client, 0);
        $verifier = new Verifier($storage, $gate);

        $outcome = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk(), sprintf('expected valid, got %s', $outcome->code()));
        self::assertSame(0, $this->leases($client), 'sha256 verification must never take an argon2 lease');
    }

    /** The waiters counter key of a namespace (mirrors the semaphore's own derivation). */
    private function waitersKey(string $namespace = 'default'): string
    {
        return '{kiwicaptcha:argon2:leases:'.$namespace.'}:sem:waiters';
    }

    public function testSaturatedAcquiresAreCountedAsWaitersWithTheLeaseTtl(): void
    {
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 1);

        $token = $semaphore->acquire();
        self::assertIsString($token);
        self::assertSame(0, $client->counters[$this->waitersKey()] ?? 0, 'a granted lease is not a waiter');

        self::assertNull($semaphore->acquire(), 'cap saturated');
        self::assertSame(1, $client->counters[$this->waitersKey()] ?? 0, 'a saturated acquire counts as one waiter');
        self::assertSame(self::LEASE_MS * 2, $client->expirations[$this->waitersKey()] ?? 0, 'the waiters counter carries the lease lifetime TTL (self-clearing)');

        // The counted waiter stays until a slot frees: the waiters counter
        // is not decremented by further saturated acquires below the bound.
        self::assertNull($semaphore->acquire());
        self::assertSame(2, $client->counters[$this->waitersKey()] ?? 0, 'each saturated acquire below the bound is counted');
    }

    public function testWaiterCountNeverExceedsTheBoundAndOverflowIsRefusedWithoutQueueing(): void
    {
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 1, 'waiters-bound', self::LEASE_MS, 3);

        self::assertIsString($semaphore->acquire(), 'grant the only lease');
        for ($i = 0; $i < 10; $i++) {
            self::assertNull($semaphore->acquire(), 'saturated acquires always refuse (CapacityExceeded)');
        }
        self::assertLessThanOrEqual(3, $client->counters[$this->waitersKey('waiters-bound')] ?? 0, 'the saturation-pressure counter must never exceed the cap: overflowing contenders are refused WITHOUT queueing (entry removed in the same Lua)');
        self::assertSame(3, $client->counters[$this->waitersKey('waiters-bound')] ?? 0, 'after the bound, each overflow attempt increments then removes its own entry (steady state = the cap)');
    }

    public function testOverCapAcquireFastFailsWithoutHoldingASlot(): void
    {
        // Round-97: the saturation-pressure fast-fail is real. Once the
        // waiters gauge exceeds the cap, the acquire script returns its
        // distinguishable sentinel (-1) and acquire() maps it to the
        // CapacityExceeded path: null, NO lease slot held, no counter
        // residue — the subsequent below-cap acquire (after the lease is
        // released) still succeeds, proving the fast-fail never wedged
        // the gate or leaked a phantom lease.
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 1, 'fast-fail', self::LEASE_MS, 2);

        $lease = $semaphore->acquire();
        self::assertIsString($lease);
        self::assertFalse($semaphore->lastAcquireFastFailed(), 'a granted acquire never fast-fails');

        // Two refusals fill the gauge exactly to the cap (2): ordinary
        // refusals, the boundary does not trip.
        self::assertNull($semaphore->acquire());
        self::assertFalse($semaphore->lastAcquireFastFailed(), 'the boundary (waiters == cap) is an ordinary refusal');
        self::assertNull($semaphore->acquire());
        self::assertFalse($semaphore->lastAcquireFastFailed(), 'waiters == cap exactly: still no trip');
        self::assertSame(2, $client->counters[$this->waitersKey('fast-fail')] ?? 0);

        // The third refusal exceeds the cap: the capacity signal fires.
        self::assertNull($semaphore->acquire(), 'the over-cap acquire returns the capacity signal (null lease)');
        self::assertTrue($semaphore->lastAcquireFastFailed(), 'the over-cap refusal is distinguishable: the fast-fail flag is set');
        self::assertSame(1, $this->leases($client, 'fast-fail'), 'the fast-fail acquires NO lease slot');
        self::assertSame(2, $client->counters[$this->waitersKey('fast-fail')] ?? 0, 'the fast-fail contender leaves no counter residue (steady state = the cap)');

        // Releasing the lease recovers the gate: the next acquire is a
        // normal grant (nothing wedged), and the granted caller serves
        // one waiter as always.
        $semaphore->release($lease);
        $next = $semaphore->acquire();
        self::assertIsString($next, 'the subsequent below-cap acquire succeeds — the fast-fail held no slot');
        self::assertFalse($semaphore->lastAcquireFastFailed(), 'a fresh acquire resets the flag');
        $semaphore->release($next);
    }

    public function testFastFailCounterResidueIsNeverNegativeAndGaugeStaysAtTheCap(): void
    {
        // A saturation storm: the gauge stays pinned at the cap no matter
        // how many over-cap contenders arrive, and every one of them is
        // the fast-fail (capacity) signal, never an ordinary refusal.
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 1, 'storm', self::LEASE_MS, 1);

        self::assertIsString($semaphore->acquire());
        self::assertNull($semaphore->acquire());
        self::assertFalse($semaphore->lastAcquireFastFailed(), 'waiters 0 -> 1: the boundary equals the cap, no trip');

        for ($i = 0; $i < 25; $i++) {
            self::assertNull($semaphore->acquire());
            self::assertTrue($semaphore->lastAcquireFastFailed(), 'every over-cap contender trips the fast-fail');
            self::assertSame(1, $client->counters[$this->waitersKey('storm')] ?? 0, 'the gauge stays at the cap through the whole storm');
        }
    }

    public function testGrantedLeaseServesOneWaiter(): void
    {
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 1);

        $token = $semaphore->acquire();
        self::assertNull($semaphore->acquire(), 'saturate');
        self::assertSame(1, $client->counters[$this->waitersKey()] ?? 0);

        $semaphore->release($token);
        $next = $semaphore->acquire();
        self::assertIsString($next, 'a freed slot admits the next contender');
        self::assertSame(0, $client->counters[$this->waitersKey()] ?? 0, 'the granted caller was a served waiter — the waiters counter is decremented in the same Lua');
        $semaphore->release($next);
    }

    public function testWaiterCountersDoNotCompeteAcrossNamespaces(): void
    {
        $client = $this->requirePredis();
        $a = new RedisAdmissionSemaphore($client, 1, 'ns-a');
        $b = new RedisAdmissionSemaphore($client, 1, 'ns-b');

        self::assertIsString($a->acquire());
        self::assertNull($a->acquire(), 'saturate ns-a');
        self::assertSame(1, $client->counters[$this->waitersKey('ns-a')] ?? 0);

        self::assertIsString($b->acquire(), 'independent namespace: a full lease set and its waiters must not block ns-b');
        self::assertSame(0, $client->counters[$this->waitersKey('ns-b')] ?? 0, 'ns-b has its own waiters counter');
        self::assertSame(1, $client->counters[$this->waitersKey('ns-a')] ?? 0, 'ns-a keeps its own waiter count');
    }

    public function testMaxWaitersBelowOneIsRejected(): void
    {
        $client = $this->requirePredis();
        $this->expectException(\InvalidArgumentException::class);
        new RedisAdmissionSemaphore($client, 1, 'default', self::LEASE_MS, 0);
    }

// ── per-scope budget ──────────────────────────────────────────────────────

    /** The per-scope lease set key of a namespace + scope (mirrors the semaphore's derivation). */
    private function scopeKey(string $scope, string $namespace = 'default'): string
    {
        return '{kiwicaptcha:argon2:leases:'.$namespace.'}:'.hash('sha256', $scope);
    }

    public function testOneScopeFillsItsBudgetAndAnotherScopeStillAcquires(): void
    {
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 100, 'scope-fair', self::LEASE_MS, 64, 2);

        // Scope 'login' fills its own budget (2) while the global cap (100)
        // is nowhere near full.
        self::assertIsString($semaphore->acquire('login'));
        self::assertIsString($semaphore->acquire('login'));
        self::assertNull($semaphore->acquire('login'), 'the 3rd login acquire must be refused by the PER-SCOPE budget');
        self::assertSame(2, $client->zcard($this->scopeKey('login', 'scope-fair')), 'the scope set holds exactly its budget');

        // A different scope still acquires within its own budget — one
        // scope's fullness never starves the others.
        self::assertIsString($semaphore->acquire('signup'), 'a second scope must acquire within its own budget');
        self::assertIsString($semaphore->acquire('signup'));
        self::assertNull($semaphore->acquire('signup'), 'signup has its own budget of 2');
        self::assertSame(2, $client->zcard($this->scopeKey('signup', 'scope-fair')));
        self::assertSame(4, $this->leases($client, 'scope-fair'), 'the global set holds both scopes\' leases');
    }

    public function testGlobalCapStillEnforcedOnTopOfPerScopeBudgets(): void
    {
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 3, 'scope-global', self::LEASE_MS, 64, 10);

        // Per-scope budgets (10) are generous; the global cap (3) is the
        // deployment-wide invariant and must bind first.
        self::assertIsString($semaphore->acquire('a'));
        self::assertIsString($semaphore->acquire('a'));
        self::assertIsString($semaphore->acquire('b'));
        self::assertNull($semaphore->acquire('c'), 'the 4th lease must be refused by the GLOBAL cap even though scope c has budget');
        self::assertSame(3, $this->leases($client, 'scope-global'));
    }

    public function testScopedReleaseRemovesTheLeaseFromBothSets(): void
    {
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 10, 'scope-release', self::LEASE_MS, 64, 2);

        $token = $semaphore->acquire('login');
        self::assertIsString($token);
        self::assertSame(1, $client->zcard($this->scopeKey('login', 'scope-release')));
        self::assertSame(1, $this->leases($client, 'scope-release'));

        $semaphore->release($token);
        self::assertSame(0, $client->zcard($this->scopeKey('login', 'scope-release')), 'release must remove the lease from the PER-SCOPE set too');
        self::assertSame(0, $this->leases($client, 'scope-release'));

        // The scope budget is free again immediately (no TTL wait).
        self::assertIsString($semaphore->acquire('login'));
    }

    public function testScopedTokenCarriesTheScopeAndUnscopedAcquiresStayHexOnly(): void
    {
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 10, 'scope-token', self::LEASE_MS, 64, 2);

        $token = $semaphore->acquire('login');
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}\.'.preg_quote(hash('sha256', 'login'), '/').'$/', $token, 'a scoped lease token carries the HASHED scope suffix (release rebuilds the scope key from it)');

        $unscoped = $semaphore->acquire();
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $unscoped, 'an unscoped acquire keeps the plain hex token');
    }

    public function testHostileScopeNamesHashIntoTheKey(): void
    {
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 10, 'scope-hash', self::LEASE_MS, 64, 2);

        // The scope is hashed, never lossily sanitized: hostile characters
        // cannot collapse distinct scopes (tenant:a vs tenant_a must stay
        // independent per-tenant budgets).
        $token = $semaphore->acquire('my/scope:weird|login');
        self::assertIsString($token);
        self::assertSame(1, $client->zcard($this->scopeKey('my/scope:weird|login', 'scope-hash')), 'the per-scope key is the hash of the EXACT scope string');
        $semaphore->release($token);
        self::assertSame(0, $client->zcard($this->scopeKey('my/scope:weird|login', 'scope-hash')));
    }

    public function testDistinctScopesNeverCollideInThePerScopeBudget(): void
    {
        // P3: a lossy sanitization collapsed tenant:a and tenant_a into one
        // per-tenant budget — one scope could starve the other. The hashed
        // scope keeps them independent.
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 100, 'scope-collide', self::LEASE_MS, 64, 1);

        $a = $semaphore->acquire('tenant:a');
        self::assertIsString($a);
        self::assertNull($semaphore->acquire('tenant:a'), 'tenant:a fills its own budget of 1');
        self::assertIsString($semaphore->acquire('tenant_a'), 'tenant_a has its OWN budget — the scopes never collide');
        self::assertSame(1, $client->zcard($this->scopeKey('tenant:a', 'scope-collide')), 'tenant:a holds exactly its member');
        self::assertSame(1, $client->zcard($this->scopeKey('tenant_a', 'scope-collide')), 'tenant_a holds exactly its member');
    }

    public function testScopeBudgetKeysAreIndependentAcrossNamespaces(): void
    {
        $client = $this->requirePredis();
        $a = new RedisAdmissionSemaphore($client, 10, 'scope-ns-a', self::LEASE_MS, 64, 1);
        $b = new RedisAdmissionSemaphore($client, 10, 'scope-ns-b', self::LEASE_MS, 64, 1);

        self::assertIsString($a->acquire('login'));
        self::assertNull($a->acquire('login'), 'namespace A scope login is full');
        self::assertIsString($b->acquire('login'), 'namespace B has its own scope budget');
    }

    public function testMaxPerScopeBelowOneIsRejected(): void
    {
        $client = $this->requirePredis();
        $this->expectException(\InvalidArgumentException::class);
        new RedisAdmissionSemaphore($client, 1, 'default', self::LEASE_MS, 64, 0);
    }

    private function solveSha256(string $prefix, string $salt, int $targetBits, string $nonce): string
    {
        $counter = 0;
        do {
            $h = hash('sha256', $prefix.$counter.base64_decode($salt, true), true);
            $counter++;
        } while (Verifier::leadingZeroBits($h) < $targetBits);
        --$counter;

        return SolutionToken::create($nonce, $counter, 5000, [])->encode();
    }

    private function solve(string $prefix, string $salt, int $targetBits, string $nonce): string
    {
        $counter = 0;
        do {
            $h = sodium_crypto_pwhash(
                32,
                $prefix.$counter,
                base64_decode($salt, true),
                3,
                64 * 1024,
                SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
            );
            $counter++;
        } while (Verifier::leadingZeroBits($h) < $targetBits);
        --$counter;

        return SolutionToken::create($nonce, $counter, 5000, [])->encode();
    }
}
