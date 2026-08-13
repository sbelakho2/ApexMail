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
 * Redis-backed Argon2id admission gate — the audit's TOKENIZED-LEASE design.
 *
 * Each acquire() mints a unique lease token stored as a sorted-set member
 * scored at its expiry; release() removes EXACTLY that token. Expired leases
 * are reaped by the acquire script (ZREMRANGEBYSCORE up to the server time),
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

        // The lease expires after LEASE_MS: advancing the server clock past
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

        // The STALE release of the expired token A must be a no-op: it can
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

    public function testUsageIsAtomicLiveAndReapsExpiredLeases(): void
    {
        // usage() must be ATOMIC-LIVE: ONE Lua script (TIME -> prune ->
        // ZCARD), so an expired-but-unreaped lease is counted exactly as the
        // next acquire would count it — ZCARD alone would overcount while a
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
