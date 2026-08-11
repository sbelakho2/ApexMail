<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore;
use BelConsulting\KiwiCaptchaBundle\Security\ThrottledVerifier;
use BelConsulting\KiwiCaptchaBundle\Security\VerificationCapacityExceededException;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;

/**
 * Redis-backed admission semaphore for the Argon2id verification cap: atomic
 * INCR/DECR admission against a shared Redis instance, so the cap holds
 * ACROSS PHP-FPM workers (unlike the in-process Argon2Semaphore). Exercised
 * against an in-memory Predis stand-in emulating the Lua scripts.
 */
final class RedisAdmissionSemaphoreTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const COUNTER_KEY = 'kiwicaptcha:argon2:active:default';

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

    public function testAcquireReleaseCycles(): void
    {
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 2);

        self::assertTrue($semaphore->acquire());
        self::assertSame('1', $client->store[self::COUNTER_KEY]);

        $semaphore->release();
        self::assertSame('0', $client->store[self::COUNTER_KEY]);

        self::assertTrue($semaphore->acquire());
        $semaphore->release();
        $semaphore->release();
        // Release below zero must delete the key (floor at 0) — no negative
        // counter can accumulate and block the next acquire.
        self::assertArrayNotHasKey(self::COUNTER_KEY, $client->store);
    }

    public function testCapIsEnforcedAtomically(): void
    {
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 2);

        self::assertTrue($semaphore->acquire());
        self::assertTrue($semaphore->acquire());
        self::assertFalse($semaphore->acquire(), 'cap saturated: third acquire must be refused');

        $semaphore->release();
        self::assertTrue($semaphore->acquire(), 'slot freed: acquire succeeds again');
    }

    public function testRejectedAcquireLeavesNoPermitBehind(): void
    {
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 1);

        self::assertTrue($semaphore->acquire());
        self::assertFalse($semaphore->acquire());

        // The rejected INCR must have been rolled back (counter stays at 1).
        self::assertSame('1', $client->store[self::COUNTER_KEY]);
    }

    public function testWatchdogTtlIsSetOnFirstAcquire(): void
    {
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 2);

        $semaphore->acquire();

        self::assertSame(60, $client->expirations[self::COUNTER_KEY] ?? null, 'first acquire must set the watchdog TTL');
    }

    public function testLeakedPermitExpiresAndRecovers(): void
    {
        // Approximation documented in the class docblock: a worker that
        // crashes while holding a permit never releases it; the watchdog TTL
        // auto-expires the counter so the cap recovers.
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 2);

        self::assertTrue($semaphore->acquire());

        // Simulate the crash: the key vanishes when the watchdog TTL lapses.
        unset($client->store[self::COUNTER_KEY]);

        self::assertTrue($semaphore->acquire(), 'expired permit must not block the next acquire');
        self::assertSame('1', $client->store[self::COUNTER_KEY]);
    }

    public function testZeroCapNeverBlocks(): void
    {
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 0);

        self::assertTrue($semaphore->acquire());
        self::assertTrue($semaphore->acquire());
    }

    public function testThrottledVerifierRejectsWhenRedisCapIsSaturated(): void
    {
        $client = $this->requirePredis();
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);

        $token = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $verifier = new ThrottledVerifier(new Verifier($storage), 1, new RedisAdmissionSemaphore($client, 1));

        self::assertTrue((new RedisAdmissionSemaphore($client, 1))->acquire(), 'saturate the cap from outside');

        $this->expectException(VerificationCapacityExceededException::class);
        $verifier->verify($token, self::SECRET, 'login', '198.51.100.7');
    }

    public function testThrottledVerifierReleasesRedisPermitAfterVerify(): void
    {
        $client = $this->requirePredis();
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);

        $token = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $verifier = new ThrottledVerifier(new Verifier($storage), 1, new RedisAdmissionSemaphore($client, 1));

        $outcome = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk(), sprintf('expected valid, got %s', $outcome->code()));
        self::assertSame('0', $client->store[self::COUNTER_KEY], 'permit must be released after verification');
    }

    private function solve(string $prefix, string $salt, int $targetBits, string $nonce): string
    {
        $counter = 0;
        do {
            $h = hash('sha256', $prefix.$counter.base64_decode($salt, true), true);
            $counter++;
        } while (Verifier::leadingZeroBits($h) < $targetBits);
        --$counter;

        return SolutionToken::create($nonce, $counter, 5000, [])->encode();
    }
}
