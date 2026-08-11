<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\Argon2Semaphore;
use BelConsulting\KiwiCaptchaBundle\Security\ThrottledVerifier;
use BelConsulting\KiwiCaptchaBundle\Security\VerificationCapacityExceededException;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;

/**
 * Aggregate Argon2id verification concurrency cap: an in-process semaphore
 * bounds how many verifications may be in flight; when the cap is saturated
 * and no slot frees up within the wait bound, verification is rejected with
 * VerificationCapacityExceededException (the validator turns that into a
 * regular captcha violation).
 */
final class Argon2SemaphoreTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    protected function setUp(): void
    {
        Argon2Semaphore::resetForTests();
        Argon2Semaphore::setMaxWaitSecsForTests(0.05);
    }

    protected function tearDown(): void
    {
        Argon2Semaphore::resetForTests();
    }

    public function testSemaphoreBoundsConcurrentAcquires(): void
    {
        self::assertTrue(Argon2Semaphore::acquire(2));
        self::assertTrue(Argon2Semaphore::acquire(2));
        self::assertFalse(Argon2Semaphore::acquire(2), 'cap saturated: acquire must time out');

        Argon2Semaphore::release();
        self::assertTrue(Argon2Semaphore::acquire(2), 'slot freed: acquire succeeds again');
    }

    public function testZeroCapNeverBlocks(): void
    {
        self::assertTrue(Argon2Semaphore::acquire(0));
        self::assertTrue(Argon2Semaphore::acquire(0));
    }

    public function testThrottledVerifierRejectsWhenCapIsSaturated(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);

        $token = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $verifier = new ThrottledVerifier(new Verifier($storage), 1);

        self::assertTrue(Argon2Semaphore::acquire(1), 'saturate the cap from outside');

        $this->expectException(VerificationCapacityExceededException::class);
        $verifier->verify($token, self::SECRET, 'login', '198.51.100.7');
    }

    public function testThrottledVerifierPassesThroughAndReleases(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);

        $token = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $verifier = new ThrottledVerifier(new Verifier($storage), 1);

        $outcome = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk(), sprintf('expected valid, got %s', $outcome->code()));
        self::assertSame(0, Argon2Semaphore::active(), 'semaphore must be released after verification');
    }

    public function testThrottledVerifierWithoutCapIsPurePassThrough(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);

        $token = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $verifier = new ThrottledVerifier(new Verifier($storage), 0);

        $outcome = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk());
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
