<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\InProcessArgonGate;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;

/**
 * In-process Argon2id admission gate (token-set based): acquire() mints a
 * unique token, release() removes exactly that token — stale or double
 * releases are no-ops. Bounds concurrency PER PROCESS (PHP-FPM workers share
 * no memory); the Redis-backed gate is the cross-worker bound.
 */
final class InProcessArgonGateTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    protected function setUp(): void
    {
        InProcessArgonGate::resetForTests();
    }

    protected function tearDown(): void
    {
        InProcessArgonGate::resetForTests();
    }

    public function testGateBoundsConcurrentAcquires(): void
    {
        $gate = new InProcessArgonGate(2);

        $a = $gate->acquire();
        $b = $gate->acquire();
        self::assertIsString($a);
        self::assertIsString($b);
        self::assertNull($gate->acquire(), 'cap saturated: acquire must be refused');
        self::assertSame(2, InProcessArgonGate::activeCount());

        $gate->release($a);
        self::assertIsString($gate->acquire(), 'slot freed: acquire succeeds again');
    }

    public function testZeroCapNeverBlocks(): void
    {
        $gate = new InProcessArgonGate(0);

        self::assertSame('disabled', $gate->acquire());
        self::assertSame('disabled', $gate->acquire());
        self::assertSame(0, InProcessArgonGate::activeCount());
    }

    public function testStaleAndWrongTokenReleasesAreNoOps(): void
    {
        $gate = new InProcessArgonGate(1);

        $tokenA = $gate->acquire();
        $gate->release(str_repeat('0', 32));
        self::assertSame(1, InProcessArgonGate::activeCount(), 'releasing a foreign token must not free a slot');

        // A token that expired "out of process" (e.g. resetForTests) can no
        // longer release a slot it no longer owns.
        InProcessArgonGate::resetForTests();
        $tokenB = $gate->acquire();
        $gate->release($tokenA);
        self::assertSame(1, InProcessArgonGate::activeCount(), 'a stale release must never remove the newer lease');

        $gate->release($tokenB);
        self::assertSame(0, InProcessArgonGate::activeCount());
    }

    public function testDoubleReleaseIsANoOp(): void
    {
        $gate = new InProcessArgonGate(2);

        $token = $gate->acquire();
        $gate->release($token);
        $gate->release($token);

        self::assertSame(0, InProcessArgonGate::activeCount());
    }

    public function testDisabledTokenReleaseIsANoOp(): void
    {
        $gate = new InProcessArgonGate(1);
        $token = $gate->acquire();

        $gate->release('disabled');

        self::assertSame(1, InProcessArgonGate::activeCount(), 'the sentinel release must not touch real leases');
        $gate->release($token);
    }

    public function testGateRejectsSaturatedVerificationWithoutBurningTheRecord(): void
    {
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
        $gate = new InProcessArgonGate(1);
        $verifier = new Verifier($storage, $gate);

        $outsideLease = $gate->acquire();
        self::assertIsString($outsideLease, 'saturate the cap from outside');

        $outcome = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::CapacityExceeded, $outcome->error);
        self::assertNotNull($storage->find($challenge->nonce), 'capacity exhaustion must NOT burn the challenge record');

        $gate->release($outsideLease);
        $outcome = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk(), sprintf('expected valid after release, got %s', $outcome->code()));
        self::assertSame(0, InProcessArgonGate::activeCount(), 'the verifier must release its lease after verifying');
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
