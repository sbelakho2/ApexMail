<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\RedisRiskHealthProvider;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceCounter;
use BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use PHPUnit\Framework\TestCase;

/**
 * Live resource-pressure provider: remaining Redis admission-semaphore slots
 * (argonCapacity) and real per-second issuance headroom as the REMAINING
 * FRACTION of the deployment-wide resource_capacity.issuance_per_second
 * (issuanceCapacity, fixed-point 0..1000: 100% remaining -> 1000, 50% ->
 * 500, 10% -> 100, 0% -> 0). The whole snapshot() is cached in-process for
 * ~100 ms so the hot path does at most one Redis read per 100 ms. The two
 * dimensions are asymmetric on an unobservable source: an unavailable
 * issuance COUNTER reports the nominal 1000 (never fabricate artificial
 * scarcity), while an UNKNOWN argon-gate usage reports 0 (conservative —
 * never fabricate headroom for a memory resource that cannot be measured).
 * Risk-backend health is NOT a snapshot field anymore: the engine's degraded
 * mode consumes the shared circuit breaker directly.
 */
final class RedisRiskHealthProviderTest extends TestCase
{
    private function requirePredis(): FakePredisClient
    {
        $nested = \dirname(__DIR__).'/vendor/kiwicaptcha/kiwicaptcha-php/vendor/autoload.php';
        if (!\class_exists(\Predis\Client::class) && is_file($nested)) {
            require_once $nested;
        }
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed; cannot test RedisRiskHealthProvider');
        }

        return new FakePredisClient();
    }

    public function testEverythingNominalWhenNothingObservable(): void
    {
        $pressure = (new RedisRiskHealthProvider())->snapshot();

        self::assertSame(1000, $pressure->argonCapacity);
        self::assertSame(1000, $pressure->issuanceCapacity);
    }

    public function testArgonCapacityTracksRemainingSemaphoreSlots(): void
    {
        $client = $this->requirePredis();
        $semaphore = new RedisAdmissionSemaphore($client, 4, 'cap-probe');
        $pressure = (new RedisRiskHealthProvider($semaphore))->snapshot();
        self::assertSame(1000, $pressure->argonCapacity, 'an idle semaphore reports full capacity');

        $token = $semaphore->acquire();
        self::assertNotNull($token);
        self::assertSame(1, $semaphore->usage(), 'usage = held leases');

        $pressure = (new RedisRiskHealthProvider($semaphore))->snapshot();
        self::assertSame(750, $pressure->argonCapacity, '1 of 4 slots busy = 3/4 remaining');

        $semaphore->release($token);
        self::assertSame(0, $semaphore->usage());
        self::assertSame(1000, (new RedisRiskHealthProvider($semaphore))->snapshot()->argonCapacity);
    }

    public function testArgonCapacityNominalWhenSemaphoreDisabled(): void
    {
        $semaphore = new RedisAdmissionSemaphore($this->requirePredis(), 0, 'cap-disabled');
        $pressure = (new RedisRiskHealthProvider($semaphore))->snapshot();

        self::assertSame(1000, $pressure->argonCapacity, 'a disabled cap (0) must report nominal, not zero');
    }

    public function testArgonCapacityConservativeZeroWhenBackendUnknown(): void
    {
        // A wired semaphore whose live-usage read FAILS (backend unknown)
        // must report 0 (saturated) — never nominal: the policy escalates
        // Argon to Sha20/StepUp instead of admitting memory-hard work on a
        // gate that cannot be measured.
        $broken = new class extends \Predis\Client {
            public function __call($commandID, $arguments)
            {
                if (strtoupper((string) $commandID) === 'EVAL') {
                    throw new \RuntimeException('connection refused');
                }

                return null;
            }
        };
        $semaphore = new RedisAdmissionSemaphore($broken, 4, 'cap-unknown');
        self::assertNull($semaphore->usage(), 'usage() must report null (unknown), never 0, on a backend failure');

        $pressure = (new RedisRiskHealthProvider($semaphore))->snapshot();
        self::assertSame(0, $pressure->argonCapacity, 'an unknown usage must be treated conservatively as saturated (0)');
        self::assertSame(1000, $pressure->issuanceCapacity, 'the issuance side stays nominal (no client wired)');
    }

    public function testIssuanceHeadroomTracksTheLiveCounterAsFraction(): void
    {
        $client = $this->requirePredis();
        $counter = new IssuanceCounter($client, '{kiwi:t}:issuance:');
        $key = IssuanceCounter::rateKey('{kiwi:t}:issuance:');
        $provider = fn (): RedisRiskHealthProvider => new RedisRiskHealthProvider(null, $client, '{kiwi:t}:issuance:', 1000);

        // Rate 0 -> full headroom (100% remaining -> 1000).
        self::assertSame(1000, $provider()->snapshot()->issuanceCapacity);

        $counter->record();
        $counter->record();
        self::assertSame(2, $client->counters[$key]);
        self::assertSame(998, $provider()->snapshot()->issuanceCapacity, 'headroom = remaining fraction of resource_capacity.issuance_per_second');

        $client->counters[$key] = 1000;
        self::assertSame(0, $provider()->snapshot()->issuanceCapacity, 'rate at the deployment cap -> 0% remaining');

        $client->counters[$key] = 5000;
        self::assertSame(0, $provider()->snapshot()->issuanceCapacity, 'a burst above the cap clamps to zero, never negative');
    }

    public function testIssuanceCapacityFixedPointBoundaries(): void
    {
        // 100% remaining -> 1000; 50% -> 500; 10% -> 100; 0% -> 0.
        $client = $this->requirePredis();
        $provider = fn (string $prefix, int $cap): RedisRiskHealthProvider => new RedisRiskHealthProvider(null, $client, $prefix, $cap);

        self::assertSame(1000, $provider('{kiwi:b1}:issuance:', 500)->snapshot()->issuanceCapacity, 'rate 0 on cap 500 -> 100% remaining');

        $key = IssuanceCounter::rateKey('{kiwi:b2}:issuance:');
        $client->counters[$key] = 9500;
        self::assertSame(50, $provider('{kiwi:b2}:issuance:', 10000)->snapshot()->issuanceCapacity, 'cap 10000 rate 9500 -> 500/10000 = 5% -> 50');

        $key = IssuanceCounter::rateKey('{kiwi:b3}:issuance:');
        $client->counters[$key] = 500;
        self::assertSame(500, $provider('{kiwi:b3}:issuance:', 1000)->snapshot()->issuanceCapacity, 'half of the cap -> 50% -> 500');

        $key = IssuanceCounter::rateKey('{kiwi:b4}:issuance:');
        $client->counters[$key] = 900;
        self::assertSame(100, $provider('{kiwi:b4}:issuance:', 1000)->snapshot()->issuanceCapacity, '90% consumed -> 10% -> 100');

        // Sub-1% remaining rounds to 0 under the same formula (never
        // negative, never above 1000).
        $key = IssuanceCounter::rateKey('{kiwi:b5}:issuance:');
        $client->counters[$key] = 9999;
        self::assertSame(0, $provider('{kiwi:b5}:issuance:', 10000)->snapshot()->issuanceCapacity, '1/10000 remaining rounds to 0');
    }

    public function testIssuanceCapacityOnTheDefaultDeploymentDenominator(): void
    {
        // The audit boundary pair on the DEFAULT resource_capacity
        // denominator (20000): rate 0 -> full headroom; rate 19000 -> 50.
        $client = $this->requirePredis();
        $provider = fn (): RedisRiskHealthProvider => new RedisRiskHealthProvider(null, $client, '{kiwi:d1}:issuance:');

        self::assertSame(1000, $provider()->snapshot()->issuanceCapacity, 'rate 0 on the default cap 20000 -> 100% remaining');

        $client->counters[IssuanceCounter::rateKey('{kiwi:d1}:issuance:')] = 19000;
        self::assertSame(50, $provider()->snapshot()->issuanceCapacity, 'cap 20000 rate 19000 -> 1000/20000 = 5% -> 50');
    }

    public function testIssuanceNominalWhenCounterUnobservable(): void
    {
        // No client: no observability -> nominal.
        self::assertSame(1000, (new RedisRiskHealthProvider())->snapshot()->issuanceCapacity);

        // A deployment cap of 0 (operator disabled the denominator) -> nominal.
        self::assertSame(1000, (new RedisRiskHealthProvider(null, $this->requirePredis(), '{kiwi:t}:issuance:', 0))->snapshot()->issuanceCapacity);

        // A failing client must never fabricate artificial scarcity.
        $broken = new class extends \Predis\Client {
            public function get(string $key): ?string
            {
                throw new \RuntimeException('connection refused');
            }
        };
        self::assertSame(1000, (new RedisRiskHealthProvider(null, $broken, '{kiwi:t}:issuance:', 1000))->snapshot()->issuanceCapacity);
    }

    public function testSnapshotIsCachedWithinThe100MsBudget(): void
    {
        // The whole snapshot() is cached in-process for ~100 ms: two
        // snapshots inside the budget perform only ONE Redis read (the
        // issuance-rate GET), not a PING + semaphore query per call.
        $client = $this->requirePredis();
        $provider = new RedisRiskHealthProvider(null, $client, '{kiwi:t}:issuance:', 1000);

        $first = $provider->snapshot();
        $callsAfterFirst = \count($client->calls);
        $second = $provider->snapshot();

        self::assertSame($first, $second, 'the cached snapshot must be the same immutable object');
        self::assertCount($callsAfterFirst, $client->calls, 'a snapshot inside the 100 ms budget must not touch Redis again');
    }
}
