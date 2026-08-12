<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\RedisRiskHealthProvider;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceCounter;
use BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Risk\Breaker\CircuitBreaker;
use PHPUnit\Framework\TestCase;

/**
 * Live resource-pressure provider: remaining Redis admission-semaphore slots
 * (argonCapacity), real per-second issuance headroom from the atomic
 * issuance-rate counter (issuanceCapacity), and risk backend health from the
 * shared circuit breaker (riskBackendHealth — NO per-request PING). The
 * whole snapshot() is cached in-process for ~100 ms so the hot path does at
 * most one Redis read per 100 ms. Any unobservable source must report the
 * nominal 1000 — pressure is an availability signal and an unavailable
 * source must never fabricate artificial scarcity.
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
        self::assertSame(1000, $pressure->riskBackendHealth);
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

    public function testBackendHealthComesFromTheCircuitBreakerNotPing(): void
    {
        $client = $this->requirePredis();
        $breaker = new CircuitBreaker(2, 60000);

        self::assertSame(1000, (new RedisRiskHealthProvider(null, $client, '{kiwi:t}:issuance:', 10000, $breaker))->snapshot()->riskBackendHealth, 'a closed breaker reports full health');

        // Two consecutive failures open the breaker -> health drops to 0.
        $breaker->recordFailure();
        $breaker->recordFailure();
        self::assertSame(0, (new RedisRiskHealthProvider(null, $client, '{kiwi:t}:issuance:', 10000, $breaker))->snapshot()->riskBackendHealth, 'an open breaker reports 0');

        // A success closes it again.
        $breaker->recordSuccess();
        self::assertSame(1000, (new RedisRiskHealthProvider(null, $client, '{kiwi:t}:issuance:', 10000, $breaker))->snapshot()->riskBackendHealth);

        // No PING may ever be issued on the hot path.
        $client->calls = [];
        (new RedisRiskHealthProvider(null, $client, '{kiwi:t}:issuance:', 10000, $breaker))->snapshot();
        self::assertSame([], array_values(array_filter($client->calls, static fn (array $call): bool => $call[0] === 'PING')), 'snapshot() must never PING redis');
    }

    public function testBackendHealthNominalWithoutBreaker(): void
    {
        $pressure = (new RedisRiskHealthProvider(null, $this->requirePredis()))->snapshot();

        self::assertSame(1000, $pressure->riskBackendHealth, 'no breaker wired -> no observability -> nominal');
    }

    public function testIssuanceHeadroomTracksTheLiveCounter(): void
    {
        $client = $this->requirePredis();
        $counter = new IssuanceCounter($client, '{kiwi:t}:issuance:');
        $key = IssuanceCounter::rateKey('{kiwi:t}:issuance:');
        $provider = fn (): RedisRiskHealthProvider => new RedisRiskHealthProvider(null, $client, '{kiwi:t}:issuance:', 1000);

        // Rate 0 -> full headroom (clamped to the nominal 1000 scale).
        self::assertSame(1000, $provider()->snapshot()->issuanceCapacity);

        $counter->record();
        $counter->record();
        self::assertSame(2, $client->counters[$key]);
        self::assertSame(998, $provider()->snapshot()->issuanceCapacity, 'headroom = global_per_second - current rate');

        $client->counters[$key] = 1000;
        self::assertSame(0, $provider()->snapshot()->issuanceCapacity, 'rate at the global cap -> zero headroom');

        $client->counters[$key] = 5000;
        self::assertSame(0, $provider()->snapshot()->issuanceCapacity, 'a burst above the cap clamps to zero, never negative');
    }

    public function testIssuanceNominalWhenCounterUnobservable(): void
    {
        // No client: no observability -> nominal.
        self::assertSame(1000, (new RedisRiskHealthProvider())->snapshot()->issuanceCapacity);

        // A global cap of 0 (operator disabled the hard limit) -> nominal.
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
