<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\RedisRiskHealthProvider;
use BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use PHPUnit\Framework\TestCase;

/**
 * Live resource-pressure provider: remaining Redis admission-semaphore slots
 * (argonCapacity), issuance headroom (not observable -> nominal), and risk
 * Redis health via PING (riskBackendHealth 0 on failure). Any unobservable
 * source must report the nominal 1000 — pressure is an availability signal
 * and an unavailable source must never fabricate artificial scarcity.
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

    public function testBackendHealthDropsToZeroOnPingFailure(): void
    {
        $client = new class extends \Predis\Client {
            public function ping(): string
            {
                throw new \RuntimeException('connection refused');
            }
        };
        $pressure = (new RedisRiskHealthProvider(null, $client))->snapshot();

        self::assertSame(0, $pressure->riskBackendHealth);
        self::assertSame(1000, $pressure->argonCapacity, 'a failing backend must not drag argon capacity with it');
    }

    public function testBackendHealthNominalWhenPingSucceeds(): void
    {
        $pressure = (new RedisRiskHealthProvider(null, $this->requirePredis()))->snapshot();

        self::assertSame(1000, $pressure->riskBackendHealth);
    }
}
