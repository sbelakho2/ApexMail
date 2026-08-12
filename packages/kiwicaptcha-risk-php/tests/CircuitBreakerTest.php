<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Breaker\CircuitBreaker;
use PHPUnit\Framework\TestCase;

final class CircuitBreakerTest extends TestCase
{
    public function testClosedByDefault(): void
    {
        self::assertFalse((new CircuitBreaker())->isOpen());
    }

    public function testOpensAfterThresholdFailures(): void
    {
        $breaker = new CircuitBreaker(2, 60_000);
        self::assertFalse($breaker->isOpen());
        $breaker->recordFailure();
        self::assertFalse($breaker->isOpen());
        $breaker->recordFailure();
        self::assertTrue($breaker->isOpen());
    }

    public function testClosesAfterWindow(): void
    {
        $breaker = new CircuitBreaker(2, 50);
        $breaker->recordFailure();
        $breaker->recordFailure();
        self::assertTrue($breaker->isOpen());
        usleep(60_000);
        self::assertFalse($breaker->isOpen());
    }

    public function testSuccessResetsCounters(): void
    {
        $breaker = new CircuitBreaker(2, 60_000);
        $breaker->recordFailure();
        $breaker->recordSuccess();
        $breaker->recordFailure();
        self::assertFalse($breaker->isOpen());
        $breaker->recordFailure();
        self::assertTrue($breaker->isOpen());
    }

    public function testFailureWhileOpenDoesNotExtendWindow(): void
    {
        $breaker = new CircuitBreaker(2, 50);
        $breaker->recordFailure();
        $breaker->recordFailure();
        self::assertTrue($breaker->isOpen());
        $breaker->recordFailure();
        usleep(60_000);
        self::assertFalse($breaker->isOpen());
    }

    public function testInvalidArgumentsThrow(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new CircuitBreaker(0, 1000);
    }
}
