<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Storage\LocalEmergencyLimiter;
use KiwiCaptcha\Risk\Storage\ProcessEmergencyCap;
use PHPUnit\Framework\TestCase;

final class ProcessEmergencyCapTest extends TestCase
{
    public function testAllowsExactlyCapPerWindow(): void
    {
        $limiter = new ProcessEmergencyCap(processPerSecond: 100);
        for ($i = 0; $i < 100; $i++) {
            self::assertTrue($limiter->allow(), "allow #" . ($i + 1));
        }
        self::assertTrue($limiter->isOpen());
        self::assertFalse($limiter->allow(), 'the cap+1th must be denied');
    }

    public function testWindowSlides(): void
    {
        $limiter = new ProcessEmergencyCap(processPerSecond: 100);
        for ($i = 0; $i < 100; $i++) {
            $limiter->allow();
        }
        // The window is 1 second; after sleeping past it, the limiter
        // recovers (expired timestamps are dequeued on the next call).
        usleep(1_050_000);
        self::assertFalse($limiter->isOpen());
        self::assertTrue($limiter->allow());
    }

    public function testIsOpenFalseWhenIdle(): void
    {
        $limiter = new ProcessEmergencyCap(processPerSecond: 100);
        self::assertFalse($limiter->isOpen());
        $limiter->allow();
        self::assertFalse($limiter->isOpen());
    }

    public function testDefaultCapIsOneProcessPerSecondKnob(): void
    {
        self::assertSame(10000, ProcessEmergencyCap::DEFAULT_PROCESS_PER_SECOND);
        $limiter = new ProcessEmergencyCap();
        for ($i = 0; $i < 10000; $i++) {
            self::assertTrue($limiter->allow(), "default allow #" . ($i + 1));
        }
        self::assertFalse($limiter->allow(), 'the 10001st must be denied at the default cap');
    }

    public function testStampsAreMonotonicNanoseconds(): void
    {
        // The window runs on hrtime(true) NANOSECONDS (monotonic clock): a
        // wall-clock jump backwards can never extend the window, and a
        // jump forwards can never hold it open early.
        $limiter = new ProcessEmergencyCap(processPerSecond: 100);
        self::assertTrue($limiter->allow());
        $prop = new \ReflectionProperty(ProcessEmergencyCap::class, 'stamps');
        $queue = $prop->getValue($limiter);
        $first = $queue->bottom();
        self::assertIsInt($first, 'stamps must be hrtime(true) nanoseconds (integer, monotonic)');
        self::assertGreaterThan(10_000_000_000, $first, 'nanosecond scale (microtime(true) is ~1.7e9, never beyond 1e10)');

        // The clock is monotonic: a later allowance is never earlier.
        self::assertTrue($limiter->allow());
        self::assertGreaterThanOrEqual($first, $queue->top(), 'hrtime must never move backwards');

        // The window semantics still hold on the nanosecond clock.
        for ($i = 0; $i < 98; $i++) {
            self::assertTrue($limiter->allow(), "allow #" . ($i + 3));
        }
        self::assertTrue($limiter->isOpen());
        self::assertFalse($limiter->allow(), 'the cap+1th must be denied on the nanosecond window too');
        usleep(1_050_000);
        self::assertFalse($limiter->isOpen(), 'the nanosecond window must slide after 1 s');
        self::assertTrue($limiter->allow());
    }

    public function testBcAliasStillResolves(): void
    {
        self::assertTrue(class_exists(LocalEmergencyLimiter::class));
        $limiter = new LocalEmergencyLimiter();
        self::assertInstanceOf(ProcessEmergencyCap::class, $limiter);
        self::assertTrue($limiter->allow());
    }
}
