<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Storage\LocalEmergencyLimiter;
use KiwiCaptcha\Risk\Storage\ProcessEmergencyCap;
use PHPUnit\Framework\TestCase;

final class ProcessEmergencyCapTest extends TestCase
{
    /**
     * The pre-audit burst tests construct with warmupRampSecs: 0 (ramp
     * disabled) so they pin the FULL-cap window semantics; the ramp's own
     * behavior is covered by the testWarmup* cases below.
     */
    public function testAllowsExactlyCapPerWindow(): void
    {
        $limiter = new ProcessEmergencyCap(processPerSecond: 100, warmupRampSecs: 0);
        for ($i = 0; $i < 100; $i++) {
            self::assertTrue($limiter->allow(), "allow #" . ($i + 1));
        }
        self::assertTrue($limiter->isOpen());
        self::assertFalse($limiter->allow(), 'the cap+1th must be denied');
    }

    public function testWindowSlides(): void
    {
        $limiter = new ProcessEmergencyCap(processPerSecond: 100, warmupRampSecs: 0);
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
        $limiter = new ProcessEmergencyCap(processPerSecond: 100, warmupRampSecs: 0);
        self::assertFalse($limiter->isOpen());
        $limiter->allow();
        self::assertFalse($limiter->isOpen());
    }

    public function testDefaultCapIsOneProcessPerSecondKnob(): void
    {
        self::assertSame(10000, ProcessEmergencyCap::DEFAULT_PROCESS_PER_SECOND);
        $limiter = new ProcessEmergencyCap(warmupRampSecs: 0);
        for ($i = 0; $i < 10000; $i++) {
            self::assertTrue($limiter->allow(), "default allow #" . ($i + 1));
        }
        self::assertFalse($limiter->allow(), 'the 10001st must be denied at the default cap');
    }

    public function testStampsAreMonotonicNanoseconds(): void
    {
        // The window runs on hrtime(true) nanoseconds (monotonic clock): a
        // wall-clock jump backwards can never extend the window, and a
        // jump forwards can never hold it open early.
        $limiter = new ProcessEmergencyCap(processPerSecond: 100, warmupRampSecs: 0);
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

    /**
     * Warm-up ramp: a fresh process must NOT start with a
     * full burst. At t≈0 the effective cap is the floor
     * max(1, cap/10); here cap 1000 -> floor 100: exactly 100 admissions
     * fit, the 101st is denied.
     */
    public function testWarmupFreshCapAllowsOnlyTheFloorRate(): void
    {
        $limiter = new ProcessEmergencyCap(processPerSecond: 1000, warmupRampSecs: 0.3);
        self::assertSame(0.3, $limiter->warmupRampSecs());
        for ($i = 0; $i < 100; $i++) {
            self::assertTrue($limiter->allow(), "floor allow #" . ($i + 1));
        }
        self::assertTrue($limiter->isOpen(), 'the floor window must be saturated');
        self::assertFalse($limiter->allow(), 'the floor+1th must be denied during the ramp');
    }

    /**
     * After the ramp the cap reaches the full value: a short
     * ramp + sleep (the implementation uses the fixed hrtime clock).
     */
    public function testWarmupReachesFullCapAfterTheRamp(): void
    {
        $limiter = new ProcessEmergencyCap(processPerSecond: 1000, warmupRampSecs: 0.3);
        for ($i = 0; $i < 100; $i++) {
            self::assertTrue($limiter->allow());
        }
        usleep(350_000); // past the 0.3 s ramp
        self::assertFalse($limiter->isOpen(), 'the floor window must have expired with the ramp');
        // The 100 ramp-phase stamps are still inside the sliding 1 s window,
        // so 900 more admissions fit at the full cap (100 + 900 = 1000).
        for ($i = 0; $i < 900; $i++) {
            self::assertTrue($limiter->allow(), "full-cap allow #" . ($i + 1));
        }
        self::assertTrue($limiter->isOpen());
        self::assertFalse($limiter->allow(), 'the full cap+1th must be denied');
    }

    /** The floor is never below 1 admission. */
    public function testWarmupFloorNeverBelowOne(): void
    {
        $limiter = new ProcessEmergencyCap(processPerSecond: 5, warmupRampSecs: 0.3);
        self::assertTrue($limiter->allow(), 'cap 5 floors at max(1, 0) = 1');
        self::assertTrue($limiter->isOpen());
        self::assertFalse($limiter->allow(), 'the 2nd must be denied during the ramp');
    }

    /** The ramp must never raise the cap above the configured value. */
    public function testWarmupNeverExceedsConfiguredCap(): void
    {
        $limiter = new ProcessEmergencyCap(processPerSecond: 10, warmupRampSecs: 0.3);
        for ($i = 0; $i < 1; $i++) {
            self::assertTrue($limiter->allow());
        }
        usleep(350_000);
        // The 1 ramp-phase stamp is still in the 1 s window: 9 more fit.
        for ($i = 0; $i < 9; $i++) {
            self::assertTrue($limiter->allow(), "full-cap allow #" . ($i + 1));
        }
        self::assertFalse($limiter->allow(), 'the ramp must not lift the cap above processPerSecond');
    }

    public function testWarmupRampRejectsNegativeRamp(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new ProcessEmergencyCap(processPerSecond: 100, warmupRampSecs: -1.0);
    }
}
