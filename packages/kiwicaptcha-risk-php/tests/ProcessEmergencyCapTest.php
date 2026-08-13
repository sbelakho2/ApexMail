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

    public function testBcAliasStillResolves(): void
    {
        self::assertTrue(class_exists(LocalEmergencyLimiter::class));
        $limiter = new LocalEmergencyLimiter();
        self::assertInstanceOf(ProcessEmergencyCap::class, $limiter);
        self::assertTrue($limiter->allow());
    }
}
