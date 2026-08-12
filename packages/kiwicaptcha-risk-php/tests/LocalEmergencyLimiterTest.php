<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Storage\LocalEmergencyLimiter;
use PHPUnit\Framework\TestCase;

final class LocalEmergencyLimiterTest extends TestCase
{
    public function testAllowsExactlyOneHundredPerWindow(): void
    {
        $limiter = new LocalEmergencyLimiter();
        for ($i = 0; $i < 100; $i++) {
            self::assertTrue($limiter->allow(), "allow #" . ($i + 1));
        }
        self::assertTrue($limiter->isOpen());
        self::assertFalse($limiter->allow(), 'the 101st must be denied');
    }

    public function testWindowSlides(): void
    {
        $limiter = new LocalEmergencyLimiter();
        for ($i = 0; $i < 100; $i++) {
            $limiter->allow();
        }
        // The window is 1 second; after sleeping past it, the limiter
        // recovers (timestamps are pruned on the next call).
        usleep(1_050_000);
        self::assertFalse($limiter->isOpen());
        self::assertTrue($limiter->allow());
    }

    public function testIsOpenFalseWhenIdle(): void
    {
        $limiter = new LocalEmergencyLimiter();
        self::assertFalse($limiter->isOpen());
        $limiter->allow();
        self::assertFalse($limiter->isOpen());
    }
}
