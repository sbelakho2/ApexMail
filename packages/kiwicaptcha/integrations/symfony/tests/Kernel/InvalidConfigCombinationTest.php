<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use PHPUnit\Framework\TestCase;

/**
 * Impossible configuration combinations must fail at container compilation,
 * not silently produce a limiter/captcha that can never work.
 */
final class InvalidConfigCombinationTest extends TestCase
{
    public function testRotationShorterThanWindowFailsCompilation(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('rate_limit_rotation_secs');

        (new InvalidRotationTestKernel('test', true))->boot();
    }

    public function testMinDurationAtOrAboveTtlFailsCompilation(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('min_duration_ms');

        (new InvalidMinDurationTestKernel('test', true))->boot();
    }
}
