<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * The impossible combination (standard mode, telemetry off + enforcement on)
 * must fail configuration — not silently accept a trap that rejects every
 * legitimate solve.
 */
final class ImpossibleTelemetryTest extends TestCase
{
    public function testEnforceTelemetryWithTelemetryOffFailsConfiguration(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('enforce_telemetry');

        $kernel = new ImpossibleTelemetryTestKernel('test', true);
        $kernel->boot();
    }
}
