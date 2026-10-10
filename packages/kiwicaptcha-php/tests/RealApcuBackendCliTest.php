<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Storage\RealApcuBackend;
use PHPUnit\Framework\TestCase;

/**
 * The cli-refusal decision of the real APCu backend: a CLI process
 * (RoadRunner worker, queue consumer) owns a private APCu segment
 * invisible to the web tier, so construction refuses it outside test
 * runners.
 */
final class RealApcuBackendCliTest extends TestCase
{
    public function testTheCliSapiRefusesOutsideTestRunners(): void
    {
        self::assertTrue(RealApcuBackend::cliConstructionRefused('cli', false));
    }

    public function testTestRunnersAndWebSapisConstruct(): void
    {
        self::assertFalse(RealApcuBackend::cliConstructionRefused('cli', true));
        self::assertFalse(RealApcuBackend::cliConstructionRefused('fpm-fcgi', false));
        self::assertFalse(RealApcuBackend::cliConstructionRefused('apache2handler', false));
    }
}
