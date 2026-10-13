<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Storage\RealApcuBackend;
use PHPUnit\Framework\TestCase;

/**
 * The cli-refusal decision of the real APCu backend. A CLI process
 * (RoadRunner worker, queue consumer) owns a private APCu segment
 * invisible to the web tier. Construction therefore refuses the cli
 * SAPI unless the apc.enable_cli precondition AND the
 * allowPrivateCliSegment acknowledgement hold together. The ini gives
 * a CLI process a segment; it never says the segment is safe. Granting
 * it alone would let every RoadRunner worker construct against a
 * foreign private segment, where (N-1)/N of the solves fail at random.
 */
final class RealApcuBackendCliTest extends TestCase
{
    public function testTheCliSapiRefusesWithoutPreconditionAndAcknowledgement(): void
    {
        // Each input alone refuses: the ini without the flag leaves
        // every CLI worker on its own private segment, the flag
        // without the ini leaves no segment at all.
        self::assertTrue(RealApcuBackend::cliConstructionRefused('cli', false));
        self::assertTrue(RealApcuBackend::cliConstructionRefused('cli', true));
        self::assertTrue(RealApcuBackend::cliConstructionRefused('cli', false, true));
    }

    public function testThePreconditionAndTheAcknowledgementTogetherConstruct(): void
    {
        self::assertFalse(RealApcuBackend::cliConstructionRefused('cli', true, true));
    }

    public function testTheWebSapisSkipTheCheck(): void
    {
        self::assertFalse(RealApcuBackend::cliConstructionRefused('fpm-fcgi', false));
        self::assertFalse(RealApcuBackend::cliConstructionRefused('fpm-fcgi', false, true));
        self::assertFalse(RealApcuBackend::cliConstructionRefused('apache2handler', true, false));
    }

    public function testTheEnableCliIniParsesAsABoolean(): void
    {
        self::assertTrue(RealApcuBackend::apcEnableCliIni('1'));
        self::assertTrue(RealApcuBackend::apcEnableCliIni('true'));
        self::assertTrue(RealApcuBackend::apcEnableCliIni(' on '));
        self::assertTrue(RealApcuBackend::apcEnableCliIni('Yes'));
        self::assertFalse(RealApcuBackend::apcEnableCliIni('0'));
        self::assertFalse(RealApcuBackend::apcEnableCliIni(''));
        self::assertFalse(RealApcuBackend::apcEnableCliIni('off'));
        // An unset ini entry (the extension is not loaded) reads off.
        self::assertFalse(RealApcuBackend::apcEnableCliIni(false));
    }
}
