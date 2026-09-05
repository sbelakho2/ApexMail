<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ExecutionChallengeGenerator;
use PHPUnit\Framework\TestCase;

/**
 * Executable execution-capability parity: the widget driver's
 * Kiwi-Execution-Max-Version header literal must equal the PHP core's
 * live generator maximum. The driver advertises the highest execution
 * grammar version it can run, and the server never issues above the
 * advertised value. A driver literal below
 * ExecutionChallengeGenerator::MAX_EXECUTION_VERSION would silently
 * strand every client on an older grammar; a literal above it would
 * claim a version no server can mint. The prose ratchet
 * (tools/ci/version-prose-lint.sh) bans stale capability wording, but
 * prose bans are no substitute for the executable check. This test
 * reads the canonical driver asset
 * (packages/kiwicaptcha-wasm/assets/widget-driver.js, the copy the
 * widget-contract suites exercise) and asserts the exact header
 * literal it sends.
 */
final class WidgetDriverCapabilityParityTest extends TestCase
{
    public function testDriverCapabilityHeaderLiteralEqualsTheGeneratorMaximum(): void
    {
        $path = \dirname(__DIR__).'/../kiwicaptcha-wasm/assets/widget-driver.js';
        if (!is_file($path)) {
            self::markTestSkipped('widget-driver.js not present (monorepo layout expected at packages/kiwicaptcha-wasm/assets/)');
        }
        $source = (string) file_get_contents($path);
        self::assertSame(
            1,
            preg_match('/Kiwi-Execution-Max-Version"\]\s*=\s*"([0-9]+)"/', $source, $matches),
            'the driver must assign the Kiwi-Execution-Max-Version header exactly once',
        );
        self::assertSame(
            (string) ExecutionChallengeGenerator::MAX_EXECUTION_VERSION,
            $matches[1],
            'the driver must advertise the live generator maximum (currently '.ExecutionChallengeGenerator::MAX_EXECUTION_VERSION.'), never a stale literal',
        );
    }
}
