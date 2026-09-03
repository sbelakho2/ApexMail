<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Composer distribution isolation of the test-only execution-trace
 * fixture: the browser-trace synthesizer must never ship to production
 * consumers. The production PSR-4 map (KiwiCaptcha\ → src/) may not
 * reach it, and the autoload-dev map (KiwiCaptcha\Tests\ → tests/)
 * must cover its new home — the same default-off boundary the Rust
 * crate draws with its `test-fixtures` feature gate.
 */
final class PackageAutoloadDevIsolationTest extends TestCase
{
    private const FIXTURE_CLASS = 'KiwiCaptcha\Tests\Support\ExecutionTraceFixture';

    public function testExecutionTraceFixtureLivesUnderAutoloadDevOnly(): void
    {
        $root = \dirname(__DIR__);
        $composer = json_decode((string) file_get_contents($root.'/composer.json'), true, 512, JSON_THROW_ON_ERROR);
        $autoload = $composer['autoload']['psr-4'];
        $autoloadDev = $composer['autoload-dev']['psr-4'];

        self::assertSame('src/', $autoload['KiwiCaptcha\\'], 'the production map must be exactly the src/ tree');

        // No production prefix may resolve (or even name) the fixture:
        // any KiwiCaptcha\TestSupport prefix would leak the synthesizer
        // into a --no-dev install.
        self::assertArrayNotHasKey('KiwiCaptcha\\TestSupport', $autoload);
        foreach ($autoload as $prefix => $dir) {
            self::assertStringNotContainsString('TestSupport', (string) $dir, sprintf('the production prefix %s must not map a TestSupport directory', $prefix));
            self::assertStringNotContainsString('TestSupport', (string) $prefix, sprintf('the production prefix %s must not name TestSupport', $prefix));
        }
        $prodFile = $root.'/src/TestSupport/ExecutionTraceFixture.php';
        self::assertFileDoesNotExist($prodFile, 'the fixture must not sit under the production src/ tree');

        // The dev map covers the fixture's new home, and the class file
        // is exactly where the dev PSR-4 resolution expects it.
        self::assertSame('tests/', $autoloadDev['KiwiCaptcha\\Tests\\'], 'the dev map must cover the tests/ tree');
        self::assertFileExists($root.'/tests/Support/ExecutionTraceFixture.php');

        $relative = str_replace('KiwiCaptcha\\Tests\\', '', self::FIXTURE_CLASS);
        self::assertFileExists(sprintf('%s/%s%s.php', $root, 'tests/', str_replace('\\', '/', $relative)));

        $source = (string) file_get_contents($root.'/tests/Support/ExecutionTraceFixture.php');
        self::assertStringContainsString('namespace KiwiCaptcha\Tests\Support;', $source, 'the fixture must declare the dev-only namespace');
    }
}
