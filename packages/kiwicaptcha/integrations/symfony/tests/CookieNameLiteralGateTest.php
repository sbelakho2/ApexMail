<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use PHPUnit\Framework\TestCase;

/**
 * WP9 P5 gate: the cookie literals `__Host-kiwi-session` and
 * `__Host-kiwi-device` appear only in the Configuration defaults and
 * the cookie classes (plus the extension wiring that reads them).
 * A literal anywhere else is a config-copy bug waiting to disagree
 * with a renamed cookie.
 */
final class CookieNameLiteralGateTest extends TestCase
{
    private const ALLOWED = [
        'src/Risk/ContinuityCookie.php',
        'src/Risk/TrustedDeviceCookie.php',
        'src/DependencyInjection/Configuration.php',
        'src/DependencyInjection/KiwiCaptchaExtension.php',
    ];

    public function testCookieLiteralsAppearOnlyInTheConfigAndCookieClasses(): void
    {
        $srcDir = dirname(__DIR__).'/src';
        $offenders = [];
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($srcDir, \FilesystemIterator::SKIP_DOTS),
        );
        foreach ($iterator as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }
            $relative = substr($file->getPathname(), \strlen($srcDir) - 3);
            if (\in_array($relative, self::ALLOWED, true)) {
                continue;
            }
            $contents = (string) file_get_contents($file->getPathname());
            if (str_contains($contents, '__Host-kiwi-session') || str_contains($contents, '__Host-kiwi-device')) {
                $offenders[] = $relative;
            }
        }
        self::assertSame([], $offenders, 'cookie literals must live only in Configuration defaults and the cookie classes');
    }
}
