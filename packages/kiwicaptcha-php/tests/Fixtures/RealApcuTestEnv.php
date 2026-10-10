<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Fixtures;

use PHPUnit\Framework\AssertionFailedError;

/**
 * The skip-or-fail gate for the real-APCu leg of the storage contract
 * suite, the exact pattern of {@see RealRedisTestEnv}.
 *
 * The environment where this suite usually runs lacks the APCu
 * extension, so the real-backend leg auto-skips there and the emulated
 * backend carries the whole invariant suite instead; that limitation
 * is documented on the storage class itself. A dedicated CI lane that
 * installs the extension sets KIWI_REQUIRE_REAL_APCU_TESTS=1 together
 * with apc.enable_cli=1. There a missing extension or a disabled cli
 * segment fails loudly instead of skipping, so a broken lane image
 * shows up red rather than silently green on the emulation alone.
 */
final class RealApcuTestEnv
{
    /**
     * Whether the fail-rather-than-skip mode is on: the dedicated CI
     * lane sets KIWI_REQUIRE_REAL_APCU_TESTS=1.
     */
    public static function required(): bool
    {
        $flag = getenv('KIWI_REQUIRE_REAL_APCU_TESTS');

        return \is_string($flag) && $flag !== '' && $flag !== '0';
    }

    /**
     * Whether the real APCu backend is usable in this process: the
     * extension loaded, and the segment enabled (a cli process also
     * needs apc.enable_cli=1). The probe writes and reads one key,
     * because a present-but-disabled segment answers exactly like an
     * absent extension.
     */
    public static function available(): bool
    {
        if (!\function_exists('apcu_store')) {
            return false;
        }
        if (\function_exists('apcu_enabled') && !apcu_enabled()) {
            return false;
        }
        $probe = 'kiwi-apcu-env-probe-'.bin2hex(random_bytes(4));
        if (!apcu_store($probe, 1, 1)) {
            return false;
        }
        apcu_delete($probe);

        return true;
    }

    /**
     * The gate the real leg calls: skip (or fail, in the required
     * mode) with one clear message when the environment is absent.
     */
    public static function gate(string $purpose): bool
    {
        if (self::available()) {
            return true;
        }
        $what = \function_exists('apcu_store')
            ? 'the APCu segment is disabled for this process (a cli run needs apc.enable_cli=1)'
            : 'the APCu extension is not loaded';
        if (self::required()) {
            throw new AssertionFailedError(
                'KIWI_REQUIRE_REAL_APCU_TESTS is set but '.$what.'; '.$purpose.' must run in the dedicated real-APCu CI lane'
            );
        }

        return false;
    }
}
