<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Fixtures;

use PHPUnit\Framework\AssertionFailedError;

/**
 * The fail-rather-than-skip gate for the real-Redis suites.
 *
 * The dedicated real-Redis CI lane (the "PHP core real-Redis
 * fault/topology" job in .github/workflows/ci.yml) publishes
 * `KC_REDIS_URL` and `TEST_REDIS_URL` together with
 * KIWI_REQUIRE_REAL_REDIS_TESTS=1. When the flag is set and a required
 * piece of the environment is absent, the suite fails with a clear
 * message instead of skipping, so a lost Redis service or a broken
 * runner image shows up red. When the flag is unset the ordinary skip
 * behavior is unchanged, and the Redis-less version-matrix lanes keep
 * their legitimate skips.
 */
final class RealRedisTestEnv
{
    /**
     * Whether the fail-rather-than-skip mode is on: the dedicated CI
     * lane sets KIWI_REQUIRE_REAL_REDIS_TESTS=1.
     */
    public static function required(): bool
    {
        $flag = getenv('KIWI_REQUIRE_REAL_REDIS_TESTS');

        return \is_string($flag) && $flag !== '' && $flag !== '0';
    }

    /**
     * Resolve the shared real-Redis URL (`KC_REDIS_URL` first, then
     * `TEST_REDIS_URL`), or null when neither is set.
     */
    public static function redisUrl(): ?string
    {
        $url = getenv('KC_REDIS_URL');
        if (\is_string($url) && $url !== '') {
            return $url;
        }
        $url = getenv('TEST_REDIS_URL');

        return \is_string($url) && $url !== '' ? $url : null;
    }

    /**
     * The Redis URL the caller may use, or null when unset and the
     * flag is off. In the required mode an unset URL is a hard
     * failure: the dedicated lane must always publish the Redis env.
     */
    public static function requireRedis(string $purpose): ?string
    {
        $url = self::redisUrl();
        if ($url !== null) {
            return $url;
        }
        self::failWhenRequired('no KC_REDIS_URL/TEST_REDIS_URL is set', $purpose);

        return null;
    }

    /**
     * True when the binary is on `PATH`. In the required mode a
     * missing binary fails the suite: the topology lanes boot their
     * own cluster and sentinel from the local redis-server build.
     */
    public static function requireBinary(string $binary, string $purpose): bool
    {
        $path = trim((string) shell_exec('command -v '.$binary.' 2>/dev/null'));
        if ($path !== '') {
            return true;
        }
        self::failWhenRequired("{$binary} is not on PATH", $purpose);

        return false;
    }

    /**
     * True when every extension is loaded. In the required mode a
     * missing extension fails the suite, for example pcntl and posix
     * in the worker-death matrix.
     *
     * @param list<string> $extensions
     */
    public static function requireExtensions(array $extensions, string $purpose): bool
    {
        foreach ($extensions as $extension) {
            if (\extension_loaded($extension)) {
                continue;
            }
            self::failWhenRequired("the {$extension} extension is not loaded", $purpose);

            return false;
        }

        return true;
    }

    /**
     * Fail when the required mode is on and the environment is
     * incomplete; the skip path is then replaced by a loud failure.
     */
    public static function failWhenRequired(string $what, string $purpose): void
    {
        if (!self::required()) {
            return;
        }
        throw new AssertionFailedError(
            'KIWI_REQUIRE_REAL_REDIS_TESTS is set but '.$what.'; '.$purpose.' must run in the dedicated real-Redis CI lane'
        );
    }
}
