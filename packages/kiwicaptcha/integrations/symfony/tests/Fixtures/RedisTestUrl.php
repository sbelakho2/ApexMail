<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

/**
 * The shared real-Redis URL resolver: the CI publishes Redis on the
 * KC_REDIS_URL / TEST_REDIS_URL value (GitHub Actions exposes 6379), while
 * the local development default remains tcp://127.0.0.1:6399. Tests must
 * never hard-code a port that the CI does not expose.
 */
final class RedisTestUrl
{
    public static function resolve(): ?string
    {
        $env = getenv('KC_REDIS_URL');
        if (\is_string($env) && $env !== '') {
            return $env;
        }
        $env = getenv('TEST_REDIS_URL');
        if (\is_string($env) && $env !== '') {
            return $env;
        }

        // No explicit Redis test environment: the real-Redis tests SKIP
        // (they run exclusively in the CI job that provisions the Redis
        // service). A silent local-development fallback would execute
        // real-Redis suites in jobs that do not provision Redis.
        return null;
    }
}
