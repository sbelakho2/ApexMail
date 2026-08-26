<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Fixtures;

/**
 * A phpredis stand-in whose OPT_MAX_RETRIES is configurable (the default
 * 10 mirrors phpredis's real default). Defined normally as a namespaced
 * fixture; the verified-WAIT guard tests load it only when the redis
 * extension is available.
 */
final class RetryEnabledPhpRedisStub extends \Redis
{
    private int $retries;

    public function __construct(int $retries = 10)
    {
        $this->retries = $retries;
    }

    public function getOption(int $option): int
    {
        if ($option === \Redis::OPT_MAX_RETRIES) {
            return $this->retries;
        }

        return 0;
    }
}
