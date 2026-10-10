<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use PHPUnit\Framework\TestCase;

/**
 * The target-failure leak watermark (target_failure.lua) over real
 * Redis: one failure leaks per minute, and the watermark advances only
 * by whole leaked minutes. A `ts = now` reset on every write erases the sub-minute remainder. A steady trickle of failures then never leaks.
 *
 * The scenario: three failures spaced 30 s apart. After the third
 * failure exactly one minute has elapsed since the watermark origin, so
 * exactly one failure must have leaked (fails = 3 - 1 = 2). The clock
 * is Redis TIME inside the script, so the test backdates the stored
 * watermark between calls to emulate the spacings.
 */
final class TargetFailureLeakTest extends TestCase
{
    private const TARGET = '5e2a9b4c1d7f38e6a0b5c9d2e4f6a813';

    private \Predis\Client $client;

    private RedisRiskStateStore $store;

    private string $namespace;

    protected function setUp(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if (!\is_string($url) || $url === '') {
            self::markTestSkipped('RISK_REDIS_URL not set; start redis with: docker run -d -p 6399:6379 redis:7-alpine');
        }
        $this->namespace = 'tfleak'.bin2hex(random_bytes(4));
        $this->client = RedisRiskStateStore::createClient($url);
        $this->client->ping();
        $this->store = new RedisRiskStateStore($this->client, namespace: $this->namespace);
    }

    protected function tearDown(): void
    {
        if (!isset($this->client)) {
            return;
        }
        try {
            $prefix = '{kiwi:'.$this->namespace.':target:5e}';
            $keys = $this->client->keys($prefix.'*');
            if ($keys !== []) {
                $this->client->del(...$keys);
            }
        } catch (\Throwable) {
            // a dead instance must not fail the shutdown path
        }
    }

    public function testSubMinuteFailuresStillLeakOnePerMinute(): void
    {
        $key = '{kiwi:'.$this->namespace.':target:5e}:risk:tgt:'.self::TARGET;

        // Failure 1: the record is created, the watermark stamps now.
        $state = $this->store->registerTargetFailure(self::TARGET, 'src100000000000000000000000000', 'as64496');
        self::assertSame(1, $state['fails']);
        $t1 = (int) $this->client->hget($key, 'ts');
        self::assertGreaterThan(0, $t1, 'the first write stamps the watermark');

        // Emulate "30 s later": backdate the watermark 30 s.
        $this->client->hset($key, 'ts', (string) ($t1 - 30000));

        // Failure 2 (30 s after the origin): nothing leaks yet, but the
        // watermark must keep the remainder instead of resetting to now.
        $state = $this->store->registerTargetFailure(self::TARGET, 'src200000000000000000000000000', 'as64496');
        self::assertSame(2, $state['fails']);
        $tsAfter2 = (int) $this->client->hget($key, 'ts');
        self::assertLessThan(
            $t1,
            $tsAfter2,
            'the watermark must not reset to now on a sub-minute failure (got '.$tsAfter2.', t1 '.$t1.')',
        );

        // Emulate "30 s later still": 60 s since the watermark origin.
        $this->client->hset($key, 'ts', (string) ($tsAfter2 - 30000));

        // Failure 3: exactly one minute has elapsed, so exactly one
        // failure leaks before the write counts (2 - 1 + 1 = 2). A
        // ts = now reset erases both remainders and answers 3.
        $state = $this->store->registerTargetFailure(self::TARGET, 'src300000000000000000000000000', 'as64496');
        self::assertSame(
            2,
            $state['fails'],
            'one failure must leak after a minute of sub-minute-spaced failures (got '.$state['fails'].')',
        );
    }
}
