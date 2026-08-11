<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

/**
 * In-memory stand-in for Predis\Client used by the RedisAdmissionSemaphore
 * tests (no real Redis in CI).
 *
 * Predis dispatches every command through `__call`, so this fake intercepts
 * exactly the commands the semaphore sends (eval, expire, del) and emulates
 * the Lua scripts' semantics:
 *
 *  - ACQUIRE script: atomic INCR admission test with cap enforcement and a
 *    watchdog TTL on first increment; the INCR is rolled back on rejection.
 *  - RELEASE script: DECR with a floor at 0 (negative counts DEL the key).
 *
 * Every call is recorded in {@see FakePredisClient::$calls} so tests can
 * assert on the Redis commands issued.
 */
final class FakePredisClient extends \Predis\Client
{
    /** @var array<string, string> */
    public array $store = [];

    /** @var array<string, int> */
    public array $expirations = [];

    /** @var list<array{0: string, 1: list<mixed>}> */
    public array $calls = [];

    public function __construct()
    {
        // Deliberately skip the parent constructor: no connection setup.
    }

    public function __call($commandID, $arguments)
    {
        $this->calls[] = [strtoupper((string) $commandID), $arguments];

        return match (strtoupper((string) $commandID)) {
            'DEL' => $this->fakeDel($arguments),
            'EXPIRE' => 1,
            'EVAL' => $this->fakeEval($arguments),
            default => null,
        };
    }

    /** @param list<mixed> $arguments */
    private function fakeDel(array $arguments): int
    {
        $removed = 0;
        foreach ($arguments as $key) {
            if (isset($this->store[(string) $key])) {
                unset($this->store[(string) $key]);
                $removed++;
            }
        }

        return $removed;
    }

    /** @param list<mixed> $arguments */
    private function fakeEval(array $arguments): mixed
    {
        $script = (string) $arguments[0];
        $numKeys = (int) $arguments[1];
        $keysAndArgs = \array_slice($arguments, 2);
        $keys = \array_slice($keysAndArgs, 0, $numKeys);
        $rest = \array_slice($keysAndArgs, $numKeys);

        if (str_contains($script, "redis.call('INCR'")) {
            // Acquire: KEYS[1] = counter key, ARGV[1] = cap, ARGV[2] = TTL.
            $key = (string) $keys[0];
            $cap = (int) $rest[0];
            $ttl = (int) ($rest[1] ?? 0);
            $n = (int) ($this->store[$key] ?? 0) + 1;
            $this->store[$key] = (string) $n;
            if ($n === 1) {
                $this->expirations[$key] = $ttl;
            }
            if ($n > $cap) {
                // Roll the INCR back, as the Lua script does.
                $this->store[$key] = (string) ($n - 1);

                return 0;
            }

            return 1;
        }

        if (str_contains($script, "redis.call('DECR'")) {
            // Release: DECR with floor at 0 — a negative count DELs the key.
            $key = (string) $keys[0];
            $n = (int) ($this->store[$key] ?? 0) - 1;
            if ($n < 0) {
                unset($this->store[$key]);
            } else {
                $this->store[$key] = (string) $n;
            }

            return $n;
        }

        return null;
    }
}
