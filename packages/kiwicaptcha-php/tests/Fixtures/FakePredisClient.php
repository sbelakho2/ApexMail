<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Fixtures;

/**
 * In-memory stand-in for Predis\Client used by the RedisStorage tests.
 *
 * There is no real Redis in CI. Predis dispatches every command through
 * `__call`, so this fake intercepts exactly the commands RedisStorage sends
 * (get, set, del, eval, expire) and emulates the Lua scripts' semantics:
 *
 *  - GETDEL script: return-and-delete (atomic single-use).
 *  - INCR script: per-key counter with cap enforcement, DECR on overflow,
 *    and TTL set on first increment.
 *
 * Every call is recorded in {@see FakePredisClient::$calls} so tests can
 * assert on the Redis commands issued (Lua usage, EX expiration, etc.).
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
            'GET' => $this->store[(string) $arguments[0]] ?? null,
            'SET' => $this->fakeSet($arguments),
            'DEL' => $this->fakeDel($arguments),
            'EXPIRE' => 1,
            'EVAL' => $this->fakeEval($arguments),
            default => null,
        };
    }

    /** @param list<mixed> $arguments */
    private function fakeSet(array $arguments): bool
    {
        $key = (string) $arguments[0];
        $this->store[$key] = (string) $arguments[1];
        if (($arguments[2] ?? null) === 'EX') {
            $this->expirations[$key] = (int) $arguments[3];
        }

        return true;
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

        if (str_contains($script, 'GETDEL')) {
            $key = (string) $keys[0];
            if (!isset($this->store[$key])) {
                return null;
            }
            $value = $this->store[$key];
            unset($this->store[$key]);

            return $value;
        }

        if (str_contains($script, "redis.call('INCR'")) {
            $key = (string) $keys[0];
            $max = (int) $rest[0];
            $ttl = (int) ($rest[1] ?? 0);
            $next = (int) ($this->store[$key] ?? 0) + 1;
            if ($next > $max) {
                // Mirrors the Lua DECR-on-overflow.
                $this->store[$key] = (string) ($next - 1);

                return 0;
            }
            $this->store[$key] = (string) $next;
            if ($next === 1) {
                $this->expirations[$key] = $ttl;
            }

            return 1;
        }

        return null;
    }
}
