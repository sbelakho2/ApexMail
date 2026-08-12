<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

/**
 * In-memory stand-in for Predis\Client used by the Redis-backed semaphore and
 * rate-limiter tests (no real Redis in CI).
 *
 * Predis dispatches every command through `__call`, so this fake intercepts
 * exactly the commands the bundle sends and emulates their semantics:
 *
 *  - TIME: reads the configurable clock ({@see self::setTimeMs()}) so tests
 *    can advance the "Redis server time" to exercise lease/window expiry.
 *  - ZSET primitives: ZADD, ZREM, ZREMRANGEBYSCORE, ZCARD, PEXPIRE — used by
 *    the tokenized-lease semaphore (sorted set of lease tokens) and the
 *    sliding-window rate limiter (sorted sets of hit timestamps).
 *  - EVAL: interprets the bundle's three Lua scripts by their shape:
 *      - semaphore ACQUIRE (1 key, 3 args, TIME + prune + cap + ZADD),
 *      - semaphore RELEASE (ZREM of one member),
 *      - rate-limiter (2 keys, 4 args, TIME + prune both + caps + ZADD both),
 *    mirroring the scripts' semantics exactly.
 *
 * Every call is recorded in {@see FakePredisClient::$calls} so tests can
 * assert on the Redis commands issued.
 */
final class FakePredisClient extends \Predis\Client
{
    /** @var array<string, array<string, float>> sorted sets: key => member => score */
    public array $zsets = [];

    /** @var array<string, int> PEXPIRE/EXPIRE deadlines in ms */
    public array $expirations = [];

    /** @var list<array{0: string, 1: list<mixed>}> */
    public array $calls = [];

    private float $clockMs = 0.0;

    public function __construct()
    {
        // Deliberately skip the parent constructor: no connection setup.
    }

    /** @internal test hook: advance the fake Redis server clock (ms). */
    public function setTimeMs(float $ms): void
    {
        $this->clockMs = $ms;
    }

    /** Current fake server time in ms (mirrors the Lua TIME read). */
    public function timeMs(): float
    {
        return $this->clockMs;
    }

    /** Redis TIME emulation: [seconds, microseconds]. */
    public function time(): array
    {
        $secs = (int) floor($this->clockMs / 1000);

        return [$secs, (int) (($this->clockMs - $secs * 1000) * 1000)];
    }

    /** Number of live members (leases/hits) in a sorted set. */
    public function zcard(string $key): int
    {
        return \count($this->zsets[$key] ?? []);
    }

    /** Members of a sorted set ordered by score (live leases/hits). */
    public function zmembers(string $key): array
    {
        $members = $this->zsets[$key] ?? [];
        asort($members);

        return array_keys($members);
    }

    public function __call($commandID, $arguments)
    {
        $this->calls[] = [strtoupper((string) $commandID), $arguments];

        return match (strtoupper((string) $commandID)) {
            'TIME' => $this->fakeTime(),
            'ZADD' => $this->fakeZadd($arguments),
            'ZREM' => $this->fakeZrem($arguments),
            'ZREMRANGEBYSCORE' => $this->fakeZremrangebyscore($arguments),
            'ZCARD' => $this->zcard((string) $arguments[0]),
            'PEXPIRE' => $this->fakePexpire($arguments),
            'EXPIRE' => $this->fakePexpire($arguments),
            'DEL' => $this->fakeDel($arguments),
            'EVAL' => $this->fakeEval($arguments),
            default => null,
        };
    }

    /** @return array{0: int, 1: int} [seconds, microseconds] */
    private function fakeTime(): array
    {
        $sec = (int) floor($this->clockMs / 1000);

        return [$sec, (int) round(($this->clockMs - $sec * 1000) * 1000)];
    }

    /** @param list<mixed> $arguments */
    private function fakeZadd(array $arguments): int
    {
        $key = (string) $arguments[0];
        $added = 0;
        $count = \count($arguments) - 1;
        for ($i = 1; $i < $count; $i += 2) {
            $score = (float) $arguments[$i];
            $member = (string) $arguments[$i + 1];
            if (!isset($this->zsets[$key][$member])) {
                $added++;
            }
            $this->zsets[$key][$member] = $score;
        }

        return $added;
    }

    /** @param list<mixed> $arguments */
    private function fakeZrem(array $arguments): int
    {
        $key = (string) $arguments[0];
        $removed = 0;
        foreach (\array_slice($arguments, 1) as $member) {
            if (isset($this->zsets[$key][(string) $member])) {
                unset($this->zsets[$key][(string) $member]);
                $removed++;
            }
        }
        if (isset($this->zsets[$key]) && $this->zsets[$key] === []) {
            unset($this->zsets[$key]);
        }

        return $removed;
    }

    /** @param list<mixed> $arguments */
    private function fakeZremrangebyscore(array $arguments): int
    {
        $key = (string) $arguments[0];
        $min = $arguments[1];
        $max = $arguments[2];
        $removed = 0;
        foreach ($this->zsets[$key] ?? [] as $member => $score) {
            if ($score >= (float) $min && $score <= (float) $max) {
                unset($this->zsets[$key][$member]);
                $removed++;
            }
        }
        if (isset($this->zsets[$key]) && $this->zsets[$key] === []) {
            unset($this->zsets[$key]);
        }

        return $removed;
    }

    /** @param list<mixed> $arguments */
    private function fakePexpire(array $arguments): int
    {
        $this->expirations[(string) $arguments[0]] = (int) $arguments[1];

        return 1;
    }

    /** @param list<mixed> $arguments */
    private function fakeDel(array $arguments): int
    {
        $removed = 0;
        foreach ($arguments as $key) {
            if (isset($this->zsets[(string) $key])) {
                unset($this->zsets[(string) $key]);
                $removed++;
            }
            unset($this->expirations[(string) $key]);
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

        if (!str_contains($script, 'ZREMRANGEBYSCORE')) {
            // Release: return redis.call('ZREM', KEYS[1], ARGV[1]).
            return $this->fakeZrem([$keys[0], $rest[0]]);
        }

        // TIME-based scripts: semaphore acquire (1 key), global-only rate
        // limiter (1 key) or the full rate limiter (2/3 keys). The `now`
        // mirrors the Lua TIME read.
        $now = $this->timeMs();

        if (str_contains($script, 'ZADD", KEYS[1], now, ARGV[3]') || str_contains($script, "ZADD', KEYS[1], now, ARGV[3]")) {
            // Global-only rate limiter: prune, global cap -> -1, add at now.
            $key = (string) $keys[0];
            $globalMax = (int) $rest[0];
            $windowMs = (int) $rest[1];
            $requestId = (string) $rest[2];
            $cutoff = $now - $windowMs;
            $this->fakeZremrangebyscore([$key, '-inf', (string) $cutoff]);
            if ($this->zcard($key) >= $globalMax) {
                return -1;
            }
            $this->fakeZadd([$key, (string) $now, $requestId]);
            $this->fakePexpire([$key, (string) ($windowMs + 1000)]);

            return 1;
        }

        if ($numKeys === 1) {
            // Acquire: prune expired leases, admit below the cap.
            $key = (string) $keys[0];
            $cap = (int) $rest[0];
            $leaseMs = (int) $rest[1];
            $token = (string) $rest[2];
            $this->fakeZremrangebyscore([$key, '-inf', (string) $now]);
            if ($this->zcard($key) >= $cap) {
                return 0;
            }
            $this->fakeZadd([$key, (string) ($now + $leaseMs), $token]);
            $this->fakePexpire([$key, (string) ($leaseMs * 2)]);

            return 1;
        }

        // Rate limiter (2 keys): prune both windows, per-client cap, then
        // global cap.
        if ($numKeys === 2) {
            $clientKey = (string) $keys[0];
            $globalKey = (string) $keys[1];
            $clientMax = (int) $rest[0];
            $globalMax = (int) $rest[1];
            $windowMs = (int) $rest[2];
            $requestId = (string) $rest[3];
            $cutoff = $now - $windowMs;
            $this->fakeZremrangebyscore([$clientKey, '-inf', (string) $cutoff]);
            $this->fakeZremrangebyscore([$globalKey, '-inf', (string) $cutoff]);
            if ($this->zcard($clientKey) >= $clientMax) {
                return 0;
            }
            if ($this->zcard($globalKey) >= $globalMax) {
                return -1;
            }
            $this->fakeZadd([$clientKey, (string) $now, $requestId]);
            $this->fakeZadd([$globalKey, (string) $now, $requestId]);
            $this->fakePexpire([$clientKey, (string) ($windowMs + 1000)]);
            $this->fakePexpire([$globalKey, (string) ($windowMs + 1000)]);

            return 1;
        }

        // Epoch-rotated limiter (3 keys): clientPrev, clientCur, and ONE
        // STABLE global ZSET. Only the CLIENT keys are per-epoch; the
        // global budget is shared by every client regardless of epoch.
        $clientPrev = (string) $keys[0];
        $clientCur = (string) $keys[1];
        $global = (string) $keys[2];
        $clientMax = (int) $rest[0];
        $globalMax = (int) $rest[1];
        $windowMs = (int) $rest[2];
        $requestId = (string) $rest[3];
        $cutoff = $now - $windowMs;
        foreach ([$clientPrev, $clientCur, $global] as $k) {
            $this->fakeZremrangebyscore([$k, '-inf', (string) $cutoff]);
        }
        if ($this->zcard($clientPrev) + $this->zcard($clientCur) >= $clientMax) {
            return 0;
        }
        if ($this->zcard($global) >= $globalMax) {
            return -1;
        }
        $this->fakeZadd([$clientCur, (string) $now, $requestId]);
        $this->fakeZadd([$global, (string) $now, $requestId]);
        foreach ([$clientPrev, $clientCur, $global] as $k) {
            $this->fakePexpire([$k, (string) ($windowMs + 1000)]);
        }

        return 1;
        $this->fakePexpire([$globalKey, (string) ($windowMs + 1000)]);

        return 1;
    }
}
