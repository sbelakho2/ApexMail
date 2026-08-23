<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

/**
 * In-memory stand-in for Predis\Client used by the Redis-backed semaphore
 * and rate-limiter tests (no real Redis in CI). Predis dispatches every
 * command through `__call`, so this fake intercepts exactly the commands
 * the bundle sends and emulates their semantics. The command surface:
 *
 *  - time: reads the configurable clock via {@see self::setTimeMs()} so
 *    tests can advance the "Redis server time" to exercise lease/window
 *    expiry.
 *  - zset primitives (zadd, zrem, zremrangebyscore, zcard, pexpire): the
 *    tokenized-lease semaphore and the sliding-window rate limiter.
 *  - hincrbyfloat: one hash field bump (the calibration score-bucket
 *    outcome counters).
 *  - eval: interprets the bundle's Lua scripts by their shape — semaphore
 *    acquire/release, outstanding-challenge issue/solve, the rate
 *    limiter, calibration confirm/correction and the outcome-ledger
 *    confirm/correct, mirroring the scripts' semantics. It also
 *    interprets the kiwicaptcha core's consume, cancel,
 *    delete-if-pending and commit-result scripts, so the same fake
 *    drives the core RedisStorage for the cancellation endpoint's
 *    record transitions.
 *
 * Every call is recorded in {@see FakePredisClient::$calls} so tests can
 * assert on the Redis commands issued.
 */
final class FakePredisClient extends \Predis\Client
{
    /** @var array<string, array<string, float>> sorted sets: key => member => score */
    public array $zsets = [];

    /** @var array<string, int> pexpire/expire deadlines in ms */
    public array $expirations = [];

    /** @var array<string, int> plain incr counters (issuance-rate signal) */
    public array $counters = [];

    /** @var array<string, string> plain strings (SET / getdel decision handles) */
    public array $strings = [];

    /** @var array<string, array<string, float|string>> hashes (hincrbyfloat calibration buckets + hset policy fields) */
    public array $hashes = [];

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

    /** Current fake server time in ms (mirrors the Lua time read). */
    public function timeMs(): float
    {
        return $this->clockMs;
    }

    /** Redis time emulation: [seconds, microseconds]. */
    public function time(): mixed
    {
        if ($this->timeUnavailable) {
            // A real Redis error (e.g. readonly on a replica) — the cap
            // must fail closed rather than fall back to host clocks.
            throw new \Predis\Response\ServerException("READONLY You can't write against a read only replica");
        }
        $secs = (int) floor($this->clockMs / 1000);

        return [$secs, (int) (($this->clockMs - $secs * 1000) * 1000)];
    }

    /** When true, time() raises a server error (fail-closed clock tests). */
    public bool $timeUnavailable = false;

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

    /**
     * @internal test hook: make a command fail with a server exception
     * (Redis-outage tests). '*' fails every command; a command name fails
     * only that one.
     */
    public ?string $failCommand = null;

    public function __call($commandID, $arguments)
    {
        if ($this->failCommand !== null
            && ($this->failCommand === '*' || strtoupper($this->failCommand) === strtoupper((string) $commandID))
        ) {
            throw new \Predis\Response\ServerException('connection refused (fake)');
        }
        $this->calls[] = [strtoupper((string) $commandID), $arguments];

        return match (strtoupper((string) $commandID)) {
            'TIME' => $this->fakeTime(),
            'ZADD' => $this->fakeZadd($arguments),
            'ZINCRBY' => $this->fakeZincrby($arguments),
            'ZREM' => $this->fakeZrem($arguments),
            'ZREMRANGEBYSCORE' => $this->fakeZremrangebyscore($arguments),
            'ZCARD' => $this->zcard((string) $arguments[0]),
            'PEXPIRE' => $this->fakePexpire($arguments),
            'EXPIRE' => $this->fakePexpire($arguments),
            'DEL' => $this->fakeDel($arguments),
            'EVAL' => $this->fakeEval($arguments),
            'INCR' => $this->fakeIncr($arguments),
            'DECR' => $this->fakeDecr($arguments),
            'GET' => $this->fakeGet($arguments),
            'GETDEL' => $this->fakeGetdel($arguments),
            'SET' => $this->fakeSet($arguments),
            'HINCRBYFLOAT' => $this->fakeHincrbyfloat($arguments),
            'HINCRBY' => $this->fakeHincrby($arguments),
            'HDEL' => $this->fakeHdel($arguments),
            'HGETALL' => $this->fakeHgetall($arguments),
            'HSET' => $this->fakeHset($arguments),
            'HGET' => $this->fakeHget($arguments),
            'PING' => $this->pingOk() ? 'PONG' : throw new \RuntimeException('connection refused (fake)'),
            default => null,
        };
    }

    /** @internal test hook: make ping fail (health probe tests). */
    public bool $pingFails = false;

    private function pingOk(): bool
    {
        return !$this->pingFails;
    }

    /**
     * hgetall: the full hash (the central security-policy state read by the
     * readiness probe), or an empty array when the key does not exist.
     */
    private function fakeHgetall(array $arguments): array
    {
        return $this->hashes[(string) $arguments[0]] ?? [];
    }

    /**
     * hset: set one hash field (the central security-policy state written
     * by tests; values are stored as strings).
     */
    private function fakeHset(array $arguments): int
    {
        $key = (string) $arguments[0];
        $field = (string) $arguments[1];
        $value = (string) $arguments[2];
        $this->hashes[$key] ??= [];
        $isNew = !\array_key_exists($field, $this->hashes[$key]);
        $this->hashes[$key][$field] = $value;

        return $isNew ? 1 : 0;
    }

    /**
     * hget: one hash field, or null when the key/field does not exist.
     */
    private function fakeHget(array $arguments): ?string
    {
        $key = (string) $arguments[0];
        $field = (string) $arguments[1];

        if (!isset($this->hashes[$key]) || !\array_key_exists($field, $this->hashes[$key])) {
            return null;
        }

        return (string) $this->hashes[$key][$field];
    }

    /**
     * hincrbyfloat: bump one hash field (the calibration score-bucket
     * outcome counters) and return the new value as a string.
     */
    private function fakeHincrbyfloat(array $arguments): string
    {
        $key = (string) $arguments[0];
        $field = (string) $arguments[1];
        $delta = (float) $arguments[2];
        $this->hashes[$key] ??= [];
        $this->hashes[$key][$field] = ($this->hashes[$key][$field] ?? 0.0) + $delta;

        return (string) $this->hashes[$key][$field];
    }

    /**
     * hincrby: bump one hash field by an integer (the bucketed global
     * limiter's per-second admission count) and return the new value.
     */
    private function fakeHincrby(array $arguments): int
    {
        $key = (string) $arguments[0];
        $field = (string) $arguments[1];
        $delta = (int) $arguments[2];
        $this->hashes[$key] ??= [];
        $this->hashes[$key][$field] = ($this->hashes[$key][$field] ?? 0) + $delta;

        return (int) $this->hashes[$key][$field];
    }

    /** hdel: drop one or more hash fields (the pruned bucket counts). */
    private function fakeHdel(array $arguments): int
    {
        $key = (string) $arguments[0];
        $removed = 0;
        foreach (\array_slice($arguments, 1) as $field) {
            if (isset($this->hashes[$key][(string) $field])) {
                unset($this->hashes[$key][(string) $field]);
                $removed++;
            }
        }
        if (isset($this->hashes[$key]) && $this->hashes[$key] === []) {
            unset($this->hashes[$key]);
        }

        return $removed;
    }

    /**
     * GET: the plain string value, then the plain incr counter, or null when
     * the key does not exist.
     */
    private function fakeGet(array $arguments): ?string
    {
        $key = (string) $arguments[0];

        return $this->strings[$key] ?? (isset($this->counters[$key]) ? (string) $this->counters[$key] : null);
    }

    /**
     * getdel: atomic read + remove of a plain string (null when absent) —
     * the nonce->decision handle consumption.
     */
    private function fakeGetdel(array $arguments): ?string
    {
        $key = (string) $arguments[0];
        $value = $this->strings[$key] ?? null;
        unset($this->strings[$key], $this->expirations[$key]);

        return $value;
    }

    /**
     * SET with optional EX (seconds) TTL and NX flag (the nonce->decision
     * handle write path and the correction once-only guard): NX returns
     * null when the key already exists (Redis SET NX nil — the guard is
     * armed exactly once). Accepts both Predis argument shapes: flat
     * ('EX', ttl, 'NX') and the options-array form.
     */
    private function fakeSet(array $arguments): ?string
    {
        $key = (string) $arguments[0];
        $value = (string) $arguments[1];
        $ttl = null;
        $flags = [];
        $rest = \array_slice($arguments, 2);
        if (isset($rest[0]) && \is_array($rest[0])) {
            $flags = array_map('strtoupper', array_keys($rest[0]));
            if (isset($rest[0]['EX'])) {
                $ttl = (int) $rest[0]['EX'];
            }
        } else {
            $flags = array_map('strtoupper', $rest);
            $exIndex = array_search('EX', $flags, true);
            if ($exIndex !== false) {
                $ttl = (int) $arguments[2 + $exIndex + 1];
            }
        }
        $nx = \in_array('NX', $flags, true);
        if ($nx && isset($this->strings[$key])) {
            return null;
        }
        $this->strings[$key] = $value;
        if ($ttl !== null) {
            $this->fakePexpire([$key, $ttl * 1000]);
        }

        return 'OK';
    }

    /** incr: bump the plain counter and return the new value. */
    private function fakeIncr(array $arguments): int
    {
        $key = (string) $arguments[0];
        $this->counters[$key] = ($this->counters[$key] ?? 0) + 1;

        return $this->counters[$key];
    }

    /** decr: lower the plain counter (floored at 0) and return the new value. */
    private function fakeDecr(array $arguments): int
    {
        $key = (string) $arguments[0];
        $this->counters[$key] = max(0, ($this->counters[$key] ?? 0) - 1);

        return $this->counters[$key];
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

    /**
     * `ZINCRBY`: increment the score of a member, creating it at the
     * increment when absent (the bucketed global limiter's per-second
     * admission count).
     *
     * @param list<mixed> $arguments
     */
    private function fakeZincrby(array $arguments): float
    {
        $key = (string) $arguments[0];
        $increment = (float) $arguments[1];
        $member = (string) $arguments[2];
        $this->zsets[$key] ??= [];
        $this->zsets[$key][$member] = ($this->zsets[$key][$member] ?? 0.0) + $increment;

        return $this->zsets[$key][$member];
    }

    /**
     * The bucketed global window count: the sum of the retained seconds'
     * hash counts (mirrors the Lua sum of HGET over the ZSET members).
     */
    private function bucketCount(string $key, string $hashKey): int
    {
        $total = 0;
        foreach ($this->zsets[$key] ?? [] as $member => $score) {
            $total += (int) ($this->hashes[$hashKey][$member] ?? 0);
        }

        return $total;
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
            unset($this->counters[(string) $key]);
            unset($this->strings[(string) $key]);
            unset($this->hashes[(string) $key]);
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

        if (str_contains($script, 'Outstanding challenge issuance')) {
            // OutstandingChallenges::issue: keys[1] per-source counter,
            // keys[2] the global LIVE-outstanding ZSET; argv[1] source cap,
            // argv[2] global cap, argv[3] TTL seconds, argv[4] absolute
            // expiry (the ZSET score), argv[5] the minted nonce (the
            // member). GET the source cap -> prune expired live members ->
            // refuse 0/-1 before anything is written -> INCR + EXPIRE the
            // source counter and `ZADD` the nonce at its absolute expiry.
            $source = (string) $keys[0];
            $global = (string) $keys[1];
            $sourceCap = (int) $rest[0];
            $globalCap = (int) $rest[1];
            $ttl = (int) $rest[2];
            if (($this->counters[$source] ?? 0) >= $sourceCap) {
                return 0;
            }
            $this->fakeZremrangebyscore([$global, '-inf', (string) floor($this->timeMs() / 1000)]);
            if ($this->zcard($global) >= $globalCap) {
                return -1;
            }
            $this->fakeIncr([$source]);
            $this->fakePexpire([$source, $ttl * 1000]);
            $this->fakeZadd([$global, (string) $rest[3], (string) $rest[4]]);

            return 1;
        }

        if (str_contains($script, 'Outstanding challenge solve')) {
            // OutstandingChallenges::solved: keys[1] per-source counter,
            // keys[2] the global live ZSET; argv[1] the solved nonce ('' =
            // none). Best-effort DECR floored at 0 + ZREM the nonce.
            $source = (string) $keys[0];
            $global = (string) $keys[1];
            $v = $this->counters[$source] ?? 0;
            if ($v > 0) {
                $this->fakeDecr([$source]);
            }
            if ((string) $rest[0] !== '') {
                $this->fakeZrem([$global, (string) $rest[0]]);
            }

            return $v - 1;
        }

        if (str_contains($script, 'Outstanding challenge aborted')) {
            // OutstandingChallenges::abortedBeforeHandoff: keys[1]
            // per-source counter, keys[2] the global live ZSET; argv[1]
            // the abandoned nonce ('' = none). Best-effort DECR floored at
            // 0 + ZREM the nonce; returns 1 (rollback never changes the
            // response).
            $source = (string) $keys[0];
            $global = (string) $keys[1];
            $v = $this->counters[$source] ?? 0;
            if ($v > 0) {
                $this->fakeDecr([$source]);
            }
            if ((string) $rest[0] !== '') {
                $this->fakeZrem([$global, (string) $rest[0]]);
            }

            return 1;
        }

        if (str_contains($script, 'Outstanding challenge cancelled')) {
            // OutstandingChallenges::cancelled: keys[1] the global live
            // ZSET; argv[1] the cancelled nonce. Best-effort idempotent
            // ZREM.
            return $this->fakeZrem([(string) $keys[0], (string) $rest[0]]);
        }

        if (str_contains($script, 'Outstanding challenge cancellation admission')) {
            // OutstandingChallenges::cancellationAdmission: keys[1] the
            // per-source cancellation window; argv[1] cap, argv[2] window
            // ms, argv[3] request id. Prune -> cap -> `ZADD` + `PEXPIRE`.
            $window = (string) $keys[0];
            $cap = (int) $rest[0];
            $windowMs = (int) $rest[1];
            $requestId = (string) $rest[2];
            $now = $this->timeMs();
            $cutoff = $now - $windowMs;
            $this->fakeZremrangebyscore([$window, '-inf', (string) $cutoff]);
            if ($this->zcard($window) >= $cap) {
                return 0;
            }
            $this->fakeZadd([$window, (string) $now, $requestId]);
            $this->fakePexpire([$window, (string) ($windowMs + 1000)]);

            return 1;
        }

        if (str_starts_with($script, '-- kiwicaptcha consume transition')) {
            // The core RedisStorage consume-transition script: a pending
            // record is flipped to consumed and kept; a consumed record
            // replays (consumed_before); a cancelled record is never
            // consumable (reported missing); ARGV[1] is the JSON-escaped
            // operation identity ('' = none) spliced with the state flip.
            $key = (string) $keys[0];
            if (!isset($this->strings[$key])) {
                return null;
            }
            $raw = $this->strings[$key];
            $obj = json_decode($raw, true);
            if (!\is_array($obj)) {
                return null;
            }
            if (($obj['state'] ?? 'pending') === 'cancelled') {
                return null;
            }
            if (($obj['state'] ?? 'pending') === 'consumed') {
                $res = $obj['consumed_result'] ?? null;

                return [$raw, 0, 1, $res !== null ? json_encode($res, JSON_UNESCAPED_SLASHES) : ''];
            }
            $obj['state'] = 'consumed';
            if (($rest[0] ?? '') !== '') {
                $obj['operation_identity'] = json_decode((string) $rest[0], true, flags: JSON_THROW_ON_ERROR);
            }
            $this->strings[$key] = json_encode($obj, JSON_UNESCAPED_SLASHES);

            return [$this->strings[$key], 1, 0, ''];
        }

        if (str_starts_with($script, '-- kiwicaptcha cancel transition')) {
            // The core RedisStorage cancel-transition script: a pending
            // record is flipped to the terminal cancelled marker and kept;
            // a consumed record is finalized and never cancellable; an
            // already-cancelled record is idempotent; a missing record is
            // nil.
            $key = (string) $keys[0];
            if (!isset($this->strings[$key])) {
                return null;
            }
            $obj = json_decode($this->strings[$key], true);
            if (!\is_array($obj)) {
                return null;
            }
            if (($obj['state'] ?? 'pending') === 'consumed') {
                return ['consumed'];
            }
            if (($obj['state'] ?? 'pending') === 'cancelled') {
                return ['cancelled'];
            }
            $obj['state'] = 'cancelled';
            $this->strings[$key] = json_encode($obj, JSON_UNESCAPED_SLASHES);

            return ['cancelled-now'];
        }

        if (str_starts_with($script, '-- kiwicaptcha delete-if-pending (atomic cleanup)')) {
            // The core RedisStorage delete-if-pending script: missing
            // reports missing; a consumed record is returned verbatim and
            // kept; a cancelled record is returned verbatim and kept too
            // (dead but retained until its TTL); only a pending record is
            // deleted.
            $key = (string) $keys[0];
            if (!isset($this->strings[$key])) {
                return ['missing'];
            }
            $raw = $this->strings[$key];
            $obj = json_decode($raw, true);
            if (!\is_array($obj)) {
                return ['missing'];
            }
            if (($obj['state'] ?? 'pending') === 'consumed') {
                return ['consumed', $raw];
            }
            if (($obj['state'] ?? 'pending') === 'cancelled') {
                return ['cancelled', $raw];
            }
            unset($this->strings[$key]);

            return ['deleted-pending'];
        }

        if (str_starts_with($script, '-- kiwicaptcha commit result')) {
            // The core RedisStorage commit-result script: stores
            // {valid, binding} on a consumed record without a result yet;
            // 1 on success, 0 otherwise (missing, pending or cancelled).
            $key = (string) $keys[0];
            if (!isset($this->strings[$key])) {
                return 0;
            }
            $obj = json_decode($this->strings[$key], true);
            if (!\is_array($obj) || ($obj['state'] ?? 'pending') !== 'consumed') {
                return 0;
            }
            if (isset($obj['consumed_result']) && $obj['consumed_result'] !== null) {
                return 0;
            }
            $obj['consumed_result'] = [
                'valid' => ($rest[0] ?? '0') === '1',
                'binding' => ($rest[2] ?? '0') === '1' ? (string) ($rest[1] ?? '') : null,
            ];
            $this->strings[$key] = json_encode($obj, JSON_UNESCAPED_SLASHES);

            return 1;
        }

        if (str_contains($script, 'waiters')) {
            // Acquire with the bounded waiters guard + the
            // per-scope budget: keys[1] global lease set,
            // keys[2] waiters counter, keys[3] per-scope lease set ('' =
            // no scope); argv[1] global cap, argv[2] leaseMs, argv[3]
            // token, argv[4] maxWaiters, argv[5] per-scope cap, argv[6]
            // hasScope. Grant (and serve one waiter) when the global slot
            // is free AND the scope budget (when present) has room; the
            // lease is recorded in both sets. Saturated acquires (either
            // cap) are counted in the global waiters counter with the lease
            // TTL and refused-without-queueing (entry removed in the same
            // script) once the count exceeds maxWaiters.
            $key = (string) $keys[0];
            $waitersKey = (string) $keys[1];
            $scopeKey = (string) $keys[2];
            $cap = (int) $rest[0];
            $leaseMs = (int) $rest[1];
            $token = (string) $rest[2];
            $maxWaiters = (int) $rest[3];
            $scopeCap = (int) $rest[4];
            $hasScope = (int) $rest[5] === 1;
            $now = $this->timeMs();
            $this->fakeZremrangebyscore([$key, '-inf', (string) $now]);
            if ($hasScope && $scopeCap > 0) {
                $this->fakeZremrangebyscore([$scopeKey, '-inf', (string) $now]);
            }
            $admitted = false;
            if ($this->zcard($key) < $cap) {
                if (!$hasScope || $scopeCap <= 0 || $this->zcard($scopeKey) < $scopeCap) {
                    $this->fakeZadd([$key, (string) ($now + $leaseMs), $token]);
                    $this->fakePexpire([$key, (string) ($leaseMs * 2)]);
                    if ($hasScope && $scopeCap > 0) {
                        $this->fakeZadd([$scopeKey, (string) ($now + $leaseMs), $token]);
                        $this->fakePexpire([$scopeKey, (string) ($leaseMs * 2)]);
                    }
                    $admitted = true;
                }
            }
            if ($admitted) {
                if (($this->counters[$waitersKey] ?? 0) > 0) {
                    $this->fakeDecr([$waitersKey]);
                }

                return 1;
            }
            $n = $this->fakeIncr([$waitersKey]);
            $this->fakePexpire([$waitersKey, (string) ($leaseMs * 2)]);
            if ($n > $maxWaiters) {
                $this->fakeDecr([$waitersKey]);

                return 0;
            }

            return 0;
        }

        if (str_contains($script, 'per-scope lease removal')) {
            // Release with the per-scope budget: keys[1] global
            // set, keys[2] per-scope set ('' = no scope); argv[1] token,
            // argv[2] hasScope. Removes the token from both sets.
            $removed = $this->fakeZrem([$keys[0], $rest[0]]);
            if ((int) $rest[1] === 1) {
                $this->fakeZrem([$keys[1], $rest[0]]);
            }

            return $removed;
        }

        if (str_contains($script, 'return redis.call(\'ZCARD\', KEYS[1])')) {
            // Semaphore usage: time -> prune -> zcard in one script
            // (atomic-live, matching the acquire pruning).
            $key = (string) $keys[0];
            $this->fakeZremrangebyscore([$key, '-inf', (string) $this->timeMs()]);

            return $this->zcard($key);
        }

        if (str_contains($script, 'Scope issuance cap')) {
            // ScopeIssuanceCap::allow: keys[1] =
            // {kiwi:<ns>}:issuance:<hex hmac-sha256(scope, K_scope)>:<minute>
            // (the raw scope is never a key component);
            // argv[1] = cap. incr -> expire 60 on the first increment ->
            // refuse beyond the cap (0), else 1.
            $key = (string) $keys[0];
            $cap = (int) $rest[0];
            $n = $this->fakeIncr([$key]);
            if ($n === 1) {
                $this->fakePexpire([$key, 60000]);
            }

            return $n > $cap ? 0 : 1;
        }

        if (str_contains($script, 'redis.call(\'INCR\', KEYS[1])')) {
            // Issuance counter: incr + expire 1 in one atomic script.
            $key = (string) $keys[0];
            $n = $this->fakeIncr([$key]);
            $this->fakePexpire([$key, 1000]);

            return $n;
        }

        if (str_contains($script, 'Decision registration: receipt + sample denominator + outcome ledger')) {
            // Canonical register_decision.lua: keys[1] receipt, keys[2]
            // decision-hour bucket, keys[3] outcome ledger;
            // argv[1] receipt JSON, argv[2] receipt TTL, argv[3] sampled,
            // argv[4] bucket TTL, argv[5] outcome TTL, argv[6] scope,
            // argv[7] decision_hour, argv[8] score, argv[9] weight.
            $receiptKey = (string) $keys[0];
            $bucketKey = (string) $keys[1];
            $ledgerKey = (string) $keys[2];
            if (isset($this->strings[$receiptKey])) {
                return 0;
            }
            $this->strings[$receiptKey] = (string) $rest[0];
            $this->strings[$ledgerKey] = (string) json_encode([
                'o' => 'P',
                'scope' => (int) $rest[5],
                'hour' => (int) $rest[6],
                'score' => (int) $rest[7],
                'w' => (float) $rest[8],
            ]);
            $this->fakePexpire([$receiptKey, (int) $rest[1] * 1000]);
            $this->fakePexpire([$ledgerKey, (int) $rest[4] * 1000]);
            if ((int) $rest[2] === 1) {
                $this->fakeHincrbyfloat([$bucketKey, 'sample_total', 1.0]);
                $this->fakePexpire([$bucketKey, (int) $rest[3] * 1000]);
            }

            return 1;
        }

        if (str_contains($script, 'Calibration confirmation: outcome ledger CAS + receipt + bucket')) {
            // Canonical confirm.lua (v2): keys[1] receipt, keys[2]
            // decision-time bucket, keys[3] outcome ledger;
            // argv[1] mode, argv[2] weight, argv[3] legitimate,
            // argv[4] bucket TTL, argv[5] outcome TTL, argv[6] expected
            // scope, argv[7] expected decision_hour.
            $receiptKey = (string) $keys[0];
            $bucketKey = (string) $keys[1];
            $ledgerKey = (string) $keys[2];
            $mode = (int) $rest[0];
            $weight = (float) $rest[1];
            $legitimate = (int) $rest[2] === 1;
            $bucketTtlSecs = (int) $rest[3];
            $outcomeTtlSecs = (int) $rest[4];
            $expectedScope = (int) $rest[5];
            $expectedHour = (int) $rest[6];

            $raw = $this->strings[$receiptKey] ?? null;
            if ($raw === null) {
                return 0;
            }
            $receipt = json_decode($raw, true);
            if (!\is_array($receipt) || !isset($receipt['scope'])) {
                unset($this->strings[$receiptKey]);

                return 0;
            }
            if ((int) $receipt['scope'] !== $expectedScope
                || (int) ($receipt['decision_hour'] ?? 0) !== $expectedHour
            ) {
                return 0;
            }
            if ($mode !== 0 && $mode !== 1 && $mode !== 2) {
                throw new \Predis\Response\ServerException('invalid calibration mode');
            }
            if ($mode === 2 && ($weight <= 0 || !\is_finite($weight))) {
                throw new \Predis\Response\ServerException('invalid calibration weight');
            }

            $ledgerRaw = $this->strings[$ledgerKey] ?? null;
            if ($ledgerRaw === null) {
                return 0;
            }
            $ledger = json_decode($ledgerRaw, true);
            if (!\is_array($ledger) || ($ledger['o'] ?? null) !== 'P') {
                return 0;
            }

            $sampled = (int) ($receipt['sampled'] ?? 0) === 1;
            $status = 1;
            if ($mode === 1 && !$sampled) {
                $status = 2;
            }
            $score = (float) ($receipt['score'] ?? 0);
            if ($score < 0) {
                $score = 0;
            }
            if ($score > 1000) {
                $score = 1000;
            }

            $ledger['o'] = $legitimate ? 'L' : 'A';
            $ledger['w'] = $weight;
            $this->strings[$ledgerKey] = (string) json_encode($ledger);
            $this->fakePexpire([$ledgerKey, $outcomeTtlSecs * 1000]);
            unset($this->strings[$receiptKey]);

            if ($status === 1) {
                if ($legitimate) {
                    $this->fakeHincrbyfloat([$bucketKey, 'legit_count', $weight]);
                    $this->fakeHincrbyfloat([$bucketKey, 'legit_score_sum', $score * $weight]);
                } else {
                    $this->fakeHincrbyfloat([$bucketKey, 'abuse_count', $weight]);
                    $this->fakeHincrbyfloat([$bucketKey, 'abuse_score_sum', $score * $weight]);
                }
                $this->fakePexpire([$bucketKey, $bucketTtlSecs * 1000]);
                if ($mode === 1) {
                    $this->fakeHincrbyfloat([$bucketKey, 'sample_resolved', 1.0]);
                }
            }

            return $status;
        }

        if (str_contains($script, 'Calibration correction: flip the outcome ledger + reverse/redo')) {
            // Canonical correction.lua: keys[1] ledger, keys[2]
            // decision-time bucket; argv[1] new outcome, argv[2] weight,
            // argv[3] bucket TTL, argv[4] outcome TTL, argv[5] expected
            // scope, argv[6] expected hour.
            $ledgerKey = (string) $keys[0];
            $bucketKey = (string) $keys[1];
            $newOutcome = (string) $rest[0];
            $weight = (float) $rest[1];
            $bucketTtlSecs = (int) $rest[2];
            $outcomeTtlSecs = (int) $rest[3];
            $expectedScope = (int) $rest[4];
            $expectedHour = (int) $rest[5];

            $ledgerRaw = $this->strings[$ledgerKey] ?? null;
            if ($ledgerRaw === null) {
                return 0;
            }
            $ledger = json_decode($ledgerRaw, true);
            if (!\is_array($ledger) || !isset($ledger['o'])) {
                return 0;
            }
            if ((int) ($ledger['scope'] ?? 0) !== $expectedScope
                || (int) ($ledger['hour'] ?? 0) !== $expectedHour
            ) {
                return 0;
            }
            if ($newOutcome !== 'L' && $newOutcome !== 'A') {
                throw new \Predis\Response\ServerException('invalid correction outcome');
            }
            if (($ledger['o'] ?? null) === $newOutcome) {
                return 0;
            }
            if ($weight <= 0 || !\is_finite($weight)) {
                throw new \Predis\Response\ServerException('invalid correction weight');
            }
            $score = (float) ($ledger['score'] ?? 0);
            if ($score < 0) {
                $score = 0;
            }
            if ($score > 1000) {
                $score = 1000;
            }
            $oldW = (float) ($ledger['w'] ?? 1);

            if (($ledger['o'] ?? null) === 'L') {
                $this->fakeHincrbyfloat([$bucketKey, 'legit_count', -$oldW]);
                $this->fakeHincrbyfloat([$bucketKey, 'legit_score_sum', -($score * $oldW)]);
            } else {
                $this->fakeHincrbyfloat([$bucketKey, 'abuse_count', -$oldW]);
                $this->fakeHincrbyfloat([$bucketKey, 'abuse_score_sum', -($score * $oldW)]);
            }
            foreach (['legit_count', 'legit_score_sum', 'abuse_count', 'abuse_score_sum'] as $field) {
                if (($this->hashes[$bucketKey][$field] ?? 0) < 0) {
                    $this->hashes[$bucketKey][$field] = 0;
                }
            }

            if ($newOutcome === 'L') {
                $this->fakeHincrbyfloat([$bucketKey, 'legit_count', $weight]);
                $this->fakeHincrbyfloat([$bucketKey, 'legit_score_sum', $score * $weight]);
            } else {
                $this->fakeHincrbyfloat([$bucketKey, 'abuse_count', $weight]);
                $this->fakeHincrbyfloat([$bucketKey, 'abuse_score_sum', $score * $weight]);
            }
            $this->fakePexpire([$bucketKey, $bucketTtlSecs * 1000]);

            $ledger['o'] = $newOutcome;
            $ledger['w'] = $weight;
            $this->strings[$ledgerKey] = (string) json_encode($ledger);
            $this->fakePexpire([$ledgerKey, $outcomeTtlSecs * 1000]);

            return 1;
        }

        if (str_contains($script, 'register: create a PENDING entry')) {
            // Canonical outcome_register.lua: keys[1] ledger;
            // argv[1] scope, argv[2] hour, argv[3] score, argv[4] TTL.
            $ledgerKey = (string) $keys[0];
            if (isset($this->strings[$ledgerKey])) {
                return 0;
            }
            $this->strings[$ledgerKey] = (string) json_encode([
                'o' => 'P',
                'scope' => (int) $rest[0],
                'hour' => (int) $rest[1],
                'score' => (int) $rest[2],
                'w' => 1.0,
            ]);
            $this->fakePexpire([$ledgerKey, (int) $rest[3] * 1000]);

            return 1;
        }

        if (str_contains($script, 'Outcome ledger confirm: PENDING -> L/A exactly once')) {
            // Canonical outcome_confirm.lua: keys[1] ledger;
            // argv[1] outcome, argv[2] TTL.
            $ledgerKey = (string) $keys[0];
            $ledgerRaw = $this->strings[$ledgerKey] ?? null;
            if ($ledgerRaw === null) {
                return 0;
            }
            $ledger = json_decode($ledgerRaw, true);
            if (!\is_array($ledger) || ($ledger['o'] ?? null) !== 'P') {
                return 0;
            }
            $ledger['o'] = (string) $rest[0];
            $this->strings[$ledgerKey] = (string) json_encode($ledger);
            $this->fakePexpire([$ledgerKey, (int) $rest[1] * 1000]);

            return 1;
        }

        if (str_contains($script, 'Outcome ledger correction: flip L <-> A')) {
            // Canonical outcome_correct.lua: keys[1] ledger;
            // argv[1] new outcome, argv[2] TTL.
            $ledgerKey = (string) $keys[0];
            $ledgerRaw = $this->strings[$ledgerKey] ?? null;
            if ($ledgerRaw === null) {
                return 0;
            }
            $ledger = json_decode($ledgerRaw, true);
            if (!\is_array($ledger) || ($ledger['o'] ?? null) === (string) $rest[0]) {
                return 0;
            }
            $ledger['o'] = (string) $rest[0];
            $this->strings[$ledgerKey] = (string) json_encode($ledger);
            $this->fakePexpire([$ledgerKey, (int) $rest[1] * 1000]);

            return 1;
        }

        if (str_contains($script, 'Sampling metrics: per-scope sample totals')) {
            // Canonical sampling_metrics.lua: 24 bucket keys; sums the two
            // sample counters; returns {sample_total, sample_resolved}.
            $total = 0.0;
            $resolved = 0.0;
            foreach ($keys as $bucketKey) {
                $total += (float) ($this->hashes[(string) $bucketKey]['sample_total'] ?? 0);
                $resolved += (float) ($this->hashes[(string) $bucketKey]['sample_resolved'] ?? 0);
            }

            return [$total, $resolved];
        }

        if (!str_contains($script, 'ZREMRANGEBYSCORE')) {
            // Release: return redis.call('zrem', keys[1], argv[1]).
            return $this->fakeZrem([$keys[0], $rest[0]]);
        }

        // TIME-based scripts: semaphore acquire (1 key), the bucketed
        // global-only limiter (2 keys: ZSET + counts hash), the full
        // bucketed rate limiter (3 keys) or the epoch-rotated variant
        // (4 keys). `now` mirrors the Lua time read.
        $now = $this->timeMs();

        if (str_contains($script, "HINCRBY', KEYS[")) {
            // The separated bucketed global limiter: the ZSET member is
            // the wall-clock second and its score is that same second
            // (the pruning timestamp only); the per-second admission
            // count lives in the counts hash. Prune the ZSET by the
            // cutoff second, drop the pruned seconds' hash fields, then
            // enforce the caps on the summed retained counts.
            $twoKey = \count($keys) === 2;
            $globalZset = (string) $keys[\count($keys) - 2];
            $globalHash = (string) $keys[\count($keys) - 1];
            $globalMax = (int) $rest[$twoKey ? 0 : 1];
            $windowMs = (int) $rest[$twoKey ? 1 : 2];
            $cutoff = $now - $windowMs;
            $bucket = (string) floor($now / 1000);
            $pruneMax = (string) floor($cutoff / 1000);
            $pruned = [];
            foreach ($this->zsets[$globalZset] ?? [] as $member => $score) {
                if ($score <= (float) $pruneMax) {
                    $pruned[] = $member;
                }
            }
            foreach ($pruned as $member) {
                unset($this->zsets[$globalZset][$member]);
                unset($this->hashes[$globalHash][$member]);
            }
            if (isset($this->zsets[$globalZset]) && $this->zsets[$globalZset] === []) {
                unset($this->zsets[$globalZset]);
            }
            if (!$twoKey) {
                // Per-client cap: the full limiter checks the current
                // client key, the rotated variant the previous + current.
                $clientKeys = \count($keys) === 3 ? [(string) $keys[0]] : [(string) $keys[0], (string) $keys[1]];
                foreach ($clientKeys as $clientKey) {
                    $this->fakeZremrangebyscore([$clientKey, '-inf', (string) $cutoff]);
                }
                $clientCount = 0;
                foreach ($clientKeys as $clientKey) {
                    $clientCount += $this->zcard($clientKey);
                }
                if ($clientCount >= (int) $rest[0]) {
                    return 0;
                }
            }
            if ($this->bucketCount($globalZset, $globalHash) >= $globalMax) {
                return -1;
            }
            if (!$twoKey) {
                $this->fakeZadd([(string) $keys[\count($keys) === 3 ? 0 : 1], (string) $now, (string) $rest[3]]);
            }
            $this->fakeZadd([$globalZset, $bucket, $bucket]);
            $this->fakeHincrby([$globalHash, $bucket, 1]);
            foreach ($keys as $k) {
                $this->fakePexpire([$k, (string) ($windowMs + 1000)]);
            }

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

        // Legacy limiter shapes (pre-separation score = second + count)
        // are not used by the bundle anymore; the `HINCRBY` branch above is
        // the canonical emulation for the current scripts.
        return 1;
    }
}
