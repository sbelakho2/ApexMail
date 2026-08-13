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
 *  - HINCRBYFLOAT: one hash field bump (the calibration score-bucket
 *    outcome counters).
 *  - EVAL: interprets the bundle's Lua scripts by their shape:
 *      - semaphore ACQUIRE (2 keys: lease set + waiters counter; TIME +
 *        prune + cap + ZADD, bounded WAITERS guard: saturated acquires are
 *        counted in the waiters counter with the lease TTL; once the waiter
 *        count exceeds maxWaiters the caller is refused without queueing
 *        and its waiter entry is removed in the same script; a granted
 *        lease decrements the waiters counter),
 *      - semaphore RELEASE (ZREM of one member),
 *      - outstanding-challenge ISSUE (2 keys: per-source + global counter;
 *        GET both caps -> refuse 0/-1 before anything is written -> INCR
 *        both + EXPIRE both),
 *      - outstanding-challenge SOLVE (1 key: best-effort DECR floored at 0),
 *      - rate-limiter (2 keys, 4 args, TIME + prune both + caps + ZADD both),
 *      - calibration CONFIRM (4 keys: outcome ledger + receipt + bucket +
 *        resolved counter; ledger check -> validate -> flip the ledger ->
 *        DEL receipt -> HINCRBYFLOAT + EXPIRE, mirroring the canonical
 *        confirm.lua),
 *      - calibration CORRECTION (2 keys: ledger + bucket; flip the ledger
 *        1 -> 2 + reverse the bucket deltas, mirroring correction.lua),
 *      - outcome-ledger CONFIRM / CORRECT (1 key: ledger; the engine-level
 *        once-only gate used without a calibration store),
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

    /** @var array<string, int> plain INCR counters (issuance-rate signal) */
    public array $counters = [];

    /** @var array<string, string> plain strings (SET / GETDEL decision handles) */
    public array $strings = [];

    /** @var array<string, array<string, float|string>> hashes (HINCRBYFLOAT calibration buckets + HSET policy fields) */
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

    /**
     * @internal test hook: make a command fail with a server exception
     * (Redis-outage tests). '*' fails EVERY command; a command name fails
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
            'HGETALL' => $this->fakeHgetall($arguments),
            'HSET' => $this->fakeHset($arguments),
            'HGET' => $this->fakeHget($arguments),
            'PING' => $this->pingOk() ? 'PONG' : throw new \RuntimeException('connection refused (fake)'),
            default => null,
        };
    }

    /** @internal test hook: make PING fail (health probe tests). */
    public bool $pingFails = false;

    private function pingOk(): bool
    {
        return !$this->pingFails;
    }

    /**
     * HGETALL: the full hash (the central security-policy state read by the
     * readiness probe), or an empty array when the key does not exist.
     */
    private function fakeHgetall(array $arguments): array
    {
        return $this->hashes[(string) $arguments[0]] ?? [];
    }

    /**
     * HSET: set one hash field (the central security-policy state written
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
     * HGET: one hash field, or null when the key/field does not exist.
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
     * HINCRBYFLOAT: bump one hash field (the calibration score-bucket
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
     * GET: the plain string value, then the plain INCR counter, or null when
     * the key does not exist.
     */
    private function fakeGet(array $arguments): ?string
    {
        $key = (string) $arguments[0];

        return $this->strings[$key] ?? (isset($this->counters[$key]) ? (string) $this->counters[$key] : null);
    }

    /**
     * GETDEL: atomic read + remove of a plain string (null when absent) —
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

    /** INCR: bump the plain counter and return the new value. */
    private function fakeIncr(array $arguments): int
    {
        $key = (string) $arguments[0];
        $this->counters[$key] = ($this->counters[$key] ?? 0) + 1;

        return $this->counters[$key];
    }

    /** DECR: lower the plain counter (floored at 0) and return the new value. */
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
            // OutstandingChallenges::issue: KEYS[1] per-source counter,
            // KEYS[2] global counter; ARGV[1] source cap, ARGV[2] global
            // cap, ARGV[3] TTL seconds. GET both caps -> refuse 0/-1
            // BEFORE anything is written -> INCR both + EXPIRE both.
            $source = (string) $keys[0];
            $global = (string) $keys[1];
            $sourceCap = (int) $rest[0];
            $globalCap = (int) $rest[1];
            $ttl = (int) $rest[2];
            if (($this->counters[$source] ?? 0) >= $sourceCap) {
                return 0;
            }
            if (($this->counters[$global] ?? 0) >= $globalCap) {
                return -1;
            }
            $this->fakeIncr([$source]);
            $this->fakeIncr([$global]);
            $this->fakePexpire([$source, $ttl * 1000]);
            $this->fakePexpire([$global, $ttl * 1000]);

            return 1;
        }

        if (str_contains($script, 'Outstanding challenge solve')) {
            // OutstandingChallenges::solved: KEYS[1] per-source counter;
            // best-effort DECR floored at 0.
            $key = (string) $keys[0];
            $v = $this->counters[$key] ?? 0;
            if ($v > 0) {
                $this->fakeDecr([$key]);
            }

            return $v - 1;
        }

        if (str_contains($script, 'waiters')) {
            // Acquire with the bounded WAITERS guard (audit #31) + the
            // PER-SCOPE budget (audit #47): KEYS[1] global lease set,
            // KEYS[2] waiters counter, KEYS[3] per-scope lease set ('' =
            // no scope); ARGV[1] global cap, ARGV[2] leaseMs, ARGV[3]
            // token, ARGV[4] maxWaiters, ARGV[5] per-scope cap, ARGV[6]
            // hasScope. Grant (and serve one waiter) when the GLOBAL slot
            // is free AND the scope budget (when present) has room; the
            // lease is recorded in BOTH sets. Saturated acquires (either
            // cap) are counted in the GLOBAL waiters counter with the lease
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
            // Release with the PER-SCOPE budget (audit #47): KEYS[1] global
            // set, KEYS[2] per-scope set ('' = no scope); ARGV[1] token,
            // ARGV[2] hasScope. Removes the token from BOTH sets.
            $removed = $this->fakeZrem([$keys[0], $rest[0]]);
            if ((int) $rest[1] === 1) {
                $this->fakeZrem([$keys[1], $rest[0]]);
            }

            return $removed;
        }

        if (str_contains($script, 'return redis.call(\'ZCARD\', KEYS[1])')) {
            // Semaphore USAGE: TIME -> prune -> ZCARD in one script
            // (atomic-live — matches the acquire pruning).
            $key = (string) $keys[0];
            $this->fakeZremrangebyscore([$key, '-inf', (string) $this->timeMs()]);

            return $this->zcard($key);
        }

        if (str_contains($script, 'Scope issuance cap')) {
            // ScopeIssuanceCap::allow: KEYS[1] = {kiwi:<ns>}:issuance:<scope>:
            // <minute>; ARGV[1] = cap. INCR -> EXPIRE 60 on the first
            // increment -> refuse beyond the cap (0), else 1.
            $key = (string) $keys[0];
            $cap = (int) $rest[0];
            $n = $this->fakeIncr([$key]);
            if ($n === 1) {
                $this->fakePexpire([$key, 60000]);
            }

            return $n > $cap ? 0 : 1;
        }

        if (str_contains($script, 'redis.call(\'INCR\', KEYS[1])')) {
            // Issuance counter: INCR + EXPIRE 1 in one atomic script.
            $key = (string) $keys[0];
            $n = $this->fakeIncr([$key]);
            $this->fakePexpire([$key, 1000]);

            return $n;
        }

        if (str_contains($script, 'Decision registration: receipt + sample denominator + outcome ledger')) {
            // Canonical register_decision.lua: KEYS[1] receipt, KEYS[2]
            // decision-hour bucket, KEYS[3] outcome ledger;
            // ARGV[1] receipt JSON, ARGV[2] receipt TTL, ARGV[3] sampled,
            // ARGV[4] bucket TTL, ARGV[5] outcome TTL, ARGV[6] scope,
            // ARGV[7] decision_hour, ARGV[8] score, ARGV[9] weight.
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
            // Canonical confirm.lua (v2): KEYS[1] receipt, KEYS[2]
            // DECISION-TIME bucket, KEYS[3] outcome ledger;
            // ARGV[1] mode, ARGV[2] weight, ARGV[3] legitimate,
            // ARGV[4] bucket TTL, ARGV[5] outcome TTL, ARGV[6] expected
            // scope, ARGV[7] expected decision_hour.
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
            // Canonical correction.lua: KEYS[1] ledger, KEYS[2]
            // decision-time bucket; ARGV[1] new outcome, ARGV[2] weight,
            // ARGV[3] bucket TTL, ARGV[4] outcome TTL, ARGV[5] expected
            // scope, ARGV[6] expected hour.
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
            // Canonical outcome_register.lua: KEYS[1] ledger;
            // ARGV[1] scope, ARGV[2] hour, ARGV[3] score, ARGV[4] TTL.
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
            // Canonical outcome_confirm.lua: KEYS[1] ledger;
            // ARGV[1] outcome, ARGV[2] TTL.
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
            // Canonical outcome_correct.lua: KEYS[1] ledger;
            // ARGV[1] new outcome, ARGV[2] TTL.
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
