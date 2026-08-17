<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Fixtures;

/**
 * In-memory stand-in for Predis\Client used by the RedisStorage tests.
 *
 * There is no real Redis in CI. Predis dispatches every command through
 * `__call`, so this fake intercepts exactly the commands RedisStorage sends
 * (get, set, del, eval, exists, wait) and emulates the Lua scripts'
 * semantics:
 *
 *  - consume-transition script: marks the stored record consumed (keeps it)
 *    and returns {json, consumed_now, consumed_before, result_json} — the
 *    one-shot transition, not a delete.
 *  - commit-result script: stores {valid, binding} on a consumed record
 *    without a result yet; returns 1/0.
 *  - WAIT: returns {@see FakePredisClient::$waitAck} (default 0 — a real
 *    replica-less Redis reports 0 acknowledged replicas without error; only
 *    the number of acknowledged replicas is returned). Tests set waitAck to
 *    model a satisfied or violated durability barrier.
 *
 * Every call is recorded in {@see FakePredisClient::$calls} so tests can
 * assert on the Redis commands issued (Lua usage, EX expiration, WAIT
 * arguments, etc.).
 */
final class FakePredisClient extends \Predis\Client
{
    /** @var array<string, string> */
    public array $store = [];

    /** @var array<string, int> */
    public array $expirations = [];

    /** Number of replicas WAIT reports as acknowledging the last write. */
    public int $waitAck = 0;

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
            'EXISTS' => isset($this->store[(string) $arguments[0]]) ? 1 : 0,
            'EVAL' => $this->fakeEval($arguments),
            'WAIT' => $this->waitAck,
            default => null,
        };
    }

    /**
     * Predis removed the typed wait() method; RedisStorage's WAIT goes
     * through executeRaw (the raw-command escape hatch). Record the call
     * like any other so tests can assert on it; the acknowledged-replica
     * count is {@see FakePredisClient::$waitAck}.
     *
     * @param list<mixed> $arguments raw command: [commandID, ...args]
     */
    public function executeRaw(array $arguments, &$error = null): mixed
    {
        $id = strtoupper((string) ($arguments[0] ?? ''));
        $this->calls[] = [$id, \array_slice($arguments, 1)];

        return $id === 'WAIT' ? $this->waitAck : null;
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

    /**
     * @param list<mixed> $arguments [script, numKeys, key1..keyN, arg1..argN]
     */
    private function fakeEval(array $arguments): mixed
    {
        $script = (string) $arguments[0];
        $numKeys = (int) $arguments[1];
        $keysAndArgs = \array_slice($arguments, 2);
        $keys = \array_slice($keysAndArgs, 0, $numKeys);
        $args = \array_slice($keysAndArgs, $numKeys);

        // Consume transition: mark consumed, keep the record.
        if (str_contains($script, 'consume transition')) {
            $key = (string) $keys[0];
            if (!isset($this->store[$key])) {
                return null;
            }
            $raw = $this->store[$key];
            try {
                $obj = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
            } catch (\JsonException) {
                // The real Lua pcall-wraps the decode: corrupt values
                // degrade to "missing" instead of erroring the eval.
                return null;
            }
            if (($obj['state'] ?? 'pending') === 'consumed') {
                $res = $obj['consumed_result'] ?? null;

                return [$raw, 0, 1, $res !== null ? json_encode($res, JSON_UNESCAPED_SLASHES) : ''];
            }
            $obj['state'] = 'consumed';
            $this->store[$key] = json_encode($obj, JSON_UNESCAPED_SLASHES);

            return [$raw, 1, 0, ''];
        }

        // Commit result: only on a consumed record without a
        // result yet. ARGV = [valid, binding, has_binding].
        if (str_contains($script, 'commit result')) {
            $key = (string) $keys[0];
            if (!isset($this->store[$key])) {
                return 0;
            }
            try {
                $obj = json_decode($this->store[$key], true, flags: JSON_THROW_ON_ERROR);
            } catch (\JsonException) {
                return 0;
            }
            if (($obj['state'] ?? 'pending') !== 'consumed') {
                return 0;
            }
            if (isset($obj['consumed_result']) && $obj['consumed_result'] !== null) {
                return 0;
            }
            $obj['consumed_result'] = [
                'valid' => ($args[0] ?? '0') === '1',
                'binding' => ($args[2] ?? '0') === '1' ? (string) ($args[1] ?? '') : null,
            ];
            $this->store[$key] = json_encode($obj, JSON_UNESCAPED_SLASHES);

            return 1;
        }

        return null;
    }
}
