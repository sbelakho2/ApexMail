<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Fixtures;

/**
 * In-memory stand-in for Predis\Client used by the RedisStorage tests.
 *
 * There is no real Redis in CI. Predis dispatches every command
 * through `__call`, so this fake intercepts exactly the commands
 * RedisStorage sends (get, set, del, eval, exists, wait). It emulates
 * the Lua scripts' semantics:
 *
 *  - consume-transition script: marks the stored record consumed (keeps
 *    it) and returns {json, consumed_now, consumed_before, result_json};
 *    the one-shot transition, not a delete. A cancelled record is never
 *    consumable: the script reports it as missing (nil).
 *  - cancel-transition script: flips a pending record to the terminal
 *    cancelled marker (kept until its TTL) and returns
 *    {state: cancelled-now | cancelled | consumed}; missing is nil.
 *  - delete-if-pending script: missing / deleted-pending / cancelled
 *    (kept) / consumed (kept, verbatim).
 *  - commit-result script: stores {valid, binding} on a consumed record
 *    without a result yet; returns 1/0. With a non-empty ARGV[4] (the
 *    resume claim owner), the claim is a fencing precondition: the
 *    envelope must carry a live claim owned by exactly that token,
 *    otherwise 2 without a write. The successful write clears the
 *    claim fields in the same transition.
 *  - resume-derivation claim script: splices `resume_owner` /
 *    `resume_until` into the record envelope (ONE key) only for a
 *    consumed, resultless, unclaimed record (returns the owner; nil
 *    otherwise).
 *  - resume-derivation claim release script: compare-and-delete of the
 *    embedded claim fields (1 when the owner matches, 0 otherwise).
 *  - WAIT: returns {@see FakePredisClient::$waitAck} (default 0; a real
 *    replica-less Redis reports 0 acknowledged replicas without error,
 *    and only the number of acknowledged replicas is returned). Tests
 *    set waitAck to model a satisfied or violated durability barrier.
 *
 * Every call is recorded in {@see FakePredisClient::$calls} so tests
 * can assert on the Redis commands issued (Lua usage, EX expiration,
 * and the like). Every EVAL additionally records its key count and key
 * list in {@see FakePredisClient::$evals}, so tests can prove the
 * single-key invariant of the claim transitions (never `CROSSSLOT`).
 */
final class FakePredisClient extends \Predis\Client
{
    /** @var array<string, string> */
    public array $store = [];

    /** @var array<string, int> */
    public array $expirations = [];

    /** Number of replicas the WAIT command reports as acknowledging. */
    public int $waitAck = 0;

    /** @var list<array{0: string, 1: list<mixed>}> */
    public array $calls = [];

    /** Number of GET commands issued so far (the record-read counter). */
    public int $gets = 0;

    /** @var list<string> the key of every GET issued so far */
    public array $getKeys = [];

    /** @var list<array{script: string, keys: list<string>}> every EVAL's key list */
    public array $evals = [];

    public function __construct()
    {
        // Deliberately skip the parent constructor: no connection setup.
    }

    public function __call($commandID, $arguments)
    {
        $this->calls[] = [strtoupper((string) $commandID), $arguments];

        return match (strtoupper((string) $commandID)) {
            'GET' => $this->fakeGet($arguments),
            'SET' => $this->fakeSet($arguments),
            'DEL' => $this->fakeDel($arguments),
            'EXISTS' => isset($this->store[(string) $arguments[0]]) ? 1 : 0,
            'EVAL' => $this->fakeEval($arguments),
            'WAIT' => $this->waitAck,
            default => null,
        };
    }

    /** @param list<mixed> $arguments */
    private function fakeGet(array $arguments): ?string
    {
        $this->gets++;
        $this->getKeys[] = (string) $arguments[0];

        return $this->store[(string) $arguments[0]] ?? null;
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
        $this->evals[] = ['script' => $script, 'keys' => array_map('strval', $keys)];

        // Consume transition: mark consumed, keep the record. ARGV[1] is
        // the JSON-escaped operation identity ('' = none); it lands in
        // the same write as the state flip, mirroring the real Lua
        // splice. A cancelled record is never consumable: the transition
        // reports it as missing (nil), mirroring the real Lua's failed
        // pending-marker splice.
        if (str_starts_with($script, '-- kiwicaptcha consume transition')) {
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
            if (($obj['state'] ?? 'pending') === 'cancelled') {
                return null;
            }
            if (($obj['state'] ?? 'pending') === 'consumed') {
                $res = $obj['consumed_result'] ?? null;

                return [$raw, 0, 1, $res !== null ? json_encode($res, JSON_UNESCAPED_SLASHES) : ''];
            }
            $obj['state'] = 'consumed';
            if (($args[0] ?? '') !== '') {
                $obj['operation_identity'] = json_decode((string) $args[0], true, flags: JSON_THROW_ON_ERROR);
            }
            $this->store[$key] = json_encode($obj, JSON_UNESCAPED_SLASHES);

            // The winner receives the updated bytes (the identity rides
            // back on its own ConsumedRecord, mirroring the real Lua).
            return [$this->store[$key], 1, 0, ''];
        }

        // Delete-if-pending (atomic cleanup): missing reports missing;
        // a consumed record is returned verbatim and kept; a cancelled
        // record is returned verbatim and kept too (dead but retained
        // until its TTL); only a pending record is deleted — mirroring
        // the real Lua.
        if (str_starts_with($script, '-- kiwicaptcha delete-if-pending (atomic cleanup)')) {
            $key = (string) $keys[0];
            if (!isset($this->store[$key])) {
                return ['missing'];
            }
            $raw = $this->store[$key];
            try {
                $obj = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
            } catch (\JsonException) {
                // Corrupt values degrade to "missing" like the real Lua.
                return ['missing'];
            }
            if (($obj['state'] ?? 'pending') === 'consumed') {
                return ['consumed', $raw];
            }
            if (($obj['state'] ?? 'pending') === 'cancelled') {
                return ['cancelled', $raw];
            }
            unset($this->store[$key]);

            return ['deleted-pending'];
        }

        // Cancel transition (atomic pending -> cancelled): a missing
        // record is nil, a consumed record is finalized and never
        // cancellable ('consumed'), an already-cancelled record is
        // idempotent ('cancelled'), and a pending record is flipped to
        // the terminal cancelled marker and kept ('cancelled-now') —
        // mirroring the real Lua splice.
        if (str_starts_with($script, '-- kiwicaptcha cancel transition')) {
            $key = (string) $keys[0];
            if (!isset($this->store[$key])) {
                return null;
            }
            $raw = $this->store[$key];
            try {
                $obj = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
            } catch (\JsonException) {
                // Corrupt values degrade to "missing" like the real Lua.
                return null;
            }
            if (($obj['state'] ?? 'pending') === 'consumed') {
                return ['consumed'];
            }
            if (($obj['state'] ?? 'pending') === 'cancelled') {
                return ['cancelled'];
            }
            $obj['state'] = 'cancelled';
            $this->store[$key] = json_encode($obj, JSON_UNESCAPED_SLASHES);

            return ['cancelled-now'];
        }

        // Commit result: only on a consumed record without a
        // result yet. ARGV = [valid, binding, has_binding, claim_owner].
        // With a non-empty ARGV[4] (the resume claim owner), the claim
        // is a fencing precondition: the envelope must carry a live
        // claim owned by exactly that token (ownership lost returns 2,
        // no write), and the successful write clears the claim fields
        // in the same transition.
        if (str_starts_with($script, '-- kiwicaptcha commit result')) {
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
            $owner = $args[3] ?? '';
            if ($owner !== '') {
                $until = $obj['resume_until'] ?? null;
                if (($obj['resume_owner'] ?? null) !== $owner || !\is_int($until) || $until <= time()) {
                    return 2;
                }
            }            $obj['consumed_result'] = [
                'valid' => ($args[0] ?? '0') === '1',
                'binding' => ($args[2] ?? '0') === '1' ? (string) ($args[1] ?? '') : null,
            ];
            if ($owner !== '') {
                unset($obj['resume_owner'], $obj['resume_until']);
            }
            $this->store[$key] = json_encode($obj, JSON_UNESCAPED_SLASHES);

            return 1;
        }

        // Resume-derivation claim: KEYS = [record] only, ARGV =
        // [owner, ttl]. The claim is refused (nil) for a missing,
        // not-consumed, committed or cancelled record, or while a live
        // claim is held; otherwise `resume_owner` / `resume_until`
        // (now + ttl, epoch seconds) are spliced into the envelope,
        // mirroring the real single-key Lua.
        if (str_starts_with($script, '-- kiwicaptcha resume-derivation claim')) {
            if (str_starts_with($script, '-- kiwicaptcha resume-derivation claim release')) {
                // Compare-and-delete release: the embedded claim fields
                // are cleared only when they still hold exactly this
                // owner.
                $key = (string) $keys[0];
                if (!isset($this->store[$key])) {
                    return 0;
                }
                try {
                    $obj = json_decode($this->store[$key], true, flags: JSON_THROW_ON_ERROR);
                } catch (\JsonException) {
                    return 0;
                }
                if (($obj['resume_owner'] ?? null) !== ($args[0] ?? null)) {
                    return 0;
                }
                unset($obj['resume_owner'], $obj['resume_until']);
                $this->store[$key] = json_encode($obj, JSON_UNESCAPED_SLASHES);

                return 1;
            }
            $key = (string) $keys[0];
            if (!isset($this->store[$key])) {
                return null;
            }
            try {
                $obj = json_decode($this->store[$key], true, flags: JSON_THROW_ON_ERROR);
            } catch (\JsonException) {
                return null;
            }
            if (($obj['state'] ?? 'pending') !== 'consumed' || ($obj['state'] ?? 'pending') === 'cancelled') {
                return null;
            }
            if (isset($obj['consumed_result']) && $obj['consumed_result'] !== null) {
                return null;
            }
            $now = time();
            if (isset($obj['resume_owner']) && isset($obj['resume_until']) && $obj['resume_until'] > $now) {
                return null;
            }
            $obj['resume_owner'] = (string) ($args[0] ?? '');
            $obj['resume_until'] = $now + (int) ($args[1] ?? 0);
            $this->store[$key] = json_encode($obj, JSON_UNESCAPED_SLASHES);

            return $args[0] ?? null;
        }

        return null;
    }
}
