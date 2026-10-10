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
     *    it) and returns {json, consumed_now, consumed_before, result_json,
     *    identity_spliced}; the one-shot transition, not a delete. A
     *    cancelled record is never consumable: the script reports it as
     *    missing (nil), and the pending-envelope guard refuses a pending
     *    record that already carries a terminal or claim field
     *    (consumed_result, operation_identity, resume_owner /
     *    resume_until), mirroring the real Lua's raw-marker check. A key
     *    without an expiry row (the real PTTL < 0, a persistent foreign
     *    key) is refused untouched, and a non-empty identity argument
     *    that finds no `"operation_identity":null` marker reports the
     *    splice count 0 instead of silently recording the identity.
     *  - cancel-transition script: flips a pending record to the terminal
     *    cancelled marker (kept until its TTL) and returns
     *    {state: cancelled-now | cancelled | consumed}; missing is nil,
     *    and a key without an expiry row is refused untouched.
     *  - delete-if-pending script: missing / deleted-pending / cancelled
     *    (kept) / consumed (kept, verbatim).
     *  - commit-result script: stores {valid, binding} on a consumed record
     *    without a result yet; returns 1/0. With a non-empty ARGV[4] (the
     *    resume claim owner), the claim is a fencing precondition. The
     *    envelope must carry a live claim owned by exactly that token
     *    (the `resume_until` lease is epoch microseconds on the
     *    microsecond clock), otherwise 2 without a write. The successful
     *    write clears the claim fields in the same transition. A key
     *    without an expiry row is refused with 0 untouched.
     *  - resume-derivation claim script: splices `resume_owner` /
     *    `resume_until` (epoch microseconds, now + ttl seconds) into the
     *    record envelope (ONE key) only for a consumed, resultless,
     *    unclaimed, expiry-bearing record (returns the owner; nil
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
 * and the like). Every Lua invocation, plain EVAL or `EVALSHA`, also
 * records its key count and key list in
 * {@see FakePredisClient::$evals}, so tests can prove the single-key
 * invariant of the claim transitions, never `CROSSSLOT`, and identify
 * which script ran regardless of the transport. `EVALSHA` resolves the
 * sha back to the body through the `SCRIPT` `LOAD` registry
 * {@see FakePredisClient::$scriptsBySha}; a real Redis caches EVAL'd
 * bodies the same way. An unloaded sha raises the same `NOSCRIPT`
 * ServerException the server would, exercising the storage's reload
 * fallback. The sha of every `EVALSHA` is recorded in
 * {@see FakePredisClient::$evalshas} and every `SCRIPT` `LOAD` body in
 * {@see FakePredisClient::$scriptLoads}.
 */
final class FakePredisClient extends \Predis\Client
{
    /** @var array<string, string> */
    public array $store = [];

    /** @var array<string, int> */
    public array $expirations = [];

    /**
     * Keys written by a raw SET with no EX/SETEX TTL — the fake's
     * stand-in for a persistent key (the real PTTL -1). The mutating
     * Lua transitions refuse these untouched; the default (a key the
     * registry has no row for) is an expiry-bearing key, so a caller
     * that copies {@see FakePredisClient::$store} between fakes keeps
     * the expiry-bearing semantics the real store() wrote.
     *
     * @var array<string, true>
     */
    public array $noExpiry = [];

    /** Number of replicas the WAIT command reports as acknowledging. */
    public int $waitAck = 0;

    /**
     * A queue of acknowledged-replica counts for the next WAITs; each
     * WAIT pops the front value, and the queue falls back to $waitAck
     * once empty. The failover tests drive a shortfall on the Nth
     * barrier (e.g. the commit after a satisfied consume) with this
     * queue.
     *
     * @var list<int>
     */
    public array $waitAckQueue = [];

    /**
     * When true, every GET throws. This is the wire failure of the
     * runtime-state read: the verifier must answer StorageUnavailable
     * and leave the record untouched.
     */
    public bool $throwOnGet = false;

    /**
     * When true, every `EVAL` and `EVALSHA` throws. This is the lost or
     * refused Lua transition: the consume and the fused cleanup both
     * fail closed, and the record is never treated as consumed without
     * evidence (the throw happens before any mutation).
     */
    public bool $throwOnEval = false;

    /**
     * When > 0, every `EVAL` and `EVALSHA` from this 1-based invocation
     * onwards throws. The commit-write-failure scenario arms it after
     * the consume transition, so only the outcome commit fails.
     */
    public int $throwOnEvalFrom = \PHP_INT_MAX;

    /** Number of `EVAL`/`EVALSHA` invocations so far, for the threshold. */
    public int $evalCount = 0;

    /**
     * When true, every WAIT throws. This is a WAIT that never returns
     * an acknowledgement count, distinct from a shortfall reply: the
     * durability barrier fails closed either way.
     */
    public bool $throwOnWait = false;

    /**
     * When true, every SET throws. This is a refused write, e.g. the
     * replication-fence write of the stored-result replay guard.
     */
    public bool $throwOnSet = false;

    /** @var array<string, int> */
    public array $calls = [];

    /** Number of GET commands issued so far (the record-read counter). */
    public int $gets = 0;

    /** @var list<string> the key of every GET issued so far */
    public array $getKeys = [];

    /** @var list<array{script: string, keys: list<string>}> every Lua invocation's key list (EVAL or `EVALSHA`) */
    public array $evals = [];

    /** @var list<string> the sha of every `EVALSHA` issued so far */
    public array $evalshas = [];

    /** @var list<string> the body of every script registered through `SCRIPT` `LOAD` */
    public array $scriptLoads = [];

    /** @var array<string, string> sha => script body registry (`SCRIPT` `LOAD` and EVAL both populate it, like a real Redis) */
    public array $scriptsBySha = [];

    public function __construct()
    {
        // Deliberately skip the parent constructor: no connection setup.
    }

    public function __call($commandID, $arguments)
    {
        $this->calls[] = [strtoupper((string) $commandID), $arguments];

        return match (strtoupper((string) $commandID)) {
            'GET' => $this->throwOnGet ? $this->throwConnection() : $this->fakeGet($arguments),
            'SET' => $this->throwOnSet ? $this->throwConnection() : $this->fakeSet($arguments),
            'SETEX' => $this->throwOnSet ? $this->throwConnection() : $this->fakeSetex($arguments),
            'DEL' => $this->fakeDel($arguments),
            'EXISTS' => isset($this->store[(string) $arguments[0]]) ? 1 : 0,
            'EVAL' => $this->evalShouldThrow() ? $this->throwConnection() : $this->fakeEval($arguments),
            'EVALSHA' => $this->evalShouldThrow() ? $this->throwConnection() : $this->fakeEvalSha($arguments),
            'SCRIPT' => $this->fakeScript($arguments),
            'WAIT' => $this->nextWaitAck(),
            default => null,
        };
    }

    /**
     * The simulated wire failure of the fault-injection knobs: a generic
     * connection failure that propagates through the storage layer the
     * way a dead socket would. The storage never catches it, so the
     * verifier's typed mapping decides the outcome.
     */
    private function throwConnection(): never
    {
        throw new \RuntimeException('simulated Redis connection failure');
    }

    /** Whether the next Lua invocation must throw. */
    private function evalShouldThrow(): bool
    {
        $this->evalCount++;

        return $this->throwOnEval || $this->evalCount >= $this->throwOnEvalFrom;
    }

    /** The acknowledged-replica count of the next WAIT, queue first. */
    private function nextWaitAck(): int
    {
        if ($this->waitAckQueue !== []) {
            return (int) array_shift($this->waitAckQueue);
        }

        return $this->waitAck;
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

        if ($id === 'WAIT') {
            if ($this->throwOnWait) {
                $this->throwConnection();
            }

            return $this->nextWaitAck();
        }

        return null;
    }

    /** @param list<mixed> $arguments */
    private function fakeSet(array $arguments): bool
    {
        $key = (string) $arguments[0];
        $this->store[$key] = (string) $arguments[1];
        if (($arguments[2] ?? null) === 'EX') {
            $this->expirations[$key] = (int) $arguments[3];
            unset($this->noExpiry[$key]);
        } else {
            // A raw SET with no TTL leaves the key persistent.
            $this->noExpiry[$key] = true;
            unset($this->expirations[$key]);
        }

        return true;
    }

    /** @param list<mixed> $arguments */
    private function fakeSetex(array $arguments): bool
    {
        // `SETEX` key ttl value: the TTL argument sits at index 1,
        // unlike the phpredis-style `SET` ... `EX` ttl at index 2. The
        // replication fence write of
        // RedisStorage::establishReplicationFence() uses `SETEX` on the
        // Predis branch.
        $key = (string) $arguments[0];
        $this->store[$key] = (string) ($arguments[2] ?? '');
        $this->expirations[$key] = (int) ($arguments[1] ?? 0);
        unset($this->noExpiry[$key]);

        return true;
    }

    /** @param list<mixed> $arguments */
    private function fakeDel(array $arguments): int
    {
        $removed = 0;
        foreach ($arguments as $key) {
            $k = (string) $key;
            if (isset($this->store[$k])) {
                unset($this->store[$k], $this->expirations[$k], $this->noExpiry[$k]);
                $removed++;
            }
        }

        return $removed;
    }

    /**
     * `SCRIPT` `LOAD`: register the body under its sha1 (the server's own
     * script-cache key) and return the sha, like a real Redis.
     *
     * @param list<mixed> $arguments ['`LOAD`', script]
     */
    private function fakeScript(array $arguments): string
    {
        if (strtoupper((string) ($arguments[0] ?? '')) !== 'LOAD') {
            return '';
        }
        $script = (string) ($arguments[1] ?? '');
        $sha = sha1($script);
        $this->scriptsBySha[$sha] = $script;
        $this->scriptLoads[] = $script;

        return $sha;
    }

    /**
     * `EVALSHA`: resolve the sha back to its body through the `SCRIPT` `LOAD`
     * registry and run it. An unknown sha raises the same `NOSCRIPT`
     * ServerException the server would, so the storage's reload
     * fallback is exercised for real.
     *
     * @param list<mixed> $arguments [sha, numKeys, key1..keyN, arg1..argN]
     */
    private function fakeEvalSha(array $arguments): mixed
    {
        $sha = (string) ($arguments[0] ?? '');
        if (!isset($this->scriptsBySha[$sha])) {
            throw new \Predis\Response\ServerException('NOSCRIPT No matching script. Please use EVAL.');
        }
        $script = $this->scriptsBySha[$sha];
        $numKeys = (int) $arguments[1];
        $keysAndArgs = \array_slice($arguments, 2);
        $keys = \array_slice($keysAndArgs, 0, $numKeys);
        $args = \array_slice($keysAndArgs, $numKeys);
        $this->evalshas[] = $sha;
        $this->evals[] = ['script' => $script, 'keys' => array_map('strval', $keys)];

        return $this->runScript($script, $keys, $args);
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
        // A real Redis caches the body of every EVAL under its sha too,
        // so a later `EVALSHA` for the same script succeeds.
        $this->scriptsBySha[sha1($script)] = $script;
        $this->evals[] = ['script' => $script, 'keys' => array_map('strval', $keys)];

        return $this->runScript($script, $keys, $args);
    }

    /**
     * The shared Lua emulation, dispatched on the script body's header
     * comment (the same dispatch the legacy EVAL-only fake used).
     *
     * @param list<string> $keys
     * @param list<mixed>  $args
     */
    private function runScript(string $script, array $keys, array $args): mixed
    {
        // Consume transition: mark consumed, keep the record. ARGV[1] is
        // the JSON-escaped operation identity ('' = none); it lands in
        // the same write as the state flip, mirroring the real Lua
        // splice, and the splice count rides the reply's fifth element —
        // a non-empty identity that finds no `"operation_identity":null`
        // marker reports 0, never a silent drop. A cancelled record is
        // never consumable: the transition reports it as missing (nil),
        // mirroring the real Lua's failed pending-marker splice. A key
        // without an expiry (the fake's expirations registry has no row,
        // the real PTTL < 0) is refused untouched, mirroring the
        // persistent-key refusal.
        if (str_contains($script, '-- kiwicaptcha consume transition')) {
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

                return [$raw, 0, 1, $res !== null ? json_encode($res, JSON_UNESCAPED_SLASHES) : '', 0];
            }
            if (($obj['state'] ?? 'pending') !== 'pending') {
                // Any other state marker is never consumable, mirroring
                // the real Lua's failed pending-marker splice.
                return null;
            }
            // The pending-envelope guard, mirroring the real Lua's
            // raw-marker check: a pending envelope that already carries a
            // terminal or claim field (a non-null consumed_result, a
            // non-null operation_identity, or any resume_owner /
            // resume_until marker) is refused with the missing
            // semantics.
            if (($obj['consumed_result'] ?? null) !== null
                || ($obj['operation_identity'] ?? null) !== null
                || isset($obj['resume_owner'])
                || isset($obj['resume_until'])) {
                return null;
            }
            if (!$this->hasExpiry($key)) {
                // A persistent foreign key (PTTL < 0): refused untouched.
                return false;
            }
            $obj['state'] = 'consumed';
            $spliced = 0;
            if (($args[0] ?? '') !== '') {
                if (\array_key_exists('operation_identity', $obj) && $obj['operation_identity'] === null) {
                    $obj['operation_identity'] = json_decode((string) $args[0], true, flags: JSON_THROW_ON_ERROR);
                    $spliced = 1;
                }
            }
            $this->store[$key] = json_encode($obj, JSON_UNESCAPED_SLASHES);

            // The winner receives the updated bytes (the identity rides
            // back on its own ConsumedRecord, mirroring the real Lua).
            return [$this->store[$key], 1, 0, '', $spliced];
        }

        // Delete-if-pending (atomic cleanup): missing reports missing;
        // a consumed record is returned verbatim and kept; a cancelled
        // record is returned verbatim and kept too (dead but retained
        // until its TTL); only a pending record is deleted — mirroring
        // the real Lua.
        if (str_contains($script, '-- kiwicaptcha delete-if-pending (atomic cleanup)')) {
            $key = (string) $keys[0];
            if (!isset($this->store[$key])) {
                return ['missing'];
            }
            $raw = $this->store[$key];
            try {
                $obj = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
            } catch (\JsonException) {
                // A value without the exact pending marker is corrupt:
                // the real Lua never mutates it and reports the
                // corruption.
                return ['corrupt'];
            }
            $state = $obj['state'] ?? 'pending';
            if ($state === 'consumed') {
                return ['consumed', $raw];
            }
            if ($state === 'cancelled') {
                return ['cancelled', $raw];
            }
            if ($state !== 'pending') {
                return ['corrupt'];
            }
            unset($this->store[$key]);

            return ['deleted-pending'];
        }

        // Cancel transition (atomic pending -> cancelled): a missing
        // record is nil, a consumed record is finalized and never
        // cancellable ('consumed'), an already-cancelled record is
        // idempotent ('cancelled'), a key without an expiry (the fake's
        // expirations registry has no row, the real PTTL < 0) is refused
        // untouched, and a pending record is flipped to the terminal
        // cancelled marker and kept ('cancelled-now') — mirroring the
        // real Lua splice.
        if (str_contains($script, '-- kiwicaptcha cancel transition')) {
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
            if (!$this->hasExpiry($key)) {
                // A persistent foreign key (PTTL < 0): refused untouched.
                return false;
            }
            $obj['state'] = 'cancelled';
            $this->store[$key] = json_encode($obj, JSON_UNESCAPED_SLASHES);

            return ['cancelled-now'];
        }

        // Commit result: only on a consumed record without a
        // result yet. ARGV = [valid, binding, has_binding, claim_owner, mac].
        // With a non-empty ARGV[4] (the resume claim owner), the claim
        // is a fencing precondition: the envelope must carry a live
        // claim owned by exactly that token (ownership lost returns 2,
        // no write; the lease expiry `resume_until` is epoch
        // microseconds, compared on the microsecond clock), and the
        // successful write clears the claim fields in the same
        // transition. A key without an expiry is refused with 0
        // untouched, mirroring the persistent-key refusal.
        if (str_contains($script, '-- kiwicaptcha commit result')) {
            $key = (string) $keys[0];
            if (!isset($this->store[$key])) {
                return 0;
            }
            if (!$this->hasExpiry($key)) {
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
                if (($obj['resume_owner'] ?? null) !== $owner || !\is_int($until) || $until <= (int) (microtime(true) * 1_000_000)) {
                    return 2;
                }
            }
            $obj['consumed_result'] = [
                'valid' => ($args[0] ?? '0') === '1',
                'binding' => ($args[2] ?? '0') === '1' ? (string) ($args[1] ?? '') : null,
            ];
            // ARGV[5]: the server-state MAC over the result, stored when
            // non-empty (the authenticated commit).
            if (($args[4] ?? '') !== '') {
                $obj['consumed_result']['mac'] = (string) $args[4];
            }
            if ($owner !== '') {
                unset($obj['resume_owner'], $obj['resume_until']);
            }
            $this->store[$key] = json_encode($obj, JSON_UNESCAPED_SLASHES);

            return 1;
        }

        // Resume-derivation claim: KEYS = [record] only, ARGV =
        // [owner, ttl]. The claim is refused (nil) for a missing,
        // not-consumed, committed, cancelled or expiry-less (persistent)
        // record, or while a live claim is held; otherwise
        // `resume_owner` / `resume_until` (now + ttl, epoch MICROseconds)
        // are spliced into the envelope, mirroring the real single-key
        // Lua's true-seconds lease.
        if (str_contains($script, '-- kiwicaptcha resume-derivation claim')) {
            if (str_contains($script, '-- kiwicaptcha resume-derivation claim release')) {
                // Compare-and-delete release: the embedded claim fields
                // are cleared only when they still hold exactly this
                // owner. A key without an expiry is refused with 0
                // untouched, mirroring the persistent-key refusal.
                $key = (string) $keys[0];
                if (!isset($this->store[$key])) {
                    return 0;
                }
                if (!$this->hasExpiry($key)) {
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
            if (!$this->hasExpiry($key)) {
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
            $nowUs = (int) (microtime(true) * 1_000_000);
            if (isset($obj['resume_owner']) && isset($obj['resume_until']) && $obj['resume_until'] > $nowUs) {
                return null;
            }
            $obj['resume_owner'] = (string) ($args[0] ?? '');
            $obj['resume_until'] = $nowUs + (int) ($args[1] ?? 0) * 1_000_000;
            $this->store[$key] = json_encode($obj, JSON_UNESCAPED_SLASHES);

            return $args[0] ?? null;
        }

        return null;
    }

    /**
     * Whether the key carries an expiry (the fake's stand-in for PTTL >=
     * 0): only a key explicitly written without a TTL (a raw SET, the
     * {@see FakePredisClient::$noExpiry} registry) is persistent; every
     * other present key is expiry-bearing, the state store() writes.
     */
    private function hasExpiry(string $key): bool
    {
        return !($this->noExpiry[$key] ?? false);
    }
}
