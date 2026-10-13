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
     *    tokenized-lease semaphore, the sliding-window rate limiter, the
     *    scope-issuance sliding-window cap and the verified-agent
     *    per-minute/per-day quota windows.
     *  - hincrbyfloat: one hash field bump (the calibration score-bucket
     *    outcome counters).
     *  - eval/evalsha/script: interprets the bundle's Lua scripts by their
     *    shape — semaphore acquire/release, outstanding-challenge
     *    issue/solve, the rate limiter, the scope-issuance sliding
     *    window, calibration confirm/correct, the step-up lock arm and
     *    the outcome-ledger confirm/correct, mirroring the scripts'
     *    semantics. It also interprets the kiwicaptcha core's consume,
 *    cancel, delete-if-pending and commit-result scripts, so the same
 *    fake drives the core RedisStorage for the cancellation endpoint's
 *    record transitions. `EVALSHA` resolves the sha back to the body
 *    through the `SCRIPT` `LOAD` registry, a real Redis caches EVAL'd
 *    bodies the same way. An unloaded sha raises the same `NOSCRIPT`
 *    ServerException the server would, so the storage's reload
 *    fallback is exercised for real.
 *
 * Every call is recorded in {@see FakePredisClient::$calls} so tests can
 * assert on the Redis commands issued.
 */
final class FakePredisClient extends \Predis\Client
{
    /** @var array<string, string> sha => script body registry (`SCRIPT` `LOAD` and EVAL both populate it, like a real Redis) */
    private array $scriptsBySha = [];

    /** @var list<string> the body of every script registered through `SCRIPT` `LOAD` */
    private array $scriptLoads = [];

    /** @var list<string> the sha of every `EVALSHA` issued so far */
    private array $evalshas = [];
    /** @var array<string, array<string, float>> sorted sets: key => member => score */
    public array $zsets = [];

    /** @var array<string, int> pexpire/expire deadlines in ms */
    public array $expirations = [];

    /** @var array<string, int> plain incr counters (issuance-rate signal) */
    public array $counters = [];

    /** @var array<string, string> plain strings (SET / getdel decision handles) */
    public array $strings = [];

    /**
     * The emulated `INFO` replication identity: role + run_id (the
     * pinned-primary authority guard reads exactly these fields). The
     * run_id defaults to a 40-hex string, the Redis shape.
     *
     * @var array{role: string, run_id: string}
     */
    public array $infoReplication = [
        'role' => 'master',
        'run_id' => '0123456789abcdef0123456789abcdef01234567',
    ];

    /** @var array{run_id: string} the emulated `INFO` server section (the run_id fallback) */
    public array $infoServer = [
        'run_id' => '0123456789abcdef0123456789abcdef01234567',
    ];

    /** @var array<string, array<string, float|string>> hashes (hincrbyfloat calibration buckets + hset policy fields) */
    public array $hashes = [];

    /** @var array<string, array<string, true>> the target-dimension spread sets (the HLL fakes) */
    public array $targetSpreadSets = [];

    /** @var list<array{0: string, 1: list<mixed>}> */
    public array $calls = [];

    /**
     * Adversarial-race hook for SET: invoked with the key and value right
     * before the write lands, so a test can install a competing value
     * inside a check-then-write window, such as the legacy-pin
     * migration's read-then-write gap.
     *
     * @var \Closure|null
     */
    public ?\Closure $beforeSet = null;

    private float $clockMs = 0.0;

    /**
     * The standalone connection object the authority-safety classifier
     * inspects. Defaults to a real direct StreamConnection (retries
     * disabled), so the pinned-primary authority guard and the
     * fail_closed runtime classifier see a provably-safe single-node
     * client. Set to null to model an uninspectable client.
     *
     * @var \Predis\Connection\NodeConnectionInterface|null
     */
    public ?\Predis\Connection\NodeConnectionInterface $connectionOverride = null;

    public function __construct()
    {
        // Deliberately skip the parent constructor: no connection setup.
        $this->connectionOverride = new \Predis\Connection\StreamConnection(new \Predis\Connection\Parameters());
    }

    public function getConnection(): mixed
    {
        return $this->connectionOverride;
    }

    /**
     * No-op connect: the emulated commands never open a real socket,
     * and the durability session of the pinned-primary wrapper pins
     * its connection with `connect()` before the barrier commands.
     */
    public function connect(): void
    {
    }

    /**
     * Raw-command emulation: records the call and answers the
     * emulated server. The verified-WAIT barrier (`WAIT` through the
     * guarded wrapper's `executeRaw`) lands here; the default answer
     * is the replica-less ack 0, overridable via
     * {@see FakePredisClient::$waitAck}.
     *
     * @param list<mixed> $arguments
     */
    public function executeRaw(array $arguments, &$error = null): mixed
    {
        $this->calls[] = ['RAW', $arguments];

        return $this->waitAck;
    }

    /** The ack the emulated `WAIT` answers (default 0 = no replica). */
    public int $waitAck = 0;

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

    /**
     * Test-facing mirror of the per-source live count (the source ZSET's
     * ZCARD) under the `counters[<sourceKey>]` key, so assertions keep
     * reading the per-source slot count.
     */
    private function mirrorSourceCount(string $sourceZset): void
    {
        $this->counters[$sourceZset] = $this->zcard($sourceZset);
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
            'EVALSHA' => $this->fakeEvalSha($arguments),
            'SCRIPT' => $this->fakeScript($arguments),
            'INCR' => $this->fakeIncr($arguments),
            'DECR' => $this->fakeDecr($arguments),
            'GET' => $this->fakeGet($arguments),
            'GETDEL' => $this->fakeGetdel($arguments),
            'SET' => $this->fakeSet($arguments),
            'EXISTS' => $this->fakeExists($arguments),
            'HINCRBYFLOAT' => $this->fakeHincrbyfloat($arguments),
            'HGETALL' => $this->fakeHgetall($arguments),
            'HSET' => $this->fakeHset($arguments),
            'HGET' => $this->fakeHget($arguments),
            'INFO' => $this->fakeInfo($arguments),
            'PING' => $this->pingOk() ? 'PONG' : throw new \RuntimeException('connection refused (fake)'),
            default => null,
        };
    }

    /**
     * `INFO` emulation: the replication section (role + run_id, the
     * pinned-primary identity) and the server section (the run_id
     * fallback). Mirrors the shape Predis parses from a real server.
     *
     * @param list<mixed> $arguments [section]
     */
    private function fakeInfo(array $arguments): array
    {
        $section = strtolower((string) ($arguments[0] ?? ''));

        return $section === 'replication' ? $this->infoReplication : $this->infoServer;
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
     * GET: the plain string value, then the plain incr counter, or null when
     * the key does not exist.
     */
    private function fakeGet(array $arguments): ?string
    {
        $key = (string) $arguments[0];

        return $this->strings[$key] ?? (isset($this->counters[$key]) ? (string) $this->counters[$key] : null);
    }

    /**
     * `EXISTS`: the per-key existence count across the fake's key spaces
     * (strings, counters, hashes, sorted sets), exactly the answer a
     * real server gives a live key. Expiry stays lazy here, like every
     * other read command of this fake: an armed TTL alone never removes
     * a key.
     *
     * @param list<mixed> $arguments
     */
    private function fakeExists(array $arguments): int
    {
        $found = 0;
        foreach ($arguments as $key) {
            $key = (string) $key;
            if (isset($this->strings[$key])
                || isset($this->counters[$key])
                || isset($this->hashes[$key])
                || isset($this->zsets[$key])) {
                $found++;
            }
        }

        return $found;
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
    /**
     * Test hook for the `EXPIREAT` the issuance script applies to the
     * membership keys (the key-level retention: the key dies at the
     * latest member deadline + margin).
     */
    private function fakeExpireatMs(string $key, int $ms): void
    {
        $this->expirations[$key] = $ms;
    }

    private function fakeSet(array $arguments): ?string
    {
        $key = (string) $arguments[0];
        $value = (string) $arguments[1];
        // Adversarial-race hook: runs after the caller resolved its write
        // decision but before the write lands, so a test can install a
        // competing value exactly inside a check-then-write window.
        if ($this->beforeSet !== null) {
            ($this->beforeSet)($key, $value);
        }
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

    /**
     * The assurance family a stored challenge kind proves, the same
     * ladder the factor completion script carries: the anonymous
     * email-ownership grant answers as the email_otp rung, the weakest
     * of the ladder. Null for a kind outside the ladder.
     */
    private static function challengeKindFamily(string $kind): ?string
    {
        return match ($kind) {
            'totp' => 'totp',
            'webauthn' => 'webauthn',
            'email_otp', 'email_ownership' => 'email_otp',
            default => null,
        };
    }

    /** The assurance rank of a stored challenge kind, null outside the ladder. */
    private static function challengeKindRank(string $kind): ?int
    {
        return match ($kind) {
            'totp' => 2,
            'webauthn' => 3,
            'email_otp', 'email_ownership' => 1,
            default => null,
        };
    }

    /**
     * TTL emulation for a plain string key: the armed lifetime in
     * whole seconds (the fake stores the pexpire/ex delta), or null
     * when the key carries no TTL.
     */
    private function remainingTtl(string $key): ?int
    {
        $ms = $this->expirations[$key] ?? null;
        if ($ms === null) {
            return null;
        }

        return (int) ceil($ms / 1000);
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

    /**
     * `SCRIPT` `LOAD`: register the body under sha1(body) like a real Redis
     * script cache and return the sha (the storage's `EVALSHA` path
     * resolves through this registry). Any other `SCRIPT` subcommand
     * returns '' — never a loadable sha.
     *
     * @param list<mixed> $arguments [subcommand, body]
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
     * The target dimension (target_failure.lua) over the fake's own
     * state: the leaky failure counter in the target hash, the two
     * spread sets as plain distinct-element sets, the window TTL on
     * every write. Answers the Lua's five-slot list.
     *
     * @param list<string> $keys [target hash, source spread, asn spread]
     * @param list<string> $args [op, source element, asn element, ttl]
     *
     * @return list<int>
     */
    private function fakeTargetFailure(array $keys, array $args): array
    {
        $op = $args[0] ?? 'read';
        $source = $args[1] ?? '';
        $asn = $args[2] ?? '';
        $now = (int) $this->clockMs;
        $hash = $this->hashes[$keys[0]] ?? [];
        $ts = (int) ($hash['ts'] ?? 0);
        $fails = (int) ($hash['fails'] ?? 0);
        // The leak: one failure per elapsed whole minute since the
        // watermark; the watermark advances only by whole leaked
        // minutes (the sub-minute remainder stays armed).
        if ($ts !== 0) {
            $leaked = intdiv(max(0, $now - $ts), 60000);
            $fails = max(0, $fails - $leaked);
            $ts = $ts + $leaked * 60000;
        }
        $spreadKey = 'target-spread:'.$keys[0];
        $set = $this->targetSpreadSets[$spreadKey] ?? [];
        if ($op === 'fail') {
            ++$fails;
            if ($ts === 0) {
                $ts = $now;
            }
            $this->hashes[$keys[0]] = [
                'ts' => (string) $ts,
                'fails' => (string) $fails,
                'last_ms' => (string) $now,
                'first_ms' => (string) ($hash['first_ms'] ?? $now),
            ];
            $this->expirations[$keys[0]] = ((int) ($args[3] ?? 0)) * 1000;
            if ($source !== '') {
                $set['src:'.$source] = true;
            }
            if ($asn !== '') {
                $set['asn:'.$asn] = true;
            }
            $this->targetSpreadSets[$spreadKey] = $set;
            $this->expirations[$spreadKey] = ((int) ($args[3] ?? 0)) * 1000;

            return [
                $fails,
                $this->countSpread($set, 'src:'),
                $this->countSpread($set, 'asn:'),
                (int) $this->hashes[$keys[0]]['first_ms'],
                $now,
            ];
        }
        if ($op === 'clear') {
            $this->hashes[$keys[0]] = ['ts' => (string) $now, 'fails' => '0'];

            return [
                0,
                $this->countSpread($set, 'src:'),
                $this->countSpread($set, 'asn:'),
                (int) ($hash['first_ms'] ?? 0),
                $now,
            ];
        }

        return [
            $fails,
            $this->countSpread($set, 'src:'),
            $this->countSpread($set, 'asn:'),
            (int) ($hash['first_ms'] ?? 0),
            (int) ($hash['last_ms'] ?? 0),
        ];
    }

    /** @param array<string, true> $set */
    private function countSpread(array $set, string $prefix): int
    {
        $count = 0;
        foreach (array_keys($set) as $element) {
            if (str_starts_with($element, $prefix)) {
                ++$count;
            }
        }

        return $count;
    }

    /**
     * `EVALSHA`: resolve the sha back to its body through the `SCRIPT` `LOAD`
     * registry and run it through the same interpreter as EVAL. An
     * unknown sha raises the same `NOSCRIPT` ServerException the server
     * would, so the storage's reload fallback is exercised for real.
     *
     * @param list<mixed> $arguments [sha, numKeys, key1..keyN, arg1..argN]
     */
    private function fakeEvalSha(array $arguments): mixed
    {
        $sha = (string) ($arguments[0] ?? '');
        if (!isset($this->scriptsBySha[$sha])) {
            throw new \Predis\Response\ServerException('NOSCRIPT No matching script. Please use EVAL.');
        }
        $this->evalshas[] = $sha;
        $script = $this->scriptsBySha[$sha];
        $numKeys = (int) $arguments[1];
        $keysAndArgs = \array_slice($arguments, 2);

        return $this->fakeEval([$script, $numKeys, ...$keysAndArgs]);
    }

    /** @param list<mixed> $arguments */
    private function fakeEval(array $arguments): mixed
    {
        $script = (string) $arguments[0];
        $numKeys = (int) $arguments[1];
        $keysAndArgs = \array_slice($arguments, 2);
        $keys = \array_slice($keysAndArgs, 0, $numKeys);
        $rest = \array_slice($keysAndArgs, $numKeys);
        // A real Redis caches the body of every EVAL under its sha too,
        // so a later `EVALSHA` for the same script succeeds.
        $this->scriptsBySha[sha1($script)] = $script;

        if (str_contains($script, 'Target-account protection state')) {
            // The target dimension (target_failure.lua): keys[1] the
            // target state hash, keys[2]/keys[3] the source and asn
            // spread sets, argv[1] the op, argv[2]/argv[3] the spread
            // elements and argv[4] the window TTL. The failure counter
            // leaks one per minute; the spreads are plain distinct
            // element sets (the HLL cardinality of a set is its size).
            return $this->fakeTargetFailure(
                array_map('strval', $keys),
                array_map('strval', $rest),
            );
        }
        if (str_contains($script, 'Step-up attempt accounting')) {
            // RedisStepUpChallengeStore::recordFailure: keys[1] the
            // challenge record JSON string; argv[1] the attempt cap.
            // Bump attempts in the decoded record, remove the record at
            // the cap, keep it within its remaining TTL otherwise.
            // Answers the attempts now used, 0 at the cap (removed),
            // -1 when absent, -2 when the stored value is not a
            // decodable record (removed, fail-closed).
            $key = (string) $keys[0];
            $cap = (int) $rest[0];
            $raw = $this->strings[$key] ?? null;
            if ($raw === null) {
                return -1;
            }
            $rec = json_decode($raw, true);
            if (!\is_array($rec) || !\is_int($rec['attempts'] ?? null) || !\is_int($rec['max_attempts'] ?? null)) {
                unset($this->strings[$key]);

                return -2;
            }
            $rec['attempts']++;
            if ($rec['attempts'] >= $cap) {
                unset($this->strings[$key]);

                return 0;
            }
            $this->strings[$key] = (string) json_encode($rec, JSON_UNESCAPED_SLASHES);

            return $rec['attempts'];
        }

        if (str_contains($script, 'Step-up begin window')) {
            // RedisStepUpChallengeStore::countBegin: keys[1] the
            // per-principal fixed-window counter; argv[1] the window
            // seconds. INCR, arm the expiry exactly once with the first
            // admission, answer the new count.
            $key = (string) $keys[0];
            $n = $this->fakeIncr([$key]);
            if ($n === 1) {
                $this->fakePexpire([$key, (int) $rest[0] * 1000]);
            }

            return $n;
        }

        if (str_contains($script, 'Step-up lockout')) {
            // RedisStepUpChallengeStore::armLockout: keys[1] the lock
            // key; argv[1] the epoch-second deadline, argv[2] the PX
            // budget in millis. A strictly greater deadline replaces
            // the stored one with its budget; a shorter or equal
            // request leaves a live lock untouched. Always answers 1.
            $key = (string) $keys[0];
            $deadline = (int) $rest[0];
            $current = isset($this->strings[$key]) ? (int) $this->strings[$key] : 0;
            if ($deadline > $current) {
                $this->strings[$key] = (string) $deadline;
                $this->fakePexpire([$key, (int) $rest[1]]);
            }

            return 1;
        }

        if (str_contains($script, 'Step-up totp step')) {
            // RedisStepUpChallengeStore::markTotpStep: keys[1] the
            // per-principal last-used step string; argv[1] the step,
            // argv[2] the guard TTL seconds. A strictly newer step wins
            // and is stored; anything at or below the stored one is a
            // replay (0).
            $key = (string) $keys[0];
            $step = (int) $rest[0];
            $current = isset($this->strings[$key]) ? (int) $this->strings[$key] : null;
            if ($current !== null && $current >= $step) {
                return 0;
            }
            $this->strings[$key] = (string) $step;
            $this->fakePexpire([$key, (int) $rest[1] * 1000]);

            return 1;
        }

        if (str_contains($script, 'Step-up demand transition')) {
            // RedisStepUpChallengeStore demand lifecycle CAS: keys[1]
            // the demand record JSON; argv[1] the op, argv[2]/argv[3]
            // the op arguments. complete moves open to completed (the
            // record is kept, re-armed with the given TTL); claim moves
            // completed to finalizing (a stale finalizing claim past
            // its window is retaken); settle moves finalizing to the
            // named terminal state (kept within the remaining TTL).
            // Answers the updated record JSON, nil on a lost race or a
            // refused transition.
            $key = (string) $keys[0];
            $raw = $this->strings[$key] ?? null;
            if ($raw === null) {
                return null;
            }
            $rec = json_decode($raw, true);
            if (!\is_array($rec) || !\is_string($rec['state'] ?? null)) {
                unset($this->strings[$key]);

                return null;
            }
            $op = (string) $rest[0];
            $rearm = function (array $rec, ?int $ttlSecs = null) use ($key): string {
                $encoded = (string) json_encode($rec, JSON_UNESCAPED_SLASHES);
                $ttl = $ttlSecs ?? $this->remainingTtl($key);
                if ($ttl === null || $ttl <= 0) {
                    unset($this->strings[$key], $this->expirations[$key]);

                    return '';
                }
                $this->strings[$key] = $encoded;
                $this->fakePexpire([$key, $ttl * 1000]);

                return $encoded;
            };
            $stateAt = \is_int($rec['state_at'] ?? null) ? $rec['state_at'] : 0;
            if ($op === 'complete') {
                if (!empty($rec['superseded_by'])) {
                    return null;
                }
                if ($rec['state'] !== 'open') {
                    return null;
                }
                $rec['state'] = 'completed';
                $rec['state_at'] = (int) $rest[1];

                return $rearm($rec, (int) $rest[2]) === '' ? null : (string) json_encode($rec, JSON_UNESCAPED_SLASHES);
            }
            if ($op === 'claim') {
                if (!empty($rec['superseded_by'])) {
                    return null;
                }
                $now = (int) $rest[1];
                if ($rec['state'] === 'completed') {
                    $rec['state'] = 'finalizing';
                    $rec['state_at'] = $now;
                } elseif ($rec['state'] === 'finalizing') {
                    if (($now - $stateAt) < (int) $rest[2]) {
                        return null;
                    }
                    $rec['state_at'] = $now;
                } else {
                    return null;
                }

                return $rearm($rec) === '' ? null : (string) json_encode($rec, JSON_UNESCAPED_SLASHES);
            }
            if ($op === 'settle') {
                if ($rec['state'] !== 'finalizing') {
                    return null;
                }
                $terminal = (string) $rest[1];
                if ($terminal !== 'authorized' && $terminal !== 'denied' && $terminal !== 'superseded') {
                    return null;
                }
                if ($terminal === 'authorized' && !empty($rec['superseded_by'])) {
                    return null;
                }
                $rec['state'] = $terminal;
                $rec['state_at'] = (int) $rest[2];
                if ($terminal === 'authorized') {
                    // The authorized terminal books its settlement
                    // timestamp and its completed factor, exactly like
                    // the settle op of the demand transition script.
                    $rec['authorized_at'] = (int) $rest[2];
                    if ((string) $rest[3] !== '') {
                        $rec['factor'] = (string) $rest[3];
                    }
                }

                return $rearm($rec) === '' ? null : (string) json_encode($rec, JSON_UNESCAPED_SLASHES);
            }
            if ($op === 'fx') {
                // The effects journal write: one known effect moves to
                // its landed stamp, and only the authorized terminal
                // journals anything. The record keeps its remaining
                // lifetime exactly.
                if ($rec['state'] !== 'authorized') {
                    return null;
                }
                $effect = (string) $rest[1];
                if ($effect !== 'authorization_settled' && $effect !== 'outcome_credited'
                    && $effect !== 'session_restored' && $effect !== 'trust_written') {
                    return null;
                }
                $fx = \is_array($rec['fx'] ?? null) ? $rec['fx'] : [];
                $fx[$effect] = (int) $rest[2];
                $rec['fx'] = $fx;

                return $rearm($rec) === '' ? null : (string) json_encode($rec, JSON_UNESCAPED_SLASHES);
            }

            return null;
        }

        if (str_contains($script, 'Step-up demand root mint')) {
            // RedisStepUpChallengeStore::createRootDemand: keys[1] the
            // demand record, keys[2] the family index; argv[1] the
            // record JSON, argv[2] the ttl millis, argv[3] the demand
            // key prefix, argv[4] the demand id. A live family tip is
            // answered as-is; otherwise the record and the index are
            // written in this one transaction.
            $demandKey = (string) $keys[0];
            $indexKey = (string) $keys[1];
            $tip = $this->strings[$indexKey] ?? null;
            if (\is_string($tip) && $tip !== '' && isset($this->strings[(string) $rest[2].$tip])) {
                return json_encode(['existing' => $tip], JSON_UNESCAPED_SLASHES);
            }
            if (isset($this->strings[$demandKey])) {
                return null;
            }
            $this->strings[$demandKey] = (string) $rest[0];
            $this->fakePexpire([$demandKey, (int) $rest[1]]);
            $this->strings[$indexKey] = (string) $rest[3];
            $this->fakePexpire([$indexKey, (int) $rest[1]]);

            return json_encode(['created' => $rest[3]], JSON_UNESCAPED_SLASHES);
        }

        if (str_contains($script, 'Step-up demand escalation')) {
            // RedisStepUpChallengeStore::supersedeDemandWithChild:
            // keys[1] the parent record, keys[2] the child record,
            // keys[3] the family index; argv[1] the child JSON, argv[2]
            // the child id. The parent must be present, unsuperseded and
            // unexpired on the fake server clock; the child key must be
            // free and inherit the parent expiry exactly; the child is
            // written within the parent's remaining lifetime, the
            // parent is marked superseded with the same lifetime and
            // the index repoints at the child.
            $parentKey = (string) $keys[0];
            $childKey = (string) $keys[1];
            $indexKey = (string) $keys[2];
            $raw = $this->strings[$parentKey] ?? null;
            if (!\is_string($raw)) {
                return null;
            }
            $parent = json_decode($raw, true);
            if (!\is_array($parent) || !\is_int($parent['expires_at'] ?? null)) {
                return null;
            }
            if (!empty($parent['superseded_by'])) {
                return null;
            }
            if (($parent['state'] ?? null) !== 'open' && ($parent['state'] ?? null) !== 'finalizing') {
                return null;
            }
            $nowS = (int) floor($this->timeMs() / 1000);
            if ($nowS >= $parent['expires_at']) {
                return null;
            }
            if (isset($this->strings[$childKey])) {
                return null;
            }
            $child = json_decode((string) $rest[0], true);
            if (!\is_array($child) || ($child['expires_at'] ?? null) !== $parent['expires_at']) {
                return null;
            }
            // The lineage is exact in both directions, the same rule
            // the production script enforces.
            if (($child['parent_demand_id'] ?? null) !== ($parent['id'] ?? null)) {
                return null;
            }
            $ttlMs = $this->expirations[$parentKey] ?? null;
            if ($ttlMs === null || $ttlMs <= 0) {
                return null;
            }
            $child['created_at'] = $nowS;
            $this->strings[$childKey] = (string) json_encode($child, JSON_UNESCAPED_SLASHES);
            $this->fakePexpire([$childKey, $ttlMs]);
            // The terminal lands in this one transaction, the same
            // shape the production script writes: state, stamp and
            // child link together.
            $parent['state'] = 'superseded';
            $parent['state_at'] = $nowS;
            $parent['superseded_by'] = (string) $rest[1];
            $this->strings[$parentKey] = (string) json_encode($parent, JSON_UNESCAPED_SLASHES);
            $this->fakePexpire([$parentKey, $ttlMs]);
            $this->strings[$indexKey] = (string) $rest[1];
            $this->fakePexpire([$indexKey, $ttlMs]);

            return json_encode(['superseded' => $parent], JSON_UNESCAPED_SLASHES);
        }

        if (str_contains($script, 'Step-up demand send lease')) {
            // RedisStepUpChallengeStore::claimDemandSendLease: keys[1]
            // the demand record; argv[1] the send cap, argv[2] the
            // resend spacing seconds, argv[3] the lease millis. Every
            // clock decision reads the fake server time: a live foreign
            // lease refuses, an expired one is recovered without a
            // second credit, the resend spacing answers the refused
            // wait.
            $key = (string) $keys[0];
            $raw = $this->strings[$key] ?? null;
            if (!\is_string($raw)) {
                return null;
            }
            $rec = json_decode($raw, true);
            if (!\is_array($rec) || !\is_int($rec['sends'] ?? null) || !\is_int($rec['expires_at'] ?? null)) {
                unset($this->strings[$key], $this->expirations[$key]);

                return null;
            }
            if (!empty($rec['superseded_by']) || ($rec['state'] ?? 'open') !== 'open') {
                return null;
            }
            $nowMs = $this->timeMs();
            $nowS = (int) floor($nowMs / 1000);
            if ($nowS >= $rec['expires_at']) {
                return null;
            }
            $ttlMs = $this->expirations[$key] ?? null;
            if ($ttlMs === null || $ttlMs <= 0) {
                return null;
            }
            $leaseUntil = \is_int($rec['lease_until'] ?? null) ? $rec['lease_until'] : 0;
            if ($leaseUntil > $nowMs) {
                return null;
            }
            $priorSends = $rec['sends'];
            $priorLast = \is_int($rec['last_sent_at'] ?? null) ? $rec['last_sent_at'] : null;
            $recovered = 0;
            if ($leaseUntil > 0) {
                $recovered = 1;
            } else {
                if ($priorSends >= (int) $rest[0]) {
                    return null;
                }
                if ($priorSends >= 1 && $priorLast !== null) {
                    $wait = ($priorLast + (int) $rest[1]) - $nowS;
                    if ($wait > 0) {
                        return json_encode(['refused' => 'resend_wait', 'wait' => $wait], JSON_UNESCAPED_SLASHES);
                    }
                }
                $rec['sends'] = $priorSends + 1;
                $rec['last_sent_at'] = $nowS;
            }
            $rec['lease_until'] = (int) floor($nowMs) + (int) $rest[2];
            $this->strings[$key] = (string) json_encode($rec, JSON_UNESCAPED_SLASHES);
            $this->fakePexpire([$key, $ttlMs]);
            $answer = ['claim_at' => $nowS, 'recovered' => $recovered, 'prior_sends' => $priorSends, 'prior_last_sent_at' => $priorLast, 'record' => $rec];

            return json_encode($answer, JSON_UNESCAPED_SLASHES);
        }

        if (str_contains($script, 'Step-up demand send settlement')) {
            // RedisStepUpChallengeStore::settleDemandSendLease: keys[1]
            // the demand record; argv[1] the lease stamp (the
            // compare-and-set key), argv[2] delivered, argv[3] prior
            // sends, argv[4] prior last delivery (-1 = null). A stale
            // stamp settles nothing; a refusal restores the pre-claim
            // state; the record keeps its remaining lifetime.
            $key = (string) $keys[0];
            $raw = $this->strings[$key] ?? null;
            if (!\is_string($raw)) {
                return false;
            }
            $rec = json_decode($raw, true);
            if (!\is_array($rec)) {
                return false;
            }
            $stamp = \is_int($rec['lease_until'] ?? null) ? $rec['lease_until'] : 0;
            if ($stamp !== (int) $rest[0]) {
                return false;
            }
            $rec['lease_until'] = null;
            if ((string) $rest[1] === '0') {
                $rec['sends'] = (int) $rest[2];
                $rec['last_sent_at'] = (string) $rest[3] === '-1' ? null : (int) $rest[3];
            }
            $ttlMs = $this->expirations[$key] ?? null;
            if ($ttlMs === null || $ttlMs <= 0) {
                unset($this->strings[$key], $this->expirations[$key]);

                return false;
            }
            $this->strings[$key] = (string) json_encode($rec, JSON_UNESCAPED_SLASHES);
            $this->fakePexpire([$key, $ttlMs]);

            return true;
        }

        if (str_contains($script, 'Step-up mail quota: reserve')) {
            // RedisStepUpChallengeStore::reserveMailQuota: keys[1] the
            // reservation marker, keys[2..] the budget counters;
            // argv[1] the window seconds, argv[2] the lease seconds,
            // argv[3] the marker, argv[4..] the per-key limits. Every
            // budget increments inside its window or the whole call
            // rolls back.
            $over = false;
            $count = count($keys);
            for ($i = 1; $i < $count; $i++) {
                $budgetKey = (string) $keys[$i];
                $n = $this->fakeIncr([$budgetKey]);
                if ($n === 1) {
                    $this->fakePexpire([$budgetKey, (int) $rest[0] * 1000]);
                }
                if ($n > (int) $rest[3 + ($i - 1)]) {
                    $over = true;
                }
            }
            if ($over) {
                for ($i = 1; $i < $count; $i++) {
                    $budgetKey = (string) $keys[$i];
                    $n = isset($this->counters[$budgetKey]) ? $this->counters[$budgetKey] : 0;
                    if ($n > 0) {
                        $this->fakeDecr([$budgetKey]);
                    }
                }

                return false;
            }
            $this->strings[(string) $keys[0]] = (string) $rest[2];
            $this->fakePexpire([(string) $keys[0], (int) $rest[1] * 1000]);

            return true;
        }

        if (str_contains($script, 'Step-up mail quota settlement')) {
            // RedisStepUpChallengeStore::commitMailQuota and
            // releaseMailQuota: keys[1] the reservation marker,
            // argv[1] commit (1) or release (0). The marker carries the
            // reservation's own budget counters, so a release decrements
            // exactly those, while the marker still lives (the lease is
            // its own TTL); a commit drops the marker only.
            if ((string) $rest[0] === '1') {
                unset($this->strings[(string) $keys[0]], $this->expirations[(string) $keys[0]]);

                return true;
            }
            $markerKey = (string) $keys[0];
            if (!isset($this->strings[$markerKey])) {
                return false;
            }
            $saved = json_decode((string) $this->strings[$markerKey], true);
            if (\is_array($saved) && isset($saved['keys']) && \is_array($saved['keys'])) {
                foreach ($saved['keys'] as $budgetKey) {
                    $budgetKey = (string) $budgetKey;
                    $n = isset($this->counters[$budgetKey]) ? $this->counters[$budgetKey] : 0;
                    if ($n > 0) {
                        $this->fakeDecr([$budgetKey]);
                    }
                }
            }
            unset($this->strings[$markerKey], $this->expirations[$markerKey]);

            return true;
        }

        if (str_contains($script, 'Step-up factor completion')) {
            // RedisStepUpChallengeStore completeFactor: keys[1] the
            // challenge record, keys[2] the demand record, keys[3] the
            // escalation index; argv[1] the demand id, argv[2] now,
            // argv[3] the presented binding hash, argv[4] the session
            // hash hint ('' skips the index write). One atomic
            // challenge+demand transition: the checks run in the
            // script's order, and the winner consumes the challenge and
            // completes the demand in one step. The judged factor
            // identity is the stored challenge's own server-held
            // snapshot, never a caller argument.
            $challengeKey = (string) $keys[0];
            $demandKey = (string) $keys[1];
            $indexKey = (string) $keys[2];
            $demandId = (string) $rest[0];
            $now = (int) $rest[1];
            $binding = (string) $rest[2];
            $hint = (string) $rest[3];
            $craw = $this->strings[$challengeKey] ?? null;
            if ($craw === null) {
                return ['missing_challenge'];
            }
            $ch = json_decode((string) $craw, true);
            if (!\is_array($ch)) {
                unset($this->strings[$challengeKey], $this->expirations[$challengeKey]);

                return ['corrupt_challenge'];
            }
            $draw = $this->strings[$demandKey] ?? null;
            if ($draw === null) {
                return ['missing_demand'];
            }
            $de = json_decode((string) $draw, true);
            if (!\is_array($de)) {
                unset($this->strings[$demandKey], $this->expirations[$demandKey]);

                return ['corrupt_demand'];
            }
            if (($ch['demand_id'] ?? null) !== $demandId || ($de['id'] ?? null) !== $demandId) {
                return ['crossed'];
            }
            if (!empty($de['superseded_by'])) {
                return ['spent'];
            }
            if (($de['state'] ?? null) !== 'open') {
                return ['spent'];
            }
            if ((is_numeric($ch['expires_at'] ?? null) ? (int) $ch['expires_at'] : 0) <= $now
                || (is_numeric($de['expires_at'] ?? null) ? (int) $de['expires_at'] : 0) <= $now) {
                return ['expired'];
            }
            $bound = (($ch['session_hash'] ?? null) === $binding) || (($ch['client_secret_hash'] ?? null) === $binding);
            if (!$bound) {
                return ['binding'];
            }
            // The factor identity gate, the script's own rule: the
            // demand's stored requirement is judged against the factor
            // identity the stored challenge record carries (its
            // server-held snapshot, resolved at begin), never a caller
            // argument. The snapshot must agree with its kind's family
            // and rank, and an incoherent one is a corrupt record,
            // removed fail-closed; a record without the snapshot (the
            // pre-snapshot wire shape) falls back to the kind tables. A
            // rank below the required one refuses, and so does a factor
            // neither the family nor the exact id the requirement names
            // at or below that rank; a strictly stronger completion
            // satisfies a weaker floor. Nothing moves on a refusal.
            $family = null;
            $rank = null;
            $fid = null;
            if (\is_string($ch['factor_family'] ?? null) && $ch['factor_family'] !== ''
                && \is_string($ch['factor_id'] ?? null) && $ch['factor_id'] !== ''
                && \is_int($ch['factor_rank'] ?? null)) {
                if (self::challengeKindFamily((string) ($ch['kind'] ?? '')) !== $ch['factor_family']
                    || self::challengeKindRank((string) ($ch['kind'] ?? '')) !== $ch['factor_rank']) {
                    unset($this->strings[$challengeKey], $this->expirations[$challengeKey]);

                    return ['corrupt_challenge'];
                }
                $family = (string) $ch['factor_family'];
                $rank = (int) $ch['factor_rank'];
                $fid = (string) $ch['factor_id'];
            } else {
                $family = self::challengeKindFamily((string) ($ch['kind'] ?? ''));
                $rank = self::challengeKindRank((string) ($ch['kind'] ?? ''));
                $fid = $family;
            }
            $requiredRank = \is_int($de['required_rank'] ?? null) ? $de['required_rank'] : null;
            if ($requiredRank !== null && $requiredRank >= 1 && ($rank === null || $rank < $requiredRank)) {
                return ['weaker_factor'];
            }
            $requiredId = $de['required_factor_id'] ?? null;
            if (\is_string($requiredId) && $requiredId !== ''
                && $family !== $requiredId && $fid !== $requiredId
                && ($requiredRank === null || $rank === null || $rank <= $requiredRank)) {
                return ['foreign_factor'];
            }
            unset($this->strings[$challengeKey], $this->expirations[$challengeKey]);
            $de['state'] = 'completed';
            $de['state_at'] = $now;
            $ttl = max(1, (int) $de['expires_at'] - $now);
            $encoded = (string) json_encode($de, JSON_UNESCAPED_SLASHES);
            $this->strings[$demandKey] = $encoded;
            $this->fakePexpire([$demandKey, $ttl * 1000]);
            // The escalation index stores the factor identity the record
            // itself carries, never a caller argument: a completion
            // cannot poison the future assurance escalation by claiming
            // a stronger factor than its challenge proves.
            if ($hint !== '' && ($ch['session_hash'] ?? null) === $hint
                && \is_string($family) && $family !== '') {
                $this->strings[$indexKey] = ((string) $ch['scope']).'|'.$family.'|'.$de['expires_at'];
                $this->fakePexpire([$indexKey, $ttl * 1000]);
            }

            return ['ok', (string) $craw, $encoded];
        }

        if (str_contains($script, 'Outstanding challenge issuance')) {
            // OutstandingChallenges::issue: keys[1] the per-source
            // membership ZSET (member = <source>:<nonce>, score = absolute
            // expiry), keys[2] the global LIVE-outstanding ZSET, keys[3]
            // the issuance sidecar (nonce -> source pseudonym); argv[1]
            // source cap, argv[2] global cap, argv[3] sidecar TTL seconds,
            // argv[4] the relative challenge lifetime (the membership
            // deadlines are the fake Redis clock + lifetime), argv[5] the
            // minted nonce, argv[6] the source pseudonym, argv[7] the
            // cleanup margin. Prune the source's ZSET by score -> ZCARD
            // cap -> global ZCARD cap -> `ZADD` both memberships (scored
            // at the fake-clock deadline) + SET the sidecar (EX) +
            // `EXPIREAT` both keys at the latest deadline + margin. No
            // scalar counter exists: the source bound is its live
            // membership (a well-defined score-range count), so a
            // heterogeneous challenge TTL can never reset it, and the key
            // TTLs bound stale-key retention.
            $sourceZset = (string) $keys[0];
            $global = (string) $keys[1];
            $sidecar = (string) $keys[2];
            $sourceCap = (int) $rest[0];
            $globalCap = (int) $rest[1];
            $ttl = (int) $rest[2];
            $now = (int) floor($this->timeMs() / 1000);
            $liveUntil = $now + (int) $rest[3];
            $cleanupMargin = (int) $rest[6];
            $pseudonym = (string) $rest[5];
            $this->fakeZremrangebyscore([$sourceZset, '-inf', (string) $now]);
            if ($this->zcard($sourceZset) >= $sourceCap) {
                return 0;
            }
            $this->fakeZremrangebyscore([$global, '-inf', (string) $now]);
            if ($this->zcard($global) >= $globalCap) {
                return -1;
            }
            $this->fakeZadd([$sourceZset, (string) $liveUntil, (string) $rest[4]]);
            $this->fakeZadd([$global, (string) $liveUntil, (string) $rest[4]]);
            $this->fakeSet([$sidecar, $pseudonym, 'EX', $ttl]);
            $this->fakeExpireatMs($sourceZset, ($liveUntil + $cleanupMargin) * 1000);
            $this->fakeExpireatMs($global, ($liveUntil + $cleanupMargin) * 1000);
            $this->mirrorSourceCount($sourceZset);

            return 1;
        }

        if (str_contains($script, 'Outstanding challenge release')) {
            // OutstandingChallenges::solved / ::cancelled /
            // ::abortedBeforeHandoff: keys[1] the global live ZSET,
            // keys[2] the nonce sidecar, keys[3] the original source's
            // membership ZSET (the caller's plain-read resolution);
            // argv[1] the released nonce, argv[2] the caller-resolved
            // source pseudonym (re-verified against the sidecar). One-shot,
            // nonce-authoritative: only the ZREM of the nonce from the
            // live membership releases the original source's member and
            // deletes the sidecar; the caller's IP is never used. A
            // duplicate release (ZREM == 0) is a no-op.
            $live = (string) $keys[0];
            $sidecar = (string) $keys[1];
            $sourceZset = (string) $keys[2];
            $nonce = (string) $rest[0];
            $expectedSource = (string) $rest[1];
            $removed = $this->fakeZrem([$live, $nonce]);
            if ($removed === 1 && isset($this->strings[$sidecar]) && (string) $this->strings[$sidecar] === $expectedSource) {
                $this->fakeZrem([$sourceZset, $nonce]);
                $this->fakeDel([$sidecar]);
                $this->mirrorSourceCount($sourceZset);
            }

            return $removed;
        }

        if (str_contains($script, 'Outstanding challenge cancellation admission')) {
            // OutstandingChallenges::cancellationAdmission: keys[1] the
            // per-source cancellation window, keys[2] the deployment-global
            // window; argv[1] cap, argv[2] window ms, argv[3] request id,
            // argv[4] global cap. Prune global -> global cap (-1) -> prune
            // source -> source cap (0) -> `ZADD` both + `PEXPIRE` both.
            $window = (string) $keys[0];
            $globalWindow = (string) $keys[1];
            $cap = (int) $rest[0];
            $windowMs = (int) $rest[1];
            $requestId = (string) $rest[2];
            $globalCap = (int) $rest[3];
            $now = $this->timeMs();
            $cutoff = $now - $windowMs;
            $this->fakeZremrangebyscore([$globalWindow, '-inf', (string) $cutoff]);
            if ($this->zcard($globalWindow) >= $globalCap) {
                return -1;
            }
            $this->fakeZremrangebyscore([$window, '-inf', (string) $cutoff]);
            if ($this->zcard($window) >= $cap) {
                return 0;
            }
            $this->fakeZadd([$window, (string) $now, $requestId]);
            $this->fakeZadd([$globalWindow, (string) $now, $requestId]);
            $this->fakePexpire([$window, (string) ($windowMs + 1000)]);
            $this->fakePexpire([$globalWindow, (string) ($windowMs + 1000)]);

            return 1;
        }

        if (str_contains($script, '-- kiwicaptcha consume transition')) {
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

        if (str_contains($script, '-- kiwicaptcha cancel transition')) {
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

        if (str_contains($script, '-- kiwicaptcha delete-if-pending (atomic cleanup)')) {
            // The core RedisStorage delete-if-pending script: missing
            // reports missing; a consumed record is returned verbatim and
            // kept; a cancelled record is returned verbatim and kept too
            // (dead but retained until its TTL); only a record carrying
            // the exact pending marker is deleted, and any other runtime
            // state is corrupt (reported without mutating the record).
            $key = (string) $keys[0];
            if (!isset($this->strings[$key])) {
                return ['missing'];
            }
            $raw = $this->strings[$key];
            $obj = json_decode($raw, true);
            if (!\is_array($obj)) {
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
            unset($this->strings[$key]);

            return ['deleted-pending'];
        }

        if (str_contains($script, '-- kiwicaptcha commit result')) {
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
            // ARGV[5]: the server-state MAC, stored when non-empty.
            if (($rest[4] ?? '') !== '') {
                $obj['consumed_result']['mac'] = (string) $rest[4];
            }
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

                // The distinguishable saturation-pressure sentinel: the
                // over-cap contender's own entry is removed in the same
                // script and acquire() maps -1 to its fast-fail
                // CapacityExceeded path.
                return -1;
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
            // {kiwi:<ns>}:issuance:<canonical scope id>:sw (the
            // per-scope sliding-window ZSET; the reserved unknown-scope
            // quota id for an unmapped scope; the raw scope is never a
            // key component), keys[2] = the unique-member counter;
            // argv[1] = now_ms, argv[2] = window_ms, argv[3] = cap.
            // Prune entries at or older than now-window -> ZCARD cap
            // check (refuse with the live count) -> INCR the seq ->
            // `ZADD` now..':'..seq -> `PEXPIRE` both keys (window + 1 s)
            // -> {1, n+1} on admission.
            $window = (string) $keys[0];
            $seqKey = (string) $keys[1];
            $now = (int) $rest[0];
            $windowMs = (int) $rest[1];
            $cap = (int) $rest[2];
            $this->fakeZremrangebyscore([$window, '-inf', (string) ($now - $windowMs)]);
            $n = $this->zcard($window);
            if ($n >= $cap) {
                $this->mirrorSourceCount($window);

                return [0, $n];
            }
            $seq = $this->fakeIncr([$seqKey]);
            $this->fakeZadd([$window, (string) $now, $now.':'.$seq]);
            $this->fakePexpire([$window, (string) ($windowMs + 1000)]);
            $this->fakePexpire([$seqKey, (string) ($windowMs + 1000)]);
            $this->mirrorSourceCount($window);

            return [1, $n + 1];
        }

        if (str_contains($script, 'Verified-agent quota')) {
            // AgentQuota::admit: keys[1..4] = the agent's minute/day
            // sliding-window ZSETs and their seq counters; argv[1] =
            // now_ms, argv[2] = minute window ms, argv[3] = day window
            // ms, argv[4] = per-minute cap, argv[5] = per-day cap.
            // Prune both windows by score -> minute zcard cap check ->
            // day zcard cap check -> INCR the minute seq -> zadd the
            // member into both windows -> pexpire all four keys.
            // Returns {1, liveMin, liveDay, 0} on admission,
            // {0, 1|2, liveCount, retryAfterSecs} on refusal.
            $minuteZset = (string) $keys[0];
            $minuteSeq = (string) $keys[1];
            $dayZset = (string) $keys[2];
            $now = (int) $rest[0];
            $minuteMs = (int) $rest[1];
            $dayMs = (int) $rest[2];
            $capMinute = (int) $rest[3];
            $capDay = (int) $rest[4];
            $retryFor = function (string $zset, int $windowMs) use ($now): int {
                $members = $this->zsets[$zset] ?? [];
                if ($members === []) {
                    return (int) ceil($windowMs / 1000);
                }
                $oldest = min($members);

                return max(1, (int) ceil(($windowMs - ($now - $oldest)) / 1000));
            };
            $this->fakeZremrangebyscore([$minuteZset, '-inf', (string) ($now - $minuteMs)]);
            $this->fakeZremrangebyscore([$dayZset, '-inf', (string) ($now - $dayMs)]);
            $nMin = $this->zcard($minuteZset);
            if ($nMin >= $capMinute) {
                return [0, 1, $nMin, $retryFor($minuteZset, $minuteMs)];
            }
            $nDay = $this->zcard($dayZset);
            if ($nDay >= $capDay) {
                return [0, 2, $nDay, $retryFor($dayZset, $dayMs)];
            }
            $seq = $this->fakeIncr([$minuteSeq]);
            $member = $now.':'.$seq;
            $this->fakeZadd([$minuteZset, (string) $now, $member]);
            $this->fakeZadd([$dayZset, (string) $now, $member]);
            $this->fakePexpire([$minuteZset, (string) ($minuteMs + 1000)]);
            $this->fakePexpire([$minuteSeq, (string) ($minuteMs + 1000)]);
            $this->fakePexpire([$dayZset, (string) ($dayMs + 1000)]);
            $this->fakePexpire([(string) $keys[3], (string) ($dayMs + 1000)]);

            return [1, $nMin + 1, $nDay + 1, 0];
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
            $sampled = (string) $rest[2];
            if ($sampled !== '0' && $sampled !== '1') {
                throw new \Predis\Response\ServerException('register_decision: sampled must be 0 or 1');
            }
            foreach ([[1, 'receipt_ttl_s'], [3, 'bucket_ttl_s'], [4, 'outcome_ttl_s']] as [$ttlIndex, $ttlLabel]) {
                $ttl = (float) $rest[$ttlIndex];
                if ($ttl < 1 || $ttl > 2147483647 || $ttl !== floor($ttl)) {
                    throw new \Predis\Response\ServerException('register_decision: '.$ttlLabel.' must be a positive integer no greater than 2147483647');
                }
            }
            if (isset($this->strings[$receiptKey])) {
                return 0;
            }
            $this->strings[$receiptKey] = (string) $rest[0];
            if (isset($this->strings[$ledgerKey])) {
                // Late re-registration: never reset an authoritative
                // ledger to pending; remove the receipt just created and
                // book no second denominator.
                unset($this->strings[$receiptKey]);

                return 0;
            }
            $this->strings[$ledgerKey] = (string) json_encode([
                'o' => 'P',
                'scope' => (int) $rest[5],
                'hour' => (int) $rest[6],
                'score' => (int) $rest[7],
                'w' => (float) $rest[8],
            ]);
            $this->fakePexpire([$receiptKey, (int) $rest[1] * 1000]);
            $this->fakePexpire([$ledgerKey, (int) $rest[4] * 1000]);
            if ($sampled === '1') {
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
            $legitimateRaw = (string) $rest[2];
            $bucketTtlSecs = (int) $rest[3];
            $outcomeTtlSecs = (int) $rest[4];
            $expectedScope = (int) $rest[5];
            $expectedHour = (int) $rest[6];

            if ($mode !== 0 && $mode !== 1 && $mode !== 2) {
                throw new \Predis\Response\ServerException('invalid calibration mode');
            }
            if ($mode === 2 && ($weight <= 0 || !\is_finite($weight))) {
                throw new \Predis\Response\ServerException('invalid calibration weight');
            }
            if ($legitimateRaw !== '0' && $legitimateRaw !== '1') {
                throw new \Predis\Response\ServerException('invalid legitimate flag');
            }
            if ($bucketTtlSecs < 1 || $bucketTtlSecs > 2147483647) {
                throw new \Predis\Response\ServerException('confirm: bucket_ttl_s must be a positive integer no greater than 2147483647');
            }
            if ($outcomeTtlSecs < 1 || $outcomeTtlSecs > 2147483647) {
                throw new \Predis\Response\ServerException('confirm: outcome_ttl_s must be a positive integer no greater than 2147483647');
            }
            $legitimate = $legitimateRaw === '1';

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
            $ledger['c'] = $status === 1 ? 1 : 0;
            $this->strings[$ledgerKey] = (string) json_encode($ledger);
            $this->fakePexpire([$ledgerKey, $outcomeTtlSecs * 1000]);
            unset($this->strings[$receiptKey]);

            $boundary = 600;
            if ($status === 1) {
                if ($legitimate) {
                    $this->fakeHincrbyfloat([$bucketKey, 'legit_count', $weight]);
                    $this->fakeHincrbyfloat([$bucketKey, 'legit_score_sum', $score * $weight]);
                    $this->fakeHincrbyfloat([$bucketKey, 'legit_above_sum', max(0.0, $score - $boundary) * $weight]);
                } else {
                    $this->fakeHincrbyfloat([$bucketKey, 'abuse_count', $weight]);
                    $this->fakeHincrbyfloat([$bucketKey, 'abuse_score_sum', $score * $weight]);
                    $this->fakeHincrbyfloat([$bucketKey, 'abuse_below_sum', max(0.0, $boundary - $score) * $weight]);
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

            if ($newOutcome !== 'L' && $newOutcome !== 'A') {
                throw new \Predis\Response\ServerException('invalid correction outcome');
            }
            if ($weight <= 0 || !\is_finite($weight)) {
                throw new \Predis\Response\ServerException('invalid correction weight');
            }
            if ($bucketTtlSecs < 1 || $bucketTtlSecs > 2147483647) {
                throw new \Predis\Response\ServerException('correction: bucket_ttl_s must be a positive integer no greater than 2147483647');
            }
            if ($outcomeTtlSecs < 1 || $outcomeTtlSecs > 2147483647) {
                throw new \Predis\Response\ServerException('correction: outcome_ttl_s must be a positive integer no greater than 2147483647');
            }

            $ledgerRaw = $this->strings[$ledgerKey] ?? null;
            if ($ledgerRaw === null) {
                return 0;
            }
            $ledger = json_decode($ledgerRaw, true);
            if (!\is_array($ledger) || !isset($ledger['o'])) {
                return 0;
            }
            if (($ledger['o'] ?? null) !== 'L' && ($ledger['o'] ?? null) !== 'A') {
                // pending is never corrected directly.
                return 0;
            }
            if ((int) ($ledger['scope'] ?? 0) !== $expectedScope
                || (int) ($ledger['hour'] ?? 0) !== $expectedHour
            ) {
                return 0;
            }
            if (($ledger['o'] ?? null) === $newOutcome) {
                return 0;
            }
            $score = (float) ($ledger['score'] ?? 0);
            if ($score < 0) {
                $score = 0;
            }
            if ($score > 1000) {
                $score = 1000;
            }
            $oldW = (float) ($ledger['w'] ?? 1);
            $counted = (int) ($ledger['c'] ?? 0) === 1;
            $boundary = 600;

            if ($counted) {
                if (($ledger['o'] ?? null) === 'L') {
                    $this->fakeHincrbyfloat([$bucketKey, 'legit_count', -$oldW]);
                    $this->fakeHincrbyfloat([$bucketKey, 'legit_score_sum', -($score * $oldW)]);
                    $this->fakeHincrbyfloat([$bucketKey, 'legit_above_sum', -(max(0.0, $score - $boundary) * $oldW)]);
                } else {
                    $this->fakeHincrbyfloat([$bucketKey, 'abuse_count', -$oldW]);
                    $this->fakeHincrbyfloat([$bucketKey, 'abuse_score_sum', -($score * $oldW)]);
                    $this->fakeHincrbyfloat([$bucketKey, 'abuse_below_sum', -(max(0.0, $boundary - $score) * $oldW)]);
                }
                foreach (['legit_count', 'legit_score_sum', 'legit_above_sum', 'abuse_count', 'abuse_score_sum', 'abuse_below_sum'] as $field) {
                    if (($this->hashes[$bucketKey][$field] ?? 0) < 0) {
                        $this->hashes[$bucketKey][$field] = 0;
                    }
                }

                if ($newOutcome === 'L') {
                    $this->fakeHincrbyfloat([$bucketKey, 'legit_count', $weight]);
                    $this->fakeHincrbyfloat([$bucketKey, 'legit_score_sum', $score * $weight]);
                    $this->fakeHincrbyfloat([$bucketKey, 'legit_above_sum', max(0.0, $score - $boundary) * $weight]);
                } else {
                    $this->fakeHincrbyfloat([$bucketKey, 'abuse_count', $weight]);
                    $this->fakeHincrbyfloat([$bucketKey, 'abuse_score_sum', $score * $weight]);
                    $this->fakeHincrbyfloat([$bucketKey, 'abuse_below_sum', max(0.0, $boundary - $score) * $weight]);
                }
                $this->fakePexpire([$bucketKey, $bucketTtlSecs * 1000]);
            }

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
            $newOutcome = (string) $rest[0];
            if ($newOutcome !== 'L' && $newOutcome !== 'A') {
                throw new \Predis\Response\ServerException('outcome_correct: new outcome must be L or A');
            }
            $ttl = (float) $rest[1];
            if ($ttl < 1 || $ttl > 2147483647 || $ttl !== floor($ttl)) {
                throw new \Predis\Response\ServerException('outcome_correct: outcome_ttl_s must be a positive integer no greater than 2147483647');
            }
            $ledgerRaw = $this->strings[$ledgerKey] ?? null;
            if ($ledgerRaw === null) {
                return 0;
            }
            $ledger = json_decode($ledgerRaw, true);
            if (!\is_array($ledger)) {
                return 0;
            }
            if (($ledger['o'] ?? null) !== 'L' && ($ledger['o'] ?? null) !== 'A') {
                return 0;
            }
            if (($ledger['o'] ?? null) === $newOutcome) {
                return 0;
            }
            $ledger['o'] = $newOutcome;
            // SET ... KEEPTTL: the original ledger TTL is preserved.
            $this->strings[$ledgerKey] = (string) json_encode($ledger);

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

        // TIME-based scripts: `now` mirrors the Lua time read.
        $now = $this->timeMs();

        if (str_contains($script, 'exact-ms sliding window')) {
            // The exact-ms rate limiter scripts: the global-only variant
            // (1 key: the global ZSET), the full limiter (2 keys: the
            // per-client ZSET + the global ZSET) and the epoch-rotated
            // variant (3 keys: previous + current client ZSETs + the
            // global ZSET). Every ZSET carries one member per admitted
            // request scored at the exact admission ms (Redis TIME):
            // prune each ZSET at <= now - window, refuse on ZCARD, then
            // `ZADD` the exact-time member.
            $keyCount = \count($keys);
            $globalMax = (int) $rest[$keyCount === 1 ? 0 : 1];
            $windowMs = (int) $rest[$keyCount === 1 ? 1 : 2];
            foreach ($keys as $k) {
                $this->fakeZremrangebyscore([$k, '-inf', (string) ($now - $windowMs)]);
            }
            if ($keyCount !== 1) {
                // Per-client cap: the full limiter checks the current
                // client key, the rotated variant the previous + current.
                $clientKeys = $keyCount === 2 ? [(string) $keys[0]] : [(string) $keys[0], (string) $keys[1]];
                $clientCount = 0;
                foreach ($clientKeys as $clientKey) {
                    $clientCount += $this->zcard($clientKey);
                }
                if ($clientCount >= (int) $rest[0]) {
                    return 0;
                }
            }
            // globalMax = 0 disables the global window entirely: the
            // real script neither counts nor writes the global ZSET.
            $globalEnabled = $keyCount === 1 ? $globalMax > 0 : $globalMax > 0;
            if ($keyCount === 1 || $globalEnabled) {
                if ($this->zcard((string) $keys[$keyCount - 1]) >= $globalMax) {
                    return -1;
                }
            }
            if ($keyCount === 1) {
                $this->fakeZadd([(string) $keys[0], (string) $now, (string) $rest[2]]);
            } else {
                $this->fakeZadd([(string) $keys[$keyCount === 2 ? 0 : 1], (string) $now, (string) $rest[3]]);
                if ($globalEnabled) {
                    $this->fakeZadd([(string) $keys[$keyCount - 1], (string) $now, (string) $rest[4]]);
                }
            }
            foreach ($keys as $k) {
                if (!$globalEnabled && $keyCount !== 1 && (string) $k === (string) $keys[$keyCount - 1]) {
                    continue;
                }
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

        // The exact-ms limiter branch above is the canonical emulation
        // for the current scripts.
        return 1;
    }
}
