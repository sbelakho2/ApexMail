<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\ArrayPostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDisposition;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisPostSolveDispositionStore;
use KiwiCaptcha\Storage\ReplicaWaitException;
use PHPUnit\Framework\TestCase;

/**
 * The post-solve disposition store's verified replica-WAIT durability
 * barrier (waitReplicas > 0) is exercised against an in-memory Redis
 * fake with a controllable WAIT acknowledgement count. Every fresh
 * mutating transition — the claim's record creation, the expired-lease
 * takeover's owner transfer, the finalize's completion — issues exactly
 * one WAIT on the same connection and fails closed when fewer than
 * waitReplicas replicas acknowledged it. The caller never learns a
 * success that was not replicated, so a returned
 * Deny/StepUp/ChainRequired can never be reported as persisted and then
 * vanish on promotion. The non-mutating paths (busy/complete claims,
 * refused finalizes, reads) never WAIT, and the in-memory Array store
 * observes the same machine without any barrier (no replicas).
 */
final class RedisPostSolveDispositionDurabilityTest extends TestCase
{
    private const NAMESPACE = 'kiwi-wait-test';

    private function key(string $nonce): string
    {
        return '{kiwi:'.self::NAMESPACE.'}:postsolve:'.$nonce;
    }

    /** @return list<array{0: string, 1: list<mixed>}> the WAIT commands issued */
    private function waits(DispositionWaitRedisFake $fake): array
    {
        return array_values(array_filter($fake->calls, static fn (array $c): bool => $c[0] === 'WAIT'));
    }

    public function testFreshClaimRecordCreationIssuesExactlyOneWait(): void
    {
        $fake = new DispositionWaitRedisFake();
        $fake->waitAck = 1;
        $store = new RedisPostSolveDispositionStore($fake, self::NAMESPACE, 300, 1, 100);
        $nonce = bin2hex(random_bytes(16));

        [$status, $record] = $store->claim($nonce, 'owner-a', 300);
        self::assertSame('claimed', $status);

        $waits = $this->waits($fake);
        self::assertCount(1, $waits, 'a fresh claim (record creation) issues exactly ONE WAIT: '.json_encode($fake->calls));
        self::assertSame(['WAIT', [1, 100]], $waits[0], 'the WAIT carries (waitReplicas, waitTimeoutMs) on the same connection');
        self::assertSame('pending', $record?->state, 'the claim response still carries the pending record');
        self::assertArrayHasKey($this->key($nonce), $fake->strings, 'the record creation write landed before the barrier');
    }

    public function testFreshFinalizeIssuesExactlyOneWaitAndReturnsSuccessOnlyAfterReplication(): void
    {
        $fake = new DispositionWaitRedisFake();
        $seed = new RedisPostSolveDispositionStore($fake, self::NAMESPACE, 300);
        $nonce = bin2hex(random_bytes(16));
        self::assertSame('claimed', $seed->claim($nonce, 'owner-a', 300)[0]);
        $fake->calls = [];

        $store = new RedisPostSolveDispositionStore($fake, self::NAMESPACE, 300, 1, 100);
        self::assertTrue($store->finalize($nonce, 'owner-a', new PostSolveDisposition(PostSolveDispositionKind::Deny, 'decision-1')), 'a fully-acknowledged finalize returns success');

        $waits = $this->waits($fake);
        self::assertCount(1, $waits, 'a fresh finalize issues exactly ONE WAIT: '.json_encode($fake->calls));
        $record = $store->read($nonce);
        self::assertSame(PostSolveDispositionKind::Deny, $record?->disposition?->kind, 'the replicated finalize reports the persisted disposition');
        self::assertSame('decision-1', $record?->disposition?->decisionId);
    }

    public function testViolatedAckFailsClosedAfterTheFreshFinalize(): void
    {
        // The replica set never acknowledges: the finalize must NOT return
        // a success that was not replicated — the barrier raises
        // ReplicaWaitException and the caller treats the disposition as
        // not persisted (a retry re-finalizes the same pending record).
        $fake = new DispositionWaitRedisFake();
        $seed = new RedisPostSolveDispositionStore($fake, self::NAMESPACE, 300);
        $nonce = bin2hex(random_bytes(16));
        self::assertSame('claimed', $seed->claim($nonce, 'owner-a', 300)[0]);
        $fake->calls = [];
        $fake->waitAck = 0;

        $store = new RedisPostSolveDispositionStore($fake, self::NAMESPACE, 300, 1, 100);
        try {
            $store->finalize($nonce, 'owner-a', new PostSolveDisposition(PostSolveDispositionKind::Deny));
            self::fail('a finalize whose write was not replicated must fail closed');
        } catch (ReplicaWaitException $e) {
            self::assertStringContainsString('acknowledged 0 of 1 requested replicas after the post-solve disposition finalize', $e->getMessage());
        }
        self::assertCount(1, $this->waits($fake), 'the failed finalize issued exactly one WAIT — the barrier ran after the fresh mutation');
    }

    public function testViolatedAckFailsClosedAfterTheFreshClaim(): void
    {
        $fake = new DispositionWaitRedisFake();
        $fake->waitAck = 0;
        $store = new RedisPostSolveDispositionStore($fake, self::NAMESPACE, 300, 1, 100);
        $nonce = bin2hex(random_bytes(16));

        try {
            $store->claim($nonce, 'owner-a', 300);
            self::fail('a claim whose record creation was not replicated must fail closed');
        } catch (ReplicaWaitException $e) {
            self::assertStringContainsString('acknowledged 0 of 1 requested replicas after the post-solve disposition claim', $e->getMessage());
        }
        self::assertCount(1, $this->waits($fake), 'the failed claim issued exactly one WAIT');
    }

    public function testExpiredLeaseTakeoverIssuesExactlyOneWait(): void
    {
        $fake = new DispositionWaitRedisFake();
        $seed = new RedisPostSolveDispositionStore($fake, self::NAMESPACE, 300);
        $store = new RedisPostSolveDispositionStore($fake, self::NAMESPACE, 300, 1, 100);
        $nonce = bin2hex(random_bytes(16));
        $seed->claim($nonce, 'owner-a', 300);

        // The lease expires; a new owner's claim takes the record over —
        // a fresh owner-transfer write (SET ... KEEPTTL) like the record
        // creation, so the takeover must hit the barrier: under failover
        // a promoted replica may still hold the superseded owner's
        // expired state, and an un-replicated takeover would let a second
        // owner win the same nonce.
        $rec = json_decode((string) $fake->strings[$this->key($nonce)], true, 8, JSON_THROW_ON_ERROR);
        $rec['lease_until'] = 1;
        $fake->strings[$this->key($nonce)] = (string) json_encode($rec, JSON_THROW_ON_ERROR);
        $fake->calls = [];
        self::assertSame('taken_over', $store->claim($nonce, 'owner-d', 300)[0]);

        $waits = $this->waits($fake);
        self::assertCount(1, $waits, 'an expired-lease takeover (a fresh owner transfer) issues exactly ONE WAIT: '.json_encode($fake->calls));
        self::assertSame(['WAIT', [1, 100]], $waits[0], 'the WAIT carries (waitReplicas, waitTimeoutMs) on the same connection');
        self::assertSame('owner-d', $store->read($nonce)?->owner, 'the takeover moved the claim to the new owner before the barrier');
    }

    public function testViolatedAckFailsClosedAfterTheExpiredLeaseTakeover(): void
    {
        // The replica set never acknowledges: the takeover must NOT
        // return a new owner that was not replicated — the barrier raises
        // ReplicaWaitException, so a second node cannot proceed from a
        // promoted replica that still holds the superseded owner's
        // expired state.
        $fake = new DispositionWaitRedisFake();
        $seed = new RedisPostSolveDispositionStore($fake, self::NAMESPACE, 300);
        $nonce = bin2hex(random_bytes(16));
        $seed->claim($nonce, 'owner-a', 300);
        $rec = json_decode((string) $fake->strings[$this->key($nonce)], true, 8, JSON_THROW_ON_ERROR);
        $rec['lease_until'] = 1;
        $fake->strings[$this->key($nonce)] = (string) json_encode($rec, JSON_THROW_ON_ERROR);
        $fake->calls = [];
        $fake->waitAck = 0;

        $store = new RedisPostSolveDispositionStore($fake, self::NAMESPACE, 300, 1, 100);
        try {
            $store->claim($nonce, 'owner-d', 300);
            self::fail('a takeover whose owner transfer was not replicated must fail closed');
        } catch (ReplicaWaitException $e) {
            self::assertStringContainsString('acknowledged 0 of 1 requested replicas after the post-solve disposition claim', $e->getMessage());
        }
        self::assertCount(1, $this->waits($fake), 'the failed takeover issued exactly one WAIT — the barrier ran after the fresh mutation');
    }

    public function testBusyCompleteRefusalsAndReadsNeverWait(): void
    {
        $fake = new DispositionWaitRedisFake();
        $seed = new RedisPostSolveDispositionStore($fake, self::NAMESPACE, 300);
        $store = new RedisPostSolveDispositionStore($fake, self::NAMESPACE, 300, 1, 100);
        $nonce = bin2hex(random_bytes(16));
        $seed->claim($nonce, 'owner-a', 300);

        // pending+other+live -> busy: no write, no WAIT.
        $fake->calls = [];
        self::assertSame('pending', $store->claim($nonce, 'owner-b', 300)[0]);
        self::assertCount(0, $this->waits($fake), 'a busy claim performs no write and never WAITs');

        // complete -> 'complete': a replay claim is an ACCEPTANCE of the
        // terminal disposition — the causal fence must be established
        // before the record is returned (the finalize may have landed
        // with its WAIT failing); a shortfall fails closed.
        $seed->finalize($nonce, 'owner-a', new PostSolveDisposition(PostSolveDispositionKind::Pass));
        $fake->calls = [];
        $fake->waitAck = 0;
        try {
            $store->claim($nonce, 'owner-c', 300);
            self::fail('a complete claim must establish the causal fence and fail closed on a shortfall');
        } catch (\KiwiCaptcha\Storage\ReplicaWaitException) {
        }
        self::assertCount(1, $this->waits($fake), 'a complete claim issues exactly one verified fence WAIT');
        $fake->waitAck = 1;
        $fake->calls = [];
        self::assertSame('complete', $store->claim($nonce, 'owner-c', 300)[0], 'a satisfied fence returns the terminal record');
        self::assertCount(1, $this->waits($fake), 'the satisfied complete claim still performs the causal fence');
        $fake->waitAck = 0;

        // A refused finalize (non-owner) is an atomic no-op, no WAIT.
        $fake->calls = [];
        self::assertFalse($store->finalize($nonce, 'owner-x', new PostSolveDisposition(PostSolveDispositionKind::Pass)));
        self::assertCount(0, $this->waits($fake), 'a refused finalize is not a mutation and never WAITs');

        // A finalize against a complete record is refused, no WAIT.
        $fake->calls = [];
        self::assertFalse($store->finalize($nonce, 'owner-c', new PostSolveDisposition(PostSolveDispositionKind::Pass)));
        self::assertCount(0, $this->waits($fake), 'a finalize on a complete record is refused and never WAITs');

        // Reads never WAIT for absent records — but a read that ACCEPTS a
        // FINAL disposition re-establishes the barrier (the failed-barrier
        // replay guard: the finalize that wrote it may have landed with
        // its WAIT failing, and a read-only acceptance would return a
        // decision a promotion could silently reverse).
        $fake->calls = [];
        self::assertNull($store->read(bin2hex(random_bytes(16))));
        self::assertCount(0, $this->waits($fake), 'an absent-record read never WAITs');
        $fake->calls = [];
        $fake->waitAck = 0;
        try {
            $store->read($nonce);
            self::fail('the final-disposition read must re-establish the barrier and fail closed on an unacknowledged replica set');
        } catch (\KiwiCaptcha\Storage\ReplicaWaitException) {
            // the fail-closed acceptance barrier fired ✓
        }
        self::assertCount(1, $this->waits($fake), 'the final-disposition acceptance read issues exactly one verified WAIT');
    }

    public function testArrayStoreObservesTheSameMachineWithoutTheReplicaBarrier(): void
    {
        // The in-memory store has no replicas: the identical claim ->
        // finalize -> replay sequence produces the identical outcomes and
        // there is no WAIT concept to invoke (single-process semantics).
        $array = new ArrayPostSolveDispositionStore(now: static fn (): int => 1000);
        $nonce = bin2hex(random_bytes(16));

        self::assertSame('claimed', $array->claim($nonce, 'owner-a', 300)[0]);
        self::assertSame('pending', $array->claim($nonce, 'owner-b', 300)[0], 'a live lease is busy, exactly like the Redis machine');
        self::assertFalse($array->finalize($nonce, 'owner-b', new PostSolveDisposition(PostSolveDispositionKind::Deny)), 'a non-owner finalize is refused');
        self::assertTrue($array->finalize($nonce, 'owner-a', new PostSolveDisposition(PostSolveDispositionKind::Deny, 'decision-1')));
        self::assertSame('complete', $array->claim($nonce, 'owner-c', 300)[0], 'a replay claim reproduces the terminal record');
        $record = $array->read($nonce);
        self::assertSame(PostSolveDispositionKind::Deny, $record?->disposition?->kind);
        self::assertSame('decision-1', $record?->disposition?->decisionId);
        self::assertFalse($array->finalize($nonce, 'owner-c', new PostSolveDisposition(PostSolveDispositionKind::Pass)), 'a completed disposition is terminal');
    }

    public function testVerifiedWaitRefusesUnsupportedPredisTopologiesAtConstruction(): void
    {
        // The same fail-closed construction matrix as the core
        // RedisStorage: the verified barrier is connection-relative, so a
        // Predis replication aggregate is refused before any write can
        // run.
        $aggregate = new \Predis\Connection\Replication\MasterSlaveReplication();
        $client = new class($aggregate) extends \Predis\Client {
            public function __construct(private readonly \Predis\Connection\Replication\ReplicationInterface $connection)
            {
            }

            public function getConnection()
            {
                return $this->connection;
            }
        };

        try {
            new RedisPostSolveDispositionStore($client, self::NAMESPACE, 300, 1, 100);
            self::fail('a Predis replication aggregate with waitReplicas > 0 must be refused at construction');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('replication aggregate', $e->getMessage());
        }
        // waitReplicas = 0 stays supported on any client.
        self::assertInstanceOf(RedisPostSolveDispositionStore::class, new RedisPostSolveDispositionStore($client, self::NAMESPACE, 300));
    }
}

/**
 * In-memory stand-in for Predis\Client emulating exactly the command
 * surface the Redis post-solve disposition store uses. The command
 * surface is GET / EVAL, with the claim and finalize Lua scripts
 * interpreted by marker. The state machine is missing -> pending(me) ->
 * claimed (with the atomic decision-mapping getdel); pending+me /
 * pending+other+live -> pending; expired-lease takeover -> taken_over;
 * complete -> complete; pending (owner) -> complete finalize. The raw
 * WAIT escape hatch runs through {@see self::executeRaw()} with a
 * controllable acknowledgement count. Every command — WAIT included —
 * is recorded in {@see self::$calls} so tests can assert exactly which
 * transitions hit the barrier.
 */
final class DispositionWaitRedisFake extends \Predis\Client
{
    /** @var array<string, string> plain strings (the disposition records + decision mappings) */
    public array $strings = [];

    /** @var list<array{0: string, 1: list<mixed>}> every command issued, WAIT included */
    public array $calls = [];

    /** The WAIT acknowledgement count to answer (violated when < waitReplicas). */
    public int $waitAck = 1;

    private float $clockMs = 1_000_000.0;

    public function __construct()
    {
        // Deliberately skip the parent constructor: no connection setup.
    }

    /** @internal test hook: advance the fake Redis server clock (ms). */
    public function setTimeMs(float $ms): void
    {
        $this->clockMs = $ms;
    }

    public function __call($commandID, $arguments)
    {
        $this->calls[] = [strtoupper((string) $commandID), $arguments];

        return match (strtoupper((string) $commandID)) {
            'GET' => $this->strings[(string) $arguments[0]] ?? null,
            'SET' => $this->fakeSet($arguments),
            'SETEX' => $this->fakeSetex($arguments),
            'GETDEL' => $this->fakeGetdel($arguments),
            'TIME' => [(int) floor($this->clockMs / 1000), (int) round(($this->clockMs - (int) floor($this->clockMs / 1000) * 1000) * 1000)],
            'EVAL' => $this->fakeEval($arguments),
            default => throw new \LogicException('unexpected command '.$commandID),
        };
    }

    /** The raw-command escape hatch the store's verified WAIT uses. */
    public function executeRaw(array $arguments, &$error = null): mixed
    {
        $this->calls[] = [strtoupper((string) ($arguments[0] ?? '')), \array_slice($arguments, 1)];

        return $this->waitAck;
    }

    private function fakeSet(array $arguments): ?string
    {
        $this->strings[(string) $arguments[0]] = (string) $arguments[1];

        return 'OK';
    }

    private function fakeSetex(array $arguments): ?string
    {
        $this->strings[(string) $arguments[0]] = (string) $arguments[2];

        return 'OK';
    }

    private function fakeGetdel(array $arguments): ?string
    {
        $key = (string) $arguments[0];
        $value = $this->strings[$key] ?? null;
        unset($this->strings[$key]);

        return $value;
    }

    private function fakeEval(array $arguments): mixed
    {
        $script = (string) $arguments[0];
        $numKeys = (int) $arguments[1];
        $keysAndArgs = \array_slice($arguments, 2);
        $keys = \array_slice($keysAndArgs, 0, $numKeys);
        $args = \array_slice($keysAndArgs, $numKeys);

        if (str_contains($script, 'Post-solve disposition claim')) {
            return $this->luaClaim($keys, $args);
        }
        if (str_contains($script, 'Post-solve disposition finalize')) {
            return $this->luaFinalize($keys, $args);
        }

        throw new \LogicException('unexpected script');
    }

    /** The claim Lua mirror: missing -> pending(me, lease) -> 'claimed'. */
    private function luaClaim(array $keys, array $args): string
    {
        $recordKey = (string) $keys[0];
        $decisionKey = (string) $keys[1];
        $owner = (string) $args[0];
        $leaseSecs = (int) $args[1];
        $ttlSecs = (int) $args[2];
        $now = (int) floor($this->clockMs / 1000);
        $existing = $this->strings[$recordKey] ?? null;
        if ($existing === null) {
            $decisionId = null;
            if ($decisionKey !== '') {
                $d = $this->fakeGetdel([$decisionKey]);
                if ($d !== null) {
                    $decoded = json_decode($d, true);
                    if (\is_array($decoded) && \is_string($decoded['decision_id'] ?? null) && $decoded['decision_id'] !== '') {
                        $decisionId = $decoded['decision_id'];
                    }
                }
            }
            $rec = [
                'v' => 1,
                'state' => 'pending',
                'owner' => $owner,
                'lease_until' => $now + $leaseSecs,
                'disposition' => null,
                'decision_id' => $decisionId,
            ];
            $this->strings[$recordKey] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

            return (string) json_encode(['status' => 'claimed', 'record' => $rec], JSON_THROW_ON_ERROR);
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if (($rec['v'] ?? null) !== 1 && ($rec['v'] ?? null) !== 2) {
            return (string) json_encode(['status' => 'corrupt'], JSON_THROW_ON_ERROR);
        }
        if (($rec['state'] ?? null) === 'complete') {
            return (string) json_encode(['status' => 'complete', 'record' => $rec], JSON_THROW_ON_ERROR);
        }
        if (($rec['state'] ?? null) !== 'pending'
            || !\is_string($rec['owner'] ?? null) || $rec['owner'] === ''
            || !\is_int($rec['lease_until'] ?? null)
            || ($rec['disposition'] ?? null) !== null
        ) {
            return (string) json_encode(['status' => 'corrupt'], JSON_THROW_ON_ERROR);
        }
        if (($rec['owner'] ?? null) === $owner) {
            return (string) json_encode(['status' => 'pending'], JSON_THROW_ON_ERROR);
        }
        if (($rec['lease_until'] ?? 0) > $now) {
            return (string) json_encode(['status' => 'pending'], JSON_THROW_ON_ERROR);
        }
        $rec['owner'] = $owner;
        $rec['lease_until'] = $now + $leaseSecs;
        $rec['disposition'] = null;
        $this->strings[$recordKey] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

        return (string) json_encode(['status' => 'taken_over', 'record' => $rec], JSON_THROW_ON_ERROR);
    }

    /** The finalize Lua mirror: pending(owner) -> complete(disposition). */
    private function luaFinalize(array $keys, array $args): mixed
    {
        $recordKey = (string) $keys[0];
        $existing = $this->strings[$recordKey] ?? null;
        if ($existing === null) {
            return false;
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if (($rec['v'] ?? null) !== 1 && ($rec['v'] ?? null) !== 2) {
            return false;
        }
        if (($rec['state'] ?? null) !== 'pending' || ($rec['owner'] ?? null) !== (string) $args[0]) {
            return false;
        }
        $rec['state'] = 'complete';
        $rec['owner'] = null;
        $rec['lease_until'] = null;
        $rec['disposition'] = json_decode((string) $args[1], true, 8, JSON_THROW_ON_ERROR);
        $this->strings[$recordKey] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

        return true;
    }
}
