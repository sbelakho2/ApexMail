<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore;
use PHPUnit\Framework\TestCase;

/**
 * The Redis-backed chain state store's Lua state machine, exercised
 * against an in-memory Redis fake that emulates the EXACT command surface
 * the store uses (GET / SET with the EX option array / TTL / TIME /
 * EVAL with the chain scripts interpreted by marker). Covers the
 * owner-scoped reservation lease (redis TIME), the terminal completed
 * transition (never a delete) and the owner-gated release — the
 * production concurrency path of the chained-challenge state machine.
 */
final class RedisChainedChallengeStateStoreTest extends TestCase
{
    private function store(): RedisChainedChallengeStateStore
    {
        return new RedisChainedChallengeStateStore(new ChainRedisFake(), 'kiwi-test');
    }

    private function issueTicket(RedisChainedChallengeStateStore $store): array
    {
        $service = new ChainedChallengeTicketService($store, '0123456789abcdef0123456789abcdef', 300);
        $ticket = $service->issue(bin2hex(random_bytes(16)), 'login', 1, requiredAction: 'argon32');
        self::assertIsString($ticket);

        return [$ticket, $service->verify($ticket)['chainId']];
    }

    public function testCreateReadAndOwnerScopedReservationLease(): void
    {
        $store = $this->store();
        [$ticket, $chainId] = $this->issueTicket($store);

        // The plain read sees the full server-held record in the
        // AVAILABLE state.
        $state = $store->read($chainId);
        self::assertIsArray($state);
        self::assertSame('available', $state['state']);
        self::assertSame('argon32', $state['requiredAction']);
        self::assertSame(2, $state['chainDepth']);
        self::assertSame(1, $state['policyVersion']);
        self::assertNull($state['owner']);
        self::assertNull($state['leaseUntil']);
        self::assertNull($state['stage2Nonce']);

        // Owner-scoped reservation: available -> reserved(me) with a
        // lease from the fake redis TIME + the record's remaining TTL.
        self::assertSame('available', $store->reserve($chainId, 'owner-a', 300));
        self::assertSame('retry', $store->reserve($chainId, 'owner-a', 300), 'reserve by the SAME owner is a retry');
        self::assertSame('busy', $store->reserve($chainId, 'owner-b', 300), 'reserve by another owner with a live lease is busy');
        $reserved = $store->read($chainId);
        self::assertSame('reserved', $reserved['state']);
        self::assertSame('owner-a', $reserved['owner']);
        self::assertNotNull($reserved['leaseUntil']);
        self::assertGreaterThanOrEqual(1000, (int) $reserved['leaseUntil'], 'the lease is now + remaining TTL');
    }

    public function testOwnerGatedReleaseAndNonOwnerReleaseNoOp(): void
    {
        $store = $this->store();
        [, $chainId] = $this->issueTicket($store);

        self::assertSame('available', $store->reserve($chainId, 'owner-a', 300));
        $store->release($chainId, 'owner-b');
        self::assertSame('busy', $store->reserve($chainId, 'owner-c', 300), 'a non-owner release is an atomic no-op — the reservation stays live');

        $store->release($chainId, 'owner-a');
        $state = $store->read($chainId);
        self::assertSame('available', $state['state'], 'the owner\'s release returns the chain to available');
        self::assertNull($state['owner']);
        self::assertNull($state['leaseUntil']);
        self::assertSame('available', $store->reserve($chainId, 'owner-b', 300), 'the released chain is reservable again');
    }

    public function testTerminalCompletionNeverDeletesAndNeverReMints(): void
    {
        $store = $this->store();
        [$ticket, $chainId] = $this->issueTicket($store);

        // A non-owner can never complete.
        self::assertSame('available', $store->reserve($chainId, 'owner-a', 300));
        self::assertNull($store->complete($chainId, 'owner-b', 'stage2-nonce'), 'a non-owner complete is an atomic no-op');

        // The owner's complete is a TERMINAL state transition: the record
        // KEEPS its TTL (never a delete) and carries the stage2Nonce.
        $completed = $store->complete($chainId, 'owner-a', 'stage2-nonce');
        self::assertIsArray($completed);
        self::assertSame('completed', $completed['state']);
        self::assertSame('stage2-nonce', $completed['stage2Nonce']);
        $read = $store->read($chainId);
        self::assertSame('completed', $read['state'], 'the completed record is still readable (the retry recovers from it)');
        self::assertSame('stage2-nonce', $read['stage2Nonce']);
        self::assertSame('completed', $store->reserve($chainId, 'owner-c', 300), 'a replayed ticket lands on the completed state');
        self::assertNull($store->complete($chainId, 'owner-a', 'another-nonce'), 'a completed chain NEVER allows a second completion (no second mint)');
        $store->release($chainId, 'owner-a');
        self::assertSame('completed', $store->read($chainId)['state'], 'a release cannot undo the terminal completed state');
    }

    public function testMissingChainAnswersMissing(): void
    {
        $store = $this->store();
        self::assertSame('missing', $store->reserve('no-such-chain', 'owner-a', 300));
        self::assertNull($store->read('no-such-chain'));
        self::assertNull($store->complete('no-such-chain', 'owner-a', 'n'));
    }
}

/**
 * In-memory stand-in for Predis\Client with exactly the command surface
 * the Redis chain state store uses: GET / SET (with the EX options-array
 * form) / TTL / TIME / EVAL. The EVAL interpreter runs the store's three
 * chain scripts by their marker comments with the SAME semantics as the
 * Lua (owner-scoped lease from TIME + remaining TTL, KEEPTTL preserved,
 * terminal completed transition). The clock advances through
 * {@see self::setTimeMs()} so the lease expiry is enforceable.
 */
final class ChainRedisFake extends \Predis\Client
{
    /** @var array<string, string> plain strings (the chain records) */
    public array $strings = [];

    /** @var array<string, int> EXPIRE deadlines in ms */
    public array $expirations = [];

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
        return match (strtoupper((string) $commandID)) {
            'GET' => $this->strings[(string) $arguments[0]] ?? null,
            'SET' => $this->fakeSet($arguments),
            'TTL' => $this->fakeTtl((string) $arguments[0]),
            'TIME' => $this->fakeTime(),
            'EVAL' => $this->fakeEval($arguments),
            default => throw new \LogicException('unexpected command '.$commandID),
        };
    }

    private function fakeSet(array $arguments): ?string
    {
        $key = (string) $arguments[0];
        $value = (string) $arguments[1];
        $ttl = null;
        if (isset($arguments[2]) && \is_array($arguments[2]) && isset($arguments[2]['EX'])) {
            $ttl = (int) $arguments[2]['EX'];
        }
        $this->strings[$key] = $value;
        if ($ttl !== null) {
            $this->expirations[$key] = (int) ($ttl * 1000);
        }

        return 'OK';
    }

    private function fakeTtl(string $key): int
    {
        if (!isset($this->strings[$key])) {
            return -2;
        }
        if (!isset($this->expirations[$key])) {
            return -1;
        }
        $remainingMs = $this->expirations[$key] - $this->clockMs;

        return (int) max(1, floor($remainingMs / 1000));
    }

    /** @return array{0: int, 1: int} [seconds, microseconds] */
    private function fakeTime(): array
    {
        $sec = (int) floor($this->clockMs / 1000);

        return [$sec, (int) round(($this->clockMs - $sec * 1000) * 1000)];
    }

    private function fakeEval(array $arguments): mixed
    {
        $script = (string) $arguments[0];
        $numKeys = (int) $arguments[1];
        $keysAndArgs = \array_slice($arguments, 2);
        $key = (string) $keysAndArgs[0];
        $args = \array_slice($keysAndArgs, $numKeys);

        if (str_contains($script, 'Chain reservation')) {
            return $this->luaReserve($key, $args);
        }
        if (str_contains($script, 'Chain completion')) {
            return $this->luaComplete($key, $args);
        }
        if (str_contains($script, 'Chain release')) {
            return $this->luaRelease($key, $args);
        }

        throw new \LogicException('unexpected script');
    }

    private function luaReserve(string $key, array $args): string
    {
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return 'missing';
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if ($rec['state'] === 'completed') {
            return 'completed';
        }
        $nowSecs = (int) floor($this->clockMs / 1000);
        if ($rec['state'] === 'reserved') {
            if ($rec['owner'] === $args[0]) {
                return 'retry';
            }
            if ((int) $rec['leaseUntil'] > $nowSecs) {
                return 'busy';
            }
        }
        $remaining = $this->fakeTtl($key);
        if ($remaining < 1) {
            $remaining = (int) $args[1];
        }
        $rec['state'] = 'reserved';
        $rec['owner'] = (string) $args[0];
        $rec['leaseUntil'] = $nowSecs + $remaining;
        // KEEPTTL: the record keeps its remaining lifetime.
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

        return 'available';
    }

    private function luaComplete(string $key, array $args): mixed
    {
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return false;
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if ($rec['state'] !== 'reserved' || $rec['owner'] !== $args[0]) {
            return false;
        }
        $rec['state'] = 'completed';
        $rec['stage2Nonce'] = (string) $args[1];
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

        return (string) json_encode($rec, JSON_THROW_ON_ERROR);
    }

    private function luaRelease(string $key, array $args): mixed
    {
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return false;
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if ($rec['state'] !== 'reserved' || $rec['owner'] !== $args[0]) {
            return false;
        }
        $rec['state'] = 'available';
        $rec['owner'] = null;
        $rec['leaseUntil'] = null;
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

        return true;
    }
}
