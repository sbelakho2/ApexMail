<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\MalformedChainedChallengeStateException;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore;
use KiwiCaptcha\Risk\RiskAction;
use PHPUnit\Framework\TestCase;

/**
 * The Redis-backed chain state store's Lua state machine, exercised
 * against an in-memory Redis fake emulating the store's command surface
 * (GET / SET with the EX options array / TTL / time / eval with the
 * chain scripts interpreted by marker). Covers the transaction-obligation
 * create-or-get, the owner-scoped short reservation lease (redis time +
 * min(lease, remaining TTL)), the idempotent issued transition, the
 * terminal verified transition with the atomic obligation deletion, the
 * nonce-pinned rearm and the owner-gated release. This is the production
 * concurrency path of the chained-challenge state machine.
 */
final class RedisChainedChallengeStateStoreTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private ?ChainRedisFake $fake = null;

    private function store(): RedisChainedChallengeStateStore
    {
        $this->fake = new ChainRedisFake();

        return new RedisChainedChallengeStateStore($this->fake, 'kiwi-test');
    }

    private function makeNonce(): string
    {
        return base64_encode(random_bytes(32));
    }

    /** @return array{0: ChainedChallengeTicketService, 1: \BelConsulting\KiwiCaptchaBundle\Risk\ChainRequirement} */
    private function issueRequirement(RedisChainedChallengeStateStore $store): array
    {
        $service = new ChainedChallengeTicketService($store, self::SECRET, 300, 15, null, fn (): int => $this->fake->clockSecs());
        $requirement = $service->requireStage2($this->makeNonce(), 'login', 'tx-binding', 1, RiskAction::Argon32, 1300);

        return [$service, $requirement];
    }

    public function testCreateReadAndOwnerScopedShortLease(): void
    {
        $store = $this->store();
        [$service, $requirement] = $this->issueRequirement($store);
        $chainId = $requirement->chainId;

        // The obligation index is created for the exact transaction anchor.
        self::assertSame($chainId, $store->obligationChainId($service->obligationIdFor('login', 'tx-binding', 1)));

        // The plain read sees the full server-held v2 record in the
        // available state.
        $state = $store->read($chainId);
        self::assertIsArray($state);
        self::assertSame('available', $state['state']);
        self::assertSame('argon32', $state['requiredAction']);
        self::assertSame(2, $state['chainDepth']);
        self::assertSame(1, $state['policyVersion']);
        self::assertSame('tx-binding', $state['requestBinding']);
        self::assertSame(64, \strlen((string) $state['obligationId']));
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/D', (string) $state['obligationId']);
        self::assertNull($state['owner']);
        self::assertNull($state['leaseUntil']);
        self::assertNull($state['stage2Nonce']);

        // Owner-scoped reservation with the short fixed lease: available ->
        // reserved with a lease of now + min(15, remaining TTL).
        self::assertSame('available', $store->reserve($chainId, 'owner-a', 15));
        self::assertSame('retry', $store->reserve($chainId, 'owner-a', 15), 'reserve by the SAME owner is a retry');
        self::assertSame('busy', $store->reserve($chainId, 'owner-b', 15), 'reserve by another owner with a live lease is busy');
        $reserved = $store->read($chainId);
        self::assertSame('reserved', $reserved['state']);
        self::assertSame('owner-a', $reserved['owner']);
        self::assertSame(1015, (int) $reserved['leaseUntil'], 'the lease is now (1000) + the SHORT lease (15), never the record TTL');
    }

    public function testExpiredLeaseIsTakenOverBeforeTheTicketExpiry(): void
    {
        $store = $this->store();
        [, $requirement] = $this->issueRequirement($store);
        $chainId = $requirement->chainId;

        self::assertSame('available', $store->reserve($chainId, 'owner-a', 15));
        $this->fake->setTimeMs(1_016_000.0);
        self::assertSame('taken_over', $store->reserve($chainId, 'owner-b', 15), 'an expired reservation is taken over by the next owner');
        $state = $store->read($chainId);
        self::assertSame('owner-b', $state['owner']);
        self::assertSame(1031, (int) $state['leaseUntil']);
    }

    public function testOwnerGatedReleaseAndNonOwnerReleaseNoOp(): void
    {
        $store = $this->store();
        [, $requirement] = $this->issueRequirement($store);
        $chainId = $requirement->chainId;

        self::assertSame('available', $store->reserve($chainId, 'owner-a', 15));
        $store->release($chainId, 'owner-b');
        self::assertSame('busy', $store->reserve($chainId, 'owner-c', 15), 'a non-owner release is an atomic no-op — the reservation stays live');

        $store->release($chainId, 'owner-a');
        $state = $store->read($chainId);
        self::assertSame('available', $state['state'], 'the owner\'s release returns the chain to available');
        self::assertNull($state['owner']);
        self::assertNull($state['leaseUntil']);
        self::assertSame('available', $store->reserve($chainId, 'owner-b', 15), 'the released chain is reservable again');
    }

    public function testMarkIssuedIsIdempotentAndOwnerGated(): void
    {
        $store = $this->store();
        [, $requirement] = $this->issueRequirement($store);
        $chainId = $requirement->chainId;
        $nonce = $this->makeNonce();

        self::assertSame('not_owner', $store->markIssued($chainId, 'owner-other', $nonce), 'an unreserved chain cannot be issued by a stranger');
        self::assertSame('available', $store->reserve($chainId, 'owner-a', 15));
        self::assertSame('issued_new', $store->markIssued($chainId, 'owner-a', $nonce));
        self::assertSame('issued_same', $store->markIssued($chainId, 'owner-a', $nonce), 'same-nonce retry is idempotent (a lost reply is recoverable)');
        self::assertSame('conflict', $store->markIssued($chainId, 'owner-a', $this->makeNonce()), 'a different nonce on an issued chain is a conflict');
        $state = $store->read($chainId);
        self::assertSame('issued', $state['state']);
        self::assertSame($nonce, $state['stage2Nonce']);
        self::assertNull($state['owner']);
        self::assertNull($state['leaseUntil']);
        self::assertSame('issued', $store->reserve($chainId, 'owner-b', 15), 'an issued chain is never re-reservable (no second mint)');
    }

    public function testMarkVerifiedIsTerminalAndDeletesTheObligation(): void
    {
        $store = $this->store();
        [$service, $requirement] = $this->issueRequirement($store);
        $chainId = $requirement->chainId;
        $nonce = $this->makeNonce();
        $obligationId = $service->obligationIdFor('login', 'tx-binding', 1);

        self::assertSame('available', $store->reserve($chainId, 'owner-a', 15));
        self::assertSame('issued_new', $store->markIssued($chainId, 'owner-a', $nonce));
        self::assertSame('verified_new', $store->markVerified($chainId, $nonce));
        self::assertSame('verified_same', $store->markVerified($chainId, $nonce), 'markVerified is idempotent (a lost reply is confirmable)');
        self::assertSame('conflict', $store->markVerified($chainId, $this->makeNonce()));
        self::assertNull($store->obligationChainId($obligationId), 'the terminal transition deletes the obligation mapping');
        $state = $store->read($chainId);
        self::assertSame('verified', $state['state'], 'the terminal verified record is kept until its TTL');
        self::assertSame($nonce, $state['stage2Nonce']);
        self::assertSame('verified', $store->reserve($chainId, 'owner-b', 15), 'a verified chain is terminal');
    }

    public function testRearmIssuedIsPinnedToTheExpectedNonce(): void
    {
        $store = $this->store();
        [, $requirement] = $this->issueRequirement($store);
        $chainId = $requirement->chainId;
        $nonce = $this->makeNonce();

        self::assertSame('available', $store->reserve($chainId, 'owner-a', 15));
        self::assertSame('issued_new', $store->markIssued($chainId, 'owner-a', $nonce));
        self::assertFalse($store->rearmIssued($chainId, $this->makeNonce()), 'rearm with a different nonce is an atomic no-op');
        self::assertTrue($store->rearmIssued($chainId, $nonce), 'rearm with the exact expected nonce returns the chain to available');
        $state = $store->read($chainId);
        self::assertSame('available', $state['state']);
        self::assertNull($state['stage2Nonce']);
    }

    public function testMissingChainAnswersMissing(): void
    {
        $store = $this->store();
        self::assertSame('missing', $store->reserve('no-such-chain', 'owner-a', 15));
        self::assertNull($store->read('no-such-chain'));
        self::assertNull($store->obligationChainId(str_repeat('a', 64)));
    }

    public function testCorruptServerRecordFailsClosed(): void
    {
        $store = $this->store();
        [, $requirement] = $this->issueRequirement($store);
        $chainId = $requirement->chainId;
        $record = $this->fake->strings['{kiwi:kiwi-test}:chain:'.$chainId];
        $corrupt = json_decode($record, true, 8, JSON_THROW_ON_ERROR);
        unset($corrupt['requiredAction']);
        $this->fake->strings['{kiwi:kiwi-test}:chain:'.$chainId] = (string) json_encode($corrupt, JSON_THROW_ON_ERROR);

        $this->expectException(MalformedChainedChallengeStateException::class);
        $store->read($chainId);
    }
}

/**
 * In-memory stand-in for Predis\Client with exactly the command surface
 * the Redis chain state store uses: GET / SET (with the EX options-array
 * form) / TTL / time / eval. The eval interpreter runs the store's chain
 * scripts by their marker comments: obligation create-or-get with rank
 * raising and stale-mapping repair, the owner-scoped short lease from
 * time + min(lease, remaining TTL) with keepttl, and the idempotent
 * issued transition. The terminal verified transition deletes the
 * obligation atomically; the nonce-pinned rearm and the owner-gated
 * release complete the surface. The clock advances through
 * {@see self::setTimeMs()} so the lease expiry is enforceable.
 */
final class ChainRedisFake extends \Predis\Client
{
    /** @var array<string, string> plain strings (the chain/obligation records) */
    public array $strings = [];

    /** @var array<string, int> expire deadlines in ms */
    public array $expirations = [];

    private float $clockMs = 1_000_000.0;

    public function clockSecs(): int
    {
        return (int) floor($this->clockMs / 1000);
    }

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
            $this->expirations[$key] = (int) ($this->clockMs + $ttl * 1000);
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
        $keys = \array_slice($keysAndArgs, 0, $numKeys);
        $args = \array_slice($keysAndArgs, $numKeys);

        if (str_contains($script, 'Chain obligation create-or-get')) {
            return $this->luaCreateOrGet($keys, $args);
        }
        if (str_contains($script, 'Chain reservation')) {
            return $this->luaReserve($keys[0], $args);
        }
        if (str_contains($script, 'Chain issuance')) {
            return $this->luaMarkIssued($keys[0], $args);
        }
        if (str_contains($script, 'Chain verification')) {
            return $this->luaMarkVerified($keys, $args);
        }
        if (str_contains($script, 'Chain rearm')) {
            return $this->luaRearm($keys[0], $args);
        }
        if (str_contains($script, 'Chain release')) {
            return $this->luaRelease($keys[0], $args);
        }
        if (str_contains($script, 'Chain completion')) {
            return $this->luaComplete($keys[0], $args);
        }
        if (str_contains($script, 'Chain obligation compare-delete')) {
            return $this->luaDeleteObligation($keys[0], $args);
        }

        throw new \LogicException('unexpected script');
    }

    private function luaCreateOrGet(array $keys, array $args): string
    {
        $obligationKey = $keys[1];
        $chainKey = $keys[0];
        $prefix = (string) $args[10];
        $existing = $this->strings[$obligationKey] ?? null;
        if ($existing !== null) {
            $chainId = $existing;
            $chained = $this->strings[$prefix.$chainId] ?? null;
            if ($chained !== null) {
                $rec = json_decode($chained, true, 8, JSON_THROW_ON_ERROR);
                if (isset($rec['requiredRank']) && \is_int($rec['requiredRank'])) {
                    $newRank = (int) $args[5];
                    if ($newRank > $rec['requiredRank']) {
                        $rec['requiredRank'] = $newRank;
                        $rec['requiredAction'] = (string) $args[4];
                        $this->strings[$prefix.$chainId] = (string) json_encode($rec, JSON_THROW_ON_ERROR);
                    }

                    return $chainId;
                }
            }
            if (($this->strings[$obligationKey] ?? null) === $chainId) {
                unset($this->strings[$obligationKey], $this->expirations[$obligationKey]);
            }
        }
        $rec = [
            'v' => 2,
            'stage1Nonce' => (string) $args[2],
            'scope' => (string) $args[3],
            'obligationId' => (string) $args[0],
            'requiredAction' => (string) $args[4],
            'requiredRank' => (int) $args[5],
            'policyVersion' => (int) $args[6],
            'chainDepth' => 2,
            'state' => 'available',
            'owner' => null,
            'leaseUntil' => null,
            'stage2Nonce' => null,
            'requestBinding' => (string) $args[7] !== '' ? (string) $args[7] : null,
            'expiresAt' => (int) $args[8],
        ];
        $ttl = (int) $args[9];
        $this->strings[$chainKey] = (string) json_encode($rec, JSON_THROW_ON_ERROR);
        $this->expirations[$chainKey] = (int) ($this->clockMs + $ttl * 1000);
        $this->strings[$obligationKey] = (string) $args[1];
        $this->expirations[$obligationKey] = (int) ($this->clockMs + $ttl * 1000);

        return (string) $args[1];
    }

    private function luaReserve(string $key, array $args): string
    {
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return 'missing';
        }
        $ttl = $this->fakeTtl($key);
        if ($ttl <= 0) {
            return 'missing';
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if ($rec['state'] === 'issued') {
            return 'issued';
        }
        if ($rec['state'] === 'verified') {
            return 'verified';
        }
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
            $lease = min((int) $args[1], $ttl);
            $rec['state'] = 'reserved';
            $rec['owner'] = (string) $args[0];
            $rec['leaseUntil'] = $nowSecs + $lease;
            $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

            return 'taken_over';
        }
        $lease = min((int) $args[1], $ttl);
        $rec['state'] = 'reserved';
        $rec['owner'] = (string) $args[0];
        $rec['leaseUntil'] = $nowSecs + $lease;
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

        return 'available';
    }

    private function luaMarkIssued(string $key, array $args): string
    {
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return 'missing';
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if ($rec['state'] === 'reserved') {
            if ($rec['owner'] !== $args[0]) {
                return 'not_owner';
            }
            $rec['state'] = 'issued';
            $rec['stage2Nonce'] = (string) $args[1];
            $rec['owner'] = null;
            $rec['leaseUntil'] = null;
            $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

            return 'issued_new';
        }
        if ($rec['state'] === 'issued' || $rec['state'] === 'completed') {
            return $rec['stage2Nonce'] === $args[1] ? 'issued_same' : 'conflict';
        }
        if ($rec['state'] === 'verified') {
            return $rec['stage2Nonce'] === $args[1] ? 'verified_same' : 'conflict';
        }

        return 'not_owner';
    }

    private function luaMarkVerified(array $keys, array $args): string
    {
        $key = $keys[0];
        $obligationKey = $keys[1];
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return 'missing';
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if ($rec['state'] === 'verified') {
            return $rec['stage2Nonce'] === $args[0] ? 'verified_same' : 'conflict';
        }
        if (($rec['state'] !== 'issued' && $rec['state'] !== 'completed') || $rec['stage2Nonce'] !== $args[0]) {
            return 'conflict';
        }
        $rec['state'] = 'verified';
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);
        if (($this->strings[$obligationKey] ?? null) === $args[1]) {
            unset($this->strings[$obligationKey], $this->expirations[$obligationKey]);
        }

        return 'verified_new';
    }

    private function luaRearm(string $key, array $args): bool
    {
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return false;
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if ($rec['state'] !== 'issued' || $rec['stage2Nonce'] !== $args[0]) {
            return false;
        }
        $rec['state'] = 'available';
        $rec['stage2Nonce'] = null;
        $rec['owner'] = null;
        $rec['leaseUntil'] = null;
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

        return true;
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

    private function luaDeleteObligation(string $key, array $args): mixed
    {
        if (($this->strings[$key] ?? null) === $args[0]) {
            unset($this->strings[$key], $this->expirations[$key]);

            return 1;
        }

        return 0;
    }
}
