<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\ArrayChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\ChainStateWalk;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisChainDriver;
use PHPUnit\Framework\TestCase;

/**
 * real-redis model checking of the chained-challenge state machine (CI
 * service container: redis on 127.0.0.1:6399, TEST_REDIS_URL /
 * KC_REDIS_URL).
 *
 * The same model-checking harness as ChainStateMachineModelTest, driven
 * against the real Lua transitions of
 * RedisChainedChallengeStateStore. The hand-enumerated sequences and the
 * bounded random walk (fixed seed) replay against the clean-room
 * {@see ChainModel}, asserting outcome parity and the invariant suite
 * after every step — the atomicity the in-memory mirror cannot prove.
 *
 * Skipped unless a Redis answers at the published test URL.
 */
final class RealRedisChainStateMachineModelTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const NAMESPACE = 'ci-chain-model';

    private \Predis\Client $client;

    protected function setUp(): void
    {
        if (!class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis not installed');
        }
        $url = \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl::resolve();
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis suites run in the CI Redis-service job');
        }
        $this->client = new \Predis\Client($url);
        try {
            $this->client->ping();
        } catch (\Throwable $e) {
            self::markTestSkipped('Redis unreachable at '.$url.': '.$e->getMessage());
        }
        $this->client->flushdb();
    }

    public function testHandEnumeratedSequencesObserveTheModelAgainstRealRedis(): void
    {
        // Each sequence runs against a clean DB (the walk's obligation id
        // is fixed, and a leftover mapping from the previous sequence
        // would look like a live obligation of the same transaction).
        // Happy path: exactly one mint, one Pass, terminal absorption.
        ChainStateWalk::run('redis-hand-happy', $this->freshDriver(), [
            ['createOrGet', ['rank' => 1]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[0]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[0], 'nonce' => ChainStateWalk::NONCES[0]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[0], 'nonce' => ChainStateWalk::NONCES[0]]],
            ['markVerified', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['markVerified', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['markVerified', ['nonce' => ChainStateWalk::NONCES[1]]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[1]]],
            ['rearmIssued', ['nonce' => ChainStateWalk::NONCES[0]]],
        ]);

        // Terminal denied: absorbing, never flipped, the obligation kept
        // and then compare-deleted.
        ChainStateWalk::run('redis-hand-denied', $this->freshDriver(), [
            ['createOrGet', ['rank' => 1]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[0]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[0], 'nonce' => ChainStateWalk::NONCES[0]]],
            ['markDenied', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['markVerified', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[1], 'nonce' => ChainStateWalk::NONCES[1]]],
            ['rearmIssued', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[1]]],
            ['markTransactionStepUpRequired', ['obligationId' => ChainStateWalk::OBLIGATION]],
        ]);

        // Rearm: nonce-pinned; the rearmed-away challenge never verifies.
        ChainStateWalk::run('redis-hand-rearm', $this->freshDriver(), [
            ['createOrGet', ['rank' => 1]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[0]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[0], 'nonce' => ChainStateWalk::NONCES[0]]],
            ['rearmIssued', ['nonce' => ChainStateWalk::NONCES[1]]],
            ['rearmIssued', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[0]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[0], 'nonce' => ChainStateWalk::NONCES[1]]],
            ['markVerified', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['markVerified', ['nonce' => ChainStateWalk::NONCES[1]]],
        ]);

        // The nonce-agnostic transaction terminalization: issued(S) ->
        // denied(S), the Pass refused (the 503 loop is impossible).
        ChainStateWalk::run('redis-hand-txn-deny', $this->freshDriver(), [
            ['createOrGet', ['rank' => 1]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[0]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[0], 'nonce' => ChainStateWalk::NONCES[0]]],
            ['markTransactionDenied', ['obligationId' => ChainStateWalk::OBLIGATION]],
            ['markVerified', ['nonce' => ChainStateWalk::NONCES[0]]],
            ['markDenied', ['nonce' => ChainStateWalk::NONCES[0]]],
        ]);

        // A foreign obligation id is refused atomically.
        ChainStateWalk::run('redis-hand-foreign', $this->freshDriver(), [
            ['createOrGet', ['rank' => 1]],
            ['markTransactionDenied', ['obligationId' => ChainStateWalk::OTHER_OBLIGATION]],
            ['markTransactionStepUpRequired', ['obligationId' => ChainStateWalk::OTHER_OBLIGATION]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[0]]],
        ]);

        // The lease-expiry takeover and the owner-scoped release.
        ChainStateWalk::run('redis-hand-lease', $this->freshDriver(), [
            ['createOrGet', ['rank' => 1]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[0]]],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[1]]],
            ['release', ['owner' => ChainStateWalk::OWNERS[1]]],
            ['advanceLease', []],
            ['reserve', ['owner' => ChainStateWalk::OWNERS[1]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[0], 'nonce' => ChainStateWalk::NONCES[0]]],
            ['markIssued', ['owner' => ChainStateWalk::OWNERS[1], 'nonce' => ChainStateWalk::NONCES[0]]],
        ]);
    }

    public function testBoundedRandomWalkKeepsEveryInvariantAgainstRealRedis(): void
    {
        // The same fixed-seed walk as the in-memory suite, against the
        // real Lua scripts: outcome parity with the model and the full
        // invariant suite after every step.
        $driver = $this->freshDriver();
        $result = ChainStateWalk::run('redis-walk', $driver, ChainStateWalk::steps(0x5EED, 600));
        self::assertSame(600, $result['steps']);
        self::assertGreaterThan(1, $result['generations'], 'the walk must exercise fresh chain creations after expiry');
    }

    /** A driver over a clean DB (the walk's obligation id is fixed). */
    private function freshDriver(): RedisChainDriver
    {
        $this->client->flushdb();

        return new RedisChainDriver($this->client, self::NAMESPACE);
    }

    public function testArrayAndRedisCreateOrGetBothHealACorruptButLiveRecord(): void
    {
        // The documented create-or-get contract says a mapping that points
        // at a missing or corrupt chain record is compare-deleted and the
        // chain created fresh ("the atomic retry"). The Redis Lua
        // predicate detects the corrupt record (isValidChainRecord) and
        // repairs it; the in-memory store now mirrors that behavior: the
        // pointed-at record is validated with the strict v2 decode and a
        // corrupt record is healed the same way (compare-delete + create
        // fresh), so both sides converge on the fresh chain.
        $store = new RedisChainedChallengeStateStore($this->client, self::NAMESPACE);
        $service = new ChainedChallengeTicketService($store, self::SECRET, 300, 15);
        $expiry = time() + 300;
        $requirement = $service->requireStage2(ChainStateWalk::S1_NONCE, 'login', 'txn-alpha', 1, \KiwiCaptcha\Risk\RiskAction::Argon32, $expiry);
        $obligationId = $service->obligationIdFor('login', 'txn-alpha', 1);
        $recordKey = sprintf('{kiwi:%s}:chain:%s', self::NAMESPACE, $requirement->chainId);

        $corrupt = $this->client->get($recordKey);
        self::assertIsString($corrupt);
        $record = json_decode($corrupt, true, 8, JSON_THROW_ON_ERROR);
        $record['state'] = 'unexpected-state';
        $this->client->set($recordKey, (string) json_encode($record, JSON_THROW_ON_ERROR), 'EX', 300);

        // Redis: the Lua predicate rejects the corrupt record and repairs
        // the mapping with a fresh chain in the same script.
        $freshChainId = 'chain-fresh-'.$requirement->chainId;
        $repaired = $store->createOrGetObligation($obligationId, $freshChainId, ChainStateWalk::S1_NONCE, 'login', 'txn-alpha', 'sha16', 1, 1, $expiry, 300);
        self::assertSame($freshChainId, $repaired, 'the Redis create-or-get REPAIRS the corrupt mapping with a fresh chain');
        self::assertSame($freshChainId, $store->obligationChainId($obligationId), 'the obligation now points at the fresh chain');

        // Array: the same documented contract — the corrupt-but-live
        // record must now be healed identically (parity, the fixed
        // divergence): the strict v2 decode rejects the corrupt record
        // and the mapping is compare-deleted + created fresh.
        $array = new ArrayChainedChallengeStateStore();
        $arrayService = new ChainedChallengeTicketService($array, self::SECRET, 300, 15);
        $arrayRequirement = $arrayService->requireStage2(ChainStateWalk::S1_NONCE, 'login', 'txn-alpha', 1, \KiwiCaptcha\Risk\RiskAction::Argon32, $expiry);
        $arrayObligationId = $arrayService->obligationIdFor('login', 'txn-alpha', 1);
        $arrayRecords = (new \ReflectionObject($array))->getProperty('records')->getValue($array);
        self::assertArrayHasKey($arrayRequirement->chainId, $arrayRecords, 'the array store holds the chain record');
        $arrayRecords[$arrayRequirement->chainId]['state'] = 'unexpected-state';
        (new \ReflectionObject($array))->getProperty('records')->setValue($array, $arrayRecords);

        $arrayFresh = 'array-chain-fresh';
        $returned = $array->createOrGetObligation($arrayObligationId, $arrayFresh, ChainStateWalk::S1_NONCE, 'login', 'txn-alpha', 'sha16', 1, 1, $expiry, 300);
        self::assertSame($arrayFresh, $returned, 'PARITY: the array create-or-get now REPAIRS the corrupt mapping with a fresh chain');
        self::assertSame($arrayFresh, $array->obligationChainId($arrayObligationId), 'the array obligation now points at the fresh chain');

        // The fresh chain is strictly decodable and live (no fail-closed
        // 503 at the read boundary).
        $fresh = $array->read($arrayFresh);
        self::assertIsArray($fresh);
        self::assertSame('available', $fresh['state']);
    }
}
