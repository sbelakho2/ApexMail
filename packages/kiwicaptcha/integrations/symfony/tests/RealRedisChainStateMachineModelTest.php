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

    public function testArrayAndRedisCreateOrGetBothRefuseToHealACorruptButLiveRecord(): void
    {
        // Corrupt state is never healed, on either store: the pointed-at
        // record is validated with the strict v2 decode, the create-or-get
        // fails closed with zero writes, and the obligation mapping keeps
        // pointing at the corrupt chain. Only a genuinely missing or
        // signed-expired record repairs the mapping.
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
        $tampered = (string) json_encode($record, JSON_THROW_ON_ERROR);
        $this->client->set($recordKey, $tampered, 'EX', 300);

        // Redis: the Lua predicate rejects the corrupt record and writes
        // nothing: the mapping and the bytes are preserved.
        $freshChainId = 'chain-fresh-'.$requirement->chainId;
        try {
            $store->createOrGetObligation($obligationId, $freshChainId, ChainStateWalk::S1_NONCE, 'login', 'txn-alpha', 'sha16', 1, 1, $expiry, 300);
            self::fail('the Redis create-or-get must fail closed on a corrupt chain, never heal');
        } catch (\BelConsulting\KiwiCaptchaBundle\Risk\MalformedChainedChallengeStateException) {
            // expected
        }
        try {
            self::assertSame($requirement->chainId, $store->obligationChainId($obligationId), 'the obligation still points at the corrupt chain');
        } catch (\BelConsulting\KiwiCaptchaBundle\Risk\MalformedChainedChallengeStateException) {
            // A validating obligation read may throw on the corrupt chain
            // instead of reporting the id: either way the mapping was NOT
            // dropped.
        }
        self::assertSame($tampered, $this->client->get($recordKey), 'the corrupt bytes are preserved');
        self::assertNull($store->read($freshChainId), 'no fresh Redis chain was created');

        // Array: the identical contract, the identical fail-closed result.
        $array = new ArrayChainedChallengeStateStore();
        $arrayService = new ChainedChallengeTicketService($array, self::SECRET, 300, 15);
        $arrayRequirement = $arrayService->requireStage2(ChainStateWalk::S1_NONCE, 'login', 'txn-alpha', 1, \KiwiCaptcha\Risk\RiskAction::Argon32, $expiry);
        $arrayObligationId = $arrayService->obligationIdFor('login', 'txn-alpha', 1);
        $arrayRecords = (new \ReflectionObject($array))->getProperty('records')->getValue($array);
        self::assertArrayHasKey($arrayRequirement->chainId, $arrayRecords, 'the array store holds the chain record');
        $arrayRecords[$arrayRequirement->chainId]['state'] = 'unexpected-state';
        (new \ReflectionObject($array))->getProperty('records')->setValue($array, $arrayRecords);

        $arrayFresh = 'array-chain-fresh';
        try {
            $array->createOrGetObligation($arrayObligationId, $arrayFresh, ChainStateWalk::S1_NONCE, 'login', 'txn-alpha', 'sha16', 1, 1, $expiry, 300);
            self::fail('PARITY: the array create-or-get must fail closed on a corrupt chain, never heal');
        } catch (\BelConsulting\KiwiCaptchaBundle\Risk\MalformedChainedChallengeStateException) {
            // expected
        }
        try {
            $array->obligationChainId($arrayObligationId);
            self::fail('the array obligation read must fail closed on the corrupt chain');
        } catch (\BelConsulting\KiwiCaptchaBundle\Risk\MalformedChainedChallengeStateException) {
            // expected: the corrupt state is never silently dropped
        }
        $arrayObligations = (new \ReflectionObject($array))->getProperty('obligations')->getValue($array);
        self::assertSame($arrayRequirement->chainId, $arrayObligations[$arrayObligationId] ?? null, 'the array mapping still points at the corrupt chain');
        self::assertNull($array->read($arrayFresh), 'no fresh Array chain was created');

        // The corrupt record stays fail-closed at the read boundary.
        try {
            $array->read($arrayRequirement->chainId);
            self::fail('the corrupt Array record must stay fail-closed');
        } catch (\BelConsulting\KiwiCaptchaBundle\Risk\MalformedChainedChallengeStateException) {
            // expected
        }
    }
}
