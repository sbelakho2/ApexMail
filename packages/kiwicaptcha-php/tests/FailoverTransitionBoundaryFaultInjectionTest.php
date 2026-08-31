<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\FailoverHookingClient;
use KiwiCaptcha\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * The failover transition boundaries, fault-injected one point at a
 * time on the counting in-memory client: the runtime-state GET, the
 * consume EVAL, the commit EVAL, the WAIT and the replication-fence
 * SET. Each scenario arms exactly one boundary, verifies the typed
 * outcome, and inspects the record's on-Redis state afterwards: a
 * failed boundary must never leave the record consumed without
 * evidence. When the transition itself truly landed (the consume
 * under a failed WAIT, or a best-effort commit whose eval failed),
 * the consumed-without-result state is the honest one and the
 * ConsumeIndeterminate contract answers.
 *
 * The client records every command, so the exact transition sequence
 * is asserted too: the runtime-state snapshot is one GET, the consume
 * is one EVAL, the commit is one EVAL, and every barrier is one WAIT.
 */
final class FailoverTransitionBoundaryFaultInjectionTest extends TestCase
{
    private function requirePredis(): FakePredisClient
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed; cannot test RedisStorage');
        }

        return new FakePredisClient();
    }

    private function makeConfig(): Config
    {
        return new Config(
            secretKey: Vectors::SECRET,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 0,
            t: 1,
            p: 1,
            targetBits: 8,
            argon2TargetBits: 8,
            ttlSecs: 120,
            minDurationMs: 0,
        );
    }

    /** @return array{0: \KiwiCaptcha\ChallengeRecord, 1: string} */
    private function issueAndSolve(FakePredisClient $client, string $scope = 'login', string $ip = '198.51.100.77'): array
    {
        $plain = new RedisStorage($client);
        $challenge = (new Issuer($this->makeConfig(), $plain, now: static fn (): int => Vectors::NOW))->issue($scope, $ip);
        $record = $plain->find($challenge->nonce);
        self::assertNotNull($record);
        $counter = $this->solveSha256($record->prefix, $record->salt, $record->targetBits);
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();

        return [$record, $token];
    }

    private function solveSha256(string $prefix, string $salt, int $targetBits): int
    {
        $saltBytes = base64_decode($salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $targetBits);

        return $counter - 1;
    }

    private function verifier(RedisStorage $storage): Verifier
    {
        return new Verifier($storage, now: static fn (): int => Vectors::NOW);
    }

    private function commandCount(FakePredisClient $client, string $id): int
    {
        $count = 0;
        foreach ($client->calls as $call) {
            if (($call[0] ?? '') === $id) {
                $count++;
            }
        }

        return $count;
    }

    private function waitCount(FakePredisClient $client): int
    {
        return $this->commandCount($client, 'WAIT');
    }

    /** @return array{gets: int, evals: int, waits: int} the client counters at this instant */
    private function snapshot(FakePredisClient $client): array
    {
        return [
            'gets' => $client->gets,
            'evals' => $client->evalCount,
            'waits' => $this->waitCount($client),
        ];
    }

    /**
     * The runtime-state GET boundary: the snapshot read fails before
     * anything touched the record. The typed StorageUnavailable
     * answers, the record stays pending, exactly one GET was issued,
     * and the clean retry succeeds.
     */
    public function testRuntimeStateGetBoundaryFailsClosedWithTheRecordUntouched(): void
    {
        $client = $this->requirePredis();
        [$record, $token] = $this->issueAndSolve($client);
        $storage = new RedisStorage($client);

        $client->throwOnGet = true;
        $before = $this->snapshot($client);
        $outcome = $this->verifier($storage)->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertSame(VerifyError::StorageUnavailable, $outcome->error, 'a failed runtime-state read is the retryable StorageUnavailable');
        self::assertSame($before['gets'] + 1, $this->commandCount($client, 'GET'), 'the snapshot read was attempted exactly once');
        self::assertSame($before['gets'], $client->gets, 'the failed read never completed');
        self::assertSame($before['evals'], $client->evalCount, 'no transition ran');
        $client->throwOnGet = false;
        self::assertNull($storage->consumedState($record->nonce), 'the record must stay pending');
        self::assertNotNull($storage->find($record->nonce), 'the record must survive the failed read');

        $recovered = $this->verifier($storage)->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs + 1_000_000,
        );
        self::assertTrue($recovered->isOk(), sprintf('the clean retry verifies, got %s', $recovered->code()));
    }

    /**
     * The consume EVAL boundary: the transition throws before any
     * mutation. The ambiguous ConsumeIndeterminate answers, the
     * record is NOT left consumed without evidence, and the clean
     * retry verifies.
     */
    public function testConsumeEvalBoundaryFailureNeverLeavesAConsumedRecord(): void
    {
        $client = $this->requirePredis();
        [$record, $token] = $this->issueAndSolve($client);
        $storage = new RedisStorage($client);

        $client->throwOnEval = true;
        $before = $this->snapshot($client);
        $outcome = $this->verifier($storage)->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertSame(VerifyError::ConsumeIndeterminate, $outcome->error, 'a lost consume reply is the ambiguous indeterminate, never RecordNotFound');
        self::assertSame($before['gets'] + 1, $client->gets, 'the snapshot read is exactly one GET');
        self::assertSame($before['evals'] + 1, $client->evalCount, 'exactly the consume transition was attempted');
        $client->throwOnEval = false;
        self::assertNull($storage->consumedState($record->nonce), 'the record must not be consumed without evidence');
        self::assertNotNull($storage->find($record->nonce), 'the record must survive the failed transition');

        $recovered = $this->verifier($storage)->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs + 1_000_000,
        );
        self::assertTrue($recovered->isOk(), sprintf('after the connection recovers the record verifies, got %s', $recovered->code()));
    }

    /**
     * The commit EVAL boundary: the outcome commit throws before any
     * write. The consume transition already landed honestly, so the
     * record is consumed without a result. The best-effort commit
     * cannot change the outcome: the valid verdict stands, and the
     * retry of the consumed-without-result record degrades to the
     * retryable ConsumeIndeterminate, never a fabricated replay.
     */
    public function testCommitEvalBoundaryFailureKeepsTheOutcomeAndTheRetryIsIndeterminate(): void
    {
        $client = $this->requirePredis();
        [$record, $token] = $this->issueAndSolve($client);
        $storage = new RedisStorage($client);

        $client->throwOnEvalFrom = 2;
        $before = $this->snapshot($client);
        $outcome = $this->verifier($storage)->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertTrue($outcome->isOk(), 'a best-effort commit failure must not change the outcome');
        self::assertSame($before['evals'] + 2, $client->evalCount, 'the consume and the commit were each attempted once');
        $client->throwOnEvalFrom = \PHP_INT_MAX;
        $state = $storage->consumedState($record->nonce);
        self::assertNotNull($state, 'the consume transition landed');
        self::assertNull($state?->consumedResult, 'the failed commit never landed a stored result');

        $retry = $this->verifier($storage)->verify($token, Vectors::SECRET, 'login', '198.51.100.77');
        self::assertSame(VerifyError::ConsumeIndeterminate, $retry->error, 'the retry of a consumed record without a stored result is indeterminate');
    }

    /**
     * The WAIT boundary after the transition landed: the consume EVAL
     * mutated the store, then the WAIT command itself throws. The
     * fail-closed ConsumeIndeterminate answers, the record is
     * consumed without a result (the honest state: the write
     * happened, its durability is unconfirmed), and no outcome was
     * committed.
     */
    public function testWaitBoundaryFailureAfterTheLandedTransitionIsIndeterminate(): void
    {
        $client = $this->requirePredis();
        [$record, $token] = $this->issueAndSolve($client);
        $barriered = new RedisStorage($client, waitReplicas: 1, waitTimeoutMs: 100);

        $client->throwOnWait = true;
        $before = $this->snapshot($client);
        $outcome = $this->verifier($barriered)->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertSame(VerifyError::ConsumeIndeterminate, $outcome->error, 'a failed barrier maps onto the typed indeterminate outcome');
        self::assertSame($before['waits'] + 1, $this->waitCount($client), 'exactly one WAIT was issued, on the landed transition');
        $state = $barriered->consumedState($record->nonce);
        self::assertNotNull($state, 'the transition landed before the WAIT failure');
        self::assertNull($state?->consumedResult, 'the failure after the marker must not fabricate a committed outcome');
    }

    /**
     * The WAIT boundary at the commit: the consume barrier is
     * satisfied, the commit write lands, and the commit barrier
     * shortfalls. The outcome stands, the stored result landed, and
     * the replay resolves it behind the failed-barrier replay guard
     * and the identity gate only.
     */
    public function testCommitWaitShortfallKeepsTheOutcomeAndGatesTheLandedResult(): void
    {
        $client = $this->requirePredis();
        [$record, $token] = $this->issueAndSolve($client);
        $identity = 'op-'.hash('sha256', 'commit-wait-shortfall');
        $barriered = new RedisStorage($client, waitReplicas: 1, waitTimeoutMs: 100);

        $client->waitAckQueue = [1];
        $client->waitAck = 0;
        $before = $this->snapshot($client);
        $outcome = $this->verifier($barriered)->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs + 1_000_000,
            operationIdentity: $identity,
        );

        self::assertTrue($outcome->isOk(), 'a best-effort commit failure must not change the outcome');
        self::assertSame($before['waits'] + 2, $this->waitCount($client), 'the consume and the commit barriers each ran once');
        $state = $barriered->consumedState($record->nonce);
        self::assertNotNull($state?->consumedResult, 'the commit write landed on the primary before the barrier shortfall');

        $fencedOut = $this->verifier($barriered)->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            operationIdentity: $identity,
        );
        self::assertSame(VerifyError::StorageUnavailable, $fencedOut->error, 'a shortfalling replay fence must refuse the stored success');

        $client->waitAck = 1;
        $replay = $this->verifier($barriered)->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            operationIdentity: $identity,
        );
        self::assertTrue($replay->isOk() && $replay->fromStoredResult, 'the satisfied fence replays the landed result');
        $denied = $this->verifier($barriered)->verify($token, Vectors::SECRET, 'login', '198.51.100.77');
        self::assertSame(VerifyError::AlreadyConsumed, $denied->error, 'without the identity the stored success is refused');
    }

    /**
     * The replication-fence SET boundary on the stored-success replay:
     * the fence write itself fails, and the identity-proven replay
     * degrades to the retryable StorageUnavailable with the stored
     * result retained. A satisfied fence replays it identity-gated.
     */
    public function testReplayFenceSetBoundaryFailureRefusesTheStoredSuccessClosed(): void
    {
        $client = $this->requirePredis();
        [$record, $token] = $this->issueAndSolve($client);
        $identity = 'op-'.hash('sha256', 'fence-set-boundary');
        $storage = new RedisStorage($client);
        $storage->consumeWithOperationIdentity($record->nonce, $identity);
        self::assertTrue($storage->commitResult($record->nonce, true, null), 'the committed stored success lands');

        $barriered = new RedisStorage($client, waitReplicas: 1, waitTimeoutMs: 100);
        $client->throwOnSet = true;
        $fencedOut = $this->verifier($barriered)->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            operationIdentity: $identity,
        );
        self::assertSame(VerifyError::StorageUnavailable, $fencedOut->error, 'a failed fence write refuses the stored success');
        $client->throwOnSet = false;
        self::assertNotNull($storage->consumedState($record->nonce)?->consumedResult, 'the stored result survives the fence failure');

        $client->waitAck = 1;
        $replay = $this->verifier($barriered)->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            operationIdentity: $identity,
        );
        self::assertTrue($replay->isOk() && $replay->fromStoredResult, 'the satisfied fence replays the stored success');
        $denied = $this->verifier($barriered)->verify($token, Vectors::SECRET, 'login', '198.51.100.77');
        self::assertSame(VerifyError::AlreadyConsumed, $denied->error, 'without the identity the stored success is refused');
    }

    /**
     * The promotion race inside one verification: the key is deleted
     * between the runtime-state snapshot and the consume. The consume
     * observes a missing record, the verify resolves RecordNotFound,
     * and no double state exists afterwards: the key stays absent and
     * no consumed marker was written.
     */
    public function testKeyDeletedBetweenSnapshotAndConsumeLeavesNoDoubleState(): void
    {
        $client = $this->requirePredis();
        [$record, $token] = $this->issueAndSolve($client);
        $wrapped = new FailoverHookingClient($client);
        $wrapped->deleteKeyAfterRuntimeRead = true;
        $storage = new RedisStorage($wrapped);

        $before = $this->snapshot($client);
        $outcome = $this->verifier($storage)->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertSame(VerifyError::RecordNotFound, $outcome->error, 'the consume of a vanished record is RecordNotFound');
        self::assertSame($before['gets'] + 1, $client->gets, 'the snapshot read is exactly one GET');
        self::assertSame($before['evals'] + 1, $client->evalCount, 'the consume ran once and found the record missing');
        self::assertArrayNotHasKey('kiwicaptcha:'.$record->nonce, $client->store, 'the key stays absent after the race');
        self::assertNull($storage->consumedState($record->nonce), 'no consumed marker was written by the raced consume');
        self::assertNull($storage->find($record->nonce), 'the record is not resurrected');

        $again = $this->verifier($storage)->verify($token, Vectors::SECRET, 'login', '198.51.100.77');
        self::assertSame(VerifyError::RecordNotFound, $again->error, 'the retry resolves the same deterministic verdict');
    }
}
