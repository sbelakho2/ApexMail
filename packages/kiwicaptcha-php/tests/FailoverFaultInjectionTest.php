<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Redis failover fault injection: the fail-closed classifications of
 * the verifier and the storage under replica-wait shortfalls, WAIT
 * command failures, connection failures on the runtime-state read and
 * on the consume transition, and a write failure on the fused
 * delete-if-pending cleanup. The RedisStorage runs against the
 * in-memory Predis stand-in whose fault knobs throw at exactly the
 * command the scenario targets.
 *
 * The primary-failure contract is also pinned: a record that vanishes
 * after a consumed state resolves deterministically as RecordNotFound,
 * and a stored-result replay requires the retained envelope (a vanished
 * envelope can never authorize).
 */
final class FailoverFaultInjectionTest extends TestCase
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

    /** @return array{0: ChallengeRecord, 1: string} */
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

    /**
     * A replica-wait shortfall on the fresh pending-to-consumed
     * transition: the transition landed on the primary, the WAIT
     * acknowledged fewer replicas than configured, and the consume must
     * fail closed with the typed indeterminate outcome, never a
     * success. The record stays consumed-without-result on the primary
     * (the honest state: the write happened, its durability is
     * unconfirmed).
     */
    public function testConsumeWaitShortfallFailsClosedAsConsumeIndeterminate(): void
    {
        $client = $this->requirePredis();
        [$record, $token] = $this->issueAndSolve($client);

        $barriered = new RedisStorage($client, waitReplicas: 1, waitTimeoutMs: 100);
        $client->waitAck = 0;
        $outcome = $this->verifier($barriered)->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertFalse($outcome->isOk(), 'a replica-wait shortfall must never succeed');
        self::assertSame(VerifyError::ConsumeIndeterminate, $outcome->error, 'the failed barrier maps onto the typed indeterminate outcome');
        $state = $barriered->consumedState($record->nonce);
        self::assertNotNull($state, 'the transition happened on the primary before the barrier failed');
        self::assertNull($state?->consumedResult, 'no outcome may be committed after the barrier failure');
    }

    /**
     * The commit-barrier shortfall after the commit write landed on the
     * primary: the Lua splice happened, only the WAIT failed. The
     * commit is best-effort, so the valid outcome stands. The landed
     * result replays only behind the failed-barrier replay guard: a
     * shortfalling fence refuses the stored success as
     * StorageUnavailable (a promotion could lose it), and a satisfied
     * fence replays it identity-gated.
     */
    public function testCommitWaitShortfallKeepsTheOutcomeAndTheLandedResultReplays(): void
    {
        $client = $this->requirePredis();
        [$record, $token] = $this->issueAndSolve($client);
        $identity = 'op-'.hash('sha256', 'commit-shortfall');

        $barriered = new RedisStorage($client, waitReplicas: 1, waitTimeoutMs: 100);
        $client->waitAckQueue = [1];
        $client->waitAck = 0;
        $outcome = $this->verifier($barriered)->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs + 1_000_000,
            operationIdentity: $identity,
        );

        self::assertTrue($outcome->isOk(), 'a best-effort commit failure must not change the outcome');
        $state = $barriered->consumedState($record->nonce);
        self::assertNotNull($state?->consumedResult, 'the commit write landed on the primary before the barrier failed');

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
     * The commit write failure itself (the eval throws before the
     * result is stored): the outcome still stands, nothing is
     * committed, and the retry of the consumed record degrades to the
     * retryable indeterminate outcome instead of replaying a success.
     */
    public function testCommitWriteFailureKeepsTheOutcomeAndTheRetryIsIndeterminate(): void
    {
        $client = $this->requirePredis();
        [$record, $token] = $this->issueAndSolve($client);

        $storage = new RedisStorage($client);
        $client->throwOnEvalFrom = 2;
        $outcome = $this->verifier($storage)->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertTrue($outcome->isOk(), 'a best-effort commit failure must not change the outcome');
        $client->throwOnEvalFrom = \PHP_INT_MAX;
        $state = $storage->consumedState($record->nonce);
        self::assertNotNull($state, 'the consume transition landed');
        self::assertNull($state?->consumedResult, 'the failed commit never landed a stored result');

        $retry = $this->verifier($storage)->verify($token, Vectors::SECRET, 'login', '198.51.100.77');
        self::assertSame(VerifyError::ConsumeIndeterminate, $retry->error, 'the retry of a consumed record without a stored result is indeterminate');
    }

    /**
     * A WAIT command failure (the command itself throws, distinct from
     * a shortfall reply): the same fail-closed classification, and the
     * record is never treated as consumed-without-evidence when the
     * failure precedes the transition.
     */
    public function testWaitCommandFailureMidConsumeAfterTheTransitionIsIndeterminate(): void
    {
        $client = $this->requirePredis();
        [$record, $token] = $this->issueAndSolve($client);

        $barriered = new RedisStorage($client, waitReplicas: 1, waitTimeoutMs: 100);
        $client->throwOnWait = true;
        $outcome = $this->verifier($barriered)->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertFalse($outcome->isOk(), 'a WAIT command failure must never succeed');
        self::assertSame(VerifyError::ConsumeIndeterminate, $outcome->error);
        $state = $barriered->consumedState($record->nonce);
        self::assertNotNull($state, 'the transition landed before the WAIT failure');
        self::assertNull($state?->consumedResult, 'the failure after the marker must not fabricate a committed outcome');
    }

    /**
     * A connection failure on the runtime-state read: the record was
     * never touched, so the challenge is presumed intact, the outcome
     * is the retryable StorageUnavailable, and the record stays pending.
     */
    public function testRuntimeStateReadConnectionFailureIsStorageUnavailable(): void
    {
        $client = $this->requirePredis();
        [$record, $token] = $this->issueAndSolve($client);

        $storage = new RedisStorage($client);
        $client->throwOnGet = true;
        $outcome = $this->verifier($storage)->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertSame(VerifyError::StorageUnavailable, $outcome->error, 'a failed read of the runtime state is StorageUnavailable');
        $client->throwOnGet = false;
        self::assertNull($storage->consumedState($record->nonce), 'the record must stay pending');
        self::assertNotNull($storage->find($record->nonce), 'the record must survive the failed read');
    }

    /**
     * A connection failure on the consume transition itself, thrown
     * before any mutation: the outcome is the ambiguous indeterminate
     * (the reply may have been lost), and the record must NOT be left
     * consumed-without-evidence. The subsequent clean verify succeeds.
     */
    public function testConsumeConnectionFailureBeforeTheTransitionLeavesTheRecordPending(): void
    {
        $client = $this->requirePredis();
        [$record, $token] = $this->issueAndSolve($client);

        $storage = new RedisStorage($client);
        $client->throwOnEval = true;
        $outcome = $this->verifier($storage)->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertFalse($outcome->isOk());
        self::assertSame(VerifyError::ConsumeIndeterminate, $outcome->error, 'a lost consume reply is the ambiguous indeterminate, never RecordNotFound');
        $client->throwOnEval = false;
        self::assertNull($storage->consumedState($record->nonce), 'the record must not be consumed without evidence');
        self::assertNotNull($storage->find($record->nonce));

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
     * A write failure on the fused delete-if-pending cleanup: the
     * cheap-failure verdict stands only when the fused transition
     * resolves; a failed cleanup cannot establish the consumed marker,
     * so the fail-closed retryable StorageUnavailable answers and the
     * record is never deleted.
     */
    public function testDeleteIfPendingWriteFailureFailsClosedAsStorageUnavailable(): void
    {
        $client = $this->requirePredis();
        [$record] = $this->issueAndSolve($client);
        $wrongScopeToken = SolutionToken::create($record->nonce, 1, 5000, [])->encode();

        $storage = new RedisStorage($client);
        $client->throwOnEval = true;
        $outcome = $this->verifier($storage)->verify($wrongScopeToken, Vectors::SECRET, 'admin', '198.51.100.77');

        self::assertSame(VerifyError::StorageUnavailable, $outcome->error, 'a failed fused cleanup is the retryable StorageUnavailable');
        $client->throwOnEval = false;
        self::assertNull($storage->consumedState($record->nonce), 'the record must not be consumed');
        self::assertNotNull($storage->find($record->nonce), 'the record must not be deleted by the failed cleanup');
    }

    /**
     * The primary-failure contract: a stored-result replay requires the
     * retained envelope. With the envelope present the same-operation
     * identity replays the committed success; once the record vanishes
     * from the store, the same replay resolves deterministically as
     * RecordNotFound, never a resurrected authorization.
     */
    public function testStoredResultReplayRequiresTheRetainedEnvelope(): void
    {
        $client = $this->requirePredis();
        [$record, $token] = $this->issueAndSolve($client);
        $identity = 'op-'.hash('sha256', 'vanished-envelope');
        $storage = new RedisStorage($client);

        $first = $this->verifier($storage)->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            nowNs: $record->issuedAtNs + 1_000_000,
            operationIdentity: $identity,
        );
        self::assertTrue($first->isOk(), sprintf('the first verify must succeed, got %s', $first->code()));

        $replay = $this->verifier($storage)->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            operationIdentity: $identity,
        );
        self::assertTrue($replay->isOk() && $replay->fromStoredResult, 'the retained envelope replays the committed success');

        unset($client->store['kiwicaptcha:'.$record->nonce]);
        $vanished = $this->verifier($storage)->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
            operationIdentity: $identity,
        );
        self::assertSame(VerifyError::RecordNotFound, $vanished->error, 'a vanished envelope can never authorize');
    }

    /**
     * The primary-failure contract for a genuinely missing key: the
     * verifier answers RecordNotFound, never a storage failure and
     * never a success.
     */
    public function testGenuinelyMissingKeyResolvesRecordNotFound(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $token = SolutionToken::create(base64_encode(random_bytes(32)), 5, 5000, [])->encode();

        $outcome = $this->verifier($storage)->verify($token, Vectors::SECRET, 'login', '198.51.100.77');

        self::assertSame(VerifyError::RecordNotFound, $outcome->error);
    }
}
