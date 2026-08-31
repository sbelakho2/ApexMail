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
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Redis primary-failure semantics against a real Redis: the observable
 * failover contract of the one-shot state. A stale-replica resurrection
 * cannot be reproduced locally, so the tests pin the deterministic
 * contract instead. A record that is genuinely absent after a consumed
 * state resolves as RecordNotFound. A stored-result replay requires
 * the retained envelope (a vanished envelope can never authorize). A
 * replica-wait shortfall on the consume fails closed as the typed
 * indeterminate outcome, and the stored-success replay behind a
 * shortfalling fence is refused as StorageUnavailable.
 *
 * Runs when `KC_REDIS_URL` or `TEST_REDIS_URL` is set (the shared
 * real-Redis env of the monorepo CI); skips otherwise, like every other
 * real-Redis suite.
 */
final class FailoverPrimaryFailureRealRedisTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    /** @return \Predis\Client|null null when Redis is unreachable */
    private function redisOrSkip(): ?\Predis\Client
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $url = getenv('KC_REDIS_URL');
        if (!\is_string($url) || $url === '') {
            $url = getenv('TEST_REDIS_URL');
        }
        if (!\is_string($url) || $url === '') {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis primary-failure suite runs in the CI Redis-service job');
        }
        try {
            $probe = new \Predis\Client($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
            $probe->ping();

            return $probe;
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at the configured KC_REDIS_URL/TEST_REDIS_URL');
        }
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

    /** @return array{0: RedisStorage, 1: ChallengeRecord, 2: string} */
    private function issueAndSolve(\Predis\Client $client, string $prefix): array
    {
        $storage = new RedisStorage($client, $prefix);
        $challenge = (new Issuer($this->makeConfig(), $storage, now: static fn (): int => self::ISSUED_AT))->issue('login', '198.51.100.7');
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $record->targetBits);
        --$counter;
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();

        return [$storage, $record, $token];
    }

    /**
     * The observable primary-failure contract: after a successful
     * consume and commit, a genuinely absent record (the primary lost
     * the key) resolves deterministically as RecordNotFound, never as a
     * storage failure and never as a resurrected authorization.
     */
    public function testMissingRecordAfterConsumedStateResolvesRecordNotFound(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        $prefix = 'fault-inject-'.bin2hex(random_bytes(4)).'-';
        [$storage, $record, $token] = $this->issueAndSolve($client, $prefix);
        $identity = 'op-'.hash('sha256', 'primary-failure-missing');
        $storage->consumeWithOperationIdentity($record->nonce, $identity);
        self::assertTrue($storage->commitResult($record->nonce, true, null), 'the committed stored success lands');
        $client->del($prefix.$record->nonce);

        $outcome = (new Verifier($storage, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            operationIdentity: $identity,
        );

        self::assertSame(VerifyError::RecordNotFound, $outcome->error, 'a genuinely absent record is RecordNotFound, never a replayed success');
    }

    /**
     * The vanished-envelope contract: the same-operation replay of the
     * committed success requires the retained envelope. While the
     * envelope exists the identity-gated replay resolves the stored
     * success; once the record vanishes, the identical replay resolves
     * as RecordNotFound and can never authorize.
     */
    public function testVanishedEnvelopeCannotAuthorizeAStoredResultReplay(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        $prefix = 'fault-inject-'.bin2hex(random_bytes(4)).'-';
        [$storage, $record, $token] = $this->issueAndSolve($client, $prefix);
        $identity = 'op-'.hash('sha256', 'primary-failure-vanished');
        $storage->consumeWithOperationIdentity($record->nonce, $identity);
        self::assertTrue($storage->commitResult($record->nonce, true, 'txn-'.$identity), 'the committed stored success lands');

        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
        $replay = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: $identity);
        self::assertTrue($replay->isOk() && $replay->fromStoredResult, 'the retained envelope replays the committed success');

        $client->del($prefix.$record->nonce);
        $vanished = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: $identity);
        self::assertSame(VerifyError::RecordNotFound, $vanished->error, 'a vanished envelope can never authorize');
    }

    /**
     * The replica-wait shortfall on a real replica-less server: the
     * pending-to-consumed transition lands, the WAIT acknowledges zero
     * replicas, and the verify fails closed with the typed
     * indeterminate outcome, never a success. The record stays
     * consumed-without-result on the primary.
     */
    public function testConsumeWaitShortfallOnRealRedisFailsClosed(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        $prefix = 'fault-inject-'.bin2hex(random_bytes(4)).'-';
        [$storage, $record, $token] = $this->issueAndSolve($client, $prefix);
        $barriered = new RedisStorage($client, $prefix, waitReplicas: 1, waitTimeoutMs: 100);

        $outcome = (new Verifier($barriered, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertFalse($outcome->isOk(), 'a replica-wait shortfall must never succeed');
        self::assertSame(VerifyError::ConsumeIndeterminate, $outcome->error, 'the failed barrier maps onto the typed indeterminate outcome');
        $state = $barriered->consumedState($record->nonce);
        self::assertNotNull($state, 'the transition happened on the primary before the barrier failed');
        self::assertNull($state?->consumedResult, 'no outcome may be committed after the barrier failure');
    }

    /**
     * The failed-barrier replay guard on a real replica-less server: a
     * stored success that the fence cannot prove durable is refused as
     * StorageUnavailable, never a Valid a promotion could lose. The
     * wait-free storage replays the same stored success.
     */
    public function testReplayFenceShortfallOnRealRedisIsStorageUnavailable(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        $prefix = 'fault-inject-'.bin2hex(random_bytes(4)).'-';
        [$storage, $record, $token] = $this->issueAndSolve($client, $prefix);
        $identity = 'op-'.hash('sha256', 'primary-failure-fence');
        $storage->consumeWithOperationIdentity($record->nonce, $identity);
        self::assertTrue($storage->commitResult($record->nonce, true, null), 'the committed stored success lands');

        $barriered = new RedisStorage($client, $prefix, waitReplicas: 1, waitTimeoutMs: 100);
        $fencedOut = (new Verifier($barriered, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            operationIdentity: $identity,
        );
        self::assertSame(VerifyError::StorageUnavailable, $fencedOut->error, 'a shortfalling replay fence refuses the stored success');

        $replay = (new Verifier($storage, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            operationIdentity: $identity,
        );
        self::assertTrue($replay->isOk() && $replay->fromStoredResult, 'the wait-free storage replays the stored success');
    }
}
