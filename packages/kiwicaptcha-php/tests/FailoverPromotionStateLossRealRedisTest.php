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
use KiwiCaptcha\Tests\Fixtures\RealRedisTestEnv;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Promotion-style state loss against a real Redis: the fail-closed
 * contract at the transition boundaries, verified on the live server
 * rather than on the in-memory stand-in. A real replica promotion
 * cannot be staged on a single node, so each scenario simulates the
 * observable window of one: the replica-less WAIT shortfall, a commit
 * reply lost after the write, and a committed record that vanishes.
 * One scenario deletes the key between the snapshot read and the
 * consume transition.
 *
 * Runs in the dedicated "PHP core real-Redis fault/topology" CI lane,
 * which publishes `KC_REDIS_URL` and `TEST_REDIS_URL` and sets
 * `KIWI_REQUIRE_REAL_REDIS_TESTS=1`; with the flag on, a missing or
 * unreachable Redis fails the suite instead of skipping. With the flag
 * off the suite skips like every other real-Redis suite.
 */
final class FailoverPromotionStateLossRealRedisTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    /** @return \Predis\Client|null null when Redis is unreachable */
    private function redisOrSkip(): ?\Predis\Client
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $url = RealRedisTestEnv::requireRedis('the real-Redis promotion-state-loss suite');
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis promotion-state-loss suite runs in the dedicated real-Redis CI lane');
        }
        try {
            $probe = new \Predis\Client($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
            $probe->ping();

            return $probe;
        } catch (\Throwable) {
            RealRedisTestEnv::failWhenRequired('no Redis is reachable at the configured KC_REDIS_URL/TEST_REDIS_URL', 'the real-Redis promotion-state-loss suite');
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

    /** @return array{0: RedisStorage, 1: \KiwiCaptcha\ChallengeRecord, 2: string, 3: string} */
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

        return [$storage, $record, $token, $challenge->nonce];
    }

    /**
     * The replica-less WAIT shortfall on the pending-to-consumed
     * transition: the consume landed on the primary, the WAIT
     * acknowledged zero replicas, and the verify fails closed as
     * ConsumeIndeterminate with the record consumed-without-result.
     * The identity-proven recovery then resolves deterministically:
     * the resumed derivation commits the same outcome, and every
     * later resolution replays the stored result behind the identity
     * gate only.
     */
    public function testConsumeWaitShortfallRecoversDeterministically(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        $prefix = 'promotion-loss-'.bin2hex(random_bytes(4)).'-';
        [$storage, $record, $token] = $this->issueAndSolve($client, $prefix);
        $identity = 'op-'.hash('sha256', 'promotion-consume-wait');

        $barriered = new RedisStorage($client, $prefix, waitReplicas: 1, waitTimeoutMs: 100);
        $attempt = (new Verifier($barriered, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            nowNs: $record->issuedAtNs + 1_000_000,
            operationIdentity: $identity,
        );

        self::assertFalse($attempt->isOk(), 'a replica-wait shortfall must never succeed');
        self::assertSame(VerifyError::ConsumeIndeterminate, $attempt->error, 'the failed barrier maps onto the typed indeterminate outcome');
        $state = $storage->consumedState($record->nonce);
        self::assertNotNull($state, 'the transition happened on the primary before the barrier failed');
        self::assertNull($state?->consumedResult, 'no outcome may be committed after the barrier failure');
        self::assertSame($identity, $state?->operationIdentity, 'the identity landed atomically with the transition');

        $recovery = (new Verifier($storage, now: static fn (): int => self::ISSUED_AT))->resumeConsumedOperation(
            $token,
            Vectors::SECRET,
            $identity,
            'login',
            '198.51.100.7',
        );
        self::assertTrue($recovery->isOk(), sprintf('the identity-proven recovery resolves, got %s', $recovery->code()));
        self::assertFalse($recovery->fromStoredResult, 'the recovery re-derives once');

        $recoveryAgain = (new Verifier($storage, now: static fn (): int => self::ISSUED_AT))->resumeConsumedOperation(
            $token,
            Vectors::SECRET,
            $identity,
            'login',
            '198.51.100.7',
        );
        self::assertTrue($recoveryAgain->isOk() && $recoveryAgain->fromStoredResult, 'the committed outcome replays deterministically');

        $gated = (new Verifier($storage, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            operationIdentity: $identity,
        );
        self::assertTrue($gated->isOk() && $gated->fromStoredResult, 'the identity-proven replay resolves the stored success');
        $denied = (new Verifier($storage, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
        );
        self::assertSame(VerifyError::AlreadyConsumed, $denied->error, 'without the identity the stored success is refused');
    }

    /**
     * The commit reply lost on the wire after the write landed: the
     * Lua splice ran on the server, the caller never saw the reply,
     * and the outcome still stands (the commit is best-effort). The
     * retry resolves the stored result behind the identity gate
     * only; a null or foreign identity is refused.
     */
    public function testCommitReplyDroppedAfterLandingKeepsTheOutcomeAndGatesTheReplay(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        $prefix = 'promotion-loss-'.bin2hex(random_bytes(4)).'-';
        [$storage, $record, $token] = $this->issueAndSolve($client, $prefix);
        $identity = 'op-'.hash('sha256', 'promotion-commit-reply');
        $wrapped = new FailoverHookingClient($client);
        $wrapped->throwAfterEvalFrom = 2;
        $hooked = new RedisStorage($wrapped, $prefix);

        $outcome = (new Verifier($hooked, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            nowNs: $record->issuedAtNs + 1_000_000,
            operationIdentity: $identity,
        );

        self::assertTrue($outcome->isOk(), sprintf('a lost commit reply must not change the outcome, got %s', $outcome->code()));
        self::assertSame(2, $wrapped->luaInvocationCount(), 'the commit transition ran on the server before the reply dropped');
        $state = $storage->consumedState($record->nonce);
        self::assertNotNull($state?->consumedResult, 'the commit write landed on the primary before the reply dropped');

        $wrapped->throwAfterEvalFrom = \PHP_INT_MAX;
        $replay = (new Verifier($hooked, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            operationIdentity: $identity,
        );
        self::assertTrue($replay->isOk() && $replay->fromStoredResult, 'the identity-proven retry resolves the landed stored result');
        $denied = (new Verifier($hooked, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
        );
        self::assertSame(VerifyError::AlreadyConsumed, $denied->error, 'without the identity the stored success is refused');
        $foreign = (new Verifier($hooked, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            operationIdentity: 'op-'.hash('sha256', 'another-operation'),
        );
        self::assertSame(VerifyError::AlreadyConsumed, $foreign->error, 'a foreign operation identity is refused');
    }

    /**
     * The stale-replica resurrection observable: the committed result
     * was granted once, then the record vanished from the store. The
     * identical verification of the same token resolves
     * RecordNotFound, never a replayed authorization.
     */
    public function testVanishedCommittedResultResolvesRecordNotFoundNeverAReplay(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        $prefix = 'promotion-loss-'.bin2hex(random_bytes(4)).'-';
        [$storage, $record, $token] = $this->issueAndSolve($client, $prefix);
        $identity = 'op-'.hash('sha256', 'promotion-vanished');
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        $first = $verifier->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            nowNs: $record->issuedAtNs + 1_000_000,
            operationIdentity: $identity,
        );
        self::assertTrue($first->isOk(), sprintf('the first verification must succeed, got %s', $first->code()));
        $replay = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: $identity);
        self::assertTrue($replay->isOk() && $replay->fromStoredResult, 'the retained envelope replays the committed success');

        $client->del($prefix.$record->nonce);
        $vanished = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7', operationIdentity: $identity);
        self::assertSame(VerifyError::RecordNotFound, $vanished->error, 'a vanished record resolves RecordNotFound, never a replayed authorization');
        self::assertNull($storage->consumedState($record->nonce), 'no consumed evidence remains after the vanish');
    }

    /**
     * The promotion race inside one verification: the key is deleted
     * between the runtime-state snapshot read and the consume
     * transition. The consume observes a missing record and the
     * verify resolves RecordNotFound, with no double state written.
     */
    public function testKeyDeletedBetweenSnapshotAndConsumeResolvesRecordNotFound(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        $prefix = 'promotion-loss-'.bin2hex(random_bytes(4)).'-';
        [$storage, $record, $token] = $this->issueAndSolve($client, $prefix);
        $wrapped = new FailoverHookingClient($client);
        $wrapped->deleteKeyAfterRuntimeRead = true;
        $hooked = new RedisStorage($wrapped, $prefix);

        $outcome = (new Verifier($hooked, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertSame(VerifyError::RecordNotFound, $outcome->error, 'the consume of a vanished record is RecordNotFound');
        self::assertNull($storage->find($record->nonce), 'the key stays absent after the race');
        self::assertNull($storage->consumedState($record->nonce), 'no consumed marker was written by the raced consume');

        $again = (new Verifier($hooked, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
        );
        self::assertSame(VerifyError::RecordNotFound, $again->error, 'the retry resolves the same deterministic verdict');
    }
}
