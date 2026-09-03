<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Config;
use KiwiCaptcha\ExecutionChallengeGenerator;
use KiwiCaptcha\TestSupport\ExecutionTraceFixture;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\VerificationAdmissionGate;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Real-Redis regression for the terminal-state admission fix:
 * a cancelled or already-consumed Argon record resolves through the
 * pre-admission runtime-state read (the Rust mirror's runtime-state
 * resolution). The scarce admission slot is never acquired, and the
 * consume transition never reveals the terminal state.
 *
 * Runs when `KC_REDIS_URL` or `TEST_REDIS_URL` is set (the shared
 * real-Redis env of the monorepo CI); skips otherwise, like every other
 * real-Redis suite.
 */
final class VerifierTerminalStateRealRedisTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    private const EXECUTION_KEY = '0123456789abcdef0123456789abcdef';

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
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis terminal-state suite runs in the CI Redis-service job');
        }
        try {
            $probe = new \Predis\Client($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
            $probe->ping();

            return $probe;
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at the configured KC_REDIS_URL/TEST_REDIS_URL');
        }
    }

    /** @return array{0: RedisStorage, 1: \KiwiCaptcha\ChallengeRecord, 2: string} */
    private function issueAndSolveArgon(\Predis\Client $client): array
    {
        $storage = new RedisStorage($client, 'terminal-state-'.bin2hex(random_bytes(4)).'-');
        $issuer = new Issuer(
            new Config(
                secretKey: Vectors::SECRET,
                algorithm: PoWAlgorithm::Argon2id,
                mKib: 64,
                t: 3,
                p: 1,
                argon2TargetBits: 4,
                ttlSecs: 120,
                minDurationMs: 0,
            ),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $issuer->issue('login', '198.51.100.7');
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = sodium_crypto_pwhash(32, $challenge->prefix.$counter, $saltBytes, $record->t, $record->mKib * 1024, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $record->targetBits);
        --$counter;
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();

        return [$storage, $record, $token];
    }

    /**
     * An admission gate that counts every acquire and release and
     * tracks the live permits, so the verifier's gate interaction is
     * observable.
     *
     * @param array{acquires?: int, releases?: int, live?: int} $counters
     */
    private function countingGate(int $capacity, array &$counters): VerificationAdmissionGate
    {
        return new class($capacity, $counters) implements VerificationAdmissionGate {
            private int $capacity;

            private array $counters;

            public function __construct(int $capacity, array &$counters)
            {
                $this->capacity = $capacity;
                $this->counters = &$counters;
            }

            public function acquire(): ?string
            {
                $this->counters['acquires']++;
                if ($this->counters['live'] >= $this->capacity) {
                    return null;
                }
                $this->counters['live']++;

                return 'lease-'.$this->counters['acquires'];
            }

            public function release(string $lease): void
            {
                $this->counters['releases']++;
                $this->counters['live']--;
            }
        };
    }

    public function testCancelledArgonRecordOnRealRedisNeverAcquiresAdmission(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        [$storage, $record, $token] = $this->issueAndSolveArgon($client);
        self::assertSame('cancelled-now', $storage->cancel($record->nonce)?->state);

        $counters = ['acquires' => 0, 'releases' => 0, 'live' => 0];
        $gate = $this->countingGate(1, $counters);
        $outcome = (new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
        );

        self::assertSame(VerifyError::RecordNotFound, $outcome->error, 'a cancelled challenge fails closed as RecordNotFound');
        self::assertSame(0, $counters['acquires'], 'a cancelled record must NEVER acquire an Argon admission slot');
        self::assertSame(0, $counters['releases']);
        self::assertSame(0, $counters['live']);
    }

    public function testCancelledArgonRecordOnRealRedisWithBadSignatureKeepsTheCheapVerdict(): void
    {
        // The malformed-signature token on a cancelled record keeps its
        // cheap-phase verdict (BadSignature): the terminal-state
        // pre-check runs only after the cheap phase, and no admission
        // slot is acquired either way.
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        [$storage, $record, $token] = $this->issueAndSolveArgon($client);
        self::assertSame('cancelled-now', $storage->cancel($record->nonce)?->state);

        $counters = ['acquires' => 0, 'releases' => 0, 'live' => 0];
        $gate = $this->countingGate(1, $counters);
        $outcome = (new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            str_rot13(Vectors::SECRET),
            'login',
            '198.51.100.7',
        );

        self::assertSame(VerifyError::BadSignature, $outcome->error, 'the cheap-phase verdict stands on a cancelled record');
        self::assertSame(0, $counters['acquires']);
        self::assertSame(0, $counters['releases']);
        self::assertSame(0, $counters['live']);
    }

    public function testConsumedArgonRecordOnRealRedisReplayDoesNotAcquireAdmission(): void
    {
        // The same-operation identity replay of an already-consumed
        // Argon record: the pre-admission terminal-state check resolves
        // the stored success without a second derivation and without
        // acquiring an Argon slot.
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        [$storage, $record, $token] = $this->issueAndSolveArgon($client);
        $identity = 'op-'.hash('sha256', 'real-redis-replay');
        $storage->consumeWithOperationIdentity($record->nonce, $identity);
        self::assertTrue($storage->commitResult($record->nonce, true, null), 'the committed stored success lands');

        $counters = ['acquires' => 0, 'releases' => 0, 'live' => 0];
        $gate = $this->countingGate(1, $counters);
        $outcome = (new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            operationIdentity: $identity,
        );

        self::assertTrue($outcome->isOk(), sprintf('the identity-proven replay must resolve the stored success, got %s', $outcome->code()));
        self::assertTrue($outcome->fromStoredResult, 'the replay comes from the stored result, never a second derivation');
        self::assertSame(0, $counters['acquires'], 'a consumed record must never acquire an Argon admission slot');
        self::assertSame(0, $counters['releases']);
        self::assertSame(0, $counters['live']);
    }

    public function testConsumedArgonRecordOnRealRedisWithWrongIdentityDoesNotAcquireAdmission(): void
    {
        // A different operation's identity on a consumed Argon record
        // resolves to AlreadyConsumed without acquiring an Argon slot.
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        [$storage, $record, $token] = $this->issueAndSolveArgon($client);
        $storage->consumeWithOperationIdentity($record->nonce, 'op-'.hash('sha256', 'real-redis-replay'));
        self::assertTrue($storage->commitResult($record->nonce, true, null), 'the committed stored success lands');

        $counters = ['acquires' => 0, 'releases' => 0, 'live' => 0];
        $gate = $this->countingGate(1, $counters);
        $outcome = (new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            operationIdentity: 'op-'.hash('sha256', 'other-operation'),
        );

        self::assertSame(VerifyError::AlreadyConsumed, $outcome->error, 'a different operation is AlreadyConsumed');
        self::assertSame(0, $counters['acquires'], 'a consumed record must never acquire an Argon admission slot');
        self::assertSame(0, $counters['releases']);
        self::assertSame(0, $counters['live']);
    }

    public function testConsumedArgonRecordOnRealRedisWithoutCommittedResultIsIndeterminate(): void
    {
        // The replay-path counterpart of the committed-result tests: a
        // consumed record whose derivation crashed before the commit
        // carries no deterministic result, so the runtime-snapshot
        // consumed branch resolves ConsumeIndeterminate (retryable)
        // without acquiring an Argon slot and without re-deriving.
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        [$storage, $record, $token] = $this->issueAndSolveArgon($client);
        $identity = 'op-'.hash('sha256', 'real-redis-resultless');
        $storage->consumeWithOperationIdentity($record->nonce, $identity);
        self::assertNull($storage->consumedState($record->nonce)?->consumedResult, 'precondition: no committed result');

        $counters = ['acquires' => 0, 'releases' => 0, 'live' => 0];
        $gate = $this->countingGate(1, $counters);
        $outcome = (new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            operationIdentity: $identity,
        );

        self::assertSame(VerifyError::ConsumeIndeterminate, $outcome->error, 'a consumed record without a committed result is ambiguous');
        self::assertSame(0, $counters['acquires'], 'the resultless replay must never acquire an Argon admission slot');
        self::assertSame(0, $counters['releases']);
        self::assertSame(0, $counters['live']);
    }

    /**
     * Issues and solves an execution-armed protocol-v4 SHA-256
     * challenge on a fresh real-Redis storage, with the executed
     * trace and the digest over it on the wire token.
     *
     * @return array{0: RedisStorage, 1: \KiwiCaptcha\ChallengeRecord, 2: string}
     */
    private function issueAndSolveArmedSha(\Predis\Client $client): array
    {
        $storage = new RedisStorage($client, 'terminal-state-exec-'.bin2hex(random_bytes(4)).'-');
        $issuer = new Issuer(
            new Config(
                secretKey: Vectors::SECRET,
                targetBits: 8,
                ttlSecs: 120,
                minDurationMs: 0,
                executionKey: self::EXECUTION_KEY,
            ),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $issuer->issueWithExecutionField('login', '198.51.100.7', true, executionAction: 'login-action', armDecoyField: true);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        self::assertSame(4, $record->protocolVersion, 'the armed issuance writes protocol v4');

        $program = ExecutionChallengeGenerator::decode($challenge->executionProgram);
        self::assertNotNull($program);
        $trace = ExecutionTraceFixture::executedTraceFor($program);
        $digest = ExecutionChallengeGenerator::digestOverTrace($challenge->executionProgram, $challenge->nonce, $trace);
        self::assertNotNull($digest);

        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [], $digest, base64_encode($trace))->encode();

        return [$storage, $record, $token];
    }

    public function testConsumedExecutionArmedRecordOnRealRedisReplayResolvesTheStoredSuccess(): void
    {
        // The same-operation identity replay of an already-consumed
        // execution-armed record on real Redis: the pre-admission
        // terminal-state check resolves the stored success without a
        // second derivation.
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        [$storage, $record, $token] = $this->issueAndSolveArmedSha($client);
        $identity = 'op-'.hash('sha256', 'real-redis-armed-replay');
        $storage->consumeWithOperationIdentity($record->nonce, $identity);
        self::assertTrue($storage->commitResult($record->nonce, true, null), 'the committed stored success lands');

        $outcome = (new Verifier($storage, now: static fn (): int => self::ISSUED_AT))->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            operationIdentity: $identity,
        );

        self::assertTrue($outcome->isOk(), sprintf('the identity-proven armed replay must resolve the stored success, got %s', $outcome->code()));
        self::assertTrue($outcome->fromStoredResult, 'the armed replay comes from the stored result, never a second derivation');
        self::assertNotNull($storage->find($record->nonce), 'the consumed record is retained on real Redis');
    }

    public function testExpiredExecutionArmedReplayOnRealRedisResolvesTheStoredSuccess(): void
    {
        // The expired-consumed recovery on real Redis: the signed
        // expiry passes after the armed record was consumed and
        // committed, and the identity-proven retry resolves the stored
        // success through the fused atomic cleanup and the replay
        // security gate with the full execution evidence.
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        [$storage, $record, $token] = $this->issueAndSolveArmedSha($client);
        $identity = 'op-'.hash('sha256', 'real-redis-armed-expired');
        $storage->consumeWithOperationIdentity($record->nonce, $identity);
        self::assertTrue($storage->commitResult($record->nonce, true, null), 'the committed stored success lands');

        $outcome = (new Verifier($storage, now: static fn (): int => self::ISSUED_AT + 121))->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            operationIdentity: $identity,
        );

        self::assertTrue($outcome->isOk(), sprintf('the expired identity-proven armed replay must resolve the stored success on real Redis, got %s', $outcome->code()));
        self::assertTrue($outcome->fromStoredResult, 'the committed outcome is expiry-exempt');
        self::assertNotNull($storage->find($record->nonce), 'the consumed recovery evidence survives on real Redis');
    }
}
