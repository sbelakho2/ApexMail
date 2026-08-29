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
use KiwiCaptcha\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Round-95 single-read audit fix: a verification against a
 * runtime-state capable storage (RedisStorage over the counting
 * Predis fake) performs exactly one GET of the record key. The
 * runtimeState() snapshot doubles as the peek, the terminal-state
 * gate and the consumed-envelope source. The old flow read the same
 * key twice with find() plus runtimeState(), and a third time with
 * consumedState() on the consumed branch.
 */
final class VerifierSingleSnapshotReadTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    private const CLIENT_IP = '198.51.100.7';

    /**
     * Issue a protocol-v2 SHA-256 challenge through RedisStorage on
     * the fake client, solve it, and return the storage, the record
     * and the solution token.
     *
     * @return array{0: RedisStorage, 1: \KiwiCaptcha\ChallengeRecord, 2: string}
     */
    private function issueAndSolve(FakePredisClient $client, string $prefix): array
    {
        $storage = new RedisStorage($client, $prefix);
        $issuer = new Issuer(
            new Config(
                secretKey: Vectors::SECRET,
                algorithm: PoWAlgorithm::Sha256,
                mKib: 0,
                t: 1,
                p: 1,
                targetBits: 8,
                argon2TargetBits: 8,
                ttlSecs: 120,
                minDurationMs: 0,
            ),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $issuer->issue('login', self::CLIENT_IP);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        return [$storage, $record, SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode()];
    }

    private function verifier(RedisStorage $storage): Verifier
    {
        return new Verifier($storage, now: static fn (): int => self::ISSUED_AT);
    }

    public function testSuccessfulVerificationPerformsExactlyOneGet(): void
    {
        // (a) A successful verification costs exactly one GET of the record key:
        // the runtimeState() snapshot is the peek, and the consume and
        // commit run as Lua, never as a second read.
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $prefix = 'one-read-';
        $client = new FakePredisClient();
        [$storage, $record, $token] = $this->issueAndSolve($client, $prefix);
        $client->gets = 0;
        $client->getKeys = [];
        $client->evals = [];

        $outcome = $this->verifier($storage)->verify(
            $token,
            Vectors::SECRET,
            'login',
            self::CLIENT_IP,
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertTrue($outcome->isOk(), sprintf('expected valid, got %s', $outcome->code()));
        self::assertSame(1, $client->gets, 'a successful verification must read the record exactly once');
        self::assertSame([$prefix.$record->nonce], $client->getKeys, 'the single GET targets the record key');
        self::assertCount(2, $client->evals, 'the consume transition and the result commit are the only Lua');
    }

    public function testConsumedSameOperationReplayPerformsExactlyOneGet(): void
    {
        // (b) A consumed-record replay of the exact logical operation
        // resolves the stored success from the envelope that rode on the
        // snapshot GET: exactly one GET and no Lua at all (the old flow issued a
        // second GET via consumedState()).
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $prefix = 'replay-';
        $client = new FakePredisClient();
        [$storage, $record, $token] = $this->issueAndSolve($client, $prefix);
        $identity = 'op-'.hash('sha256', 'single-read-replay');
        $storage->consumeWithOperationIdentity($record->nonce, $identity);
        self::assertTrue($storage->commitResult($record->nonce, true, null), 'the committed stored success lands');
        $client->gets = 0;
        $client->getKeys = [];
        $client->evals = [];

        $outcome = $this->verifier($storage)->verify(
            $token,
            Vectors::SECRET,
            'login',
            self::CLIENT_IP,
            operationIdentity: $identity,
        );

        self::assertTrue($outcome->isOk(), sprintf('the identity-proven replay must resolve the stored success, got %s', $outcome->code()));
        self::assertTrue($outcome->fromStoredResult, 'the replay comes from the stored result');
        self::assertSame(1, $client->gets, 'a consumed replay must read the record exactly once');
        self::assertSame([$prefix.$record->nonce], $client->getKeys, 'the single GET targets the record key');
        self::assertSame([], $client->evals, 'the replay must resolve from the snapshot envelope with no Lua');
    }

    public function testCancelledVerificationPerformsExactlyOneGetAndNoLua(): void
    {
        // (c) A cancelled-record verification answers RecordNotFound from
        // the snapshot with exactly one GET and no admission and no Lua (the
        // admission-slot aspect is pinned by the counting-gate tests in
        // VerifierGateTest).
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $prefix = 'cancelled-';
        $client = new FakePredisClient();
        [$storage, $record, $token] = $this->issueAndSolve($client, $prefix);
        self::assertSame('cancelled-now', $storage->cancel($record->nonce)?->state);
        $client->gets = 0;
        $client->getKeys = [];
        $client->evals = [];

        $outcome = $this->verifier($storage)->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP);

        self::assertSame(VerifyError::RecordNotFound, $outcome->error, 'a cancelled challenge fails closed as RecordNotFound');
        self::assertSame(1, $client->gets, 'a cancelled-record verification must read the record exactly once');
        self::assertSame([$prefix.$record->nonce], $client->getKeys, 'the single GET targets the record key');
        self::assertSame([], $client->evals, 'the cancelled verdict must be answered with no Lua');
    }
}
