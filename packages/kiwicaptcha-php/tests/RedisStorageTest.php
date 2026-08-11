<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * RedisStorage against an in-memory Predis stand-in (no real Redis in CI).
 *
 * Skipped when the Predis library is not installed (e.g. offline composer
 * install); the phpredis \Redis code path is exercised only if the extension
 * happens to be loaded.
 */
final class RedisStorageTest extends TestCase
{
    private function requirePredis(): FakePredisClient
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed; cannot test RedisStorage');
        }

        return new FakePredisClient();
    }

    private function makeRecord(string $nonce = 'redis-nonce-1'): ChallengeRecord
    {
        return new ChallengeRecord(
            nonce: $nonce,
            scope: 'login',
            ipHash: 'abc123',
            issuedAt: 1_800_000_000,
            expiresAt: 1_800_000_120,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 0,
            t: 1,
            p: 1,
            targetBits: 8,
            salt: 'c2FsdA==',
            prefix: 'prefix',
            challenge: 'challenge',
            minDurationMs: 0,
            issuedAtNs: 123_456_789,
        );
    }

    public function testStoreThenFindRoundTrips(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);

        $storage->store($this->makeRecord());

        $record = $storage->find('redis-nonce-1');

        self::assertNotNull($record);
        self::assertSame('redis-nonce-1', $record->nonce);
        self::assertSame('login', $record->scope);
        self::assertSame(PoWAlgorithm::Sha256, $record->algorithm);
        self::assertSame(123_456_789, $record->issuedAtNs);
    }

    public function testStoreSetsExpiration(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $record = $this->makeRecord();
        $record = new ChallengeRecord(
            nonce: $record->nonce,
            scope: $record->scope,
            ipHash: $record->ipHash,
            issuedAt: $record->issuedAt,
            expiresAt: time() + 60,
            algorithm: $record->algorithm,
            mKib: $record->mKib,
            t: $record->t,
            p: $record->p,
            targetBits: $record->targetBits,
            salt: $record->salt,
            prefix: $record->prefix,
            challenge: $record->challenge,
            minDurationMs: $record->minDurationMs,
            issuedAtNs: $record->issuedAtNs,
        );

        $storage->store($record);

        self::assertSame('kiwicaptcha:redis-nonce-1', array_key_first($client->store));
        self::assertGreaterThanOrEqual(1, $client->expirations['kiwicaptcha:redis-nonce-1']);
        $setCalls = array_values(array_filter($client->calls, fn ($c) => $c[0] === 'SET'));
        self::assertSame('EX', $setCalls[0][1][2] ?? null, 'store must set the key expiration');
    }

    public function testConsumeIsAtomicSingleUse(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $storage->store($this->makeRecord());

        // GETDEL must be used (atomic return-and-delete).
        $first = $storage->consume('redis-nonce-1');
        self::assertNotNull($first);
        self::assertSame('redis-nonce-1', $first->nonce);

        $second = $storage->consume('redis-nonce-1');
        self::assertNull($second, 'second consume must miss');
        self::assertNull($storage->find('redis-nonce-1'));
    }

    public function testConsumeUsesGetdelLuaForPredis(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $storage->store($this->makeRecord());

        $storage->consume('redis-nonce-1');

        $evals = array_values(array_filter($client->calls, fn ($c) => $c[0] === 'EVAL'));
        self::assertNotEmpty($evals, 'consume must go through eval for Predis');
        self::assertStringContainsString('GETDEL', (string) $evals[0][1][0]);
    }

    public function testConsumeOnMissingNonceReturnsNull(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);

        self::assertNull($storage->consume('never-stored'));
    }

    public function testFindDoesNotConsume(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $storage->store($this->makeRecord());

        self::assertNotNull($storage->find('redis-nonce-1'));
        self::assertNotNull($storage->find('redis-nonce-1'));
    }

    public function testDeleteRemovesRecord(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $storage->store($this->makeRecord());

        $storage->delete('redis-nonce-1');

        self::assertNull($storage->find('redis-nonce-1'));
    }

    public function testCorruptedValueIsHandledGracefully(): void
    {
        $client = $this->requirePredis();
        $client->store['kiwicaptcha:corrupt'] = 'not-php-serialize!!{';
        $storage = new RedisStorage($client);

        self::assertNull($storage->find('corrupt'));
        self::assertNull($storage->consume('corrupt'));
        self::assertNull($storage->find('corrupt'));
    }

    public function testIncrementAttemptsEnforcesCapAtomically(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        // The challenge record must exist for the counter to be created.
        $storage->store($this->makeRecord('n1'));

        self::assertTrue($storage->incrementAttempts('n1', 2));
        self::assertSame(1, $storage->attemptsUsed('n1'));
        self::assertTrue($storage->incrementAttempts('n1', 2));
        self::assertSame(2, $storage->attemptsUsed('n1'));
        // Third attempt must be rejected; the counter is left incremented
        // (the Lua script no longer DECRs on overflow).
        self::assertFalse($storage->incrementAttempts('n1', 2));
        self::assertSame(3, $storage->attemptsUsed('n1'));
    }

    public function testAttemptCounterIsPerNonce(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $storage->store($this->makeRecord('a'));
        $storage->store($this->makeRecord('b'));

        self::assertTrue($storage->incrementAttempts('a', 5));
        self::assertTrue($storage->incrementAttempts('b', 5));

        self::assertSame(1, $storage->attemptsUsed('a'));
        self::assertSame(1, $storage->attemptsUsed('b'));
    }

    public function testIncrementAttemptsOnMissingChallengeDoesNotCreateKeys(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);

        // No challenge record for 'ghost': the Lua script must return -1
        // without touching any key. The method treats that as "not blocked"
        // so the verifier proceeds to consume(), which returns null →
        // RecordNotFound (the same outcome as before, minus the key litter).
        self::assertTrue($storage->incrementAttempts('ghost', 3));
        self::assertSame(0, $storage->attemptsUsed('ghost'), 'no counter may be created for a fake nonce');
        self::assertNull($storage->consume('ghost'));

        // Assert via the fake's key set: NO keys exist for the fake nonce.
        self::assertArrayNotHasKey('kiwicaptcha:ghost', $client->store);
        self::assertArrayNotHasKey('kiwicaptcha:ghost:attempts', $client->store);
        self::assertArrayNotHasKey('kiwicaptcha:ghost:attempts', $client->expirations);

        // End-to-end: verify() with a fake nonce and maxAttempts fails with
        // RecordNotFound, not TooManyAttempts.
        $fakeToken = \KiwiCaptcha\SolutionToken::create(
            base64_encode(str_repeat('x', 32)),
            1,
            100,
            ['wd' => false],
        )->encode();
        $outcome = (new Verifier($storage))->verify($fakeToken, Vectors::SECRET, null, null, maxAttempts: 3);
        self::assertSame(VerifyError::RecordNotFound, $outcome->error);
    }

    public function testIncrementAttemptsUsesLuaWithCapAndTtl(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $storage->store($this->makeRecord('n1'));

        $storage->incrementAttempts('n1', 3);

        $evals = array_filter($client->calls, fn ($c) => $c[0] === 'EVAL');
        self::assertNotEmpty($evals);
        $eval = array_values($evals)[0][1];
        self::assertStringContainsString("redis.call('EXISTS'", (string) $eval[0]);
        self::assertStringContainsString("redis.call('INCR'", (string) $eval[0]);
        // Two KEYS: challenge key + attempt counter key.
        self::assertSame(2, (int) $eval[1]);
        self::assertSame('kiwicaptcha:n1', $eval[2]);
        self::assertSame('kiwicaptcha:n1:attempts', $eval[3]);
        self::assertSame('3', $eval[4]);
        self::assertGreaterThanOrEqual(1, $client->expirations['kiwicaptcha:n1:attempts']);
    }

    public function testFullVerifyRoundTripWithAtomicAttemptCap(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $issuer = new Issuer(
            new \KiwiCaptcha\Config(
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
        );
        $verifier = new Verifier($storage);

        $challenge = $issuer->issue('login', '198.51.100.77');
        $counter = 0;
        $saltBytes = base64_decode($challenge->salt, true);
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        $token = \KiwiCaptcha\SolutionToken::create($challenge->nonce, $counter, 5000, ['wd' => false])->encode();

        $first = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.77', maxAttempts: 1);
        self::assertTrue($first->isOk(), sprintf('first verify failed: %s', $first->code()));

        // The record is consumed by the first verify, so the second attempt
        // fails the Lua EXISTS gate (-1 = no challenge record): no counter
        // key is created for the replay, and consume() yields
        // RecordNotFound.
        $second = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.77', maxAttempts: 1);
        self::assertSame(VerifyError::RecordNotFound, $second->error);
        self::assertSame(1, $storage->attemptsUsed($challenge->nonce));
    }
}
