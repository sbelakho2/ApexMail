<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\AtomicStorageInterface;
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

    public function testStoreWritesLanguageNeutralJson(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);

        $storage->store($this->makeRecord());

        $raw = $client->store['kiwicaptcha:redis-nonce-1'];
        self::assertNotSame('a:', substr((string) $raw, 0, 2), 'records must NOT be PHP-serialized');

        $data = json_decode((string) $raw, true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($data);
        // The JSON keys are the shared language-neutral schema — identical to
        // the Rust serde keys, including attempts_used (Rust: #[serde(default)])
        // so a PHP-written record is complete for a Rust reader.
        self::assertSame([
            'nonce', 'scope', 'ip_hash', 'issued_at', 'expires_at', 'algorithm',
            'm_kib', 't', 'p', 'target_bits', 'salt', 'prefix', 'challenge',
            'min_duration_ms', 'issued_at_ns', 'attempts_used',
        ], array_keys($data));
        self::assertSame('redis-nonce-1', $data['nonce']);
        self::assertSame('sha256', $data['algorithm']);
        self::assertSame(0, $data['attempts_used']);
        self::assertSame(123_456_789, $data['issued_at_ns']);
    }

    public function testReadsRecordsWrittenWithoutAttemptsUsed(): void
    {
        // A Rust-written record may omit attempts_used (serde default) — the
        // PHP reader must accept it and default to 0.
        $client = $this->requirePredis();
        $data = $this->makeRecord('rust-rec')->toArray();
        unset($data['attempts_used']);
        $client->store['kiwicaptcha:rust-rec'] = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        $record = (new RedisStorage($client))->find('rust-rec');

        self::assertNotNull($record);
        self::assertSame('rust-rec', $record->nonce);
    }

    public function testRedisStorageImplementsAtomicStorageInterface(): void
    {
        $storage = new RedisStorage($this->requirePredis());

        self::assertInstanceOf(AtomicStorageInterface::class, $storage);
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
        $client->store['kiwicaptcha:corrupt'] = '{not valid json!!';
        $storage = new RedisStorage($client);

        self::assertNull($storage->find('corrupt'));
        self::assertNull($storage->consume('corrupt'));
        self::assertNull($storage->find('corrupt'));
    }

    public function testLegacySerializedValueIsHandledGracefully(): void
    {
        // Records written by PHP builds before the JSON interchange change:
        // serialize() output is not JSON, so it must decode to null (the
        // challenge is treated as missing) rather than crashing the verify
        // path.
        $client = $this->requirePredis();
        $client->store['kiwicaptcha:legacy'] = serialize(['nonce' => 'legacy']);
        $storage = new RedisStorage($client);

        self::assertNull($storage->find('legacy'));
    }

    public function testOneShotVerifyRemovesRecordEvenWithWrongCounter(): void
    {
        // One-shot model: the record is consumed BEFORE the proof is checked.
        // A wrong counter burns the challenge (InsufficientWork), and the
        // subsequent correct token finds no record.
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

        $wrong = \KiwiCaptcha\SolutionToken::create($challenge->nonce, 1, 5000, [])->encode();
        $outcome = $verifier->verify($wrong, Vectors::SECRET, 'login', '198.51.100.77');
        self::assertSame(VerifyError::InsufficientWork, $outcome->error);

        $counter = 0;
        $saltBytes = base64_decode($challenge->salt, true);
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        $good = \KiwiCaptcha\SolutionToken::create($challenge->nonce, $counter, 5000, ['wd' => false])->encode();
        $second = $verifier->verify($good, Vectors::SECRET, 'login', '198.51.100.77');
        self::assertSame(VerifyError::RecordNotFound, $second->error, 'wrong-counter verify must have consumed the record');
    }
}
