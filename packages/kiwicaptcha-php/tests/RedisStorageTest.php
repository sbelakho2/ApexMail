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
            bindingTag: 'abc123',
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
            bindingTag: $record->ipHash(),
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
        // Audit #48: the TTL must be fused into the SET command (SET key val
        // EX ttl) — a separate EXPIRE round trip is not atomic and must
        // never be issued.
        $expireCalls = array_values(array_filter($client->calls, fn ($c) => $c[0] === 'EXPIRE'));
        self::assertSame([], $expireCalls, 'store must set the TTL in the SET command, never a separate EXPIRE');
    }

    public function testStoreTtlIncludesTheMargin(): void
    {
        // Audit #22/#23: ttlMarginSecs extends the record's retention beyond
        // token validity — TTL = expires_at - now + margin. The margin must
        // exceed max clock skew + failover margin so a replayed token can
        // never land on an already-expired state that re-accepted it.
        $client = $this->requirePredis();
        $storage = new RedisStorage($client, ttlMarginSecs: 30);
        $record = $this->makeRecord();
        $record = new ChallengeRecord(
            nonce: $record->nonce,
            scope: $record->scope,
            bindingTag: $record->ipHash(),
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

        self::assertSame(90, $client->expirations['kiwicaptcha:redis-nonce-1'], 'TTL must be expires_at - now + ttlMarginSecs');
    }

    public function testStoreIssuesWaitWhenConfigured(): void
    {
        // Audit #22/#23: with waitReplicas > 0 the record must be
        // acknowledged by replicas (WAIT) before the challenge is handed to
        // the client. A replica-less server reports 0 acknowledged replicas
        // WITHOUT erroring — the assertion is that WAIT was issued with the
        // configured numreplicas/timeout and returned >= 0.
        $client = $this->requirePredis();
        $storage = new RedisStorage($client, waitReplicas: 2, waitTimeoutMs: 100);
        $storage->store($this->makeRecord());

        $waits = array_values(array_filter($client->calls, fn ($c) => $c[0] === 'WAIT'));
        self::assertNotEmpty($waits, 'store must issue WAIT after SET when waitReplicas > 0');
        self::assertSame([2, 100], $waits[0][1], 'WAIT must carry the configured numreplicas and timeout');
    }

    public function testStoreSkipsWaitWhenDisabled(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $storage->store($this->makeRecord());

        $waits = array_values(array_filter($client->calls, fn ($c) => $c[0] === 'WAIT'));
        self::assertSame([], $waits, 'WAIT must not be issued when waitReplicas is 0');
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
        // so a PHP-written record is complete for a Rust reader. Protocol v2
        // emits binding_tag ONLY — never the legacy ip_hash key alongside it:
        // the Rust reader uses #[serde(alias = "ip_hash")] and serde rejects a
        // struct carrying both the field and its alias as a duplicate field,
        // making a dual-key record unreadable by Rust (caught by the live
        // cross-language round trip). Round 9 adds policy_version and
        // request_binding (audits #42/#41) — 20 keys total.
        self::assertSame([
            'nonce', 'scope', 'binding_tag', 'issued_at', 'expires_at',
            'algorithm', 'm_kib', 't', 'p', 'target_bits', 'salt', 'prefix',
            'challenge', 'min_duration_ms', 'issued_at_ns', 'protocol_version',
            'attempts_used', 'region', 'policy_version', 'request_binding',
        ], array_keys($data));
        self::assertSame('redis-nonce-1', $data['nonce']);
        self::assertSame('sha256', $data['algorithm']);
        self::assertSame(0, $data['attempts_used']);
        self::assertSame(123_456_789, $data['issued_at_ns']);
        self::assertSame('abc123', $data['binding_tag']);
        self::assertArrayNotHasKey('ip_hash', $data, 'legacy ip_hash key must NOT be emitted alongside binding_tag');
        self::assertSame(2, $data['protocol_version']);
        self::assertArrayHasKey('region', $data, 'region is part of the 20-key cross-language schema');
        self::assertNull($data['region'], 'an unbound record carries region: null (byte parity with Rust serde)');
        self::assertArrayHasKey('policy_version', $data, 'policy_version is part of the 20-key cross-language schema (audit #42)');
        self::assertSame(1, $data['policy_version'], 'the default security-policy epoch is 1');
        self::assertArrayHasKey('request_binding', $data, 'request_binding is part of the 20-key cross-language schema (audit #41)');
        self::assertNull($data['request_binding'], 'an unbound record carries request_binding: null (byte parity with Rust serde)');
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

    public function testRealRedisStoreFindConsumeWithWaitReturnsNonNegative(): void
    {
        // Audit #22/#23 against a REAL Redis: store() with waitReplicas > 0
        // issues WAIT and a replica-less server reports 0 acknowledged
        // replicas (>= 0, no error). Skipped when the local test Redis
        // (127.0.0.1:6399, no password) is unreachable.
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        try {
            $client = new \Predis\Client('tcp://127.0.0.1:6399', [
                'timeout' => 1.0,
                'read_write_timeout' => 1.0,
            ]);
            $client->ping();
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at 127.0.0.1:6399 — start one for the real-Redis tests');
        }
        $nonce = base64_encode(random_bytes(32));
        $record = $this->makeRecord($nonce);
        $storage = new RedisStorage($client, waitReplicas: 1, waitTimeoutMs: 100, ttlMarginSecs: 5);
        try {
            $storage->store($record);

            $stored = $storage->find($nonce);
            self::assertNotNull($stored);
            self::assertSame($nonce, $stored->nonce);
            self::assertGreaterThanOrEqual(0, $client->executeRaw(['WAIT', 1, 100]), 'WAIT must return the acknowledged-replica count (>= 0)');

            $consumed = $storage->consume($nonce);
            self::assertNotNull($consumed);
            self::assertSame($nonce, $consumed->nonce);
            self::assertNull($storage->consume($nonce), 'GETDEL must make the record single-use');
        } finally {
            $client->del('kiwicaptcha:'.$nonce);
        }
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
            now: static fn (): int => Vectors::NOW,
        );
        $verifier = new Verifier($storage, now: static fn (): int => Vectors::NOW);

        $challenge = $issuer->issue('login', '198.51.100.77');

        // A WRONG counter must be PROVABLY wrong: at 8 bits a random counter
        // coincidentally meets the target with p=1/256 (a flake seen in CI).
        // Search upward until the hash provably misses the target.
        $wrongCounter = 1;
        $saltBytes = base64_decode($challenge->salt, true);
        while (Verifier::leadingZeroBits(hash('sha256', $challenge->prefix.$wrongCounter.$saltBytes, true)) >= $challenge->targetBits) {
            ++$wrongCounter;
        }
        $wrong = \KiwiCaptcha\SolutionToken::create($challenge->nonce, $wrongCounter, 5000, [])->encode();
        $outcome = $verifier->verify($wrong, Vectors::SECRET, 'login', '198.51.100.77');
        self::assertSame(VerifyError::InsufficientWork, $outcome->error);

        $counter = 0;
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
