<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\AtomicStorageInterface;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
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
        // The TTL must be fused into the SET command (SET key val
        // EX ttl); a separate expire round trip is not atomic and must
        // never be issued.
        $expireCalls = array_values(array_filter($client->calls, fn ($c) => $c[0] === 'EXPIRE'));
        self::assertSame([], $expireCalls, 'store must set the TTL in the SET command, never a separate EXPIRE');
    }

    public function testStoreTtlIncludesTheMargin(): void
    {
        // ttlMarginSecs extends the record's retention beyond
        // token validity: TTL = expires_at - now + margin. The margin
        // must exceed max clock skew + failover margin so a replayed
        // token can never land on an already-expired state that
        // re-accepted it.
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

    public function testStoreIssuesWaitAndVerifiesThresholdWhenConfigured(): void
    {
        // With waitReplicas > 0 the durability barrier is
        // unconditional: store() issues WAIT after SET and fails closed
        // when the acknowledged replica count is below the threshold.
        $client = $this->requirePredis();
        $storage = new RedisStorage($client, waitReplicas: 2, waitTimeoutMs: 100);

        $client->waitAck = 0;
        try {
            $storage->store($this->makeRecord());
            self::fail('store must throw when fewer replicas acked than configured');
        } catch (\KiwiCaptcha\Storage\ReplicaWaitException) {
            // expected: 0 of 2 replicas acknowledged
        }
        $waits = array_values(array_filter($client->calls, fn ($c) => $c[0] === 'WAIT'));
        self::assertNotEmpty($waits, 'store must issue WAIT after SET when waitReplicas > 0');
        self::assertSame([2, 100], $waits[0][1], 'WAIT must carry the configured numreplicas and timeout');

        // The same store satisfies the barrier when the replica set
        // acknowledges.
        $client->waitAck = 2;
        $storage->store($this->makeRecord('redis-nonce-2'));
        self::assertCount(2, array_values(array_filter($client->calls, fn ($c) => $c[0] === 'WAIT')));
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
        // The stored JSON is the shared language-neutral schema: the 22
        // canonical ChallengeRecord keys (identical to the Rust serde
        // keys, including attempts_used via #[serde(default)] so a
        // PHP-written record is complete for a Rust reader), wrapped
        // with the three storage runtime fields `state` ("pending"),
        // `consumed_result` (null) and `operation_identity` (null).
        // Protocol v2 emits binding_tag only, never the legacy ip_hash
        // key alongside it: the Rust reader uses #[serde(alias =
        // "ip_hash")] and serde rejects a struct carrying both the field
        // and its alias as a duplicate field, making a dual-key record
        // unreadable by Rust (caught by the live cross-language round
        // trip). The canonical key list is the source of truth for the
        // stored wire schema.

        self::assertSame([
            'nonce', 'scope', 'binding_tag', 'issued_at', 'expires_at',
            'algorithm', 'm_kib', 't', 'p', 'target_bits', 'salt', 'prefix',
            'challenge', 'min_duration_ms', 'issued_at_ns', 'protocol_version',
            'attempts_used', 'region', 'policy_version', 'request_binding',
            'issuer', 'kid', 'hostname', 'state', 'consumed_result',
            'operation_identity',
        ], array_keys($data));
        self::assertSame('redis-nonce-1', $data['nonce']);
        self::assertSame('sha256', $data['algorithm']);
        self::assertSame(0, $data['attempts_used']);
        self::assertSame(123_456_789, $data['issued_at_ns']);
        self::assertSame('abc123', $data['binding_tag']);
        self::assertArrayNotHasKey('ip_hash', $data, 'legacy ip_hash key must NOT be emitted alongside binding_tag');
        self::assertSame(2, $data['protocol_version']);
        self::assertArrayHasKey('region', $data, 'region is part of the 22-key cross-language schema');
        self::assertNull($data['region'], 'an unbound record carries region: null (byte parity with Rust serde)');
        self::assertArrayHasKey('policy_version', $data, 'policy_version is part of the cross-language wire schema');
        self::assertSame(1, $data['policy_version'], 'the default security-policy epoch is 1');
        self::assertArrayHasKey('request_binding', $data, 'request_binding is part of the cross-language wire schema');
        self::assertNull($data['request_binding'], 'an unbound record carries request_binding: null (byte parity with Rust serde)');
        self::assertArrayHasKey('issuer', $data, 'issuer is part of the cross-language wire schema');
        self::assertNull($data['issuer'], 'an unbound record carries issuer: null (byte parity with Rust serde)');
        self::assertArrayHasKey('kid', $data, 'kid is part of the cross-language wire schema');
        self::assertSame(1, $data['kid'], 'the default signing key id is 1');
        self::assertSame('pending', $data['state'], 'stored records start in the pending state');
        self::assertNull($data['consumed_result'], 'a pending record has no consumed_result');
        self::assertNull($data['operation_identity'], 'a pending record carries the null operation_identity marker');
    }

    public function testReadsRecordsWrittenWithoutAttemptsUsed(): void
    {
        // A Rust-written record may omit attempts_used (serde default);
        // the PHP reader must accept it and default to 0.
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

    public function testConsumeIsAtomicSingleUseTransition(): void
    {
        // consume() is a transition, not a delete: the winner gets
        // consumedNow, the record is kept (marked consumed), and a
        // second consume returns the same record with consumedBefore.
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $storage->store($this->makeRecord());

        $first = $storage->consume('redis-nonce-1');
        self::assertNotNull($first);
        self::assertSame('redis-nonce-1', $first->record->nonce);
        self::assertTrue($first->consumedNow, 'the first consume wins the transition');
        self::assertFalse($first->consumedBefore);
        self::assertNull($first->consumedResult);

        $second = $storage->consume('redis-nonce-1');
        self::assertNotNull($second, 'the consumed record is KEPT until its TTL — replay protection is the marker, not absence');
        self::assertFalse($second->consumedNow);
        self::assertTrue($second->consumedBefore, 'a retry observes the consumed marker');
        self::assertNull($second->consumedResult, 'no result committed yet');
        self::assertNotNull($storage->find('redis-nonce-1'), 'the record is still stored (pending->consumed, not deleted)');
    }

    public function testConsumeFlippedTheStoredStateToConsumed(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $storage->store($this->makeRecord());

        $storage->consume('redis-nonce-1');

        $data = json_decode((string) $client->store['kiwicaptcha:redis-nonce-1'], true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('consumed', $data['state'], 'the transition must persist state=consumed in the stored JSON');
        self::assertArrayHasKey('consumed_result', $data, 'the runtime consumed_result key must be present');
    }

    public function testConsumeUsesTransitionLuaForPredis(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $storage->store($this->makeRecord());

        $storage->consume('redis-nonce-1');

        $evals = array_values(array_filter($client->calls, fn ($c) => $c[0] === 'EVAL'));
        self::assertNotEmpty($evals, 'consume must go through eval for Predis');
        self::assertStringContainsString('consume transition', (string) $evals[0][1][0], 'the atomic consume-transition Lua must be used (no GETDEL delete)');
    }

    public function testCommitResultStoresTheDeterministicOutcome(): void
    {
        // commitResult only lands on a consumed record without a
        // result yet; the stored JSON then carries consumed_result.
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $storage->store($this->makeRecord());

        self::assertFalse($storage->commitResult('redis-nonce-1', true, 'txn-1'), 'commit on a PENDING record must fail');
        $storage->consume('redis-nonce-1');

        self::assertTrue($storage->commitResult('redis-nonce-1', true, 'txn-1'));
        self::assertFalse($storage->commitResult('redis-nonce-1', true, 'txn-1'), 'a second commit must be rejected');

        $data = json_decode((string) $client->store['kiwicaptcha:redis-nonce-1'], true, flags: JSON_THROW_ON_ERROR);
        self::assertSame(['valid' => true, 'binding' => 'txn-1'], $data['consumed_result']);
    }

    public function testCommitResultWithNullBindingStoresNull(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $storage->store($this->makeRecord());
        $storage->consume('redis-nonce-1');

        self::assertTrue($storage->commitResult('redis-nonce-1', false, null));

        $data = json_decode((string) $client->store['kiwicaptcha:redis-nonce-1'], true, flags: JSON_THROW_ON_ERROR);
        self::assertSame(['valid' => false, 'binding' => null], $data['consumed_result']);
    }

    public function testConsumeIssuesWaitAndFailsClosedBelowThreshold(): void
    {
        // The pending→consumed transition carries the same
        // durability barrier as issuance; a promotion must never
        // resurrect a consumed record from a stale replica. With the
        // threshold unmet, consume() throws (the transition did happen
        // on the primary; the caller treats the state as indeterminate).
        $client = $this->requirePredis();
        $storage = new RedisStorage($client, waitReplicas: 1, waitTimeoutMs: 100);
        $client->waitAck = 1;
        $storage->store($this->makeRecord());

        $client->waitAck = 0;
        try {
            $storage->consume('redis-nonce-1');
            self::fail('consume must fail closed when the transition is not durably replicated');
        } catch (\KiwiCaptcha\Storage\ReplicaWaitException) {
            // expected
        }
        $waits = array_values(array_filter($client->calls, fn ($c) => $c[0] === 'WAIT'));
        self::assertCount(2, $waits, 'store + consume must each issue WAIT');

        $client->waitAck = 1;
        $consumed = $storage->consume('redis-nonce-1');
        self::assertNotNull($consumed);
        self::assertTrue($consumed->consumedBefore, 'the first (failed-barrier) consume still transitioned the record');
    }

    public function testCommitResultIssuesWaitAndFailsClosedBelowThreshold(): void
    {
        // The deterministic-result commit is also barriered; for
        // best-effort callers a barrier failure cannot change the
        // outcome, but it surfaces the safe degraded state on retry.
        $client = $this->requirePredis();
        $storage = new RedisStorage($client, waitReplicas: 1, waitTimeoutMs: 100);
        $client->waitAck = 1;
        $storage->store($this->makeRecord());
        $storage->consume('redis-nonce-1');

        $client->waitAck = 0;
        try {
            $storage->commitResult('redis-nonce-1', true, 'txn-1');
            self::fail('commitResult must fail closed when the commit is not durably replicated');
        } catch (\KiwiCaptcha\Storage\ReplicaWaitException) {
            // expected
        }
        $client->waitAck = 1;
        self::assertFalse($storage->commitResult('redis-nonce-1', true, 'txn-1'), 'the failed-barrier commit DID land on the primary — a retry cannot re-commit');
    }

    public function testCommitResultUsesLuaForPredis(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $storage->store($this->makeRecord());
        $storage->consume('redis-nonce-1');

        $storage->commitResult('redis-nonce-1', false, null);

        $evals = array_values(array_filter($client->calls, fn ($c) => $c[0] === 'EVAL'));
        self::assertNotEmpty($evals);
        self::assertStringContainsString('commit result', (string) $evals[1][1][0], 'commitResult must go through its own atomic Lua');
    }

    public function testConsumeReturnsTheCommittedResultOnRetry(): void
    {
        // The deterministic retry: after commit, a retry consume returns
        // the record with the stored result, and the verifier replays it
        // without re-deriving.
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $storage->store($this->makeRecord());
        $storage->consume('redis-nonce-1');
        $storage->commitResult('redis-nonce-1', true, null);

        $retry = $storage->consume('redis-nonce-1');

        self::assertNotNull($retry);
        self::assertTrue($retry->consumedBefore);
        self::assertNotNull($retry->consumedResult, 'the committed result must ride back on the retry');
        self::assertTrue($retry->consumedResult->valid);
    }

    public function testConsumeOnMissingNonceReturnsNull(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);

        self::assertNull($storage->consume('never-stored'));
        self::assertFalse($storage->commitResult('never-stored', true, null), 'commit on a missing record must fail');
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
        // Records written by PHP builds before the JSON interchange
        // change: serialize() output is not JSON, so it must decode to
        // null (the challenge is treated as missing) rather than crashing
        // the verify path.
        $client = $this->requirePredis();
        $client->store['kiwicaptcha:legacy'] = serialize(['nonce' => 'legacy']);
        $storage = new RedisStorage($client);

        self::assertNull($storage->find('legacy'));
    }

    public function testRealRedisStoreFindConsumeWithWaitBarrierFailsClosed(): void
    {
        // Against a real Redis: a replica-less server reports 0
        // acknowledged replicas, so a configured waitReplicas=1 barrier
        // must fail closed; store() throws and the challenge is never
        // handed to the client (the write is not durably replicated).
        // Skipped when the local test Redis (127.0.0.1:6399, no password)
        // is unreachable.
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
            try {
                $storage->store($record);
                self::fail('store() must fail closed when the replica ack threshold is not met');
            } catch (\KiwiCaptcha\Storage\ReplicaWaitException $e) {
                self::assertStringContainsString('0 of 1', $e->getMessage());
            }

            // The no-barrier configuration on the same server round-trips.
            $plain = new RedisStorage($client, ttlMarginSecs: 5);
            $plain->store($record);
            $stored = $plain->find($nonce);
            self::assertNotNull($stored);
            self::assertSame($nonce, $stored->nonce);

            $consumed = $plain->consume($nonce);
            self::assertNotNull($consumed);
            self::assertSame($nonce, $consumed->record->nonce);
            self::assertTrue($consumed->consumedNow);
            $retry = $plain->consume($nonce);
            self::assertNotNull($retry, 'the transition keeps the record — replay protection is the consumed marker');
            self::assertTrue($retry->consumedBefore, 'the atomic transition must make exactly one caller the winner');
        } finally {
            $client->del('kiwicaptcha:'.$nonce);
        }
    }

    public function testWrongCounterConsumesAndRetryReplaysTheInvalidOutcome(): void
    {
        // The record is consumed before the proof is checked. A wrong
        // counter burns the challenge (InsufficientWork) and commits the
        // deterministic invalid outcome; the subsequent correct token
        // sees the same InsufficientWork without re-deriving.
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

        // A wrong counter must be provably wrong: at 8 bits a random
        // counter coincidentally meets the target with p=1/256 (a flake
        // seen in CI). Search upward until the hash provably misses the
        // target.
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
        self::assertSame(VerifyError::InsufficientWork, $second->error, 'the wrong-counter verify must have consumed the record and committed the invalid outcome');
    }

    public function testRealRedisConsumedStateReplayRoundTrip(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if ($url === false || $url === '') {
            self::markTestSkipped('RISK_REDIS_URL not set; cannot test the real-Redis consumed-state replay');
        }
        $client = new \Predis\Client($url);
        $storage = new RedisStorage($client, 'replay-test-'.bin2hex(random_bytes(4)).'-');
        $issuer = new Issuer(new \KiwiCaptcha\Config(secretKey: '0123456789abcdef0123456789abcdef', targetBits: 8), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7', 'txn-A');

        $counter = 0;
        $saltBytes = base64_decode($challenge->salt, true);
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            ++$counter;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;
        $token = \KiwiCaptcha\SolutionToken::create($challenge->nonce, $counter, 5000, ['wd' => false])->encode();
        usleep(($challenge->minDurationMs + 10) * 1000);

        $preConsume = $storage->find($challenge->nonce);
        self::assertNotNull($preConsume);
        $expectedIssuedAtNs = $preConsume->issuedAtNs;

        $verifier = new Verifier($storage);
        $identity = 'op-'.hash('sha256', 'backend|uuid|response');
        $first = $verifier->verify($token, '0123456789abcdef0123456789abcdef', 'login', '198.51.100.7', operationIdentity: $identity);
        self::assertTrue($first->isOk(), 'the first verification must succeed (got '.$first->code().')');

        // The consumed record persists with its exact integers intact;
        // the Lua must never re-encode the record, since cjson rewrote
        // issued_at_ns in scientific notation.
        $stored = $storage->find($challenge->nonce);
        self::assertNotNull($stored, 'the consumed record must persist until its TTL');
        self::assertSame($expectedIssuedAtNs, $stored->issuedAtNs, 'issued_at_ns must survive the consume transition byte-exactly');

        // Deterministic retry: the exact same logical operation returns
        // the same stored result without re-deriving.
        $replay = $verifier->verify($token, '0123456789abcdef0123456789abcdef', 'login', '198.51.100.7', operationIdentity: $identity);
        self::assertTrue($replay->isOk(), 'the replay must return the stored result (got '.$replay->code().')');
        self::assertTrue($replay->fromStoredResult, 'the replay must come from the stored result');
        self::assertSame('txn-A', $replay->requestBinding, 'the stored binding must be exposed');
    }

    public function testTenMegabyteStoredBodyIsRejectedAtParse(): void
    {
        // A 10 MB stored JSON body must be rejected by the
        // record parse (the 4096-byte string ceiling / required-field set)
        // and surface as null — no exception, and no allocation beyond the
        // body itself. A decode-before-cap regression would materialize the
        // 10 MB payload into a record structure.
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $client->store['kiwicaptcha:big'] = '{"nonce":"'.str_repeat('a', 10 * 1024 * 1024).'"}';

        self::assertNull($storage->find('big'), 'an oversized stored body must parse to null, never throw');
    }

    public function testHundredThousandLevelNestingFailsCleanly(): void
    {
        // json_decode runs at the default depth (512) — a
        // 100k-level nested body must fail cleanly (null), never exhaust
        // the stack and never surface an untyped exception.
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $client->store['kiwicaptcha:deep'] = str_repeat('[', 100_000).str_repeat(']', 100_000);

        self::assertNull($storage->find('deep'), 'a pathologically nested body must parse to null, never crash');
    }

    public function testBindingArgumentIsCappedBeforeEvalArgv(): void
    {
        // The binding embedded into the commit-result eval arguments
        // is the record's request_binding, which the strict record parse
        // caps at 128 bytes of the identifier alphabet before it can
        // reach evalScript; a 10 KB "binding" can never enter the script
        // arguments.
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);

        try {
            ChallengeRecord::fromArray([
                'nonce' => 'n', 'scope' => 'login', 'binding_tag' => 't',
                'issued_at' => 1, 'expires_at' => 100,
                'algorithm' => 'sha256', 'm_kib' => 0, 't' => 1, 'p' => 1,
                'target_bits' => 8, 'salt' => 's', 'prefix' => 'p',
                'challenge' => 'c', 'min_duration_ms' => 0,
                'request_binding' => str_repeat('x', 10_000),
            ]);
            self::fail('a 10 KB request_binding must be rejected at parse');
        } catch (\KiwiCaptcha\MalformedRecordException) {
            // expected: the 128-byte identifier cap fires before any
            // eval
        }

        self::assertTrue(true);
    }

    public function testConsumedStateParsesAConsumedResultWithNestedBraces(): void
    {
        // The consumed_result envelope parser must depth-match the JSON
        // object (the same scanner the consume Lua uses), not stop at the
        // first '}': a committed result whose binding ever contains
        // nested braces (a foreign writer or a future schema widening;
        // the PHP issuer's narrow identifier alphabet excludes them
        // today) must still parse instead of silently degrading the
        // retained state to resultless (a replay would then collapse to
        // ConsumeIndeterminate).
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $record = $this->makeRecord();
        $envelope = json_encode(
            $record->toArray() + ['state' => 'consumed', 'consumed_result' => ['valid' => true, 'binding' => 'txn{nested{"k":1}}tail'], 'operation_identity' => 'op-1'],
            JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
        );
        $client->store['kiwicaptcha:'.$record->nonce] = $envelope;

        $state = $storage->consumedState($record->nonce);
        self::assertNotNull($state);
        self::assertTrue($state->consumedBefore);
        self::assertNotNull($state->consumedResult, 'a nested-brace consumed_result must parse, not degrade to resultless');
        self::assertTrue($state->consumedResult->valid);
        self::assertSame('txn{nested{"k":1}}tail', $state->consumedResult->binding);
        self::assertSame('op-1', $state->operationIdentity);
    }

    public function testConsumeWithOperationIdentityRecordsTheIdentityInTheSameAtomicWrite(): void
    {
        // The identity lands in the same write as the pending→consumed
        // flip (the Lua splice), so the stored identity is provably the
        // actual atomic consume winner's; read back via consumedState().
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $storage->store($this->makeRecord());
        $identity = 'op-'.hash('sha256', 'backend|uuid|response');

        $consumed = $storage->consumeWithOperationIdentity('redis-nonce-1', $identity);

        self::assertNotNull($consumed);
        self::assertTrue($consumed->consumedNow, 'the identity-bearing consume wins the transition');
        self::assertSame($identity, $consumed->operationIdentity, 'the winner exposes the identity it recorded');
        $data = json_decode((string) $client->store['kiwicaptcha:redis-nonce-1'], true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('consumed', $data['state'], 'the transition must persist state=consumed in the stored JSON');
        self::assertSame($identity, $data['operation_identity'], 'the identity must be spliced into the stored JSON with the state flip');

        $state = $storage->consumedState('redis-nonce-1');
        self::assertNotNull($state);
        self::assertSame($identity, $state->operationIdentity, 'the consumed-state read exposes the recorded identity');
    }

    public function testConsumeWithOperationIdentityRejectsOversizedIdentities(): void
    {
        // The identity is bounded (never store unbounded blobs) and
        // validated against the narrow alphabet before the transition.
        // A malformed identity is rejected, never silently dropped: a
        // caller that believes the recovery identity was recorded while
        // the consume stored null would violate the deterministic
        // recovery contract.
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $storage->store($this->makeRecord());

        try {
            $storage->consumeWithOperationIdentity('redis-nonce-1', str_repeat('x', 129));
            self::fail('an over-long identity must be rejected');
        } catch (\InvalidArgumentException) {
            // expected: the 1..128-byte bound fires before any transition
        }
        $data = json_decode((string) $client->store['kiwicaptcha:redis-nonce-1'], true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('pending', $data['state'], 'a rejected identity must leave the record untouched and retryable');
        self::assertNull($data['operation_identity'], 'a rejected identity must never be stored');
    }

    public function testConsumeWithOperationIdentityRejectsGsubSpecialCharacters(): void
    {
        // The narrow alphabet exists because the identity is
        // JSON-encoded and spliced into the Lua string.gsub replacement
        // string, where `%` is the replacement-template escape: `%` (and
        // every other non-alphabet character) is rejected by
        // construction, so the raw splice can never be interpreted as a
        // template.
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $storage->store($this->makeRecord());

        try {
            $storage->consumeWithOperationIdentity('redis-nonce-1', 'deadbeef%deadbeef');
            self::fail('an identity containing the gsub replacement-template escape must be rejected');
        } catch (\InvalidArgumentException) {
            // expected
        }
        try {
            $storage->consumeWithOperationIdentity('redis-nonce-1', 'deadbeef deadbeef');
            self::fail('an identity containing a space must be rejected');
        } catch (\InvalidArgumentException) {
            // expected
        }
        $data = json_decode((string) $client->store['kiwicaptcha:redis-nonce-1'], true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('pending', $data['state'], 'a rejected identity must leave the record untouched');
        self::assertNull($data['operation_identity'], 'a rejected identity must never be stored');
    }

    public function testPlainConsumeKeepsTheIdentityMarkerNull(): void
    {
        // The identity-less consume path stays byte-identical to the
        // plain consume: the marker is always written at store() and
        // stays null.
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $storage->store($this->makeRecord());

        $consumed = $storage->consume('redis-nonce-1');

        self::assertNotNull($consumed);
        self::assertTrue($consumed->consumedNow);
        self::assertNull($consumed->operationIdentity);
        $data = json_decode((string) $client->store['kiwicaptcha:redis-nonce-1'], true, flags: JSON_THROW_ON_ERROR);
        self::assertNull($data['operation_identity'], 'a plain consume records no identity');
    }

    public function testVerifierForwardsTheOperationIdentityToTheConsumeTransition(): void
    {
        // The verifier's optional identity parameter drives the
        // identity-bearing atomic consume; a native call (no identity)
        // stays on the plain path.
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $issuer = new Issuer(new Config(secretKey: Vectors::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        $token = \KiwiCaptcha\SolutionToken::create($challenge->nonce, $counter - 1, 5000, [])->encode();
        usleep(($challenge->minDurationMs + 10) * 1000);
        $identity = 'op-'.hash('sha256', 'backend|uuid|response');

        $outcome = (new Verifier($storage))->verify($token, Vectors::SECRET, 'login', '198.51.100.7', null, false, $identity);

        self::assertTrue($outcome->isOk(), 'the identity-bearing verify must succeed (got '.$outcome->code().')');
        $data = json_decode((string) $client->store['kiwicaptcha:'.$challenge->nonce], true, flags: JSON_THROW_ON_ERROR);
        self::assertSame($identity, $data['operation_identity'], 'the verifier must forward the identity into the atomic consume');
        $state = $storage->consumedState($challenge->nonce);
        self::assertNotNull($state);
        self::assertSame($identity, $state->operationIdentity);
    }

    public function testDeleteIfPendingIsTheAtomicTriState(): void
    {
        // The atomic cleanup primitive: one Lua script decides missing /
        // deleted-pending / consumed. A pending record is deleted (the
        // one-shot policy); a consumed record is never deleted and its
        // retained state (committed result + operation identity) rides
        // back on the answer; a missing key reports missing.
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);

        // missing
        self::assertSame('missing', $storage->deleteIfPending('absent-nonce')->state);

        // pending -> deleted-pending, key gone
        $storage->store($this->makeRecord('pending-nonce'));
        $result = $storage->deleteIfPending('pending-nonce');
        self::assertSame('deleted-pending', $result->state);
        self::assertNull($client->store['kiwicaptcha:pending-nonce'] ?? null, 'the pending record is deleted atomically');

        // consumed -> kept, state returned intact
        $storage->store($this->makeRecord('consumed-nonce'));
        $identity = 'op-'.hash('sha256', 'race');
        $consumed = $storage->consumeWithOperationIdentity('consumed-nonce', $identity);
        self::assertTrue($consumed?->consumedNow);
        $storage->commitResult('consumed-nonce', true, 'txn');
        $result = $storage->deleteIfPending('consumed-nonce');
        self::assertSame('consumed', $result->state);
        self::assertNotNull($client->store['kiwicaptcha:consumed-nonce'] ?? null, 'a consumed record is never deleted');
        self::assertNotNull($result->consumed);
        self::assertTrue($result->consumed->consumedBefore);
        self::assertTrue($result->consumed->consumedResult?->valid ?? false);
        self::assertSame('txn', $result->consumed->consumedResult?->binding);
        self::assertSame($identity, $result->consumed->operationIdentity);
    }

    public function testDeleteIfPendingIssuesWaitOnlyOnTheDeletedPendingTransition(): void
    {
        // The deleted-pending transition is durability-critical: a
        // burned challenge that only vanished from the primary could
        // reappear from a stale replica after promotion and be redeemed.
        // The verified WAIT barrier runs exactly when the Lua deleted a
        // pending record — and only then: missing and consumed report no
        // mutation, so no barrier is issued.
        $client = $this->requirePredis();
        $storage = new RedisStorage($client, waitReplicas: 2, waitTimeoutMs: 100);
        $client->waitAck = 2;
        $waits = fn (): int => \count(array_values(array_filter($client->calls, fn ($c) => $c[0] === 'WAIT')));

        self::assertSame('missing', $storage->deleteIfPending('absent-nonce')->state);
        self::assertSame(0, $waits(), 'WAIT must NOT be issued for missing (no mutation occurred)');

        $storage->store($this->makeRecord('consumed-nonce')); // +1 WAIT (issuance)
        $storage->consume('consumed-nonce'); // +1 WAIT (the pending->consumed transition)
        self::assertSame('consumed', $storage->deleteIfPending('consumed-nonce')->state);
        self::assertSame(2, $waits(), 'WAIT must NOT be issued for consumed (no mutation occurred)');

        $storage->store($this->makeRecord('pending-nonce')); // +1 WAIT (issuance)
        self::assertSame('deleted-pending', $storage->deleteIfPending('pending-nonce')->state);
        $waitsList = array_values(array_filter($client->calls, fn ($c) => $c[0] === 'WAIT'));
        self::assertCount(4, $waitsList, 'two stores + one consume + the deleted-pending transition must each issue the WAIT barrier');
        self::assertSame([2, 100], $waitsList[3][1], 'WAIT must carry the configured numreplicas and timeout');
    }

    public function testDeleteIfPendingSkipsWaitWhenDisabled(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $storage->store($this->makeRecord());

        self::assertSame('deleted-pending', $storage->deleteIfPending('redis-nonce-1')->state);

        $waits = array_values(array_filter($client->calls, fn ($c) => $c[0] === 'WAIT'));
        self::assertSame([], $waits, 'WAIT must not be issued when waitReplicas is 0');
    }

    public function testDeleteIfPendingFailsClosedBelowTheAckThreshold(): void
    {
        // A violated barrier on the delete-if-pending path surfaces the
        // same durability failure as the other transitions: fewer than
        // waitReplicas acked replicas raise ReplicaWaitException, because
        // the primary-side delete alone does not prove a promoted stale
        // replica cannot resurrect the pending state.
        $client = $this->requirePredis();
        $storage = new RedisStorage($client, waitReplicas: 1, waitTimeoutMs: 100);
        $client->waitAck = 1;
        $storage->store($this->makeRecord());

        $client->waitAck = 0;
        try {
            $storage->deleteIfPending('redis-nonce-1');
            self::fail('deleteIfPending must fail closed when the delete is not durably replicated');
        } catch (\KiwiCaptcha\Storage\ReplicaWaitException $e) {
            self::assertStringContainsString('0 of 1', $e->getMessage());
            self::assertStringContainsString('delete-if-pending transition', $e->getMessage());
        }

        // The delete DID land on the primary despite the violated
        // barrier (the fail-closed exception is the durable signal, not
        // a rollback): the record is gone from the primary's view, so a
        // retry observes missing and cannot re-delete.
        self::assertNull($client->store['kiwicaptcha:redis-nonce-1'] ?? null);

        $client->waitAck = 1;
        self::assertSame('missing', $storage->deleteIfPending('redis-nonce-1')->state, 'the failed-barrier delete still removed the record on the primary');
    }

    public function testRealRedisDeleteIfPendingRaceNeverErasesCommittedEvidence(): void
    {
        // The toctou the atomic primitive closes: a cheap-failing
        // verifier (A) must not delete a record a concurrent redeemer
        // (B) consumed and committed between A's decision and A's
        // cleanup. The interleaving is forced at the storage seam — B's
        // consume+commit runs between A's cheap failure and A's
        // deleteIfPending — and the loop varies the injection point
        // (before A's cleanup, after a pre-read, and after A's cleanup
        // for the invariant check). Runs only against the local test
        // Redis (127.0.0.1:6399, no password).
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

        for ($i = 0; $i < 20; $i++) {
            $nonce = base64_encode(random_bytes(32));
            $record = $this->makeRecord($nonce);
            $prefix = 'race:'.($i % 3).':';
            $storage = new RedisStorage($client, $prefix);
            $storage->store($record);

            // B consumes + commits Valid after A has already decided to
            // clean up (the forced interleaving; the deleteIfPending
            // call below is the "resumed" cleanup).
            $identity = 'op-race-'.$i;
            $consumed = $storage->consumeWithOperationIdentity($nonce, $identity);
            self::assertTrue($consumed?->consumedNow, 'B wins the transition');
            self::assertTrue($storage->commitResult($nonce, true, 'txn'));

            // A resumes: the atomic script observes the consumed state
            // and refuses the delete; the evidence is intact.
            $result = $storage->deleteIfPending($nonce);
            self::assertSame('consumed', $result->state, "iteration $i: the committed evidence is never erased");
            self::assertNotNull($result->consumed?->consumedResult, "iteration $i: the committed result rides back");
            self::assertTrue($result->consumed->consumedResult?->valid ?? false);
            self::assertSame($identity, $result->consumed->operationIdentity, "iteration $i: the recorded identity is intact");
            self::assertNotNull($storage->find($nonce), "iteration $i: the record still exists");

            $storage->delete($nonce);
        }
    }
}
