<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\CancellableStorageInterface;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;

/**
 * The atomic pending→cancelled transition of
 * {@see CancellableStorageInterface} on the two bundled storages.
 *
 * A cancellation flips a pending record to the terminal `cancelled`
 * marker and keeps it until its TTL; the one-shot marker is the state,
 * not absence. A consumed (finalized) record is never cancelled. An
 * already-cancelled record is idempotent. A missing record is null.
 *
 * The cancelled record is unconsumable: the consume transition reports
 * it as missing, the consumed-state reads never surface it, and the
 * delete-if-pending cleanup never deletes it. Verification of a
 * cancelled record fails closed as RecordNotFound.
 *
 * The Redis backend additionally carries the verified-WAIT durability
 * barrier on the fresh flip only, the write that actually happened.
 * Missing, consumed and already-cancelled perform no write and never
 * wait.
 */
final class CancellationTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    // ── ArrayStorage ────────────────────────────────────────────────

    public function testArrayStorageImplementsCancellableStorageInterface(): void
    {
        self::assertInstanceOf(CancellableStorageInterface::class, new ArrayStorage());
    }

    public function testArrayStorageFreshCancellationFlipsTheEnvelopeAndRetainsTheRecord(): void
    {
        $storage = new ArrayStorage();
        $nonce = $this->storePending($storage);

        $result = $storage->cancel($nonce);

        self::assertNotNull($result, 'a pending record is cancellable');
        self::assertSame('cancelled-now', $result->state, 'this call performs the pending→cancelled flip');
        self::assertTrue($result->wasCancelledNow());

        $records = $this->records($storage);
        self::assertTrue($records[$nonce]['cancelled'], 'the envelope gains the terminal cancelled marker');
        self::assertFalse($records[$nonce]['consumed'], 'a cancellation is not a consume');
        self::assertNotNull($storage->find($nonce), 'the cancelled record is retained until its TTL — the marker is the state, not absence');
    }

    public function testArrayStorageConsumedRecordIsNeverCancelled(): void
    {
        $storage = new ArrayStorage();
        $nonce = $this->storePending($storage);
        self::assertNotNull($storage->consume($nonce), 'the challenge is consumed before the cancellation attempt');

        $result = $storage->cancel($nonce);

        self::assertNotNull($result);
        self::assertSame('consumed', $result->state, 'a consumed/finalized record is never cancelled');
        self::assertFalse($result->wasCancelledNow());
        $records = $this->records($storage);
        self::assertTrue($records[$nonce]['consumed'], 'the consumed record stays consumed');
        self::assertFalse($records[$nonce]['cancelled'] ?? false, 'a consumed/finalized record is never cancelled');
        self::assertNotNull($storage->consumedState($nonce), 'the consumed evidence survives the refusal');
    }

    public function testArrayStorageAlreadyCancelledIsIdempotent(): void
    {
        $storage = new ArrayStorage();
        $nonce = $this->storePending($storage);

        self::assertSame('cancelled-now', $storage->cancel($nonce)?->state);
        $result = $storage->cancel($nonce);

        self::assertNotNull($result);
        self::assertSame('cancelled', $result->state, 'an already-cancelled record is the idempotent retry');
        self::assertFalse($result->wasCancelledNow());
        self::assertTrue($this->records($storage)[$nonce]['cancelled'], 'the record stays cancelled');
    }

    public function testArrayStorageMissingNonceReturnsNull(): void
    {
        $storage = new ArrayStorage();

        self::assertNull($storage->cancel('A'.str_repeat('a', 43)), 'a never-issued nonce is a null result, not a state');
        self::assertSame([], $this->records($storage), 'no state is written for a missing nonce');
    }

    public function testArrayStorageCancelledRecordIsUnconsumableAndFailsVerificationClosed(): void
    {
        $storage = new ArrayStorage();
        $challenge = $this->issue($storage);
        self::assertSame('cancelled-now', $storage->cancel($challenge->nonce)?->state);

        // Unconsumable: the one-shot transition reports it as missing.
        self::assertNull($storage->consume($challenge->nonce), 'a cancelled record is never consumable');
        self::assertNull($storage->consumeWithOperationIdentity($challenge->nonce, 'op-x'), 'the identity-bearing consume is refused too');
        // Never recoverable: the consumed-state reads never surface it.
        self::assertNull($storage->consumedState($challenge->nonce), 'a cancelled record is never recoverable');
        // Never committable.
        self::assertFalse($storage->commitResult($challenge->nonce, true, null), 'a cancelled record can never carry a committed outcome');
        // Never eagerly deleted: the cleanup keeps the dead record.
        $cleanup = $storage->deleteIfPending($challenge->nonce);
        self::assertSame('cancelled', $cleanup->state, 'the cleanup observes the cancelled state');
        self::assertFalse($cleanup->wasConsumed(), 'the cancelled state is not consumed evidence');
        self::assertNotNull($storage->find($challenge->nonce), 'the cleanup never deletes a cancelled record');

        // Never verifiable: a genuinely valid solution fails closed as
        // RecordNotFound — the verifier's equivalent of an unavailable
        // record — never a successful redemption.
        $token = $this->solve($challenge);
        $outcome = (new Verifier($storage, now: static fn (): int => Vectors::NOW))->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
        );
        self::assertFalse($outcome->isOk(), 'a cancelled challenge must never verify');
        self::assertSame(VerifyError::RecordNotFound, $outcome->error, 'the cancelled record fails verification closed (reported missing)');
    }

    // ── RedisStorage (in-memory Predis stand-in) ─────────────────────

    public function testRedisStorageImplementsCancellableStorageInterface(): void
    {
        self::assertInstanceOf(CancellableStorageInterface::class, new RedisStorage($this->requirePredis()));
    }

    public function testRedisStorageFreshCancellationFlipsTheStoredEnvelopeAndRetainsTheRecord(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $nonce = $this->storePending($storage);

        $result = $storage->cancel($nonce);

        self::assertNotNull($result);
        self::assertSame('cancelled-now', $result->state, 'this call performs the pending→cancelled flip');
        self::assertTrue($result->wasCancelledNow());
        $data = json_decode((string) $client->store['kiwicaptcha:'.$nonce], true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('cancelled', $data['state'], 'the flip must persist state=cancelled in the stored JSON');
        self::assertArrayHasKey('consumed_result', $data, 'the runtime consumed_result key stays present');
        self::assertNotNull($storage->find($nonce), 'the cancelled record is retained until its TTL');
    }

    public function testRedisStorageConsumedRecordIsNeverCancelled(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $nonce = $this->storePending($storage);
        self::assertNotNull($storage->consume($nonce));

        $result = $storage->cancel($nonce);

        self::assertNotNull($result);
        self::assertSame('consumed', $result->state, 'a consumed/finalized record is never cancelled');
        self::assertFalse($result->wasCancelledNow());
        $data = json_decode((string) $client->store['kiwicaptcha:'.$nonce], true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('consumed', $data['state'], 'the consumed record stays consumed');
        self::assertNotNull($storage->consumedState($nonce), 'the consumed evidence survives the refusal');
    }

    public function testRedisStorageAlreadyCancelledIsIdempotent(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $nonce = $this->storePending($storage);

        self::assertSame('cancelled-now', $storage->cancel($nonce)?->state);
        $result = $storage->cancel($nonce);

        self::assertNotNull($result);
        self::assertSame('cancelled', $result->state, 'an already-cancelled record is the idempotent retry');
        self::assertFalse($result->wasCancelledNow());
        $data = json_decode((string) $client->store['kiwicaptcha:'.$nonce], true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('cancelled', $data['state'], 'the record stays cancelled');
    }

    public function testRedisStorageMissingNonceReturnsNull(): void
    {
        $storage = new RedisStorage($this->requirePredis());

        self::assertNull($storage->cancel('never-stored'), 'a never-issued nonce is a null result, not a state');
    }

    public function testRedisStorageCancelledRecordIsUnconsumableAndFailsVerificationClosed(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $challenge = $this->issue($storage);
        self::assertSame('cancelled-now', $storage->cancel($challenge->nonce)?->state);

        // Unconsumable: the atomic consume transition reports it missing.
        self::assertNull($storage->consume($challenge->nonce), 'a cancelled record is never consumable');
        self::assertNull($storage->consumeWithOperationIdentity($challenge->nonce, 'op-x'), 'the identity-bearing consume is refused too');
        // Never recoverable / never committable.
        self::assertNull($storage->consumedState($challenge->nonce), 'a cancelled record is never recoverable');
        self::assertFalse($storage->commitResult($challenge->nonce, true, null), 'a cancelled record can never carry a committed outcome');
        // Never eagerly deleted: the fused cleanup keeps the dead record.
        $cleanup = $storage->deleteIfPending($challenge->nonce);
        self::assertSame('cancelled', $cleanup->state, 'the cleanup observes the cancelled state');
        self::assertFalse($cleanup->wasConsumed(), 'the cancelled state is not consumed evidence');
        $data = json_decode((string) $client->store['kiwicaptcha:'.$challenge->nonce], true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('cancelled', $data['state'], 'the cleanup never deletes a cancelled record');

        // Never verifiable: a genuinely valid solution fails closed as
        // RecordNotFound.
        $token = $this->solve($challenge);
        $outcome = (new Verifier($storage, now: static fn (): int => Vectors::NOW))->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.77',
        );
        self::assertFalse($outcome->isOk(), 'a cancelled challenge must never verify');
        self::assertSame(VerifyError::RecordNotFound, $outcome->error, 'the cancelled record fails verification closed (reported missing)');
    }

    public function testRedisStorageCancelUsesLuaForPredis(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $nonce = $this->storePending($storage);

        $storage->cancel($nonce);

        $evals = $client->evals;
        self::assertNotEmpty($evals, 'cancel must go through the Lua script for Predis (EVALSHA after the SCRIPT LOAD warm-up)');
        self::assertStringContainsString('cancel transition', $evals[array_key_last($evals)]['script'], 'the atomic cancel-transition Lua must be used');
    }

    public function testRedisStorageCancellationPreservesTheKeyTtl(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $record = $this->makeRecord('ttl-nonce');
        $storage->store($record);

        $storage->cancel('ttl-nonce');

        // The flip preserves the key expiration: the cancelled marker is
        // retained for the record's remaining lifetime (the SET EX splice
        // of the real Lua; the fake re-writes the value with the same
        // expiration map).
        self::assertGreaterThanOrEqual(1, $client->expirations['kiwicaptcha:ttl-nonce'], 'the cancelled record keeps its TTL');
    }

    public function testRedisStorageCancelIssuesWaitOnlyOnTheFreshTransition(): void
    {
        // The verified WAIT guards the write that actually happened: a
        // fresh pending→cancelled flip issues exactly one WAIT, while an
        // already-cancelled replay, a consumed record and a missing record
        // performed no write and must issue none — an idempotent retry must
        // not turn a replica outage into a storage failure.
        $client = $this->requirePredis();
        $storage = new RedisStorage($client, waitReplicas: 1, waitTimeoutMs: 100);
        $client->waitAck = 1;
        $waits = fn (): int => \count(array_values(array_filter($client->calls, fn ($c) => $c[0] === 'WAIT')));

        $storage->store($this->makeRecord('wait-fresh')); // +1 WAIT (issuance)
        self::assertSame(1, $waits());

        $fresh = $storage->cancel('wait-fresh');
        self::assertNotNull($fresh);
        self::assertTrue($fresh->wasCancelledNow(), 'the first cancel wins the fresh transition');
        self::assertSame(2, $waits(), 'a fresh pending→cancelled flip must issue exactly one WAIT');

        $replay = $storage->cancel('wait-fresh');
        self::assertNotNull($replay);
        self::assertSame('cancelled', $replay->state);
        self::assertSame(2, $waits(), 'an already-cancelled replay performs no write and must issue NO WAIT');

        $storage->store($this->makeRecord('wait-consumed')); // +1 WAIT (issuance)
        $storage->consume('wait-consumed'); // +1 WAIT (the pending→consumed transition)
        $consumed = $storage->cancel('wait-consumed');
        self::assertNotNull($consumed);
        self::assertSame('consumed', $consumed->state);
        self::assertSame(4, $waits(), 'a consumed record performs no write and must issue NO WAIT');

        self::assertNull($storage->cancel('never-stored'));
        self::assertSame(4, $waits(), 'a missing record performs no write and must issue NO WAIT');
    }

    public function testRedisStorageCancelSkipsWaitWhenDisabled(): void
    {
        $client = $this->requirePredis();
        $storage = new RedisStorage($client);
        $nonce = $this->storePending($storage);

        $result = $storage->cancel($nonce);
        self::assertNotNull($result);
        self::assertTrue($result->wasCancelledNow());

        $waits = array_values(array_filter($client->calls, fn ($c) => $c[0] === 'WAIT'));
        self::assertSame([], $waits, 'WAIT must not be issued when waitReplicas is 0');
    }

    public function testRedisStorageCancelFailsClosedBelowTheAckThreshold(): void
    {
        // A violated barrier on the cancellation path surfaces the same
        // durability failure as the other transitions: fewer than
        // waitReplicas acked replicas raise ReplicaWaitException, because
        // the primary-side flip alone does not prove a promoted stale
        // replica cannot resurrect the pending state.
        $client = $this->requirePredis();
        $storage = new RedisStorage($client, waitReplicas: 1, waitTimeoutMs: 100);
        $client->waitAck = 1;
        $storage->store($this->makeRecord('barrier-nonce'));

        $client->waitAck = 0;
        try {
            $storage->cancel('barrier-nonce');
            self::fail('cancel must fail closed when the flip is not durably replicated');
        } catch (\KiwiCaptcha\Storage\ReplicaWaitException $e) {
            self::assertStringContainsString('0 of 1', $e->getMessage());
            self::assertStringContainsString('pending→cancelled transition', $e->getMessage());
        }

        // The flip DID land on the primary despite the violated barrier
        // (the fail-closed exception is the durable signal, not a
        // rollback): a retry observes the already-cancelled state and can
        // never re-flip — and, having performed no write, issues no WAIT.
        $client->waitAck = 1;
        $retry = $storage->cancel('barrier-nonce');
        self::assertNotNull($retry);
        self::assertSame('cancelled', $retry->state, 'the failed-barrier flip still cancelled the record on the primary');
    }

    // ── Real Redis (RISK_REDIS_URL) ─────────────────────────────────

    public function testRealRedisCancellationLifecycle(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if ($url === false || $url === '') {
            self::markTestSkipped('RISK_REDIS_URL not set; cannot test the real-Redis cancellation lifecycle');
        }
        $client = new \Predis\Client($url);
        $prefix = 'cancel-life-'.bin2hex(random_bytes(4)).'-';
        $storage = new RedisStorage($client, $prefix);
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        $key = $prefix.$challenge->nonce;

        $ttlBefore = $client->ttl($key);
        self::assertGreaterThan(0, $ttlBefore);

        self::assertSame('cancelled-now', $storage->cancel($challenge->nonce)?->state);
        self::assertSame('cancelled', $storage->cancel($challenge->nonce)?->state, 'the idempotent retry');

        // The cancelled record is retained until its TTL — the flip
        // preserves the key expiration (the one-shot marker is the state,
        // not absence).
        $ttlAfter = $client->ttl($key);
        self::assertGreaterThan(0, $ttlAfter, 'the cancelled record must still exist (retained until its TTL)');
        self::assertLessThanOrEqual($ttlBefore, $ttlAfter, 'the flip must preserve the key TTL, never reset it');

        // Unconsumable, never recoverable, never committable, never
        // eagerly deleted.
        self::assertNull($storage->consume($challenge->nonce));
        self::assertNull($storage->consumedState($challenge->nonce));
        self::assertFalse($storage->commitResult($challenge->nonce, true, null));
        self::assertSame('cancelled', $storage->deleteIfPending($challenge->nonce)->state);
        self::assertNotNull($storage->find($challenge->nonce), 'the cancelled record survives the cleanup');

        // A genuinely valid solution fails closed as RecordNotFound.
        $counter = 0;
        $saltBytes = base64_decode($challenge->salt, true);
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;
        // The server-measured minimum-duration floor: wait it out so the
        // proof itself is not rejected as TooFast (the cancelled-marker
        // behavior is what this test pins).
        usleep(((int) $challenge->minDurationMs + 10) * 1000);
        $token = \KiwiCaptcha\SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
        $outcome = (new Verifier($storage))->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertFalse($outcome->isOk());
        self::assertSame(VerifyError::RecordNotFound, $outcome->error);

        $client->del($key);
    }

    // ── helpers ─────────────────────────────────────────────────────

    private function requirePredis(): FakePredisClient
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed; cannot test RedisStorage');
        }

        return new FakePredisClient();
    }

    private function makeRecord(string $nonce = 'cancel-nonce-1'): ChallengeRecord
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

    private function storePending(\KiwiCaptcha\StorageInterface $storage): string
    {
        $storage->store($this->makeRecord());

        return 'cancel-nonce-1';
    }

    private function issue(\KiwiCaptcha\StorageInterface $storage): \KiwiCaptcha\Challenge
    {
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
            now: static fn (): int => Vectors::NOW,
        );

        return $issuer->issue('login', '198.51.100.77');
    }

    private function solve(\KiwiCaptcha\Challenge $challenge): string
    {
        $counter = 0;
        $saltBytes = base64_decode($challenge->salt, true);
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        return \KiwiCaptcha\SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
    }

    /** @return array<string, array{record: ChallengeRecord, consumed: bool, cancelled: bool, result: mixed, operationIdentity: mixed}> */
    private function records(ArrayStorage $storage): array
    {
        return (new \ReflectionObject($storage))->getProperty('records')->getValue($storage);
    }
}
