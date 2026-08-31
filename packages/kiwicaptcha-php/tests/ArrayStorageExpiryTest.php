<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\ChallengeRuntimeStateKind;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\ArrayStorage;
use PHPUnit\Framework\TestCase;

/**
 * ArrayStorage's Redis-TTL-parity expiry semantics and bounded
 * retention. An expired record is absent to every read and transition,
 * matching what Redis key TTLs give the other backend. `store()`
 * prunes expired entries, and a hard size cap evicts the
 * oldest-expiring first, so a long-lived process stays memory-bounded.
 */
final class ArrayStorageExpiryTest extends TestCase
{
    private int $clock = 1_000_000;

    private function storage(?int $maxEntries = null): ArrayStorage
    {
        return $maxEntries !== null
            ? new ArrayStorage(now: fn (): int => $this->clock, maxEntries: $maxEntries)
            : new ArrayStorage(now: fn (): int => $this->clock);
    }

    private function makeRecord(string $nonce, int $expiresAt): ChallengeRecord
    {
        return new ChallengeRecord(
            nonce: $nonce,
            scope: 'login',
            bindingTag: 'tag',
            issuedAt: $this->clock - 60,
            expiresAt: $expiresAt,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 0,
            t: 1,
            p: 1,
            targetBits: 8,
            salt: 'c2FsdA==',
            prefix: 'prefix',
            challenge: 'challenge',
            minDurationMs: 0,
            issuedAtNs: 1,
        );
    }

    /** @return int the number of retained entries (reflection on the private map) */
    private function retainedCount(ArrayStorage $storage): int
    {
        return \count((new \ReflectionObject($storage))->getProperty('records')->getValue($storage));
    }

    public function testExpiredRecordsAreAbsentToEveryReadAndTransition(): void
    {
        $storage = $this->storage();
        $record = $this->makeRecord('expired-nonce', $this->clock + 60);
        $storage->store($record);

        // Live: readable and consumable.
        self::assertNotNull($storage->find('expired-nonce'));
        self::assertNotNull($storage->consume('expired-nonce'));
        self::assertNotNull($storage->consumedState('expired-nonce'));

        // The clock passes expires_at: the key is gone, exactly like a
        // Redis TTL expiry — every lookup and transition reports
        // absence, including for the retained consumed envelope.
        $this->clock += 61;

        self::assertNull($storage->find('expired-nonce'), 'an expired record is absent to find()');
        self::assertNull($storage->consume('expired-nonce'), 'an expired record is never consumable');
        self::assertNull($storage->consumedState('expired-nonce'), 'the retained consumed state vanishes with the TTL');
        self::assertSame(ChallengeRuntimeStateKind::Missing, $storage->runtimeState('expired-nonce')->kind);
        self::assertSame('missing', $storage->deleteIfPending('expired-nonce')->state);
        self::assertNull($storage->cancel('expired-nonce'));
        self::assertFalse($storage->commitResult('expired-nonce', true, null));
    }

    public function testExpiryBoundaryMatchesTheVerifierNowGreaterOrEqual(): void
    {
        // The boundary is the verifier's own expiry rule
        // (`now >= expires_at`): the last live instant is expires_at-1.
        $storage = $this->storage();
        $storage->store($this->makeRecord('boundary', $this->clock + 10));

        $this->clock += 9;
        self::assertNotNull($storage->find('boundary'), 'one second before expires_at the record is live');

        $this->clock += 1;
        self::assertNull($storage->find('boundary'), 'at expires_at the record is expired');
    }

    public function testStorePrunesExpiredEntries(): void
    {
        $storage = $this->storage();
        $storage->store($this->makeRecord('old-1', $this->clock + 10));
        $storage->store($this->makeRecord('old-2', $this->clock + 10));
        self::assertSame(2, $this->retainedCount($storage));

        // Both entries expire; a later store (no reads in between) must
        // prune them so unobserved expired records never accumulate.
        $this->clock += 11;
        $storage->store($this->makeRecord('fresh', $this->clock + 60));

        self::assertSame(1, $this->retainedCount($storage), 'store() prunes expired entries');
        self::assertNull($storage->find('old-1'));
        self::assertNull($storage->find('old-2'));
        self::assertNotNull($storage->find('fresh'));
    }

    public function testHardCapEvictsTheOldestExpiringEntriesFirst(): void
    {
        $storage = $this->storage(maxEntries: 3);
        $storage->store($this->makeRecord('a', $this->clock + 300)); // expires last
        $storage->store($this->makeRecord('b', $this->clock + 100)); // expires first
        $storage->store($this->makeRecord('c', $this->clock + 200));
        self::assertSame(3, $this->retainedCount($storage));

        // At the cap, the next insert drops the earliest-expiring entry
        // ('b'), never the earliest-inserted ('a').
        $storage->store($this->makeRecord('d', $this->clock + 400));

        self::assertSame(3, $this->retainedCount($storage), 'the map stays at the hard cap');
        self::assertNull($storage->find('b'), 'the soonest-expiring entry was evicted');
        self::assertNotNull($storage->find('a'));
        self::assertNotNull($storage->find('c'));
        self::assertNotNull($storage->find('d'));
    }

    public function testRestoringAnExistingNonceDoesNotEvict(): void
    {
        // A re-store replaces the entry in place: the count does not
        // grow, so no unrelated entry is evicted.
        $storage = $this->storage(maxEntries: 2);
        $storage->store($this->makeRecord('a', $this->clock + 100));
        $storage->store($this->makeRecord('b', $this->clock + 200));
        $storage->store($this->makeRecord('b', $this->clock + 300));

        self::assertSame(2, $this->retainedCount($storage));
        self::assertNotNull($storage->find('a'), 'a same-key re-store evicts nothing');
        self::assertNotNull($storage->find('b'));
    }

    public function testTheDefaultCapIsTenThousand(): void
    {
        // The documented default: bounded by `DEFAULT_MAX_ENTRIES`.
        self::assertSame(10_000, ArrayStorage::DEFAULT_MAX_ENTRIES);
        $this->expectException(\InvalidArgumentException::class);
        new ArrayStorage(now: null, maxEntries: 0);
    }

    public function testRetentionMarginKeepsExpiredRecordsReadableInsideTheWindow(): void
    {
        // The Redis ttlMarginSecs shape: with a configured retention
        // margin the storage keeps the record readable inside
        // [expires_at, expires_at + margin) — the verifier's own TTL
        // check still rejects it there (Expired), and the retained
        // consumed evidence survives for the replay-exempt resolution.
        // Default 0 (used by every other test here) stays the strict
        // boundary.
        $storage = new ArrayStorage(
            now: fn (): int => $this->clock,
            retentionMarginSecs: 30,
        );
        $storage->store($this->makeRecord('margined', $this->clock + 60));
        self::assertNotNull($storage->consume('margined'));

        // Inside the margin window: expired to the verifier, still
        // readable at the storage boundary.
        $this->clock += 61;
        self::assertNotNull($storage->find('margined'), 'the record stays readable inside the margin window');
        self::assertNotNull($storage->consumedState('margined'), 'the retained consumed evidence outlives the signed lifetime inside the margin');
        self::assertSame(ChallengeRuntimeStateKind::Consumed, $storage->runtimeState('margined')->kind);

        // Past the margin the key is gone, exactly like the Redis TTL.
        $this->clock += 30;
        self::assertNull($storage->find('margined'));
        self::assertNull($storage->consumedState('margined'));
        self::assertSame(ChallengeRuntimeStateKind::Missing, $storage->runtimeState('margined')->kind);
    }

    public function testRetentionMarginBelowZeroIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new ArrayStorage(now: null, retentionMarginSecs: -1);
    }
}
