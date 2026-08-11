<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\Psr6Storage;
use KiwiCaptcha\Tests\Fixtures\ArrayPool;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Psr6Storage behaviour, including the regression test for the broken
 * consume() (it used to delete-first-then-find, which PSR-6's delete
 * postcondition makes always return null — every verification failed).
 */
final class Psr6StorageTest extends TestCase
{
    private function makeRecord(string $nonce = 'nonce-1'): ChallengeRecord
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
        );
    }

    private function makePool(): ArrayPool
    {
        return new ArrayPool();
    }

    public function testStoreThenConsumeReturnsRecord(): void
    {
        // REGRESSION: consume() must return the stored record. The old
        // delete-then-find implementation always returned null because
        // PSR-6's delete postcondition makes the subsequent find miss.
        $storage = new Psr6Storage($this->makePool());
        $storage->store($this->makeRecord());

        $record = $storage->consume('nonce-1');

        self::assertNotNull($record);
        self::assertSame('nonce-1', $record->nonce);
    }

    public function testConsumeRemovesRecord(): void
    {
        $storage = new Psr6Storage($this->makePool());
        $storage->store($this->makeRecord());

        self::assertNotNull($storage->consume('nonce-1'));
        self::assertNull($storage->consume('nonce-1'), 'second consume must miss');
        self::assertNull($storage->find('nonce-1'), 'record must be gone after consume');
    }

    public function testConsumeOnMissingNonceReturnsNull(): void
    {
        $storage = new Psr6Storage($this->makePool());

        self::assertNull($storage->consume('never-stored'));
    }

    public function testFindDoesNotConsume(): void
    {
        $storage = new Psr6Storage($this->makePool());
        $storage->store($this->makeRecord());

        self::assertNotNull($storage->find('nonce-1'));
        self::assertNotNull($storage->find('nonce-1'), 'find must not delete');
    }

    public function testStoreReplacesExistingRecord(): void
    {
        $storage = new Psr6Storage($this->makePool());
        $storage->store($this->makeRecord('n'));
        $storage->store($this->makeRecord('n'));

        $record = $storage->consume('n');

        self::assertNotNull($record);
        self::assertNull($storage->consume('n'));
    }

    public function testDeleteRemovesRecord(): void
    {
        $storage = new Psr6Storage($this->makePool());
        $storage->store($this->makeRecord());

        $storage->delete('nonce-1');

        self::assertNull($storage->find('nonce-1'));
    }

    public function testRecordRoundTripsThroughSerialization(): void
    {
        $storage = new Psr6Storage($this->makePool());
        $storage->store($this->makeRecord());

        $record = $storage->consume('nonce-1');

        self::assertSame('login', $record?->scope);
        self::assertSame(PoWAlgorithm::Sha256, $record?->algorithm);
        self::assertSame(0, $record?->issuedAtNs);
    }

    public function testAttemptsAreTrackedBestEffort(): void
    {
        $storage = new Psr6Storage($this->makePool());

        self::assertSame(0, $storage->attemptsUsed('nonce-1'));
        self::assertTrue($storage->incrementAttempts('nonce-1', 3));
        self::assertTrue($storage->incrementAttempts('nonce-1', 3));
        self::assertSame(2, $storage->attemptsUsed('nonce-1'));
    }

    public function testIssuedAtNsSurvivesRoundTrip(): void
    {
        $pool = $this->makePool();
        $writer = new Psr6Storage($pool);
        $reader = new Psr6Storage($pool);

        $record = $this->makeRecord('ns-rec');
        $writer->store($record);

        $loaded = $reader->consume('ns-rec');

        self::assertNotNull($loaded);
        self::assertSame($record->issuedAtNs, $loaded->issuedAtNs);
    }
}
