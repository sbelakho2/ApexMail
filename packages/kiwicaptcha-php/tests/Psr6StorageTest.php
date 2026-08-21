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
 * consume(): it used to delete-first-then-find, which PSR-6's delete
 * postcondition makes always return null, so every verification
 * failed.
 */
final class Psr6StorageTest extends TestCase
{
    private function makeRecord(string $nonce = 'nonce-1'): ChallengeRecord
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
        );
    }

    private function makePool(): ArrayPool
    {
        return new ArrayPool();
    }

    public function testStoreThenConsumeReturnsRecord(): void
    {
        // Regression: consume() must return the stored record. PSR-6's
        // delete postcondition makes a subsequent find miss, so a
        // transition that deletes instead of keeping the record would
        // break the contract.
        $storage = new Psr6Storage($this->makePool());
        $storage->store($this->makeRecord());

        $consumed = $storage->consume('nonce-1');

        self::assertNotNull($consumed);
        self::assertSame('nonce-1', $consumed->record->nonce);
        self::assertTrue($consumed->consumedNow);
    }

    public function testConsumeMarksConsumedAndKeepsTheRecord(): void
    {
        // consume() is a transition: the record is kept (marked
        // consumed) until its own expiration; a retry observes the
        // consumed marker instead of a missing record.
        $storage = new Psr6Storage($this->makePool());
        $storage->store($this->makeRecord());
        $storage->consume('nonce-1'); // first call wins the transition

        $retry = $storage->consume('nonce-1');
        self::assertNotNull($retry, 'the consumed record is kept — replay protection is the marker, not absence');
        self::assertTrue($retry->consumedBefore);
        self::assertNotNull($storage->find('nonce-1'), 'find must still see the consumed record');
        self::assertTrue($storage->commitResult('nonce-1', true, null), 'commit on a consumed record without result must succeed');
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
        self::assertNotNull($storage->find('nonce-1'), 'find must not transition');
    }

    public function testStoreReplacesExistingRecord(): void
    {
        $storage = new Psr6Storage($this->makePool());
        $storage->store($this->makeRecord('n'));
        $storage->store($this->makeRecord('n'));

        $consumed = $storage->consume('n');

        self::assertNotNull($consumed);
        self::assertSame('n', $consumed->record->nonce);
        self::assertNotNull($storage->consume('n'), 'the replaced record is consumed, not deleted');
    }

    public function testDeleteRemovesRecord(): void
    {
        $storage = new Psr6Storage($this->makePool());
        $storage->store($this->makeRecord());

        $storage->delete('nonce-1');

        self::assertNull($storage->find('nonce-1'));
    }

    public function testCommitResultStoresAndRejectsSecondCommit(): void
    {
        $storage = new Psr6Storage($this->makePool());
        $storage->store($this->makeRecord());

        self::assertFalse($storage->commitResult('nonce-1', true, 'txn'), 'commit on a pending record must fail');
        $storage->consume('nonce-1');
        self::assertTrue($storage->commitResult('nonce-1', true, 'txn'));
        self::assertFalse($storage->commitResult('nonce-1', false, null), 'a second commit must be rejected');

        $retry = $storage->consume('nonce-1');
        self::assertNotNull($retry);
        self::assertTrue($retry->consumedBefore);
        self::assertNotNull($retry->consumedResult, 'the committed result must ride back on the retry');
        self::assertTrue($retry->consumedResult->valid);
        self::assertSame('txn', $retry->consumedResult->binding);
    }

    public function testRecordRoundTripsThroughSerialization(): void
    {
        $storage = new Psr6Storage($this->makePool());
        $storage->store($this->makeRecord());

        $consumed = $storage->consume('nonce-1');

        self::assertSame('login', $consumed?->record->scope);
        self::assertSame(PoWAlgorithm::Sha256, $consumed?->record->algorithm);
        self::assertSame(0, $consumed?->record->issuedAtNs);
    }

    public function testConsumedStateReadsTheStoredConsumedEnvelope(): void
    {
        $storage = new Psr6Storage($this->makePool());
        $storage->store($this->makeRecord());
        self::assertNull($storage->consumedState('nonce-1'), 'a pending record has no consumed state');

        $consumed = $storage->consume('nonce-1');
        self::assertNotNull($consumed);
        self::assertTrue($consumed->consumedNow);
        $storage->commitResult('nonce-1', true, 'txn');

        // The retained consumed state must be readable without a
        // transition: the envelope carries the consumed flag, the
        // committed result and the recorded operation identity exactly
        // like the Redis/array backends.
        $state = $storage->consumedState('nonce-1');
        self::assertNotNull($state, 'consumedState() must read the stored consumed envelope');
        self::assertTrue($state->consumedBefore);
        self::assertFalse($state->consumedNow, 'the read-only inspection performs no transition');
        self::assertTrue($state->consumedResult?->valid ?? false, 'the committed result is readable');
        self::assertSame('txn', $state->consumedResult?->binding);

        $storage->store($this->makeRecord('nonce-2'));
        $storage->consumeWithOperationIdentity('nonce-2', 'op-id-1');
        $identityState = $storage->consumedState('nonce-2');
        self::assertNotNull($identityState);
        self::assertSame('op-id-1', $identityState->operationIdentity, 'the recorded operation identity is readable');
    }

    public function testConsumedStateOfAMissingRecordIsNull(): void
    {
        $storage = new Psr6Storage($this->makePool());
        self::assertNull($storage->consumedState('absent-nonce'));
    }

    public function testPsr6StorageIsMarkedNonAtomic(): void
    {
        // The capability stamp consumers can test: PSR-6 cannot fuse
        // read and transition, so the storage declares itself best-effort
        // ({@see \KiwiCaptcha\NonAtomicStorageInterface}) instead of
        // merely not claiming AtomicStorageInterface.
        self::assertNotInstanceOf(\KiwiCaptcha\AtomicStorageInterface::class, new Psr6Storage($this->makePool()));
        self::assertInstanceOf(\KiwiCaptcha\NonAtomicStorageInterface::class, new Psr6Storage($this->makePool()));
    }

    public function testPsr6StorageIsNotAtomic(): void
    {
        // PSR-6 cannot fuse read and transition, so Psr6Storage is
        // best-effort single-use; it must not claim
        // AtomicStorageInterface (only RedisStorage's fused Lua
        // transition backend does).
        self::assertNotInstanceOf(\KiwiCaptcha\AtomicStorageInterface::class, new Psr6Storage($this->makePool()));
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
        self::assertSame($record->issuedAtNs, $loaded->record->issuedAtNs);
    }

    public function testNonceContainingForwardSlashRoundTrips(): void
    {
        // base64 of bytes containing 0xFB.. yields '/' — a PSR-6-reserved
        // character that strict pools reject in keys. The hashed cache key
        // must make such nonces work.
        $nonce = base64_encode(hex2bin('fbffefc0d0e0f0a0b0c0d0e0f0010203'));
        self::assertStringContainsString('/', $nonce, 'fixture must actually contain /');

        $pool = $this->makePool();
        $storage = new Psr6Storage($pool);
        $record = $this->makeRecord($nonce);
        $storage->store($record);

        self::assertNotNull($storage->find($nonce));
        $consumed = $storage->consume($nonce);
        self::assertNotNull($consumed);
        self::assertNotNull($storage->find($nonce), 'the consumed record is kept until its own expiration');
    }

    public function testNonceContainingPlusRoundTrips(): void
    {
        $nonce = base64_encode(hex2bin('fbfedec0d0e0f0a0b0c0d0e0f0010203'));
        self::assertStringContainsString('+', $nonce, 'fixture must actually contain +');

        $pool = $this->makePool();
        $storage = new Psr6Storage($pool);
        $record = $this->makeRecord($nonce);
        $storage->store($record);

        self::assertNotNull($storage->find($nonce));
        self::assertNotNull($storage->consume($nonce));
    }

    public function testPsr6KeyLengthNeverExceeds64Characters(): void
    {
        // PSR-6 only requires support for keys up to 64 characters;
        // longer keys are optional. Base64 nonces may contain '/' and
        // '+', and are 44 chars; the hashed 'kc_' + 60-hex key must
        // stay within 64.
        $key = new \ReflectionMethod(Psr6Storage::class, 'key');

        foreach ([
            base64_encode(random_bytes(32)),              // may contain / +
            'wcUWq2z/nJ+T0m7VlNqnUq6PBv+J0x3Rq9yKxZ4Yw2c=', // guaranteed / and +
            str_repeat('a', 44),
            'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=', // shared fixture nonce
        ] as $nonce) {
            $k = (string) $key->invoke(null, $nonce);
            self::assertLessThanOrEqual(64, strlen($k), "key for nonce $nonce exceeds 64 chars");
            self::assertMatchesRegularExpression('/^[A-Za-z0-9_.]+$/', $k, 'key must be PSR-6-safe');
        }
    }

    public function testCorruptRecordWithUnknownAlgorithmIsTreatedAsAbsent(): void
    {
        $pool = $this->makePool();
        $storage = new Psr6Storage($pool);
        $nonce = 'corrupt-nonce-1';

        $item = $pool->getItem('kc_' . substr(hash('sha256', $nonce), 0, 60));
        $item->set([
            'nonce' => $nonce,
            'scope' => 'login',
            'binding_tag' => '',
            'issued_at' => 1_800_000_000,
            'expires_at' => 1_800_000_120,
            'algorithm' => 'md5', // unknown algorithm value
            'target_bits' => 8,
            'salt' => base64_encode('1234567890abcdef'),
            'prefix' => 'x',
            'challenge' => 'y',
        ]);
        $pool->save($item);

        // Must NOT throw — corrupt data is treated as absent and cleaned up.
        self::assertNull($storage->find($nonce));
        self::assertNull($storage->consume($nonce));
        self::assertFalse($pool->hasItem('kc_' . substr(hash('sha256', $nonce), 0, 60)), 'poisoned key must be cleaned up');
    }

    public function testTruncatedJsonRecordIsTreatedAsAbsent(): void
    {
        $pool = $this->makePool();
        $storage = new Psr6Storage($pool);
        $nonce = 'truncated-nonce-1';

        $item = $pool->getItem('kc_' . substr(hash('sha256', $nonce), 0, 60));
        $item->set(['nonce' => $nonce]); // structurally incomplete record
        $pool->save($item);

        self::assertNull($storage->find($nonce));
        self::assertNull($storage->consume($nonce));
    }
}
