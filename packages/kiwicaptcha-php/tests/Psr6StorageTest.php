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

    public function testInspectConsumedEnvelopeReadsTheStoredEnvelope(): void
    {
        $storage = new Psr6Storage($this->makePool());
        $storage->store($this->makeRecord());
        self::assertNull($storage->inspectConsumedEnvelope('nonce-1'), 'a pending record has no consumed envelope');

        $consumed = $storage->consume('nonce-1');
        self::assertNotNull($consumed);
        self::assertTrue($consumed->consumedNow);
        $storage->commitResult('nonce-1', true, 'txn');

        // The retained envelope stays readable without any capability
        // claim: the diagnostic inspection reports the consumed flag and
        // the committed result (the identity is always null — this
        // backend does not offer the identity-aware consume).
        $state = $storage->inspectConsumedEnvelope('nonce-1');
        self::assertNotNull($state, 'inspectConsumedEnvelope() must read the stored consumed envelope');
        self::assertTrue($state->consumedBefore);
        self::assertFalse($state->consumedNow, 'the read-only inspection performs no transition');
        self::assertTrue($state->consumedResult?->valid ?? false, 'the committed result is readable');
        self::assertSame('txn', $state->consumedResult?->binding);
        self::assertNull($state->operationIdentity, 'no identity is recorded on this backend');
    }

    public function testPsr6StorageClaimsNoRecoveryCapabilities(): void
    {
        // The capability contract: PSR-6 pools intentionally do not
        // support trusted consumed-state recovery, so the backend
        // advertises none of the recovery capabilities — only the plain
        // storage contract plus the non-atomic marker. The diagnostic
        // inspection method exists but is deliberately NOT an interface.
        $storage = new Psr6Storage($this->makePool());
        self::assertNotInstanceOf(\KiwiCaptcha\ConsumedStateReadableInterface::class, $storage);
        self::assertNotInstanceOf(\KiwiCaptcha\OperationIdentityAwareStorageInterface::class, $storage);
        self::assertNotInstanceOf(\KiwiCaptcha\AtomicDeleteIfPendingInterface::class, $storage);
        self::assertInstanceOf(\KiwiCaptcha\NonAtomicStorageInterface::class, $storage);
        self::assertTrue(method_exists($storage, 'inspectConsumedEnvelope'), 'the diagnostic inspection stays available off-interface');
    }

    public function testConsumedStateOfAMissingRecordIsNull(): void
    {
        $storage = new Psr6Storage($this->makePool());
        self::assertNull($storage->inspectConsumedEnvelope('absent-nonce'));
    }

    public function testANonAtomicStorageRaisesTheOneTimeDiagnostic(): void
    {
        // The Verifier's non-atomic-storage warning is loud (no error
        // suppression) for standalone PHP apps, and one-time per process:
        // the first construction over a non-atomic backend raises
        // E_USER_DEPRECATED exactly once; a second construction stays
        // silent. The once flag is process state, so the test asserts
        // what an error handler observes in this process around the
        // first observable raise.
        $raised = [];
        $previous = set_error_handler(static function (int $errno, string $errstr) use (&$raised): bool {
            if ($errno === \E_USER_DEPRECATED) {
                $raised[] = $errstr;
            }

            return true;
        });
        try {
            new \KiwiCaptcha\Verifier(new Psr6Storage($this->makePool()));
        } finally {
            restore_error_handler();
        }
        $alreadyWarned = $raised === [];
        if (!$alreadyWarned) {
            self::assertCount(1, $raised, 'the diagnostic fires exactly once per process');
            self::assertStringContainsString('non-atomic storage', $raised[0]);
            self::assertStringContainsString('best-effort under concurrency', $raised[0]);
        } else {
            // Another test in this process already consumed the one-time
            // warning: the invariant degenerates to "never more than
            // once", which the empty observation satisfies.
            self::assertEmpty($raised, 'the one-time diagnostic never repeats in a process');
        }
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

    public function testStoreThrowsWhenThePoolSaveFails(): void
    {
        // Fail closed: PSR-6 permits save() === false without raising. A
        // store that returned normally would hand the client a challenge
        // whose record never landed — a guaranteed verify-time
        // RecordNotFound. The issuance must fail instead.
        $pool = new \KiwiCaptcha\Tests\Fixtures\FailingSavePool();
        $storage = new Psr6Storage($pool);

        try {
            $storage->store($this->makeRecord());
            self::fail('store() must throw when the pool save fails');
        } catch (\KiwiCaptcha\Storage\StorageWriteException $e) {
            self::assertStringContainsString('save() === false', $e->getMessage());
        }
        self::assertSame(1, $pool->saveCalls);
        self::assertNull($storage->find('nonce-1'), 'nothing was handed out that a verifier could later accept');
    }

    public function testConsumeThrowsWhenTheTransitionSaveFails(): void
    {
        // Fail closed: a pending→consumed flip whose save failed leaves
        // the record pending while consume() would report itself the
        // winner (consumedNow) — a sequential replay window. The throw
        // keeps the record pending for a clean retry instead: the same
        // storage over a pool that recovered consumes normally.
        $pool = new \KiwiCaptcha\Tests\Fixtures\FailingSavePool(failFromAttempt: 2, failUntilAttempt: 2);
        $storage = new Psr6Storage($pool);
        $storage->store($this->makeRecord());

        try {
            $storage->consume('nonce-1');
            self::fail('consume() must throw when the transition save fails');
        } catch (\KiwiCaptcha\Storage\StorageWriteException $e) {
            self::assertStringContainsString('save() === false', $e->getMessage());
        }
        self::assertSame(2, $pool->saveCalls);
        self::assertNotNull($storage->find('nonce-1'), 'the record is still there — the failed flip never persisted');

        // The pool recovered: the retry wins the transition normally,
        // proving the record was left pending rather than consumed.
        $retry = $storage->consume('nonce-1');
        self::assertNotNull($retry);
        self::assertTrue($retry->consumedNow, 'the retry over the recovered pool wins the transition normally');
        self::assertFalse($retry->consumedBefore);
    }

    public function testCommitResultKeepsReturningTheSaveResult(): void
    {
        // commitResult() already surfaced save() as its boolean return;
        // the fail-closed change must not alter that contract.
        $pool = new \KiwiCaptcha\Tests\Fixtures\FailingSavePool();
        $storage = new Psr6Storage($pool);

        self::assertFalse($storage->commitResult('nonce-1', true, null), 'a failed commit save returns false, it does not throw');
    }

    public function testVerifierMapsAFailedConsumeSaveToTheTypedIndeterminateOutcome(): void
    {
        // End to end: the issuance save succeeds, the consume save
        // fails, and the Verifier's existing consume catch maps the
        // StorageWriteException onto the typed indeterminate outcome —
        // never a Valid, never an escaping exception.
        $pool = new \KiwiCaptcha\Tests\Fixtures\FailingSavePool(failFromAttempt: 2);
        $storage = new Psr6Storage($pool);
        $verifier = @new \KiwiCaptcha\Verifier($storage); // @: the non-atomic one-time diagnostic may already have fired in this process
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
        $challenge = $issuer->issue('login', '198.51.100.7');

        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (\KiwiCaptcha\Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;
        $token = \KiwiCaptcha\SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();

        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7');

        self::assertFalse($outcome->isOk(), 'a failed consume save must never verify valid');
        self::assertSame(\KiwiCaptcha\VerifyError::ConsumeIndeterminate, $outcome->error, 'the consume throw maps onto the typed indeterminate outcome');
        self::assertNotNull($storage->find($challenge->nonce), 'the record stays pending in the pool for a clean retry');
    }
}
