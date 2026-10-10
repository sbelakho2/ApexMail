<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\AtomicStorageInterface;
use KiwiCaptcha\CancellableStorageInterface;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\ChallengeRuntimeStateKind;
use KiwiCaptcha\Config;
use KiwiCaptcha\ConsumedResult;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\SqliteStorage;
use KiwiCaptcha\Storage\SqliteStorageException;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * SqliteStorage against a real sqlite database: the invariant suite
 * the other bundled backends pass, run unchanged in spirit on the
 * single-node adapter.
 *
 * Coverage: the schema and pragma bootstrap, the one-shot consume
 * contract, the commit, cleanup, cancellation and resume-claim state
 * machines, expiry, and the verifier's replay identity gate. Also
 * fail-closed behavior under corruption and lock contention, plus a
 * forked multi-process consume race proving no double spend.
 */
final class SqliteStorageContractTest extends TestCase
{

    /**
     * The wire nonce of a logical fixture label. The record decode
     * boundary requires the 44-char standard-base64 shape of 32 bytes.
     * That is the strict serde twin. Logical labels map to it here and
     * the storage keys stay readable at the call sites.
     */
    private static function wn(string $logical): string
    {
        return \KiwiCaptcha\Tests\Support\WireFixture::nonce($logical);
    }
    private const ISSUED_AT = 1_800_000_000;

    private const CLIENT_IP = '198.51.100.7';

    private const IDENTITY_A = 'op-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    private const IDENTITY_B = 'op-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

    private int $clock = self::ISSUED_AT;

    protected function setUp(): void
    {
        if (!\in_array('sqlite', \PDO::getAvailableDrivers(), true)) {
            self::markTestSkipped('ext-pdo_sqlite is not available; cannot test SqliteStorage');
        }
    }

    // ── schema, pragmas, construction ─────────────────────────────

    public function testFileDatabaseEnablesWalAndTheBusyTimeout(): void
    {
        $path = $this->tempDbPath();
        $storage = new SqliteStorage($path);

        self::assertSame('wal', $storage->pdo()->query('PRAGMA journal_mode')->fetchColumn());
        self::assertSame(5000, (int) $storage->pdo()->query('PRAGMA busy_timeout')->fetchColumn());
        self::assertFileExists($path.'-wal', 'the wal sidecar file proves the journal mode took hold');
        $this->unlinkDb($path);
    }

    public function testCustomBusyTimeoutIsApplied(): void
    {
        $path = $this->tempDbPath();
        $storage = new SqliteStorage($path, busyTimeoutMs: 1234);

        self::assertSame(1234, (int) $storage->pdo()->query('PRAGMA busy_timeout')->fetchColumn());
        $this->unlinkDb($path);
    }

    public function testSchemaCreationIsIdempotentAcrossReopens(): void
    {
        $path = $this->tempDbPath();
        $first = new SqliteStorage($path);
        $first->store($this->makeRecord('reopen-nonce'));
        unset($first);

        $second = new SqliteStorage($path);
        self::assertSame(1, (int) $second->pdo()->query('PRAGMA user_version')->fetchColumn());
        self::assertNotNull($second->find(self::wn('reopen-nonce')), 'a reopened database keeps its records');
        $this->unlinkDb($path);
    }

    public function testConstructorAcceptsAnOpenPdoConnection(): void
    {
        $path = $this->tempDbPath();
        $pdo = new \PDO('sqlite:'.$path, null, null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]);
        $storage = new SqliteStorage($pdo, ttlMarginSecs: 0);

        $storage->store($this->makeRecord('pdo-arg-nonce'));
        self::assertNotNull($storage->find(self::wn('pdo-arg-nonce')));
        self::assertSame('wal', $pdo->query('PRAGMA journal_mode')->fetchColumn(), 'the pragmas reach the caller connection');
        $this->unlinkDb($path);
    }

    public function testAFutureSchemaVersionIsRefused(): void
    {
        $path = $this->tempDbPath();
        $storage = new SqliteStorage($path);
        unset($storage);
        $pdo = new \PDO('sqlite:'.$path);
        $pdo->exec('PRAGMA user_version = 99');

        try {
            new SqliteStorage($path);
            self::fail('a newer schema version must be refused, never mutated by a downgrade');
        } catch (SqliteStorageException $e) {
            self::assertStringContainsString('newer than', $e->getMessage());
        }
        $this->unlinkDb($path);
    }

    public function testAStampedDatabaseWithoutTheTableIsRefused(): void
    {
        $path = $this->tempDbPath();
        $pdo = new \PDO('sqlite:'.$path);
        $pdo->exec('PRAGMA user_version = 1');

        try {
            new SqliteStorage($path);
            self::fail('a stamped database whose table vanished is damaged and must be refused');
        } catch (SqliteStorageException $e) {
            self::assertStringContainsString('challenge table is missing', $e->getMessage());
        }
        $this->unlinkDb($path);
    }

    public function testAnUnopenablePathFailsClosedWithTheDriverError(): void
    {
        try {
            new SqliteStorage('/no-such-directory/kiwi-test.db');
            self::fail('an unopenable path must surface as the typed storage failure');
        } catch (SqliteStorageException $e) {
            self::assertStringContainsString('opening the database file', $e->getMessage());
        }
    }

    public function testOutOfRangeConstructorArgumentsAreRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new SqliteStorage(':memory:', busyTimeoutMs: -1);
    }

    public function testImplementsTheAtomicPeerCapabilitySet(): void
    {
        $storage = new SqliteStorage(':memory:');
        self::assertInstanceOf(AtomicStorageInterface::class, $storage);
        self::assertInstanceOf(CancellableStorageInterface::class, $storage);
        self::assertInstanceOf(
            \KiwiCaptcha\OperationIdentityAwareStorageInterface::class,
            $storage,
        );
        self::assertInstanceOf(
            \KiwiCaptcha\AtomicDeleteIfPendingInterface::class,
            $storage,
        );
        self::assertInstanceOf(
            \KiwiCaptcha\ChallengeRuntimeStateReadableInterface::class,
            $storage,
        );
        self::assertInstanceOf(
            \KiwiCaptcha\ResumeDerivationClaimInterface::class,
            $storage,
        );
        self::assertInstanceOf(
            \KiwiCaptcha\AuthenticatedResultCommitInterface::class,
            $storage,
        );
        self::assertInstanceOf(
            \KiwiCaptcha\ReplicationBarrierInterface::class,
            $storage,
        );
        // The fence is the documented no-op of the single-node adapter.
        $storage->establishReplicationFence('acceptance point');
        self::addToAssertionCount(1);
    }

    // ── the one-shot consume contract ─────────────────────────────

    public function testStoreFindRoundTripsEveryField(): void
    {
        $storage = $this->memoryStorage();
        $record = new ChallengeRecord(
            nonce: self::wn('full-nonce'),
            scope: 'login',
            bindingTag: 'tag-1',
            issuedAt: self::ISSUED_AT - 30,
            expiresAt: self::ISSUED_AT + 90,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 4,
            t: 2,
            p: 1,
            targetBits: 12,
            salt: \KiwiCaptcha\Tests\Support\WireFixture::SALT,
            prefix: \KiwiCaptcha\Tests\Support\WireFixture::prefix('challenge-string'),
            challenge: 'challenge-string',
            minDurationMs: 250,
            issuedAtNs: 123_456_789_012_345,
            protocolVersion: 3,
            region: 'eu',
            policyVersion: 4,
            requestBinding: 'txn-9',
            issuer: 'prod',
            kid: 2,
            hostname: 'example.test',
            decoyField: 'fax_number',
        );
        $storage->store($record);

        $loaded = $storage->find(self::wn('full-nonce'));

        self::assertNotNull($loaded);
        foreach ([
            'nonce', 'scope', 'bindingTag', 'issuedAt', 'expiresAt',
            'mKib', 't', 'p', 'targetBits', 'salt', 'prefix', 'challenge',
            'minDurationMs', 'issuedAtNs', 'protocolVersion', 'region',
            'policyVersion', 'requestBinding', 'issuer', 'kid', 'hostname',
            'decoyField',
        ] as $field) {
            self::assertSame($record->$field, $loaded->$field, "field $field must round-trip");
        }
        self::assertSame(PoWAlgorithm::Sha256, $loaded->algorithm);
    }

    public function testStoreReplacesAnExistingRecordWithTheSameNonce(): void
    {
        $storage = $this->memoryStorage();
        $storage->store($this->makeRecord('same-nonce', expiresAt: self::ISSUED_AT + 60));
        $storage->store($this->makeRecord('same-nonce', expiresAt: self::ISSUED_AT + 300));

        $loaded = $storage->find(self::wn('same-nonce'));
        self::assertSame(self::ISSUED_AT + 300, $loaded?->expiresAt, 'the second store replaces the first');
        self::assertSame(1, $this->rowCount($storage), 'one nonce maps to exactly one row');
    }

    public function testConsumeIsExactlyOnceAndRetainsTheRecord(): void
    {
        $storage = $this->memoryStorage();
        $storage->store($this->makeRecord('consume-once'));

        $first = $storage->consume(self::wn('consume-once'));
        $second = $storage->consume(self::wn('consume-once'));

        self::assertNotNull($first);
        self::assertTrue($first->consumedNow);
        self::assertFalse($first->consumedBefore);
        self::assertNull($first->consumedResult, 'the winner sees no committed result yet');
        self::assertNotNull($second, 'the replay reads the retained consumed state');
        self::assertFalse($second->consumedNow);
        self::assertTrue($second->consumedBefore);
        self::assertNotNull($storage->find(self::wn('consume-once')), 'the consumed record is retained until its retention ends');
    }

    public function testConsumeOfAMissingNonceIsNull(): void
    {
        $storage = $this->memoryStorage();

        self::assertNull($storage->consume(self::wn('never-stored')));
        self::assertNull($storage->find(self::wn('never-stored')));
    }

    public function testCommitResultIsOneShotAndRidesOnLaterConsumes(): void
    {
        $storage = $this->memoryStorage();
        $storage->store($this->makeRecord('commit-once'));
        $storage->consume(self::wn('commit-once'));

        self::assertTrue($storage->commitResult(self::wn('commit-once'), false, null));
        self::assertFalse($storage->commitResult(self::wn('commit-once'), true, 'other'), 'a resultless consumed row accepts exactly one result');

        $retry = $storage->consume(self::wn('commit-once'));
        self::assertNotNull($retry?->consumedResult);
        self::assertFalse($retry->consumedResult->valid, 'the committed invalid outcome replays without re-deriving');
        self::assertNull($retry->consumedResult->binding);
    }

    public function testCommitResultIsRefusedForPendingMissingAndCancelledRows(): void
    {
        $storage = $this->memoryStorage();
        $storage->store($this->makeRecord('pending-commit'));
        self::assertFalse($storage->commitResult(self::wn('pending-commit'), true, null), 'a pending row never takes a result');

        self::assertFalse($storage->commitResult(self::wn('missing-commit'), true, null));

        $storage->store($this->makeRecord('cancelled-commit'));
        $storage->cancel(self::wn('cancelled-commit'));
        self::assertFalse($storage->commitResult(self::wn('cancelled-commit'), true, null), 'a cancelled row never takes a result');
    }

    public function testConsumedStateReadsTheRetainedEvidenceWithoutATransition(): void
    {
        $storage = $this->memoryStorage();
        $storage->store($this->makeRecord('state-read'));

        self::assertNull($storage->consumedState(self::wn('state-read')), 'a pending row has no consumed state');
        self::assertNull($storage->consumedState(self::wn('missing-read')));

        $storage->consumeWithOperationIdentity(self::wn('state-read'), self::IDENTITY_A);
        $storage->commitResult(self::wn('state-read'), true, 'b-1');

        $consumed = $storage->consumedState(self::wn('state-read'));
        self::assertNotNull($consumed);
        self::assertTrue($consumed->consumedBefore);
        self::assertFalse($consumed->consumedNow);
        self::assertSame(self::IDENTITY_A, $consumed->operationIdentity);
        self::assertTrue($consumed->consumedResult?->valid);
        self::assertSame('b-1', $consumed->consumedResult?->binding);
    }

    public function testConsumeWithOperationIdentityRecordsTheWinnerIdentity(): void
    {
        $storage = $this->memoryStorage();
        $storage->store($this->makeRecord('identity-consume'));

        $winner = $storage->consumeWithOperationIdentity(self::wn('identity-consume'), self::IDENTITY_A);
        self::assertNotNull($winner);
        self::assertTrue($winner->consumedNow);
        self::assertSame(self::IDENTITY_A, $winner->operationIdentity);
        self::assertSame(self::IDENTITY_A, $storage->consumedState(self::wn('identity-consume'))?->operationIdentity);
    }

    public function testPlainConsumeRecordsNullIdentity(): void
    {
        $storage = $this->memoryStorage();
        $storage->store($this->makeRecord('plain-identity'));
        $storage->consume(self::wn('plain-identity'));

        self::assertNull($storage->consumedState(self::wn('plain-identity'))?->operationIdentity);
    }

    public function testAMalformedIdentityIsRejectedAndTheRowStaysPending(): void
    {
        $storage = $this->memoryStorage();
        $storage->store($this->makeRecord('bad-identity'));

        try {
            $storage->consumeWithOperationIdentity(self::wn('bad-identity'), 'not valid!');
            self::fail('a malformed identity must be rejected at the storage boundary');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('1..128 bytes', $e->getMessage());
        }

        self::assertSame('pending', $this->stateColumn($storage, 'bad-identity'), 'the refused consume leaves the row pending');
        $lateWinner = $storage->consume(self::wn('bad-identity'));
        self::assertTrue($lateWinner?->consumedNow, 'the challenge stays redeemable after the refusal');
    }

    public function testAPendingRowCarryingTerminalFieldsIsRefusedAsMissing(): void
    {
        // The pending-envelope guard: a row flipped to pending while it
        // already carries a result, an identity or a claim lease is a
        // forged rewrite, and the consume reports it missing.
        $storage = $this->memoryStorage();
        $storage->store($this->makeRecord('forged-pending'));
        $storage->pdo()->exec(
            "UPDATE kiwicaptcha_challenge_records SET consumed_result_json = '{\"valid\":true,\"binding\":null}' WHERE nonce = '". self::wn('forged-pending') ."'"
        );

        self::assertNull($storage->consume(self::wn('forged-pending')), 'the forged pending row reports missing');
        self::assertSame(ChallengeRuntimeStateKind::Pending, $storage->runtimeState(self::wn('forged-pending'))->kind, 'the runtime state still classifies the snapshot');
    }

    public function testARuntimeStateSnapshotClassifiesEveryState(): void
    {
        $storage = $this->memoryStorage();
        self::assertSame(ChallengeRuntimeStateKind::Missing, $storage->runtimeState(self::wn('absent'))->kind);

        $storage->store($this->makeRecord('rt-pending'));
        self::assertSame(ChallengeRuntimeStateKind::Pending, $storage->runtimeState(self::wn('rt-pending'))->kind);

        $storage->consume(self::wn('rt-pending'));
        $state = $storage->runtimeState(self::wn('rt-pending'));
        self::assertSame(ChallengeRuntimeStateKind::Consumed, $state->kind);
        self::assertTrue($state->consumed?->consumedBefore);

        $storage->store($this->makeRecord('rt-cancelled'));
        $storage->cancel(self::wn('rt-cancelled'));
        self::assertSame(ChallengeRuntimeStateKind::Cancelled, $storage->runtimeState(self::wn('rt-cancelled'))->kind);
    }

    // ── the fused cleanup and cancellation transitions ────────────

    public function testDeleteIfPendingDecidesEveryStateAtomically(): void
    {
        $storage = $this->memoryStorage();

        self::assertSame('missing', $storage->deleteIfPending(self::wn('cleanup-absent'))->state);

        $storage->store($this->makeRecord('cleanup-pending'));
        self::assertSame('deleted-pending', $storage->deleteIfPending(self::wn('cleanup-pending'))->state);
        self::assertNull($storage->find(self::wn('cleanup-pending')), 'the one-shot cheap-failure policy deletes the pending row');

        $storage->store($this->makeRecord('cleanup-consumed'));
        $storage->consumeWithOperationIdentity(self::wn('cleanup-consumed'), self::IDENTITY_A);
        $storage->commitResult(self::wn('cleanup-consumed'), true, 'kept');
        $kept = $storage->deleteIfPending(self::wn('cleanup-consumed'));
        self::assertSame('consumed', $kept->state);
        self::assertTrue($kept->consumed?->consumedBefore);
        self::assertSame('kept', $kept->consumed?->consumedResult?->binding);
        self::assertSame(self::IDENTITY_A, $kept->consumed?->operationIdentity);
        self::assertNotNull($storage->find(self::wn('cleanup-consumed')), 'the committed recovery evidence is never erased');

        $storage->store($this->makeRecord('cleanup-cancelled'));
        $storage->cancel(self::wn('cleanup-cancelled'));
        self::assertSame('cancelled', $storage->deleteIfPending(self::wn('cleanup-cancelled'))->state);
        self::assertNotNull($storage->find(self::wn('cleanup-cancelled')), 'a cancelled row is dead but retained');
    }

    public function testACorruptRowIsReportedCorruptAndLeftUntouched(): void
    {
        $storage = $this->memoryStorage();
        $storage->store($this->makeRecord('corrupt-row'));
        $storage->pdo()->exec("UPDATE kiwicaptcha_challenge_records SET record_json = 'not-json' WHERE nonce = '". self::wn('corrupt-row')."'");

        $result = $storage->deleteIfPending(self::wn('corrupt-row'));
        self::assertSame('corrupt', $result->state);
        self::assertSame('pending', $this->stateColumn($storage, 'corrupt-row'), 'the cleanup never mutates a row it cannot classify');
    }

    public function testDeleteRemovesTheRow(): void
    {
        $storage = $this->memoryStorage();
        $storage->store($this->makeRecord('delete-me'));
        $storage->delete(self::wn('delete-me'));

        self::assertNull($storage->find(self::wn('delete-me')));
        self::assertNull($storage->consume(self::wn('delete-me')));
    }

    public function testCancelLifecycle(): void
    {
        $storage = $this->memoryStorage();

        self::assertNull($storage->cancel(self::wn('cancel-absent')), 'a never-issued nonce cancels idempotently as null');

        $storage->store($this->makeRecord('cancel-pending'));
        $fresh = $storage->cancel(self::wn('cancel-pending'));
        self::assertSame('cancelled-now', $fresh?->state);
        self::assertTrue($fresh?->wasCancelledNow());
        self::assertSame('cancelled', $storage->cancel(self::wn('cancel-pending'))?->state, 'the retry is idempotent');

        $storage->store($this->makeRecord('cancel-consumed'));
        $storage->consume(self::wn('cancel-consumed'));
        self::assertSame('consumed', $storage->cancel(self::wn('cancel-consumed'))?->state, 'a finalized record is never cancelled');
        self::assertSame('consumed', $this->stateColumn($storage, 'cancel-consumed'));
    }

    public function testACancelledRecordIsUnconsumableAndNeverRecoverable(): void
    {
        $storage = $this->memoryStorage();
        $storage->store($this->makeRecord('dead-row'));
        $storage->cancel(self::wn('dead-row'));

        self::assertNull($storage->consume(self::wn('dead-row')));
        self::assertNull($storage->consumeWithOperationIdentity(self::wn('dead-row'), self::IDENTITY_A));
        self::assertNull($storage->consumedState(self::wn('dead-row')));
        self::assertFalse($storage->commitResult(self::wn('dead-row'), true, null));
        self::assertNull($storage->claimResumeDerivation(self::wn('dead-row')));
        self::assertNotNull($storage->find(self::wn('dead-row')), 'the dead row is retained until its retention ends');
    }

    // ── expiry and retention ──────────────────────────────────────

    public function testAnExpiredRowIsAbsentOnEveryPath(): void
    {
        $storage = $this->memoryStorage(ttlMarginSecs: 0);
        $storage->store($this->makeRecord('expired-row', expiresAt: $this->clock + 10));
        $this->clock += 10;

        self::assertNull($storage->find(self::wn('expired-row')));
        self::assertNull($storage->consume(self::wn('expired-row')));
        self::assertNull($storage->consumedState(self::wn('expired-row')));
        self::assertSame(ChallengeRuntimeStateKind::Missing, $storage->runtimeState(self::wn('expired-row'))->kind);
        self::assertSame('missing', $storage->deleteIfPending(self::wn('expired-row'))->state);
        self::assertNull($storage->cancel(self::wn('expired-row')));
        self::assertFalse($storage->commitResult(self::wn('expired-row'), true, null));
    }

    public function testTheRetentionMarginExtendsReadabilityPastSignedExpiry(): void
    {
        $storage = $this->memoryStorage(ttlMarginSecs: 30);
        $storage->store($this->makeRecord('margin-row', expiresAt: $this->clock + 100));
        $this->clock += 110;

        self::assertNotNull($storage->find(self::wn('margin-row')), 'the retained evidence outlives the signed expiry by the margin');
        $consumed = $storage->consume(self::wn('margin-row'));
        self::assertTrue($consumed?->consumedNow, 'the margin window keeps the one-shot transition open');

        $this->clock += 30;
        self::assertNull($storage->consumedState(self::wn('margin-row')), 'past the margin the retained evidence is gone');
    }

    public function testStoreSweepsExpiredRowsThroughTheExpiryIndex(): void
    {
        $storage = $this->memoryStorage(ttlMarginSecs: 0);
        $storage->store($this->makeRecord('sweep-me', expiresAt: $this->clock + 5));
        $this->clock += 5;
        $storage->store($this->makeRecord('sweep-keeper', expiresAt: $this->clock + 100));

        self::assertSame(1, $this->rowCount($storage), 'the sweep removed the expired row');
        self::assertNull($storage->find(self::wn('sweep-me')));
    }

    // ── the resume-derivation claim ───────────────────────────────

    public function testTheClaimRequiresAConsumedResultlessRow(): void
    {
        $storage = $this->memoryStorage();

        $storage->store($this->makeRecord('claim-pending'));
        self::assertNull($storage->claimResumeDerivation(self::wn('claim-pending')), 'a pending row is refused');
        self::assertNull($storage->claimResumeDerivation(self::wn('claim-absent')));

        $storage->consume(self::wn('claim-pending'));
        $owner = $storage->claimResumeDerivation(self::wn('claim-pending'));
        self::assertNotNull($owner);
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/D', $owner);

        $storage->commitResult(self::wn('claim-pending'), true, null);
        self::assertNull($storage->claimResumeDerivation(self::wn('claim-pending')), 'a committed row is refused');
    }

    public function testALiveClaimExcludesASecondClaimAndExpires(): void
    {
        $storage = $this->memoryStorage();
        $storage->store($this->makeRecord('claim-live'));
        $storage->consume(self::wn('claim-live'));

        $first = $storage->claimResumeDerivation(self::wn('claim-live'), 60);
        self::assertNotNull($first);
        self::assertNull($storage->claimResumeDerivation(self::wn('claim-live'), 60), 'a live lease blocks every other claimer');

        $this->clock += 61;
        $second = $storage->claimResumeDerivation(self::wn('claim-live'), 60);
        self::assertNotSame($first, $second, 'the expired lease is re-claimable by a fresh owner');
    }

    public function testClaimTtlBelowOneSecondIsRejected(): void
    {
        $storage = $this->memoryStorage();
        $this->expectException(\InvalidArgumentException::class);
        $storage->claimResumeDerivation(self::wn('whatever'), 0);
    }

    public function testTheReleaseIsACompareAndDelete(): void
    {
        $storage = $this->memoryStorage();
        $storage->store($this->makeRecord('claim-release'));
        $storage->consume(self::wn('claim-release'));
        $owner = $storage->claimResumeDerivation(self::wn('claim-release'));
        self::assertNotNull($owner);

        $other = str_repeat('c', 32);
        self::assertFalse($storage->releaseResumeDerivation(self::wn('claim-release'), $other), 'a different token never clears the lease');

        self::assertTrue($storage->releaseResumeDerivation(self::wn('claim-release'), $owner));
        self::assertFalse($storage->releaseResumeDerivation(self::wn('claim-release'), $owner), 'the cleared lease stays cleared');

        $reclaimed = $storage->claimResumeDerivation(self::wn('claim-release'));
        self::assertNotNull($reclaimed, 'a released lease is immediately re-claimable');
    }

    public function testAMalformedOwnerIsRejectedAtTheBoundary(): void
    {
        $storage = $this->memoryStorage();
        $storage->store($this->makeRecord('bad-owner'));
        $storage->consume(self::wn('bad-owner'));

        try {
            $storage->releaseResumeDerivation(self::wn('bad-owner'), 'nothex');
            self::fail('a malformed owner token must be rejected');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('32 lowercase hex', $e->getMessage());
        }
    }

    public function testTheResumeCommitFencesOnTheLiveClaim(): void
    {
        $storage = $this->memoryStorage();
        $storage->store($this->makeRecord('resume-commit'));
        $storage->consume(self::wn('resume-commit'));

        $owner = $storage->claimResumeDerivation(self::wn('resume-commit'), 60);
        self::assertNotNull($owner);
        self::assertFalse($storage->commitResultResume(self::wn('resume-commit'), true, 'win', str_repeat('d', 32)), 'a foreign owner never commits');

        self::assertTrue($storage->commitResultResume(self::wn('resume-commit'), true, 'win', $owner));
        self::assertSame('win', $storage->consumedState(self::wn('resume-commit'))?->consumedResult?->binding);
        self::assertNull($storage->claimResumeDerivation(self::wn('resume-commit')), 'the commit cleared the lease and the result now fences');

        $storage->store($this->makeRecord('resume-expired'));
        $storage->consume(self::wn('resume-expired'));
        $staleOwner = $storage->claimResumeDerivation(self::wn('resume-expired'), 60);
        $this->clock += 61;
        self::assertFalse($storage->commitResultResume(self::wn('resume-expired'), true, null, $staleOwner), 'a lease that expired mid-derivation never commits');
    }

    public function testTheAuthenticatedCommitsStoreTheServerStateMac(): void
    {
        $storage = $this->memoryStorage();
        $storage->store($this->makeRecord('mac-plain'));
        $storage->consume(self::wn('mac-plain'));
        $mac = hash_hmac('sha256', 'body', 'key');
        self::assertTrue($storage->commitAuthenticatedResult(self::wn('mac-plain'), new ConsumedResult(true, 'b', $mac)));
        self::assertSame($mac, $storage->consumedState(self::wn('mac-plain'))?->consumedResult?->mac);

        $storage->store($this->makeRecord('mac-resume'));
        $storage->consume(self::wn('mac-resume'));
        $owner = $storage->claimResumeDerivation(self::wn('mac-resume'));
        self::assertTrue($storage->commitAuthenticatedResultResume(self::wn('mac-resume'), new ConsumedResult(false, null, $mac), $owner));
        $result = $storage->consumedState(self::wn('mac-resume'))?->consumedResult;
        self::assertFalse($result?->valid);
        self::assertSame($mac, $result?->mac);
    }

    public function testACorruptCommittedResultDegradesToAbsent(): void
    {
        $storage = $this->memoryStorage();
        $storage->store($this->makeRecord('bad-result'));
        $storage->consume(self::wn('bad-result'));
        $storage->commitResult(self::wn('bad-result'), true, 'x');
        $storage->pdo()->exec("UPDATE kiwicaptcha_challenge_records SET consumed_result_json = '{\"valid\":\"yes\"}' WHERE nonce = '". self::wn('bad-result')."'");

        self::assertNull($storage->consumedState(self::wn('bad-result'))?->consumedResult, 'a malformed stored result is never trusted');
    }

    // ── the verifier invariants on this backend ───────────────────

    /** @return array{0: SqliteStorage, 1: ChallengeRecord, 2: string} */
    private function issueAndSolve(?string $requestBinding = null): array
    {
        $storage = $this->memoryStorage();
        $issuer = new Issuer(
            new Config(secretKey: Vectors::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0),
            $storage,
            now: fn (): int => $this->clock,
        );
        $challenge = $issuer->issue('login', self::CLIENT_IP, $requestBinding);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        return [$storage, $record, \KiwiCaptcha\SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode()];
    }

    private function verifier(SqliteStorage $storage): Verifier
    {
        return new Verifier($storage, now: fn (): int => $this->clock);
    }

    public function testAVerificationIsSingleUseAndItsReplayIsRefused(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();
        $verifier = $this->verifier($storage);

        $first = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertTrue($first->isOk(), sprintf('the fresh verification must pass, got %s', $first->code()));

        $second = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertFalse($second->isOk(), 'a second use of the same token must never pass');
        self::assertSame(VerifyError::AlreadyConsumed, $second->error);
        self::assertNotNull($storage->find($record->nonce), 'the consumed evidence stays readable');
    }

    public function testTheStoredSuccessReplaysOnlyToTheExactOperation(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();
        $verifier = $this->verifier($storage);

        $first = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP, operationIdentity: self::IDENTITY_A);
        self::assertTrue($first->isOk());
        self::assertFalse($first->fromStoredResult);

        $retry = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP, operationIdentity: self::IDENTITY_A);
        self::assertTrue($retry->isOk(), 'the exact operation replays the stored success');
        self::assertTrue($retry->fromStoredResult);

        $other = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP, operationIdentity: self::IDENTITY_B);
        self::assertSame(VerifyError::AlreadyConsumed, $other->error, 'one solve, one grant');

        $anonymous = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::AlreadyConsumed, $anonymous->error);
    }

    public function testAStoredInvalidOutcomeReplaysToAnyCaller(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();
        $saltBytes = base64_decode($record->salt, true);
        $wrong = 0;
        while (Verifier::leadingZeroBits(hash('sha256', $record->prefix.$wrong.$saltBytes, true)) >= $record->targetBits) {
            ++$wrong;
        }
        $wrongToken = \KiwiCaptcha\SolutionToken::create($record->nonce, $wrong, 5000, [])->encode();

        $verifier = $this->verifier($storage);
        self::assertSame(VerifyError::InsufficientWork, $verifier->verify($wrongToken, Vectors::SECRET, 'login', self::CLIENT_IP)->error);

        foreach ([null, self::IDENTITY_A, self::IDENTITY_B] as $identity) {
            $replay = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP, operationIdentity: $identity);
            self::assertSame(VerifyError::InsufficientWork, $replay->error, 'the deterministic failure replays to every caller');
        }
    }

    public function testACheapFailureDeletesOnlyThePendingRow(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();
        $verifier = $this->verifier($storage);

        $outcome = $verifier->verify($token, Vectors::SECRET, 'checkout', self::CLIENT_IP);
        self::assertSame(VerifyError::WrongScope, $outcome->error);
        self::assertNull($storage->find($record->nonce), 'the pending row failing a cheap check is burned');
    }

    public function testACancelledChallengeFailsVerificationClosed(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();
        $storage->cancel($record->nonce);

        $outcome = $this->verifier($storage)->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertFalse($outcome->isOk());
        self::assertSame(VerifyError::RecordNotFound, $outcome->error, 'a cancelled challenge is pinned to the deterministic missing verdict');
    }

    public function testAnExpiredChallengeFailsClosed(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();
        $this->clock += 121;

        $outcome = $this->verifier($storage)->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::Expired, $outcome->error);
    }

    public function testTheResultlessResumeCommitsThroughTheClaim(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();

        // Simulate the crash window: the identity-bearing consume
        // landed, the result commit never did.
        $consumed = $storage->consumeWithOperationIdentity($record->nonce, self::IDENTITY_A);
        self::assertTrue($consumed?->consumedNow);
        self::assertNull($consumed->consumedResult);
        $probe = $storage->claimResumeDerivation($record->nonce);
        self::assertNotNull($probe, 'the resultless row is claimable');
        self::assertTrue($storage->releaseResumeDerivation($record->nonce, $probe), 'the probe releases the lease for the verifier to claim');

        $outcome = $this->verifier($storage)->resumeConsumedOperation($token, Vectors::SECRET, self::IDENTITY_A, 'login', self::CLIENT_IP);
        self::assertTrue($outcome->isOk(), sprintf('the identity-proven resume must derive and commit, got %s', $outcome->code()));

        $after = $storage->consumedState($record->nonce);
        self::assertTrue($after?->consumedResult?->valid, 'the resume committed the deterministic outcome');
        self::assertNull($storage->claimResumeDerivation($record->nonce), 'the lease is gone after the commit');

        $replay = $this->verifier($storage)->resumeConsumedOperation($token, Vectors::SECRET, self::IDENTITY_A, 'login', self::CLIENT_IP);
        self::assertTrue($replay->isOk(), 'the committed recovery is idempotent');
    }

    public function testAResumeWithTheWrongIdentityIsRefused(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();
        $storage->consumeWithOperationIdentity($record->nonce, self::IDENTITY_A);

        $outcome = $this->verifier($storage)->resumeConsumedOperation($token, Vectors::SECRET, self::IDENTITY_B, 'login', self::CLIENT_IP);
        self::assertFalse($outcome->isOk(), 'an unproven operation never resumes another operation derivation');
    }

    // ── fail-closed under damage and contention ───────────────────

    public function testADroppedTableFailsEveryVerifyPathClosed(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();
        $verifier = $this->verifier($storage);
        $storage->pdo()->exec('DROP TABLE kiwicaptcha_challenge_records');

        try {
            $storage->consume($record->nonce);
            self::fail('a consume against a missing table must throw');
        } catch (SqliteStorageException $e) {
            self::assertStringContainsString('pending-to-consumed transition', $e->getMessage());
        }

        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertFalse($outcome->isOk(), 'a storage failure can never surface as a pass');
        self::assertSame(VerifyError::StorageUnavailable, $outcome->error, 'the failure maps to the same unavailable-store verdict the Redis path gives');
    }

    public function testALockHeldPastTheTimeoutFailsClosedWithTheRemedy(): void
    {
        $path = $this->tempDbPath();
        $issuer = new SqliteStorage($path, ttlMarginSecs: 60);
        $issuer->store($this->makeRecord('locked-row', expiresAt: self::ISSUED_AT + 300));
        $blocked = new SqliteStorage($path, busyTimeoutMs: 120, ttlMarginSecs: 60);

        $blocker = new \PDO('sqlite:'.$path, null, null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]);
        $blocker->exec('PRAGMA busy_timeout = 5000');
        $blocker->exec('BEGIN IMMEDIATE');

        try {
            $blocked->consume(self::wn('locked-row'));
            self::fail('a write lock held past the busy timeout must fail closed');
        } catch (SqliteStorageException $e) {
            self::assertStringContainsString('write lock stayed held past the busy timeout', $e->getMessage());
            self::assertStringContainsString('raise busyTimeoutMs', $e->getMessage());
        }

        $blocker->exec('ROLLBACK');
        $winner = $blocked->consume(self::wn('locked-row'));
        self::assertTrue($winner?->consumedNow, 'the release restores the transition, still exactly once');
        $this->unlinkDb($path);
    }

    public function testALockHeldPastTheTimeoutFailsVerificationClosed(): void
    {
        $path = $this->tempDbPath();
        $storage = new SqliteStorage($path, ttlMarginSecs: 60);
        [$record, $token] = $this->issueOnFile($storage);

        $blocker = new \PDO('sqlite:'.$path, null, null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]);
        $blocker->exec('PRAGMA busy_timeout = 5000');
        $blocker->exec('BEGIN IMMEDIATE');

        $outcome = (new Verifier($storage))->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertFalse($outcome->isOk());
        // A lost consume response is intrinsically ambiguous, and the
        // verifier reports the same fail-closed verdict a lost Redis
        // consume reply produces: the indeterminate retryable state.
        self::assertSame(VerifyError::ConsumeIndeterminate, $outcome->error);

        $blocker->exec('ROLLBACK');
        $this->unlinkDb($path);
    }

    public function testACorruptDatabaseFileFailsConstructionClosed(): void
    {
        $path = $this->tempDbPath();
        $storage = new SqliteStorage($path);
        $storage->store($this->makeRecord('to-corrupt', expiresAt: self::ISSUED_AT + 300));
        unset($storage);
        clearstatcache();
        self::assertFileDoesNotExist($path.'-wal', 'closing the last connection checkpoints the wal');

        file_put_contents($path, random_bytes(8192));
        try {
            new SqliteStorage($path);
            self::fail('a corrupt file must never open as an empty usable store');
        } catch (SqliteStorageException $e) {
            self::assertStringContainsString('schema initialization', $e->getMessage());
        }
        $this->unlinkDb($path);
    }

    public function testACorruptPayloadRowFailsVerificationClosedAsMissing(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();
        $storage->pdo()->exec("UPDATE kiwicaptcha_challenge_records SET record_json = 'garbage' WHERE nonce = '".$record->nonce."'");

        $outcome = $this->verifier($storage)->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertFalse($outcome->isOk(), 'a corrupt row can never verify');
        self::assertSame(VerifyError::RecordNotFound, $outcome->error);
    }

    // ── concurrency: the no-double-spend proofs ───────────────────

    public function testTwoConnectionsSeeCommittedStateAndStaySingleUse(): void
    {
        $path = $this->tempDbPath();
        $first = new SqliteStorage($path, ttlMarginSecs: 60);
        $first->store($this->makeRecord('two-conn', expiresAt: self::ISSUED_AT + 300));

        // A second connection on the same file: its consume observes
        // the committed consumed state of the first, under the wal
        // snapshot isolation, and never wins a second transition.
        $second = new SqliteStorage($path, ttlMarginSecs: 60);
        $winner = $first->consume(self::wn('two-conn'));
        $loser = $second->consume(self::wn('two-conn'));

        self::assertTrue($winner?->consumedNow);
        self::assertFalse($loser?->consumedNow);
        self::assertTrue($loser?->consumedBefore, 'the second connection reads the committed consumed state');
        self::assertTrue($second->commitResult(self::wn('two-conn'), true, 'from-second'), 'the retained row accepts the commit from either connection');
        $this->unlinkDb($path);
    }

    public function testForkedConsumersCannotDoubleSpend(): void
    {
        if (!\function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is unavailable; the forked race needs real processes');
        }
        $path = $this->tempDbPath();
        $seed = new SqliteStorage($path, ttlMarginSecs: 60);
        $seed->store($this->makeRecord('fork-nonce', expiresAt: self::ISSUED_AT + 300));
        unset($seed);

        $codes = $this->forkWorkers($path, 8, 'consume');
        sort($codes);

        self::assertSame([0, 1, 1, 1, 1, 1, 1, 1], $codes, 'exactly one consume winner, every loser reads the consumed state, no failures');
        $verifier = new SqliteStorage($path, ttlMarginSecs: 60);
        $final = $verifier->consume(self::wn('fork-nonce'));
        self::assertTrue($final?->consumedBefore);
        self::assertSame('fork-win', $final?->consumedResult?->binding, 'the single winner committed exactly one result');
        $this->unlinkDb($path);
    }

    public function testForkedIdentityConsumersRecordExactlyTheWinnersIdentity(): void
    {
        if (!\function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is unavailable; the forked race needs real processes');
        }
        $path = $this->tempDbPath();
        $seed = new SqliteStorage($path, ttlMarginSecs: 60);
        $seed->store($this->makeRecord('fork-identity', expiresAt: self::ISSUED_AT + 300));
        unset($seed);

        $codes = $this->forkWorkers($path, 6, 'identity');
        $winners = array_filter($codes, static fn (int $c): bool => $c === 0);

        self::assertCount(1, $winners, 'exactly one identity-bearing consume wins');

        $final = (new SqliteStorage($path, ttlMarginSecs: 60))->consumedState(self::wn('fork-identity'));
        self::assertNotNull($final?->operationIdentity);
        self::assertMatchesRegularExpression('/^op-fork-[0-9]+$/', $final->operationIdentity, 'the stored identity is provably the actual winner identity');
        $this->unlinkDb($path);
    }

    public function testForkedConsumeVersusCancelNeverRedeemsACancelledRecord(): void
    {
        if (!\function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is unavailable; the forked race needs real processes');
        }
        $path = $this->tempDbPath();
        $seed = new SqliteStorage($path, ttlMarginSecs: 60);
        $seed->store($this->makeRecord('fork-mixed', expiresAt: self::ISSUED_AT + 300));
        unset($seed);

        $codes = $this->forkWorkers($path, 8, 'mixed');
        $consumeWins = array_filter($codes, static fn (int $c): bool => $c === 0);
        $consumeNulls = array_filter($codes, static fn (int $c): bool => $c === 2);
        $cancelFresh = array_filter($codes, static fn (int $c): bool => $c === 10);
        $errors = array_filter($codes, static fn (int $c): bool => $c === 3 || $c === 5);

        self::assertSame([], array_values($errors), 'no worker failed on lock contention');
        self::assertLessThanOrEqual(1, \count($consumeWins), 'at most one consume winner exists in every interleaving');
        // Either exactly one consume won and the cancellers all saw the
        // finalized record, or a cancellation won first and every
        // consumer read the dead record as missing.
        if (\count($consumeWins) === 1) {
            self::assertSame([], array_values($cancelFresh), 'a consume winner finalizes the record before every cancellation');
            $state = (new SqliteStorage($path, ttlMarginSecs: 60))->runtimeState(self::wn('fork-mixed'));
            self::assertSame(ChallengeRuntimeStateKind::Consumed, $state->kind);
        } else {
            self::assertCount(1, $cancelFresh, 'with no consume winner exactly one cancellation flipped the record');
            self::assertCount(4, $consumeNulls, 'every consumer read the cancelled record as missing');
            $state = (new SqliteStorage($path, ttlMarginSecs: 60))->runtimeState(self::wn('fork-mixed'));
            self::assertSame(ChallengeRuntimeStateKind::Cancelled, $state->kind);
        }
        $this->unlinkDb($path);
    }

    public function testForkedClaimersElectExactlyOneDerivationOwner(): void
    {
        if (!\function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is unavailable; the forked race needs real processes');
        }
        $path = $this->tempDbPath();
        $seed = new SqliteStorage($path, ttlMarginSecs: 60);
        $seed->store($this->makeRecord('fork-claim', expiresAt: self::ISSUED_AT + 300));
        $seed->consume(self::wn('fork-claim'));
        unset($seed);

        $codes = $this->forkWorkers($path, 6, 'claim');
        $winners = array_filter($codes, static fn (int $c): bool => $c === 0);
        $refused = array_filter($codes, static fn (int $c): bool => $c === 1);

        self::assertCount(1, $winners, 'exactly one recovery holds the derivation lease');
        self::assertCount(5, $refused, 'every other recovery is refused while the lease is live');
        $this->unlinkDb($path);
    }

    /**
     * Fork N workers; every child opens its own connection, jitter its
     * start, run one transition and report the outcome through its
     * exit code. Children never print and never touch the parent
     * storage; the parent collects the codes after every child exits.
     *
     * @return list<int> the exit code of each worker, parent order
     */
    private function forkWorkers(string $path, int $count, string $mode): array
    {
        $pids = [];
        for ($i = 0; $i < $count; $i++) {
            $pid = pcntl_fork();
            if ($pid === 0) {
                exit($this->runWorker($path, $i, $mode));
            }
            $pids[] = $pid;
        }
        $codes = [];
        foreach ($pids as $workerPid) {
            pcntl_waitpid($workerPid, $status);
            $codes[] = pcntl_wexitstatus($status);
        }

        return $codes;
    }

    /** The worker body; the returned int becomes the exit code. */
    private function runWorker(string $path, int $index, string $mode): int
    {
        try {
            usleep(random_int(0, 4000));
            $storage = new SqliteStorage($path, busyTimeoutMs: 15000, ttlMarginSecs: 60);
            if ($mode === 'consume') {
                $consumed = $storage->consume(self::wn('fork-nonce'));
                if ($consumed === null) {
                    return 2;
                }

                return $consumed->consumedNow
                    ? ($storage->commitResult(self::wn('fork-nonce'), true, 'fork-win') ? 0 : 5)
                    : 1;
            }
            if ($mode === 'identity') {
                $identity = 'op-fork-'.$index;
                $consumed = $storage->consumeWithOperationIdentity(self::wn('fork-identity'), $identity);

                return $consumed?->consumedNow === true ? 0 : 1;
            }
            if ($mode === 'claim') {
                return $storage->claimResumeDerivation(self::wn('fork-claim')) !== null ? 0 : 1;
            }
            // The mixed consume-versus-cancel storm.
            if ($index % 2 === 0) {
                $consumed = $storage->consume(self::wn('fork-mixed'));
                if ($consumed === null) {
                    return 2;
                }

                return $consumed->consumedNow ? 0 : 1;
            }
            $cancelled = $storage->cancel(self::wn('fork-mixed'));

            return $cancelled?->wasCancelledNow() === true ? 10 : 11;
        } catch (\Throwable) {
            return 3;
        }
    }

    // ── helpers ───────────────────────────────────────────────────

    private function memoryStorage(int $ttlMarginSecs = 60): SqliteStorage
    {
        return new SqliteStorage(
            ':memory:',
            ttlMarginSecs: $ttlMarginSecs,
            now: fn (): int => $this->clock,
        );
    }

    private function makeRecord(string $nonce, ?int $expiresAt = null): ChallengeRecord
    {
        return new ChallengeRecord(
            nonce: self::wn($nonce),
            scope: 'login',
            bindingTag: 'tag-1',
            issuedAt: self::ISSUED_AT,
            expiresAt: $expiresAt ?? self::ISSUED_AT + 120,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 0,
            t: 1,
            p: 1,
            targetBits: 8,
            salt: \KiwiCaptcha\Tests\Support\WireFixture::SALT,
            prefix: \KiwiCaptcha\Tests\Support\WireFixture::prefix('challenge'),
            challenge: 'challenge',
            minDurationMs: 0,
            issuedAtNs: self::ISSUED_AT * 1_000_000,
        );
    }

    /**
     * Issue and solve on a file-backed storage whose clock runs on the
     * wall, for the lock-contention suites.
     *
     * @return array{0: ChallengeRecord, 1: string}
     */
    private function issueOnFile(SqliteStorage $storage): array
    {
        $issuer = new Issuer(
            new Config(secretKey: Vectors::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0),
            $storage,
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

        return [$record, \KiwiCaptcha\SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode()];
    }

    private function rowCount(SqliteStorage $storage): int
    {
        return (int) $storage->pdo()->query('SELECT COUNT(*) FROM kiwicaptcha_challenge_records')->fetchColumn();
    }

    private function stateColumn(SqliteStorage $storage, string $nonce): string
    {
        $select = $storage->pdo()->prepare('SELECT state FROM kiwicaptcha_challenge_records WHERE nonce = ?');
        $select->execute([self::wn($nonce)]);

        return (string) $select->fetchColumn();
    }

    private function tempDbPath(): string
    {
        return sys_get_temp_dir().'/kiwi-sqlite-test-'.bin2hex(random_bytes(6)).'.db';
    }

    private function unlinkDb(string $path): void
    {
        @unlink($path);
        @unlink($path.'-wal');
        @unlink($path.'-shm');
    }
}
