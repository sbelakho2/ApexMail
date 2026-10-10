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
use KiwiCaptcha\Storage\FilesystemStorage;
use KiwiCaptcha\Storage\FilesystemStorageException;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * FilesystemStorage against a real directory tree: the invariant
 * suite the other bundled backends pass, run unchanged in spirit on
 * the atomic-rename adapter.
 *
 * Coverage: the layout and marker bootstrap, the one-shot consume
 * contract, the commit, cleanup, cancellation and resume-claim state
 * machines, expiry, and the verifier's replay identity gate. Also
 * fail-closed behavior under corruption, a deleted store and lock
 * contention, plus a forked multi-process consume race proving no
 * double spend, and the file-hygiene bounds of the lock and claim
 * trees.
 */
final class FilesystemStorageContractTest extends TestCase
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

    /** @var list<string> */
    private array $directories = [];

    protected function tearDown(): void
    {
        foreach ($this->directories as $dir) {
            $this->removeTree($dir);
        }
        $this->directories = [];
    }

    // ── layout, marker, construction ─────────────────────────────

    public function testConstructionCreatesTheLayoutWithOwnerOnlyPermissions(): void
    {
        $dir = $this->tempStoreDir();
        new FilesystemStorage($dir, localDiskAcknowledged: true);

        self::assertDirectoryExists($dir.'/records');
        self::assertDirectoryExists($dir.'/locks');
        self::assertDirectoryExists($dir.'/claims');
        self::assertStringEqualsFile($dir.'/format', 'kiwicaptcha-filesystem-1');
        self::assertSame(0700, fileperms($dir) & 0777, 'the store directory is owner-only');
        self::assertSame(0700, fileperms($dir.'/records') & 0777);
    }

    public function testReopeningAnInitializedDirectoryKeepsItsRecords(): void
    {
        $dir = $this->tempStoreDir();
        $first = new FilesystemStorage($dir, localDiskAcknowledged: true);
        $first->store($this->makeRecord('reopen-nonce'));

        $second = new FilesystemStorage($dir, localDiskAcknowledged: true);
        self::assertNotNull($second->find(self::wn('reopen-nonce')), 'a reopened directory keeps its records');
    }

    public function testConstructionWithoutTheLocalDiskAcknowledgementIsRefused(): void
    {
        try {
            new FilesystemStorage($this->tempStoreDir());
            self::fail('the local-disk requirement must be acknowledged explicitly');
        } catch (FilesystemStorageException $e) {
            self::assertStringContainsString('local-disk acknowledgement', $e->getMessage());
        }
    }

    public function testConstructionRefusesNetworkStreamPaths(): void
    {
        try {
            new FilesystemStorage('nfs://server/export/kiwi', localDiskAcknowledged: true);
            self::fail('a stream URL must be refused as a network path');
        } catch (FilesystemStorageException $e) {
            self::assertStringContainsString('stream URL', $e->getMessage());
        }
    }

    public function testConstructionOnAnExistingRegularFileIsRefused(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'kiwi-fs-file');
        self::assertIsString($path);
        $this->directories[] = $path;

        try {
            new FilesystemStorage($path, localDiskAcknowledged: true);
            self::fail('a regular file must never be adopted as the store directory');
        } catch (FilesystemStorageException $e) {
            self::assertStringContainsString('regular file', $e->getMessage());
        }
    }

    public function testAnUnwritableDirectoryFailsConstructionClosed(): void
    {
        $dir = $this->tempStoreDir();
        mkdir($dir, 0700, true);
        chmod($dir, 0500);

        try {
            new FilesystemStorage($dir, localDiskAcknowledged: true);
            self::fail('an unwritable directory must fail construction closed');
        } catch (FilesystemStorageException $e) {
            self::assertStringContainsString('writable', $e->getMessage());
        } finally {
            chmod($dir, 0700);
        }
    }

    public function testAForeignLayoutMarkerIsRefused(): void
    {
        $dir = $this->tempStoreDir();
        $storage = new FilesystemStorage($dir, localDiskAcknowledged: true);
        $storage->store($this->makeRecord('marker-nonce'));
        file_put_contents($dir.'/format', 'kiwicaptcha-filesystem-99');

        try {
            new FilesystemStorage($dir, localDiskAcknowledged: true);
            self::fail('a newer or foreign marker must be refused, never mutated');
        } catch (FilesystemStorageException $e) {
            self::assertStringContainsString('newer or foreign', $e->getMessage());
        }
    }

    public function testAMarkedStoreWithoutTheRecordDirectoryIsRefused(): void
    {
        $dir = $this->tempStoreDir();
        new FilesystemStorage($dir, localDiskAcknowledged: true);
        $this->removeTree($dir.'/records');

        try {
            new FilesystemStorage($dir, localDiskAcknowledged: true);
            self::fail('a marked store whose record tree vanished is damaged and must be refused');
        } catch (FilesystemStorageException $e) {
            self::assertStringContainsString('record directory is missing', $e->getMessage());
        }
    }

    public function testRecordFilesWithoutALayoutMarkerAreRefused(): void
    {
        $dir = $this->tempStoreDir();
        $storage = new FilesystemStorage($dir, localDiskAcknowledged: true);
        $storage->store($this->makeRecord('orphan-nonce'));
        unlink($dir.'/format');

        try {
            new FilesystemStorage($dir, localDiskAcknowledged: true);
            self::fail('record files without a marker belong to a foreign adapter and must be refused');
        } catch (FilesystemStorageException $e) {
            self::assertStringContainsString('without a layout marker', $e->getMessage());
        }
    }

    public function testAStaleTemporaryFileIsSweptAtConstructionAndAFreshOneIsKept(): void
    {
        $dir = $this->tempStoreDir();
        $storage = new FilesystemStorage($dir, localDiskAcknowledged: true);
        $storage->store($this->makeRecord('sweep-tmp'));
        $shardDir = \dirname($storage->pathsFor(self::wn('sweep-tmp'))['record']);
        file_put_contents($shardDir.'/debris.tmp', 'leftover');
        touch($shardDir.'/debris.tmp', time() - 400);
        file_put_contents($shardDir.'/inflight.tmp', 'fresh');

        new FilesystemStorage($dir, localDiskAcknowledged: true);

        self::assertFileDoesNotExist($shardDir.'/debris.tmp', 'the boot sweep removes aged crashed-writer debris');
        self::assertFileExists($shardDir.'/inflight.tmp', 'a fresh temporary file may belong to a writer in flight and is never touched');
        unlink($shardDir.'/inflight.tmp');
        self::assertFileExists($storage->pathsFor(self::wn('sweep-tmp'))['record'], 'the live record survives the boot sweep');
    }

    public function testOutOfRangeConstructorArgumentsAreRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new FilesystemStorage($this->tempStoreDir(), localDiskAcknowledged: true, lockTimeoutMs: -1);
    }

    public function testImplementsTheAtomicPeerCapabilitySet(): void
    {
        $storage = new FilesystemStorage($this->tempStoreDir(), localDiskAcknowledged: true);
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
        $storage = $this->dirStorage();
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
        $storage = $this->dirStorage();
        $storage->store($this->makeRecord('same-nonce', expiresAt: self::ISSUED_AT + 60));
        $storage->store($this->makeRecord('same-nonce', expiresAt: self::ISSUED_AT + 300));

        $loaded = $storage->find(self::wn('same-nonce'));
        self::assertSame(self::ISSUED_AT + 300, $loaded?->expiresAt, 'the second store replaces the first');
        self::assertSame(1, $this->countFiles($storage, 'records', '.json'), 'one nonce maps to exactly one record file');
    }

    public function testConsumeIsExactlyOnceAndRetainsTheRecord(): void
    {
        $storage = $this->dirStorage();
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
        $storage = $this->dirStorage();

        self::assertNull($storage->consume(self::wn('never-stored')));
        self::assertNull($storage->find(self::wn('never-stored')));
    }

    public function testCommitResultIsOneShotAndRidesOnLaterConsumes(): void
    {
        $storage = $this->dirStorage();
        $storage->store($this->makeRecord('commit-once'));
        $storage->consume(self::wn('commit-once'));

        self::assertTrue($storage->commitResult(self::wn('commit-once'), false, null));
        self::assertFalse($storage->commitResult(self::wn('commit-once'), true, 'other'), 'a resultless consumed record accepts exactly one result');

        $retry = $storage->consume(self::wn('commit-once'));
        self::assertNotNull($retry?->consumedResult);
        self::assertFalse($retry->consumedResult->valid, 'the committed invalid outcome replays without re-deriving');
        self::assertNull($retry->consumedResult->binding);
    }

    public function testCommitResultIsRefusedForPendingMissingAndCancelledRows(): void
    {
        $storage = $this->dirStorage();
        $storage->store($this->makeRecord('pending-commit'));
        self::assertFalse($storage->commitResult(self::wn('pending-commit'), true, null), 'a pending record never takes a result');

        self::assertFalse($storage->commitResult(self::wn('missing-commit'), true, null));

        $storage->store($this->makeRecord('cancelled-commit'));
        $storage->cancel(self::wn('cancelled-commit'));
        self::assertFalse($storage->commitResult(self::wn('cancelled-commit'), true, null), 'a cancelled record never takes a result');
    }

    public function testConsumedStateReadsTheRetainedEvidenceWithoutATransition(): void
    {
        $storage = $this->dirStorage();
        $storage->store($this->makeRecord('state-read'));

        self::assertNull($storage->consumedState(self::wn('state-read')), 'a pending record has no consumed state');
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
        $storage = $this->dirStorage();
        $storage->store($this->makeRecord('identity-consume'));

        $winner = $storage->consumeWithOperationIdentity(self::wn('identity-consume'), self::IDENTITY_A);
        self::assertNotNull($winner);
        self::assertTrue($winner->consumedNow);
        self::assertSame(self::IDENTITY_A, $winner->operationIdentity);
        self::assertSame(self::IDENTITY_A, $storage->consumedState(self::wn('identity-consume'))?->operationIdentity);
    }

    public function testPlainConsumeRecordsNullIdentity(): void
    {
        $storage = $this->dirStorage();
        $storage->store($this->makeRecord('plain-identity'));
        $storage->consume(self::wn('plain-identity'));

        self::assertNull($storage->consumedState(self::wn('plain-identity'))?->operationIdentity);
    }

    public function testAMalformedIdentityIsRejectedAndTheRecordStaysPending(): void
    {
        $storage = $this->dirStorage();
        $storage->store($this->makeRecord('bad-identity'));

        try {
            $storage->consumeWithOperationIdentity(self::wn('bad-identity'), 'not valid!');
            self::fail('a malformed identity must be rejected at the storage boundary');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('1..128 bytes', $e->getMessage());
        }

        self::assertSame('pending', $this->envelopeState($storage, self::wn('bad-identity')), 'the refused consume leaves the record pending');
        $lateWinner = $storage->consume(self::wn('bad-identity'));
        self::assertTrue($lateWinner?->consumedNow, 'the challenge stays redeemable after the refusal');
    }

    public function testAPendingRecordCarryingTerminalFieldsIsRefusedAsMissing(): void
    {
        // The pending-envelope guard: a record rewritten to pending
        // while it already carries a result, an identity or a claim
        // fence is a forged rewrite, and the consume reports it
        // missing.
        $storage = $this->dirStorage();
        $storage->store($this->makeRecord('forged-pending'));
        $path = $storage->pathsFor(self::wn('forged-pending'))['record'];
        $envelope = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
        $envelope['consumed_result'] = ['valid' => true, 'binding' => null];
        file_put_contents($path, json_encode($envelope, JSON_UNESCAPED_SLASHES));

        self::assertNull($storage->consume(self::wn('forged-pending')), 'the forged pending record reports missing');
        self::assertSame(ChallengeRuntimeStateKind::Pending, $storage->runtimeState(self::wn('forged-pending'))->kind, 'the runtime state still classifies the snapshot');

        $storage->store($this->makeRecord('forged-claim'));
        $claimPath = $storage->pathsFor(self::wn('forged-claim'))['claim'];
        @mkdir(\dirname($claimPath), 0700, true);
        file_put_contents(
            $claimPath,
            json_encode(['owner' => str_repeat('a', 32), 'until' => self::ISSUED_AT + 3600], JSON_UNESCAPED_SLASHES),
        );

        self::assertNull($storage->consume(self::wn('forged-claim')), 'a pending record behind a claim fence reports missing');
        self::assertSame(ChallengeRuntimeStateKind::Pending, $storage->runtimeState(self::wn('forged-claim'))->kind);
    }

    public function testARuntimeStateSnapshotClassifiesEveryState(): void
    {
        $storage = $this->dirStorage();
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
        $storage = $this->dirStorage();

        self::assertSame('missing', $storage->deleteIfPending(self::wn('cleanup-absent'))->state);

        $storage->store($this->makeRecord('cleanup-pending'));
        self::assertSame('deleted-pending', $storage->deleteIfPending(self::wn('cleanup-pending'))->state);
        self::assertNull($storage->find(self::wn('cleanup-pending')), 'the one-shot cheap-failure policy deletes the pending record');

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
        self::assertNotNull($storage->find(self::wn('cleanup-cancelled')), 'a cancelled record is dead but retained');
    }

    public function testACorruptRecordFileIsReportedCorruptAndLeftUntouched(): void
    {
        $storage = $this->dirStorage();
        $storage->store($this->makeRecord('corrupt-row'));
        $path = $storage->pathsFor(self::wn('corrupt-row'))['record'];
        file_put_contents($path, 'not-json');

        $result = $storage->deleteIfPending(self::wn('corrupt-row'));
        self::assertSame('corrupt', $result->state);
        self::assertStringEqualsFile($path, 'not-json', 'the cleanup never mutates a file it cannot classify');
    }

    public function testDeleteRemovesTheRowAndItsClaimFence(): void
    {
        $storage = $this->dirStorage();
        $storage->store($this->makeRecord('delete-me'));
        $storage->delete(self::wn('delete-me'));

        self::assertNull($storage->find(self::wn('delete-me')));
        self::assertNull($storage->consume(self::wn('delete-me')));

        $storage->store($this->makeRecord('delete-claim'));
        $storage->consume(self::wn('delete-claim'));
        $storage->claimResumeDerivation(self::wn('delete-claim'));
        $paths = $storage->pathsFor(self::wn('delete-claim'));
        $storage->delete(self::wn('delete-claim'));

        self::assertFileDoesNotExist($paths['claim'], 'the claim fence goes with its record');
    }

    public function testCancelLifecycle(): void
    {
        $storage = $this->dirStorage();

        self::assertNull($storage->cancel(self::wn('cancel-absent')), 'a never-issued nonce cancels idempotently as null');

        $storage->store($this->makeRecord('cancel-pending'));
        $fresh = $storage->cancel(self::wn('cancel-pending'));
        self::assertSame('cancelled-now', $fresh?->state);
        self::assertTrue($fresh?->wasCancelledNow());
        self::assertSame('cancelled', $storage->cancel(self::wn('cancel-pending'))?->state, 'the retry is idempotent');

        $storage->store($this->makeRecord('cancel-consumed'));
        $storage->consume(self::wn('cancel-consumed'));
        self::assertSame('consumed', $storage->cancel(self::wn('cancel-consumed'))?->state, 'a finalized record is never cancelled');
        self::assertSame('consumed', $this->envelopeState($storage, self::wn('cancel-consumed')));
    }

    public function testACancelledRecordIsUnconsumableAndNeverRecoverable(): void
    {
        $storage = $this->dirStorage();
        $storage->store($this->makeRecord('dead-row'));
        $storage->cancel(self::wn('dead-row'));

        self::assertNull($storage->consume(self::wn('dead-row')));
        self::assertNull($storage->consumeWithOperationIdentity(self::wn('dead-row'), self::IDENTITY_A));
        self::assertNull($storage->consumedState(self::wn('dead-row')));
        self::assertFalse($storage->commitResult(self::wn('dead-row'), true, null));
        self::assertNull($storage->claimResumeDerivation(self::wn('dead-row')));
        self::assertNotNull($storage->find(self::wn('dead-row')), 'the dead record is retained until its retention ends');
    }

    // ── expiry and retention ──────────────────────────────────────

    public function testAnExpiredRowIsAbsentOnEveryPath(): void
    {
        $storage = $this->dirStorage(ttlMarginSecs: 0);
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
        $storage = $this->dirStorage(ttlMarginSecs: 30);
        $storage->store($this->makeRecord('margin-row', expiresAt: $this->clock + 100));
        $this->clock += 110;

        self::assertNotNull($storage->find(self::wn('margin-row')), 'the retained evidence outlives the signed expiry by the margin');
        $consumed = $storage->consume(self::wn('margin-row'));
        self::assertTrue($consumed?->consumedNow, 'the margin window keeps the one-shot transition open');

        $this->clock += 30;
        self::assertNull($storage->consumedState(self::wn('margin-row')), 'past the margin the retained evidence is gone');
    }

    public function testStoreSweepsExpiredRowsAndTheirSidecarFiles(): void
    {
        $storage = $this->dirStorage(ttlMarginSecs: 0);
        $storage->store($this->makeRecord('sweep-me', expiresAt: $this->clock + 5));
        $stalePaths = $storage->pathsFor(self::wn('sweep-me'));
        $this->clock += 5;
        $storage->store($this->makeRecord('sweep-keeper', expiresAt: $this->clock + 100));

        self::assertSame(1, $this->countFiles($storage, 'records', '.json'), 'the sweep removed the expired record');
        self::assertNull($storage->find(self::wn('sweep-me')));
        self::assertFileDoesNotExist($stalePaths['lock'], 'the sweep removed the expired lock file');
    }

    public function testLockAndClaimFilesStayBoundedByTheLiveSet(): void
    {
        $storage = $this->dirStorage(ttlMarginSecs: 0);
        $storage->store($this->makeRecord('hygiene-a', expiresAt: $this->clock + 10));
        $storage->store($this->makeRecord('hygiene-b', expiresAt: $this->clock + 10));
        $storage->store($this->makeRecord('hygiene-c', expiresAt: $this->clock + 10));
        $storage->consume(self::wn('hygiene-b'));
        $storage->claimResumeDerivation(self::wn('hygiene-b'));
        $this->clock += 10;

        $storage->store($this->makeRecord('hygiene-keeper', expiresAt: $this->clock + 100));

        self::assertSame(1, $this->countFiles($storage, 'records', '.json'), 'exactly the live record remains');
        self::assertSame(1, $this->countFiles($storage, 'locks', '.lock'), 'one lock file per live record, no more');
        self::assertSame(0, $this->countFiles($storage, 'claims', '.claim'), 'no claim fence outlives its record');
        self::assertFileExists($storage->pathsFor(self::wn('hygiene-keeper'))['record']);
    }

    // ── the resume-derivation claim ───────────────────────────────

    public function testTheClaimRequiresAConsumedResultlessRow(): void
    {
        $storage = $this->dirStorage();

        $storage->store($this->makeRecord('claim-pending'));
        self::assertNull($storage->claimResumeDerivation(self::wn('claim-pending')), 'a pending record is refused');
        self::assertNull($storage->claimResumeDerivation(self::wn('claim-absent')));

        $storage->consume(self::wn('claim-pending'));
        $owner = $storage->claimResumeDerivation(self::wn('claim-pending'));
        self::assertNotNull($owner);
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/D', $owner);

        $storage->commitResult(self::wn('claim-pending'), true, null);
        self::assertNull($storage->claimResumeDerivation(self::wn('claim-pending')), 'a committed record is refused');
    }

    public function testALiveClaimExcludesASecondClaimAndExpires(): void
    {
        $storage = $this->dirStorage();
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
        $storage = $this->dirStorage();
        $this->expectException(\InvalidArgumentException::class);
        $storage->claimResumeDerivation(self::wn('whatever'), 0);
    }

    public function testTheReleaseIsACompareAndDelete(): void
    {
        $storage = $this->dirStorage();
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
        $storage = $this->dirStorage();
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
        $storage = $this->dirStorage();
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
        $storage = $this->dirStorage();
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
        $storage = $this->dirStorage();
        $storage->store($this->makeRecord('bad-result'));
        $storage->consume(self::wn('bad-result'));
        $storage->commitResult(self::wn('bad-result'), true, 'x');
        $path = $storage->pathsFor(self::wn('bad-result'))['record'];
        $envelope = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
        $envelope['consumed_result'] = ['valid' => 'yes'];
        file_put_contents($path, json_encode($envelope, JSON_UNESCAPED_SLASHES));

        self::assertNull($storage->consumedState(self::wn('bad-result'))?->consumedResult, 'a malformed stored result is never trusted');
    }

    // ── the verifier invariants on this backend ───────────────────

    /** @return array{0: FilesystemStorage, 1: ChallengeRecord, 2: string} */
    private function issueAndSolve(?string $requestBinding = null): array
    {
        $storage = $this->dirStorage();
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

    private function verifier(FilesystemStorage $storage): Verifier
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
        self::assertNull($storage->find($record->nonce), 'the pending record failing a cheap check is burned');
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
        self::assertNotNull($probe, 'the resultless record is claimable');
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

    public function testADeletedStoreDirectoryFailsEveryVerifyPathClosed(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();
        $verifier = $this->verifier($storage);
        $this->removeTree(\dirname(\dirname(\dirname($storage->pathsFor($record->nonce)['record']))));

        try {
            $storage->consume($record->nonce);
            self::fail('a consume against a deleted store must throw');
        } catch (FilesystemStorageException $e) {
            self::assertStringContainsString('pending-to-consumed transition', $e->getMessage());
        }

        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertFalse($outcome->isOk(), 'a storage failure can never surface as a pass');
        self::assertSame(VerifyError::StorageUnavailable, $outcome->error, 'the failure maps to the same unavailable-store verdict the Redis path gives');
    }

    public function testAnUnwritableRecordDirectoryFailsTheWriteClosed(): void
    {
        $storage = $this->dirStorage();
        $storage->store($this->makeRecord('write-fail'));
        $shardDir = \dirname($storage->pathsFor(self::wn('write-fail'))['record']);
        chmod($shardDir, 0500);

        try {
            // The same nonce hashes into the read-only shard, so the
            // replacement write must fail creating its temporary file.
            $storage->store($this->makeRecord('write-fail'));
            self::fail('a write into an unwritable directory must fail closed with the remedy');
        } catch (FilesystemStorageException $e) {
            self::assertStringContainsString('cannot create the temporary file', $e->getMessage());
            self::assertStringContainsString('writable', $e->getMessage());
        } finally {
            chmod($shardDir, 0700);
        }

        self::assertNotNull($storage->find(self::wn('write-fail')), 'the intact record survives the refused write');
    }

    public function testALockHeldPastTheTimeoutFailsClosedWithTheRemedy(): void
    {
        $dir = $this->tempStoreDir();
        $issuer = new FilesystemStorage($dir, localDiskAcknowledged: true, ttlMarginSecs: 60);
        $issuer->store($this->makeRecord('locked-row', expiresAt: self::ISSUED_AT + 300));
        $blocked = new FilesystemStorage($dir, localDiskAcknowledged: true, lockTimeoutMs: 120, ttlMarginSecs: 60);

        $handle = fopen($blocked->pathsFor(self::wn('locked-row'))['lock'], 'c');
        self::assertIsResource($handle);
        flock($handle, LOCK_EX);

        try {
            $blocked->consume(self::wn('locked-row'));
            self::fail('a record lock held past the lock timeout must fail closed');
        } catch (FilesystemStorageException $e) {
            self::assertStringContainsString('record lock stayed held past the lock timeout', $e->getMessage());
            self::assertStringContainsString('raise lockTimeoutMs', $e->getMessage());
        }

        flock($handle, LOCK_UN);
        fclose($handle);
        $winner = $blocked->consume(self::wn('locked-row'));
        self::assertTrue($winner?->consumedNow, 'the release restores the transition, still exactly once');
    }

    public function testALockHeldPastTheTimeoutFailsVerificationClosed(): void
    {
        $dir = $this->tempStoreDir();
        $storage = new FilesystemStorage($dir, localDiskAcknowledged: true, ttlMarginSecs: 60);
        [$record, $token] = $this->issueOnDirectory($storage);

        $handle = fopen($storage->pathsFor($record->nonce)['lock'], 'c');
        self::assertIsResource($handle);
        flock($handle, LOCK_EX);

        $outcome = (new Verifier($storage))->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertFalse($outcome->isOk());
        // A lost consume response is intrinsically ambiguous, and the
        // verifier reports the same fail-closed verdict a lost Redis
        // consume reply produces: the indeterminate retryable state.
        self::assertSame(VerifyError::ConsumeIndeterminate, $outcome->error);

        flock($handle, LOCK_UN);
        fclose($handle);
    }

    public function testACorruptLayoutMarkerFailsConstructionClosed(): void
    {
        $dir = $this->tempStoreDir();
        $storage = new FilesystemStorage($dir, localDiskAcknowledged: true);
        $storage->store($this->makeRecord('to-corrupt', expiresAt: self::ISSUED_AT + 300));
        file_put_contents($dir.'/format', random_bytes(64));

        try {
            new FilesystemStorage($dir, localDiskAcknowledged: true);
            self::fail('a corrupt marker must never open as an empty usable store');
        } catch (FilesystemStorageException $e) {
            self::assertStringContainsString('layout marker', $e->getMessage());
        }
    }

    public function testACorruptPayloadFileFailsVerificationClosedAsMissing(): void
    {
        [$storage, $record, $token] = $this->issueAndSolve();
        file_put_contents($storage->pathsFor($record->nonce)['record'], 'garbage');

        $outcome = $this->verifier($storage)->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertFalse($outcome->isOk(), 'a corrupt record can never verify');
        self::assertSame(VerifyError::RecordNotFound, $outcome->error);
    }

    // ── concurrency: the no-double-spend proofs ───────────────────

    public function testTwoAdaptersOnOneDirectoryStaySingleUse(): void
    {
        $dir = $this->tempStoreDir();
        $first = new FilesystemStorage($dir, localDiskAcknowledged: true, ttlMarginSecs: 60);
        $first->store($this->makeRecord('two-conn', expiresAt: self::ISSUED_AT + 300));

        // A second adapter on the same directory: its consume observes
        // the committed consumed state of the first, under the
        // per-record lock, and never wins a second transition.
        $second = new FilesystemStorage($dir, localDiskAcknowledged: true, ttlMarginSecs: 60);
        $winner = $first->consume(self::wn('two-conn'));
        $loser = $second->consume(self::wn('two-conn'));

        self::assertTrue($winner?->consumedNow);
        self::assertFalse($loser?->consumedNow);
        self::assertTrue($loser?->consumedBefore, 'the second adapter reads the committed consumed state');
        self::assertTrue($second->commitResult(self::wn('two-conn'), true, 'from-second'), 'the retained record accepts the commit from either adapter');
    }

    public function testForkedConsumersCannotDoubleSpend(): void
    {
        if (!\function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is unavailable; the forked race needs real processes');
        }
        $dir = $this->tempStoreDir();
        $seed = new FilesystemStorage($dir, localDiskAcknowledged: true, ttlMarginSecs: 60);
        $seed->store($this->makeRecord('fork-nonce', expiresAt: self::ISSUED_AT + 300));
        unset($seed);

        $codes = $this->forkWorkers($dir, 8, 'consume');
        sort($codes);

        self::assertSame([0, 1, 1, 1, 1, 1, 1, 1], $codes, 'exactly one consume winner, every loser reads the consumed state, no failures');
        $verifier = new FilesystemStorage($dir, localDiskAcknowledged: true, ttlMarginSecs: 60);
        $final = $verifier->consume(self::wn('fork-nonce'));
        self::assertTrue($final?->consumedBefore);
        self::assertSame('fork-win', $final?->consumedResult?->binding, 'the single winner committed exactly one result');
    }

    public function testForkedIdentityConsumersRecordExactlyTheWinnersIdentity(): void
    {
        if (!\function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is unavailable; the forked race needs real processes');
        }
        $dir = $this->tempStoreDir();
        $seed = new FilesystemStorage($dir, localDiskAcknowledged: true, ttlMarginSecs: 60);
        $seed->store($this->makeRecord('fork-identity', expiresAt: self::ISSUED_AT + 300));
        unset($seed);

        $codes = $this->forkWorkers($dir, 6, 'identity');
        $winners = array_filter($codes, static fn (int $c): bool => $c === 0);

        self::assertCount(1, $winners, 'exactly one identity-bearing consume wins');

        $final = (new FilesystemStorage($dir, localDiskAcknowledged: true, ttlMarginSecs: 60))->consumedState(self::wn('fork-identity'));
        self::assertNotNull($final?->operationIdentity);
        self::assertMatchesRegularExpression('/^op-fork-[0-9]+$/', $final->operationIdentity, 'the stored identity is provably the actual winner identity');
    }

    public function testForkedConsumeVersusCancelNeverRedeemsACancelledRecord(): void
    {
        if (!\function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is unavailable; the forked race needs real processes');
        }
        $dir = $this->tempStoreDir();
        $seed = new FilesystemStorage($dir, localDiskAcknowledged: true, ttlMarginSecs: 60);
        $seed->store($this->makeRecord('fork-mixed', expiresAt: self::ISSUED_AT + 300));
        unset($seed);

        $codes = $this->forkWorkers($dir, 8, 'mixed');
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
            $state = (new FilesystemStorage($dir, localDiskAcknowledged: true, ttlMarginSecs: 60))->runtimeState(self::wn('fork-mixed'));
            self::assertSame(ChallengeRuntimeStateKind::Consumed, $state->kind);
        } else {
            self::assertCount(1, $cancelFresh, 'with no consume winner exactly one cancellation flipped the record');
            self::assertCount(4, $consumeNulls, 'every consumer read the cancelled record as missing');
            $state = (new FilesystemStorage($dir, localDiskAcknowledged: true, ttlMarginSecs: 60))->runtimeState(self::wn('fork-mixed'));
            self::assertSame(ChallengeRuntimeStateKind::Cancelled, $state->kind);
        }
    }

    public function testForkedClaimersElectExactlyOneDerivationOwner(): void
    {
        if (!\function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is unavailable; the forked race needs real processes');
        }
        $dir = $this->tempStoreDir();
        $seed = new FilesystemStorage($dir, localDiskAcknowledged: true, ttlMarginSecs: 60);
        $seed->store($this->makeRecord('fork-claim', expiresAt: self::ISSUED_AT + 300));
        $seed->consume(self::wn('fork-claim'));
        unset($seed);

        $codes = $this->forkWorkers($dir, 6, 'claim');
        $winners = array_filter($codes, static fn (int $c): bool => $c === 0);
        $refused = array_filter($codes, static fn (int $c): bool => $c === 1);

        self::assertCount(1, $winners, 'exactly one recovery holds the derivation lease');
        self::assertCount(5, $refused, 'every other recovery is refused while the lease is live');
    }

    /**
     * Fork N workers; every child opens its own adapter, jitters its
     * start, runs one transition and reports the outcome through its
     * exit code. Children never print and never touch the parent
     * storage; the parent collects the codes after every child exits.
     *
     * @return list<int> the exit code of each worker, parent order
     */
    private function forkWorkers(string $dir, int $count, string $mode): array
    {
        $pids = [];
        for ($i = 0; $i < $count; $i++) {
            $pid = pcntl_fork();
            if ($pid === 0) {
                exit($this->runWorker($dir, $i, $mode));
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
    private function runWorker(string $dir, int $index, string $mode): int
    {
        try {
            usleep(random_int(0, 4000));
            $storage = new FilesystemStorage($dir, localDiskAcknowledged: true, lockTimeoutMs: 15000, ttlMarginSecs: 60);
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

    private function dirStorage(int $ttlMarginSecs = 60): FilesystemStorage
    {
        return new FilesystemStorage(
            $this->tempStoreDir(),
            localDiskAcknowledged: true,
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
     * Issue and solve on a directory-backed storage whose clock runs
     * on the wall, for the lock-contention suites.
     *
     * @return array{0: ChallengeRecord, 1: string}
     */
    private function issueOnDirectory(FilesystemStorage $storage): array
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

    /** The envelope state of a stored record, read straight from the file. */
    private function envelopeState(FilesystemStorage $storage, string $nonce): string
    {
        $raw = (string) file_get_contents($storage->pathsFor($nonce)['record']);
        $envelope = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);

        return (string) $envelope['state'];
    }

    /** Count the files of one suffix under one store tree, recursively. */
    private function countFiles(FilesystemStorage $storage, string $tree, string $suffix): int
    {
        $paths = $storage->pathsFor(self::wn('count-probe'));
        $root = \dirname(\dirname(\dirname($paths['record']))).'/'.$tree;
        if (!is_dir($root)) {
            return 0;
        }
        $count = 0;
        $stack = [$root];
        while ($stack !== []) {
            $dir = array_pop($stack);
            $entries = scandir($dir);
            if ($entries === false) {
                continue;
            }
            foreach ($entries as $entry) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }
                $path = $dir.'/'.$entry;
                if (is_dir($path)) {
                    $stack[] = $path;
                    continue;
                }
                if (str_ends_with($path, $suffix)) {
                    $count++;
                }
            }
        }

        return $count;
    }

    /** A fresh unique directory under the system temp directory. */
    private function tempStoreDir(): string
    {
        $dir = sys_get_temp_dir().'/kiwi-fs-test-'.bin2hex(random_bytes(6));
        $this->directories[] = $dir;

        return $dir;
    }

    /** Remove a directory tree, or a plain file, quietly. */
    private function removeTree(string $path): void
    {
        if (!is_dir($path)) {
            @unlink($path);

            return;
        }
        $entries = @scandir($path);
        if ($entries !== false) {
            foreach ($entries as $entry) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }
                $child = $path.'/'.$entry;
                if (is_dir($child)) {
                    $this->removeTree($child);
                    continue;
                }
                @unlink($child);
            }
        }
        @rmdir($path);
    }
}
