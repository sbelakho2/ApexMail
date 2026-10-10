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
use KiwiCaptcha\Storage\ApcuBackendInterface;
use KiwiCaptcha\Storage\ApcuStorage;
use KiwiCaptcha\Storage\ApcuStorageException;
use KiwiCaptcha\Storage\RealApcuBackend;
use KiwiCaptcha\Tests\Fixtures\RealApcuTestEnv;
use KiwiCaptcha\Tests\Fixtures\SharedMemoryApcuBackend;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * ApcuStorage against both backend legs of the seam: the fork-shareable
 * shared-memory emulation that runs everywhere, and the real APCu
 * extension when the host carries it.
 *
 * The honest limitation first: the environment this suite usually runs
 * in lacks the APCu extension, so the real-backend leg auto-skips there
 * (a dedicated lane sets KIWI_REQUIRE_REAL_APCU_TESTS=1 to turn that
 * skip into a failure). The emulation is a faithful stand-in, not a
 * mock of convenience. One shared memory segment plus one kernel
 * semaphore reproduce the contract every storage transition leans on,
 * atomic create-if-absent, atomic overwrite and expiry-reads-as-absent,
 * so the one-shot consume proofs below exercise the same interleavings
 * the real segment produces. Where the two can differ (segment size
 * caps, parallel readers), the emulation is the more demanding side,
 * never the looser one.
 *
 * Coverage mirrors the SQLite and filesystem suites. The one-shot
 * consume contract, the commit, cleanup, cancellation and resume-claim
 * state machines, expiry, the verifier's replay identity gate, the
 * fail-closed behavior under corruption, lock contention and backend
 * refusal, plus forked multi-process races proving no double spend on
 * both legs.
 */
final class ApcuStorageContractTest extends TestCase
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

    /** @var list<SharedMemoryApcuBackend> the emulated backends this case owns */
    private array $ownedBackends = [];

    protected function tearDown(): void
    {
        foreach ($this->ownedBackends as $backend) {
            $backend->dispose();
        }
        $this->ownedBackends = [];
    }

    /**
     * The two backend legs every contract test runs against: the
     * shared-memory emulation, always present, and the real extension
     * when the host carries it.
     *
     * @return iterable<string, list<string>>
     */
    public static function storageLegProvider(): iterable
    {
        yield 'emulated backend' => ['emulated'];

        yield 'real apcu backend' => ['real-apcu'];
    }

    // ── construction, layout, capability set ──────────────────────

    #[DataProvider('storageLegProvider')]
    public function testImplementsTheAtomicPeerCapabilitySet(string $leg): void
    {
        [$storage] = $this->newStorage($leg);

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
        // The fence is the documented no-op of the single-host adapter.
        $storage->establishReplicationFence('acceptance point');
        self::addToAssertionCount(1);
    }

    #[DataProvider('storageLegProvider')]
    public function testKeysForDerivesTheNamespacedLayout(string $leg): void
    {
        $prefix = 'kiwi-'.bin2hex(random_bytes(4));
        [$storage] = $this->newStorage($leg, prefix: $prefix);

        $keys = $storage->keysFor(self::wn('layout-nonce'));
        self::assertSame($prefix.':rec:'.self::wn('layout-nonce'), $keys['record']);
        self::assertSame($prefix.':lock:'.self::wn('layout-nonce'), $keys['lock']);
    }

    #[DataProvider('storageLegProvider')]
    public function testOutOfRangeConstructorArgumentsAreRejected(string $leg): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->newStorage($leg, lockTimeoutMs: -1);
    }

    #[DataProvider('storageLegProvider')]
    public function testAnEmptyKeyPrefixIsRejected(string $leg): void
    {
        [$backend] = $this->newBackend($leg);
        $this->expectException(\InvalidArgumentException::class);
        new ApcuStorage($backend, '');
    }

    public function testTheDefaultBackendFailsClosedWhereTheExtensionIsMissing(): void
    {
        // The default construction path names the remedy instead of a
        // fatal undefined-function call later; where the extension is
        // present and enabled the same call simply works.
        if (RealApcuTestEnv::available()) {
            $storage = new ApcuStorage();
            $storage->establishReplicationFence('probe');
            self::addToAssertionCount(1);

            return;
        }
        try {
            new ApcuStorage();
            self::fail('a missing APCu extension must fail construction closed');
        } catch (ApcuStorageException $e) {
            self::assertStringContainsString('ext-apcu', $e->getMessage());
        }
    }

    /**
     * The physical sweep of this backend is the TTL: every record write
     * carries its retention deadline as the entry TTL, clamped to the
     * documented ceiling. Asserted through the emulation's expiry
     * introspection; the real leg's expiry bookkeeping is APCu's own.
     */
    #[DataProvider('storageLegProvider')]
    public function testRecordWritesCarryTheRetentionDeadlineAsTheTtl(string $leg): void
    {
        if ($leg !== 'emulated') {
            self::markTestSkipped('the TTL introspection is the emulation fixture\'s own seam');
        }
        [$storage, $backend] = $this->newStorage($leg, ttlMarginSecs: 60);
        $storage->store($this->makeRecord('ttl-far', expiresAt: self::ISSUED_AT + 120));
        $storage->store($this->makeRecord('ttl-near', expiresAt: time() + 300, issuedAt: time()));

        $farExpiry = $backend->expiryOf($storage->keysFor(self::wn('ttl-far'))['record']);
        $nearExpiry = $backend->expiryOf($storage->keysFor(self::wn('ttl-near'))['record']);
        self::assertNotNull($farExpiry);
        self::assertNotNull($nearExpiry);
        // The far-future fake clock clamps to the ceiling; the wall-clock
        // record carries exactly its retention deadline.
        self::assertEqualsWithDelta(time() + 86_400, $farExpiry, 2, 'a retention beyond the ceiling clamps to it');
        self::assertEqualsWithDelta(time() + 360, $nearExpiry, 2, 'the retention deadline rides the entry as its TTL');
    }

    /**
     * A TTL-expired entry reads as absent and is reclaimable by add:
     * the expiry semantics every storage path above the seam leans on.
     */
    public function testExpiredEntriesReadAsAbsentAndAreReclaimable(): void
    {
        $backend = SharedMemoryApcuBackend::create();
        $this->ownedBackends[] = $backend;
        $key = 'kiwi-expiry-probe';

        self::assertTrue($backend->store($key, 'v', -5), 'an already-past TTL stores an already-expired entry');
        self::assertFalse($backend->fetch($key)->found, 'an expired entry reads as absent');
        self::assertTrue($backend->add($key, 'w', 60), 'an expired entry is reclaimable by add');
        self::assertSame('w', $backend->fetch($key)->value());
    }

    // ── the one-shot consume contract ─────────────────────────────

    #[DataProvider('storageLegProvider')]
    public function testStoreFindRoundTripsEveryField(string $leg): void
    {
        [$storage] = $this->newStorage($leg);
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

    #[DataProvider('storageLegProvider')]
    public function testStoreReplacesAnExistingRecordWithTheSameNonce(string $leg): void
    {
        [$storage] = $this->newStorage($leg);
        $storage->store($this->makeRecord('same-nonce', expiresAt: self::ISSUED_AT + 60));
        $storage->store($this->makeRecord('same-nonce', expiresAt: self::ISSUED_AT + 300));

        $loaded = $storage->find(self::wn('same-nonce'));
        self::assertSame(self::ISSUED_AT + 300, $loaded?->expiresAt, 'the second store replaces the first');
        self::assertSame(ChallengeRuntimeStateKind::Pending, $storage->runtimeState(self::wn('same-nonce'))->kind, 'the replacement is a fresh pending record');
    }

    #[DataProvider('storageLegProvider')]
    public function testConsumeIsExactlyOnceAndRetainsTheRecord(string $leg): void
    {
        [$storage] = $this->newStorage($leg);
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

    #[DataProvider('storageLegProvider')]
    public function testConsumeOfAMissingNonceIsNull(string $leg): void
    {
        [$storage] = $this->newStorage($leg);

        self::assertNull($storage->consume(self::wn('never-stored')));
        self::assertNull($storage->find(self::wn('never-stored')));
    }

    #[DataProvider('storageLegProvider')]
    public function testCommitResultIsOneShotAndRidesOnLaterConsumes(string $leg): void
    {
        [$storage] = $this->newStorage($leg);
        $storage->store($this->makeRecord('commit-once'));
        $storage->consume(self::wn('commit-once'));

        self::assertTrue($storage->commitResult(self::wn('commit-once'), false, null));
        self::assertFalse($storage->commitResult(self::wn('commit-once'), true, 'other'), 'a resultless consumed record accepts exactly one result');

        $retry = $storage->consume(self::wn('commit-once'));
        self::assertNotNull($retry?->consumedResult);
        self::assertFalse($retry->consumedResult->valid, 'the committed invalid outcome replays without re-deriving');
        self::assertNull($retry->consumedResult->binding);
    }

    #[DataProvider('storageLegProvider')]
    public function testCommitResultIsRefusedForPendingMissingAndCancelledRecords(string $leg): void
    {
        [$storage] = $this->newStorage($leg);
        $storage->store($this->makeRecord('pending-commit'));
        self::assertFalse($storage->commitResult(self::wn('pending-commit'), true, null), 'a pending record never takes a result');

        self::assertFalse($storage->commitResult(self::wn('missing-commit'), true, null));

        $storage->store($this->makeRecord('cancelled-commit'));
        $storage->cancel(self::wn('cancelled-commit'));
        self::assertFalse($storage->commitResult(self::wn('cancelled-commit'), true, null), 'a cancelled record never takes a result');
    }

    #[DataProvider('storageLegProvider')]
    public function testConsumedStateReadsTheRetainedEvidenceWithoutATransition(string $leg): void
    {
        [$storage] = $this->newStorage($leg);
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

    #[DataProvider('storageLegProvider')]
    public function testConsumeWithOperationIdentityRecordsTheWinnerIdentity(string $leg): void
    {
        [$storage] = $this->newStorage($leg);
        $storage->store($this->makeRecord('identity-consume'));

        $winner = $storage->consumeWithOperationIdentity(self::wn('identity-consume'), self::IDENTITY_A);
        self::assertNotNull($winner);
        self::assertTrue($winner->consumedNow);
        self::assertSame(self::IDENTITY_A, $winner->operationIdentity);
        self::assertSame(self::IDENTITY_A, $storage->consumedState(self::wn('identity-consume'))?->operationIdentity);
    }

    #[DataProvider('storageLegProvider')]
    public function testPlainConsumeRecordsNullIdentity(string $leg): void
    {
        [$storage] = $this->newStorage($leg);
        $storage->store($this->makeRecord('plain-identity'));
        $storage->consume(self::wn('plain-identity'));

        self::assertNull($storage->consumedState(self::wn('plain-identity'))?->operationIdentity);
    }

    #[DataProvider('storageLegProvider')]
    public function testAMalformedIdentityIsRejectedAndTheRecordStaysPending(string $leg): void
    {
        [$storage] = $this->newStorage($leg);
        $storage->store($this->makeRecord('bad-identity'));

        try {
            $storage->consumeWithOperationIdentity(self::wn('bad-identity'), 'not valid!');
            self::fail('a malformed identity must be rejected at the storage boundary');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('1..128 bytes', $e->getMessage());
        }

        self::assertSame(ChallengeRuntimeStateKind::Pending, $storage->runtimeState(self::wn('bad-identity'))->kind, 'the refused consume leaves the record pending');
        $lateWinner = $storage->consume(self::wn('bad-identity'));
        self::assertTrue($lateWinner?->consumedNow, 'the challenge stays redeemable after the refusal');
    }

    #[DataProvider('storageLegProvider')]
    public function testAPendingRecordCarryingTerminalFieldsIsRefusedAsMissing(string $leg): void
    {
        // The pending-envelope guard: a record rewritten to pending
        // while it already carries a result or an identity is a forged
        // rewrite, and the consume reports it missing.
        [$storage, $backend] = $this->newStorage($leg);
        $storage->store($this->makeRecord('forged-pending'));
        $this->rewriteEnvelope($backend, $storage, self::wn('forged-pending'), static function (array $envelope): array {
            $envelope['consumed_result'] = ['valid' => true, 'binding' => null];

            return $envelope;
        });

        self::assertNull($storage->consume(self::wn('forged-pending')), 'the forged pending record reports missing');
        self::assertSame(ChallengeRuntimeStateKind::Pending, $storage->runtimeState(self::wn('forged-pending'))->kind, 'the runtime state still classifies the snapshot');

        $storage->store($this->makeRecord('forged-lease'));
        $this->rewriteEnvelope($backend, $storage, self::wn('forged-lease'), static function (array $envelope): array {
            $envelope['resume_owner'] = str_repeat('a', 32);
            $envelope['resume_until'] = self::ISSUED_AT + 3600;

            return $envelope;
        });

        self::assertNull($storage->consume(self::wn('forged-lease')), 'a pending record carrying a claim lease reports missing');
    }

    #[DataProvider('storageLegProvider')]
    public function testARuntimeStateSnapshotClassifiesEveryState(string $leg): void
    {
        [$storage] = $this->newStorage($leg);
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

    #[DataProvider('storageLegProvider')]
    public function testDeleteIfPendingDecidesEveryStateAtomically(string $leg): void
    {
        [$storage] = $this->newStorage($leg);

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

    #[DataProvider('storageLegProvider')]
    public function testACorruptRecordValueIsReportedCorruptAndLeftUntouched(string $leg): void
    {
        [$storage, $backend] = $this->newStorage($leg);
        $storage->store($this->makeRecord('corrupt-value'));
        $backend->store($storage->keysFor(self::wn('corrupt-value'))['record'], 'not-json', 3600);

        $result = $storage->deleteIfPending(self::wn('corrupt-value'));
        self::assertSame('corrupt', $result->state);
        self::assertSame('not-json', $backend->fetch($storage->keysFor(self::wn('corrupt-value'))['record'])->value(), 'the cleanup never mutates a value it cannot classify');
    }

    #[DataProvider('storageLegProvider')]
    public function testAnEnvelopeFromANewerLayoutIsRefusedAsCorrupt(string $leg): void
    {
        // A value stamped by a future envelope layout is corruption to
        // this release, never a partially trusted record.
        [$storage, $backend] = $this->newStorage($leg);
        $storage->store($this->makeRecord('future-envelope'));
        $this->rewriteEnvelope($backend, $storage, self::wn('future-envelope'), static function (array $envelope): array {
            $envelope['version'] = 99;

            return $envelope;
        });

        self::assertNull($storage->find(self::wn('future-envelope')));
        self::assertSame('corrupt', $storage->deleteIfPending(self::wn('future-envelope'))->state);
    }

    #[DataProvider('storageLegProvider')]
    public function testDeleteRemovesTheRecord(string $leg): void
    {
        [$storage] = $this->newStorage($leg);
        $storage->store($this->makeRecord('delete-me'));
        $storage->consume(self::wn('delete-me'));
        $storage->claimResumeDerivation(self::wn('delete-me'));
        $storage->delete(self::wn('delete-me'));

        self::assertNull($storage->find(self::wn('delete-me')));
        self::assertNull($storage->consume(self::wn('delete-me')));
    }

    #[DataProvider('storageLegProvider')]
    public function testCancelLifecycle(string $leg): void
    {
        [$storage] = $this->newStorage($leg);

        self::assertNull($storage->cancel(self::wn('cancel-absent')), 'a never-issued nonce cancels idempotently as null');

        $storage->store($this->makeRecord('cancel-pending'));
        $fresh = $storage->cancel(self::wn('cancel-pending'));
        self::assertSame('cancelled-now', $fresh?->state);
        self::assertTrue($fresh?->wasCancelledNow());
        self::assertSame('cancelled', $storage->cancel(self::wn('cancel-pending'))?->state, 'the retry is idempotent');

        $storage->store($this->makeRecord('cancel-consumed'));
        $storage->consume(self::wn('cancel-consumed'));
        self::assertSame('consumed', $storage->cancel(self::wn('cancel-consumed'))?->state, 'a finalized record is never cancelled');
        self::assertSame(ChallengeRuntimeStateKind::Consumed, $storage->runtimeState(self::wn('cancel-consumed'))->kind);
    }

    #[DataProvider('storageLegProvider')]
    public function testACancelledRecordIsUnconsumableAndNeverRecoverable(string $leg): void
    {
        [$storage] = $this->newStorage($leg);
        $storage->store($this->makeRecord('dead-record'));
        $storage->cancel(self::wn('dead-record'));

        self::assertNull($storage->consume(self::wn('dead-record')));
        self::assertNull($storage->consumeWithOperationIdentity(self::wn('dead-record'), self::IDENTITY_A));
        self::assertNull($storage->consumedState(self::wn('dead-record')));
        self::assertFalse($storage->commitResult(self::wn('dead-record'), true, null));
        self::assertNull($storage->claimResumeDerivation(self::wn('dead-record')));
        self::assertNotNull($storage->find(self::wn('dead-record')), 'the dead record is retained until its retention ends');
    }

    // ── expiry and retention ──────────────────────────────────────

    #[DataProvider('storageLegProvider')]
    public function testAnExpiredRecordIsAbsentOnEveryPath(string $leg): void
    {
        [$storage] = $this->newStorage($leg, ttlMarginSecs: 0);
        $storage->store($this->makeRecord('expired-record', expiresAt: $this->clock + 10));
        $this->clock += 10;

        self::assertNull($storage->find(self::wn('expired-record')));
        self::assertNull($storage->consume(self::wn('expired-record')));
        self::assertNull($storage->consumedState(self::wn('expired-record')));
        self::assertSame(ChallengeRuntimeStateKind::Missing, $storage->runtimeState(self::wn('expired-record'))->kind);
        self::assertSame('missing', $storage->deleteIfPending(self::wn('expired-record'))->state);
        self::assertNull($storage->cancel(self::wn('expired-record')));
        self::assertFalse($storage->commitResult(self::wn('expired-record'), true, null));
    }

    #[DataProvider('storageLegProvider')]
    public function testTheRetentionMarginExtendsReadabilityPastSignedExpiry(string $leg): void
    {
        [$storage] = $this->newStorage($leg, ttlMarginSecs: 30);
        $storage->store($this->makeRecord('margin-record', expiresAt: $this->clock + 100));
        $this->clock += 110;

        self::assertNotNull($storage->find(self::wn('margin-record')), 'the retained evidence outlives the signed expiry by the margin');
        $consumed = $storage->consume(self::wn('margin-record'));
        self::assertTrue($consumed?->consumedNow, 'the margin window keeps the one-shot transition open');

        $this->clock += 30;
        self::assertNull($storage->consumedState(self::wn('margin-record')), 'past the margin the retained evidence is gone');
    }

    // ── the resume-derivation claim ───────────────────────────────

    #[DataProvider('storageLegProvider')]
    public function testTheClaimRequiresAConsumedResultlessRecord(string $leg): void
    {
        [$storage] = $this->newStorage($leg);

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

    #[DataProvider('storageLegProvider')]
    public function testALiveClaimExcludesASecondClaimAndExpires(string $leg): void
    {
        [$storage] = $this->newStorage($leg);
        $storage->store($this->makeRecord('claim-live'));
        $storage->consume(self::wn('claim-live'));

        $first = $storage->claimResumeDerivation(self::wn('claim-live'), 60);
        self::assertNotNull($first);
        self::assertNull($storage->claimResumeDerivation(self::wn('claim-live'), 60), 'a live lease blocks every other claimer');

        $this->clock += 61;
        $second = $storage->claimResumeDerivation(self::wn('claim-live'), 60);
        self::assertNotSame($first, $second, 'the expired lease is re-claimable by a fresh owner');
    }

    #[DataProvider('storageLegProvider')]
    public function testClaimTtlBelowOneSecondIsRejected(string $leg): void
    {
        [$storage] = $this->newStorage($leg);
        $this->expectException(\InvalidArgumentException::class);
        $storage->claimResumeDerivation(self::wn('whatever'), 0);
    }

    #[DataProvider('storageLegProvider')]
    public function testTheReleaseIsACompareAndDelete(string $leg): void
    {
        [$storage] = $this->newStorage($leg);
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

    #[DataProvider('storageLegProvider')]
    public function testAMalformedOwnerIsRejectedAtTheBoundary(string $leg): void
    {
        [$storage] = $this->newStorage($leg);
        $storage->store($this->makeRecord('bad-owner'));
        $storage->consume(self::wn('bad-owner'));

        try {
            $storage->releaseResumeDerivation(self::wn('bad-owner'), 'nothex');
            self::fail('a malformed owner token must be rejected');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('32 lowercase hex', $e->getMessage());
        }
    }

    #[DataProvider('storageLegProvider')]
    public function testTheResumeCommitFencesOnTheLiveClaim(string $leg): void
    {
        [$storage] = $this->newStorage($leg);
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

    #[DataProvider('storageLegProvider')]
    public function testTheAuthenticatedCommitsStoreTheServerStateMac(string $leg): void
    {
        [$storage] = $this->newStorage($leg);
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

    #[DataProvider('storageLegProvider')]
    public function testACorruptCommittedResultDegradesToAbsent(string $leg): void
    {
        [$storage, $backend] = $this->newStorage($leg);
        $storage->store($this->makeRecord('bad-result'));
        $storage->consume(self::wn('bad-result'));
        $storage->commitResult(self::wn('bad-result'), true, 'x');
        $this->rewriteEnvelope($backend, $storage, self::wn('bad-result'), static function (array $envelope): array {
            $envelope['consumed_result'] = ['valid' => 'yes'];

            return $envelope;
        });

        self::assertNull($storage->consumedState(self::wn('bad-result'))?->consumedResult, 'a malformed stored result is never trusted');
    }

    // ── the verifier invariants on this backend ───────────────────

    /** @return array{0: ApcuStorage, 1: ChallengeRecord, 2: string, 3: ApcuBackendInterface} */
    private function issueAndSolve(string $leg, ?string $requestBinding = null): array
    {
        [$storage, $backend] = $this->newStorage($leg);
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

        return [$storage, $record, \KiwiCaptcha\SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode(), $backend];
    }

    private function verifier(ApcuStorage $storage): Verifier
    {
        return new Verifier($storage, now: fn (): int => $this->clock);
    }

    #[DataProvider('storageLegProvider')]
    public function testAVerificationIsSingleUseAndItsReplayIsRefused(string $leg): void
    {
        [$storage, $record, $token] = $this->issueAndSolve($leg);
        $verifier = $this->verifier($storage);

        $first = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertTrue($first->isOk(), sprintf('the fresh verification must pass, got %s', $first->code()));

        $second = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertFalse($second->isOk(), 'a second use of the same token must never pass');
        self::assertSame(VerifyError::AlreadyConsumed, $second->error);
        self::assertNotNull($storage->find($record->nonce), 'the consumed evidence stays readable');
    }

    #[DataProvider('storageLegProvider')]
    public function testTheStoredSuccessReplaysOnlyToTheExactOperation(string $leg): void
    {
        [$storage, $record, $token] = $this->issueAndSolve($leg);
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

    #[DataProvider('storageLegProvider')]
    public function testAStoredInvalidOutcomeReplaysToAnyCaller(string $leg): void
    {
        [$storage, $record, $token] = $this->issueAndSolve($leg);
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

    #[DataProvider('storageLegProvider')]
    public function testACheapFailureDeletesOnlyThePendingRecord(string $leg): void
    {
        [$storage, $record, $token] = $this->issueAndSolve($leg);
        $verifier = $this->verifier($storage);

        $outcome = $verifier->verify($token, Vectors::SECRET, 'checkout', self::CLIENT_IP);
        self::assertSame(VerifyError::WrongScope, $outcome->error);
        self::assertNull($storage->find($record->nonce), 'the pending record failing a cheap check is burned');
    }

    #[DataProvider('storageLegProvider')]
    public function testACancelledChallengeFailsVerificationClosed(string $leg): void
    {
        [$storage, $record, $token] = $this->issueAndSolve($leg);
        $storage->cancel($record->nonce);

        $outcome = $this->verifier($storage)->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertFalse($outcome->isOk());
        self::assertSame(VerifyError::RecordNotFound, $outcome->error, 'a cancelled challenge is pinned to the deterministic missing verdict');
    }

    #[DataProvider('storageLegProvider')]
    public function testAnExpiredChallengeFailsClosed(string $leg): void
    {
        [$storage, $record, $token] = $this->issueAndSolve($leg);
        $this->clock += 121;

        $outcome = $this->verifier($storage)->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::Expired, $outcome->error);
    }

    #[DataProvider('storageLegProvider')]
    public function testTheResultlessResumeCommitsThroughTheClaim(string $leg): void
    {
        [$storage, $record, $token] = $this->issueAndSolve($leg);

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

    #[DataProvider('storageLegProvider')]
    public function testAResumeWithTheWrongIdentityIsRefused(string $leg): void
    {
        [$storage, $record, $token] = $this->issueAndSolve($leg);
        $storage->consumeWithOperationIdentity($record->nonce, self::IDENTITY_A);

        $outcome = $this->verifier($storage)->resumeConsumedOperation($token, Vectors::SECRET, self::IDENTITY_B, 'login', self::CLIENT_IP);
        self::assertFalse($outcome->isOk(), 'an unproven operation never resumes another operation derivation');
    }

    // ── fail-closed under damage and contention ───────────────────

    #[DataProvider('storageLegProvider')]
    public function testACorruptRecordFailsVerificationClosedAsMissing(string $leg): void
    {
        [$storage, $record, $token, $backend] = $this->issueAndSolve($leg);
        $backend->store($storage->keysFor($record->nonce)['record'], 'garbage', 3600);

        $outcome = $this->verifier($storage)->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertFalse($outcome->isOk(), 'a corrupt record can never verify');
        self::assertSame(VerifyError::RecordNotFound, $outcome->error);
    }

    #[DataProvider('storageLegProvider')]
    public function testALockHeldPastTheTimeoutFailsClosedWithTheRemedy(string $leg): void
    {
        [$seedStorage, $backend] = $this->newStorage($leg, ttlMarginSecs: 60, wallClock: true);
        $seedStorage->store($this->makeRecord('locked-record', expiresAt: self::ISSUED_AT + 300));
        $prefix = $this->prefixOf($leg, $seedStorage);

        $blocked = $this->storageOn($leg, $backend, $prefix, lockTimeoutMs: 120, ttlMarginSecs: 60);
        self::assertTrue($backend->add($blocked->keysFor(self::wn('locked-record'))['lock'], 'foreign-holder', 30), 'the foreign lock holder wins the lock key');

        try {
            $blocked->consume(self::wn('locked-record'));
            self::fail('a transition lock held past the timeout must fail closed');
        } catch (ApcuStorageException $e) {
            self::assertStringContainsString('transition lock stayed held past the lock timeout', $e->getMessage());
            self::assertStringContainsString('raise lockTimeoutMs', $e->getMessage());
        }

        self::assertTrue($backend->delete($blocked->keysFor(self::wn('locked-record'))['lock']));
        $winner = $blocked->consume(self::wn('locked-record'));
        self::assertTrue($winner?->consumedNow, 'the release restores the transition, still exactly once');
    }

    #[DataProvider('storageLegProvider')]
    public function testALockHeldPastTheTimeoutFailsVerificationClosed(string $leg): void
    {
        [$storage, $backend] = $this->newStorage($leg, ttlMarginSecs: 60, wallClock: true);
        [$record, $token] = $this->issueOnStorage($storage);
        $blocked = $this->storageOn($leg, $backend, $this->prefixOf($leg, $storage), lockTimeoutMs: 120, ttlMarginSecs: 60);
        self::assertTrue($backend->add($storage->keysFor($record->nonce)['lock'], 'foreign-holder', 30));

        $outcome = (new Verifier($blocked))->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP);
        self::assertFalse($outcome->isOk());
        // A lost consume response is intrinsically ambiguous, and the
        // verifier reports the same fail-closed verdict a lost Redis
        // consume reply produces: the indeterminate retryable state.
        self::assertSame(VerifyError::ConsumeIndeterminate, $outcome->error);

        $backend->delete($storage->keysFor($record->nonce)['lock']);
    }

    #[DataProvider('storageLegProvider')]
    public function testABackendWriteRefusalFailsTheTransitionClosed(string $leg): void
    {
        [$storage, $backend] = $this->newStorage($leg, ttlMarginSecs: 60);
        $storage->store($this->makeRecord('refused-write'));
        $prefix = $this->prefixOf($leg, $storage);

        $refusing = new class($backend) implements ApcuBackendInterface {
            public bool $refuse = true;

            public function __construct(private readonly ApcuBackendInterface $inner)
            {
            }

            public function fetch(string $key): \KiwiCaptcha\Storage\ApcuFetchOutcome
            {
                return $this->inner->fetch($key);
            }

            public function store(string $key, mixed $value, int $ttlSecs): bool
            {
                return $this->refuse ? false : $this->inner->store($key, $value, $ttlSecs);
            }

            public function add(string $key, mixed $value, int $ttlSecs): bool
            {
                return $this->inner->add($key, $value, $ttlSecs);
            }

            public function delete(string $key): bool
            {
                return $this->inner->delete($key);
            }
        };
        $blocked = new ApcuStorage($refusing, $prefix, lockTimeoutMs: 5000, ttlMarginSecs: 60);

        try {
            $blocked->consume(self::wn('refused-write'));
            self::fail('a refused envelope write must fail the transition closed');
        } catch (ApcuStorageException $e) {
            self::assertStringContainsString('refused the record write', $e->getMessage());
        }

        $lateWinner = $storage->consume(self::wn('refused-write'));
        self::assertTrue($lateWinner?->consumedNow, 'the refused transition left the record pending and redeemable');
    }

    // ── concurrency: the no-double-spend proofs ───────────────────

    #[DataProvider('storageLegProvider')]
    public function testTwoAdaptersOnOneBackendStaySingleUse(string $leg): void
    {
        [$first, $backend] = $this->newStorage($leg, ttlMarginSecs: 60, wallClock: true);
        $first->store($this->makeRecord('two-adapter', expiresAt: self::ISSUED_AT + 300));
        $prefix = $this->prefixOf($leg, $first);

        // A second adapter on the same backend and prefix: its consume
        // observes the written consumed state of the first, under the
        // shared transition lock, and never wins a second transition.
        $second = $this->storageOn($leg, $backend, $prefix, ttlMarginSecs: 60);
        $winner = $first->consume(self::wn('two-adapter'));
        $loser = $second->consume(self::wn('two-adapter'));

        self::assertTrue($winner?->consumedNow);
        self::assertFalse($loser?->consumedNow);
        self::assertTrue($loser?->consumedBefore, 'the second adapter reads the retained consumed state');
        self::assertTrue($second->commitResult(self::wn('two-adapter'), true, 'from-second'), 'the retained record accepts the commit from either adapter');
    }

    #[DataProvider('storageLegProvider')]
    public function testForkedConsumersCannotDoubleSpend(string $leg): void
    {
        if (!\function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is unavailable; the forked race needs real processes');
        }
        [$seed, $backend] = $this->newStorage($leg, ttlMarginSecs: 60, wallClock: true);
        $seed->store($this->makeRecord('fork-nonce', expiresAt: self::ISSUED_AT + 300));
        $prefix = $this->prefixOf($leg, $seed);

        $codes = $this->forkWorkers($leg, $backend, $prefix, 8, 'consume');
        sort($codes);

        self::assertSame([0, 1, 1, 1, 1, 1, 1, 1], $codes, 'exactly one consume winner, every loser reads the consumed state, no failures');
        $final = $this->storageOn($leg, $backend, $prefix, ttlMarginSecs: 60);
        $after = $final->consume(self::wn('fork-nonce'));
        self::assertTrue($after?->consumedBefore);
        self::assertSame('fork-win', $after?->consumedResult?->binding, 'the single winner committed exactly one result');
    }

    #[DataProvider('storageLegProvider')]
    public function testForkedIdentityConsumersRecordExactlyTheWinnersIdentity(string $leg): void
    {
        if (!\function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is unavailable; the forked race needs real processes');
        }
        [$seed, $backend] = $this->newStorage($leg, ttlMarginSecs: 60, wallClock: true);
        $seed->store($this->makeRecord('fork-identity', expiresAt: self::ISSUED_AT + 300));
        $prefix = $this->prefixOf($leg, $seed);

        $codes = $this->forkWorkers($leg, $backend, $prefix, 6, 'identity');
        $winners = array_filter($codes, static fn (int $c): bool => $c === 0);

        self::assertCount(1, $winners, 'exactly one identity-bearing consume wins');

        $final = $this->storageOn($leg, $backend, $prefix, ttlMarginSecs: 60);
        $consumed = $final->consumedState(self::wn('fork-identity'));
        self::assertNotNull($consumed?->operationIdentity);
        self::assertMatchesRegularExpression('/^op-fork-[0-9]+$/', $consumed->operationIdentity, 'the stored identity is provably the actual winner identity');
    }

    #[DataProvider('storageLegProvider')]
    public function testForkedConsumeVersusCancelNeverRedeemsACancelledRecord(string $leg): void
    {
        if (!\function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is unavailable; the forked race needs real processes');
        }
        [$seed, $backend] = $this->newStorage($leg, ttlMarginSecs: 60, wallClock: true);
        $seed->store($this->makeRecord('fork-mixed', expiresAt: self::ISSUED_AT + 300));
        $prefix = $this->prefixOf($leg, $seed);

        $codes = $this->forkWorkers($leg, $backend, $prefix, 8, 'mixed');
        $consumeWins = array_filter($codes, static fn (int $c): bool => $c === 0);
        $consumeNulls = array_filter($codes, static fn (int $c): bool => $c === 2);
        $cancelFresh = array_filter($codes, static fn (int $c): bool => $c === 10);
        $errors = array_filter($codes, static fn (int $c): bool => $c === 3 || $c === 5);

        self::assertSame([], array_values($errors), 'no worker failed on lock contention');
        self::assertLessThanOrEqual(1, \count($consumeWins), 'at most one consume winner exists in every interleaving');
        // Either exactly one consume won and the cancellers all saw the
        // finalized record, or a cancellation won first and every
        // consumer read the dead record as missing.
        $final = $this->storageOn($leg, $backend, $prefix, ttlMarginSecs: 60);
        if (\count($consumeWins) === 1) {
            self::assertSame([], array_values($cancelFresh), 'a consume winner finalizes the record before every cancellation');
            self::assertSame(ChallengeRuntimeStateKind::Consumed, $final->runtimeState(self::wn('fork-mixed'))->kind);
        } else {
            self::assertCount(1, $cancelFresh, 'with no consume winner exactly one cancellation flipped the record');
            self::assertCount(4, $consumeNulls, 'every consumer read the cancelled record as missing');
            self::assertSame(ChallengeRuntimeStateKind::Cancelled, $final->runtimeState(self::wn('fork-mixed'))->kind);
        }
    }

    #[DataProvider('storageLegProvider')]
    public function testForkedClaimersElectExactlyOneDerivationOwner(string $leg): void
    {
        if (!\function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is unavailable; the forked race needs real processes');
        }
        [$seed, $backend] = $this->newStorage($leg, ttlMarginSecs: 60, wallClock: true);
        $seed->store($this->makeRecord('fork-claim', expiresAt: self::ISSUED_AT + 300));
        $seed->consume(self::wn('fork-claim'));
        $prefix = $this->prefixOf($leg, $seed);

        $codes = $this->forkWorkers($leg, $backend, $prefix, 6, 'claim');
        $winners = array_filter($codes, static fn (int $c): bool => $c === 0);
        $refused = array_filter($codes, static fn (int $c): bool => $c === 1);

        self::assertCount(1, $winners, 'exactly one recovery holds the derivation lease');
        self::assertCount(5, $refused, 'every other recovery is refused while the lease is live');
    }

    /**
     * Fork N workers; every child constructs its own adapter over the
     * same backend (the emulation through segment attachment, the real
     * extension through its inherited shared segment), jitters its
     * start, runs one transition and reports the outcome through its
     * exit code. Children never print and never touch the parent
     * storage; the parent collects the codes after every child exits.
     *
     * @return list<int> the exit code of each worker, parent order
     */
    private function forkWorkers(string $leg, ApcuBackendInterface $backend, string $prefix, int $count, string $mode): array
    {
        $descriptor = $backend instanceof SharedMemoryApcuBackend ? $backend->descriptor() : null;
        $pids = [];
        for ($i = 0; $i < $count; $i++) {
            $pid = pcntl_fork();
            if ($pid === 0) {
                exit($this->runWorker($leg, $descriptor, $prefix, $i, $mode));
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
    private function runWorker(string $leg, ?array $descriptor, string $prefix, int $index, string $mode): int
    {
        try {
            usleep(random_int(0, 4000));
            $backend = $leg === 'emulated'
                ? SharedMemoryApcuBackend::attach($descriptor['shm'], $descriptor['sem'])
                : new RealApcuBackend();
            $storage = new ApcuStorage($backend, $prefix, lockTimeoutMs: 15000, ttlMarginSecs: 60);
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

    /**
     * One fresh storage over a fresh backend of the leg, with the
     * deterministic clock and a random key prefix.
     *
     * @return array{0: ApcuStorage, 1: ApcuBackendInterface}
     */
    private function newStorage(string $leg, int $ttlMarginSecs = 60, int $lockTimeoutMs = 5000, ?string $prefix = null, bool $wallClock = false): array
    {
        [$backend, $prefix] = $this->newBackend($leg, $prefix);
        $now = $wallClock ? null : fn (): int => $this->clock;

        return [
            new ApcuStorage($backend, $prefix, lockTimeoutMs: $lockTimeoutMs, ttlMarginSecs: $ttlMarginSecs, now: $now),
            $backend,
        ];
    }

    /**
     * One more storage over an existing backend and prefix: the shared
     * backend path of the two-adapter and post-fork reads.
     */
    private function storageOn(string $leg, ApcuBackendInterface $backend, string $prefix, int $lockTimeoutMs = 5000, int $ttlMarginSecs = 60): ApcuStorage
    {
        return new ApcuStorage($backend, $prefix, lockTimeoutMs: $lockTimeoutMs, ttlMarginSecs: $ttlMarginSecs);
    }

    /**
     * A fresh backend of the leg with a fresh random prefix.
     *
     * @return array{0: ApcuBackendInterface, 1: string}
     */
    private function newBackend(string $leg, ?string $prefix = null): array
    {
        $prefix ??= 'kiwi-apcu-test-'.bin2hex(random_bytes(6));
        if ($leg === 'real-apcu') {
            if (!RealApcuTestEnv::gate('the real-APCu contract leg')) {
                self::markTestSkipped('the APCu extension is absent here; the emulated backend leg carries this contract');
            }

            return [new RealApcuBackend(), $prefix];
        }
        $backend = SharedMemoryApcuBackend::create();
        $this->ownedBackends[] = $backend;

        return [$backend, $prefix];
    }

    /** The key prefix a storage derives its layout from. */
    private function prefixOf(string $leg, ApcuStorage $storage): string
    {
        $record = $storage->keysFor(self::wn('probe'))['record'];

        return substr($record, 0, strrpos($record, ':rec:'));
    }

    private function makeRecord(string $nonce, ?int $expiresAt = null, ?int $issuedAt = null): ChallengeRecord
    {
        return new ChallengeRecord(
            nonce: self::wn($nonce),
            scope: 'login',
            bindingTag: 'tag-1',
            issuedAt: $issuedAt ?? self::ISSUED_AT,
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
     * Rewrite one stored envelope through the raw backend, preserving
     * the layout version the tamper must ride on.
     */
    private function rewriteEnvelope(ApcuBackendInterface $backend, ApcuStorage $storage, string $nonce, \Closure $mutate): void
    {
        $key = $storage->keysFor($nonce)['record'];
        $raw = $backend->fetch($key)->value();
        self::assertIsString($raw);
        $envelope = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($envelope);
        $envelope = $mutate($envelope);
        self::assertTrue($backend->store($key, json_encode($envelope, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), 3600));
    }

    /**
     * Issue and solve on a storage whose clock runs on the wall, for
     * the lock-contention suites.
     *
     * @return array{0: ChallengeRecord, 1: string}
     */
    private function issueOnStorage(ApcuStorage $storage): array
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
}
