<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

use KiwiCaptcha\AtomicDeleteIfPendingInterface;
use KiwiCaptcha\AtomicStorageInterface;
use KiwiCaptcha\AuthenticatedResultCommitInterface;
use KiwiCaptcha\CancellableStorageInterface;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\ChallengeRuntimeState;
use KiwiCaptcha\ChallengeRuntimeStateKind;
use KiwiCaptcha\ChallengeRuntimeStateReadableInterface;
use KiwiCaptcha\ConsumedRecord;
use KiwiCaptcha\ConsumedResult;
use KiwiCaptcha\ConsumedStateReadableInterface;
use KiwiCaptcha\CancellationResult;
use KiwiCaptcha\DeleteIfPendingResult;
use KiwiCaptcha\OperationIdentity;
use KiwiCaptcha\OperationIdentityAwareStorageInterface;
use KiwiCaptcha\ReplicationBarrierInterface;
use KiwiCaptcha\ResumeDerivationClaimInterface;

/**
 * APCu-backed storage: the zero-infrastructure adapter for one PHP
 * host, no network and no file beside the shared memory segment the
 * extension already manages.
 *
 * Every durable state transition runs under a per-nonce transition
 * lock built from one primitive: `apcu_add()` on a lock key, the
 * atomic create-if-absent the extension serializes inside its segment.
 * The lock is acquired before the body reads, held across the
 * read-decide-write, and released after the write lands, so two racing
 * consumers of one nonce serialize: exactly one caller wins
 * `consumedNow` and the loser reads the winner's retained consumed
 * state. The atomicity contract of {@see AtomicStorageInterface} holds
 * on this backend through that lock discipline.
 *
 * Why `apcu_add()` and not the other candidates. `apcu_cas()` only
 * exchanges integers, so it cannot carry a record envelope. An
 * `flock()` sidecar lock file would move half of every transition onto
 * a second durable substrate the adapter does not govern, with a lock
 * file lifecycle the segment never shares. The add-key keeps every
 * transition inside APCu itself, and a crashed lock holder self-heals
 * through the lock key's TTL rather than through orphaned files.
 *
 * The lock's honest limit, documented rather than hidden: a kernel
 * `flock()` releases when its holder dies, while an APCu lock key
 * survives a crashed holder until its TTL passes. The TTL is therefore
 * generous against every documented transition (the body is
 * milliseconds). The release compares the lock's value against the
 * random token the holder installed, so a stalled holder that lost its
 * lock to TTL expiry never deletes a successor's lock. The residual
 * fetch-then-delete window is bounded by that same TTL margin.
 *
 * Records are one envelope value per nonce, the exact runtime column
 * set of the SQLite row: the canonical record JSON, the state, the
 * committed result, the recorded operation identity, the resume-claim
 * lease and the retention deadline. Envelope bytes decode through the
 * strict authority {@see StrictJson::decodeObject()}, so a corrupt
 * value fails closed exactly like a corrupt value on any other
 * backend. Logical retention mirrors the peers: a record whose signed
 * expiry plus the retention margin has passed on the storage clock is
 * absent to every read and transition. The physical sweep is the TTL
 * itself, the mechanism this backend owns natively: every record write
 * carries the retention deadline as its entry TTL, clamped to a
 * ceiling. The segment collects dead records without a scan, and no
 * expired entry can outlive its retention by more than that bound.
 *
 * Documented limits, exactly as the storage-plane design frames them:
 * this is the single-PHP-host adapter. The APCu segment is process
 * memory shared by the workers of one server; there is no replication,
 * no failover and no cross-host topology, and the segment is lost on
 * restart, which every expiry and retention bound already tolerates.
 * Deployments that need shared or replicated stores use the Redis
 * backend.
 *
 * Honest limitation of this adapter's own test surface: the real
 * backend needs the APCu extension, and many CI images lack it. All
 * state flows through the narrow {@see ApcuBackendInterface} seam, so
 * the full invariant suite runs unchanged against a fork-shareable
 * shared-memory emulation of that seam. The real-APCu leg of the suite
 * auto-skips when the extension is absent and runs where it is
 * installed.
 *
 * Implements the same capability set as {@see RedisStorage},
 * {@see SqliteStorage} and {@see FilesystemStorage}. The retained
 * consumed-state read, the identity-bearing consume, the fused
 * delete-if-pending cleanup, the cancellation transition, the
 * single-snapshot runtime-state read, the resume-derivation claim and
 * the authenticated result commit, each fused into one locked
 * transition. The replication fence of
 * {@see ReplicationBarrierInterface} is an explicit no-op: one host's
 * segment write is already visible to every worker on it, and there is
 * no replica acknowledgement to wait for.
 */
final class ApcuStorage implements AtomicStorageInterface, ConsumedStateReadableInterface, OperationIdentityAwareStorageInterface, AtomicDeleteIfPendingInterface, CancellableStorageInterface, ChallengeRuntimeStateReadableInterface, ReplicationBarrierInterface, ResumeDerivationClaimInterface, AuthenticatedResultCommitInterface
{
    /**
     * The envelope layout version this adapter writes, carried inside
     * every record value. An envelope stamped with a newer version is
     * refused as corrupt: a downgrade must never trust a layout a
     * future release owns.
     */
    private const ENVELOPE_VERSION = 1;

    /**
     * The transition-lock TTL: a crashed holder's lock key dies after
     * this bound, the APCu-native stand-in for the kernel releasing an
     * `flock()` when its holder dies. Transition bodies run in
     * milliseconds, so the bound is two orders above every documented
     * ceiling while keeping crash recovery prompt.
     */
    private const LOCK_TTL_SECS = 30;

    /**
     * The record-TTL ceiling. Record entries carry their retention
     * deadline as the TTL so the segment sweeps dead records itself;
     * the ceiling bounds the clamp when the storage clock runs ahead
     * of the wall clock the TTL counts on. An entry collected early
     * still reads as an expired record on every path, so the ceiling
     * can never widen retention semantics, only narrow the sweep lag.
     */
    private const TTL_CEILING_SECS = 86_400;

    private ApcuBackendInterface $backend;

    private string $prefix;

    /**
     * @param ApcuBackendInterface|null $backend        the backend
     *                                                 seam, defaulting
     *                                                 to the real
     *                                                 APCu backend;
     *                                                 inject the
     *                                                 emulated backend
     *                                                 in tests.
     * @param string                   $keyPrefix      the key namespace,
     *                                                 separating one
     *                                                 deployment's
     *                                                 records from a
     *                                                 neighbor's in a
     *                                                 shared segment.
     * @param int                      $lockTimeoutMs  how long a
     *                                                 transition waits
     *                                                 for the per-nonce
     *                                                 lock before
     *                                                 failing closed.
     * @param int                      $ttlMarginSecs  extra retention
     *                                                 beyond the signed
     *                                                 expiry, mirroring
     *                                                 the Redis
     *                                                 backend's margin.
     * @param \Closure|null            $now            the storage clock
     *                                                 in epoch seconds,
     *                                                 defaulting to
     *                                                 time().
     *                                                 A test seam for
     *                                                 deterministic
     *                                                 expiry and lease
     *                                                 checks.
     *
     * @throws ApcuStorageException   when the default real backend is
     *                                requested and the extension is
     *                                missing or disabled
     * @throws \InvalidArgumentException when an argument is out of
     *                                  range.

     */
    public function __construct(
        ?ApcuBackendInterface $backend = null,
        string $keyPrefix = 'kiwicaptcha',
        private readonly int $lockTimeoutMs = 5000,
        private readonly int $ttlMarginSecs = 60,
        private readonly ?\Closure $now = null,
    ) {
        if ($this->lockTimeoutMs < 0) {
            throw new \InvalidArgumentException('lockTimeoutMs must be >= 0');
        }
        if ($this->ttlMarginSecs < 0) {
            throw new \InvalidArgumentException('ttlMarginSecs must be >= 0');
        }
        if ($keyPrefix === '') {
            throw new \InvalidArgumentException('keyPrefix must not be empty');
        }
        $this->backend = $backend ?? new RealApcuBackend();
        $this->prefix = $keyPrefix;
    }

    /**
     * Diagnostic seam mirroring {@see FilesystemStorage::pathsFor()}.
     * It exposes the two backend keys a nonce maps onto, so operators
     * and tests can inspect and fence the documented layout. The storage itself
     * resolves every key through this same derivation.
     *
     * @return array{record: string, lock: string}
     */
    public function keysFor(string $nonce): array
    {
        return [
            'record' => $this->prefix.':rec:'.$nonce,
            'lock' => $this->prefix.':lock:'.$nonce,
        ];
    }

    /**
     * Store a challenge record, replacing any existing record with the
     * same nonce. The envelope lands in its pending state with no
     * result, no identity and no claim lease, under the transition
     * lock so a concurrent transition on the same nonce serializes
     * against the replacement. The retention deadline rides the
     * entry as its TTL.
     */
    public function store(ChallengeRecord $record): void
    {
        $retainedUntil = $record->expiresAt + $this->ttlMarginSecs;
        $keys = $this->keysFor($record->nonce);

        $this->writeTransition('challenge issuance', $record->nonce, function () use ($record, $retainedUntil, $keys): void {
            $prior = $this->liveDecoded($keys['record']);
            if ($prior !== null && ($prior['state'] ?? 'pending') !== 'pending') {
                throw new StorageWriteException('refusing to rewind a consumed or cancelled record to pending');
            }
            $this->putEnvelope(
                $keys['record'],
                $this->encodeEnvelope($record, 'pending', null, null, null, null, $retainedUntil),
                'challenge issuance',
                $retainedUntil,
            );
        });
    }

    public function find(string $nonce): ?ChallengeRecord
    {
        return $this->read('finding the record', function () use ($nonce): ?ChallengeRecord {
            $decoded = $this->liveDecoded($this->keysFor($nonce)['record']);

            return $decoded === null ? null : $decoded['record'];
        });
    }

    /**
     * The atomic consume transition. The per-nonce lock is held across
     * the read and the flip, so a concurrent consumer of the same
     * nonce waits, then observes this caller's written consumed state:
     * exactly one caller wins `consumedNow`. A cancelled, corrupt or
     * expired record reports missing, mirroring the Redis script's nil
     * semantics.
     */
    public function consume(string $nonce): ?ConsumedRecord
    {
        return $this->doConsume($nonce, null);
    }

    /**
     * The identity-bearing consume transition: the validated identity
     * is written in the same locked transition as the state flip, so
     * the stored identity is provably the actual transition winner's.
     */
    public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?ConsumedRecord
    {
        return $this->doConsume($nonce, OperationIdentity::validate($operationIdentity));
    }

    /**
     * The shared implementation of both consume entry points. The
     * pending-envelope guard mirrors the Redis script's marker check:
     * a pending envelope that already carries a result, an identity or
     * a claim lease is a forged or damaged rewrite and reports
     * missing, never a fresh grant.
     *
     * @throws StorageWriteException when the flipped envelope write
     *                               is refused by the backend
     */
    private function doConsume(string $nonce, ?string $identity): ?ConsumedRecord
    {
        $keys = $this->keysFor($nonce);

        return $this->writeTransition('the pending-to-consumed transition', $nonce, function () use ($keys, $identity): ?ConsumedRecord {
            $decoded = $this->liveDecoded($keys['record']);
            if ($decoded === null) {
                return null;
            }
            if ($decoded['state'] === 'consumed') {
                return new ConsumedRecord($decoded['record'], false, true, $decoded['result'], $decoded['identity']);
            }
            if ($decoded['state'] !== 'pending') {
                // A cancelled record is never consumable, and any other
                // value is corruption the decode already normalized.
                return null;
            }
            if ($decoded['result'] !== null || $decoded['identity'] !== null || $decoded['resume_owner'] !== null) {
                return null;
            }
            $this->putEnvelope(
                $keys['record'],
                $this->encodeEnvelope($decoded['record'], 'consumed', null, $identity, null, null, $decoded['retained_until']),
                'the pending-to-consumed transition',
                $decoded['retained_until'],
            );

            return new ConsumedRecord($decoded['record'], true, false, null, $identity);
        });
    }

    /**
     * The retained consumed state, read without any transition: the
     * committed result and the recorded identity ride back, exactly
     * what the idempotent consumed-outcome recovery resolves through.
     */
    public function consumedState(string $nonce): ?ConsumedRecord
    {
        return $this->read('reading the consumed state', function () use ($nonce): ?ConsumedRecord {
            $decoded = $this->liveDecoded($this->keysFor($nonce)['record']);
            if ($decoded === null || $decoded['state'] !== 'consumed') {
                return null;
            }

            return new ConsumedRecord($decoded['record'], false, true, $decoded['result'], $decoded['identity']);
        });
    }

    /**
     * Commit the deterministic result of a consumed record. The locked
     * transition fuses the check and the write, so the commit is
     * one-shot: only a retained, consumed, resultless record is
     * written, exactly once, by exactly one caller.
     */
    public function commitResult(string $nonce, bool $valid, ?string $binding): bool
    {
        return $this->commitAuthenticatedResult($nonce, new ConsumedResult($valid, $binding));
    }

    /**
     * The MAC-carrying commit, see
     * {@see AuthenticatedResultCommitInterface}: the result object is
     * stored verbatim, the server-state MAC included.
     */
    public function commitAuthenticatedResult(string $nonce, ConsumedResult $result): bool
    {
        $keys = $this->keysFor($nonce);

        return $this->writeTransition('the result commit', $nonce, function () use ($keys, $result): bool {
            $decoded = $this->liveDecoded($keys['record']);
            if ($decoded === null || $decoded['state'] !== 'consumed' || $decoded['result'] !== null) {
                return false;
            }
            $this->putEnvelope(
                $keys['record'],
                $this->encodeEnvelope($decoded['record'], 'consumed', $result, $decoded['identity'], $decoded['resume_owner'], $decoded['resume_until'], $decoded['retained_until']),
                'the result commit',
                $decoded['retained_until'],
            );

            return true;
        });
    }

    /**
     * Delete a record by nonce, inside one locked transition so a
     * concurrent transition on the same record is serialized against
     * it. The claim lease is a field of the same envelope, so it goes
     * with the record.
     */
    public function delete(string $nonce): void
    {
        $keys = $this->keysFor($nonce);

        $this->writeTransition('the record deletion', $nonce, function () use ($keys): void {
            $this->backend->delete($keys['record']);
        });
    }

    /**
     * The fused cleanup transition: one locked transition decides
     * missing, deleted-pending, consumed, cancelled or corrupt, and
     * only the exact pending record is deleted. A consumed record
     * keeps its retained evidence and answers with it, a cancelled
     * record is kept as dead until its retention ends, and a corrupt
     * record is reported without being mutated.
     */
    public function deleteIfPending(string $nonce): DeleteIfPendingResult
    {
        $keys = $this->keysFor($nonce);

        return $this->writeTransition('the delete-if-pending transition', $nonce, function () use ($keys): DeleteIfPendingResult {
            $outcome = $this->backend->fetch($keys['record']);
            if (!$outcome->found) {
                return new DeleteIfPendingResult('missing');
            }
            $decoded = $this->decodeEnvelope($outcome->value());
            if ($decoded === null) {
                return new DeleteIfPendingResult('corrupt');
            }
            if ($this->nowInSeconds() >= $decoded['retained_until']) {
                // A decodable record past its retention reads missing,
                // the exact mirror of an expired row or file.
                return new DeleteIfPendingResult('missing');
            }
            if ($decoded['state'] === 'consumed') {
                return new DeleteIfPendingResult('consumed', new ConsumedRecord(
                    $decoded['record'],
                    false,
                    true,
                    $decoded['result'],
                    $decoded['identity'],
                ));
            }
            if ($decoded['state'] === 'cancelled') {
                return new DeleteIfPendingResult('cancelled');
            }
            if ($decoded['state'] !== 'pending') {
                return new DeleteIfPendingResult('corrupt');
            }
            $this->backend->delete($keys['record']);

            return new DeleteIfPendingResult('deleted-pending');
        });
    }

    /**
     * The single-snapshot runtime-state read: one fetch classifies
     * missing, pending, consumed or cancelled from the same value
     * bytes, never two separately timed reads. The backend's atomic
     * fetch makes the single read a consistent snapshot.
     */
    public function runtimeState(string $nonce): ChallengeRuntimeState
    {
        return $this->read('reading the runtime state', function () use ($nonce): ChallengeRuntimeState {
            $decoded = $this->liveDecoded($this->keysFor($nonce)['record']);
            if ($decoded === null) {
                // A corrupt or expired record fails closed as missing,
                // never pending.
                return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Missing);
            }
            if ($decoded['state'] === 'cancelled') {
                return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Cancelled, $decoded['record']);
            }
            if ($decoded['state'] === 'consumed') {
                $consumed = new ConsumedRecord($decoded['record'], false, true, $decoded['result'], $decoded['identity']);

                return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Consumed, $decoded['record'], $consumed);
            }
            if ($decoded['state'] === 'pending') {
                return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Pending, $decoded['record']);
            }

            return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Missing);
        });
    }

    /**
     * The atomic cancellation transition: pending flips to the
     * terminal cancelled state inside one locked transition, so a
     * concurrent consumer that flipped first is observed consumed and
     * never cancelled. A consumed record is finalized and refused, an
     * already-cancelled record is idempotent, and a missing or corrupt
     * record answers null.
     */
    public function cancel(string $nonce): ?CancellationResult
    {
        $keys = $this->keysFor($nonce);

        return $this->writeTransition('the pending-to-cancelled transition', $nonce, function () use ($keys): ?CancellationResult {
            $decoded = $this->liveDecoded($keys['record']);
            if ($decoded === null) {
                return null;
            }
            if ($decoded['state'] === 'consumed') {
                return new CancellationResult('consumed');
            }
            if ($decoded['state'] === 'cancelled') {
                return new CancellationResult('cancelled');
            }
            if ($decoded['state'] !== 'pending') {
                return null;
            }
            $this->putEnvelope(
                $keys['record'],
                $this->encodeEnvelope($decoded['record'], 'cancelled', null, $decoded['identity'], null, null, $decoded['retained_until']),
                'the pending-to-cancelled transition',
                $decoded['retained_until'],
            );

            return new CancellationResult('cancelled-now');
        });
    }

    /**
     * The replication-fence acceptance point as an explicit no-op:
     * this backend has exactly one host, a segment write is already
     * visible to every worker on it, and there is no replica
     * acknowledgement an acceptance point could wait for.
     */
    public function establishReplicationFence(string $what): void
    {
        // Intentionally nothing: single-host visibility is the write.
    }

    /**
     * Claim the re-derivation ownership of a consumed, resultless
     * record under a bounded lease. The transition lock fuses the
     * claimability check with the lease write, so exactly one
     * concurrent recovery wins the claim; the losers read null. The
     * lease lives inside the record envelope, so a concurrent commit
     * can never leave it behind. A lease that expired on the storage
     * clock is re-claimable, mirroring the Redis envelope lease.
     *
     * @param int $ttlSecs the claim lease length in seconds (>= 1)
     *
     * @throws \InvalidArgumentException when $ttlSecs is below 1
     */
    public function claimResumeDerivation(string $nonce, int $ttlSecs = 60): ?string
    {
        if ($ttlSecs < 1) {
            throw new \InvalidArgumentException('the resume claim TTL must be at least 1 second');
        }
        $keys = $this->keysFor($nonce);

        return $this->writeTransition('the resume-derivation claim', $nonce, function () use ($keys, $ttlSecs): ?string {
            $decoded = $this->liveDecoded($keys['record']);
            if ($decoded === null || $decoded['state'] !== 'consumed' || $decoded['result'] !== null) {
                return null;
            }
            if ($decoded['resume_owner'] !== null && $decoded['resume_until'] !== null && $decoded['resume_until'] > $this->nowInSeconds()) {
                return null;
            }
            // Secure RNG fail closed: a repeatable owner could let two
            // recoveries observe the same apparent ownership across a
            // lease expiry, so generation failure propagates.
            $owner = bin2hex(random_bytes(16));
            $this->putEnvelope(
                $keys['record'],
                $this->encodeEnvelope($decoded['record'], 'consumed', null, $decoded['identity'], $owner, $this->nowInSeconds() + $ttlSecs, $decoded['retained_until']),
                'the resume-derivation claim',
                $decoded['retained_until'],
            );

            return $owner;
        });
    }

    /**
     * Compare-and-delete release of the resume claim: the lease is
     * cleared only when the envelope still holds exactly this owner
     * token, so a stale owner can never clear a newer recovery's
     * claim.
     *
     * @throws \InvalidArgumentException when the owner is not 32 lowercase hex chars
     */
    public function releaseResumeDerivation(string $nonce, string $owner): bool
    {
        $this->assertValidResumeOwner($owner);
        $keys = $this->keysFor($nonce);

        return $this->writeTransition('the resume-claim release', $nonce, function () use ($keys, $owner): bool {
            $decoded = $this->liveDecoded($keys['record']);
            if ($decoded === null || $decoded['resume_owner'] !== $owner) {
                return false;
            }
            $this->putEnvelope(
                $keys['record'],
                $this->encodeEnvelope($decoded['record'], $decoded['state'], $decoded['result'], $decoded['identity'], null, null, $decoded['retained_until']),
                'the resume-claim release',
                $decoded['retained_until'],
            );

            return true;
        });
    }

    /**
     * The resume-path commit: the claim is a fencing precondition and
     * is cleared in the same locked transition as the result write. A
     * stale owner, an expired lease or a record that gained a result
     * is refused without any write.
     *
     * @throws \InvalidArgumentException when the owner is not 32 lowercase hex chars
     */
    public function commitResultResume(string $nonce, bool $valid, ?string $binding, string $owner): bool
    {
        return $this->commitAuthenticatedResultResume($nonce, new ConsumedResult($valid, $binding), $owner);
    }

    /** The MAC-carrying resume commit, see {@see self::commitResultResume()}. */
    public function commitAuthenticatedResultResume(string $nonce, ConsumedResult $result, string $owner): bool
    {
        $this->assertValidResumeOwner($owner);
        $keys = $this->keysFor($nonce);

        return $this->writeTransition('the claim-bearing result commit', $nonce, function () use ($keys, $result, $owner): bool {
            $decoded = $this->liveDecoded($keys['record']);
            if ($decoded === null || $decoded['state'] !== 'consumed' || $decoded['result'] !== null) {
                return false;
            }
            if ($decoded['resume_owner'] !== $owner || $decoded['resume_until'] === null || $decoded['resume_until'] <= $this->nowInSeconds()) {
                return false;
            }
            $this->putEnvelope(
                $keys['record'],
                $this->encodeEnvelope($decoded['record'], 'consumed', $result, $decoded['identity'], null, null, $decoded['retained_until']),
                'the claim-bearing result commit',
                $decoded['retained_until'],
            );

            return true;
        });
    }

    /**
     * The shared resume-claim owner contract, identical to the Redis,
     * SQLite, filesystem and array backends: exactly 32 lowercase hex
     * characters.
     *
     * @throws \InvalidArgumentException
     */
    private function assertValidResumeOwner(string $owner): void
    {
        if (preg_match('/^[0-9a-f]{32}$/D', $owner) !== 1) {
            throw new \InvalidArgumentException('the resume claim owner must be exactly 32 lowercase hex characters');
        }
    }

    /**
     * Run one durable transition under the per-nonce lock. The lock is
     * taken before the body reads, so the read-decide-write sequence is
     * serialized against every other process on the same nonce. The
     * lock key carries the holder's random token, and the release
     * deletes the key only while that token still sits in it, so a
     * stalled holder whose TTL passed never removes a successor's
     * lock. A backend refusal inside the body surfaces as the typed
     * fail-closed exception with the lock released.
     *
     * @template T
     *
     * @param callable():T $body the transition, reading and writing entries
     *
     * @return T
     */
    private function writeTransition(string $what, string $nonce, callable $body): mixed
    {
        $lockKey = $this->keysFor($nonce)['lock'];
        $token = $this->acquireTransitionLock($what, $lockKey);
        try {
            return $body();
        } finally {
            $this->releaseTransitionLock($lockKey, $token);
        }
    }

    /**
     * Acquire the per-nonce transition lock through the backend's
     * atomic create-if-absent, polling without blocking until the
     * configured deadline; a lock that stays held past the deadline
     * fails closed with the remedy in the message. A lock generation
     * failure fails closed too: a transition without its lock would
     * break the single-use guarantee the lock exists to hold.
     *
     * @return string the random lock token this holder installed
     */
    private function acquireTransitionLock(string $what, string $lockKey): string
    {
        try {
            $token = bin2hex(random_bytes(8));
        } catch (\Throwable $e) {
            throw self::storageFailure($what, 'the transition lock token could not be generated: '.$e->getMessage());
        }
        $deadline = microtime(true) + ($this->lockTimeoutMs / 1000.0);
        while (!$this->backend->add($lockKey, $token, self::LOCK_TTL_SECS)) {
            if (microtime(true) >= $deadline) {
                throw self::lockContention($what);
            }
            usleep(2000);
        }

        return $token;
    }

    /**
     * Release the transition lock: the key is deleted only while it
     * still carries this holder's token, so a successor that acquired
     * after a TTL expiry keeps its own lock.
     */
    private function releaseTransitionLock(string $lockKey, string $token): void
    {
        $outcome = $this->backend->fetch($lockKey);
        if ($outcome->found && $outcome->value() === $token) {
            $this->backend->delete($lockKey);
        }
    }

    /**
     * The typed contention failure, mirroring the SQLite and
     * filesystem remedies: the failing operation, the held lock, and
     * how to widen the wait or serialize the writers.
     */
    private static function lockContention(string $what): ApcuStorageException
    {
        return new ApcuStorageException(sprintf(
            'apcu storage failure during %s: the transition lock stayed held past the lock timeout; raise lockTimeoutMs or serialize the writers on this host',
            $what,
        ));
    }

    /**
     * Run one read-only path, mapping an unexpected failure to the
     * typed fail-closed exception the verifier resolves as an
     * unavailable store.
     *
     * @template T
     *
     * @param callable():T $body
     *
     * @return T
     */
    private function read(string $what, callable $body): mixed
    {
        try {
            return $body();
        } catch (ApcuStorageException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw self::storageFailure($what, $e->getMessage());
        }
    }

    /**
     * Write one envelope value under its record key with the retention
     * deadline as the TTL. A backend refusal fails closed: a
     * transition whose write never landed must never answer as though
     * it had.
     */
    private function putEnvelope(string $recordKey, string $json, string $what, int $retainedUntil): void
    {
        $ttl = max(1, min($retainedUntil - time(), self::TTL_CEILING_SECS));
        if (!$this->backend->store($recordKey, $json, $ttl)) {
            throw self::storageFailure($what, 'the backend refused the record write; the APCu segment may be full');
        }
    }

    /**
     * The decoded envelope for a nonce, or null when the entry is
     * absent, undecodable, or past its retention: the expiry boundary
     * is `now >= retained_until`, the exact mirror of a Redis key
     * whose TTL elapsed.
     *
     * @return array{record: ChallengeRecord, result: ConsumedResult|null, identity: string|null, state: string, resume_owner: string|null, resume_until: int|null, retained_until: int}|null
     */
    private function liveDecoded(string $recordKey): ?array
    {
        $outcome = $this->backend->fetch($recordKey);
        if (!$outcome->found) {
            return null;
        }
        $decoded = $this->decodeEnvelope($outcome->value());
        if ($decoded === null) {
            return null;
        }
        if ($this->nowInSeconds() >= $decoded['retained_until']) {
            return null;
        }

        return $decoded;
    }

    /**
     * Decode one envelope value into the record, its committed result,
     * its recorded identity and its claim lease. The bytes pass the
     * strict authority {@see StrictJson::decodeObject()} first, so a
     * corrupt value fails closed exactly like a corrupt value on any
     * other backend. A malformed committed result degrades to absent.
     * Any structural failure answers null: an unusable record, never a
     * partially trusted one.
     *
     * @return array{record: ChallengeRecord, result: ConsumedResult|null, identity: string|null, state: string, resume_owner: string|null, resume_until: int|null, retained_until: int}|null
     */
    private function decodeEnvelope(mixed $raw): ?array
    {
        if (!\is_string($raw)) {
            return null;
        }
        $envelope = StrictJson::decodeObject($raw);
        if ($envelope === null) {
            return null;
        }
        if (($envelope['version'] ?? null) !== self::ENVELOPE_VERSION) {
            // An envelope from a newer layout is corruption to this
            // release, never a partially trusted record.
            return null;
        }
        $recordData = $envelope['record'] ?? null;
        if (!\is_array($recordData)) {
            return null;
        }
        try {
            $record = ChallengeRecord::fromArray($recordData);
        } catch (\Throwable) {
            return null;
        }
        $state = $envelope['state'] ?? null;
        $state = \is_string($state) ? $state : '';
        if ($state !== 'pending' && $state !== 'consumed' && $state !== 'cancelled') {
            // A foreign state value reads as the empty string, which
            // every caller resolves through its corrupt path.
            $state = '';
        }
        $result = null;
        $rawResult = $envelope['consumed_result'] ?? null;
        if (\is_array($rawResult)) {
            try {
                $result = ConsumedResult::fromArray($rawResult);
            } catch (\Throwable) {
                $result = null;
            }
        }
        $identity = $envelope['operation_identity'] ?? null;
        $resumeOwner = $envelope['resume_owner'] ?? null;
        $resumeUntil = $envelope['resume_until'] ?? null;
        $retainedUntil = $envelope['retained_until'] ?? 0;

        return [
            'record' => $record,
            'result' => $result,
            'identity' => \is_string($identity) ? $identity : null,
            'state' => $state,
            'resume_owner' => \is_string($resumeOwner) ? $resumeOwner : null,
            'resume_until' => \is_int($resumeUntil) ? $resumeUntil : null,
            'retained_until' => \is_int($retainedUntil) ? $retainedUntil : 0,
        ];
    }

    /**
     * Encode one envelope write. The shape is the exact runtime column
     * set of the SQLite row: the canonical record, the state, the
     * committed result, the recorded identity, the claim lease and the
     * retention deadline every read and the TTL share.
     */
    private function encodeEnvelope(
        ChallengeRecord $record,
        string $state,
        ?ConsumedResult $result,
        ?string $identity,
        ?string $resumeOwner,
        ?int $resumeUntil,
        int $retainedUntil,
    ): string {
        $envelope = [
            'version' => self::ENVELOPE_VERSION,
            'record' => $record->toArray(),
            'state' => $state,
            'consumed_result' => $result?->toArray(),
            'operation_identity' => $identity,
            'resume_owner' => $resumeOwner,
            'resume_until' => $resumeUntil,
            'retained_until' => $retainedUntil,
        ];
        try {
            return json_encode($envelope, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw self::storageFailure('serializing the record envelope', $e->getMessage());
        }
    }

    /** The storage clock: the constructor seam or the wall clock. */
    private function nowInSeconds(): int
    {
        return $this->now !== null ? (int) ($this->now)() : time();
    }

    /**
     * Wrap a backend failure in the typed fail-closed exception with an
     * actionable message naming the failing operation and the
     * underlying error.
     */
    private static function storageFailure(string $what, string $error): ApcuStorageException
    {
        return new ApcuStorageException(sprintf('apcu storage failure during %s: %s', $what, $error));
    }
}
