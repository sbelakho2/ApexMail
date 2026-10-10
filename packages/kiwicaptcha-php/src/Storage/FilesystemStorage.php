<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

use KiwiCaptcha\AtomicDeleteIfPendingInterface;
use KiwiCaptcha\AtomicStorageInterface;
use KiwiCaptcha\AuthenticatedResultCommitInterface;
use KiwiCaptcha\CancellableStorageInterface;
use KiwiCaptcha\CancellationResult;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\ChallengeRuntimeState;
use KiwiCaptcha\ChallengeRuntimeStateKind;
use KiwiCaptcha\ChallengeRuntimeStateReadableInterface;
use KiwiCaptcha\ConsumedRecord;
use KiwiCaptcha\ConsumedResult;
use KiwiCaptcha\ConsumedStateReadableInterface;
use KiwiCaptcha\DeleteIfPendingResult;
use KiwiCaptcha\OperationIdentity;
use KiwiCaptcha\OperationIdentityAwareStorageInterface;
use KiwiCaptcha\ReplicationBarrierInterface;
use KiwiCaptcha\ResumeDerivationClaimInterface;

/**
 * Filesystem-backed storage: the zero-infrastructure adapter for a
 * deployment where even a database file is too much. One directory
 * holds one JSON envelope per live record, written with nothing
 * beyond the PHP core filesystem functions.
 *
 * Atomicity rests on two primitives. Every durable write lands
 * through a unique temporary file followed by `rename()`: renaming
 * within one filesystem replaces the target atomically, so a reader
 * observes either the whole record or the record that came before
 * it. A torn or partial file never appears under a final name.
 * Transitions that must compare file contents cannot be expressed as
 * a rename, so each one runs under an exclusive `flock()` on a
 * per-record lock file, held across the read, the decision and the
 * write. Two racing consumers of one nonce therefore serialize:
 * exactly one caller wins `consumedNow` and the loser reads the
 * winner's retained state. The atomicity contract of
 * {@see AtomicStorageInterface} holds on this backend through that
 * lock discipline.
 *
 * Layout: the record path is a namespaced SHA-256 of the nonce,
 * sharded by its first two hex characters, so the nonce itself never
 * reaches a path and each directory holds about one 256th of the
 * live records. The bound keeps directory scans short and creation
 * costs flat as the store grows. Beside the records, a `claims/`
 * tree holds the resume-derivation lease fences and a `locks/` tree
 * the per-record lock files: one lock file per live record, removed
 * by the same retention sweep that removes expired records.
 *
 * Documented limits, exactly as the storage-plane design frames
 * them: this is the single-node, single-host adapter. The store is
 * one directory on one local disk; there is no replication, no
 * failover and no shared multi-host topology, and concurrent
 * processes must run on the same machine over the same directory.
 * Advisory `flock()` semantics hold only on a local filesystem: on
 * an NFS mount two hosts can both believe they hold the lock, which
 * would break single-use, so the constructor demands an explicit
 * local-disk acknowledgement and refuses URL-style stream paths
 * outright. Deployments that need shared or replicated stores use
 * the Redis backend.
 *
 * Implements the same capability set as {@see RedisStorage} and
 * {@see SqliteStorage}. The retained consumed-state read, the
 * identity-bearing consume, the fused delete-if-pending cleanup, the
 * cancellation transition, the single-snapshot runtime-state read,
 * the resume-derivation claim and the authenticated result commit
 * each fuse into one locked transition. The replication fence of
 * {@see ReplicationBarrierInterface} is an explicit no-op: a renamed
 * file is already durable on the one node, and there is no replica
 * acknowledgement to wait for.
 */
final class FilesystemStorage implements AtomicStorageInterface, ConsumedStateReadableInterface, OperationIdentityAwareStorageInterface, AtomicDeleteIfPendingInterface, CancellableStorageInterface, ChallengeRuntimeStateReadableInterface, ReplicationBarrierInterface, ResumeDerivationClaimInterface, AuthenticatedResultCommitInterface
{
    /**
     * The layout marker this adapter writes into the store directory.
     * A directory carrying a different marker is refused: a newer
     * layout must never be mutated by an older release, and a foreign
     * directory must never be adopted as a store.
     */
    private const FORMAT_MARKER = 'kiwicaptcha-filesystem-1';

    /**
     * The hash namespace separating record paths from every other
     * file family in the store, so a nonce-derived path can never
     * collide with a claim, a lock or a foreign file.
     */
    private const HASH_NAMESPACE = 'kiwicaptcha:record:v1';

    /**
     * The age a temporary file must reach before the boot sweep
     * treats it as crashed-writer debris. No single write outlives
     * milliseconds, while debris from a crashed writer stays until a
     * later construction removes it, so the bound keeps the sweep
     * away from a concurrent writer's in-flight temporary file.
     */
    private const TEMP_DEBRIS_SECONDS = 300;

    private readonly string $recordsDir;

    private readonly string $locksDir;

    private readonly string $claimsDir;

    /**
     * @param string       $directory             the storage directory,
     *                                            created with mode
     *                                            0700 when absent;
     *                                            refused when it
     *                                            exists as a regular
     *                                            file, when it cannot
     *                                            be written, or when
     *                                            its layout marker is
     *                                            foreign or newer.
     * @param bool         $localDiskAcknowledged the operator's
     *                                            confirmation that the
     *                                            directory sits on a
     *                                            local disk; required,
     *                                            because lock and
     *                                            rename atomicity do
     *                                            not hold on a network
     *                                            mount.
     * @param int          $lockTimeoutMs         how long a transition
     *                                            waits for the
     *                                            per-record lock
     *                                            before failing
     *                                            closed.
     * @param int          $ttlMarginSecs         extra retention beyond
     *                                            the signed expiry,
     *                                            mirroring the Redis
     *                                            backend's margin: the
     *                                            record stays readable
     *                                            as recovery evidence
     *                                            for this many seconds
     *                                            past expires_at.
     * @param \Closure|null $now                   the storage clock in
     *                                            epoch seconds,
     *                                            defaulting to
     *                                            time(); a test seam
     *                                            for deterministic
     *                                            expiry and lease
     *                                            checks.
     *
     * @throws FilesystemStorageException when the directory is a file,
     *                                    unwritable, network-looking,
     *                                    unacknowledged, or refused by
     *                                    the layout guard.
     * @throws \InvalidArgumentException  when an argument is out of
     *                                    range.
     */
    public function __construct(
        private readonly string $directory,
        bool $localDiskAcknowledged = false,
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
        if (!$localDiskAcknowledged) {
            throw new FilesystemStorageException(
                'the filesystem storage requires the local-disk acknowledgement: confirm the directory sits on a local disk and construct with localDiskAcknowledged true, because lock and rename atomicity do not hold on a network filesystem'
            );
        }
        $this->assertNotANetworkPath($this->directory);
        $this->recordsDir = $this->directory.'/records';
        $this->locksDir = $this->directory.'/locks';
        $this->claimsDir = $this->directory.'/claims';
        $this->initializeLayout();
    }

    /**
     * Diagnostic seam mirroring {@see SqliteStorage::pdo()}: the three
     * file paths a nonce maps onto, so operators and tests can inspect
     * and fence the documented layout. The storage itself resolves
     * every path through this same derivation.
     *
     * @return array{record: string, lock: string, claim: string}
     */
    public function pathsFor(string $nonce): array
    {
        $hash = hash('sha256', self::HASH_NAMESPACE.':'.$nonce);
        $shard = substr($hash, 0, 2);
        $stem = substr($hash, 2);

        return [
            'record' => $this->recordsDir.'/'.$shard.'/'.$stem.'.json',
            'lock' => $this->locksDir.'/'.$shard.'/'.$stem.'.lock',
            'claim' => $this->claimsDir.'/'.$shard.'/'.$stem.'.claim',
        ];
    }

    /**
     * Refuse a stream URL as the store path: a network wrapper makes
     * every promise this adapter depends on a lie, and the cheap
     * signature of one is the `scheme://` prefix.
     */
    private function assertNotANetworkPath(string $directory): void
    {
        if (preg_match('~^[A-Za-z][A-Za-z0-9+.\-]*://~', $directory) === 1) {
            throw new FilesystemStorageException(sprintf(
                'the filesystem storage requires a plain directory path on a local disk, and "%s" is a stream URL; network filesystems break the lock and rename atomicity this adapter depends on',
                $directory,
            ));
        }
    }

    /**
     * Create or validate the store layout. The marker decides: a
     * marked directory must still carry its record tree, an unmarked
     * directory must be empty of records, and the adapter writes the
     * marker itself only in the second case. Construction finishes by
     * sweeping leftover temporary files, so a crashed writer leaves
     * no debris under any final name.
     */
    private function initializeLayout(): void
    {
        clearstatcache(true, $this->directory);
        if (is_file($this->directory)) {
            throw new FilesystemStorageException(sprintf(
                'the filesystem storage path "%s" exists as a regular file; pass a directory path',
                $this->directory,
            ));
        }
        if (!is_dir($this->directory)) {
            $this->ensureDirectory($this->directory, 'layout initialization');
        }
        if (!is_writable($this->directory)) {
            throw new FilesystemStorageException(sprintf(
                'the filesystem storage directory %s is not writable by this process',
                $this->directory,
            ));
        }
        $marker = $this->directory.'/format';
        clearstatcache(true, $marker);
        if (is_file($marker)) {
            $content = @file_get_contents($marker);
            if ($content !== self::FORMAT_MARKER) {
                throw new FilesystemStorageException(sprintf(
                    'the storage directory carries the layout marker "%s", which is newer or foreign; this adapter understands "%s"',
                    $content === false ? '(unreadable)' : trim($content),
                    self::FORMAT_MARKER,
                ));
            }
            clearstatcache(true, $this->recordsDir);
            if (!is_dir($this->recordsDir)) {
                throw new FilesystemStorageException(
                    'the storage directory is marked but its record directory is missing; the store is damaged'
                );
            }
        } else {
            clearstatcache(true, $this->recordsDir);
            if (is_dir($this->recordsDir) && $this->directoryHasEntries($this->recordsDir)) {
                throw new FilesystemStorageException(
                    'the storage directory holds record files without a layout marker; it belongs to a newer or foreign adapter and is refused'
                );
            }
            foreach ([$this->recordsDir, $this->locksDir, $this->claimsDir] as $dir) {
                $this->ensureDirectory($dir, 'layout initialization');
            }
            $this->writeAtomic($marker, self::FORMAT_MARKER, 'layout initialization');
        }
        $this->sweepTemporaryFiles();
    }

    /** Whether a directory holds at least one entry beyond its links. */
    private function directoryHasEntries(string $dir): bool
    {
        $entries = @scandir($dir);

        return $entries !== false && $entries !== ['.', '..'];
    }

    /**
     * Store a challenge record, replacing any existing record with the
     * same nonce. The envelope lands in its pending state with no
     * result, no identity and no claim lease, and expired records are
     * swept in the same locked transition.
     */
    public function store(ChallengeRecord $record): void
    {
        $retainedUntil = $record->expiresAt + $this->ttlMarginSecs;
        $paths = $this->pathsFor($record->nonce);

        $this->writeTransition('challenge issuance', $paths['lock'], function () use ($record, $retainedUntil, $paths): void {
            $this->sweepExpiredRecords();
            $prior = $this->liveDecoded($paths['record']);
            if ($prior !== null && ($prior['state'] ?? 'pending') !== 'pending') {
                throw new StorageWriteException('refusing to rewind a consumed or cancelled record to pending');
            }
            $this->writeAtomic(
                $paths['record'],
                $this->encodeEnvelope($record, 'pending', null, null, $retainedUntil),
                'challenge issuance',
            );
            // A fresh pending record carries no lease; a leftover claim
            // file would trip the pending-envelope guard.
            $this->removeClaim($paths['claim'], 'challenge issuance');
        });
    }

    public function find(string $nonce): ?ChallengeRecord
    {
        return $this->read('finding the record', function () use ($nonce): ?ChallengeRecord {
            $decoded = $this->liveDecoded($this->pathsFor($nonce)['record']);

            return $decoded === null ? null : $decoded['record'];
        });
    }

    /**
     * The atomic consume transition. The per-record lock is held
     * across the read and the flip, so a concurrent consumer of the
     * same nonce waits, then observes this caller's committed consumed
     * state: exactly one caller wins `consumedNow`. A cancelled,
     * corrupt or expired record reports missing, mirroring the Redis
     * script's nil semantics.
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
     * a claim file is a forged or damaged rewrite and reports missing,
     * never a fresh grant.
     */
    private function doConsume(string $nonce, ?string $identity): ?ConsumedRecord
    {
        $paths = $this->pathsFor($nonce);

        return $this->writeTransition('the pending-to-consumed transition', $paths['lock'], function () use ($identity, $paths): ?ConsumedRecord {
            $decoded = $this->liveDecoded($paths['record']);
            if ($decoded === null) {
                return null;
            }
            if ($decoded['state'] === 'consumed') {
                return new ConsumedRecord($decoded['record'], false, true, $decoded['result'], $decoded['identity']);
            }
            if ($decoded['state'] !== 'pending') {
                // A cancelled record is never consumable, and any
                // unknown state decoded to the empty string.
                return null;
            }
            if ($decoded['result'] !== null || $decoded['identity'] !== null || $this->claimFileHeld($paths['claim'])) {
                return null;
            }
            $this->writeAtomic(
                $paths['record'],
                $this->encodeEnvelope($decoded['record'], 'consumed', null, $identity, $decoded['retained_until']),
                'the pending-to-consumed transition',
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
            $decoded = $this->liveDecoded($this->pathsFor($nonce)['record']);
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
        $paths = $this->pathsFor($nonce);

        return $this->writeTransition('the result commit', $paths['lock'], function () use ($paths, $result): bool {
            $decoded = $this->liveDecoded($paths['record']);
            if ($decoded === null || $decoded['state'] !== 'consumed' || $decoded['result'] !== null) {
                return false;
            }
            $this->writeAtomic(
                $paths['record'],
                $this->encodeEnvelope($decoded['record'], 'consumed', $result, $decoded['identity'], $decoded['retained_until']),
                'the result commit',
            );

            return true;
        });
    }

    /**
     * Delete a record by nonce, inside one locked transition so a
     * concurrent transition on the same record is serialized against
     * it. The claim fence goes with the record.
     */
    public function delete(string $nonce): void
    {
        $paths = $this->pathsFor($nonce);

        $this->writeTransition('the record deletion', $paths['lock'], function () use ($paths): void {
            $this->removeRecord($paths['record'], 'the record deletion');
            $this->removeClaim($paths['claim'], 'the record deletion');
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
        $paths = $this->pathsFor($nonce);

        return $this->writeTransition('the delete-if-pending transition', $paths['lock'], function () use ($paths): DeleteIfPendingResult {
            $decoded = $this->liveDecoded($paths['record']);
            if ($decoded === null) {
                $raw = $this->rawIfPresent($paths['record']);
                if ($raw === null) {
                    return new DeleteIfPendingResult('missing');
                }
                if ($this->decodeEnvelope($raw) === null) {
                    return new DeleteIfPendingResult('corrupt');
                }

                // A decodable record past its retention reads missing,
                // the exact mirror of an expired row.
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
            $this->removeRecord($paths['record'], 'the delete-if-pending transition');
            $this->removeClaim($paths['claim'], 'the delete-if-pending transition');

            return new DeleteIfPendingResult('deleted-pending');
        });
    }

    /**
     * The single-snapshot runtime-state read: one file read classifies
     * missing, pending, consumed or cancelled from the same bytes,
     * never two separately timed reads. Rename atomicity makes the
     * single read a consistent snapshot.
     */
    public function runtimeState(string $nonce): ChallengeRuntimeState
    {
        return $this->read('reading the runtime state', function () use ($nonce): ChallengeRuntimeState {
            $decoded = $this->liveDecoded($this->pathsFor($nonce)['record']);
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
        $paths = $this->pathsFor($nonce);

        return $this->writeTransition('the pending-to-cancelled transition', $paths['lock'], function () use ($paths): ?CancellationResult {
            $decoded = $this->liveDecoded($paths['record']);
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
            $this->writeAtomic(
                $paths['record'],
                $this->encodeEnvelope($decoded['record'], 'cancelled', null, $decoded['identity'], $decoded['retained_until']),
                'the pending-to-cancelled transition',
            );

            return new CancellationResult('cancelled-now');
        });
    }

    /**
     * The replication-fence acceptance point as an explicit no-op:
     * this backend has exactly one node, a renamed file is already
     * durable on it, and there is no replica acknowledgement an
     * acceptance point could wait for.
     */
    public function establishReplicationFence(string $what): void
    {
        // Intentionally nothing: single-node durability is the rename.
    }

    /**
     * Claim the re-derivation ownership of a consumed, resultless
     * record under a bounded lease. The record lock fuses the
     * claimability check with the lease install, so exactly one
     * concurrent recovery wins the claim; the losers read null. The
     * lease itself is a fence file installed by `link()`, which
     * refuses an existing target, so ownership survives even a path
     * that bypasses the lock discipline. A lease that expired on the
     * storage clock is re-claimable, mirroring the Redis envelope
     * lease.
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
        $paths = $this->pathsFor($nonce);

        return $this->writeTransition('the resume-derivation claim', $paths['lock'], function () use ($paths, $ttlSecs): ?string {
            $decoded = $this->liveDecoded($paths['record']);
            if ($decoded === null || $decoded['state'] !== 'consumed' || $decoded['result'] !== null) {
                return null;
            }
            $lease = $this->readClaimLease($paths['claim'], 'the resume-derivation claim');
            if ($lease !== null && $lease['until'] > $this->nowInSeconds()) {
                return null;
            }
            // An expired or unreadable fence is cleared under the
            // record lock before the fresh claim installs.
            if ($this->claimFileHeld($paths['claim'])) {
                $this->removeClaim($paths['claim'], 'the resume-derivation claim');
            }
            // Secure RNG fail closed: a repeatable owner could let two
            // recoveries observe the same apparent ownership across a
            // lease expiry, so generation failure propagates.
            $owner = bin2hex(random_bytes(16));
            if (!$this->installClaim($paths['claim'], $owner, $this->nowInSeconds() + $ttlSecs, 'the resume-derivation claim')) {
                return null;
            }

            return $owner;
        });
    }

    /**
     * Compare-and-delete release of the resume claim: the fence file
     * is removed only when it still holds exactly this owner token,
     * so a stale owner can never clear a newer recovery's claim.
     *
     * @throws \InvalidArgumentException when the owner is not 32 lowercase hex chars
     */
    public function releaseResumeDerivation(string $nonce, string $owner): bool
    {
        $this->assertValidResumeOwner($owner);
        $paths = $this->pathsFor($nonce);

        return $this->writeTransition('the resume-claim release', $paths['lock'], function () use ($paths, $owner): bool {
            $lease = $this->readClaimLease($paths['claim'], 'the resume-claim release');
            if ($lease === null || $lease['owner'] !== $owner) {
                return false;
            }
            $this->removeClaim($paths['claim'], 'the resume-claim release');

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
        $paths = $this->pathsFor($nonce);

        return $this->writeTransition('the claim-bearing result commit', $paths['lock'], function () use ($paths, $result, $owner): bool {
            $decoded = $this->liveDecoded($paths['record']);
            if ($decoded === null || $decoded['state'] !== 'consumed' || $decoded['result'] !== null) {
                return false;
            }
            $lease = $this->readClaimLease($paths['claim'], 'the claim-bearing result commit');
            if ($lease === null || $lease['owner'] !== $owner || $lease['until'] <= $this->nowInSeconds()) {
                return false;
            }
            $this->writeAtomic(
                $paths['record'],
                $this->encodeEnvelope($decoded['record'], 'consumed', $result, $decoded['identity'], $decoded['retained_until']),
                'the claim-bearing result commit',
            );
            $this->removeClaim($paths['claim'], 'the claim-bearing result commit');

            return true;
        });
    }

    /**
     * The shared resume-claim owner contract, identical to the Redis,
     * SQLite and array backends: exactly 32 lowercase hex characters.
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
     * Run one durable transition under the per-record lock. The lock
     * is taken before the body reads, so the read-decide-write
     * sequence is serialized against every other process on the same
     * record, and the rename is the durability point. A storage-level
     * failure surfaces as the typed fail-closed exception with the
     * lock released.
     *
     * @template T
     *
     * @param callable():T $body the transition, reading and writing files
     *
     * @return T
     */
    private function writeTransition(string $what, string $lockPath, callable $body): mixed
    {
        $this->assertStorePresent($what);
        $handle = $this->openLockFile($lockPath, $what);
        try {
            $this->acquireLock($handle, $what);
            try {
                return $body();
            } catch (\JsonException $e) {
                throw self::storageFailure($what, $e->getMessage());
            }
        } finally {
            @flock($handle, LOCK_UN);
            \fclose($handle);
        }
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
        $this->assertStorePresent($what);
        try {
            return $body();
        } catch (FilesystemStorageException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw self::storageFailure($what, $e->getMessage());
        }
    }

    /**
     * Open the per-record lock file in create mode, never truncating:
     * an empty file whose existence carries the lock is all the
     * adapter needs from it.
     *
     * @return resource
     */
    private function openLockFile(string $lockPath, string $what)
    {
        $this->ensureDirectory(\dirname($lockPath), $what);
        $handle = @fopen($lockPath, 'c');
        if ($handle === false) {
            throw self::storageFailure($what, sprintf(
                'cannot open the record lock file %s; check the directory exists and is writable',
                $lockPath,
            ));
        }

        return $handle;
    }

    /**
     * Acquire the exclusive record lock, polling without blocking
     * until the configured deadline; a lock that stays held past the
     * deadline fails closed with the remedy in the message.
     *
     * @param resource $handle
     */
    private function acquireLock($handle, string $what): void
    {
        $deadline = microtime(true) + ($this->lockTimeoutMs / 1000.0);
        while (!@flock($handle, LOCK_EX | LOCK_NB)) {
            if (microtime(true) >= $deadline) {
                throw self::lockContention($what);
            }
            usleep(2000);
        }
    }

    /**
     * The typed contention failure, mirroring the SQLite busy-timeout
     * remedy: the failing operation, the held lock, and how to widen
     * the wait or serialize the writers.
     */
    private static function lockContention(string $what): FilesystemStorageException
    {
        return new FilesystemStorageException(sprintf(
            'filesystem storage failure during %s: the record lock stayed held past the lock timeout; raise lockTimeoutMs or serialize the writers on this directory',
            $what,
        ));
    }

    /**
     * Fail closed when the store directory vanished mid-flight: a
     * deleted store must surface as the typed unavailable failure,
     * never as a directory where every nonce reads missing.
     */
    private function assertStorePresent(string $what): void
    {
        clearstatcache(true, $this->recordsDir);
        if (!is_dir($this->recordsDir)) {
            throw new FilesystemStorageException(sprintf(
                'filesystem storage failure during %s: the record store directory %s is missing; restore it or point the adapter at a live directory',
                $what,
                $this->recordsDir,
            ));
        }
    }

    /**
     * The raw bytes of a record file, or null when absent. Stat
     * results are dropped for the path first, so a deletion by
     * another process is observed within this call.
     */
    private function rawIfPresent(string $recordPath): ?string
    {
        clearstatcache(true, $recordPath);
        if (!is_file($recordPath)) {
            return null;
        }
        $raw = @file_get_contents($recordPath);
        if ($raw === false) {
            throw self::storageFailure('reading the record file', sprintf('cannot read %s', $recordPath));
        }

        return $raw;
    }

    /**
     * The decoded envelope for a nonce, or null when the file is
     * absent, undecodable, or past its retention: the expiry boundary
     * is `now >= retained_until`, the exact mirror of a Redis key
     * whose TTL elapsed.
     *
     * @return array{record: ChallengeRecord, result: ConsumedResult|null, identity: string|null, state: string, retained_until: int}|null
     */
    private function liveDecoded(string $recordPath): ?array
    {
        $raw = $this->rawIfPresent($recordPath);
        if ($raw === null) {
            return null;
        }
        $decoded = $this->decodeEnvelope($raw);
        if ($decoded === null) {
            return null;
        }
        if ($this->nowInSeconds() >= $decoded['retained_until']) {
            return null;
        }

        return $decoded;
    }

    /**
     * Decode one envelope into the record, its committed result and
     * its recorded identity. The bytes pass the strict authority
     * {@see StrictJson::decodeObject()} first, so a corrupt file
     * fails closed exactly like a corrupt value on any other backend.
     * A malformed committed result degrades to absent. Any structural
     * failure answers null: an unusable record, never a partially
     * trusted one.
     *
     * @return array{record: ChallengeRecord, result: ConsumedResult|null, identity: string|null, state: string, retained_until: int}|null
     */
    private function decodeEnvelope(string $raw): ?array
    {
        $envelope = StrictJson::decodeObject($raw);
        if ($envelope === null) {
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
        $retainedUntil = $envelope['retained_until'] ?? 0;

        return [
            'record' => $record,
            'result' => $result,
            'identity' => \is_string($identity) ? $identity : null,
            'state' => $state,
            'retained_until' => \is_int($retainedUntil) ? $retainedUntil : 0,
        ];
    }

    /**
     * Encode one envelope write. The shape is the exact runtime
     * column set of the SQLite row: the canonical record, the state,
     * the committed result, the recorded identity and the retention
     * deadline the sweep and every read share.
     */
    private function encodeEnvelope(
        ChallengeRecord $record,
        string $state,
        ?ConsumedResult $result,
        ?string $identity,
        int $retainedUntil,
    ): string {
        $envelope = [
            'record' => $record->toArray(),
            'state' => $state,
            'consumed_result' => $result?->toArray(),
            'operation_identity' => $identity,
            'retained_until' => $retainedUntil,
        ];
        try {
            return json_encode($envelope, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw self::storageFailure('serializing the record envelope', $e->getMessage());
        }
    }

    /**
     * Write bytes to their final path atomically: a unique temporary
     * file in the target directory, flushed and synchronized, then
     * renamed over the target. PHP 8.1 has no `fsync()`, so its
     * barrier stops at the flush; process crashes are covered either
     * way, and the rename itself never exposes a partial file.
     */
    private function writeAtomic(string $path, string $bytes, string $what): void
    {
        $tmp = $this->writeTemporaryFile(\dirname($path), $bytes, $what);
        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            throw self::storageFailure($what, sprintf('cannot move %s onto %s', $tmp, $path));
        }
    }

    /**
     * Create the unique temporary file every durable write and every
     * claim install begins with. The name carries the `.tmp` suffix
     * the construction boot sweep matches, so a crashed writer leaves
     * no debris any later construction keeps.
     */
    private function writeTemporaryFile(string $dir, string $bytes, string $what): string
    {
        $this->ensureDirectory($dir, $what);
        $tmp = $dir.'/'.bin2hex(random_bytes(10)).'.tmp';
        $handle = @fopen($tmp, 'xb');
        if ($handle === false) {
            throw self::storageFailure($what, sprintf(
                'cannot create the temporary file %s; check the directory exists and is writable',
                $tmp,
            ));
        }
        try {
            $length = \strlen($bytes);
            $written = 0;
            while ($written < $length) {
                $chunk = @fwrite($handle, substr($bytes, $written));
                if ($chunk === false) {
                    throw self::storageFailure($what, sprintf('cannot write the temporary file %s', $tmp));
                }
                $written += $chunk;
            }
            fflush($handle);
            if (\function_exists('fsync')) {
                fsync($handle);
            }
        } finally {
            \fclose($handle);
        }
        @chmod($tmp, 0600);

        return $tmp;
    }

    /**
     * Install the resume-claim fence: the lease payload lands in a
     * temporary file, then a hard link places it under the claim
     * name. `link()` refuses an existing target, which is the
     * create-if-absent decision a rename cannot express, so a
     * concurrent install loses exactly here and answers false.
     */
    private function installClaim(string $claimPath, string $owner, int $until, string $what): bool
    {
        try {
            $payload = json_encode(['owner' => $owner, 'until' => $until], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw self::storageFailure($what, $e->getMessage());
        }
        $tmp = $this->writeTemporaryFile(\dirname($claimPath), $payload, $what);
        if (!@link($tmp, $claimPath)) {
            @unlink($tmp);
            clearstatcache(true, $claimPath);
            if (is_file($claimPath)) {
                return false;
            }
            throw self::storageFailure($what, sprintf(
                'cannot install the claim fence %s; the filesystem may not support hard links',
                $claimPath,
            ));
        }
        @unlink($tmp);

        return true;
    }

    /**
     * The claim lease of a nonce, or null when the fence file is
     * absent or unreadable. An unreadable lease reads as absent, and
     * the fence file itself still blocks a fresh install through the
     * link refusal, so corruption can fail closed without crashing
     * the recovery path.
     *
     * @return array{owner: string, until: int}|null
     */
    private function readClaimLease(string $claimPath, string $what): ?array
    {
        clearstatcache(true, $claimPath);
        if (!is_file($claimPath)) {
            return null;
        }
        $raw = @file_get_contents($claimPath);
        if ($raw === false) {
            throw self::storageFailure($what, sprintf('cannot read the claim file %s', $claimPath));
        }
        $lease = StrictJson::decodeObject($raw);
        if ($lease === null) {
            return null;
        }
        $owner = $lease['owner'] ?? null;
        $until = $lease['until'] ?? null;
        if (!\is_string($owner) || !\is_int($until)) {
            return null;
        }

        return ['owner' => $owner, 'until' => $until];
    }

    /** Whether the claim fence file exists, whatever its content. */
    private function claimFileHeld(string $claimPath): bool
    {
        clearstatcache(true, $claimPath);

        return is_file($claimPath);
    }

    /**
     * Remove the claim fence file; a fence that refuses deletion
     * while still present fails closed, because a stale fence would
     * block every later claim on the record.
     */
    private function removeClaim(string $claimPath, string $what): void
    {
        if (@unlink($claimPath)) {
            clearstatcache(true, $claimPath);

            return;
        }
        clearstatcache(true, $claimPath);
        if (is_file($claimPath)) {
            throw self::storageFailure($what, sprintf('cannot delete the claim file %s', $claimPath));
        }
    }

    /**
     * Remove a record file; an absent file is a quiet success, the
     * exact mirror of deleting a missing row.
     */
    private function removeRecord(string $recordPath, string $what): void
    {
        if (@unlink($recordPath)) {
            clearstatcache(true, $recordPath);

            return;
        }
        clearstatcache(true, $recordPath);
        if (is_file($recordPath)) {
            throw self::storageFailure($what, sprintf('cannot delete the record file %s', $recordPath));
        }
    }

    /**
     * Sweep retention on every issuance, mirroring the SQLite expiry
     * index: records whose retention passed are removed together with
     * their claim fences, their lock files and their orphaned claims.
     * The scan is linear in the live record count, the documented
     * cost ceiling of this adapter. A record whose envelope cannot be
     * decoded is never mutated by the sweep; it stays for the
     * operator.
     */
    private function sweepExpiredRecords(): void
    {
        $now = $this->nowInSeconds();
        foreach ($this->shardDirectories($this->recordsDir) as $shardDir) {
            $entries = @scandir($shardDir);
            if ($entries === false) {
                continue;
            }
            $shard = basename($shardDir);
            foreach ($entries as $entry) {
                if (!str_ends_with($entry, '.json')) {
                    continue;
                }
                $recordPath = $shardDir.'/'.$entry;
                $raw = @file_get_contents($recordPath);
                if ($raw === false) {
                    continue;
                }
                $envelope = StrictJson::decodeObject($raw);
                if ($envelope === null) {
                    continue;
                }
                $retainedUntil = $envelope['retained_until'] ?? null;
                if (!\is_int($retainedUntil) || $now < $retainedUntil) {
                    continue;
                }
                $stem = substr($entry, 0, -5);
                $this->sweepRecord(
                    $recordPath,
                    $this->claimsDir.'/'.$shard.'/'.$stem.'.claim',
                    $this->locksDir.'/'.$shard.'/'.$stem.'.lock',
                );
            }
        }
        $this->sweepOrphanedClaims();
    }

    /**
     * Remove claim fences whose record file is gone: a lease without
     * its record is dead weight the next issuance clears.
     */
    private function sweepOrphanedClaims(): void
    {
        foreach ($this->shardDirectories($this->claimsDir) as $shardDir) {
            $entries = @scandir($shardDir);
            if ($entries === false) {
                continue;
            }
            $shard = basename($shardDir);
            foreach ($entries as $entry) {
                if (!str_ends_with($entry, '.claim')) {
                    continue;
                }
                $stem = substr($entry, 0, -6);
                $recordPath = $this->recordsDir.'/'.$shard.'/'.$stem.'.json';
                clearstatcache(true, $recordPath);
                if (is_file($recordPath)) {
                    continue;
                }
                $this->sweepRecord(
                    $recordPath,
                    $shardDir.'/'.$entry,
                    $this->locksDir.'/'.$shard.'/'.$stem.'.lock',
                );
            }
        }
    }

    /**
     * Remove one expired record's three files under its own lock,
     * taken without waiting: a record whose lock is busy belongs to a
     * live transition and is left for the next sweep. The lock file
     * goes last, while its lock is held; a racer that opened the
     * removed inode then observes a missing record, and its
     * transitions stay no-ops. A full store still lands as one
     * complete renamed file.
     */
    private function sweepRecord(string $recordPath, string $claimPath, string $lockPath): void
    {
        $handle = @fopen($lockPath, 'c');
        if ($handle === false) {
            return;
        }
        try {
            if (!@flock($handle, LOCK_EX | LOCK_NB)) {
                return;
            }
            @unlink($recordPath);
            @unlink($claimPath);
            @unlink($lockPath);
            clearstatcache(true, $recordPath);
            clearstatcache(true, $claimPath);
            clearstatcache(true, $lockPath);
        } finally {
            \fclose($handle);
        }
    }

    /**
     * The construction boot sweep removes temporary debris under the
     * record and claim trees and the store root once it passes the
     * age bound. Debris from a crashed writer never outlives the next
     * construction. A concurrent writer's in-flight temporary file
     * stays untouched.
     */
    private function sweepTemporaryFiles(): void
    {
        foreach ([$this->recordsDir, $this->claimsDir] as $root) {
            foreach ($this->shardDirectories($root) as $shardDir) {
                $this->unlinkTemporaryFiles($shardDir);
            }
        }
        $this->unlinkTemporaryFiles($this->directory);
    }

    /**
     * Remove the `.tmp` debris of one directory past the age bound,
     * quietly: a fresh temporary file may belong to a writer in
     * flight right now and is never touched.
     */
    private function unlinkTemporaryFiles(string $dir): void
    {
        $entries = @scandir($dir);
        if ($entries === false) {
            return;
        }
        $cutoff = time() - self::TEMP_DEBRIS_SECONDS;
        foreach ($entries as $entry) {
            if (!str_ends_with($entry, '.tmp')) {
                continue;
            }
            $path = $dir.'/'.$entry;
            clearstatcache(true, $path);
            $mtime = @filemtime($path);
            if ($mtime !== false && $mtime < $cutoff) {
                @unlink($path);
            }
        }
    }

    /**
     * The shard directories of one store tree, absent trees included
     * as an empty list.
     *
     * @return list<string>
     */
    private function shardDirectories(string $root): array
    {
        clearstatcache(true, $root);
        if (!is_dir($root)) {
            return [];
        }
        $entries = @scandir($root);
        if ($entries === false) {
            return [];
        }
        $dirs = [];
        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $candidate = $root.'/'.$entry;
            if (is_dir($candidate)) {
                $dirs[] = $candidate;
            }
        }

        return $dirs;
    }

    /**
     * Ensure a directory exists, creating it and its parents with
     * mode 0700; creation failures surface as the typed storage
     * failure with an actionable message.
     */
    private function ensureDirectory(string $dir, string $what): void
    {
        clearstatcache(true, $dir);
        if (is_dir($dir)) {
            return;
        }
        if (!@mkdir($dir, 0700, true)) {
            clearstatcache(true, $dir);
            if (!is_dir($dir)) {
                throw self::storageFailure($what, sprintf(
                    'cannot create the directory %s; check the parent directory exists and is writable',
                    $dir,
                ));
            }
        }
    }

    /** The storage clock: the constructor seam or the wall clock. */
    private function nowInSeconds(): int
    {
        return $this->now !== null ? (int) ($this->now)() : time();
    }

    /**
     * Wrap a filesystem failure in the typed fail-closed exception
     * with an actionable message naming the failing operation and the
     * underlying error.
     */
    private static function storageFailure(string $what, string $error): FilesystemStorageException
    {
        return new FilesystemStorageException(sprintf('filesystem storage failure during %s: %s', $what, $error));
    }
}
