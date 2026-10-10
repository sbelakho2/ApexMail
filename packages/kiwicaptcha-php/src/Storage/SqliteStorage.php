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
use KiwiCaptcha\DeleteIfPendingResult;
use KiwiCaptcha\OperationIdentity;
use KiwiCaptcha\OperationIdentityAwareStorageInterface;
use KiwiCaptcha\ReplicationBarrierInterface;
use KiwiCaptcha\ResumeDerivationClaimInterface;

/**
 * SQLite-backed storage: the zero-infrastructure single-node adapter.
 *
 * The whole store is one SQLite database file created on first use,
 * with write-ahead logging enabled, so a small site runs the verifier
 * with no server beyond PHP itself and still gets single-use,
 * replay-safe verification. Every durable state transition runs inside
 * one begin-immediate transaction (`BEGIN` `IMMEDIATE` before the row
 * is read, the decision and the write follow, the commit is the
 * durability point). SQLite serializes writers, so two racing
 * consumers of one nonce cannot both observe the pending row: exactly
 * one caller wins `consumedNow` and the loser reads the winner's
 * retained state. The atomicity contract of
 * {@see AtomicStorageInterface} therefore holds on this backend
 * without any script engine.
 *
 * Records live in one table keyed by nonce. The canonical record JSON
 * is stored beside the runtime columns the capability interfaces read
 * and write: the state, the committed result, the recorded operation
 * identity, and the resume-claim lease. Reads decode the record JSON
 * through the strict authority {@see StrictJson::decodeObject()}, so a
 * corrupt row fails closed exactly like a corrupt value on any other
 * backend. Expiry mirrors the Redis key TTLs: a row whose signed
 * expiry plus the retention margin has passed on the storage clock is
 * absent to every read and transition, and `store()` sweeps expired
 * rows through the expiry index.
 *
 * Documented limits, exactly as the storage-plane design frames them:
 * this is the single-node adapter. One database file serves one
 * deployment; there is no replication, no failover and no shared
 * multi-node topology. WAL mode lets readers proceed beside the one
 * writer, and the busy timeout makes concurrent writers wait their
 * turn. A write lock held past the timeout surfaces as the same
 * fail-closed storage failure an unavailable Redis produces, so
 * verification never silently passes. Deployments that need shared or
 * replicated stores use the Redis backend.
 *
 * Implements the same capability set as {@see RedisStorage}: the
 * retained consumed-state read, the identity-bearing consume, the
 * fused delete-if-pending cleanup, the cancellation transition, the
 * single-snapshot runtime-state read, the resume-derivation claim and
 * the authenticated result commit, each fused into one immediate
 * transaction. The replication fence of
 * {@see ReplicationBarrierInterface} is an explicit no-op: a committed
 * SQLite transaction is already durable on the one node, and there is
 * no replica acknowledgement to wait for.
 */
final class SqliteStorage implements AtomicStorageInterface, ConsumedStateReadableInterface, OperationIdentityAwareStorageInterface, AtomicDeleteIfPendingInterface, CancellableStorageInterface, ChallengeRuntimeStateReadableInterface, ReplicationBarrierInterface, ResumeDerivationClaimInterface, AuthenticatedResultCommitInterface
{
    /**
     * The schema version this adapter writes and understands, tracked
     * in the database header through the `user_version` pragma. A file
     * carrying a newer version is refused: a downgrade must never
     * mutate a schema a future release owns.
     */
    private const SCHEMA_VERSION = 1;

    private const TABLE = 'kiwicaptcha_challenge_records';

    /** The one row shape every transition reads, column-named. */
    private const SELECT_ROW = 'SELECT record_json, state, consumed_result_json, operation_identity, resume_owner, resume_until, retained_until FROM kiwicaptcha_challenge_records WHERE nonce = :nonce';

    private \PDO $pdo;

    /**
     * @param \PDO|string   $pdoOrPath     an open sqlite PDO connection, or a
     *                                     database file path the adapter
     *                                     opens itself; an absent file is
     *                                     created, so the default path
     *                                     just works.
     * @param int           $busyTimeoutMs how long a writer waits for the
     *                                     single write lock before failing
     *                                     closed, applied as the
     *                                     connection busy timeout.
     * @param int           $ttlMarginSecs extra retention beyond the signed
     *                                     expiry, mirroring the Redis
     *                                     backend's margin: the row stays
     *                                     readable as recovery evidence
     *                                     for this many seconds past
     *                                     expires_at.
     * @param \Closure|null $now           the storage clock in epoch
     *                                     seconds, defaulting to time();
     *                                     a test seam for deterministic
     *                                     expiry and lease checks.
     *
     * @throws SqliteStorageException   when the sqlite driver or the
     *                                  database file is unavailable, or
     *                                  the schema guard refuses the file.
     * @throws \InvalidArgumentException when a given PDO connection is
     *                                  bound to a driver other than
     *                                  sqlite, or an argument is out of
     *                                  range.
     */
    public function __construct(
        \PDO|string $pdoOrPath,
        private readonly int $busyTimeoutMs = 5000,
        private readonly int $ttlMarginSecs = 60,
        private readonly ?\Closure $now = null,
    ) {
        if ($this->busyTimeoutMs < 0) {
            throw new \InvalidArgumentException('busyTimeoutMs must be >= 0');
        }
        if ($this->ttlMarginSecs < 0) {
            throw new \InvalidArgumentException('ttlMarginSecs must be >= 0');
        }
        if ($pdoOrPath instanceof \PDO) {
            $driver = (string) $pdoOrPath->getAttribute(\PDO::ATTR_DRIVER_NAME);
            if ($driver !== 'sqlite') {
                throw new \InvalidArgumentException(sprintf(
                    'SqliteStorage requires an sqlite PDO connection, got driver "%s"',
                    $driver,
                ));
            }
            $pdo = $pdoOrPath;
            $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        } else {
            $pdo = self::openSqlitePdo($pdoOrPath);
        }
        $this->pdo = $pdo;
        try {
            $this->applyPragmas();
            $this->initializeSchema();
        } catch (\PDOException $e) {
            throw self::storageFailure('schema initialization', $e);
        }
    }

    /**
     * Diagnostic seam: the live connection, so operators and tests can
     * inspect the applied pragmas and the schema stamp. The storage
     * itself never touches it after construction.
     */
    public function pdo(): \PDO
    {
        return $this->pdo;
    }

    /**
     * Open the database file. The pdo_sqlite extension is a suggestion,
     * never a requirement of the package, so its absence surfaces here
     * as one clean, actionable error naming the extension and the
     * remedy instead of a fatal error on an undefined class.
     *
     * @throws SqliteStorageException when the PDO core or the sqlite
     *                                driver is missing, or the file
     *                                cannot be opened
     */
    private static function openSqlitePdo(string $path): \PDO
    {
        if (!\class_exists(\PDO::class)) {
            throw new SqliteStorageException(
                'the PDO core is not installed; install or enable ext-pdo to use SqliteStorage'
            );
        }
        if (!\in_array('sqlite', \PDO::getAvailableDrivers(), true)) {
            throw new SqliteStorageException(
                'the pdo_sqlite extension is not installed; install or enable ext-pdo_sqlite (for example the php-sqlite3 package) to use SqliteStorage'
            );
        }
        try {
            return new \PDO(
                'sqlite:'.$path,
                null,
                null,
                [
                    \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
                    \PDO::ATTR_EMULATE_PREPARES => false,
                ],
            );
        } catch (\PDOException $e) {
            throw self::storageFailure('opening the database file', $e);
        }
    }

    /**
     * Apply the connection pragmas: the busy timeout first, so every
     * later statement queues behind a held write lock instead of
     * failing at once, then the WAL journal mode, which lets readers
     * proceed beside the writer. An in-memory database keeps its
     * memory journal mode; the switch is simply a no-op there.
     */
    private function applyPragmas(): void
    {
        $this->pdo->exec(sprintf('PRAGMA busy_timeout = %d', $this->busyTimeoutMs));
        $this->pdo->query('PRAGMA journal_mode = WAL')->fetchColumn();
    }

    /**
     * Create the schema idempotently under the version guard: one
     * immediate transaction reads `user_version`, creates the table
     * and its expiry index when the file is uninitialized, and stamps
     * the version it wrote. A file stamped with a newer version is
     * refused, and a stamped file whose table vanished is refused too,
     * so a damaged or foreign database never silently reinitializes.
     */
    private function initializeSchema(): void
    {
        $this->pdo->exec('BEGIN IMMEDIATE');
        try {
            $version = (int) $this->pdo->query('PRAGMA user_version')->fetchColumn();
            if ($version > self::SCHEMA_VERSION) {
                throw new SqliteStorageException(sprintf(
                    'the database carries schema version %d, newer than the %d this adapter supports; upgrade the kiwicaptcha-php package',
                    $version,
                    self::SCHEMA_VERSION,
                ));
            }
            if ($version === self::SCHEMA_VERSION) {
                $this->assertTablePresent();
            } else {
                $this->pdo->exec(
                    'CREATE TABLE IF NOT EXISTS kiwicaptcha_challenge_records ('
                    .'nonce TEXT PRIMARY KEY, '
                    .'record_json TEXT NOT NULL, '
                    ."state TEXT NOT NULL CHECK (state IN ('pending', 'consumed', 'cancelled')), "
                    .'consumed_result_json TEXT, '
                    .'operation_identity TEXT, '
                    .'resume_owner TEXT, '
                    .'resume_until INTEGER, '
                    .'retained_until INTEGER NOT NULL)'
                );
                $this->pdo->exec(
                    'CREATE INDEX IF NOT EXISTS kiwicaptcha_challenge_records_retained_until_idx '
                    .'ON kiwicaptcha_challenge_records (retained_until)'
                );
                $this->pdo->exec(sprintf('PRAGMA user_version = %d', self::SCHEMA_VERSION));
            }
            $this->pdo->exec('COMMIT');
        } catch (\Throwable $e) {
            $this->safeRollback();
            throw $e;
        }
    }

    /** Refuse a stamped database whose record table is gone. */
    private function assertTablePresent(): void
    {
        $present = $this->pdo->query(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'kiwicaptcha_challenge_records'"
        )->fetchColumn();
        if ((int) $present !== 1) {
            throw new SqliteStorageException(
                'the database is stamped with the kiwicaptcha schema version but the challenge table is missing; the file is damaged'
            );
        }
    }

    /**
     * Store a challenge record, replacing any existing record with the
     * same nonce. The row lands in its pending state with no result,
     * no identity and no claim lease, and expired rows are swept
     * through the expiry index in the same transaction.
     */
    public function store(ChallengeRecord $record): void
    {
        try {
            $json = json_encode($record->toArray(), JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw self::storageFailure('serializing the challenge record', $e);
        }
        $retainedUntil = $record->expiresAt + $this->ttlMarginSecs;

        $this->writeTransition('challenge issuance', function () use ($record, $json, $retainedUntil): void {
            $sweep = $this->pdo->prepare(
                'DELETE FROM kiwicaptcha_challenge_records WHERE retained_until <= :now'
            );
            $sweep->execute([':now' => $this->nowInSeconds()]);
            $prior = $this->pdo->prepare('SELECT state FROM kiwicaptcha_challenge_records WHERE nonce = :nonce');
            $prior->execute([':nonce' => $record->nonce]);
            $priorState = $prior->fetchColumn();
            if ($priorState !== false && $priorState !== null && $priorState !== 'pending') {
                throw new StorageWriteException('refusing to rewind a consumed or cancelled record to pending');
            }
            $insert = $this->pdo->prepare(
                'INSERT INTO kiwicaptcha_challenge_records '
                .'(nonce, record_json, state, consumed_result_json, operation_identity, resume_owner, resume_until, retained_until) '
                .'VALUES (:nonce, :record_json, :state, :consumed_result_json, :operation_identity, :resume_owner, :resume_until, :retained_until) '
                .'ON CONFLICT(nonce) DO UPDATE SET '
                .'record_json = excluded.record_json, state = excluded.state, '
                .'consumed_result_json = excluded.consumed_result_json, '
                .'operation_identity = excluded.operation_identity, '
                .'resume_owner = excluded.resume_owner, resume_until = excluded.resume_until, '
                .'retained_until = excluded.retained_until'
            );
            $insert->execute([
                ':nonce' => $record->nonce,
                ':record_json' => $json,
                ':state' => 'pending',
                ':consumed_result_json' => null,
                ':operation_identity' => null,
                ':resume_owner' => null,
                ':resume_until' => null,
                ':retained_until' => $retainedUntil,
            ]);
        });
    }

    public function find(string $nonce): ?ChallengeRecord
    {
        return $this->read('finding the record', function () use ($nonce): ?ChallengeRecord {
            $row = $this->liveRow($nonce);
            if ($row === null) {
                return null;
            }

            return $this->decodeRow($row)['record'] ?? null;
        });
    }

    /**
     * The atomic consume transition. The immediate transaction holds
     * the write lock across the read and the flip, so a concurrent
     * consumer of the same nonce waits, then observes this caller's
     * committed consumed state: exactly one caller wins `consumedNow`.
     * A cancelled, corrupt or expired row reports missing, mirroring
     * the Redis script's nil semantics.
     */
    public function consume(string $nonce): ?ConsumedRecord
    {
        return $this->doConsume($nonce, null);
    }

    /**
     * The identity-bearing consume transition: the validated identity
     * is written in the same transaction as the state flip, so the
     * stored identity is provably the actual transition winner's.
     */
    public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?ConsumedRecord
    {
        return $this->doConsume($nonce, OperationIdentity::validate($operationIdentity));
    }

    /**
     * The shared implementation of both consume entry points. The
     * pending-envelope guard mirrors the Redis script's marker check:
     * a pending row that already carries a result, an identity or a
     * claim lease is a forged or damaged rewrite and reports missing,
     * never a fresh grant.
     *
     * @throws StorageWriteException when a non-null identity wins the
     *                               flip but the row refused it
     */
    private function doConsume(string $nonce, ?string $identity): ?ConsumedRecord
    {
        return $this->writeTransition('the pending-to-consumed transition', function () use ($nonce, $identity): ?ConsumedRecord {
            $row = $this->liveRow($nonce);
            if ($row === null) {
                return null;
            }
            $decoded = $this->decodeRow($row);
            if ($decoded === null) {
                return null;
            }
            $state = $this->stateOf($row);
            if ($state === 'consumed') {
                return new ConsumedRecord($decoded['record'], false, true, $decoded['result'], $decoded['identity']);
            }
            if ($state !== 'pending') {
                // A cancelled row is never consumable, and any other
                // value is corruption the constraint already excludes.
                return null;
            }
            if ($row['consumed_result_json'] !== null || $row['operation_identity'] !== null || $row['resume_owner'] !== null) {
                return null;
            }
            $update = $this->pdo->prepare(
                'UPDATE kiwicaptcha_challenge_records SET state = :state, operation_identity = :identity WHERE nonce = :nonce'
            );
            $update->execute([':state' => 'consumed', ':identity' => $identity, ':nonce' => $nonce]);
            if ($identity !== null && (int) $update->rowCount() !== 1) {
                throw new StorageWriteException(
                    'the consume transition could not record the operation identity on the flipped row'
                );
            }

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
            $row = $this->liveRow($nonce);
            if ($row === null || $this->stateOf($row) !== 'consumed') {
                return null;
            }

            return $this->consumedFromRow($row);
        });
    }

    /**
     * Commit the deterministic result of a consumed record. The
     * immediate transaction fuses the check and the write, so the
     * commit is one-shot: only a retained, consumed, resultless row is
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
        try {
            $json = json_encode($result->toArray(), JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw self::storageFailure('serializing the consumed result', $e);
        }

        return $this->writeTransition('the result commit', function () use ($nonce, $json): bool {
            $row = $this->liveRow($nonce);
            if ($row === null || $this->decodeRow($row) === null || $this->stateOf($row) !== 'consumed' || $row['consumed_result_json'] !== null) {
                return false;
            }
            $update = $this->pdo->prepare(
                'UPDATE kiwicaptcha_challenge_records SET consumed_result_json = :result WHERE nonce = :nonce'
            );
            $update->execute([':result' => $json, ':nonce' => $nonce]);

            return true;
        });
    }

    /**
     * Delete a record by nonce, inside one immediate transaction so a
     * concurrent transition on the same row is serialized against it.
     */
    public function delete(string $nonce): void
    {
        $this->writeTransition('the record deletion', function () use ($nonce): void {
            $delete = $this->pdo->prepare('DELETE FROM kiwicaptcha_challenge_records WHERE nonce = :nonce');
            $delete->execute([':nonce' => $nonce]);
        });
    }

    /**
     * The fused cleanup transition: one immediate transaction decides
     * missing, deleted-pending, consumed, cancelled or corrupt, and
     * only the exact pending row is deleted. A consumed row keeps its
     * retained evidence and answers with it, a cancelled row is kept
     * as dead until its retention ends, and a corrupt row is reported
     * without being mutated.
     */
    public function deleteIfPending(string $nonce): DeleteIfPendingResult
    {
        return $this->writeTransition('the delete-if-pending transition', function () use ($nonce): DeleteIfPendingResult {
            $row = $this->liveRow($nonce);
            if ($row === null) {
                return new DeleteIfPendingResult('missing');
            }
            $decoded = $this->decodeRow($row);
            if ($decoded === null) {
                return new DeleteIfPendingResult('corrupt');
            }
            $state = $this->stateOf($row);
            if ($state === 'consumed') {
                return new DeleteIfPendingResult('consumed', $this->consumedFromRow($row));
            }
            if ($state === 'cancelled') {
                return new DeleteIfPendingResult('cancelled');
            }
            if ($state !== 'pending') {
                return new DeleteIfPendingResult('corrupt');
            }
            $delete = $this->pdo->prepare('DELETE FROM kiwicaptcha_challenge_records WHERE nonce = :nonce');
            $delete->execute([':nonce' => $nonce]);

            return new DeleteIfPendingResult('deleted-pending');
        });
    }

    /**
     * The single-snapshot runtime-state read: one select classifies
     * missing, pending, consumed or cancelled from the same row bytes,
     * never two separately timed reads.
     */
    public function runtimeState(string $nonce): ChallengeRuntimeState
    {
        return $this->read('reading the runtime state', function () use ($nonce): ChallengeRuntimeState {
            $row = $this->liveRow($nonce);
            if ($row === null) {
                return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Missing);
            }
            $decoded = $this->decodeRow($row);
            if ($decoded === null) {
                // A corrupt row fails closed as missing, never pending.
                return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Missing);
            }
            $state = $this->stateOf($row);
            if ($state === 'cancelled') {
                return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Cancelled, $decoded['record']);
            }
            if ($state === 'consumed') {
                $consumed = $this->consumedFromRow($row);

                return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Consumed, $consumed->record, $consumed);
            }
            if ($state === 'pending') {
                return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Pending, $decoded['record']);
            }

            return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Missing);
        });
    }

    /**
     * The atomic cancellation transition: pending flips to the
     * terminal cancelled state inside one immediate transaction, so a
     * concurrent consumer that flipped first is observed consumed and
     * never cancelled. A consumed record is finalized and refused, an
     * already-cancelled record is idempotent, and a missing or corrupt
     * record answers null.
     */
    public function cancel(string $nonce): ?\KiwiCaptcha\CancellationResult
    {
        return $this->writeTransition('the pending-to-cancelled transition', function () use ($nonce): ?\KiwiCaptcha\CancellationResult {
            $row = $this->liveRow($nonce);
            if ($row === null || $this->decodeRow($row) === null) {
                return null;
            }
            $state = $this->stateOf($row);
            if ($state === 'consumed') {
                return new \KiwiCaptcha\CancellationResult('consumed');
            }
            if ($state === 'cancelled') {
                return new \KiwiCaptcha\CancellationResult('cancelled');
            }
            if ($state !== 'pending') {
                return null;
            }
            $update = $this->pdo->prepare(
                'UPDATE kiwicaptcha_challenge_records SET state = :state WHERE nonce = :nonce'
            );
            $update->execute([':state' => 'cancelled', ':nonce' => $nonce]);

            return new \KiwiCaptcha\CancellationResult('cancelled-now');
        });
    }

    /**
     * The replication-fence acceptance point as an explicit no-op:
     * this backend has exactly one node, a committed transaction is
     * already durable on it, and there is no replica acknowledgement
     * an acceptance point could wait for.
     */
    public function establishReplicationFence(string $what): void
    {
        // Intentionally nothing: single-node durability is the commit.
    }

    /**
     * Claim the re-derivation ownership of a consumed, resultless
     * record under a bounded lease. One immediate transaction fuses
     * the claimability check with the lease write, so exactly one
     * concurrent recovery wins the claim; the losers read null. A
     * claim whose lease expired on the storage clock is re-claimable,
     * mirroring the Redis envelope lease.
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

        return $this->writeTransition('the resume-derivation claim', function () use ($nonce, $ttlSecs): ?string {
            $row = $this->liveRow($nonce);
            if ($row === null || $this->decodeRow($row) === null || $this->stateOf($row) !== 'consumed' || $row['consumed_result_json'] !== null) {
                return null;
            }
            $now = $this->nowInSeconds();
            if ($row['resume_owner'] !== null && (int) $row['resume_until'] > $now) {
                return null;
            }
            // Secure RNG fail closed: a repeatable owner could let two
            // recoveries observe the same apparent ownership across a
            // lease expiry, so generation failure propagates.
            $owner = bin2hex(random_bytes(16));
            $update = $this->pdo->prepare(
                'UPDATE kiwicaptcha_challenge_records SET resume_owner = :owner, resume_until = :until WHERE nonce = :nonce'
            );
            $update->execute([':owner' => $owner, ':until' => $now + $ttlSecs, ':nonce' => $nonce]);

            return $owner;
        });
    }

    /**
     * Compare-and-delete release of the resume claim: the lease is
     * cleared only when the row still holds exactly this owner token,
     * so a stale owner can never clear a newer recovery's claim.
     *
     * @throws \InvalidArgumentException when the owner is not 32 lowercase hex chars
     */
    public function releaseResumeDerivation(string $nonce, string $owner): bool
    {
        $this->assertValidResumeOwner($owner);

        return $this->writeTransition('the resume-claim release', function () use ($nonce, $owner): bool {
            $row = $this->liveRow($nonce);
            if ($row === null || $row['resume_owner'] !== $owner) {
                return false;
            }
            $update = $this->pdo->prepare(
                'UPDATE kiwicaptcha_challenge_records SET resume_owner = NULL, resume_until = NULL WHERE nonce = :nonce'
            );
            $update->execute([':nonce' => $nonce]);

            return true;
        });
    }

    /**
     * The resume-path commit: the claim is a fencing precondition and
     * is cleared in the same transaction as the result write. A stale
     * owner, an expired lease or a row that gained a result is refused
     * without any write.
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
        try {
            $json = json_encode($result->toArray(), JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw self::storageFailure('serializing the consumed result', $e);
        }

        return $this->writeTransition('the claim-bearing result commit', function () use ($nonce, $json, $owner): bool {
            $row = $this->liveRow($nonce);
            if ($row === null || $this->decodeRow($row) === null || $this->stateOf($row) !== 'consumed' || $row['consumed_result_json'] !== null) {
                return false;
            }
            if ($row['resume_owner'] !== $owner || $row['resume_until'] === null || (int) $row['resume_until'] <= $this->nowInSeconds()) {
                return false;
            }
            $update = $this->pdo->prepare(
                'UPDATE kiwicaptcha_challenge_records '
                .'SET consumed_result_json = :result, resume_owner = NULL, resume_until = NULL '
                .'WHERE nonce = :nonce'
            );
            $update->execute([':result' => $json, ':nonce' => $nonce]);

            return true;
        });
    }

    /**
     * The shared resume-claim owner contract, identical to the Redis
     * and array backends: exactly 32 lowercase hex characters.
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
     * Run one durable transition inside a begin-immediate transaction.
     * The lock is taken before the body reads, so the read-decide-write
     * sequence is serialized against every other writer on the file,
     * and the commit is the durability point. A storage-level failure
     * rolls back and surfaces as the typed fail-closed exception.
     *
     * @template T
     *
     * @param callable():T $body the transition, reading and writing rows
     *
     * @return T
     */
    private function writeTransition(string $what, callable $body): mixed
    {
        try {
            $this->pdo->exec('BEGIN IMMEDIATE');
        } catch (\PDOException $e) {
            throw self::storageFailure($what, $e);
        }
        try {
            $result = $body();
            $this->pdo->exec('COMMIT');
        } catch (\PDOException $e) {
            $this->safeRollback();
            throw self::storageFailure($what, $e);
        } catch (\JsonException $e) {
            $this->safeRollback();
            throw self::storageFailure($what, $e);
        } catch (\Throwable $e) {
            $this->safeRollback();
            throw $e;
        }

        return $result;
    }

    /**
     * Run one read-only path, mapping a driver failure to the typed
     * fail-closed exception the verifier resolves as an unavailable
     * store.
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
        } catch (\PDOException $e) {
            throw self::storageFailure($what, $e);
        }
    }

    /** Roll back quietly; a broken connection has nothing to undo. */
    private function safeRollback(): void
    {
        try {
            $this->pdo->exec('ROLLBACK');
        } catch (\Throwable) {
            // The rollback of a broken connection is best-effort; the
            // original failure is the one the caller must learn.
        }
    }

    /**
     * The row for a nonce, or null when absent or past its retention:
     * the expiry boundary is `now >= retained_until`, the exact mirror
     * of a Redis key whose TTL elapsed.
     *
     * @return array<string, mixed>|null
     */
    private function liveRow(string $nonce): ?array
    {
        $row = $this->row($nonce);
        if ($row === null) {
            return null;
        }
        if ($this->nowInSeconds() >= (int) $row['retained_until']) {
            return null;
        }

        return $row;
    }

    /**
     * The raw row for a nonce without the expiry filter, shared by the
     * live-row check and the read paths that decode from one fetch.
     *
     * @return array<string, mixed>|null
     */
    private function row(string $nonce): ?array
    {
        $select = $this->pdo->prepare(self::SELECT_ROW);
        $select->execute([':nonce' => $nonce]);
        $row = $select->fetch(\PDO::FETCH_ASSOC);
        if ($row === false) {
            return null;
        }

        return $row;
    }

    /** The runtime state column, or an empty string when the value is broken. */
    private function stateOf(array $row): string
    {
        $state = $row['state'] ?? null;

        return \is_string($state) ? $state : '';
    }

    /**
     * Decode a row into the record, its committed result and its
     * recorded identity. The record JSON passes the strict authority
     * first, a malformed committed result degrades to absent, and any
     * structural failure answers null: an unusable row, never a
     * partially trusted one.
     *
     * @param array<string, mixed> $row
     *
     * @return array{record: ChallengeRecord, result: ConsumedResult|null, identity: string|null}|null
     */
    private function decodeRow(array $row): ?array
    {
        $data = StrictJson::decodeObject((string) $row['record_json']);
        if ($data === null) {
            return null;
        }
        try {
            $record = ChallengeRecord::fromArray($data);
        } catch (\Throwable) {
            return null;
        }
        $result = null;
        $rawResult = $row['consumed_result_json'] ?? null;
        if (\is_string($rawResult)) {
            $decoded = StrictJson::decodeObject($rawResult);
            if (\is_array($decoded)) {
                try {
                    $result = ConsumedResult::fromArray($decoded);
                } catch (\Throwable) {
                    $result = null;
                }
            }
        }
        $identity = $row['operation_identity'] ?? null;

        return [
            'record' => $record,
            'result' => $result,
            'identity' => \is_string($identity) ? $identity : null,
        ];
    }

    /**
     * The retained consumed record of a row, carrying the committed
     * result and the recorded identity.
     *
     * @param array<string, mixed> $row
     */
    private function consumedFromRow(array $row): ConsumedRecord
    {
        $decoded = $this->decodeRow($row);

        return new ConsumedRecord($decoded['record'], false, true, $decoded['result'], $decoded['identity']);
    }

    /** The storage clock: the constructor seam or the wall clock. */
    private function nowInSeconds(): int
    {
        return $this->now !== null ? (int) ($this->now)() : time();
    }

    /**
     * Wrap a driver failure in the typed fail-closed exception with an
     * actionable message: the failing operation, the driver error, and
     * the write-lock remedy whenever the failure is contention.
     */
    private static function storageFailure(string $what, \Exception $e): SqliteStorageException
    {
        $message = sprintf('sqlite storage failure during %s: %s', $what, $e->getMessage());
        if (stripos($e->getMessage(), 'locked') !== false || stripos($e->getMessage(), 'busy') !== false) {
            $message .= '; the write lock stayed held past the busy timeout, so raise busyTimeoutMs or serialize writers';
        }

        return new SqliteStorageException($message, 0, $e);
    }
}
