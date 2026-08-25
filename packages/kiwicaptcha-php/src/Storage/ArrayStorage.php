<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\ConsumedRecord;
use KiwiCaptcha\AtomicStorageInterface;
use KiwiCaptcha\ConsumedResult;
use KiwiCaptcha\OperationIdentity;
use KiwiCaptcha\OperationIdentityAwareStorageInterface;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\ChallengeRuntimeStateReadableInterface;
use KiwiCaptcha\ChallengeRuntimeStateKind;
use KiwiCaptcha\ChallengeRuntimeState;

/**
 * In-memory storage (single-process, non-persistent). Intended for tests,
 * CLI tools, and single-worker apps where Redis or a database is not
 * available.
 *
 * consume() is the one-shot transition: the record is marked consumed
 * and kept until deletion; replay protection is the consumed marker, not
 * absence. The transition is read-then-write, and the state is a plain
 * in-process array that no other process or thread can observe (PHP
 * copies on fork, so forked children never share it). Because the state
 * is unshareable, the read-modify-write transition is de-facto atomic,
 * and the class therefore implements {@see AtomicStorageInterface}.
 * Shared backends with genuine concurrent access (PSR-6 pools, Redis
 * clients without transactions) must implement the compare-and-set
 * contract themselves; see {@see Psr6Storage} for the documented
 * counter-example.
 *
 * The runtime envelope mirrors the Redis backend: every entry carries the
 * `operation_identity` marker (null | a bounded <= 128-byte
 * logical-operation identity written in the same transition as the state
 * flip via
 * {@see OperationIdentityAwareStorageInterface::consumeWithOperationIdentity()}),
 * exposed on the consumed read. The envelope also carries the terminal
 * `cancelled` marker of
 * {@see \KiwiCaptcha\CancellableStorageInterface::cancel()}; a cancelled
 * record is unverifiable and retained until deletion.
 */
final class ArrayStorage implements AtomicStorageInterface, \KiwiCaptcha\ConsumedStateReadableInterface, OperationIdentityAwareStorageInterface, \KiwiCaptcha\AtomicDeleteIfPendingInterface, \KiwiCaptcha\CancellableStorageInterface, \KiwiCaptcha\ChallengeRuntimeStateReadableInterface
{
    /** @var array<string, array{record: ChallengeRecord, consumed: bool, cancelled: bool, result: ConsumedResult|null, operationIdentity: string|null}> */
    private array $records = [];

    public function store(ChallengeRecord $record): void
    {
        $this->records[$record->nonce] = ['record' => $record, 'consumed' => false, 'cancelled' => false, 'result' => null, 'operationIdentity' => null];
    }

    public function find(string $nonce): ?ChallengeRecord
    {
        return $this->records[$nonce]['record'] ?? null;
    }

    public function consume(string $nonce): ?ConsumedRecord
    {
        $entry = $this->records[$nonce] ?? null;
        if ($entry === null) {
            return null;
        }
        if (($entry['cancelled'] ?? false)) {
            // A cancelled record is never consumable: the one-shot
            // transition reports it as missing, mirroring the Redis
            // backend's raw-splice gsub failure (the verifier then fails
            // the token closed instead of ever redeeming it).
            return null;
        }
        if ($entry['consumed']) {
            return new ConsumedRecord($entry['record'], false, true, $entry['result'], $entry['operationIdentity']);
        }
        $this->records[$nonce]['consumed'] = true;

        return new ConsumedRecord($entry['record'], true, false, null, null);
    }

    public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?ConsumedRecord
    {
        // The identity, validated against the narrow shared alphabet via
        // {@see OperationIdentity::validate()} (1..128 bytes of
        // [A-Za-z0-9_-]), lands in the same write as the state flip. A
        // malformed identity is rejected with InvalidArgumentException,
        // never silently dropped.
        $validated = OperationIdentity::validate($operationIdentity);
        $entry = $this->records[$nonce] ?? null;
        if ($entry === null) {
            return null;
        }
        if (($entry['cancelled'] ?? false)) {
            return null;
        }
        if ($entry['consumed']) {
            return new ConsumedRecord($entry['record'], false, true, $entry['result'], $entry['operationIdentity']);
        }
        $this->records[$nonce]['consumed'] = true;
        if ($validated !== null) {
            $this->records[$nonce]['operationIdentity'] = $validated;
        }

        return new ConsumedRecord($entry['record'], true, false, null, $this->records[$nonce]['operationIdentity']);
    }

    public function consumedState(string $nonce): ?ConsumedRecord
    {
        $entry = $this->records[$nonce] ?? null;
        if ($entry === null || !$entry['consumed']) {
            return null;
        }

        return new ConsumedRecord($entry['record'], false, true, $entry['result'], $entry['operationIdentity']);
    }

    public function commitResult(string $nonce, bool $valid, ?string $binding): bool
    {
        $entry = $this->records[$nonce] ?? null;
        if ($entry === null || !$entry['consumed'] || $entry['result'] !== null) {
            return false;
        }
        $this->records[$nonce]['result'] = new ConsumedResult($valid, $binding);

        return true;
    }

    public function delete(string $nonce): void
    {
        unset($this->records[$nonce]);
    }

    /**
     * The fused cleanup transition. The state is a plain in-process
     * array no other process can observe, so the read-decide-delete
     * sequence is de-facto atomic here. A missing record reports
     * missing, a pending record is deleted, and a consumed record is
     * kept untouched with its retained state riding back on the answer —
     * the same tri-state contract as the Redis backend's Lua script. A
     * cancelled record is kept too: dead but retained until its TTL.
     *
     * No replica barrier: this backend has no replicas, so the verified
     * WAIT durability contract of the Redis backend's delete-if-pending
     * transition does not apply — there is nothing to replicate, and a
     * delete cannot be resurrected by a promoted stale replica.
     */
    public function deleteIfPending(string $nonce): \KiwiCaptcha\DeleteIfPendingResult
    {
        $entry = $this->records[$nonce] ?? null;
        if ($entry === null) {
            return new \KiwiCaptcha\DeleteIfPendingResult('missing');
        }
        if ($entry['consumed']) {
            return new \KiwiCaptcha\DeleteIfPendingResult(
                'consumed',
                new ConsumedRecord($entry['record'], false, true, $entry['result'], $entry['operationIdentity']),
            );
        }
        if (($entry['cancelled'] ?? false)) {
            // A cancelled record is dead but retained until its TTL — the
            // cleanup never deletes it, so a cancellation can never be
            // resurrected as pending (mirrors the Redis backend's
            // delete-if-pending script).
            return new \KiwiCaptcha\DeleteIfPendingResult('cancelled');
        }
        unset($this->records[$nonce]);

        return new \KiwiCaptcha\DeleteIfPendingResult('deleted-pending');
    }

    /**
     * The atomic cancellation transition (in-process de-facto atomic, like
     * the other transitions here): a pending record is marked cancelled
     * and kept; a consumed record is finalized and never cancellable; an
     * already-cancelled record is idempotent; a missing record is null.
     */
    public function runtimeState(string $nonce): ChallengeRuntimeState
    {
        $entry = $this->records[$nonce] ?? null;
        if ($entry === null) {
            return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Missing);
        }
        if ($entry['cancelled'] ?? false) {
            return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Cancelled, $entry['record']);
        }
        if ($entry['consumed']) {
            return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Consumed, $entry['record'], new ConsumedRecord($entry['record'], false, true, $entry['result'], $entry['operationIdentity']));
        }

        return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Pending, $entry['record']);
    }

    public function cancel(string $nonce): ?\KiwiCaptcha\CancellationResult
    {
        $entry = $this->records[$nonce] ?? null;
        if ($entry === null) {
            return null;
        }
        if ($entry['consumed']) {
            return new \KiwiCaptcha\CancellationResult('consumed');
        }
        if (($entry['cancelled'] ?? false)) {
            return new \KiwiCaptcha\CancellationResult('cancelled');
        }
        $this->records[$nonce]['cancelled'] = true;

        return new \KiwiCaptcha\CancellationResult('cancelled-now');
    }
}
