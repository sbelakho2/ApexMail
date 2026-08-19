<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\ConsumedRecord;
use KiwiCaptcha\AtomicStorageInterface;
use KiwiCaptcha\ConsumedResult;
use KiwiCaptcha\OperationIdentityAwareStorageInterface;
use KiwiCaptcha\StorageInterface;

/**
 * In-memory storage (single-process, non-persistent). Intended for tests,
 * CLI tools, and single-worker apps where Redis/DB is not available.
 *
 * consume() is the one-shot TRANSITION: the record is marked
 * consumed and KEPT until deletion — replay protection is the consumed
 * marker, not absence. The transition is read-then-write; the state is a
 * plain in-process array that NO other process or thread can observe (PHP
 * copies on fork, so forked children never share it). Because the state is
 * unshareable, the read-modify-write transition is de-facto atomic — the
 * class therefore implements {@see AtomicStorageInterface}. Shared backends
 * with genuine concurrent access (PSR-6 pools, Redis MULTI-less clients)
 * must implement the compare-and-set contract themselves; see
 * {@see Psr6Storage} for the documented counter-example.
 *
 * The runtime envelope mirrors the Redis backend: every entry carries the
 * `operation_identity` marker (null | a bounded <= 128-byte
 * logical-operation identity written in the SAME transition as the state
 * flip via {@see OperationIdentityAwareStorageInterface::consumeWithOperationIdentity()}),
 * exposed on the consumed read.
 */
final class ArrayStorage implements AtomicStorageInterface, \KiwiCaptcha\ConsumedStateReadableInterface, OperationIdentityAwareStorageInterface
{
    /** @var array<string, array{record: ChallengeRecord, consumed: bool, result: ConsumedResult|null, operationIdentity: string|null}> */
    private array $records = [];

    public function store(ChallengeRecord $record): void
    {
        $this->records[$record->nonce] = ['record' => $record, 'consumed' => false, 'result' => null, 'operationIdentity' => null];
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
        if ($entry['consumed']) {
            return new ConsumedRecord($entry['record'], false, true, $entry['result'], $entry['operationIdentity']);
        }
        $this->records[$nonce]['consumed'] = true;

        return new ConsumedRecord($entry['record'], true, false, null, null);
    }

    public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?ConsumedRecord
    {
        $entry = $this->records[$nonce] ?? null;
        if ($entry === null) {
            return null;
        }
        if ($entry['consumed']) {
            return new ConsumedRecord($entry['record'], false, true, $entry['result'], $entry['operationIdentity']);
        }
        // The identity (bounded — an over-long identity is IGNORED) lands
        // in the SAME write as the state flip.
        $this->records[$nonce]['consumed'] = true;
        if ($operationIdentity !== null && \strlen($operationIdentity) <= 128) {
            $this->records[$nonce]['operationIdentity'] = $operationIdentity;
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
}
