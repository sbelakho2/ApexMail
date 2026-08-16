<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\ConsumedRecord;
use KiwiCaptcha\AtomicStorageInterface;
use KiwiCaptcha\ConsumedResult;
use KiwiCaptcha\StorageInterface;

/**
 * In-memory storage (single-process, non-persistent). Intended for tests,
 * CLI tools, and single-worker apps where Redis/DB is not available.
 *
 * consume() is the one-shot TRANSITION (audit #74): the record is marked
 * consumed and KEPT until deletion — replay protection is the consumed
 * marker, not absence. The transition is read-then-write; the state is a
 * plain in-process array that NO other process or thread can observe (PHP
 * copies on fork, so forked children never share it). Because the state is
 * unshareable, the read-modify-write transition is de-facto atomic — the
 * class therefore implements {@see AtomicStorageInterface}. Shared backends
 * with genuine concurrent access (PSR-6 pools, Redis MULTI-less clients)
 * must implement the compare-and-set contract themselves; see
 * {@see Psr6Storage} for the documented counter-example.
 */
final class ArrayStorage implements AtomicStorageInterface
{
    /** @var array<string, array{record: ChallengeRecord, consumed: bool, result: ConsumedResult|null}> */
    private array $records = [];

    public function store(ChallengeRecord $record): void
    {
        $this->records[$record->nonce] = ['record' => $record, 'consumed' => false, 'result' => null];
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
            return new ConsumedRecord($entry['record'], false, true, $entry['result']);
        }
        $this->records[$nonce]['consumed'] = true;

        return new ConsumedRecord($entry['record'], true, false, null);
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
