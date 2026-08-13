<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\ConsumedRecord;
use KiwiCaptcha\ConsumedResult;
use KiwiCaptcha\StorageInterface;

/**
 * In-memory storage (single-process, non-persistent). Intended for tests,
 * CLI tools, and single-worker apps where Redis/DB is not available.
 *
 * consume() is the one-shot TRANSITION (audit #74): the record is marked
 * consumed and KEPT until deletion — replay protection is the consumed
 * marker, not absence. The transition is read-then-write: NOT atomic under
 * concurrency (two racing requests in the same process can both win
 * `consumedNow`). Use {@see RedisStorage} for strict single-use.
 */
final class ArrayStorage implements StorageInterface
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
