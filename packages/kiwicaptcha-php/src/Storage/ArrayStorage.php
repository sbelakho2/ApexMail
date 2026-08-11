<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\StorageInterface;

/**
 * In-memory storage (single-process, non-persistent). Intended for tests,
 * CLI tools, and single-worker apps where Redis/DB is not available.
 *
 * consume() is read-then-delete: single-use per stored item, but NOT
 * atomic under concurrency (two racing requests in the same process can
 * both read the same record). Use {@see RedisStorage} for strict single-use.
 */
final class ArrayStorage implements StorageInterface
{
    /** @var array<string, ChallengeRecord> */
    private array $records = [];

    public function store(ChallengeRecord $record): void
    {
        $this->records[$record->nonce] = $record;
    }

    public function find(string $nonce): ?ChallengeRecord
    {
        return $this->records[$nonce] ?? null;
    }

    public function consume(string $nonce): ?ChallengeRecord
    {
        $record = $this->records[$nonce] ?? null;
        unset($this->records[$nonce]);

        return $record;
    }

    public function delete(string $nonce): void
    {
        unset($this->records[$nonce]);
    }
}
