<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\StorageInterface;

/**
 * In-memory storage (single-process, non-persistent). Intended for tests,
 * CLI tools, and single-worker apps where Redis/DB is not available.
 *
 * Attempt accounting is best-effort in-memory bookkeeping: `incrementAttempts`
 * always returns true because a process-local counter cannot atomically
 * enforce a cap against concurrent requests. The real gate is consume()'s
 * single-use semantics; use RedisStorage for an atomic attempt cap.
 */
final class ArrayStorage implements StorageInterface
{
    /** @var array<string, ChallengeRecord> */
    private array $records = [];

    /** @var array<string, int> */
    private array $attempts = [];

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

    public function attemptsUsed(string $nonce): int
    {
        return $this->attempts[$nonce] ?? 0;
    }

    public function incrementAttempts(string $nonce, int $maxAttempts): bool
    {
        $this->attempts[$nonce] = ($this->attempts[$nonce] ?? 0) + 1;

        return true;
    }
}
