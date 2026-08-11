<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Persistence for issued challenges.
 *
 * Implementations MUST be consistent with the atomic single-use semantics:
 * once `consume()` returns true the record is gone, so replaying a token
 * yields no record and verification fails.
 */
interface StorageInterface
{
    /**
     * Store a challenge record, replacing any existing record with the same
     * nonce.
     */
    public function store(ChallengeRecord $record): void;

    /**
     * Load a record by nonce without consuming it (used to inspect state).
     */
    public function find(string $nonce): ?ChallengeRecord;

    /**
     * Atomically load-and-delete a record. Returns the record only if it
     * existed; a second call for the same nonce MUST return null.
     */
    public function consume(string $nonce): ?ChallengeRecord;

    /**
     * Delete a record by nonce.
     */
    public function delete(string $nonce): void;

    /**
     * Number of verify attempts recorded so far for a nonce.
     */
    public function attemptsUsed(string $nonce): int;

    /**
     * Record one verify attempt for a nonce, atomically when the backend
     * supports it (Redis). Returns false when the attempt would exceed
     * $maxAttempts — the caller then rejects with TooManyAttempts.
     *
     * Implementations without atomic counters (PSR-6, in-memory) perform
     * best-effort read-modify-write accounting and MUST document that they
     * cannot enforce the cap under concurrency.
     */
    public function incrementAttempts(string $nonce, int $maxAttempts): bool;
}
