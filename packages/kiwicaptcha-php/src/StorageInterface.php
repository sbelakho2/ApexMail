<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Persistence for issued challenges.
 *
 * `consume()` returns the record and removes it, enforcing single-use
 * semantics per stored item. Implementations MAY be non-atomic under
 * concurrency: two racing requests can both read the same record before
 * either removes it. Implementations that guarantee STRICT single-use
 * (a second call MUST return null even under concurrency) implement
 * {@see AtomicStorageInterface}.
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
     * Load-and-remove a record: returns the record only if it existed and
     * removes it from the store, so replaying a token yields no record and
     * verification fails. Best-effort single-use — MAY be non-atomic under
     * concurrency; implementations that guarantee atomic single-use
     * implement {@see AtomicStorageInterface}.
     */
    public function consume(string $nonce): ?ChallengeRecord;

    /**
     * Delete a record by nonce.
     */
    public function delete(string $nonce): void;
}
