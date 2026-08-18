<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Persistence for issued challenges.
 *
 * `consume()` is a one-shot TRANSITION: it marks the record
 * consumed and KEEPS it until its TTL — replay protection is the consumed
 * marker, not absence. The returned {@see ConsumedRecord} distinguishes the
 * winner of the transition (`consumedNow`) from a retry on an
 * already-consumed record (`consumedBefore`, with the deterministic
 * `consumedResult` when it was committed before a crash).
 *
 * Implementations MAY be non-atomic under concurrency: two racing requests
 * can both observe the pending state before either marks it consumed.
 * Implementations that guarantee STRICT single-use (exactly one caller wins
 * `consumedNow`, even under concurrency) implement
 * {@see AtomicStorageInterface}.
 */
interface StorageInterface
{
    /**
     * Store a challenge record, replacing any existing record with the same
     * nonce. The record is stored in its PENDING state.
     */
    public function store(ChallengeRecord $record): void;

    /**
     * Load a record by nonce without consuming it (used to inspect state).
     * Returns the record whether it is pending or already consumed.
     */
    public function find(string $nonce): ?ChallengeRecord;

    /**
     * One-shot consume transition: returns the record and marks it consumed
     * (keeping it until its TTL). A missing record yields null; an
     * already-consumed record is returned with `consumedBefore` set, plus
     * the committed result (if any).
     */
    public function consume(string $nonce): ?ConsumedRecord;

    /**
     * READ-ONLY consumed-state inspection: returns the retained
     * ConsumedRecord for an already-consumed record WITHOUT any state
     * transition (a fresh record is untouched), or null when the record
     * is missing or not yet consumed. Used for idempotent reconstruction
     * of a committed outcome after the signed challenge has expired.
     */
    public function consumedState(string $nonce): ?ConsumedRecord;

    /**
     * Commit the deterministic verification result of a consumed record.
     * Only succeeds (returns true) when the record exists, is in the
     * CONSUMED state, and has no committed result yet (atomic in the Redis
     * backend; best-effort elsewhere). The verifier calls this
     * best-effort — a failure must never change the verification outcome.
     */
    public function commitResult(string $nonce, bool $valid, ?string $binding): bool;

    /**
     * Delete a record by nonce.
     */
    public function delete(string $nonce): void;
}
