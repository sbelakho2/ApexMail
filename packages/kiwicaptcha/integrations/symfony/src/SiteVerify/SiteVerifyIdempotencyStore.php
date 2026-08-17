<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * Round 30 (P1): atomic provider-style verification idempotency.
 *
 * Turnstile semantics: an optional UUID idempotency_key makes validation
 * retries SAFE while tokens remain single-use:
 *   same response + NO key        -> first success, second timeout-or-duplicate
 *   same response + SAME key      -> first success, retries return the SAME
 *                                    canonical response (only one redemption)
 *   same response + DIFFERENT key -> second key gets timeout-or-duplicate
 *   same key + DIFFERENT response -> rejected (CONFLICT)
 *
 * The crash window (claim -> consume -> crash before finalize) is
 * recovered through the CORE's retained consumed-state machinery: a retry
 * with the same key + same response hash may interpret the stored
 * consumed result as the original success and finalize the entry — this
 * does NOT make ordinary token replays successful (the key+hash pair must
 * match a pending claim for THIS pair).
 *
 * Round 31 (P2): every claim carries a LEASE (`lease_expires_at`, Unix
 * seconds, set at claim creation and refreshed on takeover). A PENDING_SAME
 * waiter whose lease has expired may atomically TAKEOVER the entry and
 * become the owner — a crashed owner therefore blocks the key for at most
 * one lease window instead of the full TTL.
 */
interface SiteVerifyIdempotencyStore
{
    /** The lease window in seconds (see {@see self::takeover()}). */
    public const LEASE_SECONDS = 30;

    /**
     * Atomically claim (or join) the idempotency entry for this
     * backend + key + response pair. `backendId` separates configured
     * siteverify secrets/policies so namespaces never collide.
     *
     * @return array{0: IdempotencyClaim, 1: ?string} the claim outcome and
     *         the OWNER token when this request claimed the entry (null
     *         otherwise) — only the owner may finalize it
     */
    public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds): array;

    /**
     * Persist the canonical provider response for a COMPLETE claim so a
     * same-key retry returns the identical bytes. No-op unless this
     * request owns the claim.
     */
    public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): void;

    /** The stored canonical response for a COMPLETE_SAME claim, or null. */
    public function stored(string $backendId, string $idempotencyKey): ?array;

    /**
     * Atomically take over a PENDING_SAME claim whose lease has expired.
     * Succeeds ONLY when the entry is still pending AND
     * `lease_expires_at` is in the past: the caller then replaces the
     * owner, refreshes the lease, and wins the takeover. A losing attempt
     * leaves the record untouched.
     *
     * @return array{0: IdempotencyClaim, 1: ?string} TookOver + the NEW
     *         owner token the winner must finalize with, or StillPending +
     *         null when the lease is still held (or the entry is complete /
     *         belongs to a different response hash)
     */
    public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds): array;
}
