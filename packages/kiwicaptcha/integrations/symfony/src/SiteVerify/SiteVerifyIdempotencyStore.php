<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * Atomic provider-style verification idempotency.
 *
 * Turnstile semantics: an optional UUID idempotency_key makes validation
 * retries safe while tokens remain single-use:
 *   same response + NO key        -> first success, second timeout-or-duplicate.
 *   same response + same key      -> first success, retries return the same
 *                                    canonical response (only one redemption).
 *   same response + different key -> second key gets timeout-or-duplicate.
 *   same key + different response -> rejected (`CONFLICT`).
 *   same key + different remoteip -> rejected (`CONFLICT`: the claim binds
 *                                    the canonicalized remoteip pseudonym —
 *                                    a purpose-separated keyed HMAC, never
 *                                    the raw address; the raw request
 *                                    binding is likewise stored only as a
 *                                    keyed equality digest).
 *
 * The crash window (claim -> consume -> crash before finalize) is
 * recovered through the core's retained consumed-state machinery: a
 * retry with the same key + same response hash may interpret the stored
 * consumed result as the original success. It then finalizes the entry.
 * This does not make ordinary token replays successful: the key+hash
 * pair must match a pending claim for this pair. Recovery is
 * additionally gated by the consumed record's own operation identity,
 * see {@see \KiwiCaptcha\OperationIdentityAwareStorageInterface}: the
 * identity was written atomically with the pending→consumed transition,
 * so a takeover may reconstruct only when the record's identity equals
 * the claiming fingerprint. A consumed token can never become
 * successful again through a different idempotency UUID or backend
 * secret.
 *
 * Lease semantics: every claim and every successful takeover starts a
 * lease window (default 60 seconds, configurable per store constructor).
 * The lease is fixed: the controller never derives it from a token's
 * remaining signed validity. A `PENDING_SAME` waiter whose owner's lease
 * has expired may atomically take over the entry and become the owner; a
 * crashed owner therefore blocks the key for at most one lease window
 * instead of the full TTL. The lease exceeds the maximum supported
 * verification / request execution window plus a safety margin, the same
 * lease-must-exceed-runtime requirement the Argon semaphore
 * configuration documents. The owner confirms its ownership after the
 * verification by an atomic renewal, see {@see self::renew()}.
 * Safety depends on the verification never outlasting the lease: a
 * verification that outlasts the lease may be displaced, in which case
 * the displaced owner's local result is never authoritative: it returns
 * the stored outcome of the takeover winner instead. No process-global
 * signal state is involved in keeping an owner alive.
 */
interface SiteVerifyIdempotencyStore
{
    /**
     * The default lease window in seconds, see {@see self::takeover()}.
     * The ordering invariant is strict and enforced by the Siteverify
     * controller at construction. The max verification window stays
     * below `LEASE_SECONDS` (60). The retained-state recovery retention
     * is at least 90. The per-request `PENDING_SAME` waiter bound (2 s)
     * stays below the lease, only capping request-slot occupancy. The
     * default challenge lifetime stays above the retention.
     *
     * A lease that outlives the waiter bound would make the crash-
     * recovery takeover unreachable (the waiter gives up first), and a
     * lease that outlives the challenge lifetime would find the retained
     * consumed record expired at takeover time. 60s exceeds any
     * supported verification window (bounded by the Argon semaphore,
     * which documents the same lease-must-exceed-runtime requirement)
     * with margin, while keeping both orderings above.
     */
    public const LEASE_SECONDS = 60;

    /** The configured lease window in seconds (default {@see self::LEASE_SECONDS}). */
    public function leaseSeconds(): int;

    /**
     * Atomically claim (or join) the idempotency entry for this
     * backend + key + response pair. `backendId` separates configured
     * siteverify secrets/policies so namespaces never collide, and
     * `remoteipFingerprint` (the canonicalized request remoteip, or
     * 'no-ip') is bound into the record: a later claim with the same key
     * but a different pseudonym conflicts. The same UUID with a changed
     * remoteip must never join, overtake or reuse an entry whose outcome
     * was derived under another IP.
     *
     * @return array{0: IdempotencyClaim, 1: ?string} the claim outcome and
     *         the owner token when this request claimed the entry (null
     *         otherwise) — only the owner may finalize it. `leaseSeconds`
     *         (null = the store's fixed configured lease) sizes the owner
     *         lease window; the controller always passes null.
     */
    public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array;

    /**
     * Persist the canonical provider response for a complete claim so a
     * same-key retry returns the identical bytes. No-op unless this
     * request owns the claim AND the response hash matches the record.
     */
    public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): bool;

    /** The stored canonical response for a complete-same claim, or null. */
    public function stored(string $backendId, string $idempotencyKey): ?array;

    /**
     * Atomically take over a `PENDING_SAME` claim whose lease has expired.
     * Succeeds only when the entry is still pending, the response hash
     * and the remoteip fingerprint both match the bound record, and
     * `lease_expires_at` is in the past: the caller then replaces the
     * owner, refreshes the lease, and wins the takeover. The fingerprint
     * check is defense-in-depth: every waiter passes through claim()
     * first, where the fingerprint is already enforced, but the store
     * enforces the complete claim identity itself even if a future
     * caller skipped claim(). A losing attempt leaves the record
     * untouched.
     *
     * @param int|null $leaseSeconds the lease window for the new owner in
     *                               seconds, overriding the store's
     *                               configured lease (null = the store's
     *                               configured lease). The controller
     *                               always passes null: the fixed owner
     *                               lease is the store's configured lease
     *                               (default 60s, which exceeds any
     *                               supported verification window), never
     *                               a per-token derivation, and the
     *                               takeover keeps it for the whole
     *                               lifecycle.
     *
     * @return array{0: IdempotencyClaim, 1: ?string} TookOver + the new
     *         owner token the winner must finalize with, or StillPending +
     *         null when the lease is still held (or the entry is complete /
     *         a different response hash or remoteip fingerprint)
     */
    public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array;

        /**
     * After verification, atomically confirm that this request still owns
     * the pending claim and extend the lease through finalization. A
     * false result means ownership was lost and the caller must use the
     * authoritative stored outcome.
     */
    public function renew(string $backendId, string $idempotencyKey, string $owner): bool;
}
