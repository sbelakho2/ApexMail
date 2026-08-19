<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * Atomic provider-style verification idempotency.
 *
 * Turnstile semantics: an optional UUID idempotency_key makes validation
 * retries SAFE while tokens remain single-use:
 *   same response + NO key        -> first success, second timeout-or-duplicate
 *   same response + SAME key      -> first success, retries return the SAME
 *                                    canonical response (only one redemption)
 *   same response + DIFFERENT key -> second key gets timeout-or-duplicate
 *   same key + DIFFERENT response -> rejected (CONFLICT)
 *   same key + DIFFERENT remoteip -> rejected (CONFLICT — the claim binds
 *                                    the canonicalized remoteip fingerprint)
 *
 * The crash window (claim -> consume -> crash before finalize) is
 * recovered through the CORE's retained consumed-state machinery: a retry
 * with the same key + same response hash may interpret the stored
 * consumed result as the original success and finalize the entry — this
 * does NOT make ordinary token replays successful (the key+hash pair must
 * match a pending claim for THIS pair). Recovery is additionally gated by
 * the consumed record's OWN operation identity ({@see
 * \KiwiCaptcha\OperationIdentityAwareStorageInterface}): the identity was
 * written atomically with the pending→consumed transition, so a takeover
 * may reconstruct ONLY when the record's identity equals the claiming
 * fingerprint — a consumed token can never become successful again
 * through a different idempotency UUID or backend secret.
 *
 * Lease semantics: every claim and every successful takeover starts a
 * lease window (default 60 seconds, configurable per store constructor).
 * The lease is FIXED — the controller never derives it from a token's
 * remaining signed validity. A PENDING_SAME waiter whose owner's lease
 * has expired may atomically TAKEOVER the entry and become the owner — a
 * crashed owner therefore blocks the key for at most one lease window
 * instead of the full TTL. The lease exceeds the maximum supported
 * verification / request execution window plus a safety margin — the
 * same lease-must-exceed-runtime requirement the Argon semaphore
 * configuration documents — and the owner confirms its ownership AFTER
 * the verification by an atomic renewal ({@see self::renew()}). Safety
 * therefore depends on the verification never outlasting the lease: a
 * verification that outlasts the lease may be displaced, in which case
 * the displaced owner's local result is never authoritative — it returns
 * the stored outcome of the takeover winner instead. No process-global
 * signal state is involved in keeping an owner alive.
 */
interface SiteVerifyIdempotencyStore
{
    /**
     * The default lease window in seconds (see {@see self::takeover()}).
     * The ordering invariant is strict and enforced by the Siteverify
     * controller at construction:
     *
     *   max verification window  <  LEASE_SECONDS (60)
     *                            <  the PENDING_SAME waiter bound (90)
     *                            <  the default challenge lifetime (120)
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
     * 'no-ip') is bound into the record: a later claim with the SAME key
     * but a DIFFERENT fingerprint CONFLICTS — the same UUID with a
     * changed remoteip must never join, overtake or reuse an entry whose
     * outcome was derived under another IP.
     *
     * @return array{0: IdempotencyClaim, 1: ?string} the claim outcome and
     *         the OWNER token when this request claimed the entry (null
     *         otherwise) — only the owner may finalize it. `leaseSeconds`
     *         (null = the store's FIXED configured lease) sizes the owner
     *         lease window; the controller always passes null.
     */
    public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null): array;

    /**
     * Persist the canonical provider response for a COMPLETE claim so a
     * same-key retry returns the identical bytes. No-op unless this
     * request owns the claim AND the response hash matches the record.
     */
    public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): void;

    /** The stored canonical response for a COMPLETE_SAME claim, or null. */
    public function stored(string $backendId, string $idempotencyKey): ?array;

    /**
     * Atomically take over a PENDING_SAME claim whose lease has expired.
     * Succeeds ONLY when the entry is still pending, the response hash
     * AND the remoteip fingerprint both match the bound record, and
     * `lease_expires_at` is in the past: the caller then replaces the
     * owner, refreshes the lease, and wins the takeover. The fingerprint
     * check is defense-in-depth — every waiter passes through claim()
     * first, where the fingerprint is already enforced — but the store
     * enforces the complete claim identity itself even if a future
     * caller skipped claim(). A losing attempt leaves the record
     * untouched.
     *
     * @param int|null $leaseSeconds the lease window for the NEW owner in
     *                               seconds, overriding the store's
     *                               configured lease (null = the store's
     *                               configured lease). The controller
     *                               always passes null: the FIXED owner
     *                               lease is the store's configured lease
     *                               (default 60s — it exceeds any
     *                               supported verification window), never
     *                               a per-token derivation, and the
     *                               takeover keeps it for the whole
     *                               lifecycle.
     *
     * @return array{0: IdempotencyClaim, 1: ?string} TookOver + the NEW
     *         owner token the winner must finalize with, or StillPending +
     *         null when the lease is still held (or the entry is complete /
     *         belongs to a different response hash or remoteip fingerprint)
     */
    public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null): array;

        /**
     * After verification, atomically confirm that this request still owns
     * the pending claim and extend the lease through finalization. A
     * false result means ownership was lost and the caller must use the
     * authoritative stored outcome.
     */
    public function renew(string $backendId, string $idempotencyKey, string $owner): bool;
}
