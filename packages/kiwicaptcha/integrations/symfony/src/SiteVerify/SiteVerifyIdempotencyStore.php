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
 */
interface SiteVerifyIdempotencyStore
{
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
}
