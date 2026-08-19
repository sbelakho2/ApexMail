<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * NONCE-LEVEL redemption guard for Siteverify idempotency.
 *
 * The idempotency store proves only that a takeover reused the same
 * backend + key + response hash + remote-IP fingerprint — NOT that the
 * takeover's UUID is the logical operation that originally redeemed the
 * nonce. A consumed token replayed under a NEW UUID can therefore take
 * over its own pending claim and reconstruct the committed success of a
 * different logical operation.
 *
 * The guard closes that gap at the NONCE level: the first logical
 * Siteverify operation for a (backend, nonce) pair registers its
 * response hash (FIRST-WRITE-WINS — concurrent firsts are serialized by
 * the atomic set-if-absent), and any later UUID for the same nonce is a
 * DIFFERENT logical operation. Crash reconstruction is recovery-eligible
 * only when the claiming response hash IS the original redemption's
 * hash; a different-UUID claim for an already-redeemed nonce proceeds to
 * the ordinary verify, which returns timeout-or-duplicate.
 */
interface SiteVerifyRedemptionGuard
{
    /**
     * Register the response hash for this (backend, nonce) pair with
     * FIRST-WRITE-WINS semantics: the first registration wins and every
     * later register is an atomic no-op. The entry lives for
     * `$ttlSeconds` — long enough to outlive the retained consumed-state
     * evidence, so the guard stays authoritative for the whole
     * takeover/retry horizon.
     */
    public function register(string $backendId, string $nonce, string $responseHash, int $ttlSeconds): void;

    /**
     * The registered response hash of the ORIGINAL logical redemption
     * for this (backend, nonce) pair, or null when no registration
     * exists (or its TTL expired).
     */
    public function originalHash(string $backendId, string $nonce): ?string;
}
