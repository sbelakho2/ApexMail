<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * Durable, NONCE-KEYED final disposition of a verified proof.
 *
 * The validator resolves ONE final disposition (PASS | DENY | STEP_UP |
 * CHAIN_REQUIRED) per verification and persists it BEFORE the application
 * sees the outcome, so a replay of the same token reproduces the same
 * disposition — a stored core result can never bypass the post-solve
 * policy (it only answers "was the PoW cryptographically valid?").
 *
 * Claim model (single-writer): exactly one owner computes the disposition
 * for a nonce. The SHORT FIXED lease (15 s — the post-solve computation is
 * cheap, the lease is a contention bound, NEVER the record TTL) lets a
 * crash-taken-over computation be redone after expiry; the record itself
 * lives for the whole retryable lifetime of the consumed core result.
 *
 * The record JSON carries ONLY the disposition (kind / decision_id /
 * chain_id) plus the original decision handle — raw risk vectors,
 * fingerprints and descriptors are never stored.
 */
interface PostSolveDispositionStore
{
    /**
     * Atomically claim the right to compute the nonce's disposition.
     *
     * @return 'claimed'|'pending'|'taken_over'|'complete'
     *         claimed      — the caller holds a fresh claim (missing -> pending(me));
     *         pending      — pending with a live owner (me or another) — busy;
     *         taken_over   — the caller took over an expired-lease claim (pending(me));
     *         complete     — the final disposition is already persisted.
     *
     * @param string      $nonce       the verified challenge nonce (random security state)
     * @param string      $owner       a fresh random owner token of this claim
     * @param int         $ttlSeconds  the RECORD TTL (the lease is a fixed short bound)
     * @param string|null $decisionKey the FULL nonce -> decision mapping key
     *                                 ({kiwi:<ns>}:decision:<nonce> — the same
     *                                 hash-tagged key the gateway pairs the
     *                                 handle under). The mapping is CONSUMED
     *                                 (GETDEL, at most one winner) inside the
     *                                 same atomic transition as the claim and
     *                                 the paired decision id is persisted in
     *                                 the pending record; a TAKEOVER keeps the
     *                                 ORIGINAL handle (never the new owner's),
     *                                 so a crash-taken-over computation
     *                                 completes with the first owner's decision
     *                                 id. null = no decision mapping (the
     *                                 records carry null)
     *
     * @throws \Throwable when the store is unavailable (fail closed)
     */
    public function claim(string $nonce, string $owner, int $ttlSeconds, ?string $decisionKey = null): string;

    /**
     * Read the current record behind a nonce, or null when absent/expired.
     *
     * @throws \Throwable when the store is unavailable (fail closed)
     */
    public function read(string $nonce): ?PostSolveDispositionRecord;

    /**
     * Atomically transition pending(me) -> complete(disposition). Refused
     * (false) for a non-owner or a non-pending record — never overwrites
     * another owner's work.
     *
     * @throws \Throwable when the store is unavailable (fail closed)
     */
    public function finalize(string $nonce, string $owner, PostSolveDisposition $disposition): bool;
}
