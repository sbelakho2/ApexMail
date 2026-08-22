<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * Durable, nonce-keyed final disposition of a verified proof.
 *
 * The validator resolves one final disposition (pass | deny | step-up |
 * chain-required) per verification and persists it before the
 * application sees the outcome. A replay of the same token then
 * reproduces the same disposition and can never bypass the post-solve
 * policy.
 *
 * Claim model (single-writer): exactly one owner computes the
 * disposition for a nonce. The short fixed lease (15 s) is a
 * contention bound, never the record TTL; the record lives for the
 * whole retryable lifetime of the consumed core result.
 *
 * The record JSON carries only the disposition (kind / decision_id /
 * chain_id) plus the original decision handle — raw risk vectors,
 * fingerprints and descriptors are never stored.
 */
interface PostSolveDispositionStore
{
    /**
     * Atomically claim the right to compute the nonce's disposition.
     *
     * The claim transition answers with the claim outcome AND the
     * disposition record the caller needs for that outcome, so the
     * common fresh path is exactly claim -> compute -> finalize: no
     * separate read round-trip before or after the claim. The record
     * travels inside the same transition the Lua/Array state machine
     * performs (or the state it read), so a fallible caller read can
     * never observe a different record than the one the claim decided
     * on.
     *
     * @return array{0: 'claimed'|'pending'|'taken_over'|'complete', 1: ?PostSolveDispositionRecord}
     *         claimed:     the caller holds a fresh claim, missing
     *                      going to pending(me). The response carries the
     *                      pending record (the consumed decision handle
     *                      when a mapping was wired).
     *         pending:     pending with a live owner (me or another),
     *                      busy. No record is carried — the caller answers
     *                      the retryable busy outcome without a read.
     *         taken_over:  the caller took over an expired-lease claim,
     *                      reaching pending(me). The response carries the
     *                      pending record with the original decision
     *                      handle preserved.
     *         complete:    the final disposition is already persisted. The
     *                      response carries the complete record (the
     *                      persisted disposition and decision handle).
     *
     * A corrupt existing record is refused fail-closed inside the claim
     * transition: {@see MalformedPostSolveDispositionException}, never
     * healed into valid state by a takeover, never answered as a valid
     * disposition.
     *
     * @param string      $nonce       the verified challenge nonce (random
     *                                 security state).
     * @param string      $owner       a fresh random owner token of this
     *                                 claim.
     * @param int         $ttlSeconds  the record TTL (the lease is a fixed
     *                                 short bound).
     * @param string|null $decisionKey the full nonce -> decision mapping
     *                                 key ({kiwi:<ns>}:decision:<nonce>, the
     *                                 same hash-tagged key the gateway pairs
     *                                 the handle under). The mapping is
     *                                 consumed atomically (delete-on-read,
     *                                 at most one winner) only when the
     *                                 claim creates the missing pending
     *                                 record, and the paired decision id is
     *                                 persisted in that record in the same
     *                                 transition. A complete, busy or
     *                                 takeover claim never touches the
     *                                 mapping key, and a takeover keeps the
     *                                 original handle, so a
     *                                 crash-taken-over computation completes
     *                                 with the first owner's decision id.
     *                                 null = no decision mapping (the
     *                                 records carry null).
     *
     * @throws \Throwable when the store is unavailable (fail closed)
     */
    public function claim(string $nonce, string $owner, int $ttlSeconds, ?string $decisionKey = null): array;

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
