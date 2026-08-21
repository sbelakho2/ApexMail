<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * Server-held state of a chained-challenge chain: the stage-1 challenge
 * nonce (the verified proof that opened the chain), the scope, the
 * authoritative transaction binding, the required next action and its
 * rank, the policy epoch, the chain depth and the obligation id. It is
 * keyed by the random chain id that the signed chain ticket carries.
 *
 * State machine (v2, strict schema): available -> reserved(owner, short
 * lease) -> issued(stage2Nonce), with the terminal transitions
 * verified, step_up_required and denied, the rearm back to available,
 * and the nonce-agnostic transaction terminalizations.
 *
 *  - The chain is a server-side transaction obligation: every chain is
 *    anchored on a bounded pseudonymous obligation id, the hmac of
 *    "chain-obligation\0{policyVersion}\0{scope}\0{binding}" with
 *    chainSecret, never a raw binding in a key. The obligation index
 *    ({kiwi:<ns>}:chain-obligation:<obligationId> -> chainId, same hash
 *    tag as the chain record, same TTL) is created atomically with the
 *    chain. A client cannot restart a transaction at stage 1 by
 *    discarding the ticket: a later challenge request for the same
 *    transaction auto-resumes the open chain.
 *  - reserve() claims the chain for one owner with a short lease (the
 *    reservation_lease_secs knob, bounded by the chain record's own
 *    remaining TTL). available -> reserved(me) answers 'available';
 *    reserved by me answers 'retry'; reserved by another owner with a
 *    live lease answers 'busy'; an expired other-owner lease is taken
 *    over and answers 'taken_over'. issued/verified answer 'issued' /
 *    'verified' (recover, never re-mint); the terminal
 *    step_up_required/denied states answer 'step_up_required'/'denied'
 *    (the obligation stays bound); absent answers 'missing'. A chain
 *    record without an expiry is corrupted state, so it fails closed
 *    ('missing'); a lifetime is never manufactured from the configured
 *    TTL.
 *  - markIssued() is the idempotent owner-scoped issuance transition,
 *    reserved(me) -> issued(stage2Nonce). The issued record is kept with
 *    its TTL, so a retry can recover the already-issued challenge instead
 *    of re-minting. An issued chain id can never gate a second mint,
 *    except through the explicit rearm, which returns the chain to the
 *    available state for a fresh stage-2 mint at the same-or-stronger
 *    floor, never a stage-1.
 *  - markVerified() is the terminal Pass transition, issued(nonce) ->
 *    verified(nonce), and atomically deletes the obligation key only if
 *    it still points at this chainId. The terminal verified record is
 *    kept until its TTL, so a retry can confirm the chain ended.
 *  - markStepUpRequired() / markDenied() are the terminal disposition
 *    transitions: issued(nonce) -> step_up_required(nonce), and
 *    issued(nonce) -> denied(nonce). The obligation mapping is kept, so
 *    the transaction stays bound to its final disposition and a later
 *    challenge request re-encounters the terminal state (never a new
 *    stage-1). The terminal records are kept until their TTL. The
 *    transactional contract adds the obligation-bound, nonce-agnostic
 *    markTransactionDenied() / markTransactionStepUpRequired()
 *    terminalizations of an open obligation: a fresh Deny or StepUp from
 *    a different verified nonce of the obligated transaction becomes
 *    durable, keyed by the chain/obligation identity. The transition is
 *    atomic over the chain record plus the obligation mapping, so a
 *    stale chain whose obligation moved can never be terminalized. The
 *    terminal states carry an optional stage-2 nonce (the exact nonce
 *    when one was issued, null otherwise).
 *  - release(owner) undoes a reservation (reserved -> available) on any
 *    refused or failed issuance: the ticket stays reusable, so the chain
 *    is not burned by a later failure. A release by a non-owner is an
 *    atomic no-op: a failing request can never free another owner's live
 *    reservation. The issued/verified transitions are owner-gated too (a
 *    non-owner transition is an atomic no-op).
 *
 * The one-shot invariant is unchanged: a chain id can never gate a second
 * issuance while issued/terminal, and a client cannot skip stages by
 * replaying a consumed chain. The state TTL equals the chain lifetime
 * (risk.chaining.ttl_secs), so an unused chain evaporates with its
 * ticket.
 *
 * The typed surface ({@see ChainRequirement} /
 * {@see ChainReservationResult} / {@see ChainIssuedResult} /
 * {@see ChainVerifiedResult}) lives in its own PSR-4 files, loadable
 * standalone.
 *
 * @deprecated contract: the transactional machine lives on
 *              {@see TransactionalChainedChallengeStateStore}. These
 *              legacy methods are retained for source compatibility and
 *              removed in the next major. The legacy 'completed' state is
 *              the historical name of the terminal-with-stage2Nonce state
 *              (semantically identical to 'issued'); the transactional
 *              contract never writes it.
 */
interface ChainedChallengeStateStore
{
    /**
     * Persist the chain state in the available state with the given
     * lifetime, without an obligation mapping. The legacy path is not
     * transaction-anchored, which is why it is deprecated.
     *
     * @param string|null $requestBinding the authoritative request binding
     *                                    (null when the transaction is
     *                                    unbound).
     * @param string|null $requiredAction the reassessed RiskAction's value
     *                                    (a chainable PoW action
     *                                    Sha16..Argon64, required: a
     *                                    record without a chainable action
     *                                    is corrupt state and refused).
     * @param int         $policyVersion  the security-policy epoch the
     *                                    stage-1 proof was verified under.
     *
     * @throws \Throwable on backend failure: the caller fails closed (no
     *                    ticket without a server-held chain state).
     *
     * @deprecated use createWithObligation()/createOrGetObligation(), the
     *             obligation-anchored transactional contract.
     */
    public function create(string $chainId, string $stage1Nonce, string $scope, int $ttlSecs, ?string $requestBinding = null, ?string $requiredAction = null, int $policyVersion = 1): void;

    /**
     * Plain read of the chain state (no transition, no mutation): the
     * full strictly-decoded v2 record or null when the chain is
     * absent/expired.
     *
     * @return array{stage1Nonce: string, scope: string, requestBinding: ?string, requiredAction: string, requiredRank: int, policyVersion: int, chainDepth: int, state: 'available'|'reserved'|'issued'|'verified'|'step_up_required'|'denied'|'completed', owner: ?string, leaseUntil: ?int, stage2Nonce: ?string, obligationId: string, expiresAt: int}|null
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema (fail
     *                                                 closed; the caller
     *                                                 answers
     *                                                 temporary-unavailable).
     */
    public function read(string $chainId): ?array;

    /**
     * Atomic owner-scoped reservation with a short lease
     * (reservation_lease_secs, bounded by the record's own remaining TTL,
     * KEEPTTL). A record without an expiry is corrupted state and answers
     * 'missing'. Outcomes:
     *
     *  - 'available'   this call reserved the chain; the caller proceeds.
     *  - 'retry'       already reserved by the same owner token; the
     *                  caller proceeds.
     *  - 'busy'        reserved by another owner with a live lease; the
     *                  caller must not enter the issuance pipeline (the
     *                  retryable in-progress refusal).
     *  - 'taken_over'  reserved by another owner with an expired lease;
     *                  the chain is claimed with a fresh lease and the
     *                  caller proceeds.
     *  - 'issued'      the chain already issued a stage-2 challenge; the
     *                  caller recovers it instead of re-minting
     *                  ('completed' for legacy records, the historical
     *                  name of the same terminal state).
     *  - 'verified'    the chain is terminal; the caller recovers the
     *                  issued challenge.
     *  - 'step_up_required' / 'denied' the chain is terminal with the
     *                  transaction bound to its final disposition; the
     *                  caller must not issue.
     *  - 'missing'     no state exists (never issued, expired, or corrupt
     *                  without expiry).
     *
     * @param string $ownerToken random per-request owner token (16 bytes,
     *                           hex). The only handle that may release or
     *                           issue this reservation.
     *
     * @deprecated use reserve() on the transactional contract (the
     *             short-lease machine with the same outcome set).
     */
    public function reserve(string $chainId, string $ownerToken, int $ttlSecs): string;

    /**
     * Release a reservation: reserved(owner) -> available (the record
     * keeps its TTL). Called by the reservation owner's retry path after
     * a refused or failed issuance, so the ticket stays reusable and the
     * chain is not burned. A release by a non-owner is an atomic no-op: a
     * failing request can never free another owner's live reservation.
     */
    public function release(string $chainId, string $ownerToken): void;

    /**
     * Deprecated legacy completion: reserved(owner) -> completed(
     * stage2Nonce), the historical name of the terminal-with-nonce state,
     * semantically identical to the transactional contract's markIssued()
     * -> issued. The completed record keeps its TTL so a retry can
     * recover the issued challenge. Returns the completed record, or null
     * when the transition is refused (absent, not reserved, not the
     * owner, an atomic no-op, or already terminal).
     *
     * @return array{stage1Nonce: string, scope: string, requestBinding: ?string, requiredAction: string, requiredRank: int, policyVersion: int, chainDepth: int, state: 'completed', owner: ?string, leaseUntil: ?int, stage2Nonce: string, obligationId: string, expiresAt: int}|null
     *
     * @deprecated use markIssued() on the transactional contract.
     */
    public function complete(string $chainId, string $ownerToken, string $stage2Nonce): ?array;
}
