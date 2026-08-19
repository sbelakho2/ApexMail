<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * Server-held state of a chained-challenge chain: the stage-1 challenge
 * nonce (the verified proof that opened the chain), the scope, the
 * stage-1 request binding, the REQUIRED next action, the policy epoch and
 * the chain depth, keyed by the random chain id that the signed chain
 * ticket carries.
 *
 * The state is CREATED atomically with ticket issuance (issue() writes
 * the FULL server-held state and returns the minimal signed ticket) and
 * driven through an atomic THREE-STATE machine at the stage-2 issuance:
 *
 *   available --reserve(owner)--> reserved(owner, leaseUntil)
 *       ^                              |
 *       +--------release(owner)--------+
 *       reserved(owner) --complete(owner, stage2Nonce)--> completed(stage2Nonce)
 *
 *  - reserve() claims the chain for ONE owner (a random per-request
 *    token): available -> reserved(me) answers 'available', reserved by
 *    ME answers 'retry', reserved by ANOTHER owner with a LIVE lease
 *    answers 'busy', reserved by another owner with an EXPIRED lease is
 *    TAKEN OVER (reserved(me), fresh lease) and answers 'available',
 *    completed answers 'completed' and absent answers 'missing'. The
 *    reservation lease is bounded by the chain record's OWN remaining TTL
 *    (redis TIME on the Redis side, an explicit clock on the array side):
 *    the whole record expires with the signed ticket, so the lease can
 *    never outlive the chain.
 *  - complete() is the TERMINAL one-shot transition: reserved(me) ->
 *    completed(stage2Nonce) — a state TRANSITION, never a delete. The
 *    completed record (kept with its TTL) lets a retry RECOVER the
 *    already-issued challenge instead of re-minting: a completed chain id
 *    can never gate a second mint.
 *  - release(owner) undoes a reservation (reserved -> available) on any
 *    refused or failed issuance: the ticket stays reusable — the chain is
 *    not burned by a later failure. A release by a NON-owner is an atomic
 *    no-op: a failing request can never free another owner's live
 *    reservation.
 *
 * The one-shot invariant is unchanged: a completed chain id can never
 * gate a second issuance, and a client cannot skip stages by replaying a
 * consumed chain. The state TTL equals the chain lifetime
 * (risk.chaining.ttl_secs), so an unused chain evaporates with its
 * ticket.
 */
interface ChainedChallengeStateStore
{
    /**
     * Persist the chain state in the AVAILABLE state with the given
     * lifetime. The chain id is random (16 bytes, base64url) and minted by
     * the ticket service, so the key namespace is attacker-unbounded only
     * by the service's own random generation. Every other field is written
     * by the SERVER at issue() time — a client can never alter them.
     *
     * @param string|null $requestBinding the stage-1 challenge's signed
     *                                    request binding (null when the
     *                                    challenge had none)
     * @param string|null $requiredAction the reassessed RiskAction's value
     *                                    the chain must satisfy at stage 2
     * @param int         $policyVersion  the security-policy epoch the
     *                                    stage-1 proof was verified under
     *
     * @throws \Throwable on backend failure — the caller fails closed
     *                    (no ticket without a server-held chain state)
     */
    public function create(string $chainId, string $stage1Nonce, string $scope, int $ttlSecs, ?string $requestBinding = null, ?string $requiredAction = null, int $policyVersion = 1): void;

    /**
     * PLAIN read of the chain state (no transition, no mutation): the
     * full record or null when the chain is absent/expired. Used by the
     * controller for the policy checks (scope, policy epoch, chain depth,
     * request binding) BEFORE the reservation claim.
     *
     * @return array{stage1Nonce: string, scope: string, requestBinding: ?string, requiredAction: string, policyVersion: int, chainDepth: int, state: 'available'|'reserved'|'completed', owner: ?string, leaseUntil: ?int, stage2Nonce: ?string}|null
     */
    public function read(string $chainId): ?array;

    /**
     * ATOMIC owner-scoped reservation: available -> reserved(owner,
     * leaseUntil) (the record KEEPS its remaining TTL — the signed ticket
     * expiry is the true bound; the lease is now + remaining TTL, never a
     * reset). Outcomes:
     *
     *  - 'available'  this call reserved the chain (or took over an
     *                 expired lease) — the caller proceeds,
     *  - 'retry'      already reserved by the SAME owner token — the
     *                 caller proceeds,
     *  - 'busy'       reserved by another owner with a LIVE lease — the
     *                 caller must NOT enter the issuance pipeline (the
     *                 retryable in-progress refusal),
     *  - 'completed'  the chain was already completed — the caller
     *                 recovers the issued challenge instead,
     *  - 'missing'    no state exists (never issued / expired).
     *
     * @param string $ownerToken random per-request owner token (16 bytes,
     *                           hex) — the ONLY handle that may release or
     *                           complete this reservation
     */
    public function reserve(string $chainId, string $ownerToken, int $ttlSecs): string;

    /**
     * Release a reservation: reserved(owner) -> available (the record
     * keeps its TTL). Called by the reservation owner's retry path after
     * a refused or failed issuance — the ticket is reusable, the chain is
     * not burned. A release by a NON-owner is an atomic no-op: a failing
     * request can never free another owner's live reservation.
     */
    public function release(string $chainId, string $ownerToken): void;

    /**
     * ATOMIC TERMINAL completion: reserved(owner) -> completed(
     * stage2Nonce) — a state transition, NEVER a delete (the completed
     * record keeps its TTL so a retry can recover the issued challenge).
     * Returns the completed state, or null when the transition is refused
     * (absent, not reserved, not the owner — atomic no-op — or already
     * completed). A completed state NEVER allows a second mint.
     *
     * @return array{stage1Nonce: string, scope: string, requestBinding: ?string, requiredAction: string, policyVersion: int, chainDepth: int, state: 'completed', owner: ?string, leaseUntil: ?int, stage2Nonce: ?string}|null
     */
    public function complete(string $chainId, string $ownerToken, string $stage2Nonce): ?array;
}
