<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\Risk\RiskAction;

/**
 * Server-held state of a chained-challenge chain: the stage-1 challenge
 * nonce (the verified proof that opened the chain), the scope, the
 * authoritative transaction binding, the REQUIRED next action + its rank,
 * the policy epoch, the chain depth and the obligation id, keyed by the
 * random chain id that the signed chain ticket carries.
 *
 * STATE MACHINE (v2, strict schema):
 *
 *   available --reserve(owner, short lease)--> reserved(owner, leaseUntil)
 *       ^                                            |
 *       +-------------release(owner)-----------------+
 *   reserved(owner) --markIssued(owner, nonce)--> issued(stage2Nonce)
 *   issued(stage2Nonce) --markVerified(nonce)--> verified(stage2Nonce)  [TERMINAL]
 *   issued(stage2Nonce) --rearmIssued(nonce)--> available
 *
 *  - The chain is a SERVER-SIDE TRANSACTION OBLIGATION: every chain is
 *    anchored on a bounded pseudonymous obligation id
 *    (hmac("chain-obligation\0{policyVersion}\0{scope}\0{binding}",
 *    chainSecret) — never a raw binding in a key) and the obligation
 *    index ({kiwi:<ns>}:chain-obligation:<obligationId> -> chainId, same
 *    hash tag as the chain record, SAME TTL) is created atomically with
 *    the chain. A client cannot restart a transaction at stage 1 by
 *    discarding the ticket: a later challenge request for the same
 *    transaction auto-resumes the open chain.
 *  - reserve() claims the chain for ONE owner with a SHORT lease (the
 *    reservation_lease_secs knob, bounded by the chain record's OWN
 *    remaining TTL): available -> reserved(me) answers 'available',
 *    reserved by ME answers 'retry', reserved by ANOTHER owner with a
 *    LIVE lease answers 'busy', an EXPIRED other-owner lease is TAKEN
 *    OVER and answers 'taken_over', issued/verified answer 'issued' /
 *    'verified' (recover, never re-mint) and absent answers 'missing'. A
 *    chain record WITHOUT an expiry is CORRUPTED state — fail closed
 *    ('missing'), never manufacture a lifetime from the configured TTL.
 *  - markIssued() is the idempotent owner-scoped issuance transition
 *    (reserved(me) -> issued(stage2Nonce)): the issued record (kept with
 *    its TTL) lets a retry RECOVER the already-issued challenge instead
 *    of re-minting — an issued chain id can never gate a second mint
 *    (except through the explicit rearm, which returns the chain to the
 *    available state for a FRESH stage-2 mint at the same-or-stronger
 *    floor — NEVER a stage-1).
 *  - markVerified() is the TERMINAL transition (issued(nonce) ->
 *    verified(nonce)) and ATOMICALLY deletes the obligation key ONLY if
 *    it still points at this chainId. The terminal verified record is
 *    kept until its TTL (a retry can confirm the chain ended).
 *  - release(owner) undoes a reservation (reserved -> available) on any
 *    refused or failed issuance: the ticket stays reusable — the chain is
 *    not burned by a later failure. A release by a NON-owner is an atomic
 *    no-op: a failing request can never free another owner's live
 *    reservation. The issued/verified transitions are OWNER-GATED too (a
 *    non-owner transition is an atomic no-op).
 *
 * The one-shot invariant is unchanged: a chain id can never gate a second
 * issuance while issued/verified, and a client cannot skip stages by
 * replaying a consumed chain. The state TTL equals the chain lifetime
 * (risk.chaining.ttl_secs), so an unused chain evaporates with its
 * ticket.
 *
 * @deprecated contract — the four-state transactional machine lives on
 *              {@see TransactionalChainedChallengeStateStore}; these
 *              legacy methods are retained for source compatibility and
 *              removed in the next major. The legacy 'completed' state is
 *              the historical name of the terminal-with-stage2Nonce state
 *              (semantically identical to 'issued'); the transactional
 *              contract never writes it.
 */
interface ChainedChallengeStateStore
{
    /**
     * Persist the chain state in the AVAILABLE state with the given
     * lifetime, WITHOUT an obligation mapping (the legacy path is not
     * transaction-anchored — deprecated for that reason).
     *
     * @param string|null $requestBinding the authoritative request binding
     *                                    (null when the transaction is
     *                                    unbound)
     * @param string|null $requiredAction the reassessed RiskAction's value
     *                                    (a chainable PoW action
     *                                    Sha16..Argon64 — REQUIRED: a
     *                                    record without a chainable action
     *                                    is corrupt state and refused)
     * @param int         $policyVersion  the security-policy epoch the
     *                                    stage-1 proof was verified under
     *
     * @throws \Throwable on backend failure — the caller fails closed
     *                    (no ticket without a server-held chain state)
     *
     * @deprecated use createWithObligation()/createOrGetObligation() (the
     *             obligation-anchored transactional contract)
     */
    public function create(string $chainId, string $stage1Nonce, string $scope, int $ttlSecs, ?string $requestBinding = null, ?string $requiredAction = null, int $policyVersion = 1): void;

    /**
     * PLAIN read of the chain state (no transition, no mutation): the
     * full strictly-decoded v2 record or null when the chain is
     * absent/expired.
     *
     * @return array{stage1Nonce: string, scope: string, requestBinding: ?string, requiredAction: string, requiredRank: int, policyVersion: int, chainDepth: int, state: 'available'|'reserved'|'issued'|'verified'|'completed', owner: ?string, leaseUntil: ?int, stage2Nonce: ?string, obligationId: string, expiresAt: int}|null
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema (fail
     *                                                 closed — the caller
     *                                                 answers
     *                                                 temporary-unavailable)
     */
    public function read(string $chainId): ?array;

    /**
     * ATOMIC owner-scoped reservation with a SHORT lease
     * (reservation_lease_secs, bounded by the record's OWN remaining TTL
     * — KEEPTTL; a record without an expiry is corrupted state and
     * answers 'missing'). Outcomes:
     *
     *  - 'available'   this call reserved the chain — the caller proceeds,
     *  - 'retry'       already reserved by the SAME owner token — the
     *                  caller proceeds,
     *  - 'busy'        reserved by another owner with a LIVE lease — the
     *                  caller must NOT enter the issuance pipeline (the
     *                  retryable in-progress refusal),
     *  - 'taken_over'  reserved by another owner with an EXPIRED lease —
     *                  the chain is claimed with a fresh lease, the
     *                  caller proceeds,
     *  - 'issued'      the chain already issued a stage-2 challenge — the
     *                  caller recovers it instead of re-minting
     *                  ('completed' for legacy records — the historical
     *                  name of the same terminal state),
     *  - 'verified'    the chain is TERMINAL — the caller recovers the
     *                  issued challenge,
     *  - 'missing'     no state exists (never issued / expired / corrupt
     *                  without expiry).
     *
     * @param string $ownerToken random per-request owner token (16 bytes,
     *                           hex) — the ONLY handle that may release or
     *                           issue this reservation
     *
     * @deprecated use reserve() on the transactional contract (the
     *             short-lease machine with the same outcome set)
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
     * DEPRECATED legacy completion: reserved(owner) -> completed(
     * stage2Nonce) — the historical name of the terminal-with-nonce
     * state, semantically identical to the transactional contract's
     * markIssued() -> issued. The completed record keeps its TTL so a
     * retry can recover the issued challenge. Returns the completed
     * record, or null when the transition is refused (absent, not
     * reserved, not the owner — atomic no-op — or already terminal).
     *
     * @return array{stage1Nonce: string, scope: string, requestBinding: ?string, requiredAction: string, requiredRank: int, policyVersion: int, chainDepth: int, state: 'completed', owner: ?string, leaseUntil: ?int, stage2Nonce: string, obligationId: string, expiresAt: int}|null
     *
     * @deprecated use markIssued() on the transactional contract
     */
    public function complete(string $chainId, string $ownerToken, string $stage2Nonce): ?array;
}

/**
 * The open-chain REQUIREMENT of one transaction — the typed surface the
 * stage-2 issuance and the disposition layer consume. The state is the
 * machine state of the chain: available | reserved | issued | verified.
 * (Legacy 'completed' records — the historical name of the
 * terminal-with-nonce state — are reported as 'issued': semantically
 * identical.)
 */
final class ChainRequirement
{
    public function __construct(
        public readonly string $chainId,
        public readonly string $stage1Nonce,
        public readonly string $scope,
        /** The AUTHORITATIVE transaction binding ('' = the transaction is unbound). */
        public readonly string $requestBinding,
        public readonly int $policyVersion,
        public readonly RiskAction $requiredAction,
        public readonly int $requiredRank,
        /** Always 2 — the chain is a selective extension of depth 2. */
        public readonly int $chainDepth,
        /** available | reserved | issued | verified. */
        public readonly string $state,
        /** The issued stage-2 challenge nonce (issued/verified). */
        public readonly ?string $stage2Nonce,
        /** The reservation owner (reserved). */
        public readonly ?string $owner,
        /** The reservation lease deadline, unix seconds (reserved). */
        public readonly ?int $leaseUntil,
        public readonly int $expiresAt,
    ) {
    }
}

/**
 * The typed result of the owner-scoped reservation claim
 * ({@see TransactionalChainedChallengeStateStore::reserve()}) — never
 * magic strings at the consumer surface.
 */
enum ChainReservationResult: string
{
    /** This call reserved the chain (or took over an expired lease). */
    case Available = 'available';
    /** Already reserved by the SAME owner token. */
    case Retry = 'retry';
    /** Reserved by another owner with a LIVE lease — the in-progress 503. */
    case Busy = 'busy';
    /** Reserved by another owner with an EXPIRED lease — claimed by this call. */
    case TakenOver = 'taken_over';
    /** The chain already issued a stage-2 challenge — recover it. */
    case Issued = 'issued';
    /** The chain is TERMINAL — recover the issued challenge. */
    case Verified = 'verified';
    /** No state exists (never issued / expired). */
    case Missing = 'missing';
}

/**
 * The typed result of the idempotent issuance transition
 * ({@see TransactionalChainedChallengeStateStore::markIssued()}).
 */
enum ChainIssuedResult: string
{
    /** reserved(me) -> issued(stage2Nonce) — this call performed the transition. */
    case IssuedNew = 'issued_new';
    /** Already issued with the SAME nonce (a retry) — the issuance is confirmed. */
    case IssuedSame = 'issued_same';
    /** Already verified with the SAME nonce — the stage was durably issued. */
    case VerifiedSame = 'verified_same';
    /** Issued/verified with a DIFFERENT nonce — another issuance won the chain. */
    case Conflict = 'conflict';
    /** The chain is not reserved by this owner (or not reserved at all). */
    case NotOwner = 'not_owner';
    /** The chain state is absent/expired. */
    case Missing = 'missing';
}

/**
 * The typed result of the TERMINAL verification transition
 * ({@see TransactionalChainedChallengeStateStore::markVerified()}).
 */
enum ChainVerifiedResult: string
{
    /** issued(nonce) -> verified(nonce) — this call performed the transition. */
    case VerifiedNew = 'verified_new';
    /** Already verified with the SAME nonce (a retry) — the chain is confirmed terminal. */
    case VerifiedSame = 'verified_same';
    /** The chain holds a DIFFERENT nonce or is not in an issuable state. */
    case Conflict = 'conflict';
    /** The chain state is absent/expired. */
    case Missing = 'missing';
}
