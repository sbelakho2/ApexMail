<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The transactional chained-challenge state contract: the stronger,
 * obligation-anchored machine behind selective chained challenges.
 *
 * Extends the (deprecated) {@see ChainedChallengeStateStore} surface with
 * the v2 transaction model:
 *
 *  - every chain is created with its obligation mapping
 *    ({kiwi:<ns>}:chain-obligation:<obligationId> -> chainId, the same
 *    hash tag as the chain record, same TTL) in one atomic operation. A
 *    client can never restart the transaction at stage 1 by discarding
 *    the ticket.
 *  - The state machine is available -> reserved(owner, short lease) ->
 *    issued(stage2Nonce), with three disposition-aware terminal
 *    transitions. verified(stage2Nonce) is the Pass transition that
 *    atomically clears the obligation mapping. The
 *    step_up_required(stage2Nonce) and denied(stage2Nonce) transitions
 *    keep the obligation mapping, so the transaction stays bound to its
 *    final disposition and a later challenge request re-encounters the
 *    terminal state (never a new stage-1).
 *  - Two nonce-agnostic transaction-level terminal transitions,
 *    markTransactionDenied() and markTransactionStepUpRequired(), make
 *    the terminality durable even when the Deny or StepUp arises from a
 *    different verified nonce of the obligated transaction. The
 *    terminalization is obligation-bound: it takes the transaction's
 *    obligation id and runs over both keys (the chain record plus the
 *    obligation mapping, one hash tag). The mapping must still point at
 *    the chain and the record must still agree on the obligation id, or
 *    the transition is refused with 'obligation_moved'. The terminal
 *    states carry an optional stage-2 nonce.
 *  - rearmIssued() returns an issued chain to the available state for a
 *    fresh stage-2 mint (pinned to the exact expected nonce, never a
 *    stage-1 downgrade).
 *  - Every record is decoded all-or-nothing against the strict v2 schema.
 *    A malformed server record throws
 *    {@see MalformedChainedChallengeStateException} (fail closed, never
 *    a defaulted chain).
 *  - The transition result strings are the documented outcome values
 *    (typed enums at the ticket-service surface).
 *
 * Redis and the in-memory store implement the same contract (identical
 * decode, identical outcomes), so tests and production observe one
 * machine.
 */
interface TransactionalChainedChallengeStateStore extends ChainedChallengeStateStore
{
    /**
     * Atomic create-or-get over the chain + obligation keys (one Lua
     * script, both keys in the same hash tag):
     *
     *  - no obligation mapping -> create the chain (state available, v2
     *    schema) plus the obligation (same TTL) and return the new id.
     *  - The obligation exists -> return the existing chain id. When the
     *    existing record's requiredRank is lower than the new reassessment
     *    it is raised (with the required action, never lowered).
     *  - The obligation points at a missing or corrupt chain record ->
     *    compare-delete the stale mapping and create the chain fresh in
     *    the same script, so a stale mapping can never block a
     *    transaction.
     *
     * @param string $obligationId the bounded pseudonymous transaction
     *                             obligation id (exact 64 lowercase hex).
     * @param string $requiredAction the reassessed chainable PoW action
     *                               (Sha16..Argon64).
     * @param int    $requiredRank   its monotonic rank.
     * @param int    $expiresAt      the absolute chain expiry (unix
     *                               seconds; the signed ticket expiry).
     * @param int    $ttlSecs        the record/obligation lifetime.
     *
     * @return string the chain id of the transaction's chain.
     *
     * @throws \InvalidArgumentException on an invalid obligation id shape.
     * @throws \Throwable                on backend failure: the caller
     *                                   fails closed (a transaction can
     *                                   never be silently downgraded to
     *                                   stage 1).
     */
    public function createOrGetObligation(string $obligationId, string $chainId, string $stage1Nonce, string $scope, string $requestBinding, string $requiredAction, int $requiredRank, int $policyVersion, int $expiresAt, int $ttlSecs): string;

    /**
     * Create the chain state and its obligation mapping in the available
     * state with the given lifetime (one atomic operation; no chain
     * exists without its obligation). An existing obligation for the id
     * is left untouched (use createOrGetObligation for the create-or-get
     * semantics).
     *
     * @param string|null $requestBinding the authoritative transaction
     *                                    binding (null = unbound).
     *
     * @throws \InvalidArgumentException on an invalid obligation id shape.
     */
    public function createWithObligation(string $chainId, string $obligationId, string $stage1Nonce, string $scope, ?string $requestBinding, string $requiredAction, int $policyVersion, int $ttlSecs): void;

    /**
     * The chain id behind a transaction obligation, or null when the
     * obligation is absent/expired.
     */
    public function obligationChainId(string $obligationId): ?string;

    /**
     * Atomic owner-scoped reservation with a short lease: the lease is
     * min(reservation-lease, the record's own remaining TTL) computed
     * from the server clock (redis TIME on the Redis side, the explicit
     * clock on the array side). The lease can never outlive the chain. A
     * chain record without an expiry is corrupted state and answers
     * 'missing' (fail closed; never manufacture a lifetime from the
     * configured TTL).
     *
     * Outcome values: 'available' | 'retry' | 'busy' | 'taken_over' |
     * 'issued' | 'verified' | 'step_up_required' | 'denied' | 'missing',
     * plus the legacy 'completed' for records written by the deprecated
     * complete() path (the historical name of the issued state). See the
     * parent interface for the per-outcome semantics.
     *
     * @param string $ownerToken random per-request owner token (16 bytes,
     *                           hex). The only handle that may release or
     *                           issue this reservation.
     * @param int    $leaseSecs  the short reservation lease
     *                           (risk.chaining.reservation_lease_secs,
     *                           bounded by the record's own remaining
     *                           TTL).
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema (fail
     *                                                 closed).
     */
    public function reserve(string $chainId, string $ownerToken, int $leaseSecs): string;

    /**
     * Atomic idempotent issuance transition, reserved(me) ->
     * issued(stage2Nonce), KEEPTTL. A state transition, never a delete,
     * so a retry can recover the already-issued challenge instead of
     * re-minting. Outcomes:
     *
     *  - 'issued_new'    this call performed the transition.
     *  - 'issued_same'   already issued with the same nonce, confirmed.
     *  - 'verified_same' already verified with the same nonce, so the
     *                    issuance is durably confirmed.
     *  - 'conflict'      issued or terminal with a different nonce:
     *                    another issuance (or a terminal transition) won
     *                    the chain.
     *  - 'not_owner'     not reserved by this owner (or not reserved at
     *                    all), an atomic no-op.
     *  - 'missing'       the chain state is absent or expired.
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema (fail
     *                                                 closed).
     */
    public function markIssued(string $chainId, string $ownerToken, string $stage2Nonce): string;

    /**
     * Atomic terminal verification, issued(stage2Nonce) ->
     * verified(stage2Nonce), KEEPTTL (the terminal record is kept until
     * its TTL). The obligation mapping is deleted atomically only if it
     * still points at this chainId, so a re-created chain of the same
     * transaction is never unlinked by a stale delete. Outcomes:
     *
     *  - 'verified_new'  this call performed the transition.
     *  - 'verified_same' already verified with the same nonce, confirmed
     *                    terminal.
     *  - 'conflict'      the chain holds a different nonce or is not in
     *                    an issuable state, an atomic no-op.
     *  - 'missing'       the chain state is absent or expired.
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema (fail
     *                                                 closed).
     */
    public function markVerified(string $chainId, string $stage2Nonce): string;

    /**
     * Atomic terminal step-up transition, issued(stage2Nonce) ->
     * step_up_required(stage2Nonce), KEEPTTL. The obligation mapping is
     * kept, so the transaction stays bound to the step-up requirement and
     * a later challenge request re-encounters the terminal state (never
     * a new stage-1). Outcomes:
     *
     *  - 'step_up_required_new'  this call performed the transition.
     *  - 'step_up_required_same' already step_up_required with the same
     *                            nonce, confirmed terminal.
     *  - 'conflict'              the chain holds a different nonce or is
     *                            not in an issuable state, an atomic
     *                            no-op.
     *  - 'missing'               the chain state is absent or expired.
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema (fail
     *                                                 closed).
     */
    public function markStepUpRequired(string $chainId, string $stage2Nonce): string;

    /**
     * Atomic terminal denial transition, issued(stage2Nonce) ->
     * denied(stage2Nonce), KEEPTTL. The obligation mapping is kept, so
     * the transaction stays bound to its final denial and a later
     * challenge request re-encounters the terminal state (never a new
     * stage-1). Outcomes:
     *
     *  - 'denied_new'  this call performed the transition.
     *  - 'denied_same' already denied with the same nonce, confirmed
     *                  terminal.
     *  - 'conflict'    the chain holds a different nonce or is not in an
     *                  issuable state, an atomic no-op.
     *  - 'missing'     the chain state is absent or expired.
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema (fail
     *                                                 closed).
     */
    public function markDenied(string $chainId, string $stage2Nonce): string;

    /**
     * Atomic obligation-bound, nonce-agnostic transaction
     * terminalization: an open obligation (state available|reserved|
     * issued|completed) -> denied, KEEPTTL. The record keeps its own
     * remaining TTL; the obligation mapping is kept, and the chainId and
     * original expiry are preserved. The stage2Nonce field is preserved:
     * the exact stage-2 nonce when one exists, null otherwise. The
     * transition is atomic over both keys (the chain record plus the
     * obligation mapping, one hash tag). The chain record must still
     * agree on the obligation id and the obligation mapping must still
     * point at this chain, otherwise the transaction's chain moved and
     * nothing is transitioned (fail closed). Outcomes:
     *
     *  - 'denied_new'        this call performed the transition.
     *  - 'denied_same'       already denied, idempotent.
     *  - 'conflict'          the chain is terminal with the other
     *                        disposition (step_up_required). A terminal
     *                        state can never be reopened or flipped.
     *  - 'already_verified'  the chain is already verified: the
     *                        transaction already ended via Pass and its
     *                        obligation is gone, so there is no chain
     *                        left to terminalize.
     *  - 'already_completed' the obligation mapping is gone while the
     *                        chain record survives: the transaction
     *                        already ended.
     *  - 'obligation_moved'  the obligation mapping points at a
     *                        different chain (or the record does not
     *                        agree on the obligation id). The
     *                        transaction's chain is no longer this one,
     *                        so nothing is transitioned; the caller
     *                        re-reads the requirement and terminalizes
     *                        the current chain.
     *  - 'missing'           the chain state is absent or expired.
     *
     * Race semantics (the Lua script is the single writer): the
     * terminalization wins against an in-flight reservation (a reserve
     * on the terminalized chain answers the terminal result 'denied')
     * and against an in-flight issuance (a markIssued on the terminalized
     * chain answers 'conflict'). Against markVerified the first writer
     * wins (verified -> 'already_completed' with the obligation already
     * gone; terminal -> markVerified 'conflict').
     *
     * @param string $obligationId the transaction's obligation id (the
     *                             exact 64-lowercase-hex id the chain was
     *                             created under; the obligation key the
     *                             transition verifies).
     *
     * @throws \InvalidArgumentException on an invalid obligation id shape.
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema (fail
     *                                                 closed).
     */
    public function markTransactionDenied(string $chainId, string $obligationId): string;

    /**
     * Atomic obligation-bound, nonce-agnostic transaction
     * terminalization: an open obligation (state available|reserved|
     * issued|completed) -> step_up_required, KEEPTTL. The record keeps
     * its own remaining TTL; the obligation mapping is kept, and the
     * chainId and original expiry are preserved. The stage2Nonce field
     * is preserved: the exact stage-2 nonce when one exists, null
     * otherwise. The transition is atomic over both keys (the chain
     * record plus the obligation mapping, one hash tag). The chain
     * record must still agree on the obligation id and the obligation
     * mapping must still point at this chain, otherwise the transaction's
     * chain moved and nothing is transitioned (fail closed). Outcomes:
     *
     *  - 'step_up_required_new'  this call performed the transition.
     *  - 'step_up_required_same' already step_up_required, idempotent.
     *  - 'conflict'              the chain is terminal with the other
     *                            disposition (denied). A terminal state
     *                            can never be reopened or flipped.
     *  - 'already_verified'      the chain is already verified: the
     *                            transaction already ended via Pass and
     *                            its obligation is gone, so there is no
     *                            chain left to terminalize.
     *  - 'already_completed'     the obligation mapping is gone while
     *                            the chain record survives: the
     *                            transaction already ended.
     *  - 'obligation_moved'      the obligation mapping points at a
     *                            different chain (or the record does not
     *                            agree on the obligation id). The
     *                            transaction's chain is no longer this
     *                            one, so nothing is transitioned.
     *  - 'missing'               the chain state is absent or expired.
     *
     * Race semantics (the Lua script is the single writer): the
     * terminalization wins against an in-flight reservation (a reserve
     * on the terminalized chain answers the terminal result
     * 'step_up_required') and against an in-flight issuance (a
     * markIssued on the terminalized chain answers 'conflict'). Against
     * markVerified the first writer wins (verified ->
     * 'already_completed' with the obligation already gone; terminal ->
     * markVerified 'conflict').
     *
     * @param string $obligationId the transaction's obligation id (the
     *                             exact 64-lowercase-hex id the chain was
     *                             created under; the obligation key the
     *                             transition verifies).
     *
     * @throws \InvalidArgumentException on an invalid obligation id shape.
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema (fail
     *                                                 closed).
     */
    public function markTransactionStepUpRequired(string $chainId, string $obligationId): string;

    /**
     * Atomic rearm of an issued chain: issued(expectedStage2Nonce) ->
     * available (the reservation fields and the stage2Nonce are cleared,
     * KEEPTTL), so the controller then reserves and mints a new stage-2
     * challenge at the same or stronger floor, never a stage-1. A
     * different nonce (or any other state) is an atomic no-op (false).
     */
    public function rearmIssued(string $chainId, string $expectedStage2Nonce): bool;

    /**
     * Compare-delete the obligation mapping only if it still points at
     * this chainId (a re-created chain of the same transaction must never
     * be unlinked by a stale delete).
     */
    public function deleteObligation(string $chainId, string $obligationId): void;
}
