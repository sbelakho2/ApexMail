<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The TRANSACTIONAL chained-challenge state contract — the stronger,
 * obligation-anchored machine behind selective chained challenges.
 *
 * Extends the (deprecated) {@see ChainedChallengeStateStore} surface with
 * the v2 transaction model:
 *
 *  - every chain is created WITH its obligation mapping
 *    ({kiwi:<ns>}:chain-obligation:<obligationId> -> chainId — the same
 *    hash tag as the chain record, same TTL) in ONE atomic operation, so
 *    a client can never restart the transaction at stage 1 by discarding
 *    the ticket;
 *  - the state machine is available -> reserved(owner, short lease) ->
 *    issued(stage2Nonce) with THREE disposition-aware TERMINAL
 *    transitions: verified(stage2Nonce) — the PASS transition that
 *    atomically clears the obligation mapping — and the
 *    step_up_required(stage2Nonce) / denied(stage2Nonce) transitions
 *    that KEEP the obligation mapping (the transaction stays bound to
 *    its final disposition, so a later challenge request for the same
 *    transaction re-encounters the terminal state — never a new
 *    stage-1);
 *  - TWO NONCE-AGNOSTIC TRANSACTION-LEVEL terminal transitions
 *    (markTransactionDenied() / markTransactionStepUpRequired()) make
 *    the terminality DURABLE even when the Deny/StepUp arises from a
 *    DIFFERENT verified nonce of the obligated transaction (never the
 *    exact stage-2 nonce): the open obligation becomes terminal —
 *    atomically, keyed by the chain/obligation identity — with the
 *    obligation mapping KEPT; the terminal states carry an OPTIONAL
 *    stage-2 nonce (the exact nonce when one was issued, null
 *    otherwise). The terminalization is OBLIGATION-BOUND: it takes the
 *    transaction's obligation id and the transition runs over BOTH keys
 *    (the chain record + the obligation mapping, one hash tag) — the
 *    mapping must STILL point at the chain AND the record must STILL
 *    agree on the obligation id, or the transition is refused
 *    ('obligation_moved' — a stale chain whose obligation moved can
 *    never be terminalized);
 *  - rearmIssued() returns an issued chain to the available state for a
 *    FRESH stage-2 mint (pinned to the exact expected nonce — never a
 *    stage-1 downgrade);
 *  - every record is decoded ALL-OR-NOTHING against the strict v2 schema
 *    (a malformed SERVER record throws
 *    {@see MalformedChainedChallengeStateException} — fail closed, never
 *    a defaulted chain);
 *  - the result strings of the transitions are the documented outcome
 *    values (typed enums at the ticket-service surface).
 *
 * Redis and the in-memory store implement the SAME contract (identical
 * decode, identical outcomes), so tests and production observe one
 * machine.
 */
interface TransactionalChainedChallengeStateStore extends ChainedChallengeStateStore
{
    /**
     * ATOMIC create-or-get over the chain + obligation keys (ONE Lua
     * script, both keys in the same hash tag):
     *
     *  - no obligation mapping -> create the chain (state available, v2
     *    schema) + the obligation (same TTL) and return the NEW chain id;
     *  - the obligation exists -> return the EXISTING chain id; when the
     *    existing record's requiredRank is LOWER than the new
     *    reassessment it is RAISED (with the required action — never
     *    lowered);
     *  - the obligation points at a missing/corrupt chain record ->
     *    COMPARE-DELETE the stale mapping and create the chain fresh in
     *    the same script (the retry is inside the atomic script — a stale
     *    mapping can never block a transaction).
     *
     * @param string $obligationId the bounded pseudonymous transaction
     *                             obligation id (exact 64 lowercase hex)
     * @param string $requiredAction the reassessed chainable PoW action
     *                               (Sha16..Argon64)
     * @param int    $requiredRank   its monotonic rank
     * @param int    $expiresAt      the absolute chain expiry (unix
     *                               seconds — the signed ticket expiry)
     * @param int    $ttlSecs        the record/obligation lifetime
     *
     * @return string the chain id of the transaction's chain
     *
     * @throws \InvalidArgumentException on an invalid obligation id shape
     * @throws \Throwable                on backend failure — the caller
     *                                   fails closed (a transaction can
     *                                   never be silently downgraded to
     *                                   stage 1)
     */
    public function createOrGetObligation(string $obligationId, string $chainId, string $stage1Nonce, string $scope, string $requestBinding, string $requiredAction, int $requiredRank, int $policyVersion, int $expiresAt, int $ttlSecs): string;

    /**
     * Create the chain state + its obligation mapping in the AVAILABLE
     * state with the given lifetime (one atomic operation — no chain
     * exists without its obligation). An existing obligation for the id
     * is left untouched (use createOrGetObligation for the
     * create-or-get semantics).
     *
     * @param string|null $requestBinding the authoritative transaction
     *                                    binding (null = unbound)
     *
     * @throws \InvalidArgumentException on an invalid obligation id shape
     */
    public function createWithObligation(string $chainId, string $obligationId, string $stage1Nonce, string $scope, ?string $requestBinding, string $requiredAction, int $policyVersion, int $ttlSecs): void;

    /**
     * The chain id behind a transaction obligation, or null when the
     * obligation is absent/expired.
     */
    public function obligationChainId(string $obligationId): ?string;

    /**
     * ATOMIC owner-scoped reservation with a SHORT lease: the lease is
     * min(reservation-lease, the record's OWN remaining TTL) computed
     * from the server clock (redis TIME on the Redis side, the explicit
     * clock on the array side) — the whole record expires with the
     * signed ticket, so the lease can never outlive the chain. A chain
     * record WITHOUT an expiry is CORRUPTED state and answers 'missing'
     * (fail closed — never manufacture a lifetime from the configured
     * TTL).
     *
     * Outcome values: 'available' | 'retry' | 'busy' | 'taken_over' |
     * 'issued' | 'verified' | 'step_up_required' | 'denied' | 'missing'
     * (plus the legacy 'completed' for records written by the deprecated
     * complete() path — the historical name of the issued state). See the
     * parent interface for the per-outcome semantics.
     *
     * @param string $ownerToken random per-request owner token (16 bytes,
     *                           hex) — the ONLY handle that may release or
     *                           issue this reservation
     * @param int    $leaseSecs  the SHORT reservation lease
     *                           (risk.chaining.reservation_lease_secs,
     *                           bounded by the record's own remaining TTL)
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema (fail
     *                                                 closed)
     */
    public function reserve(string $chainId, string $ownerToken, int $leaseSecs): string;

    /**
     * ATOMIC idempotent issuance transition (reserved(me) ->
     * issued(stage2Nonce), KEEPTTL — a state TRANSITION, never a delete;
     * the issued record lets a retry RECOVER the already-issued challenge
     * instead of re-minting). Outcomes:
     *
     *  - 'issued_new'    this call performed the transition,
     *  - 'issued_same'   already issued with the SAME nonce — confirmed,
     *  - 'verified_same' already verified with the SAME nonce — the
     *                    issuance is durably confirmed,
     *  - 'conflict'      issued/terminal with a DIFFERENT nonce — another
     *                    issuance (or a terminal transition) won the
     *                    chain,
     *  - 'not_owner'     not reserved by this owner (or not reserved at
     *                    all) — an atomic no-op,
     *  - 'missing'       the chain state is absent/expired.
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema (fail
     *                                                 closed)
     */
    public function markIssued(string $chainId, string $ownerToken, string $stage2Nonce): string;

    /**
     * ATOMIC TERMINAL verification: issued(stage2Nonce) ->
     * verified(stage2Nonce) (KEEPTTL — the terminal record is kept until
     * its TTL), ATOMICALLY deleting the obligation mapping ONLY if it
     * still points at this chainId (a re-created chain of the same
     * transaction must never be unlinked by a stale delete). Outcomes:
     *
     *  - 'verified_new'  this call performed the transition,
     *  - 'verified_same' already verified with the SAME nonce — confirmed
     *                    terminal,
     *  - 'conflict'      the chain holds a DIFFERENT nonce or is not in
     *                    an issuable state — an atomic no-op,
     *  - 'missing'       the chain state is absent/expired.
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema (fail
     *                                                 closed)
     */
    public function markVerified(string $chainId, string $stage2Nonce): string;

    /**
     * ATOMIC TERMINAL step-up transition: issued(stage2Nonce) ->
     * step_up_required(stage2Nonce) (KEEPTTL — the terminal record is
     * kept until its TTL). The obligation mapping is KEPT: the
     * transaction stays bound to the step-up requirement, so a later
     * challenge request for the same transaction re-encounters the
     * terminal state (never a new stage-1). Outcomes:
     *
     *  - 'step_up_required_new'  this call performed the transition,
     *  - 'step_up_required_same' already step_up_required with the SAME
     *                            nonce — confirmed terminal,
     *  - 'conflict'              the chain holds a DIFFERENT nonce or is
     *                            not in an issuable state — an atomic
     *                            no-op,
     *  - 'missing'               the chain state is absent/expired.
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema (fail
     *                                                 closed)
     */
    public function markStepUpRequired(string $chainId, string $stage2Nonce): string;

    /**
     * ATOMIC TERMINAL denial transition: issued(stage2Nonce) ->
     * denied(stage2Nonce) (KEEPTTL — the terminal record is kept until
     * its TTL). The obligation mapping is KEPT: the transaction stays
     * bound to its final denial, so a later challenge request for the
     * same transaction re-encounters the terminal state (never a new
     * stage-1). Outcomes:
     *
     *  - 'denied_new'  this call performed the transition,
     *  - 'denied_same' already denied with the SAME nonce — confirmed
     *                  terminal,
     *  - 'conflict'    the chain holds a DIFFERENT nonce or is not in an
     *                  issuable state — an atomic no-op,
     *  - 'missing'     the chain state is absent/expired.
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema (fail
     *                                                 closed)
     */
    public function markDenied(string $chainId, string $stage2Nonce): string;

    /**
     * ATOMIC OBLIGATION-BOUND NONCE-AGNOSTIC TRANSACTION terminalization:
     * an OPEN obligation (state available|reserved|issued|completed) ->
     * denied (KEEPTTL — the record keeps its OWN remaining TTL; the
     * obligation mapping is KEPT, the chainId and the original expiry
     * are preserved). The stage2Nonce field is PRESERVED: the exact
     * stage-2 nonce when one exists (issued/completed), null otherwise
     * (available/reserved) — the terminal state carries an OPTIONAL
     * stage-2 nonce. The transition is ATOMIC over BOTH keys (the chain
     * record + the obligation mapping, one hash tag): the chain record
     * must STILL agree on the obligation id AND the obligation mapping
     * must STILL point at this chain — otherwise the transaction's chain
     * moved and nothing is transitioned (fail closed). Outcomes:
     *
     *  - 'denied_new'        this call performed the transition,
     *  - 'denied_same'       already denied — idempotent (no state
     *                        change),
     *  - 'conflict'          the chain is terminal with the OTHER
     *                        disposition (step_up_required) — a terminal
     *                        state can never be reopened or flipped,
     *  - 'already_verified'  the chain is already verified — the
     *                        transaction already ended via Pass (its
     *                        obligation is gone): there is no chain left
     *                        to terminalize (defensive — the fresh Deny
     *                        applies to the nonce alone),
     *  - 'already_completed' the obligation mapping is GONE while the
     *                        chain record survives — the transaction
     *                        already ended (the obligation is deleted
     *                        atomically at verification): there is no
     *                        chain left to terminalize,
     *  - 'obligation_moved'  the obligation mapping points at a
     *                        DIFFERENT chain (or the record does not
     *                        agree on the obligation id) — the
     *                        transaction's chain is no longer this one:
     *                        NOTHING is transitioned (fail closed — the
     *                        caller re-reads the requirement and
     *                        terminalizes the CURRENT chain),
     *  - 'missing'           the chain state is absent/expired.
     *
     * RACE SEMANTICS (the Lua script is the single writer): the
     * terminalization WINS against an in-flight reservation (a reserve
     * on the terminalized chain answers the terminal result
     * 'denied') and against an in-flight issuance (a markIssued on the
     * terminalized chain answers 'conflict'); against markVerified the
     * FIRST writer wins (verified -> 'already_completed' with the
     * obligation already gone; terminal -> markVerified 'conflict').
     *
     * @param string $obligationId the transaction's obligation id (the
     *                             exact 64-lowercase-hex id the chain was
     *                             created under — the obligation key the
     *                             transition verifies)
     *
     * @throws \InvalidArgumentException on an invalid obligation id shape
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema (fail
     *                                                 closed)
     */
    public function markTransactionDenied(string $chainId, string $obligationId): string;

    /**
     * ATOMIC OBLIGATION-BOUND NONCE-AGNOSTIC TRANSACTION terminalization:
     * an OPEN obligation (state available|reserved|issued|completed) ->
     * step_up_required (KEEPTTL — the record keeps its OWN remaining
     * TTL; the obligation mapping is KEPT, the chainId and the original
     * expiry are preserved). The stage2Nonce field is PRESERVED: the
     * exact stage-2 nonce when one exists (issued/completed), null
     * otherwise (available/reserved) — the terminal state carries an
     * OPTIONAL stage-2 nonce. The transition is ATOMIC over BOTH keys
     * (the chain record + the obligation mapping, one hash tag): the
     * chain record must STILL agree on the obligation id AND the
     * obligation mapping must STILL point at this chain — otherwise the
     * transaction's chain moved and nothing is transitioned (fail
     * closed). Outcomes:
     *
     *  - 'step_up_required_new'  this call performed the transition,
     *  - 'step_up_required_same' already step_up_required — idempotent
     *                            (no state change),
     *  - 'conflict'              the chain is terminal with the OTHER
     *                            disposition (denied) — a terminal
     *                            state can never be reopened or
     *                            flipped,
     *  - 'already_verified'      the chain is already verified — the
     *                            transaction already ended via Pass (its
     *                            obligation is gone): there is no chain
     *                            left to terminalize (defensive — the
     *                            fresh StepUp applies to the nonce
     *                            alone),
     *  - 'already_completed'     the obligation mapping is GONE while
     *                            the chain record survives — the
     *                            transaction already ended: there is no
     *                            chain left to terminalize,
     *  - 'obligation_moved'      the obligation mapping points at a
     *                            DIFFERENT chain (or the record does not
     *                            agree on the obligation id) — the
     *                            transaction's chain is no longer this
     *                            one: NOTHING is transitioned (fail
     *                            closed),
     *  - 'missing'               the chain state is absent/expired.
     *
     * RACE SEMANTICS (the Lua script is the single writer): the
     * terminalization WINS against an in-flight reservation (a reserve
     * on the terminalized chain answers the terminal result
     * 'step_up_required') and against an in-flight issuance (a
     * markIssued on the terminalized chain answers 'conflict'); against
     * markVerified the FIRST writer wins (verified ->
     * 'already_completed' with the obligation already gone; terminal ->
     * markVerified 'conflict').
     *
     * @param string $obligationId the transaction's obligation id (the
     *                             exact 64-lowercase-hex id the chain was
     *                             created under — the obligation key the
     *                             transition verifies)
     *
     * @throws \InvalidArgumentException on an invalid obligation id shape
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema (fail
     *                                                 closed)
     */
    public function markTransactionStepUpRequired(string $chainId, string $obligationId): string;

    /**
     * ATOMIC rearm of an ISSUED chain: issued(expectedStage2Nonce) ->
     * available (the reservation fields and the stage2Nonce are cleared,
     * KEEPTTL) — the controller then reserves + mints a NEW stage-2
     * challenge at the SAME OR STRONGER floor (NEVER a stage-1). A
     * different nonce (or any other state) is an atomic no-op (false).
     */
    public function rearmIssued(string $chainId, string $expectedStage2Nonce): bool;

    /**
     * Compare-delete the obligation mapping ONLY if it still points at
     * this chainId (a re-created chain of the same transaction must never
     * be unlinked by a stale delete).
     */
    public function deleteObligation(string $chainId, string $obligationId): void;
}
