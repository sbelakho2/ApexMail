<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * Server-held state of a chained-challenge chain: the stage-1 challenge
 * nonce (the verified proof that opened the chain), the scope, the
 * stage-1 request binding and the REQUIRED next action, keyed by the
 * random chain id that the signed chain ticket carries.
 *
 * The state is CREATED atomically with ticket issuance (the ticket signs
 * the same chain id + stage-1 nonce + scope + binding + required action)
 * and driven through an atomic THREE-STATE machine at the stage-2
 * issuance:
 *
 *   available --reserve()--> reserved --consume()--> (deleted)
 *       ^                        |
 *       +--------release()-------+
 *
 *  - reserve() transitions available -> reserved and is IDEMPOTENT for the
 *    same chain id (a retry with the same ticket re-enters the reserved
 *    state and re-attempts issuance). The reservation inherits the chain
 *    TTL, so an abandoned reservation evaporates with the ticket.
 *  - consume() is the ATOMIC one-shot completion (GET + DEL): it runs only
 *    after the stage-2 issuance is DURABLY complete, so a ticket is
 *    spent exactly when the challenge it paid for was really handed out.
 *  - release() undoes a reservation (reserved -> available) on any refused
 *    or failed issuance: the ticket stays reusable — the chain is not
 *    burned by a later failure.
 *
 * The one-shot invariant is unchanged: a consumed chain id can never gate
 * a second issuance, and a client cannot skip stages by replaying a
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
     * by the service's own random generation.
     *
     * @param string|null $requestBinding the stage-1 challenge's signed
     *                                    request binding (null when the
     *                                    challenge had none)
     * @param string|null $requiredAction the reassessed RiskAction's value
     *                                    the chain must satisfy at stage 2
     *
     * @throws \Throwable on backend failure — the caller fails closed
     *                    (no ticket without a server-held chain state)
     */
    public function create(string $chainId, string $stage1Nonce, string $scope, int $ttlSecs, ?string $requestBinding = null, ?string $requiredAction = null): void;

    /**
     * ATOMIC reservation transition: available -> reserved (the record
     * keeps its TTL). Idempotent for the same chain id: a retry of the
     * same ticket while reserved re-enters the reserved state (the
     * issuance is re-attempted, never refused by its own reservation).
     *
     * @return 'available'|'reserved'|'consumed'|'missing' — the transition
     *         outcome: 'available' when THIS call reserved the chain,
     *         'reserved' when it was already reserved (retry), 'consumed'
     *         when the chain was already spent (a replayed ticket), and
     *         'missing' when no state exists (never issued / expired)
     */
    public function reserve(string $chainId, int $ttlSecs): string;

    /**
     * ATOMIC one-shot completion: GET + DEL of the chain state — at most
     * ONE consumer ever wins a chain id, and only the reserved/available
     * state can be consumed. Returns the state
     * ({stage1Nonce, scope, requestBinding, requiredAction}) or null when
     * absent/already consumed.
     *
     * @return array{stage1Nonce: string, scope: string, requestBinding: ?string, requiredAction: ?string}|null
     */
    public function consume(string $chainId): ?array;

    /**
     * Release a reservation: reserved -> available (the record keeps its
     * TTL). Called by the reservation holder's retry path after a refused
     * or failed issuance — the ticket is reusable, the chain is not
     * burned. No-op when the chain is not reserved.
     */
    public function release(string $chainId): void;
}
