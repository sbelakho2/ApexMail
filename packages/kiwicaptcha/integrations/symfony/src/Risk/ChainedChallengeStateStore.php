<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * Server-held state of a chained-challenge chain: the stage-1 challenge
 * nonce (the verified proof that opened the chain) plus the scope, keyed
 * by the random chain id that the signed chain ticket carries.
 *
 * The state is CREATED atomically with ticket issuance (the ticket signs
 * the same chain id + stage-1 nonce + scope) and CONSUMED atomically at
 * the stage-2 issuance — a ticket is one-shot: the same chain id can
 * never gate two issuances, and a client cannot skip stages by replaying
 * a consumed chain. The state TTL equals the chain lifetime
 * (risk.chaining.ttl_secs), so an unused chain evaporates with its
 * ticket.
 */
interface ChainedChallengeStateStore
{
    /**
     * Persist the chain state with the given lifetime. The chain id is
     * random (16 bytes, base64url) and minted by the ticket service, so
     * the key namespace is attacker-unbounded only by the service's own
     * random generation.
     *
     * @throws \Throwable on backend failure — the caller fails closed
     *                    (no ticket without a server-held chain state)
     */
    public function create(string $chainId, string $stage1Nonce, string $scope, int $ttlSecs): void;

    /**
     * ATOMIC one-shot read+delete of the chain state: at most ONE
     * consumer ever wins a chain id. Returns the state
     * ({stage1Nonce, scope}) or null when absent/expired/already
     * consumed.
     *
     * @return array{stage1Nonce: string, scope: string}|null
     */
    public function consume(string $chainId): ?array;
}
