<?php

declare (strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

/**
 * Optional capability: the principal's first-seen network tag records.
 * One record per principal and network-bucket pair, written with SET NX.
 * This mirrors the Rust `PrincipalNetworkTagStore` trait.
 *
 * The record marks a network bucket as established for the principal
 * (written when the session credit is granted, a completed step-up from
 * that network), so a bare password check never vouches for the network
 * and a retried stuffed login stays novel until the victim really proves
 * themselves. Stores without the surface report `null` on every read and
 * the engine degrades the novel-network gate to neutral (never novel),
 * never breaking an assessment.
 */
interface PrincipalNetworkTagStoreInterface
{
    /**
     * Whether the principal has been seen (established) from this
     * network bucket: `true` = seen before, `false` = never seen (the
     * first-attempt novel-network signal), `null` = no record surface
     * (neutral: never novel).
     *
     * @throws RiskStoreException when the state backend fails
     */
    public function principalNetworkSeen (string $principalId, string $network): ?bool;

    /**
     * Records the first-seen network tag for the (principal, network)
     * pair (SET NX, first write wins). Called when a session credit is
     * granted for a login from this network. Answers whether the record
     * was newly created.
     *
     * @throws RiskStoreException when the state backend fails
     */
    public function recordPrincipalNetworkTag (string $principalId, string $network): bool;

    /**
     * Whether the account carries ANY established network: the "no
     * prior trusted network" half of the novel-network gate.
     * `true` = the account has a trusted network, `false` = none,
     * `null` = no record surface.
     *
     * @throws RiskStoreException when the state backend fails
     */
    public function principalHasTrustedNetwork (string $principalId): ?bool;
}
