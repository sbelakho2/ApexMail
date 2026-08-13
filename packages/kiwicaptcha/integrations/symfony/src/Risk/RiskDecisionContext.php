<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * Request-local holder for the risk decision id of the current request.
 *
 * The RiskGateway sets it on every pre-issue and post-solve decision, so the
 * application can read the decision id that governs the current request
 * (e.g. to pair a later ConfirmedLegitimate / ConfirmedAbuse signal back to
 * the ORIGINAL decision). The value is per-request in practice: the gateway
 * overwrites it on each decision, and cross-request pairing goes through the
 * short-lived nonce -> decision mapping ({@see RiskGateway::attachDecisionForNonce()}),
 * never through this holder.
 */
final class RiskDecisionContext
{
    private ?string $decisionId = null;

    /** Record the decision id of the current request's decision. */
    public function set(string $decisionId): void
    {
        $this->decisionId = $decisionId;
    }

    /** The decision id of the current request's decision, or null when the
     * risk engine was not consulted (yet). */
    public function current(): ?string
    {
        return $this->decisionId;
    }
}
