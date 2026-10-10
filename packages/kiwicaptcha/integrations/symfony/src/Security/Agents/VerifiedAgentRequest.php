<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\Agents;

use KiwiCaptcha\ChallengeProfile;
use KiwiCaptcha\Risk\Outcomes\OutcomeHandle;

/**
 * A request that verified as a configured agent: the definition it
 * authenticated as, plus the attribution identity derived from it.
 * The controller prices the issuance at the agent's tier and marks
 * the response as machine-client (no widget eligibility), and every
 * outcome or mark the request produces addresses
 * {@see self::outcomeHandle()}.
 */
final class VerifiedAgentRequest
{
    public function __construct(
        private readonly AgentDefinition $agent,
        private readonly string $signatureLabel,
    ) {
    }

    public function definition(): AgentDefinition
    {
        return $this->agent;
    }

    public function name(): string
    {
        return $this->agent->name;
    }

    public function priceTier(): AgentPriceTier
    {
        return $this->agent->priceTier;
    }

    /** The interim tier price, see {@see AgentPriceTier::challengeProfile()}. */
    public function priceProfile(): ChallengeProfile
    {
        return $this->agent->priceTier->challengeProfile();
    }

    /** The attribution handle: the agent dimension of the outcomes plane. */
    public function outcomeHandle(): OutcomeHandle
    {
        return $this->agent->outcomeHandle();
    }

    /** The Signature-Input label that carried the verified signature. */
    public function signatureLabel(): string
    {
        return $this->signatureLabel;
    }
}
