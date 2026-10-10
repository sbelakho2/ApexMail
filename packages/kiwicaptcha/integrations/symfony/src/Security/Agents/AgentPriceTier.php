<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\Agents;

use KiwiCaptcha\ChallengeProfile;

/**
 * The pricing tier of a configured verified agent
 * (risk.agents.<name>.price_tier).
 *
 * The tier selects the proof-of-work rung a verified agent is issued
 * and billed at, independent of the adaptive risk ladder: a signed
 * machine client never passes through the browser-oriented risk
 * assessment, so its price comes from the configuration alone.
 */
enum AgentPriceTier: string
{
    case Low = 'low';
    case Standard = 'standard';
    case High = 'high';
    case Critical = 'critical';

    /**
     * The interim tier pricing: this bundle-side mapping from the
     * configured tier to a challenge rung. A dedicated pricing stage
     * in the risk cores may land later and will supersede this
     * mapping. Until then this is the documented price of a tier:
     *
     *  - low: SHA-256 at 16 leading zero bits.
     *  - standard: SHA-256 at 18 leading zero bits.
     *  - high: SHA-256 at 20 leading zero bits.
     *  - critical: Argon2id, the fixed 16 MiB envelope, t=3, p=1.
     *
     * The rung is issued exactly as the tier names it, never clamped
     * to the deployment's widget baseline. The tier is the price the
     * operator quoted the agent, so the solver pays exactly that.
     */
    public function challengeProfile(): ChallengeProfile
    {
        return match ($this) {
            self::Low => ChallengeProfile::sha(16),
            self::Standard => ChallengeProfile::sha(18),
            self::High => ChallengeProfile::sha(20),
            self::Critical => ChallengeProfile::argon16(),
        };
    }
}
