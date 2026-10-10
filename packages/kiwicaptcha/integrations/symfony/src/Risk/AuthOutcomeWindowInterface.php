<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The windowed authentication-outcome counter behind the success-trust
 * gate: per session identity, the bundle counts authentication failures
 * and successes inside a bounded window, so the gate can evaluate the
 * spec's rule with evidence it observes itself. The counts live beside
 * the risk state (the same Redis when one is configured; a bounded
 * in-memory map otherwise, documented as per-process for that case).
 */
interface AuthOutcomeWindowInterface
{
    /** Record one authentication failure for the session identity. */
    public function recordFailure(string $sessionPseudonym): void;

    /** Record one authentication success for the session identity. */
    public function recordSuccess(string $sessionPseudonym): void;

    /**
     * The failure ratio f / (f + s) over the window, or null when the
     * window is unreadable OR empty. An empty window is not a clean
     * history: the gate refuses credit so a brand-new identity never
     * earns trust from a single success (fail closed).
     */
    public function failureRatio(string $sessionPseudonym): ?float;
}
