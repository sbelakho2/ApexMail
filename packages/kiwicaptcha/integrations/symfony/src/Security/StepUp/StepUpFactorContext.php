<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The completion history one factor resolution may build on: the
 * assurance family the subject's standing completion was proven with.
 *
 * The value comes from the completion plane (the completed-demand
 * marker of the store, or the session success marker of the principal
 * factors), never from the request. A null family means no completion
 * stands, so the resolution has no parent rung to escalate past. A
 * family outside the ladder is refused at construction, fail-closed:
 * an unproven history can never masquerade as a completed one.
 */
final class StepUpFactorContext
{
    public function __construct(
        public readonly ?string $completedFactorFamily = null,
    ) {
        if ($completedFactorFamily !== null && !FactorRequirement::isFamily($completedFactorFamily)) {
            throw new \InvalidArgumentException('The completed factor family of a step-up context must be a family of the assurance ladder');
        }
    }
}
