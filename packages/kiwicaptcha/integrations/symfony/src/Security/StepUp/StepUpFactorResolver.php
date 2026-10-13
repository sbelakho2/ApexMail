<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use KiwiCaptcha\Risk\RiskDecision;

/**
 * The source of "which factor does this step-up demand require". The
 * risk decision names the action (a step-up stands) but carries no
 * factor, so the required factor has exactly one authority: this
 * resolver, from the deployment's configured factor and the subject's
 * completion history.
 *
 * The base requirement is the scope's configured factor, falling back
 * to the plane's default handler. The child rule sits on top: a demand
 * minted after a completed one must name a strictly stronger family
 * than the completed factor, so one session cannot satisfy every
 * demand with its weakest proven factor. When the ladder offers no
 * higher rung (webauthn completed), the child stays on the completed
 * rank, since no escalation is available. The requirement the resolver
 * answers is a snapshot: the demand stores it, and later completions
 * are judged against the stored record, never against the request.
 */
final class StepUpFactorResolver
{
    /**
     * @param string $defaultHandler the plane's default handler name
     *                               (a family of the ladder)
     * @param array<string, string> $factorByScope scope name to the
     *                               required family, for a deployment
     *                               that demands a stronger factor on
     *                               one scope; absent entries use the
     *                               default handler
     */
    public function __construct(
        private readonly string $defaultHandler,
        private readonly array $factorByScope = [],
    ) {
        if (!FactorRequirement::isFamily($defaultHandler)) {
            throw new \InvalidArgumentException('The default step-up handler must name a family of the assurance ladder');
        }
        foreach ($factorByScope as $scope => $family) {
            if (!\is_string($scope) || $scope === '' || !\is_string($family) || !FactorRequirement::isFamily($family)) {
                throw new \InvalidArgumentException('The per-scope factor map must name a ladder family for every non-empty scope');
            }
        }
    }

    /**
     * The factor the demand under this scope requires. The decision is
     * the reason a demand stands at all; the resolver is the only
     * source of which factor answers it. A decision therefore carries
     * no factor of its own, and a null decision (a caller that holds
     * only the decision id) resolves the same requirement.
     */
    public function requiredFactor(string $scope, ?RiskDecision $decision, StepUpFactorContext $context): FactorRequirement
    {
        $base = $this->baseOf($scope);
        $completed = $context->completedFactorFamily;
        if ($completed === null) {
            return $base;
        }
        $parentRank = FactorRequirement::rankOf($completed);
        if ($parentRank < 1) {
            return $base;
        }
        $escalation = null;
        foreach (FactorRequirement::LADDER as $family => $rank) {
            if ($rank > $parentRank && ($escalation === null || $rank < $escalation[1])) {
                $escalation = [$family, $rank];
            }
        }
        if ($escalation === null) {
            // No higher rung exists: the child stays on the completed
            // rank, never weaker than the factor already proven.
            if ($base->assuranceRank >= $parentRank) {
                return $base;
            }

            return new FactorRequirement($completed, $completed, $parentRank);
        }
        if ($escalation[1] >= $base->assuranceRank) {
            return new FactorRequirement($escalation[0], $escalation[0], $escalation[1]);
        }

        // The configured floor is already above the escalation rung:
        // the child demands the configured factor, which is strictly
        // stronger than the parent's completion on its own.
        return $base;
    }

    private function baseOf(string $scope): FactorRequirement
    {
        $family = $this->factorByScope[$scope] ?? null;
        if (!\is_string($family) || !FactorRequirement::isFamily($family)) {
            $family = $this->defaultHandler;
        }

        return new FactorRequirement($family, $family, FactorRequirement::rankOf($family));
    }
}
