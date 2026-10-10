<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The data-backed success-trust gate: an authentication success credits
 * the session and the source dimensions only when the identity's
 * windowed failure ratio sits below the configured threshold AND the
 * presented target carries no live long-memory mark. Both reads come
 * from the deployment's own evidence: the window counts the auth
 * outcomes the bridge observes, and the mark read goes through the
 * risk store's canonical marks surface. Any unreadable input refuses
 * the credit (fail closed), and the principal credit is unconditional
 * and unaffected.
 */
final class StoreBackedOutcomeTrustGate implements OutcomeTrustGateInterface
{
    /**
     * @param AuthOutcomeWindowInterface   $window         the observed-outcome counter
     * @param TargetMarkProbe|\Closure|null $targetMarkRead callable(string $targetPseudonym): bool — true when a live mark exists
     * @param float                        $theta          the failure-ratio ceiling
     */
    public function __construct(
        private readonly AuthOutcomeWindowInterface $window,
        private readonly TargetMarkProbe|\Closure|null $targetMarkRead = null,
        private readonly float $theta = 0.05,
    ) {
    }

    public function allowsSessionSourceCredit(string $principalPseudonym, ?string $sessionPseudonym, ?string $targetPseudonym): bool
    {
        if ($sessionPseudonym === null || $sessionPseudonym === '') {
            return false;
        }
        // Both the session and the principal must carry a readable,
        // clean history. A brand-new session (no window) earns nothing
        // from one success, and a principal whose other sessions are
        // failing never earns credit here.
        $ratio = $this->window->failureRatio($sessionPseudonym);
        if ($ratio === null || $ratio >= $this->theta) {
            return false;
        }
        $principalRatio = $this->window->failureRatio($principalPseudonym);
        if ($principalRatio === null || $principalRatio >= $this->theta) {
            return false;
        }
        if ($targetPseudonym !== null && $targetPseudonym !== '' && $this->targetMarkRead !== null) {
            try {
                if (($this->targetMarkRead)($targetPseudonym) === true) {
                    // A target under attack never earns the attacker-side
                    // session any credit from this success.
                    return false;
                }
            } catch (\Throwable) {
                return false;
            }
        }

        return true;
    }
}
