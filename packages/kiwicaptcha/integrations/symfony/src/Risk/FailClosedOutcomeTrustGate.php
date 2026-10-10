<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The no-evidence fallback of the success-trust gate: without observed
 * authentication outcomes the gate cannot prove the identity is below
 * the failure threshold. Unproven means no session or source credit,
 * never silent credit: a credential stuffer with valid stolen
 * credentials must not farm source trust while the evidence is
 * unreadable. Deployments with the auth-outcome window wired bind the
 * data-backed {@see StoreBackedOutcomeTrustGate} instead; the principal
 * credit is unconditional and unaffected either way.
 */
final class FailClosedOutcomeTrustGate implements OutcomeTrustGateInterface
{
    public function allowsSessionSourceCredit(string $principalPseudonym, ?string $sessionPseudonym, ?string $targetPseudonym): bool
    {
        return false;
    }
}
