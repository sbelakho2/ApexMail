<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\Risk\RiskDecision;

/**
 * The post-credential, pre-session decision seam: one assessment with
 * the AuthenticationSuccess event and the resolved principal id. The
 * first-attempt login guard calls this so the engine's
 * firstAttemptEvidence can demand a step-up before the session is
 * granted. Separated from the concrete gateway so the guard is
 * testable and so a deployment can swap the implementation.
 */
interface LoginDecisionGate
{
    public function loginDecision(string $scope, string $ip, ?string $session = null, ?string $principal = null, ?string $idempotencyKey = null): ?RiskDecision;
}
