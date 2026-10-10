<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The owner notification of the step-up lockout budget: called
 * whenever a principal or target lockout is armed or extended, with
 * the budget dimension, the pseudonym (never a raw identifier), the
 * deadline and the windowed failure count. The default binding is the
 * logging hook ({@see LoggingStepUpOwnerNotifier}); a deployment
 * replaces the service to page a human on call.
 */
interface StepUpOwnerNotifier
{
    /**
     * @param string $dimension  "principal" or "target"
     * @param string $pseudonym  the canonical pseudonym of that dimension
     * @param int    $untilSecs  the lockout deadline, epoch seconds
     * @param int    $failures   the windowed failure count that escalated
     */
    public function notifyLockout(string $dimension, string $pseudonym, int $untilSecs, int $failures): void;

    /**
     * Out-of-band owner notification whenever a second factor is
     * enrolled or replaced on an account.
     *
     * @param array<string, mixed> $context
     */
    public function notifyFactorEnrolled(string $principalPseudonym, string $factor, array $context = []): void;
}
