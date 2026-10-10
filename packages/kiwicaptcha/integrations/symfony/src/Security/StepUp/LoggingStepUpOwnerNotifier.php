<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Psr\Log\LoggerInterface;

/**
 * The default owner notification of the step-up lockout budget: one
 * warning line per armed lockout, carrying the budget dimension, the
 * pseudonym (never a raw identifier), the deadline and the failure
 * count. A deployment replaces this service to page a human; the log
 * hook is the floor every deployment gets.
 */
final class LoggingStepUpOwnerNotifier implements StepUpOwnerNotifier
{
    public function __construct(
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    public function notifyLockout(string $dimension, string $pseudonym, int $untilSecs, int $failures): void
    {
        $this->logger?->warning('KiwiCaptcha step-up lockout armed for the {dimension} budget (failures={failures}, until={until}); the owner should review the account for brute-force activity.', [
            'dimension' => $dimension,
            'pseudonym' => $pseudonym,
            'failures' => $failures,
            'until' => $untilSecs,
        ]);
    }

    public function notifyFactorEnrolled(string $principalPseudonym, string $factor, array $context = []): void
    {
        $this->logger?->warning('KiwiCaptcha second factor {factor} enrolled on an account; the owner should confirm this was intentional.', [
            'factor' => $factor,
            'pseudonym' => $principalPseudonym,
            'context' => $context,
        ]);
    }
}
