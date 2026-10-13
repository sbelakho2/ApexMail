<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * Resolves the delivery address of a principal for the email
 * one-time-passcode factor. The bundle never assumes the principal's
 * identifier is the address: a username-based account resolves its
 * address through this seam, so the factor can still deliver a code.
 *
 * The default resolution ({@see MailerStepUpCodeSender}) reads a
 * conventional `getEmail()` accessor from the user object and falls
 * back to an email-shaped identifier. An application with its own
 * user model binds its own implementation of this interface as the
 * `risk.step_up.email_resolver` service.
 */
interface PrincipalEmailResolverInterface
{
    /**
     * The delivery address of the principal, or null when none is
     * resolvable (the caller then refuses the delivery, fail-closed).
     *
     * @param object|string|null $user the authenticated user object
     *                                  (or its identifier string) of
     *                                  the principal stepping up
     */
    public function resolveEmail(object|string|null $user): ?string;
}
