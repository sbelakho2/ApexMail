<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The handler family a challenge record belongs to. String-backed so
 * the persisted wire format is stable and machine-readable.
 */
enum StepUpChallengeKind: string
{
    case EmailOtp = 'email_otp';
    case Totp = 'totp';
    case WebAuthn = 'webauthn';
    /** The anonymous email-ownership challenge of the step_up_email carrier. */
    case EmailOwnership = 'email_ownership';
}
