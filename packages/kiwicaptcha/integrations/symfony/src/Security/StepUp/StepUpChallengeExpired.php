<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The expired-challenge marker of the handlers' ticket resolution: a
 * well-signed ticket whose own expiry has passed resolves to this
 * marker so the completion answers the expired failure code instead of
 * a bare unknown. A unit type; the single instance is the marker.
 */
final class StepUpChallengeExpired
{
    private static ?StepUpChallengeExpired $marker = null;

    private function __construct()
    {
    }

    public static function marker(): self
    {
        return self::$marker ??= new self();
    }
}
