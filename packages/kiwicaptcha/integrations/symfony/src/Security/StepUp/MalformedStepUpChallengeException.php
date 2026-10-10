<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * A persisted step-up challenge record violates the strict schema.
 * Thrown on the read path of a store, fail-closed: a corrupt record is
 * never healed into a verifiable challenge.
 */
final class MalformedStepUpChallengeException extends \RuntimeException
{
}
