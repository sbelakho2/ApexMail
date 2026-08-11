<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

/**
 * Thrown when the Argon2id verification concurrency cap is reached and no
 * slot frees up within the semaphore's wait window. Fail closed: the caller
 * must reject the submission (the validator turns this into a violation).
 */
final class VerificationCapacityExceededException extends \RuntimeException
{
}
