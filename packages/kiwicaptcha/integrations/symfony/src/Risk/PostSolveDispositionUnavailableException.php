<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The final disposition cannot be resolved durably: the store is
 * unavailable, the claim is busy, the finalize was refused, or the chain
 * obligation could not be cleared. The validator fails closed with the
 * retryable temporary_unavailable violation — never a silent pass.
 */
final class PostSolveDispositionUnavailableException extends \RuntimeException
{
}
