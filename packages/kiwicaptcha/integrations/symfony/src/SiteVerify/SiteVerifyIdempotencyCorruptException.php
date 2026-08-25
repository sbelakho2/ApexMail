<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * The idempotency record exists but is malformed or structurally
 * inconsistent (undecodable JSON, a non-object envelope, a completed
 * record without a result). Security state that cannot be interpreted is
 * NEVER transformed into "nothing here": the caller maps this typed
 * exception to the retryable 503, never to a fresh claim and never to a
 * default.
 */
final class SiteVerifyIdempotencyCorruptException extends \RuntimeException
{
}
