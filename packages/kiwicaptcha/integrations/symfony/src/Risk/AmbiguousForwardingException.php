<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * Thrown (only when risk.reject_ambiguous_forwarding is true) when a
 * trusted peer sends both X-Forwarded-For and Forwarded: the two headers
 * can disagree, so the canonical client IP is ambiguous and the request
 * is rejected (HTTP 400 AMBIGUOUS_FORWARDING on the challenge endpoint).
 * From an untrusted peer both headers are ignored entirely, never
 * ambiguous, never an anomaly.
 */
final class AmbiguousForwardingException extends \RuntimeException
{
}
