<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * Thrown (only when risk.reject_ambiguous_forwarding is true) when a
 * TRUSTED peer sends BOTH X-Forwarded-For AND Forwarded: the two headers
 * can disagree, so the canonical client IP is ambiguous and the request is
 * rejected (HTTP 400 AMBIGUOUS_FORWARDING on the challenge endpoint).
 * From an UNTRUSTED peer both headers are ignored entirely — never
 * ambiguous, never an anomaly.
 */
final class AmbiguousForwardingException extends \RuntimeException
{
}
