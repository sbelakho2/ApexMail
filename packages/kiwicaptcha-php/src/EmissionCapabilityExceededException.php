<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Issuance was asked to arm a protocol extension beyond the confirmed
 * emission capability: the caller requested work the configured fleet
 * has not been confirmed to read. The request fails explicitly instead
 * of being silently downgraded, so an integration can never believe it
 * armed a dimension that was actually dropped.
 *
 * The one documented fallback is the rsw modulus identity. Requesting
 * it below {@see ChallengeRecord::RSW_IDENTITY_PROTOCOL_VERSION} emits
 * the identityless legacy base shape. The identity is additive signing
 * metadata with a defined backward-compatible form, unlike the decoy
 * or execution segments, which change the wire grammar the reader must
 * understand.
 */
final class EmissionCapabilityExceededException extends \RuntimeException
{
}
