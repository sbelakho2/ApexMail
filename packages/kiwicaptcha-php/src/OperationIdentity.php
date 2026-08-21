<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * The logical-operation identity validation contract shared by every
 * storage implementing {@see OperationIdentityAwareStorageInterface}:
 * Redis, PSR-6 and the array backend all route the identity through this
 * single seam, so a malformed identity is rejected identically
 * everywhere; it is never silently dropped. A caller that believes the
 * recovery identity was recorded while the consume stored null would
 * violate the deterministic-recovery contract (a later takeover could
 * never prove the operation), so the identity is validated before the
 * transition can execute.
 *
 * The alphabet is narrow because the identity is JSON-encoded and
 * spliced into the Redis consume Lua's `string.gsub` replacement
 * string. In a Lua replacement string `%` is the template escape: `%1`,
 * `%b` and the
 * other `%x` forms are interpreted by gsub, so an arbitrary string
 * would be a replacement-template hazard. The validated alphabet
 * `[A-Za-z0-9_-]` excludes `%` and every other gsub-special character
 * by construction, which makes the raw splice safe without a replacement
 * function. Hex fingerprints, base64url, UUIDs and HMAC digests all fit
 * the alphabet; the bound (1..128 bytes) matches the stored-record
 * identifier ceiling.
 */
final class OperationIdentity
{
    /**
     * The only accepted shape: 1..128 bytes of the identifier alphabet.
     * The `/D` anchor makes the regex fail on a trailing newline, so a
     * 128-char identity cannot smuggle a 129th byte.
     */
    private const PATTERN = '/^[A-Za-z0-9_-]{1,128}$/D';

    /**
     * Validate a caller-supplied operation identity. Null, the plain
     * consume path used by every native caller, passes through unchanged
     * and records no identity. Anything non-null that is not a non-empty
     * string of `[A-Za-z0-9_-]`, 1..128 bytes, is rejected with
     * \InvalidArgumentException before the pending→consumed transition.
     * The record is left untouched, and the caller can retry with a valid
     * identity.
     *
     * @throws \InvalidArgumentException when a non-null identity is
     *                                   malformed (empty, over-long, or
     *                                   outside the narrow alphabet)
     */
    public static function validate(?string $operationIdentity): ?string
    {
        if ($operationIdentity === null) {
            return null;
        }
        if (\preg_match(self::PATTERN, $operationIdentity) !== 1) {
            throw new \InvalidArgumentException(
                'operation identity must be 1..128 bytes of [A-Za-z0-9_-]'
            );
        }

        return $operationIdentity;
    }
}
