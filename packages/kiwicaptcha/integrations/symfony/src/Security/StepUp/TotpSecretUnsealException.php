<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * A stored time-based secret cannot be opened under the key of the
 * principal that owns the record. The blob was written before the
 * at-rest seal existed, the store is tampered, or the ciphertext was
 * copied across principals
 * (the seal key is bound to the principal pseudonym, so a cross-slot
 * transplant never decrypts). Thrown on the unseal path, fail-closed:
 * the handler maps it to a typed completion failure instead of an
 * uncaught error, and the account must re-enroll its passcode.
 */
final class TotpSecretUnsealException extends \RuntimeException
{
}
