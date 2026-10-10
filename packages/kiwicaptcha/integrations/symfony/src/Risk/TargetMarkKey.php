<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The ONE spelling boundary between the canonical target pseudonym
 * and the outcomes API's target handle id.
 *
 * The canonical target pseudonym is the engine's full 32-byte digest:
 * 64 lowercase hex characters, exactly what
 * {@see \KiwiCaptcha\Risk\RiskIdentityFactory::targetId()} derives and
 * what every step-up context, challenge record and trust-gate call
 * carries. The outcomes API addresses target marks under the 128-bit
 * family shape (32 lowercase hex chars).
 * {@see \KiwiCaptcha\Risk\Outcomes\OutcomeHandle::target()} enforces
 * that spelling, and the mark keys follow the handle id. Every mark
 * write and every mark read for a target projects the canonical
 * pseudonym through this single function. Nothing "tries 64 then falls
 * back to 32" anymore: a target is 64 hex everywhere above this class,
 * and 32 hex only inside the handle/mark key this class derives.
 */
final class TargetMarkKey
{
    /** The canonical target pseudonym: the full 32-byte digest, 64 hex chars. */
    public const PSEUDONYM_PATTERN = '/^[0-9a-f]{64}$/D';

    /** The derived mark/handle key: the leading 128 bits, 32 hex chars. */
    public const MARK_KEY_PATTERN = '/^[0-9a-f]{32}$/D';

    /**
     * The mark/handle key of a canonical target pseudonym: its leading
     * 128 bits. The projection is total and deterministic — the same
     * target always maps to the same key, and a non-canonical input is
     * refused rather than truncated blindly.
     *
     * @throws \InvalidArgumentException when the value is not the 64-hex canonical pseudonym
     */
    public static function of(string $targetPseudonym): string
    {
        if (preg_match(self::PSEUDONYM_PATTERN, $targetPseudonym) !== 1) {
            throw new \InvalidArgumentException(
                'The target pseudonym must be the 64-char lowercase hex digest (32 bytes), never a raw identifier or a truncated form',
            );
        }

        return substr($targetPseudonym, 0, 32);
    }
}
