<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Pricing;

/**
 * The per-request pricing inputs a deployment resolves: the value class
 * of the protected action and the session's raw bucket-trust credit in
 * its current ASN bucket (0..=10000, the trust plane's raw scale).
 */
final class PriceInputs
{
    public function __construct(
        public readonly ValueClass $valueClass,
        public readonly int $bucketTrust,
    ) {
        if ($bucketTrust < 0) {
            throw new \InvalidArgumentException('bucket trust must not be negative');
        }
    }

    /**
     * The fail-closed inputs for an unreadable pricing surface: a
     * standard-value request with zero bucket credit, so the pressure
     * gate treats the identity as unproven and the full ramp applies.
     * The price may still only raise the composed action.
     */
    public static function failClosed(): self
    {
        return new self(valueClass: ValueClass::Standard, bucketTrust: 0);
    }
}
