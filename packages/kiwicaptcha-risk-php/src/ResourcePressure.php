<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * Resource pressure snapshot, all fixed-point 0..1000.
 *
 * - argonCapacity:   how much memory-hard PoW the backend can still serve
 * - issuanceCapacity: remaining challenge issuance headroom
 */
final class ResourcePressure
{
    public function __construct(
        public readonly int $argonCapacity,
        public readonly int $issuanceCapacity,
    ) {
        foreach ([$argonCapacity, $issuanceCapacity] as $value) {
            if ($value < 0 || $value > 1000) {
                throw new \InvalidArgumentException(
                    sprintf('Resource pressure values must be within 0..1000 (got %d)', $value)
                );
            }
        }
    }
}
