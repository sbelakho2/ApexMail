<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * The ADDITIVE risk-v2 signal fields (each 0..1000), in a fixed order.
 *
 * These are a separate surface from the 13 risk-v1 contract fields: they
 * are derived from the risk-v2 context (honeypot evidence, session
 * client-context consistency) at assessment time and NEVER mutate the
 * risk-v1 state script or the v1 SignalVector. Both crates use the
 * identical field names and fixed-point semantics.
 */
final class RiskV2Signals
{
    public function __construct(
        /** Honeypot/decoy evidence: 1000 when ANY honeypot event kind fired or the context reported a honeypot hit, 0 otherwise. */
        public readonly int $honeypot = 0,
        /** Session client-context inconsistency: 1000 when the session's first-seen client-context tag differs from the current request's tag, 0 when consistent or when no tag exists (first request / absent). */
        public readonly int $sessionInconsistency = 0,
    ) {
        foreach (get_object_vars($this) as $value) {
            if ($value < 0 || $value > 1000) {
                throw new \InvalidArgumentException(
                    sprintf('Risk-v2 signal values must be within 0..1000 (got %d)', $value)
                );
            }
        }
    }

    /** All-zero vector (no risk-v2 evidence). */
    public static function zero(): self
    {
        return new self(0, 0);
    }

    public function isZero(): bool
    {
        return $this->honeypot === 0 && $this->sessionInconsistency === 0;
    }
}
