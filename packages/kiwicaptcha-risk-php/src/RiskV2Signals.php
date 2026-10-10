<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * The additive risk-v2 signal fields (each 0..1000), in a fixed order.
 *
 * These are a separate surface from the 13 risk-v1 contract fields. They
 * are derived from the risk-v2 context (honeypot evidence, session
 * client-context consistency, trusted-edge TLS consistency) at assessment
 * time and never mutate the risk-v1 state script or the v1 SignalVector.
 * Both crates use the identical field names and fixed-point semantics
 * (Rust mirror: honeypot, session_inconsistency, tls_inconsistency).
 *
 * There is deliberately no execution-evidence field. Execution traces
 * and digests are forgeable without a browser by a full-knowledge
 * forger. The v6 envelopes are public functions of the shipped
 * operands. See WhiteBoxEnvelopeForger, pass rate 1.0. They are never
 * weighted as proof of a real browser anywhere in the risk engine.
 */
final class RiskV2Signals
{
    public function __construct(
        /** Honeypot/decoy evidence: 1000 when ANY honeypot event kind fired or the context reported a honeypot hit, 0 otherwise. */
        public readonly int $honeypot = 0,
        /** Session client-context inconsistency: 1000 when the session's first-seen client-context tag differs from the current request's tag, 0 when consistent or when no tag exists (first request / absent). */
        public readonly int $sessionInconsistency = 0,
        /** Trusted-edge TLS inconsistency: 1000 when the session's first-seen TLS classification tag differs from the current request's tag, 0 when consistent or when no tag exists (first request / absent / unbounded value). */
        public readonly int $tlsInconsistency = 0,
        /** Target-account authentication-failure pressure, normalized against the attack threshold. */
        public readonly int $targetFailurePressure = 0,
        /** Wider of the distinct-source and distinct-ASN spreads of
         * failures against the target, normalized (never the sum). */
        public readonly int $targetSpread = 0,
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
        return new self(0, 0, 0, 0, 0);
    }

    public function isZero(): bool
    {
        return $this->honeypot === 0 && $this->sessionInconsistency === 0 && $this->tlsInconsistency === 0
            && $this->targetFailurePressure === 0 && $this->targetSpread === 0;
    }
}
