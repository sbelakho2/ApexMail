<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * The 3 ADDITIVE risk-v2 weight fields, same names/order as RiskV2Signals.
 *
 * The risk-v1 contract weights (RiskWeights) are untouched — these are a
 * separate, additive surface with identical fixed-point semantics. DEFAULT
 * weights are byte-identical with the Rust mirror.
 */
final class RiskV2Weights
{
    /** Weight of the honeypot/decoy evidence signal (one hit raises the aggregate meaningfully without hard-denying alone). */
    public const DEFAULT_HONEYPOT = 200;
    /** Weight of the session client-context inconsistency signal (a changed context tag raises the aggregate; a consistent or absent tag is neutral). */
    public const DEFAULT_SESSION_INCONSISTENCY = 120;
    /** Weight of the trusted-edge TLS inconsistency signal (a changed TLS classification tag raises the aggregate; a consistent or absent tag is neutral). */
    public const DEFAULT_TLS = 80;

    public function __construct(
        public readonly int $honeypot = self::DEFAULT_HONEYPOT,
        public readonly int $sessionInconsistency = self::DEFAULT_SESSION_INCONSISTENCY,
        public readonly int $tls = self::DEFAULT_TLS,
    ) {
        foreach (get_object_vars($this) as $value) {
            if ($value < 0 || $value > 1000) {
                throw new \InvalidArgumentException(
                    sprintf('Risk-v2 weight values must be within 0..1000 (got %d)', $value)
                );
            }
        }
    }

    /** Snake_case keys in field order. */
    public function toArray(): array
    {
        return [
            'honeypot' => $this->honeypot,
            'session_inconsistency' => $this->sessionInconsistency,
            'tls' => $this->tls,
        ];
    }
}
