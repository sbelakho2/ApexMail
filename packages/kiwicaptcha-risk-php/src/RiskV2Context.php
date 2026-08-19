<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * The ADDITIVE risk-v2 context surface: probabilistic evidence that feeds
 * the scorer but is NEVER a security gate and NEVER mutates the risk-v1
 * state contract.
 *
 * - honeypotHit: true when ANY honeypot/decoy evidence fired
 *   (RiskEventKind::isHoneypot() kinds, or a decoy marker observed by the
 *   caller). The engine maps it to the bounded `honeypot` signal.
 * - clientContextTag: the ephemeral coarse capability tag of the current
 *   request (bounded, keyed to deployment + session — never a stable
 *   device identifier, stable for the session's whole lifetime). The
 *   engine compares it against the tag recorded for this session's FIRST
 *   tag-bearing request.
 * - tlsTag: the COARSE, server-attested TLS classification tag supplied by
 *   trusted reverse-proxy/CDN infrastructure (e.g. "tls13|http2") — never
 *   a raw fingerprint database. The engine records only the ephemeral
 *   classification as the session's first-seen tag and compares the
 *   current request's tag against it; values over 64 chars are treated as
 *   absent by the consuming engine (bounded).
 */
final class RiskV2Context
{
    public function __construct(
        public readonly bool $honeypotHit = false,
        public readonly ?string $clientContextTag = null,
        public readonly ?string $tlsTag = null,
    ) {
    }

    /** True when the context carries NO risk-v2 evidence at all. */
    public function isEmpty(): bool
    {
        return !$this->honeypotHit && $this->clientContextTag === null && $this->tlsTag === null;
    }
}
