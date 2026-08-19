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
 *   request (bounded, keyed to deployment + short epoch + session — never a
 *   stable device identifier). The engine compares it against the tag
 *   recorded for this session's FIRST tag-bearing request.
 * - clientContextConsistent: COMPUTED by the engine from the session's
 *   first-seen tag record (the risk-v2 session record, same TTL as the
 *   risk-v1 session state); callers pass the default and the derivation
 *   overwrites it.
 */
final class RiskV2Context
{
    public function __construct(
        public readonly bool $honeypotHit = false,
        public readonly ?string $clientContextTag = null,
        public readonly bool $clientContextConsistent = false,
    ) {
    }

    /** True when the context carries NO risk-v2 evidence at all. */
    public function isEmpty(): bool
    {
        return !$this->honeypotHit && $this->clientContextTag === null;
    }
}
