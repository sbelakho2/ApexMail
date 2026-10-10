<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * The additive risk-v2 context surface: probabilistic evidence that
 * feeds the scorer but is never a security gate and never mutates the
 * risk-v1 state contract.
 *
 * - honeypotHit: true when any honeypot/decoy evidence fired, e.g. the
 *   RiskEventKind::isHoneypot() kinds or a decoy marker observed by the
 *   caller. The engine maps it to the bounded `honeypot` signal.
 * - clientContextTag: the ephemeral coarse capability tag of the current
 *   request (bounded to 64 bytes, keyed to deployment + session, never a
 *   stable device identifier and stable for the session's whole lifetime).
 *   The engine compares it against the tag recorded for this session's
 *   first tag-bearing request; a longer tag rejects the assessment input
 *   (never a silent truncation, which would split one session's identity
 *   across tag records).
 * - tlsTag: the coarse, server-attested TLS classification tag supplied
 *   by trusted reverse-proxy/CDN infrastructure (e.g. "tls13|http2"),
 *   never a raw fingerprint database. The engine records only the
 *   ephemeral classification as the session's first-seen tag and
 *   compares the current request's tag against it; values over 64
 *   chars are treated as absent by the consuming engine (bounded).
 * - telemetryPayload: the raw telemetry-v1 payload text from the
 *   solution token (protocol/telemetry-v1/payload.json). The engine
 *   parses it per the schema; a rejected or over-bound payload is the
 *   neutral-unknown state, never a negative signal.
 * - solveMs and solveRung: the solved challenge's client-reported
 *   duration and issued rung key (the client-performance difficulty
 *   key). They ride together or not at all; a half-present pair rejects
 *   the assessment input.
 */
final class RiskV2Context
{
    /** The contract bound on the risk-v2 session tag strings (bytes),
     * shared with Rust: assess_v2.lua rejects longer tags as the last
     * line of defense, and the engines reject the assessment input up
     * front. */
    public const MAX_TAG_BYTES = 64;
    /** The contract bound on the telemetry payload string (bytes),
     * shared with Rust: an over-bound payload rejects the assessment
     * input up front (the published schema is
     * protocol/telemetry-v1/payload.json). */
    public const MAX_TELEMETRY_PAYLOAD_BYTES = Evidence\TelemetryPayloadV1::MAX_PAYLOAD_BYTES;
    public function __construct(
        public readonly bool $honeypotHit = false,
        public readonly ?string $clientContextTag = null,
        public readonly ?string $tlsTag = null,
        public readonly ?string $telemetryPayload = null,
        public readonly ?int $solveMs = null,
        public readonly ?string $solveRung = null,
        public readonly bool $breachedCredential = false,
    ) {
    }

    /** True when the context carries NO risk-v2 evidence at all. */
    public function isEmpty(): bool
    {
        return !$this->honeypotHit
            && $this->clientContextTag === null
            && $this->tlsTag === null
            && $this->telemetryPayload === null
            && $this->solveMs === null
            && $this->solveRung === null
            && !$this->breachedCredential;
    }
}
