<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

/**
 * Optional risk-v2 capability of a risk state store: records the
 * session's first-seen trusted-edge TLS classification tag and returns
 * the recorded tag.
 *
 * This is a separate capability interface so third-party implementations
 * of the 1.x RiskStateStoreInterface keep compiling unchanged. A store
 * that does not implement it has no record surface, and the engine
 * degrades the tls-inconsistency signal to neutral (consistent), the
 * exact backend-miss semantics.
 */
interface SessionTlsTagStoreInterface
{
    /**
     * The risk-v2 session trusted-edge TLS record: records $tag as the
     * session's first-seen TLS classification tag (SET NX, first write
     * wins) and returns the recorded tag — the first coarse, server-
     * attested TLS classification (e.g. "tls13|http2", supplied only by
     * trusted proxy/CDN infrastructure) the session ever presented, or
     * null when the store has no record surface.
     *
     * The record is keyed by the session's HMAC pseudonym (never the raw
     * cookie value) and expires with the same TTL as the risk-v1 session
     * state. The engine derives the tls_inconsistency signal by comparing
     * the current request's tag against the returned first tag; null /
     * backend failure degrade to "consistent" (neutral), never breaking an
     * assessment. Only the ephemeral classification is stored — never a
     * raw fingerprint database. The Rust mirror names the record
     * `session_first_tls_tag`.
     *
     * @throws RiskStoreException when the underlying state backend fails
     */
    public function sessionFirstTlsTag(string $sessionId, string $tag): ?string;
}
