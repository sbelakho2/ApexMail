<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

/**
 * OPTIONAL risk-v2 capability of a risk state store: records the session's
 * FIRST-seen client-context tag and returns the recorded tag.
 *
 * This is a separate capability interface so third-party implementations
 * of the 1.x RiskStateStoreInterface keep compiling unchanged: a store
 * that does not implement it has no record surface, and the engine
 * degrades the session-consistency signal to neutral (consistent) —
 * exactly the backend-miss semantics.
 */
interface SessionContextTagStoreInterface
{
    /**
     * The risk-v2 session client-context record: records $tag as the
     * session's FIRST-seen client-context tag (SET NX, first write wins)
     * and returns the recorded tag — the first tag the session ever
     * presented, or null when the store has no record surface.
     *
     * The record is keyed by the session's HMAC pseudonym (never the raw
     * cookie value) and expires with the SAME TTL as the risk-v1 session
     * state. The engine derives the session_consistency signal by
     * comparing the current request's tag against the returned first tag;
     * null / backend failure degrade to "consistent" (neutral), never
     * breaking an assessment.
     *
     * @throws RiskStoreException when the underlying state backend fails
     */
    public function sessionFirstContextTag(string $sessionId, string $tag): ?string;
}
