<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * Ephemeral coarse client-context tag for the risk-v2 session-consistency
 * signal.
 *
 * The tag is a bounded base36 string over ~10 bits derived from a small
 * capability descriptor ({@see ClientContextTag::derive()}) — deliberately
 * coarse: no canvas/audio/font-list/GPU fingerprinting, no stable device
 * identifier. The derivation is KEYED to the deployment namespace and the
 * continuity session, so the same capability combination yields a different
 * tag per deployment and per session: the tag can never be used to
 * correlate a device across deployments or sessions. The tag is STABLE for
 * the whole lifetime of one continuity session — the session's first tag
 * is the comparison baseline — so a session created just before an hour
 * boundary is not flagged as inconsistent at the next request. The engine
 * only ever compares tags WITHIN one session to detect a CHANGED coarse
 * context (an inconsistency signal) — a changed tag is probabilistic risk
 * evidence, never a security gate.
 *
 * Privacy contract: the descriptor is the coarse, bounded capability string
 * the widget reports (viewport class, touch capability, language family,
 * timezone offset class); the tag is its keyed hash — never a raw
 * fingerprint, never the descriptor itself. The session is a fresh random
 * per-session identity, so the tag is already fresh per session — removing
 * the hourly epoch from the derivation does not link requests across
 * sessions.
 */
final class ClientContextTag
{
    /** Tag width: 10 bits -> 1024 distinct tags per session. */
    public const BITS = 10;

    private const BASE36 = '0123456789abcdefghijklmnopqrstuvwxyz';

    /**
     * Derives the bounded tag: base36 of the TOP `BITS` bits of
     * sha256(deployment | session | descriptor).
     *
     * Deterministic within (deployment, session, descriptor) — there is NO
     * time input, so the tag is identical whenever it is computed for the
     * same continuity session and the same coarse capabilities: the
     * session's FIRST tag stays the baseline for its whole lifetime.
     * Changing the session or the descriptor produces a different tag.
     */
    public static function derive(string $deployment, string $session, string $descriptor): string
    {
        $digest = hash('sha256', $deployment.'|'.$session.'|'.$descriptor, true);
        $bits = ((ord($digest[0]) << 2) | (ord($digest[1]) >> 6)) & 0x3FF;

        return self::BASE36[intdiv($bits, 36)].self::BASE36[$bits % 36];
    }
}
