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
 * identifier. The derivation is KEYED to the deployment namespace, a SHORT
 * epoch and the continuity session, so the same capability combination
 * yields a different tag per deployment, per epoch and per session: the tag
 * can never be used to correlate a device across deployments, epochs or
 * sessions. The engine only ever compares tags WITHIN one session to detect
 * a CHANGED coarse context (an inconsistency signal) — a changed tag is
 * probabilistic risk evidence, never a security gate.
 *
 * Privacy contract: the descriptor is the coarse, bounded capability string
 * the widget reports (viewport class, touch capability, language family,
 * timezone offset class); the tag is its keyed hash — never a raw
 * fingerprint, never the descriptor itself.
 */
final class ClientContextTag
{
    /** Epoch length (seconds): the tag is re-keyed every hour. */
    public const EPOCH_SECS = 3600;

    /** Tag width: 10 bits -> 1024 distinct tags per session+epoch. */
    public const BITS = 10;

    private const BASE36 = '0123456789abcdefghijklmnopqrstuvwxyz';

    /**
     * Derives the bounded tag: base36 of the TOP `BITS` bits of
     * sha256(deployment | epoch | session | descriptor).
     *
     * Deterministic within (deployment, epoch, session, descriptor): the
     * same session reporting the same coarse capabilities produces the same
     * tag inside one epoch; any of the four inputs changing produces a
     * different tag.
     */
    public static function derive(string $deployment, int $nowSecs, string $session, string $descriptor): string
    {
        $epoch = intdiv($nowSecs, self::EPOCH_SECS);
        $digest = hash('sha256', $deployment.'|'.$epoch.'|'.$session.'|'.$descriptor, true);
        $bits = ((ord($digest[0]) << 2) | (ord($digest[1]) >> 6)) & 0x3FF;

        return self::BASE36[intdiv($bits, 36)].self::BASE36[$bits % 36];
    }
}
