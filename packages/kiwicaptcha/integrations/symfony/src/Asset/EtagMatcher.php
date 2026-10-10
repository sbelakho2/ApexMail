<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Asset;

/**
 * RFC 7232 If-None-Match matching for the widget asset endpoints.
 *
 * The historical comparison was exact string equality, so a legitimate
 * conditional request never got its 304 when a client or intermediary
 * sent a weakened validator (`W/"..."`) or a comma separated list
 * (`"a", "b"`). Both are legal for If-None-Match, which uses the weak
 * comparison function, and both re-downloaded the asset every time.
 */
final class EtagMatcher
{
    /**
     * Whether the If-None-Match header matches the entity tag. Weak
     * validators compare equal to their strong form for If-None-Match
     * (RFC 7232 section 3.2), and a list matches when any member does.
     */
    public static function matches(?string $header, string $etag): bool
    {
        if ($header === null || $header === '') {
            return false;
        }
        $wanted = self::normalize($etag);
        if ($header === '*') {
            return true;
        }
        foreach (explode(',', $header) as $candidate) {
            if (self::normalize(trim($candidate)) === $wanted) {
                return true;
            }
        }

        return false;
    }

    private static function normalize(string $tag): string
    {
        $tag = trim($tag);
        if (str_starts_with($tag, 'W/')) {
            $tag = substr($tag, 2);
        }

        return trim($tag);
    }
}
