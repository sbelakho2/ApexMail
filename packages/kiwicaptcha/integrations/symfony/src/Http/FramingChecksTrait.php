<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Http;

use Symfony\Component\HttpFoundation\Request;

/**
 * The universal HTTP framing rule shared by every security-sensitive
 * endpoint (challenge, cancellation, SiteVerify): one canonical HTTP
 * representation.
 *
 *   Content-Length:        max one occurrence
 *   Transfer-Encoding:     never together with Content-Length
 *   Content-Type:          max one occurrence
 *   Content-Encoding:      max one occurrence
 *
 * A duplicated header (two different values) is the kind of ambiguity
 * different proxies and application layers interpret differently, so it
 * is refused rather than silently collapsed.
 */
trait FramingChecksTrait
{
    /**
     * Whether the request's framing headers are canonical. False means
     * the caller must refuse the request (the caller builds its own
     * response vocabulary).
     */
    private function framingHeadersAcceptable(Request $request): bool
    {
        if (\count($request->headers->all('Content-Length')) > 1) {
            return false;
        }
        if ($request->headers->has('Content-Length') && $request->headers->has('Transfer-Encoding')) {
            return false;
        }
        if (\count($request->headers->all('Content-Type')) > 1) {
            return false;
        }
        if (\count($request->headers->all('Content-Encoding')) > 1) {
            return false;
        }

        return true;
    }
}
