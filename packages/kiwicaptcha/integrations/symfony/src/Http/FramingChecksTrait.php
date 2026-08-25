<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Http;

use Symfony\Component\HttpFoundation\Request;

/**
 * The universal HTTP framing rule shared by every security-sensitive
 * endpoint (challenge, cancellation, SiteVerify): one canonical HTTP
 * representation.
 *
 *   Content-Length:        max one occurrence, canonical decimal grammar
 *   Transfer-Encoding:     max one occurrence, 'chunked' only, never
 *                          together with Content-Length
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
        $lengths = $request->headers->all('Content-Length');
        if (\count($lengths) > 1) {
            return false;
        }
        // Canonical Content-Length grammar: a single canonical decimal
        // integer (0 or a leading-digit-non-zero sequence) — malformed
        // values (-1, +123, 123junk, "123, 123", empty) are refused
        // explicitly rather than left to PHP coercion, because this
        // repository deliberately defends across parser boundaries.
        if ($lengths !== []) {
            $value = $lengths[0];
            if (!\is_string($value)
                || $value === ''
                || preg_match('/^(?:0|[1-9][0-9]*)$/D', $value) !== 1
            ) {
                return false;
            }
        }
        $transferEncodings = $request->headers->all('Transfer-Encoding');
        // Transfer-Encoding must be singular AND, if it survives at the
        // application boundary at all, the only representation a
        // de-chunking server stack can present is a single 'chunked'.
        if (\count($transferEncodings) > 1) {
            return false;
        }
        if ($lengths !== [] && $transferEncodings !== []) {
            return false;
        }
        if ($transferEncodings !== []) {
            $value = $transferEncodings[0];
            if (!\is_string($value) || strtolower(trim($value)) !== 'chunked') {
                return false;
            }
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
