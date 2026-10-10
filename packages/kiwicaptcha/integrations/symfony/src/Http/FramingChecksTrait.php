<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Http;

use Symfony\Component\HttpFoundation\Request;

/**
 * The universal HTTP framing rule shared by every security-sensitive
 * endpoint (challenge, cancellation, SiteVerify): one canonical HTTP
 * representation.
 *
 *   Content-Length:        max one occurrence, canonical decimal grammar.
 *   Transfer-Encoding:     max one occurrence, 'chunked' only, never
 *                          together with Content-Length.
 *   Content-Type:          max one occurrence.
 *   Content-Encoding:      max one occurrence.
 *
 * A duplicated header (two different values) is the kind of ambiguity
 * different proxies and application layers interpret differently, so it
 * is refused rather than silently collapsed.
 *
 * SAPI caveat: duplicate-header detection only fires where the SAPI
 * preserves duplicate occurrences as separate values in the request
 * bag. Conventional php-fpm/nginx typically collapse duplicates into
 * one comma-joined value before PHP sees them. Under that stack the
 * duplicate rows of this contract are therefore enforced by the
 * intermediary's own collapse (a single non-canonical value is still
 * refused by the grammar checks). The full duplicate-refusal behavior is
 * effective
 * under FrankenPHP, Swoole, and the test harness (built Symfony
 * Requests), where every occurrence reaches the application verbatim.
 */
trait FramingChecksTrait
{
    /**
     * Whether the raw request target is the canonical origin-form path.
     * False means the caller must refuse the request before any handling.
     * The caller builds its own response vocabulary.
     *
     * The raw target is inspected, never a normalized route. An
     * intermediary that rewrites or normalizes the target (a matrix
     * parameter, a trailing dot, a fragment, an absolute-form scheme and
     * host, or a dot segment) would otherwise let a second spelling of
     * the target reach the endpoint's state-changing pipeline.
     *
     * Rejected shapes:
     *  - anything without a leading slash: absolute-form, authority-form
     *    and relative targets.
     *  - a fragment ("#") anywhere in the target.
     *  - any byte outside printable ASCII: raw spaces, tabs, CR, LF,
     *    NUL, DEL, other control bytes and non-ASCII bytes.
     *  - any percent-encoded byte, backslash or matrix semicolon in the
     *    path.
     *  - any empty or dot segment ("//", a trailing slash, "/.", "/..").
     *  - any segment ending with "." (some intermediaries strip the dot
     *    and fold "/challenge." onto "/challenge").
     *
     * Only the path component is inspected here; a query string is
     * rejected separately by each endpoint.
     */
    private function isCanonicalRequestTarget(string $rawRequestUri): bool
    {
        if ($rawRequestUri === '' || $rawRequestUri[0] !== '/') {
            return false;
        }
        if (str_contains($rawRequestUri, '#') || preg_match('/[^\x21-\x7E]/', $rawRequestUri) === 1) {
            return false;
        }
        $path = $rawRequestUri;
        $queryPos = strpos($rawRequestUri, '?');
        if ($queryPos !== false) {
            $path = substr($rawRequestUri, 0, $queryPos);
        }
        if (str_contains($path, '%') || str_contains($path, '\\') || str_contains($path, ';')) {
            return false;
        }
        // The empty element before the leading slash is the absolute-path
        // marker, not a segment (guaranteed present by the check above);
        // every other empty segment (a `//` in the middle, or the trailing
        // `/` of "/challenge/") is noncanonical.
        $segments = explode('/', $path);
        for ($i = 1, $count = \count($segments); $i < $count; $i++) {
            $segment = $segments[$i];
            if ($segment === '' || $segment === '.' || $segment === '..') {
                return false;
            }
            if ($segment[\strlen($segment) - 1] === '.') {
                return false;
            }
        }

        return true;
    }

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
