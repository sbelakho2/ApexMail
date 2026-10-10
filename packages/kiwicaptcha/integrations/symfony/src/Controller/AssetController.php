<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Controller;

use BelConsulting\KiwiCaptchaBundle\Asset\AssetDigestIndex;
use BelConsulting\KiwiCaptchaBundle\Asset\EtagMatcher;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * Serves the versioned immutable widget assets (asset_mode "files"):
 * `GET {prefix}/assets/{name}.{sha256-64}.{js|css}` returns the exact bytes
 * the inline mode embeds, with a long immutable cache lifetime, the
 * Content-Length and the content-hash ETag, so browsers and CDNs reuse
 * one cached copy across pages. The hash in the URL is the full 256-bit
 * sha256 of the content (64 hex characters, the same digest as the
 * ETag), and an unknown hash is a 404. A page can only reference the
 * exact bytes the server serves, so a mismatch can never pair a stale
 * hash with different content.
 *
 * Rolling deploys: a page rendered by a new node can reference a hash an
 * old node is serving, and the reverse. The controller therefore accepts
 * an explicit list of previous-release asset directories and serves the
 * requested content hash from the active directory first, then from each
 * fallback in order. Deployments that keep their previous asset
 * directories mounted keep lazy modules loading during the rollout.
 * Moving content-addressed assets to shared storage or a CDN works too.
 * Without fallbacks an unknown hash stays a 404, which degrades to
 * worker-unavailable or English-only UI until the rollout settles.
 *
 * The same-origin, content-addressed URLs are CSP-compatible with the
 * existing recommended profile (`script-src 'self'`, `style-src 'self'`):
 * no new directive is required for files mode.
 */
final class AssetController
{
    private const HASH_LENGTH = 64;
    private const MAX_AGE_SECS = 31536000;

    private const ASSETS = [
        'runtime' => ['file' => 'kiwicaptcha-wasm.js', 'content_type' => 'application/javascript; charset=UTF-8'],
        'widget' => ['file' => 'widget.css', 'content_type' => 'text/css; charset=UTF-8'],
        'driver' => ['file' => 'widget-driver.js', 'content_type' => 'application/javascript; charset=UTF-8'],
        'worker' => ['file' => 'kiwi-worker.js', 'content_type' => 'application/javascript; charset=UTF-8'],
        'execution' => ['file' => 'execution-interpreter.js', 'content_type' => 'application/javascript; charset=UTF-8'],
        'risk' => ['file' => 'widget-risk.js', 'content_type' => 'application/javascript; charset=UTF-8'],
        'telemetry' => ['file' => 'widget-telemetry.js', 'content_type' => 'application/javascript; charset=UTF-8'],
        'locales' => ['file' => 'widget-locales.js', 'content_type' => 'application/javascript; charset=UTF-8'],
        // The combined WebAuthn ceremony script: one file that branches
        // on doc.ceremony (create vs get), so a strict-CSP deployment
        // without per-request nonces can serve it as the external
        // scriptSrc instead of copying the constant by hand.
        'ceremony' => ['file' => 'webauthn-ceremony.js', 'content_type' => 'application/javascript; charset=UTF-8'],
    ];

    /**
     * @param list<string> $fallbackDirs previous-release asset directories
     *                                   searched (in order) when the
     *                                   requested hash is not the active
     *                                   copy
     */
    public function __construct(
        private readonly string $assetsDir,
        private readonly array $fallbackDirs = [],
        private readonly ?AssetDigestIndex $digestIndex = null,
    ) {
    }

    public function asset(Request $request, string $name, string $hash, string $extension): Response
    {
        if (!isset(self::ASSETS[$name])) {
            throw new NotFoundHttpException();
        }
        $spec = self::ASSETS[$name];
        if ($extension !== ($name === 'widget' ? 'css' : 'js')) {
            // The name and the extension are a fixed pair: a css name
            // served as a script (or the reverse) is a malformed URL.
            throw new NotFoundHttpException();
        }
        // Resolve the requested content hash from the active directory
        // first, then the previous-release fallbacks: the digest index
        // answers the active copy without reading or hashing it.
        $fullHash = null;
        $body = null;
        if ($this->digestIndex !== null) {
            $active = $this->digestIndex->digest($spec['file']);
            if ($active !== null && hash_equals($active, $hash)) {
                $fullHash = $active;
                $body = $this->digestIndex->read($spec['file']);
            }
        }
        if ($fullHash === null) {
            foreach ([$this->assetsDir, ...$this->fallbackDirs] as $dir) {
                $candidate = (string) @file_get_contents(rtrim($dir, '/').'/'.$spec['file']);
                if ($candidate === '') {
                    continue;
                }
                $candidateHash = hash('sha256', $candidate);
                // The URL hash is the full 256-bit digest, the whole
                // sha256 hex, so the URL can only ever address the exact
                // bytes the route serves, the same digest the ETag
                // carries.
                if (hash_equals(substr($candidateHash, 0, self::HASH_LENGTH), $hash)) {
                    $fullHash = $candidateHash;
                    $body = $candidate;
                    break;
                }
            }
        }
        if ($fullHash === null || $body === null || $body === '') {
            throw new NotFoundHttpException();
        }
        $etag = '"'.$fullHash.'"';
        if (EtagMatcher::matches($request->headers->get('If-None-Match'), $etag)) {
            return new Response('', Response::HTTP_NOT_MODIFIED, [
                'ETag' => $etag,
                'Cache-Control' => 'public, max-age='.self::MAX_AGE_SECS.', immutable',
            ]);
        }

        return new Response($body, Response::HTTP_OK, [
            'Content-Type' => $spec['content_type'],
            'Cache-Control' => 'public, max-age='.self::MAX_AGE_SECS.', immutable',
            'ETag' => $etag,
            'Content-Length' => (string) \strlen($body),
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }
}
