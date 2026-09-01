<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Controller;

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
    ];

    public function __construct(
        private readonly string $assetsDir,
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
        $body = (string) @file_get_contents(rtrim($this->assetsDir, '/').'/'.$spec['file']);
        if ($body === '') {
            throw new NotFoundHttpException();
        }
        $fullHash = hash('sha256', $body);
        // The URL hash is the full 256-bit digest, the whole sha256
        // hex, so the URL can only ever address the exact bytes the
        // route serves, the same digest the ETag carries.
        if (!hash_equals(substr($fullHash, 0, self::HASH_LENGTH), $hash)) {
            throw new NotFoundHttpException();
        }
        $etag = '"'.$fullHash.'"';
        if ((string) $request->headers->get('If-None-Match') === $etag) {
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
