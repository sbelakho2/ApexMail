<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * Serves the first-party incumbent-compatibility loader:
 * `GET {prefix}/api.js[?compat=recaptcha|hcaptcha|turnstile]` returns the
 * canonical wasm glue and widget driver as one same-origin external script.
 * The driver's built-in compat section auto-detects the `compat` query
 * parameter, auto-renders the incumbent containers (.g-recaptcha /
 * .h-captcha / .cf-turnstile), installs the provider global
 * (grecaptcha/hcaptcha/turnstile), and keeps the provider-named response
 * field in sync. An incumbent page changes only its provider script URL.
 *
 * The response is a mutable public asset: the stable {prefix}/api.js URL
 * changes on every upgrade, so it uses ETag + no-cache revalidation.
 * Only versioned or content-addressed URLs (e.g.
 * /kiwicaptcha/v1.6.20/api.js) or the release SHA256SUMS/SRI pins are
 * immutable. CSP guidance: the path is served same-origin; the compat
 * loader builds its Argon worker from a Blob URL (the inline
 * compatibility tier's worker model), so a conventional migration
 * deployment must allow `script-src 'self'` + `worker-src 'self' blob:`.
 * SHA-256 mode needs no worker and no WASM capability thanks to the
 * pure-JS solver; Argon2id adds the WASM permission via the worker's own
 * CSP-less context.
 */
final class ApiJsController
{
    /**
     * Marker splitting the glue from the driver in the concatenated
     * loader: the driver's compat section fetches its own script source
     * and extracts the glue part for the Blob-worker prelude, so Argon2id
     * stays worker-only and working through the external /api.js path.
     */
    private const SPLIT = "\n/*KIWI_COMPAT_SPLIT*/\n";

    /** @var string|null in-process cache of the concatenated loader */
    private static ?string $cachedBody = null;

    public function __construct(
        private readonly string $assetsDir,
    ) {
    }

    public function apiJs(Request $request): Response
    {
        $body = $this->cachedBody();
        $etag = '"'.hash('sha256', $body).'"';

        // The stable {prefix}/api.js URL is mutable (it changes on every
        // upgrade), so year-long immutable caching is wrong: a browser or
        // CDN could retain a vulnerable loader for a year after the server
        // was upgraded. The stable migration URL uses revalidation instead:
        // ETag + public no-cache (304 on match); versioned or
        // content-addressed URLs are reserved for truly immutable assets.
        if ((string) $request->headers->get('If-None-Match') === $etag) {
            return new Response('', Response::HTTP_NOT_MODIFIED, [
                'ETag' => $etag,
                'Cache-Control' => 'public, no-cache',
            ]);
        }

        return new Response($body, Response::HTTP_OK, [
            'Content-Type' => 'application/javascript; charset=UTF-8',
            'Cache-Control' => 'public, no-cache',
            'ETag' => $etag,
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }

    public function widgetCss(Request $request): Response
    {
        $body = (string) file_get_contents(rtrim($this->assetsDir, '/').'/widget.css');
        $etag = '"'.hash('sha256', $body).'"';
        if ((string) $request->headers->get('If-None-Match') === $etag) {
            return new Response('', Response::HTTP_NOT_MODIFIED, [
                'ETag' => $etag,
                'Cache-Control' => 'public, no-cache',
            ]);
        }

        return new Response($body, Response::HTTP_OK, [
            'Content-Type' => 'text/css; charset=UTF-8',
            'Cache-Control' => 'public, no-cache',
            'ETag' => $etag,
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }

    private function cachedBody(): string
    {
        if (self::$cachedBody === null) {
            $glue = (string) file_get_contents(rtrim($this->assetsDir, '/').'/kiwicaptcha-wasm.js');
            $driver = (string) file_get_contents(rtrim($this->assetsDir, '/').'/widget-driver.js');
            self::$cachedBody = $glue.self::SPLIT.$driver;
        }

        return self::$cachedBody;
    }
}
