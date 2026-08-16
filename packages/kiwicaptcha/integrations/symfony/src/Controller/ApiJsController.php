<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * Serves the first-party incumbent-compatibility loader (round 24):
 * `GET {prefix}/api.js[?compat=recaptcha|hcaptcha|turnstile]` returns the
 * canonical wasm glue + widget driver as ONE same-origin external script.
 * The driver's built-in compat section auto-detects the `compat` query
 * parameter, auto-renders the incumbent containers (.g-recaptcha /
 * .h-captcha / .cf-turnstile), installs the provider global
 * (grecaptcha/hcaptcha/turnstile), and keeps the provider-named response
 * field in sync — an incumbent page changes only its provider script URL.
 *
 * The response is an immutable, cacheable public asset (the bytes are the
 * same canonical assets the browser tests verify); CSP guidance: this path
 * is served same-origin, so a conventional deployment approaches
 * `script-src 'self'` + `worker-src 'self'` with no inline/blob
 * directives (SHA-256 mode needs no WASM capability thanks to the pure-JS
 * fallback; Argon2id deployments add the WASM permission).
 */
final class ApiJsController
{
    /**
     * Marker splitting the glue from the driver in the concatenated
     * loader (round 26): the driver's compat section fetches its own
     * script source and extracts the glue part for the Blob-worker
     * prelude, so Argon2id stays worker-only and working through the
     * external /api.js path.
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

        // Round 26 (P2): the stable {prefix}/api.js URL is MUTABLE (it
        // changes on every upgrade), so year-long immutable caching is
        // wrong — a browser/CDN could retain a vulnerable loader for a
        // year after the server was upgraded. The stable migration URL
        // uses revalidation instead: ETag + public no-cache (304 on
        // match); version/content-addressed URLs are reserved for truly
        // immutable assets.
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
