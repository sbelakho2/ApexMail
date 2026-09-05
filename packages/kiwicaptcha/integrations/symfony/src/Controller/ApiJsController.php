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

    /**
     * The lazy widget modules that ride the loader response after the
     * driver core: widget-risk.js first, then widget-compat.js. The
     * worker machinery and the armed-evidence runners of widget-risk.js
     * register on the core bridge the moment they execute, so an
     * Argon2id/decoy/execution lifecycle on the compat route never
     * needs an extra fetch. The compat bootstrap activates only when
     * the loader URL carries the compat parameter. Ordinary widget
     * pages never load the /api.js route, so the modules stay lazy
     * everywhere else.
     *
     * widget-locales.js is deliberately NOT in this set: the loader is
     * a mutable asset served to every compat page, and a default-
     * language page must pay zero bytes for translations. The locales
     * descriptor below (the content-addressed asset URL parts) rides
     * the response instead, and the compat markup issues it as
     * container attributes, so the driver lazy-fetches the module only
     * when a non-default language is resolved.
     *
     * @return list<string>
     */
    private function loaderChunks(): array
    {
        return ['widget-driver.js', 'widget-risk.js', 'widget-compat.js'];
    }

    /**
     * The widget-locales.js descriptor for the compat tier: the module
     * is never concatenated into the loader (see loaderChunks), so the
     * rendered compat containers carry its content-addressed URL and
     * SRI digest as data-kiwi-locales-src / data-kiwi-locales-integrity
     * instead. The widget-compat.js chunk reads the marker below and
     * composes the asset URL from its own script URL.
     */
    private function localesMarker(): string
    {
        $body = (string) file_get_contents(rtrim($this->assetsDir, '/').'/widget-locales.js');
        $hash = hash('sha256', $body);

        $sri = 'sha256-'.base64_encode(hash('sha256', $body, true));

        return "\n/*KIWI_LOCALES_MARKER*/\n"
            .'window.__kiwiCaptchaCompatLocales={name:"locales",hash:"'.$hash.'",sri:"'.$sri.'"};'."\n";
    }

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
            $body = $glue.self::SPLIT;
            foreach ($this->loaderChunks() as $chunk) {
                if ($chunk === 'widget-compat.js') {
                    // The locales marker precedes the compat chunk so the
                    // rendered containers can issue the lazy module URL.
                    $body .= $this->localesMarker();
                }
                $body .= (string) file_get_contents(rtrim($this->assetsDir, '/').'/'.$chunk)."\n";
            }
            self::$cachedBody = $body;
        }

        return self::$cachedBody;
    }
}
