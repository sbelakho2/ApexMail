<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Controller;

use BelConsulting\KiwiCaptchaBundle\Asset\AssetDigestIndex;
use BelConsulting\KiwiCaptchaBundle\Asset\EtagMatcher;
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
     * Placeholder for the descriptor table in the cached loader body. The
     * asset digests come from the asset files and the route-absolute URLs
     * from the request path, so the cached chunks carry this marker and
     * every response substitutes the concrete table.
     */
    private const ASSET_MARKER = "\n/*KIWI_COMPAT_ASSETS*/\n";

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
     * The lazy module assets that stay out of the set — widget-locales.js,
     * widget-telemetry.js and execution-interpreter.js — ride the response
     * as content-addressed descriptors instead; see the descriptor table
     * below. A default-language, telemetry-off, execution-unarmed compat
     * lifecycle then pays zero bytes for them.
     *
     * @return list<string>
     */
    private function loaderChunks(): array
    {
        return ['widget-driver.js', 'widget-risk.js', 'widget-compat.js'];
    }

    /**
     * The compat descriptor table: kind => asset file and extension. The
     * kinds mirror the asset names the AssetController route serves, so
     * every emitted URL is the exact content-addressed route URL. The
     * locales entry keeps the compat tier's lazy translation packing. The
     * telemetry and execution entries carry the modules the compat loader
     * embeds nowhere, so an armed compat page can fetch them. The runtime
     * and worker entries are informational in this tier: the loader
     * embeds the glue and the worker source, so files-mode delivery stays
     * opt-in.
     *
     * @var array<string, array{file: string, ext: string}>
     */
    private const COMPAT_ASSETS = [
        'locales' => ['file' => 'widget-locales.js', 'ext' => 'js'],
        'telemetry' => ['file' => 'widget-telemetry.js', 'ext' => 'js'],
        'execution' => ['file' => 'execution-interpreter.js', 'ext' => 'js'],
        'runtime' => ['file' => 'kiwicaptcha-wasm.js', 'ext' => 'js'],
        'worker' => ['file' => 'kiwi-worker.js', 'ext' => 'js'],
    ];

    /** @var array<string, array{file: string, ext: string, hash: string, sri: string, path: string}>|null in-process descriptor cache */
    private ?array $descriptors = null;

    /** @var string|null in-process cache of the concatenated loader */
    private static ?string $cachedBody = null;

    /**
     * Per-request-path ETag cache of the loader body. The body is the
     * static chunks plus a small path-dependent marker, so the 575 KB
     * sha256 is computed once per distinct request path per process
     * instead of on every no-cache revalidation.
     *
     * @var array<string, string>
     */
    private static array $etagCache = [];

    public function __construct(
        private readonly string $assetsDir,
        private readonly ?AssetDigestIndex $digestIndex = null,
    ) {
    }

    public function apiJs(Request $request): Response
    {
        $assetBase = $this->assetBase($request);
        $body = str_replace(
            self::ASSET_MARKER,
            $this->compatMarker($assetBase),
            $this->cachedBody(),
        );
        // The full-body hash is the expensive part of a revalidation;
        // cache it per request-path spelling (bounded by the route
        // spellings the loader is served under).
        $etag = self::$etagCache[$assetBase] ??= '"'.hash('sha256', $body).'"';

        // The stable {prefix}/api.js URL is mutable (it changes on every
        // upgrade), so year-long immutable caching is wrong: a browser or
        // CDN could retain a vulnerable loader for a year after the server
        // was upgraded. The stable migration URL uses revalidation instead:
        // ETag + public no-cache (304 on match); versioned or
        // content-addressed URLs are reserved for truly immutable assets.
        if (EtagMatcher::matches($request->headers->get('If-None-Match'), $etag)) {
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
        // The digest index answers the ETag without reading or hashing
        // the stylesheet; a 304 never touches the bytes at all.
        $digest = $this->digestIndex?->digest('widget.css');
        $body = null;
        if ($digest === null) {
            $body = (string) file_get_contents(rtrim($this->assetsDir, '/').'/widget.css');
            $digest = hash('sha256', $body);
        }
        $etag = '"'.$digest.'"';
        if (EtagMatcher::matches($request->headers->get('If-None-Match'), $etag)) {
            return new Response('', Response::HTTP_NOT_MODIFIED, [
                'ETag' => $etag,
                'Cache-Control' => 'public, no-cache',
            ]);
        }

        $body ??= (string) file_get_contents(rtrim($this->assetsDir, '/').'/widget.css');

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
                    // The descriptor table precedes the compat chunk so the
                    // rendered containers can issue the lazy module URLs.
                    $body .= self::ASSET_MARKER;
                }
                $body .= (string) file_get_contents(rtrim($this->assetsDir, '/').'/'.$chunk)."\n";
            }
            self::$cachedBody = $body;
        }

        return self::$cachedBody;
    }

    /**
     * The route base of the loader script URL, as the request path spells
     * it: '/security/captcha/api.js' yields '/security/captcha/'. The
     * empty string when the request path does not identify the loader, so
     * the descriptor URL falls back to its script-relative form.
     */
    private function assetBase(Request $request): string
    {
        $suffix = '/api.js';
        $path = rtrim($request->getPathInfo(), '/');
        if (!str_ends_with($path, $suffix)) {
            return '';
        }

        return substr($path, 0, -\strlen($suffix)).'/';
    }

    /**
     * The content-addressed descriptor table, built once from the exact
     * asset bytes: hash is the full sha256 hex of the served bytes, sri
     * is the sha256-<base64> digest of the same bytes, and path is the
     * asset-route suffix. A missing asset fails loudly at loader
     * construction with the actionable remedy, the same contract as
     * KiwiCaptchaRuntime::readAsset(): hashing the empty string would
     * pin bytes that exist nowhere.
     *
     * @return array<string, array{file: string, ext: string, hash: string, sri: string, path: string}>
     */
    private function descriptors(): array
    {
        if ($this->descriptors !== null) {
            return $this->descriptors;
        }
        $descriptors = [];
        foreach (self::COMPAT_ASSETS as $kind => $spec) {
            $digest = $this->digestIndex?->digest($spec['file']);
            if ($digest === null) {
                $path = rtrim($this->assetsDir, '/').'/'.$spec['file'];
                $body = @file_get_contents($path);
                if ($body === false) {
                    throw new \RuntimeException(sprintf('KiwiCaptcha asset not found: %s (run bin/sync-assets.sh)', $path));
                }
                $hash = hash('sha256', $body);
                $sri = 'sha256-'.base64_encode(hash('sha256', $body, true));
            } else {
                $hash = $digest;
                $sri = 'sha256-'.base64_encode((string) hex2bin($digest));
            }
            $descriptors[$kind] = [
                'file' => $spec['file'],
                'ext' => $spec['ext'],
                'hash' => $hash,
                'sri' => $sri,
                'path' => 'assets/'.$kind.'.'.$hash.'.'.$spec['ext'],
            ];
        }

        return $this->descriptors = $descriptors;
    }

    /**
     * The compat bootstrap descriptor block, emitted before the
     * widget-compat chunk. `window.__kiwiCaptchaCompatAssets` maps every
     * kind to {name, hash, sri, src, url}: src is the script-relative
     * content-addressed path the compat markup resolves against its own
     * script URL, url is the route-absolute form when the request path is
     * known. The widget consumes the table through the frozen attribute
     * contract data-kiwi-<kind>-src / data-kiwi-<kind>-integrity, with
     * locales, telemetry and execution as the required kinds. The
     * `window.__kiwiCaptchaCompatLocales` alias stays byte-identical for
     * the widget's existing locales path.
     */
    private function compatMarker(string $assetBase): string
    {
        $table = [];
        foreach ($this->descriptors() as $kind => $descriptor) {
            $table[$kind] = [
                'name' => $kind,
                'hash' => $descriptor['hash'],
                'sri' => $descriptor['sri'],
                'src' => $descriptor['path'],
                'url' => $assetBase.$descriptor['path'],
            ];
        }
        $locales = $table['locales'];

        return self::ASSET_MARKER
            .'window.__kiwiCaptchaCompatAssets='.json_encode($table, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR).';'."\n"
            .'window.__kiwiCaptchaCompatLocales={name:"locales",hash:"'.$locales['hash'].'",sri:"'.$locales['sri'].'"};'."\n";
    }
}
