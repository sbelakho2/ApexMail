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
    /** @var string|null in-process cache of the concatenated loader */
    private static ?string $cachedBody = null;

    public function __construct(
        private readonly string $assetsDir,
    ) {
    }

    public function apiJs(): Response
    {
        if (self::$cachedBody === null) {
            $glue = (string) file_get_contents(rtrim($this->assetsDir, '/').'/kiwicaptcha-wasm.js');
            $driver = (string) file_get_contents(rtrim($this->assetsDir, '/').'/widget-driver.js');
            self::$cachedBody = $glue."\n".$driver;
        }
        $body = self::$cachedBody;

        return new Response($body, Response::HTTP_OK, [
            'Content-Type' => 'application/javascript; charset=UTF-8',
            'Cache-Control' => 'public, max-age=31536000, immutable',
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }
}
