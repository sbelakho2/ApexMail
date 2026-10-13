<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;

/**
 * First-party session continuity cookie for the adaptive risk engine.
 *
 * The risk-v1 "session" signal links observations from the same browser
 * across requests. The link material must be a fresh random nonce, never
 * an IP-derived or device-derived identifier. This service mints exactly
 * that: a 16-byte random value (hex, 32 chars) stored in a first-party,
 * HttpOnly, SameSite=Strict cookie. The constructor's default applies;
 * the operator may relax it. The engine only ever stores the
 * keyed pseudonym of the value (HMAC-SHA256 with the derived session
 * key), never the value itself.
 *
 * Privacy contract: the cookie is a random nonce with no embedded
 * identity; it expires after the configured TTL (default 30 minutes; the
 * spec's 15-30 minute window) and follows the request scheme for the
 * Secure flag (null default). Browsers that reject the cookie (e.g.
 * third-party contexts, strict blockers) simply fall back to a
 * session-less risk identity — the engine pads an absent session with
 * zeros, so availability is never coupled to cookie acceptance.
 */
final class ContinuityCookie
{
    public const VALUE_PATTERN = '/^[0-9a-f]{32}$/D';

    public function __construct(
        private readonly string $name = '__Host-kiwi-session',
        private readonly int $ttlSecs = 1800,
        private readonly string $path = '/',
        private readonly ?bool $secure = null,
        private readonly string $sameSite = 'strict',
        private readonly bool $httpOnly = true,
    ) {
        if ($this->name === '') {
            throw new \InvalidArgumentException('Continuity cookie name must not be empty');
        }
        if ($this->ttlSecs < 0) {
            throw new \InvalidArgumentException('Continuity cookie TTL must be >= 0');
        }
        // The browser contract of the __Host- prefix: Secure, no Domain
        // and Path=/. Secure is forced in cookie(); the path is refused
        // here, because a __Host- cookie with any other path is dropped
        // by browsers and session continuity silently disappears.
        if (str_starts_with($this->name, '__Host-') && $this->path !== '/') {
            throw new \InvalidArgumentException(
                'A __Host- prefixed continuity cookie requires path "/" (browsers refuse any other path)'
            );
        }
        // SameSite=None is only meaningful on a Secure cookie; modern
        // browsers reject it otherwise (the cookie is dropped, not
        // weakened). The __Host- prefix forces Secure, so it satisfies
        // the requirement too.
        if ($this->sameSite === 'none' && $this->secure !== true && !str_starts_with($this->name, '__Host-')) {
            throw new \InvalidArgumentException(
                'Continuity cookie SameSite=None requires an effectively Secure cookie (secure: true, or a __Host- prefixed name)'
            );
        }
    }

    /**
     * The validated session value from the request (32 lowercase hex chars),
     * or null when the cookie is absent, malformed, or stale.
     */
    public function read(Request $request): ?string
    {
        // The raw parameter map, never the typed accessor: an array-shaped
        // cookie (session[]=x) makes the typed accessor throw, while here
        // any non-string shape simply reads as absent.
        $value = $request->cookies->all()[$this->name] ?? null;
        if (!\is_string($value) || preg_match(self::VALUE_PATTERN, $value) !== 1) {
            return null;
        }

        return $value;
    }

    /**
     * Mints a fresh session value: 16 random bytes as 32 lowercase hex
     * chars (the risk-v1 "raw 16-byte session cookie value").
     */
    public function mint(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * The Symfony Cookie to attach to a response so the client carries the
     * session value in subsequent requests. A `__Host-` prefixed name
     * forces Secure=true regardless of the request scheme. The browser
     * contract for the prefix requires Secure (and no Domain attribute,
     * path /), and behind a TLS-terminating proxy the request scheme at
     * the PHP layer is plain http even though the client connection is
     * HTTPS. A scheme-derived Secure flag would then silently drop the
     * cookie and the session signal would never survive the first
     * response.
     */
    public function cookie(Request $request, string $value): Cookie
    {
        $secure = $this->secure ?? $request->isSecure();
        if (str_starts_with($this->name, '__Host-')) {
            $secure = true;
        }

        return new Cookie(
            name: $this->name,
            value: $value,
            expire: $this->ttlSecs > 0 ? time() + $this->ttlSecs : 0,
            path: $this->path,
            secure: $secure,
            httpOnly: $this->httpOnly,
            sameSite: $this->sameSite,
        );
    }

    /** The configured cookie name. */
    public function name(): string
    {
        return $this->name;
    }

    /** The configured TTL in seconds. */
    public function ttlSecs(): int
    {
        return $this->ttlSecs;
    }
}
