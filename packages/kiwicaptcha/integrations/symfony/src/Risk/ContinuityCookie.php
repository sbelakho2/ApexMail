<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;

/**
 * First-party session continuity cookie for the adaptive risk engine.
 *
 * The risk-v1 "session" signal links observations from the same browser
 * across requests. The link material must be a fresh random nonce — never an
 * IP-derived or device-derived identifier — so this service mints exactly
 * that: a 16-byte random value (hex, 32 chars) stored in a first-party,
 * HttpOnly, SameSite=Strict cookie (the constructor's default; the operator
 * may relax it). The engine only ever stores the keyed
 * pseudonym of the value (HMAC-SHA256 with the derived session key), never
 * the value itself.
 *
 * Privacy contract: the cookie is a random nonce with no embedded identity;
 * it expires after the configured TTL (default 30 minutes; the spec's
 * 15-30 minute window) and follows the
 * request scheme for the Secure flag (null default). Browsers that reject the
 * cookie (e.g. third-party contexts, strict blockers) simply fall back to a
 * session-less risk identity — the engine pads an absent session with zeros,
 * so availability is never coupled to cookie acceptance.
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
    }

    /**
     * The validated session value from the request (32 lowercase hex chars),
     * or null when the cookie is absent, malformed, or stale.
     */
    public function read(Request $request): ?string
    {
        $value = $request->cookies->get($this->name);
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
     * session value in subsequent requests.
     */
    public function cookie(Request $request, string $value): Cookie
    {
        $secure = $this->secure ?? $request->isSecure();

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
}
