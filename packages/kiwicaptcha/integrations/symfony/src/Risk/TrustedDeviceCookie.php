<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;

/**
 * First-party trusted-device cookie for the adaptive risk engine.
 *
 * The continuity cookie (__Host-kiwi-session) expires in 30 minutes.
 * A real user who returns the next day or after lunch presents a new
 * or absent session cookie and would count as novel. This cookie
 * outlives a single visit: a random 16-byte nonce (hex, 32 chars)
 * stored in a first-party, HttpOnly, SameSite=Lax cookie with a
 * Max-Age of the configured trusted-device TTL (default 90 days).
 *
 * Privacy contract: the cookie is a random, revocable, first-party id.
 * The engine stores only the HMAC pseudonym under the principal
 * (never the raw value). The tag is capped at 16 per principal and is
 * purged by forgetDevices (password change, admin lockout,
 * sign-out-everywhere).
 */
final class TrustedDeviceCookie
{
    public const VALUE_PATTERN = '/^[0-9a-f]{32}$/D';

    public function __construct(
        private readonly string $name = '__Host-kiwi-device',
        private readonly int $ttlSecs = 7_776_000,
        private readonly string $path = '/',
        private readonly ?bool $secure = null,
        private readonly string $sameSite = 'lax',
        private readonly bool $httpOnly = true,
    ) {
        if ($this->name === '') {
            throw new \InvalidArgumentException('Trusted-device cookie name must not be empty');
        }
        if ($this->ttlSecs < 0) {
            throw new \InvalidArgumentException('Trusted-device cookie TTL must be >= 0');
        }
        if (str_starts_with($this->name, '__Host-') && $this->path !== '/') {
            throw new \InvalidArgumentException(
                'A __Host- prefixed device cookie requires path "/" (browsers refuse any other path)',
            );
        }
        if ($this->sameSite === 'none' && $this->secure !== true && !str_starts_with($this->name, '__Host-')) {
            throw new \InvalidArgumentException(
                'Trusted-device cookie SameSite=None requires an effectively Secure cookie',
            );
        }
    }

    /**
     * The validated device value from the request (32 lowercase hex
     * chars), or null when the cookie is absent or malformed.
     */
    public function read(Request $request): ?string
    {
        $value = $request->cookies->all()[$this->name] ?? null;
        if (!\is_string($value) || preg_match(self::VALUE_PATTERN, $value) !== 1) {
            return null;
        }

        return $value;
    }

    /** Mints a fresh device value: 16 random bytes as 32 hex chars. */
    public function mint(): string
    {
        return bin2hex(random_bytes(16));
    }

    /** The Symfony Cookie to attach to a response. */
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

    /** The configured cookie name (read from config, never a literal). */
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
