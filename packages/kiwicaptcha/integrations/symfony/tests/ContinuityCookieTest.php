<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The continuity cookie's Secure-flag contract: a `__Host-` prefixed
 * name forces Secure regardless of the request scheme (the prefix's
 * browser contract). A TLS-terminating proxy — where the PHP-side
 * request scheme is the proxy's plain-http hop — can therefore never
 * cause the browser to silently drop the session cookie. A custom name
 * without the prefix keeps the configured/derived flag.
 */
final class ContinuityCookieTest extends TestCase
{
    private function httpProxyHopRequest(): Request
    {
        // The PHP-side view of a TLS-terminating proxy without a trusted
        // X-Forwarded-Proto: the request itself is plain http.
        return Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.4']);
    }

    public function testASessionCookieTtlZeroMintsNoMaxAge(): void
    {
        // ttl_secs 0 is the browser-session-cookie contract: the cookie
        // carries no Max-Age and dies with the browser session. It is the
        // browser lifetime only; the server-side risk state TTL is
        // risk.session_state_ttl_secs and is always positive.
        $cookie = new ContinuityCookie('__Host-kiwi-session', 0, '/', true, 'strict', true);
        $rendered = $cookie->cookie($this->httpProxyHopRequest(), $cookie->mint());

        self::assertSame(0, $rendered->getExpiresTime(), 'ttl 0 mints a session cookie (expire 0, no Max-Age)');
        self::assertTrue($rendered->isSecure());
    }

    public function testAHostPrefixedNameWithANonRootPathIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/__Host- prefixed continuity cookie requires path/');

        new ContinuityCookie('__Host-kiwi-session', 1800, '/sub', true, 'strict', true);
    }

    public function testSameSiteNoneRequiresAnEffectivelySecureCookie(): void
    {
        foreach ([false, null] as $secure) {
            try {
                new ContinuityCookie('kiwi-session', 1800, '/', $secure, 'none', true);
                self::fail('SameSite=None with secure '.var_export($secure, true).' must be refused');
            } catch (\InvalidArgumentException $e) {
                self::assertStringContainsString('SameSite=None requires an effectively Secure cookie', $e->getMessage());
            }
        }

        // Explicit Secure passes; the __Host- prefix forces Secure, so it
        // passes too.
        $explicit = new ContinuityCookie('kiwi-session', 1800, '/', true, 'none', true);
        self::assertSame('none', $explicit->cookie($this->httpProxyHopRequest(), $explicit->mint())->getSameSite());
        $hostPrefixed = new ContinuityCookie('__Host-kiwi-session', 1800, '/', null, 'none', true);
        self::assertTrue($hostPrefixed->cookie($this->httpProxyHopRequest(), $hostPrefixed->mint())->isSecure());
    }

    public function testAHostPrefixedNameForcesSecureOnAPlainHttpRequest(): void
    {
        $cookie = new ContinuityCookie(); // default name __Host-kiwi-session
        $value = $cookie->mint();
        $rendered = $cookie->cookie($this->httpProxyHopRequest(), $value);

        self::assertTrue($rendered->isSecure(), 'a __Host- prefixed cookie forces the Secure flag regardless of the request scheme');
        self::assertTrue($rendered->isHttpOnly());
        self::assertSame('__Host-kiwi-session', $rendered->getName());
    }

    public function testAHostPrefixedNameForcesSecureEvenWhenSecureIsExplicitlyNull(): void
    {
        // secure: null (the default) means "follow the request scheme";
        // the __Host- prefix overrides the derivation.
        $cookie = new ContinuityCookie('__Host-kiwi-session', 1800, '/', null, 'strict', true);
        self::assertTrue($cookie->cookie($this->httpProxyHopRequest(), $cookie->mint())->isSecure());
    }

    public function testAHostPrefixedNameNeverDowngradesAnExplicitlySecureConfiguration(): void
    {
        $cookie = new ContinuityCookie('__Host-kiwi-session', 1800, '/', true, 'strict', true);
        self::assertTrue($cookie->cookie($this->httpProxyHopRequest(), $cookie->mint())->isSecure());
    }

    public function testACustomNameKeepsTheSchemeDerivedFlag(): void
    {
        // Without the prefix the configured/derived semantics apply: a
        // plain-http request mints a non-Secure cookie (the doctor warns
        // about this combination behind trusted proxies).
        $cookie = new ContinuityCookie('kiwi-session', 1800, '/', null, 'strict', true);
        self::assertFalse($cookie->cookie($this->httpProxyHopRequest(), $cookie->mint())->isSecure(), 'a non-prefixed name keeps the scheme-derived flag');

        $secureCookie = new ContinuityCookie('kiwi-session', 1800, '/', true, 'strict', true);
        self::assertTrue($secureCookie->cookie($this->httpProxyHopRequest(), $secureCookie->mint())->isSecure(), 'an explicit secure configuration is honored for a non-prefixed name');
    }
}
