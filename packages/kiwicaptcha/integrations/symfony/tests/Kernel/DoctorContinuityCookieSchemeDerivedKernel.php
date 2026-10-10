<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

/**
 * The warned combination: a custom (non-__Host-) cookie name with a
 * scheme-derived Secure flag (secure: null) behind trusted proxies.
 * Behind a TLS-terminating proxy the PHP-side scheme is the proxy's
 * plain-http hop, so the cookie can be minted without Secure and
 * dropped by the browser.
 */
final class DoctorContinuityCookieSchemeDerivedKernel extends DoctorContinuityCookieTestKernel
{
    protected function riskOverrides(): array
    {
        return [
            'client_ip_mode' => 'symfony_trusted_proxies',
            'trusted_proxies' => ['10.0.0.0/8'],
            'continuity_cookie' => ['name' => 'kiwi-session', 'secure' => null],
        ];
    }
}
