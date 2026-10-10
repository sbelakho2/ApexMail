<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

/**
 * The passing combination: the __Host- prefixed cookie name (the
 * default), which forces the Secure flag regardless of the request
 * scheme, behind the same trusted proxies.
 */
final class DoctorContinuityCookieHostPrefixedKernel extends DoctorContinuityCookieTestKernel
{
    protected function riskOverrides(): array
    {
        return [
            'client_ip_mode' => 'symfony_trusted_proxies',
            'trusted_proxies' => ['10.0.0.0/8'],
            'continuity_cookie' => ['name' => '__Host-kiwi-session', 'secure' => null],
        ];
    }
}
