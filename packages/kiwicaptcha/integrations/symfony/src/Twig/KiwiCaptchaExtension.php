<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Twig;

use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

final class KiwiCaptchaExtension extends AbstractExtension
{
    public function getFunctions(): array
    {
        return [
            new TwigFunction('kiwi_captcha_widget', [KiwiCaptchaRuntime::class, 'renderWidget'], ['is_safe' => ['html'], 'needs_environment' => true]),
            // Audit #71: the explicit frame-ancestors CSP directive for the
            // WIDGET PAGE (null when risk.challenge_origin_allowlist is
            // empty). The application appends it to its own
            // Content-Security-Policy header — frame-ancestors is ignored
            // inside <meta> tags, so the header is the only effective
            // delivery; the challenge ENDPOINT emits the header itself.
            new TwigFunction('kiwi_captcha_csp_frame_ancestors', [KiwiCaptchaRuntime::class, 'cspFrameAncestors']),
        ];
    }
}
