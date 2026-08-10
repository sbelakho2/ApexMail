<?php

declare(strict_types=1);

namespace KiwiCaptcha\Symfony\Twig;

use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

final class KiwiCaptchaExtension extends AbstractExtension
{
    public function getFunctions(): array
    {
        return [
            new TwigFunction('kiwi_captcha_widget', [KiwiCaptchaRuntime::class, 'renderWidget'], ['is_safe' => ['html']]),
        ];
    }
}
