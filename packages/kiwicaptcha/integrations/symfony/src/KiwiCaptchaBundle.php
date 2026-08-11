<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * KiwiCaptcha Symfony bundle.
 *
 * Register in config/bundles.php:
 *   BelConsulting\KiwiCaptchaBundle\KiwiCaptchaBundle::class => ['all' => true],
 *
 * Configure in config/packages/kiwi_captcha.yaml:
 *   kiwi_captcha:
 *     secret_key: '%env(KIWI_SECRET_KEY)%'   # required, min 16 bytes
 *     storage: kiwi_captcha.storage.redis    # shared storage required outside test/dev
 *
 * The bundle is fully self-contained: challenges are issued and verified
 * locally (no external services), and the widget (CSS + WASM solver +
 * driver) is embedded from the package assets.
 */
final class KiwiCaptchaBundle extends Bundle
{
    public function getContainerExtension(): ?ExtensionInterface
    {
        return new KiwiCaptchaExtension();
    }
}
