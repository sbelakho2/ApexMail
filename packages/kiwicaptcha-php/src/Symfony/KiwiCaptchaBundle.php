<?php

declare(strict_types=1);

namespace KiwiCaptcha\Symfony;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * KiwiCaptcha Symfony bundle.
 *
 * Register in config/bundles.php:
 *   KiwiCaptcha\Symfony\KiwiCaptchaBundle::class => ['all' => true],
 *
 * Configuration (config/packages/kiwicaptcha.yaml):
 *   kiwicaptcha:
 *     secret: '%env(KIWI_SECRET_KEY)%'        # required
 *     algorithm: sha256                       # sha256 | argon2id
 *     difficulty_bits: 20
 *     challenge_ttl_secs: 120
 *     storage: kiwicaptcha.storage.array       # or your own service id
 *     route_prefix: /kiwi-captcha
 */
final class KiwiCaptchaBundle extends Bundle
{
    public function getContainerExtension(): ?ExtensionInterface
    {
        return new DependencyInjection\KiwiCaptchaExtension();
    }

    public function build(ContainerBuilder $container): void
    {
        parent::build($container);
    }
}
