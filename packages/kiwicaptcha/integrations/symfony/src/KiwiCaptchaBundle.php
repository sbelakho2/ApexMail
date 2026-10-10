<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\StepUpControllerResolverPass;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * KiwiCaptcha Symfony bundle.
 *
 * Register in config/bundles.php:
 *   BelConsulting\KiwiCaptchaBundle\KiwiCaptchaBundle::class => ['all' => true].
 *
 * Configure in config/packages/kiwi_captcha.yaml:
 *   kiwi_captcha:
 *     secret_key: '%env(KIWI_SECRET_KEY)%'   # required, min 16 bytes.
 *     storage: kiwi_captcha.storage.redis    # shared storage required outside test/dev.
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

    public function build(ContainerBuilder $container): void
    {
        parent::build($container);
        // The step-up controller's principal-resolver binding runs as a
        // pass so an application-registered resolver is seen in every
        // kernel timing; the extension's load-time view alone cannot
        // guarantee that.
        $container->addCompilerPass(new StepUpControllerResolverPass());
    }
}
