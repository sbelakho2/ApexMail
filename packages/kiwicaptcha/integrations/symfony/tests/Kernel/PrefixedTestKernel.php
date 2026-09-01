<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Test kernel with a non-default challenge route prefix, exercising the
 * auto-registered route's configured-path behavior. The configured value
 * deliberately carries a trailing slash: the configuration tree
 * canonicalizes it (single canonical form, no trailing slash), so every
 * consumer — the route loader, the Twig runtime, the form type and the
 * container parameter — sees exactly '/security/captcha'.
 */
final class PrefixedTestKernel extends TestKernel
{
    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(function (ContainerBuilder $container): void {
            $container->loadFromExtension('framework', [
                'secret' => 'test-secret',
                'test' => true,
            ]);
            $container->loadFromExtension('twig', [
                'form_themes' => ['@KiwiCaptcha/form_div_layout.html.twig'],
                'paths' => [
                    __DIR__.'/templates' => 'Test',
                ],
            ]);
            $container->loadFromExtension('kiwi_captcha', [
                'secret_key' => self::SECRET,
                'difficulty_bits' => 8,
                'route_prefix' => '/security/captcha/',
            ]);
        });
    }
}
