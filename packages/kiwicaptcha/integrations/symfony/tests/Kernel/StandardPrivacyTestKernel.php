<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Kernel with privacy_mode 'standard': the operator's explicit telemetry and
 * timing choices must pass through untouched.
 */
final class StandardPrivacyTestKernel extends TestKernel
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
                'privacy_mode' => 'standard',
                'telemetry' => 'minimal',
                'min_duration_ms' => 100,
            ]);
        });
    }
}
