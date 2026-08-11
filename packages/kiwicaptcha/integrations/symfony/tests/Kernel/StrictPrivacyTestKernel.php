<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Kernel with privacy_mode 'strict' while the operator EXPLICITLY requests
 * the privacy-sensitive options (telemetry 'full', same_origin_only false,
 * min_duration_ms 500). The extension must FORCE them off/true/0 — that is
 * the strict privacy contract.
 */
final class StrictPrivacyTestKernel extends TestKernel
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
                'privacy_mode' => 'strict',
                'telemetry' => 'full',
                'same_origin_only' => false,
                'min_duration_ms' => 500,
            ]);
        });
    }
}
