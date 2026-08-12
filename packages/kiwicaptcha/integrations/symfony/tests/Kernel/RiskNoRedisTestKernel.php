<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

/**
 * Kernel with risk.enabled but NO Redis client anywhere: the extension must
 * fail fast with a LogicException at compile time (never a runtime surprise).
 */
final class RiskNoRedisTestKernel extends TestKernel
{
    public function registerContainerConfiguration(\Symfony\Component\Config\Loader\LoaderInterface $loader): void
    {
        $loader->load(function (\Symfony\Component\DependencyInjection\ContainerBuilder $container): void {
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
                'risk' => [
                    'enabled' => true,
                ],
            ]);
        });
    }
}
