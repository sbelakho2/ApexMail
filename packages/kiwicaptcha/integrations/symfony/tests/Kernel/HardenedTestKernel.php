<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Kernel with the production-hardening options enabled: per-IP issuance rate
 * limiting (with a shared PSR-6 pool) and the Argon2id verification
 * concurrency cap. Proves the extension wires them into the real services.
 */
final class HardenedTestKernel extends TestKernel
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
            $container->register('my.rate.limit.pool', ArrayAdapter::class);
            $container->loadFromExtension('kiwi_captcha', [
                'secret_key' => self::SECRET,
                'difficulty_bits' => 8,
                'algorithm' => 'argon2id',
                'argon_m_kib' => 64,
                'argon_t' => 3,
                'argon_p' => 1,
                'argon2_difficulty_bits' => 4,
                'rate_limit' => 2,
                'rate_limit_window_secs' => 60,
                'rate_limit_cache' => 'my.rate.limit.pool',
                'argon2_max_concurrent_verifications' => 2,
            ]);
        });
    }
}
