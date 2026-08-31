<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Test kernel wired through the twelve-factor env-managed form: the
 * redis_dsn and public_base_url config values are Symfony %env()%
 * placeholders (the exact shape the recipe ships), resolved by the
 * container's parameter bag at compile/runtime from the process
 * environment. The Redis DSN env names mirror the recipe manifest
 * (KIWI_REDIS_DSN, KIWI_PUBLIC_URL); the secret keeps the smoke
 * prefix so a developer's real KIWI_SECRET_KEY is never touched.
 */
final class EnvDsnTestKernel extends TestKernel
{
    public const REDIS_DSN_ENV = 'KIWI_REDIS_DSN';
    public const PUBLIC_URL_ENV = 'KIWI_PUBLIC_URL';

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(function (ContainerBuilder $container): void {
            $container->loadFromExtension('framework', [
                'secret' => 'test-secret',
                'test' => true,
            ]);
            $container->loadFromExtension('twig', [
                'form_themes' => ['@KiwiCaptcha/form_div_layout.html.twig'],
            ]);
            $container->loadFromExtension('kiwi_captcha', [
                'secret_key' => self::SECRET,
                'difficulty_bits' => 8,
                'public_base_url' => '%env('.self::PUBLIC_URL_ENV.')%',
                'redis_dsn' => '%env('.self::REDIS_DSN_ENV.')%',
            ]);
        });
    }
}
