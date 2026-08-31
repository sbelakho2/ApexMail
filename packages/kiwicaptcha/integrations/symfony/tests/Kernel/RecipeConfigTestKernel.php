<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Kernel wired with the recipe's exact config values
 * (recipes-contrib/bel-consulting/kiwicaptcha-symfony/1.0/
 * config/packages/kiwicaptcha.yaml): protection_profile + the %env()%
 * secret + the %env()% public origin and DSN the recipe ships (the
 * manifest declares the KIWI_REDIS_DSN / KIWI_PUBLIC_URL defaults into
 * .env). The env-managed values are resolved by the container's
 * parameter bag at compile/runtime; the DSN's resolved shape is
 * validated by the extension's runtime guard when the client is
 * constructed. The secret keeps the smoke prefix so a developer's real
 * KIWI_SECRET_KEY is never touched; the DSN and origin env names mirror
 * the recipe manifest exactly.
 */
final class RecipeConfigTestKernel extends TestKernel
{
    /**
     * The environment variable the recipe's %env()% secret resolves
     * from (the recipe manifest writes the generated value into .env).
     */
    public const SECRET_ENV = 'KIWI_RECIPE_SMOKE_SECRET';

    /**
     * The environment variables the recipe's %env()% DSN and origin
     * resolve from (the manifest declares their defaults into .env).
     */
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
                'protection_profile' => 'balanced',
                'secret_key' => '%env('.self::SECRET_ENV.')%',
                'public_base_url' => '%env('.self::PUBLIC_URL_ENV.')%',
                'redis_dsn' => '%env('.self::REDIS_DSN_ENV.')%',
            ]);
        });
    }
}
