<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Test kernel variant wired through the high-level redis_dsn setting:
 * the extension builds the Redis-backed services (challenge storage,
 * rate limiter, Argon admission) from the DSN, so a real-Redis test can
 * drive the DSN-built services end to end.
 */
class RedisDsnTestKernel extends TestKernel
{
    public function __construct(
        string $environment,
        bool $debug,
        private readonly string $redisDsn,
    ) {
        parent::__construct($environment, $debug);
    }

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
                // Prod kernels must carry the canonical
                // origin (the prod-invariant guard requires it).
                'public_base_url' => 'https://captcha.example.com',
                'redis_dsn' => $this->redisDsn,
            ]);
        });
    }
}
