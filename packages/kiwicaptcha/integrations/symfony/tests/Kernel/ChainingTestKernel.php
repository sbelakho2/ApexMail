<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

/**
 * Kernel with the adaptive risk engine AND selective chained challenges
 * (risk.chaining) enabled, plus the trusted-edge TLS header. The fake
 * Predis client cannot speak the risk-v1 EVALSHA protocol, so runtime
 * engine calls degrade — this kernel only exercises the WIRING (services
 * exist and are injected into the controller + validator).
 */
final class ChainingTestKernel extends TestKernel
{
    public function registerContainerConfiguration(\Symfony\Component\Config\Loader\LoaderInterface $loader): void
    {
        $loader->load(function (\Symfony\Component\DependencyInjection\ContainerBuilder $container): void {
            $container->register('fake_redis', \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient::class)
                ->setPublic(true);
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
                    'redis_service' => 'fake_redis',
                    'trusted_tls_header' => 'X-Tls-Class',
                    'chaining' => [
                        'enabled' => true,
                        'ttl_secs' => 120,
                    ],
                    'scopes' => [
                        'login' => ['id' => 10],
                    ],
                ],
            ]);
        });
    }
}
