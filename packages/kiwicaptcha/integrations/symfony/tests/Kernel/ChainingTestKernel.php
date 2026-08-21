<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Risk\RequestBindingAuthorityInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Kernel with the adaptive risk engine AND selective chained challenges
 * (risk.chaining) enabled, plus the trusted-edge TLS header and the
 * deployment's authoritative transaction-binding resolver. The fake
 * Predis client cannot speak the risk-v1 evalsha protocol, so runtime
 * engine calls degrade — this kernel only exercises the wiring (services
 * exist and are injected into the controller + validator).
 */
final class ChainingTestKernel extends TestKernel
{
    public function registerContainerConfiguration(\Symfony\Component\Config\Loader\LoaderInterface $loader): void
    {
        $loader->load(function (\Symfony\Component\DependencyInjection\ContainerBuilder $container): void {
            $container->register('fake_redis', \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient::class)
                ->setPublic(true);
            $container->register('fake_binding_authority', ChainingBindingAuthority::class)
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
                    'request_binding_authority' => 'fake_binding_authority',
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

/**
 * The authoritative transaction-binding fixture of the chaining kernel: a
 * transaction is anchored on the fixed 'txn-alpha' binding (the presented
 * client string is a hint — a different presented value is refused, exactly
 * like the production authority contract).
 */
final class ChainingBindingAuthority implements RequestBindingAuthorityInterface
{
    public function resolve(Request $request, string $scope, ?string $presentedBinding): ?string
    {
        if ($presentedBinding !== null && $presentedBinding !== '' && $presentedBinding !== 'txn-alpha') {
            throw new \InvalidArgumentException('presented binding does not match the authoritative transaction binding');
        }

        return 'txn-alpha';
    }
}
