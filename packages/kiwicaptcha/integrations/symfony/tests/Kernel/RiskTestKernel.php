<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

/**
 * Kernel with the adaptive risk engine ENABLED and a fake Predis client as
 * risk.redis_service. The fake does not speak the risk-v1 EVALSHA protocol,
 * so the engine takes its degraded path (store failure -> circuit breaker ->
 * degraded decisions) — which is exactly what this kernel exercises: risk
 * wiring must NEVER break issuance, even when the risk backend is down.
 */
final class RiskTestKernel extends TestKernel
{
    protected function build(\Symfony\Component\DependencyInjection\ContainerBuilder $container): void
    {
        // Constraint validators are inlined when private; expose the bundle's
        // validator so the tests can assert the risk wiring on it.
        $container->addCompilerPass(new class implements \Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface {
            public function process(\Symfony\Component\DependencyInjection\ContainerBuilder $container): void
            {
                $id = \BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator::class;
                if ($container->hasDefinition($id)) {
                    $container->getDefinition($id)->setPublic(true);
                }
            }
        });
    }

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
                    'scopes' => [
                        'login' => ['id' => 10],
                        'signup' => ['id' => 11, 'base_risk' => 300, 'minimum' => 'sha20'],
                    ],
                ],
            ]);
        });
    }
}
