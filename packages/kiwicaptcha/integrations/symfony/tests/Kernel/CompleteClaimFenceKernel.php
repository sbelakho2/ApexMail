<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Risk\RedisPostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\Tests\DispositionWaitRedisFake;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Kernel with the bundle core Redis ('core_fake_redis') and
 * risk.redis_service ('risk_fake_redis') wired as TWO intentionally
 * separate in-memory clients, both with wait_replicas = 1. Used to prove
 * the post-solve complete-claim acceptance establishes its causal fence
 * on the RISK connection itself: an unrelated fence on the separate core
 * connection shares no replication stream and can never cover the risk
 * store's acceptance.
 */
final class CompleteClaimFenceKernel extends TestKernel
{
    protected function build(ContainerBuilder $container): void
    {
        $container->addCompilerPass(new class implements CompilerPassInterface {
            public function process(ContainerBuilder $container): void
            {
                $id = RedisPostSolveDispositionStore::class;
                if ($container->hasDefinition($id)) {
                    $container->getDefinition($id)->setPublic(true);
                }
            }
        });
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(function (ContainerBuilder $container): void {
            $container->register('core_fake_redis', FakePredisClient::class)
                ->setPublic(true);
            $container->register('risk_fake_redis', DispositionWaitRedisFake::class)
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
                'redis_service' => 'core_fake_redis',
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'risk_fake_redis',
                    'redis' => [
                        'wait_replicas' => 1,
                        'wait_timeout_ms' => 100,
                    ],
                    'scopes' => [
                        'login' => ['id' => 10],
                    ],
                ],
            ]);
        });
    }
}
