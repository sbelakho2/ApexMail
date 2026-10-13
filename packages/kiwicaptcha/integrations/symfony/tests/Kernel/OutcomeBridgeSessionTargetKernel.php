<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

// The security event shims must exist before the container compiles:
// the extension gates the outcome bridge on the event classes being
// present, and the compile happens after this file is loaded.
(require_once __DIR__.'/../Fixtures/security-event-shims.php') || true;

/**
 * Kernel for the form-login target leg of the outcome bridge: the
 * identical risk and outcomes wiring of OutcomeBridgeTestKernel, but
 * without the spy compiler pass. The shipped KiwiOutcomeReporter books
 * every report against the fake risk store, so the test can read the
 * target's failure counter back the way the engine's own stages do.
 * The kernel registers no listener of its own: the shipped bridge is
 * the only writer the login failure lane has.
 */
final class OutcomeBridgeSessionTargetKernel extends TestKernel
{
    protected function build(ContainerBuilder $container): void
    {
        parent::build($container);
        // Bundle build() runs before the extension load, so the risk
        // store definition does not exist yet: the exposure happens in
        // a compiler pass, which runs after the extension load.
        $container->addCompilerPass(new class implements CompilerPassInterface {
            public function process(ContainerBuilder $container): void
            {
                if ($container->hasDefinition('kiwi_captcha.risk.store')) {
                    $container->getDefinition('kiwi_captcha.risk.store')->setPublic(true);
                }
            }
        });
    }

    public function registerContainerConfiguration(\Symfony\Component\Config\Loader\LoaderInterface $loader): void
    {
        $loader->load(function (ContainerBuilder $container): void {
            $container->register('fake_redis', \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient::class)
                ->setPublic(true);
            $container->loadFromExtension('framework', [
                'secret' => 'test-secret',
                'test' => true,
            ]);
            $container->loadFromExtension('kiwi_captcha', [
                'secret_key' => self::SECRET,
                'difficulty_bits' => 8,
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'fake_redis',
                    'scopes' => [
                        'login' => ['id' => 10, 'target_field' => 'username'],
                    ],
                    'outcomes' => [
                        'auto_bridge' => true,
                        'scope' => 'login',
                    ],
                ],
            ]);
        });
    }
}
