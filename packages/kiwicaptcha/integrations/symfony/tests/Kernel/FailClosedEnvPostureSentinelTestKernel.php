<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Test kernel variant for the replay_durability posture resolved from
 * the environment, %env(KIWI_REPLAY_DURABILITY)% = fail_closed, with a
 * Predis Sentinel replication aggregate wired as the storage/limiter
 * client. The build-time lanes cannot classify an env-resolved posture,
 * since the placeholder skips every literal comparison, so the kernel
 * boots. The runtime authority-transition guard then refuses the
 * aggregate when the checked client is first constructed, with the
 * posture resolved by then; that is the authoritative fail_closed
 * boundary.
 */
class FailClosedEnvPostureSentinelTestKernel extends TestKernel
{
    public const POSTURE_ENV = 'KIWI_REPLAY_DURABILITY';

    protected function build(ContainerBuilder $container): void
    {
        parent::build($container);
        $container->register('runtime.sentinel.redis', \Predis\Client::class)
            ->setArguments([[
                ['scheme' => 'tcp', 'host' => '127.0.0.1', 'port' => 6398, 'timeout' => 0.5],
            ], [
                'replication' => 'sentinel',
                'service' => 'mymaster',
            ]])
            ->setPublic(true);
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
                'public_base_url' => 'https://captcha.example.com',
                'replay_durability' => '%env('.self::POSTURE_ENV.')%',
                'redis_service' => 'runtime.sentinel.redis',
            ]);
        });
    }
}
