<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Test kernel variant for the explicit replay_durability "best_effort"
 * posture with a Predis Sentinel replication aggregate: the build
 * accepts it (best_effort is the current boundary) and the doctor
 * must keep the replication-topology warn with the posture named.
 */
class DoctorBestEffortSentinelTestKernel extends TestKernel
{
    protected function build(ContainerBuilder $container): void
    {
        parent::build($container);
        $container->register('doctor.sentinel.redis', \Predis\Client::class)
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
                'replay_durability' => 'best_effort',
                'redis_service' => 'doctor.sentinel.redis',
            ]);
        });
    }
}
