<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Test kernel variant for the replay_durability "fail_closed" posture
 * with a Predis Sentinel replication aggregate wired as the
 * storage/limiter client. The extension must refuse the container
 * build (a LogicException naming the posture and the remediation),
 * so booting this kernel throws before the doctor can exist.
 */
class DoctorFailClosedSentinelTestKernel extends TestKernel
{
    protected function build(ContainerBuilder $container): void
    {
        parent::build($container);
        // The same dead-port sentinel aggregate the best-effort kernel
        // uses: Predis builds the aggregate eagerly and connects lazily.
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
                'replay_durability' => 'fail_closed',
                'redis_service' => 'doctor.sentinel.redis',
            ]);
        });
    }
}
