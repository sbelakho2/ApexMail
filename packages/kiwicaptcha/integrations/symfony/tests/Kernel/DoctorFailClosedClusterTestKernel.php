<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Test kernel variant for the replay_durability "fail_closed" posture
 * with a Predis Redis Cluster aggregate wired as the storage/limiter
 * client. The extension must refuse the container build (a
 * LogicException naming the posture and the remediation), so booting
 * this kernel throws before the doctor can exist.
 */
class DoctorFailClosedClusterTestKernel extends TestKernel
{
    protected function build(ContainerBuilder $container): void
    {
        parent::build($container);
        // A three-node cluster shape (the nodes never connect): the
        // 'cluster' option builds the RedisCluster aggregate.
        $container->register('doctor.cluster.redis', \Predis\Client::class)
            ->setArguments([[
                'tcp://127.0.0.1:7001',
                'tcp://127.0.0.1:7002',
                'tcp://127.0.0.1:7003',
            ], [
                'cluster' => 'redis',
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
                'redis_service' => 'doctor.cluster.redis',
            ]);
        });
    }
}
