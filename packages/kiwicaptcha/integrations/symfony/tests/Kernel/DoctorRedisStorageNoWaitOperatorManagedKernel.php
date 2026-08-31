<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use KiwiCaptcha\Storage\RedisStorage;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Test kernel variant for the replay_durability "operator_managed"
 * posture with Redis-backed storage (RedisStorage over a dead-port
 * direct client) and waitReplicas 0. A single-node direct client, so
 * the build accepts it under every posture and the doctor must report
 * the replication-topology check PASSing with the operator contract
 * noted.
 */
class DoctorRedisStorageNoWaitOperatorManagedKernel extends TestKernel
{
    protected function build(ContainerBuilder $container): void
    {
        parent::build($container);
        $container->register('doctor.dead.redis', \Predis\Client::class)
            ->setArguments([[
                'scheme' => 'tcp',
                'host' => '127.0.0.1',
                'port' => 6398,
                'timeout' => 0.5,
            ]])
            ->setPublic(true);
        $container->register(RedisStorage::class, RedisStorage::class)
            ->setArguments([new Reference('doctor.dead.redis'), 'kiwicaptcha:'])
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
                'replay_durability' => 'operator_managed',
                'storage' => RedisStorage::class,
            ]);
        });
    }
}
