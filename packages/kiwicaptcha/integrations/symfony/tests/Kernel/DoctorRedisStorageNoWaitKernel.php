<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use KiwiCaptcha\Storage\RedisStorage;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Test kernel variant with Redis-backed storage (RedisStorage over a
 * dead-port client) and no verified-WAIT knob (the risk.redis
 * wait_replicas default is 0): the doctor command's
 * replication-topology check must warn, because the promotion
 * boundary applies with no cross-authority replay guarantee. The
 * storage constructor connects lazily, so the wiring compiles and
 * boots without a live Redis.
 */
class DoctorRedisStorageNoWaitKernel extends TestKernel
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
                'storage' => RedisStorage::class,
            ]);
        });
    }
}
