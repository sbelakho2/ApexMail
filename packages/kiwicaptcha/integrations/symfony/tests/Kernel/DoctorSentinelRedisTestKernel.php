<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Test kernel variant whose wired storage/limiter Redis client is a
 * Predis Sentinel replication aggregate pointing at a dead sentinel
 * port: the doctor command's replication-topology check must warn
 * (the failover topology has no cross-authority replay guarantee),
 * without needing a live sentinel. Predis builds the aggregate
 * eagerly and connects lazily, so the client class is detectable and
 * the reachability check fails deterministically on PING.
 */
class DoctorSentinelRedisTestKernel extends TestKernel
{
    protected function build(ContainerBuilder $container): void
    {
        parent::build($container);
        // Port 6398 has no listener: the sentinel aggregate is built
        // without connecting, and any command fails on connect with a
        // connection-refused exception.
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
                // The explicit client service id: the extension cannot
                // inspect kernel-level definitions, so the DSN-build
                // path is not involved and the aggregate is wired
                // verbatim.
                'redis_service' => 'doctor.sentinel.redis',
            ]);
        });
    }
}
