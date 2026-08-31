<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Test kernel variant whose Redis client points at a dead port: the
 * doctor command's Redis reachability check must fail deterministically
 * (connection refused on PING), exercising the failed-check exit-code
 * path.
 */
class DoctorFailingRedisTestKernel extends TestKernel
{
    protected function build(ContainerBuilder $container): void
    {
        parent::build($container);
        // Port 6398 has no listener; Predis fails on connect with a
        // connection-refused exception, so PING can never succeed.
        $container->register('doctor.failing.redis', \Predis\Client::class)
            ->setArguments([[
                'scheme' => 'tcp',
                'host' => '127.0.0.1',
                'port' => 6398,
                'timeout' => 0.5,
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
                'redis_service' => 'doctor.failing.redis',
                // The risk layer shares the same broken client, so the
                // risk Redis check FAILs too. The explicit risk
                // redis_service is required: the extension runs inside a
                // temporary container during compilation and cannot
                // inspect kernel-level definitions, so the bundle-client
                // reuse path would refuse the invisible class.
                'risk' => ['enabled' => true, 'redis_service' => 'doctor.failing.redis'],
            ]);
        });
    }
}
