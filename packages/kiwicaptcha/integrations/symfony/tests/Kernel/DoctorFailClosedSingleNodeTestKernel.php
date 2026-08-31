<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Test kernel variant for the replay_durability "fail_closed" posture
 * with a single-node direct Predis client: the build must accept it
 * (single-node direct clients are fine under every posture) and the
 * doctor must report the replication-topology check PASSing with the
 * posture noted.
 */
class DoctorFailClosedSingleNodeTestKernel extends TestKernel
{
    protected function build(ContainerBuilder $container): void
    {
        parent::build($container);
        // A plain standalone tcp connection to a dead port: Predis
        // connects lazily, so the wiring compiles and boots.
        $container->register('doctor.single.redis', \Predis\Client::class)
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
                'replay_durability' => 'fail_closed',
                'redis_service' => 'doctor.single.redis',
            ]);
        });
    }
}
