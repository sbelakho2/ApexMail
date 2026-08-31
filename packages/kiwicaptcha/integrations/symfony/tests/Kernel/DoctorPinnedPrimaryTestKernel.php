<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Test kernel variant for ha_authority "pinned_primary": the storage /
 * limiter Redis client is a FakePredisClient, the pinned-primary guard
 * is wired around it, and the doctor reports the HA authority check
 * state (armed after the first verification pins the authority).
 */
class DoctorPinnedPrimaryTestKernel extends TestKernel
{
    protected function build(ContainerBuilder $container): void
    {
        parent::build($container);
        $container->register('doctor.pinned.redis', FakePredisClient::class)
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
                'ha_authority' => 'pinned_primary',
                'redis_service' => 'doctor.pinned.redis',
            ]);
        });
    }
}
