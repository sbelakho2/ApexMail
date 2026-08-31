<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Doctor scenario: no protection profile (the default profile) with
 * the decoy surface explicitly enabled. The doctor must keep the
 * historical warn (exit 0) when the central floor is below 3 or
 * absent, because the two-phase rollout stays an operator action.
 */
final class DoctorExplicitV3WriterKernel extends DoctorV3WriterTestKernel
{
    protected function loadKiwiCaptcha(ContainerBuilder $container): void
    {
        $container->loadFromExtension('kiwi_captcha', [
            'secret_key' => self::SECRET,
            'difficulty_bits' => 8,
            'public_base_url' => 'https://captcha.example.com',
            'redis_service' => self::FAKE_REDIS_ID,
            'risk' => [
                // The risk array node is canBeEnabled(): any array form
                // auto-enables the engine, so the non-high_abuse
                // scenario declares the disabled posture explicitly.
                'enabled' => false,
                'namespace' => 'doctor-v3',
                'decoy_v3_enabled' => true,
            ],
        ]);
    }
}
