<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Doctor scenario: the high_abuse protection profile with the decoy
 * surface derived from the profile (risk.decoy_v3_enabled true). The
 * doctor must fail the protocol-v3 writer check when the central floor
 * is absent or below 3, and pass once the floor confirms v3.
 */
final class DoctorHighAbuseV3WriterKernel extends DoctorV3WriterTestKernel
{
    protected function loadKiwiCaptcha(ContainerBuilder $container): void
    {
        $container->loadFromExtension('kiwi_captcha', [
            'secret_key' => self::SECRET,
            'difficulty_bits' => 8,
            'public_base_url' => 'https://captcha.example.com',
            'protection_profile' => 'high_abuse',
            'redis_service' => self::FAKE_REDIS_ID,
            'risk' => [
                'namespace' => 'doctor-v3',
                'redis_service' => self::FAKE_REDIS_ID,
            ],
        ]);
    }
}
