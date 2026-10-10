<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Doctor scenario: the decoy-escalation gate points at a versioned
 * qualification-matrix asset that does not exist. The doctor must fail
 * the asset validation: a configured pair is a runtime contract the
 * deploy gate checks, not a silent fallback.
 */
final class DoctorDecoyGateBrokenAssetKernel extends DoctorV3WriterTestKernel
{
    protected function loadKiwiCaptcha(ContainerBuilder $container): void
    {
        $container->loadFromExtension('kiwi_captcha', [
            'secret_key' => self::SECRET,
            'difficulty_bits' => 8,
            'public_base_url' => 'https://captcha.example.com',
            'protection_profile' => 'balanced',
            'redis_service' => self::FAKE_REDIS_ID,
            'risk' => [
                'namespace' => 'doctor-v3',
                'redis_service' => self::FAKE_REDIS_ID,
                'decoy_escalation' => [
                    'qualification_matrix' => '/nonexistent/autofill-matrix.json',
                ],
            ],
        ]);
    }
}
