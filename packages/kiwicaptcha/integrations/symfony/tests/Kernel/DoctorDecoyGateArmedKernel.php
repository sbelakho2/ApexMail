<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Doctor scenario: the decoy-escalation autofill-qualification gate
 * opened by the explicit configuration value
 * (risk.decoy_escalation.armed: true). The doctor must `WARN` about the
 * deliberate arm (never silently accept it) and must not fail: the
 * operator decision is the supported non-matrix path that keeps a
 * runtime security decision off the tests/ QA data.
 */
final class DoctorDecoyGateArmedKernel extends DoctorV3WriterTestKernel
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
                    'armed' => true,
                ],
            ],
        ]);
    }
}
