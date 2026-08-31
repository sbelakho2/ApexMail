<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Doctor scenario: the profile resolution is the lowest-precedence
 * layer, so the doctor must honor the final processed values. The
 * first layer selects high_abuse; the second layer (the documented
 * prod-overlay shape) carries `protection_profile: null`, which clears
 * the profile, plus the explicit decoy override. The effective profile
 * is therefore null, the effective risk.decoy_v3_enabled is true, and
 * the doctor must warn (exit 0) on a sub-v3 floor, never fail, since
 * high_abuse is no longer the effective profile.
 */
final class DoctorNullClearedProfileV3WriterKernel extends DoctorV3WriterTestKernel
{
    protected function loadKiwiCaptcha(ContainerBuilder $container): void
    {
        $container->loadFromExtension('kiwi_captcha', [
            'protection_profile' => 'high_abuse',
        ]);
        $container->loadFromExtension('kiwi_captcha', [
            'secret_key' => self::SECRET,
            'difficulty_bits' => 8,
            'public_base_url' => 'https://captcha.example.com',
            'protection_profile' => null,
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
