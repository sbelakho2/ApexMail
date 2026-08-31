<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Doctor scenario: the high_abuse protection profile with the decoy
 * surface explicitly deferred (risk.decoy_v3_enabled false overrides
 * the profile-derived true) and NO protocol rollout migration mode
 * declared (the default normal). The doctor must fail the protocol-v3
 * writer check: a false security switch does not itself prove the
 * deployment is deliberately in the two-phase v3 migration, so the
 * forgotten override must not silently persist. The migration
 * declaration turns the same configuration into the documented warn:
 * see DoctorHighAbuseDecoyDeferredKernel.
 */
final class DoctorHighAbuseDecoyDeferredNormalKernel extends DoctorV3WriterTestKernel
{
    protected function loadKiwiCaptcha(ContainerBuilder $container): void
    {
        $container->loadFromExtension('kiwi_captcha', [
            'secret_key' => self::SECRET,
            'difficulty_bits' => 8,
            'public_base_url' => 'https://captcha.example.com',
            'protection_profile' => 'high_abuse',
            'redis_service' => self::FAKE_REDIS_ID,
            'protocol_rollout' => [
                'mode' => 'normal',
            ],
            'risk' => [
                'namespace' => 'doctor-v3',
                'redis_service' => self::FAKE_REDIS_ID,
                'decoy_v3_enabled' => false,
            ],
        ]);
    }
}
