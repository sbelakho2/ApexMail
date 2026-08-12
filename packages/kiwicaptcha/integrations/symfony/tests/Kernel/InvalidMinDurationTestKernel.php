<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Invalid combination: min_duration_ms (20000) >= challenge_ttl_secs (10) *
 * 1000. A floor at or above the TTL leaves no acceptable submission time
 * (TooFast before expiry, Expired after) — the extension must refuse.
 */
final class InvalidMinDurationTestKernel extends TestKernel
{
    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(function (ContainerBuilder $container): void {
            $container->loadFromExtension('framework', [
                'secret' => 'test-secret',
                'test' => true,
            ]);
            $container->loadFromExtension('kiwi_captcha', [
                'secret_key' => self::SECRET,
                'difficulty_bits' => 8,
                'privacy_mode' => 'standard',
                'challenge_ttl_secs' => 10,
                'min_duration_ms' => 20_000,
            ]);
        });
    }
}
