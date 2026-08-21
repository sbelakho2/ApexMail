<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Kernel with the impossible combination (standard mode): telemetry off +
 * enforce_telemetry true. The extension must refuse to compile — an off
 * widget sends empty telemetry and enforcement rejects it, so every
 * legitimate solve would fail.
 */
final class ImpossibleTelemetryTestKernel extends TestKernel
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
                'telemetry' => 'off',
                'enforce_telemetry' => true,
            ]);
        });
    }
}
