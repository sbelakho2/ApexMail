<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Invalid combination: rate_limit_rotation_secs (30) < rate_limit_window_secs
 * (120). A rotation shorter than the window would drop live hits from epochs
 * older than (current - 1) from the two-epoch accounting — the extension must
 * refuse to compile.
 */
final class InvalidRotationTestKernel extends TestKernel
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
                'rate_limit_rotation_secs' => 30,
                'rate_limit_window_secs' => 120,
            ]);
        });
    }
}
