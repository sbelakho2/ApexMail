<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use KiwiCaptcha\Tests\Support\RswFixture;

/**
 * Doctor scenario: the optional rsw time-lock algorithm armed with the
 * shared fixture trapdoor pair (the same keys the core tests embed).
 * The container compile proves the full trapdoor configuration is
 * valid, and the doctor reports the armed rsw posture as passing.
 */
final class DoctorRswArmedTestKernel extends TestKernel
{
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
                'algorithm' => 'rsw',
                'rsw_modulus_n' => RswFixture::MODULUS_N_B64,
                'rsw_lambda' => RswFixture::LAMBDA_B64,
                'rsw_t' => 10_000,
            ]);
        });
    }
}
