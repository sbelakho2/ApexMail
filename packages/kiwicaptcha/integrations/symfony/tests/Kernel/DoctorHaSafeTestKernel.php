<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Test kernel variant for the ha_safe protection profile: the profile
 * derives ha_authority "pinned_primary" + replay_durability
 * "operator_managed" and the mechanical guard is wired. With
 * $overrideNone the profile's derived ha_authority is explicitly
 * overridden to "none" in the same layer, which the doctor must fail
 * (the profile promises mechanical enforcement that is not active).
 */
class DoctorHaSafeTestKernel extends TestKernel
{
    public function __construct(string $environment, bool $debug, private readonly bool $overrideNone = false)
    {
        parent::__construct($environment, $debug);
    }

    protected function build(ContainerBuilder $container): void
    {
        parent::build($container);
        $container->register('doctor.hasafe.redis', FakePredisClient::class)
            ->setPublic(true);
    }

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
            $config = [
                'secret_key' => self::SECRET,
                'difficulty_bits' => 8,
                'public_base_url' => 'https://captcha.example.com',
                'protection_profile' => 'ha_safe',
                'redis_service' => 'doctor.hasafe.redis',
            ];
            if ($this->overrideNone) {
                $config['ha_authority'] = 'none';
            }
            $container->loadFromExtension('kiwi_captcha', $config);
        });
    }

    public function getCacheDir(): string
    {
        // The kernel cache is keyed on the class + environment, so the
        // override variant must carve its own cache directory or the
        // second test would reuse the first variant's compiled
        // container.
        return parent::getCacheDir().'-'.($this->overrideNone ? 'none' : 'hasafe');
    }
}
