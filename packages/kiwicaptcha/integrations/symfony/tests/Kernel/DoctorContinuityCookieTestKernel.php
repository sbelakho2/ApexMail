<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Test kernel family for the doctor's continuity-cookie privacy check:
 * the risk layer is enabled (so the cookie is actually minted) with a
 * trusted proxy configured, and the concrete subclass decides the
 * cookie name/secure combination. The scheme-derived Secure flag
 * behind trusted proxies warns; a __Host- name (which forces Secure)
 * or an explicit secure: true passes.
 */
abstract class DoctorContinuityCookieTestKernel extends TestKernel
{
    protected function build(ContainerBuilder $container): void
    {
        parent::build($container);
        $container->register('doctor.cookie.fake.redis', FakePredisClient::class)
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
            $container->loadFromExtension('kiwi_captcha', [
                'secret_key' => self::SECRET,
                'difficulty_bits' => 8,
                'public_base_url' => 'https://captcha.example.com',
                'redis_service' => 'doctor.cookie.fake.redis',
                'risk' => array_merge(
                    ['enabled' => true, 'redis_service' => 'doctor.cookie.fake.redis'],
                    $this->riskOverrides(),
                ),
            ]);
        });
    }

    /**
     * @return array<string, mixed>
     */
    abstract protected function riskOverrides(): array;
}
