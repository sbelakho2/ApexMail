<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Test kernel variant for replay_durability "fail_closed" with an
 * opaque custom-factory client: the service has no inspectable class
 * and the factory returns an uninspectable object, so every build-time
 * lane treats it as "not proven aggregate" and the kernel boots. The
 * runtime authority-transition guard classifies the actual instance at
 * service construction and refuses it as unknown (unknown
 * authority-transition semantics are unsafe under fail_closed until
 * proven safe), which is the fail-closed invariant the build-time
 * classifier could not enforce.
 */
class FailClosedOpaqueFactoryClientTestKernel extends TestKernel
{
    protected function build(ContainerBuilder $container): void
    {
        parent::build($container);
        // The class is the container's static shape (required by
        // Symfony's CheckDefinitionValidityPass); the factory result is
        // the opaque instance the runtime classifier inspects.
        $container->register('runtime.opaque.redis', \stdClass::class)
            ->setFactory([self::class, 'opaqueClient'])
            ->setPublic(true);
    }

    /**
     * The opaque product: a non-Predis object whose topology the
     * classifier cannot inspect.
     */
    public static function opaqueClient(): object
    {
        return new class {
        };
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
                'replay_durability' => 'fail_closed',
                'redis_service' => 'runtime.opaque.redis',
            ]);
        });
    }
}
