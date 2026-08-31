<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Kernel family for the doctor's protocol-v3 writer gate scenarios.
 * The wired storage/limiter Redis and the risk Redis are the same
 * in-memory fake (FakePredisClient). The test seeds that fake's
 * `{kiwi:<ns>}:security-policy` hash with the central
 * `min_protocol_version` floor before executing the doctor, so the
 * writer gate sees a confirmed, sub-v3 or absent floor without live
 * Redis. Concrete subclasses differ only in the kiwi_captcha config
 * (profile, explicit decoy override), so each scenario boots its own
 * cached container.
 */
abstract class DoctorV3WriterTestKernel extends TestKernel
{
    public const FAKE_REDIS_ID = 'doctor.v3writer.fake.redis';

    /** The fixed risk namespace, so the policy key is deterministic. */
    public const POLICY_KEY = '{kiwi:doctor-v3}:security-policy';

    protected function build(ContainerBuilder $container): void
    {
        parent::build($container);
        $container->register(self::FAKE_REDIS_ID, FakePredisClient::class)
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
            $this->loadKiwiCaptcha($container);
        });
    }

    abstract protected function loadKiwiCaptcha(ContainerBuilder $container): void;
}
