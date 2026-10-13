<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Kernel family for the doctor's carrier checks. The scopes carry the
 * abuse-posture enforcement knobs: a critical scope carried by
 * login_step_up always, a low scope carried by the step_up_email
 * grant. Concrete kernels decide whether the named factors are wired,
 * so the doctor's value-class pricing accepts the carriers while the
 * carrier-factor check fails a dead-end carrier.
 */
abstract class DoctorCarrierTestKernel extends TestKernel
{
    public const FAKE_REDIS_ID = 'doctor.carrier.fake.redis';

    protected function build(ContainerBuilder $container): void
    {
        parent::build($container);
        $container->register(self::FAKE_REDIS_ID, FakePredisClient::class)
            ->setPublic(true);
        // The real delivery seams the carrier answerability audits: a
        // named carrier passes only when its codes actually leave the
        // deployment (never the logging dev sender).
        $container->register('doctor.carrier.ownership_sender', \BelConsulting\KiwiCaptchaBundle\Tests\Kernel\Fixtures\DoctorCarrierOwnershipSender::class)
            ->setPublic(true);
        $container->register('doctor.carrier.otp_sender', \BelConsulting\KiwiCaptchaBundle\Tests\Kernel\Fixtures\DoctorCarrierOtpSender::class)
            ->setPublic(true);
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(function (ContainerBuilder $container): void {
            $container->loadFromExtension('framework', [
                'secret' => 'test-secret',
                'test' => true,
                'router' => [
                    'resource' => __DIR__.'/Fixtures/doctor_carrier_routes.php',
                ],
            ]);
            $container->loadFromExtension('twig', [
                'form_themes' => ['@KiwiCaptcha/form_div_layout.html.twig'],
            ]);
            $this->loadKiwiCaptcha($container);
        });
    }

    abstract protected function loadKiwiCaptcha(ContainerBuilder $container): void;

    /**
     * The shared scope matrix: the critical admin scope prices beyond
     * its rung and is carried by the login gate; the low signup scope
     * is carried by the email grant. Both code factors carry real
     * senders, so a named carrier is answerable end to end.
     *
     * @return array<string, mixed>
     */
    protected function riskConfig(bool $emailOwnershipEnabled): array
    {
        return [
            'secret_key' => self::SECRET,
            'difficulty_bits' => 8,
            'public_base_url' => 'https://captcha.example.com',
            'redis_service' => self::FAKE_REDIS_ID,
            'risk' => [
                'namespace' => 'doctor-carrier',
                'redis_service' => self::FAKE_REDIS_ID,
                'scopes' => [
                    'admin_login' => ['id' => 30, 'value_class' => 'critical', 'login_step_up' => 'always'],
                    'signup' => ['id' => 31, 'value_class' => 'low', 'carrier' => 'step_up_email'],
                ],
                // The gate check audits the guard the login map arms,
                // and the default financial_action row names the totp
                // carrier, so the plane carries both named factors.
                'login_scopes' => ['main' => 'admin_login'],
                'step_up' => [
                    'enabled' => true,
                    'scope' => 'signup',
                    'default_handler' => 'email_otp',
                    'handlers' => [
                        'email_otp' => ['enabled' => true, 'sender' => 'doctor.carrier.otp_sender'],
                        'totp' => ['enabled' => true],
                    ],
                    'email_ownership' => [
                        'enabled' => $emailOwnershipEnabled,
                        'sender' => 'doctor.carrier.ownership_sender',
                    ],
                ],
            ],
        ];
    }
}
