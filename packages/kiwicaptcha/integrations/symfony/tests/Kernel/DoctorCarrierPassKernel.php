<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Both named factors are wired: the pricing accepts the login gate and
 * the email grant as carriers, and the carrier-factor check passes.
 */
final class DoctorCarrierPassKernel extends DoctorCarrierTestKernel
{
    protected function loadKiwiCaptcha(ContainerBuilder $container): void
    {
        $container->loadFromExtension('kiwi_captcha', $this->riskConfig(true));
    }
}
