<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * The signup scope names the email grant but the factor is disabled:
 * the doctor fails the carrier-factor check. The critical scope sits
 * on a rung with no carrier at all (its login gate was dropped), so
 * the pricing check hard-fails it in the same run.
 */
final class DoctorCarrierFailKernel extends DoctorCarrierTestKernel
{
    protected function loadKiwiCaptcha(ContainerBuilder $container): void
    {
        $config = $this->riskConfig(false);
        $config['risk']['scopes']['admin_login'] = ['id' => 30, 'value_class' => 'critical', 'minimum' => 'sha20'];
        $container->loadFromExtension('kiwi_captcha', $config);
    }
}
