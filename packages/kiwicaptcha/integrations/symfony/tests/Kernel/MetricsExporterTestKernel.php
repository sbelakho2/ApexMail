<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Kernel with the metrics exporter armed: risk.metrics.secret carries a
 * literal 32-byte secret, so the route loader registers {prefix}/metrics
 * and the exporter authenticates against it. The disabled variant is the
 * plain {@see TestKernel} (a null secret leaves the route unregistered).
 */
final class MetricsExporterTestKernel extends TestKernel
{
    public const METRICS_SECRET = 'route-level-exporter-secret-0123456789';

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        parent::registerContainerConfiguration($loader);
        $loader->load(function (ContainerBuilder $container): void {
            $container->register('fake_redis', \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient::class)
                ->setPublic(true);
            $container->loadFromExtension('kiwi_captcha', [
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'fake_redis',
                    'metrics' => [
                        'secret' => self::METRICS_SECRET,
                    ],
                ],
            ]);
        });
    }
}
