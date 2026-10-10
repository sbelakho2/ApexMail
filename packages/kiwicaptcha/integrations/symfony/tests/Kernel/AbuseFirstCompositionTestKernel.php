<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

/**
 * Kernel for the full abuse_first composition end to end. The adaptive
 * risk engine runs over a genuine Redis, so the canonical risk-v1,
 * marks, trust and outcome Lua scripts execute for real. The kernel
 * arms the abuse_first protection profile, a target-carrying login
 * scope, a pricing-probe scope and the metrics exporter. The boot is
 * skipped when KC_REDIS_URL is absent, the same gate as the other
 * real-Redis integration tests.
 */
final class AbuseFirstCompositionTestKernel extends TestKernel
{
    public const METRICS_SECRET = 'metrics-exporter-secret-0123456789abcdef';

    public static function redisUrl(): ?string
    {
        $url = getenv('KC_REDIS_URL');

        return $url === false || $url === '' ? null : $url;
    }

    public function __construct(
        string $environment,
        bool $debug,
        private readonly string $riskNamespace = 'e2e-abuse-first',
    ) {
        parent::__construct($environment, $debug);
    }

    public function getCacheDir(): string
    {
        return parent::getCacheDir().'-'.md5($this->riskNamespace);
    }

    public function getLogDir(): string
    {
        return parent::getLogDir().'-'.md5($this->riskNamespace);
    }

    public function registerContainerConfiguration(\Symfony\Component\Config\Loader\LoaderInterface $loader): void
    {
        $url = self::redisUrl();
        $namespace = $this->riskNamespace;
        $loader->load(function (\Symfony\Component\DependencyInjection\ContainerBuilder $container) use ($url, $namespace): void {
            $container->setDefinition('kiwi_e2e_redis', new \Symfony\Component\DependencyInjection\Definition(
                \Predis\Client::class,
                [$url],
            ))->setPublic(true);
            $container->loadFromExtension('framework', [
                'secret' => 'test-secret',
                'test' => true,
            ]);
            $container->loadFromExtension('kiwi_captcha', [
                'secret_key' => self::SECRET,
                'difficulty_bits' => 8,
                // The change.md Part 5 name of the abuse posture: this
                // kernel is the living proof that the profile turns on
                // everything in Part 3.
                'protection_profile' => 'abuse_first',
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'kiwi_e2e_redis',
                    // The per-kernel namespace isolates the aggregate
                    // global state, so a storm leg starts from a quiet
                    // store no matter which legs ran before it.
                    'namespace' => $namespace,
                    'scopes' => [
                        'login' => ['id' => 10, 'target_field' => 'username'],
                        // The pricing probe: a scope whose plain band
                        // sits low enough that the price stage's trusted
                        // and untrusted terms land on visibly different
                        // ladder rungs.
                        'pricing_probe' => ['id' => 20, 'base_risk' => 220, 'minimum' => 'allow'],
                    ],
                    'asn' => ['dataset_path' => RiskStageMatrixTestKernel::asnFixturePath()],
                    'outcomes' => ['scope' => 'login'],
                    'metrics' => ['secret' => self::METRICS_SECRET],
                ],
            ]);
        });
    }
}
