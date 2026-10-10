<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

/**
 * Kernel for the stage-composition wiring matrix: the adaptive risk
 * engine enabled over the fake Redis client, one target-carrying scope,
 * and the protection profile (plus optional risk-config overrides)
 * selected per instance. The fake never serves the risk Lua, so no
 * decision pipeline runs; the matrix reflects on the composed engine
 * arguments only.
 */
final class RiskStageMatrixTestKernel extends TestKernel
{
    /**
     * The shared ASN dataset fixture (the IPtoASN tsv shape): one
     * listed /8 and one listed /16, written once per process.
     */
    public static function asnFixturePath(): string
    {
        $path = sys_get_temp_dir().'/kiwicaptcha-asn-fixture.tsv';
        if (!\array_key_exists(__METHOD__, $GLOBALS) || !$GLOBALS[__METHOD__]) {
            file_put_contents($path, "# test dataset\n10.0.0.0\t10.255.255.255\t64512\n192.168.0.0\t192.168.255.255\t64513\n");
            $GLOBALS[__METHOD__] = true;
        }

        return $path;
    }

    public function __construct(
        string $environment,
        bool $debug,
        private readonly ?string $profile = null,
        private readonly array $riskOverrides = [],
        private readonly bool $withAsnDataset = true,
    ) {
        parent::__construct($environment, $debug);
    }

    public function getCacheDir(): string
    {
        return parent::getCacheDir().'-'.md5(serialize([$this->profile, $this->riskOverrides, $this->withAsnDataset]));
    }

    public function getLogDir(): string
    {
        return parent::getLogDir().'-'.md5(serialize([$this->profile, $this->riskOverrides, $this->withAsnDataset]));
    }

    public function registerContainerConfiguration(\Symfony\Component\Config\Loader\LoaderInterface $loader): void
    {
        $profile = $this->profile;
        $overrides = $this->riskOverrides;
        $withAsn = $this->withAsnDataset;
        $loader->load(function (\Symfony\Component\DependencyInjection\ContainerBuilder $container) use ($profile, $overrides, $withAsn): void {
            $container->register('fake_redis', \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient::class)
                ->setPublic(true);
            $container->loadFromExtension('framework', [
                'secret' => 'test-secret',
                'test' => true,
            ]);
            $risk = array_merge([
                'enabled' => true,
                'redis_service' => 'fake_redis',
                'scopes' => [
                    'login' => ['id' => 10, 'target_field' => 'username', 'value_class' => 'critical'],
                ],
            ], $withAsn ? ['asn' => ['dataset_path' => self::asnFixturePath()]] : [], $overrides);
            $container->loadFromExtension('kiwi_captcha', array_filter([
                'secret_key' => self::SECRET,
                'difficulty_bits' => 8,
                'protection_profile' => $profile,
                'risk' => $risk,
            ], static fn ($v): bool => $v !== null));
        });
    }
}
