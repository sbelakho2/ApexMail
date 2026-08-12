<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisRiskHealthProvider;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceCounter;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Risk\Calibration\AggregateCalibrator;
use KiwiCaptcha\Risk\Storage\ProcessEmergencyCap;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * The risk wiring contract at the definition level (extension load, no
 * container compile): the emergency limiter uses the NEW ProcessEmergencyCap
 * name, the calibrator receives the three bound knobs, the engine receives
 * enableGlobalPressure from global_pressure.enabled, the provider is built
 * with the issuance-counter key + client + breaker + hard limit, and the
 * controller receives the issuance counter.
 */
final class RiskWiringTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private function load(array $risk): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->register('fake_redis', FakePredisClient::class);
        (new KiwiCaptchaExtension())->load([[
            'secret_key' => self::SECRET,
            'difficulty_bits' => 8,
            'risk' => $risk,
        ]], $container);

        return $container;
    }

    private function riskDefaults(): array
    {
        return [
            'enabled' => true,
            'redis_service' => 'fake_redis',
            'namespace' => 'wiring-test',
            'scopes' => ['login' => ['id' => 10]],
        ];
    }

    public function testEmergencyLimiterUsesProcessEmergencyCapWithHardLimits(): void
    {
        $container = $this->load($this->riskDefaults());

        $definition = $container->getDefinition('kiwi_captcha.risk.emergency_limiter');
        self::assertSame(ProcessEmergencyCap::class, $definition->getClass(), 'the bundle must use the NEW ProcessEmergencyCap class name');
        self::assertSame([100, 10000], $definition->getArguments(), 'args = hard_limits.source_per_second, hard_limits.global_per_second');
    }

    public function testCalibratorReceivesTheThreeBoundKnobs(): void
    {
        $risk = $this->riskDefaults();
        $risk['calibration'] = ['enabled' => true, 'min_samples' => 500, 'max_adjustment' => 77, 'max_change_per_minute' => 5];
        $container = $this->load($risk);

        $definition = $container->getDefinition('kiwi_captcha.risk.calibration');
        self::assertSame(AggregateCalibrator::class, $definition->getClass());
        $args = $definition->getArguments();
        self::assertInstanceOf(Reference::class, $args[0], 'arg 0 = the risk Predis client');
        self::assertSame('wiring-test', $args[1], 'arg 1 = the risk namespace');
        self::assertSame(500, $args[2], 'arg 2 = min_samples');
        self::assertSame(77, $args[3], 'arg 3 = max_adjustment');
        self::assertSame(5, $args[4], 'arg 4 = max_change_per_minute');

        // Without calibration.enabled the service must not exist.
        $container = $this->load($this->riskDefaults());
        self::assertFalse($container->hasDefinition('kiwi_captcha.risk.calibration'));
    }

    public function testEngineReceivesEnableGlobalPressureFromConfig(): void
    {
        $risk = $this->riskDefaults();
        $container = $this->load($risk);
        self::assertTrue($container->getDefinition('kiwi_captcha.risk.engine')->getArgument('$enableGlobalPressure'), 'global_pressure.enabled defaults to true');

        $risk['global_pressure'] = ['enabled' => false, 'hysteresis_secs' => 30];
        $container = $this->load($risk);
        self::assertFalse($container->getDefinition('kiwi_captcha.risk.engine')->getArgument('$enableGlobalPressure'), 'enableGlobalPressure must follow global_pressure.enabled');
    }

    public function testProviderWiredWithCounterKeyClientBreakerAndHardLimit(): void
    {
        $risk = $this->riskDefaults();
        $risk['hard_limits'] = ['source_per_second' => 50, 'global_per_second' => 250];
        $container = $this->load($risk);

        $definition = $container->getDefinition('kiwi_captcha.risk.resource_pressure');
        self::assertSame(RedisRiskHealthProvider::class, $definition->getClass());
        $args = $definition->getArguments();
        self::assertNull($args[0], 'no argon semaphore wired (sha256) -> null');
        self::assertInstanceOf(Reference::class, $args[1], 'arg 1 = the risk Redis client for the counter reads');
        self::assertSame('{kiwi:wiring-test}:issuance:', $args[2], 'arg 2 = the issuance counter key prefix (hash-tagged)');
        self::assertSame(250, $args[3], 'arg 3 = hard_limits.global_per_second');
        self::assertSame('kiwi_captcha.risk.breaker', (string) $args[4], 'arg 4 = the shared circuit breaker');

        // The breaker is a hoisted service shared by engine and provider.
        self::assertTrue($container->hasDefinition('kiwi_captcha.risk.breaker'));
        self::assertSame('kiwi_captcha.risk.breaker', (string) $container->getDefinition('kiwi_captcha.risk.engine')->getArgument('$breaker'));
    }

    public function testIssuanceCounterServiceAndControllerWiring(): void
    {
        $container = $this->load($this->riskDefaults());

        $counter = $container->getDefinition('kiwi_captcha.risk.issuance_counter');
        self::assertSame(IssuanceCounter::class, $counter->getClass());
        $args = $counter->getArguments();
        self::assertInstanceOf(Reference::class, $args[0]);
        self::assertSame('{kiwi:wiring-test}:issuance:', $args[1]);

        $controllerArgs = $container->getDefinition(ChallengeController::class)->getArguments();
        self::assertSame('kiwi_captcha.risk.issuance_counter', (string) $controllerArgs[5], 'the controller receives the issuance counter');
    }

    public function testGatewayReceivesBaselineUnknownScopeModeByDefault(): void
    {
        $container = $this->load($this->riskDefaults());
        self::assertSame('baseline', $container->getDefinition(RiskGateway::class)->getArgument('$unknownScopeMode'));

        $risk = $this->riskDefaults();
        $risk['unknown_scope'] = ['mode' => 'reject'];
        $container = $this->load($risk);
        self::assertSame('reject', $container->getDefinition(RiskGateway::class)->getArgument('$unknownScopeMode'));
    }
}
