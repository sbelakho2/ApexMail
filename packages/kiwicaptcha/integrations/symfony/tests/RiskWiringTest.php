<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Risk\PrincipalResolverInterface;
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
 * name, the calibrator receives the three bound knobs + the receipt TTL, the
 * engine receives enableGlobalPressure from global_pressure.enabled, the
 * provider is built with the issuance-counter key + client + hard limit (no
 * breaker — backend health is the engine's degraded mode), the controller
 * receives the issuance counter, and the gateway receives the request stack,
 * the decision-handle Redis wiring and (optionally) the principal resolver.
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

    public function testCalibratorReceivesTheBoundKnobsAndReceiptTtl(): void
    {
        $risk = $this->riskDefaults();
        $risk['calibration'] = ['enabled' => true, 'min_samples' => 500, 'max_adjustment' => 77, 'max_change_per_minute' => 5, 'receipt_ttl_secs' => 600];
        $container = $this->load($risk);

        $definition = $container->getDefinition('kiwi_captcha.risk.calibration');
        self::assertSame(AggregateCalibrator::class, $definition->getClass());
        $args = $definition->getArguments();
        self::assertInstanceOf(Reference::class, $args[0], 'arg 0 = the risk Predis client');
        self::assertSame('wiring-test', $args[1], 'arg 1 = the risk namespace');
        self::assertSame(500, $args[2], 'arg 2 = min_samples');
        self::assertSame(77, $args[3], 'arg 3 = max_adjustment');
        self::assertSame(5, $args[4], 'arg 4 = max_change_per_minute');
        self::assertSame(600, $args[5], 'arg 5 = receipt_ttl_secs (the AggregateCalibrator ctor position after maxChangePerMinute)');

        // The default receipt TTL is the audit's 300 s.
        $risk = $this->riskDefaults();
        $risk['calibration'] = ['enabled' => true];
        $defaults = $this->load($risk)->getDefinition('kiwi_captcha.risk.calibration')->getArguments();
        self::assertSame(300, $defaults[5], 'receipt_ttl_secs defaults to 300');

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

    public function testProviderWiredWithCounterKeyClientAndHardLimit(): void
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

        // The breaker is hoisted for the ENGINE's degraded mode only — the
        // provider no longer consumes it (no riskBackendHealth field).
        self::assertTrue($container->hasDefinition('kiwi_captcha.risk.breaker'));
        self::assertSame('kiwi_captcha.risk.breaker', (string) $container->getDefinition('kiwi_captcha.risk.engine')->getArgument('$breaker'));
    }

    public function testGatewayReceivesDecisionHandleWiringAndRequestStack(): void
    {
        $container = $this->load($this->riskDefaults());

        $gateway = $container->getDefinition(RiskGateway::class);
        self::assertSame('request_stack', (string) $gateway->getArgument('$requestStack'), 'the gateway resolves the request principal via the request stack');
        self::assertSame('fake_redis', (string) $gateway->getArgument('$decisionRedis'), 'the nonce->decision handles live in the risk Redis');
        self::assertSame('{kiwi:wiring-test}:decision:', $gateway->getArgument('$decisionKeyPrefix'), 'the handle key prefix is hash-tagged with the risk namespace');
        self::assertSame(300, $gateway->getArgument('$decisionTtlSecs'), 'the handle TTL follows calibration.receipt_ttl_secs (default 300)');
        self::assertArrayNotHasKey('$principalResolver', $gateway->getArguments(), 'no principal resolver wired by default');
        self::assertSame('kiwi_captcha.risk.policy', (string) $gateway->getArgument('$policy'), 'the gateway receives the policy for the degraded fallback');

        $risk = $this->riskDefaults();
        $risk['calibration'] = ['enabled' => true, 'receipt_ttl_secs' => 900];
        $container = $this->load($risk);
        self::assertSame(900, $container->getDefinition(RiskGateway::class)->getArgument('$decisionTtlSecs'), 'the handle TTL follows the configured receipt_ttl_secs');
    }

    public function testGatewayReceivesPrincipalResolverWhenServiceExists(): void
    {
        $container = $this->load($this->riskDefaults());
        self::assertFalse($container->has(PrincipalResolverInterface::class));

        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->register('fake_redis', FakePredisClient::class);
        $container->register(PrincipalResolverInterface::class, \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePrincipalResolver::class);
        (new KiwiCaptchaExtension())->load([[
            'secret_key' => self::SECRET,
            'difficulty_bits' => 8,
            'risk' => $this->riskDefaults(),
        ]], $container);

        $resolverRef = $container->getDefinition(RiskGateway::class)->getArgument('$principalResolver');
        self::assertInstanceOf(Reference::class, $resolverRef);
        self::assertSame(PrincipalResolverInterface::class, (string) $resolverRef, 'a registered principal resolver must be injected into the gateway');
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
