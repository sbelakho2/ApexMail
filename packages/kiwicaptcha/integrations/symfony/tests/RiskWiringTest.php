<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Risk\PrincipalResolverInterface;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisRiskHealthProvider;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceCounter;
use BelConsulting\KiwiCaptchaBundle\Security\OutstandingChallenges;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Risk\Calibration\AggregateCalibrator;
use KiwiCaptcha\Risk\Storage\ProcessEmergencyCap;
use KiwiCaptcha\Storage\RedisStorage;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * The risk wiring contract at the definition level (extension load, no
 * container compile): the emergency limiter uses the NEW ProcessEmergencyCap
 * name. The calibrator receives the three bound knobs plus the outcome
 * receipt/ledger TTL (outcome_receipt_ttl_secs -> receiptTtlSecs and
 * the appended outcomeTtlSecs). The store receives
 * the outcome-ledger TTL, the engine receives enableGlobalPressure from
 * global_pressure.enabled, the provider gets the issuance-counter key +
 * client + hard limit (no breaker — backend health is the engine's
 * degraded mode), and the controller receives the issuance counter. The
 * gateway receives the request stack, the decision-handle Redis wiring
 * (TTL = risk.nonce_to_decision_ttl_secs), the calibrator when enabled
 * and (optionally) the principal resolver.
 */
final class RiskWiringTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private function load(array $risk, array $topLevel = [], ?\Closure $register = null): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->register('fake_redis', FakePredisClient::class);
        if ($register !== null) {
            $register($container);
        }
        (new KiwiCaptchaExtension())->load([[
            'secret_key' => self::SECRET,
            'difficulty_bits' => 8,
            'risk' => $risk,
            ...$topLevel,
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

    public function testEmergencyLimiterUsesProcessEmergencyCapWithSingleHardLimit(): void
    {
        $container = $this->load($this->riskDefaults());

        $definition = $container->getDefinition('kiwi_captcha.risk.emergency_limiter');
        self::assertSame(ProcessEmergencyCap::class, $definition->getClass(), 'the bundle must use the NEW ProcessEmergencyCap class name');
        self::assertSame([10000], $definition->getArguments(), 'args = [hard_limits.process_per_second] (the single per-process cap)');
    }

    public function testCalibratorReceivesTheBoundKnobsOutcomeTtlAndSamplingContract(): void
    {
        $risk = $this->riskDefaults();
        $risk['calibration'] = ['enabled' => true, 'min_samples' => 500, 'max_adjustment' => 77, 'max_change_per_minute' => 5, 'outcome_receipt_ttl_secs' => 43200];
        $container = $this->load($risk);

        $definition = $container->getDefinition('kiwi_captcha.risk.calibration');
        self::assertSame(AggregateCalibrator::class, $definition->getClass());
        $args = $definition->getArguments();
        self::assertInstanceOf(Reference::class, $args[0], 'arg 0 = the risk Predis client');
        self::assertSame('wiring-test', $args[1], 'arg 1 = the risk namespace');
        self::assertSame(500, $args[2], 'arg 2 = min_samples');
        self::assertSame(77, $args[3], 'arg 3 = max_adjustment');
        self::assertSame(5, $args[4], 'arg 4 = max_change_per_minute');
        self::assertSame(43200, $args[5], 'arg 5 = receiptTtlSecs (the AggregateCalibrator ctor position after maxChangePerMinute) follows outcome_receipt_ttl_secs');
        self::assertSame('random_sample', $args['$samplingMode'], 'samplingMode follows calibration.mode (default random_sample)');
        self::assertSame(100000, $args['$samplingProbabilityPpm'], 'samplingProbabilityPpm follows calibration.sampling_probability_ppm (default 100000)');
        self::assertSame(0.8, $args['$minimumResolutionRatio'], 'minimumResolutionRatio follows calibration.minimum_resolution_ratio (default 0.80 — the resolution gate)');
        self::assertSame(1.0, $args['$falsePositiveCost'], 'falsePositiveCost follows calibration.false_positive_cost (default 1.0)');
        self::assertSame(2.0, $args['$falseNegativeCost'], 'falseNegativeCost follows calibration.false_negative_cost (default 2.0)');
        self::assertSame(43200, $args['$outcomeTtlSecs'], 'outcomeTtlSecs (appended AggregateCalibrator ctor param) follows outcome_receipt_ttl_secs');

        // Explicit sampling config flows through to the calibrator.
        $risk = $this->riskDefaults();
        $risk['calibration'] = ['enabled' => true, 'mode' => 'weighted', 'sampling_probability_ppm' => 500000];
        $args = $this->load($risk)->getDefinition('kiwi_captcha.risk.calibration')->getArguments();
        self::assertSame('weighted', $args['$samplingMode']);
        self::assertSame(500000, $args['$samplingProbabilityPpm']);

        // Explicit resolution-gate / class-cost knobs flow through to the
        // calibrator.
        $risk = $this->riskDefaults();
        $risk['calibration'] = ['enabled' => true, 'minimum_resolution_ratio' => 0.5, 'false_positive_cost' => 2.5, 'false_negative_cost' => 3.75];
        $args = $this->load($risk)->getDefinition('kiwi_captcha.risk.calibration')->getArguments();
        self::assertSame(0.5, $args['$minimumResolutionRatio']);
        self::assertSame(2.5, $args['$falsePositiveCost']);
        self::assertSame(3.75, $args['$falseNegativeCost']);

        // The default outcome TTL is the 24 h outcome/receipt lifetime.
        $risk = $this->riskDefaults();
        $risk['calibration'] = ['enabled' => true];
        $defaults = $this->load($risk)->getDefinition('kiwi_captcha.risk.calibration')->getArguments();
        self::assertSame(86400, $defaults[5], 'receiptTtlSecs defaults to outcome_receipt_ttl_secs (86400)');
        self::assertSame(86400, $defaults['$outcomeTtlSecs'], 'outcomeTtlSecs defaults to outcome_receipt_ttl_secs (86400)');

        // Without calibration.enabled the service must not exist.
        $container = $this->load($this->riskDefaults());
        self::assertFalse($container->hasDefinition('kiwi_captcha.risk.calibration'));
    }

    public function testStateStoreReceivesTheOutcomeTtl(): void
    {
        $container = $this->load($this->riskDefaults());
        self::assertSame(86400, $container->getDefinition('kiwi_captcha.risk.store')->getArgument('$outcomeTtlSecs'), 'the store outcome-ledger TTL follows outcome_receipt_ttl_secs (default 86400)');

        $risk = $this->riskDefaults();
        $risk['calibration'] = ['outcome_receipt_ttl_secs' => 172800];
        $container = $this->load($risk);
        self::assertSame(172800, $container->getDefinition('kiwi_captcha.risk.store')->getArgument('$outcomeTtlSecs'), 'the store outcome-ledger TTL follows the configured outcome_receipt_ttl_secs');
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

    public function testProviderWiredWithCounterKeyClientAndDeploymentCapacity(): void
    {
        $risk = $this->riskDefaults();
        $risk['hard_limits'] = ['process_per_second' => 250];
        $container = $this->load($risk);

        $definition = $container->getDefinition('kiwi_captcha.risk.resource_pressure');
        self::assertSame(RedisRiskHealthProvider::class, $definition->getClass());
        $args = $definition->getArguments();
        self::assertNull($args[0], 'no argon semaphore wired (sha256) -> null');
        self::assertInstanceOf(Reference::class, $args[1], 'arg 1 = the risk Redis client for the counter reads');
        self::assertSame('{kiwi:wiring-test}:issuance:', $args[2], 'arg 2 = the issuance counter key prefix (hash-tagged)');
        self::assertSame(500, $args[3], 'arg 3 = resource_capacity.issuance_per_second (the DEPLOYMENT-WIDE denominator, default 500, aligned with the hard global limiter)');

        // The deployment denominator is a separate knob from the per-process
        // emergency cap: hard_limits.process_per_second stays exclusively on
        // the emergency limiter.
        $risk = $this->riskDefaults();
        $risk['hard_limits'] = ['process_per_second' => 999];
        $container = $this->load($risk, ['resource_capacity' => ['issuance_per_second' => 12345]]);
        self::assertSame(12345, $container->getDefinition('kiwi_captcha.risk.resource_pressure')->getArguments()[3], 'the provider denominator follows resource_capacity.issuance_per_second (root-level node)');
        self::assertSame([999], $container->getDefinition('kiwi_captcha.risk.emergency_limiter')->getArguments(), 'hard_limits.process_per_second remains ONLY the local emergency cap');

        // The breaker is hoisted for the engine's degraded mode only — the
        // provider no longer consumes it (no riskBackendHealth field).
        self::assertTrue($container->hasDefinition('kiwi_captcha.risk.breaker'));
        self::assertSame('kiwi_captcha.risk.breaker', (string) $container->getDefinition('kiwi_captcha.risk.engine')->getArgument('$breaker'));
    }

    public function testGatewayReceivesDecisionHandleWiringAndRequestStack(): void
    {
        $container = $this->load($this->riskDefaults());

        $gateway = $container->getDefinition(RiskGateway::class);
        self::assertSame('request_stack', (string) $gateway->getArgument('$requestStack'), 'the gateway resolves the request principal via the request stack');
        self::assertSame('kiwi_captcha.redis.checked.risk', (string) $gateway->getArgument('$decisionRedis'), 'the nonce->decision handles live in the checked risk Redis');
        self::assertSame('{kiwi:wiring-test}:decision:', $gateway->getArgument('$decisionKeyPrefix'), 'the handle key prefix is hash-tagged with the risk namespace');
        self::assertSame(300, $gateway->getArgument('$decisionTtlSecs'), 'the handle TTL follows risk.nonce_to_decision_ttl_secs (default 300)');
        self::assertArrayNotHasKey('$principalResolver', $gateway->getArguments(), 'no principal resolver wired by default');
        self::assertSame('kiwi_captcha.risk.policy', (string) $gateway->getArgument('$policy'), 'the gateway receives the policy for the degraded fallback');
        self::assertNull($gateway->getArgument('$calibration'), 'no calibration store wired while calibration is disabled');

        $risk = $this->riskDefaults();
        $risk['nonce_to_decision_ttl_secs'] = 900;
        $container = $this->load($risk);
        self::assertSame(900, $container->getDefinition(RiskGateway::class)->getArgument('$decisionTtlSecs'), 'the handle TTL follows the configured risk.nonce_to_decision_ttl_secs');

        // Calibration.enabled wires the calibration store into the gateway
        // (samplingMetrics delegates to it).
        $risk = $this->riskDefaults();
        $risk['calibration'] = ['enabled' => true];
        $container = $this->load($risk);
        $calibrationArg = $container->getDefinition(RiskGateway::class)->getArgument('$calibration');
        self::assertInstanceOf(Reference::class, $calibrationArg);
        self::assertSame('kiwi_captcha.risk.calibration', (string) $calibrationArg, 'the enabled calibrator is injected into the gateway');
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

    public function testGatewayReceivesMinimumUnknownScopeModeByDefault(): void
    {
        $container = $this->load($this->riskDefaults());
        self::assertSame('minimum', $container->getDefinition(RiskGateway::class)->getArgument('$unknownScopeMode'), 'unknown_scope.mode defaults to minimum (synthetic sha20 policy for scope typos)');

        $risk = $this->riskDefaults();
        $risk['unknown_scope'] = ['mode' => 'reject'];
        $container = $this->load($risk);
        self::assertSame('reject', $container->getDefinition(RiskGateway::class)->getArgument('$unknownScopeMode'));
    }

    public function testRegionFlowsToIssuerAndVerifierOnlyWhenConfigured(): void
    {
        // Default: region null — the optional core $region params must NOT
        // be set at all (older cores stay untouched).
        $container = $this->load($this->riskDefaults());
        self::assertArrayNotHasKey('$region', $container->getDefinition('kiwi_captcha.issuer')->getArguments(), 'no region configured: the issuer definition must not carry a $region arg');
        self::assertArrayNotHasKey('$region', $container->getDefinition('kiwi_captcha.verifier')->getArguments(), 'no region configured: the verifier definition must not carry a $region arg');

        // Configured region: baked into issued challenges by the issuer and
        // enforced at verification by the verifier (failover-replay Option A).
        $risk = $this->riskDefaults();
        $risk['region'] = 'eu-central-1';
        $container = $this->load($risk);
        self::assertSame('eu-central-1', $container->getDefinition('kiwi_captcha.issuer')->getArgument('$region'), 'risk.region must reach the core Issuer ($region)');
        self::assertSame('eu-central-1', $container->getDefinition('kiwi_captcha.verifier')->getArgument('$region'), 'risk.region must reach the core Verifier ($region)');
    }

    public function testRedisStorageReceivesWaitAndTtlMarginParamsWhenOptedIn(): void
    {
        $registerRedisStorage = static function (ContainerBuilder $c): void {
            $c->register('my.redis.storage', RedisStorage::class)
                ->setArguments([new Reference('fake_redis'), 'kiwicaptcha:']);
        };

        // The risk.redis knobs target the challenge storage when it is a
        // RedisStorage definition. Opting out (defaults) must leave the
        // definition untouched (older cores stay compatible).
        $container = $this->load($this->riskDefaults(), ['storage' => 'my.redis.storage'], $registerRedisStorage);
        self::assertArrayNotHasKey('$waitReplicas', $container->getDefinition('my.redis.storage')->getArguments(), 'default wait_replicas=0/ttl_margin_secs=0: the storage definition must not be touched');

        $risk = $this->riskDefaults();
        $risk['redis'] = ['wait_replicas' => 2, 'wait_timeout_ms' => 500, 'ttl_margin_secs' => 30];
        $container = $this->load($risk, ['storage' => 'my.redis.storage'], $registerRedisStorage);
        $args = $container->getDefinition('my.redis.storage')->getArguments();
        self::assertSame(2, $args['$waitReplicas'], 'wait_replicas must reach the RedisStorage definition ($waitReplicas)');
        self::assertSame(500, $args['$waitTimeoutMs'], 'wait_timeout_ms must reach the RedisStorage definition ($waitTimeoutMs)');
        self::assertSame(30, $args['$ttlMarginSecs'], 'ttl_margin_secs must reach the RedisStorage definition ($ttlMarginSecs)');

        // ttl_margin alone also opts in (wait stays disabled).
        $risk = $this->riskDefaults();
        $risk['redis'] = ['ttl_margin_secs' => 60];
        $container = $this->load($risk, ['storage' => 'my.redis.storage'], $registerRedisStorage);
        $args = $container->getDefinition('my.redis.storage')->getArguments();
        self::assertSame(0, $args['$waitReplicas']);
        self::assertSame(100, $args['$waitTimeoutMs']);
        self::assertSame(60, $args['$ttlMarginSecs']);

        // A NON-RedisStorage storage definition is never touched.
        $container = $this->load($this->riskDefaults(), ['storage' => 'my.pool.storage'], static function (ContainerBuilder $c): void {
            $c->register('my.pool.storage', \KiwiCaptcha\Storage\ArrayStorage::class);
        });
        self::assertArrayNotHasKey('$waitReplicas', $container->getDefinition('my.pool.storage')->getArguments());
    }

    public function testOutstandingChallengesServiceWiredWithCapsAndMargin(): void
    {
        $risk = $this->riskDefaults();
        $risk['max_outstanding_challenges'] = 7;
        $risk['max_outstanding_challenges_global'] = 12345;
        $risk['redis'] = ['ttl_margin_secs' => 45];
        $container = $this->load($risk);

        $definition = $container->getDefinition('kiwi_captcha.risk.outstanding');
        self::assertSame(OutstandingChallenges::class, $definition->getClass());
        $args = $definition->getArguments();
        self::assertInstanceOf(Reference::class, $args[0], 'arg 0 = the risk Predis client (shared with the state store)');
        self::assertSame('{kiwi:wiring-test}:outstanding:', $args[1], 'arg 1 = the hash-tagged outstanding key prefix');
        self::assertSame('kiwi_captcha.risk.keys', (string) $args[2], 'arg 2 = the risk identity keys (the event key HMACs the canonical IP)');
        self::assertSame(7, $args[3], 'arg 3 = risk.max_outstanding_challenges');
        self::assertSame(12345, $args[4], 'arg 4 = risk.max_outstanding_challenges_global');
        self::assertSame(45, $args[5], 'arg 5 = risk.redis.ttl_margin_secs');

        // Without risk enabled the service must not exist.
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        (new KiwiCaptchaExtension())->load([['secret_key' => self::SECRET, 'risk' => ['enabled' => false]]], $container);
        self::assertFalse($container->hasDefinition('kiwi_captcha.risk.outstanding'), 'the outstanding service lives with the risk engine');
    }

    public function testControllerReceivesOutstandingAllowlistFetchMetadataAndStorage(): void
    {
        $risk = $this->riskDefaults();
        $risk['challenge_origin_allowlist'] = ['https://app.example.com'];
        $risk['enforce_fetch_metadata'] = true;
        $container = $this->load($risk, ['storage' => 'my.redis.storage'], static function (ContainerBuilder $c): void {
            $c->register('my.redis.storage', RedisStorage::class)
                ->setArguments([new Reference('fake_redis'), 'kiwicaptcha:']);
        });

        $args = $container->getDefinition(ChallengeController::class)->getArguments();
        self::assertSame('kiwi_captcha.risk.outstanding', (string) $args[6], 'the controller receives the outstanding-challenge counter');
        self::assertSame(['https://app.example.com'], $args[7], 'the controller receives risk.challenge_origin_allowlist');
        self::assertTrue($args[8], 'the controller receives risk.enforce_fetch_metadata');
        self::assertSame('my.redis.storage', (string) $args[9], 'the controller receives the challenge storage (record discard on counter-race refusal)');
    }

    public function testControllerWiringWithoutRiskEngine(): void
    {
        // Outstanding/storage still reach the controller; allowlist and
        // fetch-metadata follow the config defaults when risk is disabled.
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->register('my.redis.storage', \KiwiCaptcha\Storage\ArrayStorage::class);
        (new KiwiCaptchaExtension())->load([['secret_key' => self::SECRET, 'risk' => ['enabled' => false], 'storage' => 'my.redis.storage']], $container);
        $args = $container->getDefinition(ChallengeController::class)->getArguments();
        self::assertNull($args[6], 'no risk engine: no outstanding counter');
        self::assertSame([], $args[7]);
        self::assertFalse($args[8]);
        self::assertSame('my.redis.storage', (string) $args[9]);
    }

    public function testControllerReceivesDefaultRequestBindingAndEnforceOrigin(): void
    {
        $risk = $this->riskDefaults();
        $risk['request_binding'] = 'static-txn';
        $risk['enforce_origin'] = true;
        $container = $this->load($risk);

        $args = $container->getDefinition(ChallengeController::class)->getArguments();
        self::assertSame('static-txn', $args[10], 'risk.request_binding must reach the controller as the static default');
        self::assertTrue($args[11], 'risk.enforce_origin must reach the controller');

        // Defaults: no static binding, origin enforcement off.
        $args = $this->load($this->riskDefaults())->getDefinition(ChallengeController::class)->getArguments();
        self::assertNull($args[10]);
        self::assertFalse($args[11]);
    }

    public function testPolicyVersionFlowsIntoConfigAndVerifier(): void
    {
        $container = $this->load($this->riskDefaults());

        self::assertSame(1, $container->getDefinition('kiwi_captcha.config')->getArgument('$policyVersion'), 'risk.policy_version (default 1) must reach the core Config');
        self::assertSame(1, $container->getDefinition('kiwi_captcha.verifier')->getArgument('$expectedPolicyVersion'), 'risk.policy_version must reach the core Verifier as expectedPolicyVersion');

        $risk = $this->riskDefaults();
        $risk['policy_version'] = 2;
        $container = $this->load($risk);
        self::assertSame(2, $container->getDefinition('kiwi_captcha.config')->getArgument('$policyVersion'), 'a bumped epoch must reach the issuer Config');
        self::assertSame(2, $container->getDefinition('kiwi_captcha.verifier')->getArgument('$expectedPolicyVersion'), 'a bumped epoch must reach the verifier (outstanding challenges die immediately)');
    }

    public function testStaticRequestBindingIsValidatedAtCompileTime(): void
    {
        // A static binding containing '|' (the canonical-payload separator)
        // would 422 every challenge request — refused at compile time.
        try {
            $risk = $this->riskDefaults();
            $risk['request_binding'] = 'bad|binding';
            $this->load($risk);
            self::fail('a static request binding containing "|" must be refused at compile time');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('request_binding', $e->getMessage());
        }

        try {
            $risk = $this->riskDefaults();
            $risk['request_binding'] = str_repeat('x', 129);
            $this->load($risk);
            self::fail('a static request binding longer than 128 chars must be refused at compile time');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('request_binding', $e->getMessage());
        }

        // Out-of-charset bytes are refused at compile time too.
        try {
            $risk = $this->riskDefaults();
            $risk['request_binding'] = 'static binding';
            $this->load($risk);
            self::fail('a static request binding with out-of-charset bytes must be refused at compile time');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('request_binding', $e->getMessage());
        }

        // Valid static bindings load fine.
        $risk = $this->riskDefaults();
        $risk['request_binding'] = 'static-txn';
        $this->load($risk);
        self::assertTrue(true);
    }

    public function testResolverReceivesFixedEnvelopeAndEscalationLadder(): void
    {
        $container = $this->load($this->riskDefaults());
        $resolver = $container->getDefinition('kiwi_captcha.risk.resolver');
        $args = $resolver->getArguments();
        self::assertSame(16384, $args[2], 'arg 2 = risk.argon_verification_memory_kib (the FIXED envelope, default 16384)');
        self::assertSame([1, 2, 4], $args[3], 'arg 3 = risk.argon_escalation_target_bits (default [1, 2, 4])');

        $risk = $this->riskDefaults();
        $risk['argon_verification_memory_kib'] = 32768;
        $risk['argon_escalation_target_bits'] = [2, 6, 10];
        $args = $this->load($risk)->getDefinition('kiwi_captcha.risk.resolver')->getArguments();
        self::assertSame(32768, $args[2], 'the configured envelope reaches the resolver');
        self::assertSame([2, 6, 10], $args[3], 'the configured ladder reaches the resolver');
    }

    public function testSecurityEpochMonitorWiredIntoVerifierAndValidator(): void
    {
        $risk = $this->riskDefaults();
        $risk['policy_version'] = 2;
        $risk['security_epoch_cache_secs'] = 3;
        $risk['region'] = 'eu-central-1';
        $container = $this->load($risk, ['redis_service' => 'fake_redis']);

        $monitor = $container->getDefinition(\BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor::class);
        self::assertSame('kiwi_captcha.verifier', (string) $monitor->getArgument(0), 'the monitor rotates the SHARED verifier');
        self::assertSame('kiwi_captcha.redis.checked', (string) $monitor->getArgument(1), 'the monitor reads the central policy state from the checked security Redis');
        self::assertSame('wiring-test', $monitor->getArgument(2), 'the monitor uses the risk namespace ({kiwi:<ns>}:security-policy)');
        self::assertSame(2, $monitor->getArgument(3), 'the monitor floors at risk.policy_version');
        self::assertSame(3, $monitor->getArgument(4), 'the monitor uses risk.security_epoch_cache_secs');
        // The monitor owns only the policy epoch: region and issuer are
        // construction-time verifier expectations and must never be
        // carried (or rewritten) by the monitor — wiring a null issuer
        // through it would silently disable the issuer security boundary
        // after the first epoch bump.
        self::assertArrayNotHasKey('region', $monitor->getArguments(), 'the monitor must NOT carry the verifier region: an epoch refresher never rewrites deployment expectations');
        self::assertArrayNotHasKey('issuer', $monitor->getArguments(), 'the monitor must NOT carry the verifier issuer: an epoch refresher never rewrites deployment expectations');

        // The validator receives the monitor (per-verification refresh).
        $validator = $container->getDefinition(\BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator::class);
        self::assertSame(\BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor::class, (string) $validator->getArgument('$epochMonitor'), 'the validator must refresh the epoch monitor before every verification');

        // Wired even when the risk engine is off (the central state exists
        // independently; the monitor serves the configured epoch without
        // Redis).
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        (new KiwiCaptchaExtension())->load([['secret_key' => self::SECRET, 'risk' => ['enabled' => false]]], $container);
        $monitor = $container->getDefinition(\BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor::class);
        self::assertNull($monitor->getArgument(1), 'no Redis client: the monitor serves the configured epoch');
        self::assertSame(1, $monitor->getArgument(3));
    }

    public function testResultReceiptSignerWiredIntoValidator(): void
    {
        // Default: signing disabled.
        $container = $this->load($this->riskDefaults());
        $signer = $container->getDefinition(\BelConsulting\KiwiCaptchaBundle\Security\ResultReceiptSigner::class);
        self::assertNull($signer->getArgument(0), 'risk.result_receipt_signing_key defaults to null (disabled)');
        $validator = $container->getDefinition(\BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator::class);
        self::assertSame(\BelConsulting\KiwiCaptchaBundle\Security\ResultReceiptSigner::class, (string) $validator->getArgument('$receiptSigner'), 'the validator receives the signer (disabled by default)');

        // A valid seed is wired.
        $seed = base64_encode(random_bytes(32));
        $risk = $this->riskDefaults();
        $risk['result_receipt_signing_key'] = $seed;
        $signer = $this->load($risk)->getDefinition(\BelConsulting\KiwiCaptchaBundle\Security\ResultReceiptSigner::class);
        self::assertSame($seed, $signer->getArgument(0), 'the configured Ed25519 seed reaches the signer');

        // A malformed seed fails at compile time.
        foreach ([base64_encode(random_bytes(16)), 'not-base64!!'] as $bad) {
            try {
                $risk = $this->riskDefaults();
                $risk['result_receipt_signing_key'] = $bad;
                $this->load($risk);
                self::fail('a malformed Ed25519 seed must be refused at compile time');
            } catch (\InvalidArgumentException $e) {
                self::assertStringContainsString('result_receipt_signing_key', $e->getMessage());
            }
        }
    }

    public function testScopeIssuanceCapWiredWhenConfiguredAndFailFastWithoutRedis(): void
    {
        // Cap > 0 with a Redis client: the service is wired into the
        // controller with the risk namespace key prefix.
        $risk = $this->riskDefaults();
        $risk['max_challenges_per_scope_per_minute'] = 50;
        $container = $this->load($risk);
        $cap = $container->getDefinition('kiwi_captcha.risk.scope_issuance_cap');
        self::assertSame('kiwi_captcha.redis.checked.risk', (string) $cap->getArgument(0), 'the cap uses the checked risk Redis client');
        self::assertSame('{kiwi:wiring-test}:issuance:', $cap->getArgument(1), 'the cap keys live in the risk hash-tag family');
        self::assertSame(50, $cap->getArgument(2), 'the cap reaches the service');
        $controllerArgs = $container->getDefinition(ChallengeController::class)->getArguments();
        self::assertSame('kiwi_captcha.risk.scope_issuance_cap', (string) $controllerArgs['$scopeIssuanceCap'], 'the controller receives the scope cap');

        // Cap > 0 without any Redis client: fail fast at compile time.
        try {
            $risk = $this->riskDefaults();
            $risk['enabled'] = false;
            $risk['max_challenges_per_scope_per_minute'] = 10;
            $container = new ContainerBuilder();
            $container->setParameter('kernel.environment', 'test');
            (new KiwiCaptchaExtension())->load([['secret_key' => self::SECRET, 'risk' => $risk]], $container);
            self::fail('a per-scope cap without any Redis client must be refused at compile time');
        } catch (\LogicException $e) {
            self::assertStringContainsString('max_challenges_per_scope_per_minute', $e->getMessage());
        }

        // Default (0 = unlimited): no cap service, controller gets null.
        $container = $this->load($this->riskDefaults());
        self::assertFalse($container->hasDefinition('kiwi_captcha.risk.scope_issuance_cap'));
        self::assertNull($container->getDefinition(ChallengeController::class)->getArgument('$scopeIssuanceCap'));
    }

    public function testHealthControllerReceivesTheVerificationEnvelope(): void
    {
        $container = $this->load($this->riskDefaults());
        $health = $container->getDefinition(\BelConsulting\KiwiCaptchaBundle\Controller\KiwiHealthController::class);
        self::assertSame(16384, $health->getArgument('$argonEnvelopeMemoryKib'), 'the memory-budget invariant uses the FIXED verification envelope');

        $risk = $this->riskDefaults();
        $risk['argon_verification_memory_kib'] = 65536;
        $health = $this->load($risk)->getDefinition(\BelConsulting\KiwiCaptchaBundle\Controller\KiwiHealthController::class);
        self::assertSame(65536, $health->getArgument('$argonEnvelopeMemoryKib'));
    }

    public function testHealthControllerWiringAndRouteLoaderFlag(): void
    {
        $risk = $this->riskDefaults();
        $risk['policy_version'] = 2;
        $container = $this->load($risk, ['redis_service' => 'fake_redis']);

        $health = $container->getDefinition(\BelConsulting\KiwiCaptchaBundle\Controller\KiwiHealthController::class);
        self::assertSame(self::SECRET, $health->getArgument(0), 'the health controller receives the signing secret (key-configured leg)');
        self::assertSame('kiwi_captcha.redis.checked', (string) $health->getArgument(1), 'the health controller probes the bundle\'s checked security Redis');
        self::assertSame('wiring-test', $health->getArgument(2), 'the health controller uses the risk namespace for the central policy key');
        self::assertSame(2, $health->getArgument(3), 'the health controller compares min_policy_epoch against risk.policy_version');

        // The route loader registers the health routes when enabled.
        $loaderArgs = $container->getDefinition(\BelConsulting\KiwiCaptchaBundle\Routing\KiwiCaptchaRouteLoader::class)->getArguments();
        self::assertTrue($loaderArgs[1], 'risk.health.enabled (default true) must reach the route loader');

        $risk = $this->riskDefaults();
        $risk['health'] = ['enabled' => false];
        $loaderArgs = $this->load($risk)->getDefinition(\BelConsulting\KiwiCaptchaBundle\Routing\KiwiCaptchaRouteLoader::class)->getArguments();
        self::assertFalse($loaderArgs[1], 'risk.health.enabled=false must disable the health routes');
    }

    public function testHealthControllerWiredEvenWhenRiskEngineIsOff(): void
    {
        // The health endpoints live under the risk.* config namespace but
        // must work without the risk engine (no state store needed).
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        (new KiwiCaptchaExtension())->load([['secret_key' => self::SECRET, 'risk' => ['enabled' => false]]], $container);
        self::assertTrue($container->hasDefinition(\BelConsulting\KiwiCaptchaBundle\Controller\KiwiHealthController::class), 'health must be wired even when the risk engine is off');
        $health = $container->getDefinition(\BelConsulting\KiwiCaptchaBundle\Controller\KiwiHealthController::class);
        self::assertNull($health->getArgument(1), 'no Redis client: the health controller gets null (Redis legs vacuous)');
        self::assertSame(1, $health->getArgument(3), 'the default risk.policy_version (1) reaches the health controller');
    }
}
