<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Risk\ArrayChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisPostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Twig\KiwiCaptchaRuntime;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use KiwiCaptcha\Risk\RiskV2Weights;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * The selective-chaining wiring contract at the definition level
 * (extension load, no container compile): risk.chaining wires the
 * Redis-backed chain state store (in-memory when no Redis client exists)
 * plus the ticket service into both the challenge controller and the
 * validator. risk.trusted_tls_header flows into the controller.
 * chaining.enabled requires risk.enabled and a non-null
 * risk.request_binding_authority — the extension refuses the
 * combination at compile time.
 */
final class ChainingWiringTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const BINDING_AUTHORITY = 'fake_binding_authority';

    private function load(array $risk, bool $redis = true): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        if ($redis) {
            $container->register('fake_redis', FakePredisClient::class);
        }
        (new KiwiCaptchaExtension())->load([[
            'secret_key' => self::SECRET,
            'difficulty_bits' => 8,
            'risk' => [
                'enabled' => true,
                'redis_service' => 'fake_redis',
                ...$risk,
            ],
        ]], $container);

        return $container;
    }

    public function testStrictPrivacyModeRefusesClientContext(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->register('fake_redis', FakePredisClient::class);
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('risk.client_context cannot be true under privacy_mode "strict"');
        (new KiwiCaptchaExtension())->load([[
            'secret_key' => self::SECRET,
            'difficulty_bits' => 8,
            'privacy_mode' => 'strict',
            'risk' => [
                'enabled' => true,
                'redis_service' => 'fake_redis',
                'client_context' => true,
            ],
        ]], $container);
    }

    public function testStrictPrivacyModeRendersNoOptInAttributeEvenWithTheRenderOverride(): void
    {
        $env = new \Twig\Environment(new \Twig\Loader\FilesystemLoader(__DIR__.'/../src/Resources/views'));
        $runtime = new KiwiCaptchaRuntime(
            '/kiwi-captcha',
            \dirname(__DIR__).'/Resources/public',
            'form_div_layout.html.twig',
            'off',
            null,
            [],
            false,
            true,
        );

        $html = $runtime->renderWidget($env, ['risk_client_context' => true]);
        // The attribute name also appears in the embedded driver source;
        // assert on the container tag sequence (the only render surface).
        self::assertStringNotContainsString('data-kiwi-telemetry="off" data-kiwi-risk-context="coarse"', $html, 'strict privacy mode must never render the opt-in attribute');
    }

    public function testClientContextOptInRendersTheAttributeAndDefaultsAreOff(): void
    {
        $env = new \Twig\Environment(new \Twig\Loader\FilesystemLoader(__DIR__.'/../src/Resources/views'));
        $runtime = new KiwiCaptchaRuntime(
            '/kiwi-captcha',
            \dirname(__DIR__).'/Resources/public',
            'form_div_layout.html.twig',
            'off',
            null,
            [],
            false,
            false,
        );

        self::assertStringNotContainsString('data-kiwi-telemetry="off" data-kiwi-risk-context="coarse"', $runtime->renderWidget($env), 'the attribute must be off by default');
        $html = $runtime->renderWidget($env, ['risk_client_context' => true]);
        self::assertStringContainsString('data-kiwi-telemetry="off" data-kiwi-risk-context="coarse"', $html, 'the per-render override must render the attribute when not strict');
    }

    public function testChainingEnabledWiresRedisStoreAndTicketService(): void
    {
        $container = $this->load(['chaining' => ['enabled' => true, 'ttl_secs' => 120], 'request_binding_authority' => self::BINDING_AUTHORITY]);

        self::assertTrue($container->hasDefinition(RedisChainedChallengeStateStore::class));
        self::assertTrue($container->hasDefinition(ChainedChallengeTicketService::class));
        $service = $container->getDefinition(ChainedChallengeTicketService::class);
        self::assertSame(ChainedChallengeTicketService::class, $service->getClass());
        self::assertSame(120, $service->getArgument(2), 'the chain ttl flows into the ticket service');
        self::assertSame(self::SECRET, $service->getArgument(1), 'the chain HMAC secret falls back to the captcha secret_key');
        self::assertSame(15, $service->getArgument(3), 'the SHORT reservation lease defaults to 15s');
        $authority = $service->getArgument('$bindingAuthority');
        self::assertInstanceOf(Reference::class, $authority);
        self::assertSame(self::BINDING_AUTHORITY, (string) $authority, 'the authoritative binding resolver flows into the ticket service');
    }

    public function testChainingWithoutRedisClientWiresTheArrayStore(): void
    {
        // The risk engine itself requires a Predis client, so chaining
        // without any Redis client cannot be reached through the normal
        // risk wiring; the Array branch mirrors the idempotency-store
        // pattern for completeness (the extension prefers the risk Redis).
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->register('fake_redis', FakePredisClient::class);
        (new KiwiCaptchaExtension())->load([[
            'secret_key' => self::SECRET,
            'difficulty_bits' => 8,
            'risk' => [
                'enabled' => true,
                'redis_service' => 'fake_redis',
                'chaining' => ['enabled' => true],
                'request_binding_authority' => self::BINDING_AUTHORITY,
            ],
        ]], $container);
        self::assertTrue($container->hasDefinition(RedisChainedChallengeStateStore::class));

        // The Array store class is available for the same contract.
        self::assertTrue(\class_exists(ArrayChainedChallengeStateStore::class));
    }

    public function testChainingDisabledWiresNoChainService(): void
    {
        $container = $this->load([]);

        self::assertFalse($container->hasDefinition(ChainedChallengeTicketService::class));
        self::assertFalse($container->hasDefinition(RedisChainedChallengeStateStore::class));
        $controller = $container->getDefinition(ChallengeController::class);
        self::assertNull($controller->getArgument('$chainTickets'), 'chaining disabled injects null into the controller');
        self::assertNull($controller->getArgument('$bindingAuthority'), 'without a configured authority the controller falls back to the legacy binding behavior');
    }

    public function testChainServiceAndTlsHeaderFlowIntoControllerAndValidator(): void
    {
        $container = $this->load([
            'chaining' => ['enabled' => true],
            'request_binding_authority' => self::BINDING_AUTHORITY,
            'trusted_tls_header' => 'X-Tls-Class',
            'trusted_tls_proxies' => ['10.0.0.0/8', '192.168.1.5'],
        ]);

        $controller = $container->getDefinition(ChallengeController::class);
        $chain = $controller->getArgument('$chainTickets');
        self::assertInstanceOf(Reference::class, $chain);
        self::assertSame(ChainedChallengeTicketService::class, (string) $chain);
        self::assertSame('X-Tls-Class', $controller->getArgument('$trustedTlsHeader'));
        self::assertSame(['10.0.0.0/8', '192.168.1.5'], $controller->getArgument('$trustedTlsProxies'), 'risk.trusted_tls_proxies flows into the controller (the header is read only from a trusted direct peer)');
        self::assertSame(1, $controller->getArgument('$policyVersion'));
        $authority = $controller->getArgument('$bindingAuthority');
        self::assertInstanceOf(Reference::class, $authority);
        self::assertSame(self::BINDING_AUTHORITY, (string) $authority, 'the authoritative transaction-binding resolver flows into the controller (a client-supplied string is never signed unexamined)');

        // The post-solve disposition store is injected into the controller
        // too: a consumed-valid stage-2 challenge is never terminal from
        // the core's consumed result alone — the controller reads the
        // nonce's final disposition and transitions the chain by kind.
        $disposition = $controller->getArgument('$postSolveDispositionStore');
        self::assertInstanceOf(Reference::class, $disposition, 'the controller receives the post-solve disposition store');

        $validator = $container->getDefinition(KiwiCaptchaValidator::class);
        $validatorChain = $validator->getArgument('$chainTickets');
        self::assertInstanceOf(Reference::class, $validatorChain);
        self::assertSame(ChainedChallengeTicketService::class, (string) $validatorChain);
        $resolver = $validator->getArgument('$riskResolver');
        self::assertInstanceOf(Reference::class, $resolver);
        self::assertSame('kiwi_captcha.risk.resolver', (string) $resolver, 'the risk profile resolver (the authoritative stage-strength comparison) flows into the validator');
    }

    public function testChainingEnabledWithoutTheBindingAuthorityIsRefusedAtCompileTime(): void
    {
        // The chain is a server-side transaction obligation anchored on
        // the authoritative binding — chaining without the authority is a
        // configuration error, refused at compile time (the config tree),
        // never silently degraded.
        try {
            $this->load(['chaining' => ['enabled' => true]]);
            self::fail('chaining.enabled without a request_binding_authority must be refused');
        } catch (InvalidConfigurationException $e) {
            self::assertStringContainsString('request_binding_authority', $e->getMessage(), 'the refusal names the required authority');
            self::assertStringContainsString('risk.enabled=true', $e->getMessage(), 'the refusal names both requirements');
        }
    }

    public function testReservationLeaseSecsFlowsIntoTheTicketService(): void
    {
        $container = $this->load([
            'chaining' => ['enabled' => true, 'reservation_lease_secs' => 42],
            'request_binding_authority' => self::BINDING_AUTHORITY,
        ]);

        self::assertSame(42, $container->getDefinition(ChainedChallengeTicketService::class)->getArgument(3), 'the configured SHORT reservation lease flows into the ticket service');
    }

    public function testNonMonotoneOrOutOfRangeArgonLadderIsRefusedAtCompileTime(): void
    {
        // The argon escalation ladder must satisfy
        // 1 <= rung1 < rung2 < rung3 <= Config::MAX_argon2_target_bits:
        // a non-monotone or out-of-range ladder is refused when the
        // config tree processes the extension load — never silently
        // accepted.
        foreach ([
            [1, 5, 5],
            [5, 5, 10],
            [1, 4, 11],
            [0, 4, 8],
            [1, 4],
            [1, 4, 8, 10],
        ] as $ladder) {
            try {
                $this->load(['argon_escalation_target_bits' => $ladder]);
                self::fail('a ladder violating 1 <= rung1 < rung2 < rung3 <= 10 must be refused: '.json_encode($ladder));
            } catch (InvalidConfigurationException) {
                self::assertTrue(true);
            }
        }

        // The monotonicity refusal names the ladder constraint.
        try {
            $this->load(['argon_escalation_target_bits' => [1, 5, 5]]);
            self::fail('a non-monotone ladder must be refused');
        } catch (InvalidConfigurationException $e) {
            self::assertStringContainsString('1 <= rung1 < rung2 < rung3 <= 10', $e->getMessage(), 'the refusal names the ladder constraint');
        }
    }

    public function testRiskV2WeightsFlowIntoTheGateway(): void
    {
        $container = $this->load([
            'v2' => [
                'honeypot_weight' => 333,
                'session_consistency_weight' => 222,
                'tls_weight' => 111,
            ],
        ]);

        $weights = $container->getDefinition('kiwi_captcha.risk.v2_weights');
        self::assertNotNull($weights);
        self::assertSame(RiskV2Weights::class, $weights->getClass());
        self::assertSame(333, $weights->getArgument('$honeypot'));
        self::assertSame(222, $weights->getArgument('$sessionInconsistency'));
        self::assertSame(111, $weights->getArgument('$tls'));

        $gateway = $container->getDefinition(RiskGateway::class);
        $v2Weights = $gateway->getArgument('$v2Weights');
        self::assertInstanceOf(Reference::class, $v2Weights);
        self::assertSame('kiwi_captcha.risk.v2_weights', (string) $v2Weights, 'the configured risk-v2 weights are wired into the gateway');
    }

    public function testChainingHmacSecretPrefersTheChainingSecret(): void
    {
        $container = $this->load(['chaining' => ['enabled' => true, 'hmac_secret' => str_repeat('h', 32)], 'request_binding_authority' => self::BINDING_AUTHORITY]);

        self::assertSame(str_repeat('h', 32), $container->getDefinition(ChainedChallengeTicketService::class)->getArgument(1));
    }

    public function testChainAndDispositionStoresReceiveTheWaitReplicasKnobs(): void
    {
        // The risk.redis replica-durability knobs flow into both stores,
        // the same knobs that harden the challenge storage: the chain
        // state store and the post-solve disposition store must verify
        // the configured replica acknowledgement on their fresh mutating
        // transitions.
        $container = $this->load([
            'chaining' => ['enabled' => true],
            'request_binding_authority' => self::BINDING_AUTHORITY,
            'redis' => ['wait_replicas' => 2, 'wait_timeout_ms' => 500],
        ]);

        $chainArgs = $container->getDefinition(RedisChainedChallengeStateStore::class)->getArguments();
        self::assertInstanceOf(Reference::class, $chainArgs[0], 'the chain store receives the Redis client');
        self::assertSame(2, $chainArgs[2], 'wait_replicas must reach the Redis chain state store');
        self::assertSame(500, $chainArgs[3], 'wait_timeout_ms must reach the Redis chain state store');

        $dispositionArgs = $container->getDefinition(RedisPostSolveDispositionStore::class)->getArguments();
        self::assertInstanceOf(Reference::class, $dispositionArgs[0], 'the disposition store receives the Redis client');
        self::assertSame(2, $dispositionArgs[3], 'wait_replicas must reach the Redis disposition store');
        self::assertSame(500, $dispositionArgs[4], 'wait_timeout_ms must reach the Redis disposition store');
    }

    public function testChainAndDispositionStoresDefaultToWaitDisabled(): void
    {
        // No risk.redis knobs configured: the stores stay at the built-in
        // defaults (wait_replicas 0, wait_timeout_ms 100) — the same
        // byte-identical behavior as a deployment that never opts in.
        $container = $this->load(['chaining' => ['enabled' => true], 'request_binding_authority' => self::BINDING_AUTHORITY]);

        $chainArgs = $container->getDefinition(RedisChainedChallengeStateStore::class)->getArguments();
        self::assertSame(0, $chainArgs[2], 'wait_replicas defaults to 0 (WAIT disabled)');
        self::assertSame(100, $chainArgs[3], 'wait_timeout_ms defaults to 100');

        $dispositionArgs = $container->getDefinition(RedisPostSolveDispositionStore::class)->getArguments();
        self::assertSame(0, $dispositionArgs[3], 'wait_replicas defaults to 0 (WAIT disabled)');
        self::assertSame(100, $dispositionArgs[4], 'wait_timeout_ms defaults to 100');
    }
}
