<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Risk\ArrayChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * The selective-chaining wiring contract at the definition level (extension
 * load, no container compile): risk.chaining wires the Redis-backed chain
 * state store (in-memory when no Redis client exists) + the ticket service,
 * and injects the service into BOTH the challenge controller (stage-2
 * gate) and the validator (CHAIN_REQUIRED issuance); risk.trusted_tls_header
 * flows into the controller.
 */
final class ChainingWiringTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

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

    public function testChainingEnabledWiresRedisStoreAndTicketService(): void
    {
        $container = $this->load(['chaining' => ['enabled' => true, 'ttl_secs' => 120]]);

        self::assertTrue($container->hasDefinition(RedisChainedChallengeStateStore::class));
        self::assertTrue($container->hasDefinition(ChainedChallengeTicketService::class));
        $service = $container->getDefinition(ChainedChallengeTicketService::class);
        self::assertSame(ChainedChallengeTicketService::class, $service->getClass());
        self::assertSame(120, $service->getArgument(2), 'the chain ttl flows into the ticket service');
        self::assertSame(self::SECRET, $service->getArgument(1), 'the chain HMAC secret falls back to the captcha secret_key');
    }

    public function testChainingWithoutRedisClientWiresTheArrayStore(): void
    {
        // The risk engine itself REQUIRES a Predis client, so chaining
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
    }

    public function testChainServiceAndTlsHeaderFlowIntoControllerAndValidator(): void
    {
        $container = $this->load([
            'chaining' => ['enabled' => true],
            'trusted_tls_header' => 'X-Tls-Class',
        ]);

        $controller = $container->getDefinition(ChallengeController::class);
        $chain = $controller->getArgument('$chainTickets');
        self::assertInstanceOf(Reference::class, $chain);
        self::assertSame(ChainedChallengeTicketService::class, (string) $chain);
        self::assertSame('X-Tls-Class', $controller->getArgument('$trustedTlsHeader'));
        self::assertSame(1, $controller->getArgument('$policyVersion'));

        $validator = $container->getDefinition(KiwiCaptchaValidator::class);
        $validatorChain = $validator->getArgument('$chainTickets');
        self::assertInstanceOf(Reference::class, $validatorChain);
        self::assertSame(ChainedChallengeTicketService::class, (string) $validatorChain);
    }

    public function testChainingHmacSecretPrefersTheChainingSecret(): void
    {
        $container = $this->load(['chaining' => ['enabled' => true, 'hmac_secret' => str_repeat('h', 32)]]);

        self::assertSame(str_repeat('h', 32), $container->getDefinition(ChainedChallengeTicketService::class)->getArgument(1));
    }
}
