<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Security\InProcessArgonGate;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceRateLimiter;
use BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore;
use BelConsulting\KiwiCaptchaBundle\Security\RequestScopeAdmissionGate;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * The extension must wire the Argon2id admission gate into the core Verifier
 * natively: RedisAdmissionSemaphore (tokenized leases, cross-worker) when a
 * Redis client is available (redis_service option, or RedisStorage as the
 * storage backend), InProcessArgonGate otherwise, null gate for sha256 or
 * cap 0. When a Redis client is available, the rate limiter must use the
 * ATOMIC Redis backend with the global cap and deployment namespace.
 */
final class RedisSemaphoreWiringTest extends TestCase
{
    private function load(array $config, ?\Closure $register = null): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        if ($register !== null) {
            $register($container);
        }
        (new KiwiCaptchaExtension())->load([array_merge([
            'secret_key' => str_repeat('a', 32),
        ], $config)], $container);

        return $container;
    }

    private const ARGON2 = [
        'algorithm' => 'argon2id',
        'argon_m_kib' => 64,
        'argon_t' => 3,
        'argon_p' => 1,
    ];

    public function testRedisServiceOptionWiresRedisSemaphoreIntoVerifier(): void
    {
        $container = $this->load(self::ARGON2 + [
            'argon2_max_concurrent_verifications' => 2,
            'redis_service' => 'my.redis.client',
            'argon2_semaphore_namespace' => 'deployment-a',
        ], static function (ContainerBuilder $c): void {
            $c->register('my.redis.client', \Redis::class);
        });

        self::assertTrue($container->hasDefinition('kiwi_captcha.argon2_redis_semaphore'));
        $semaphore = $container->getDefinition('kiwi_captcha.argon2_redis_semaphore');
        self::assertSame(RedisAdmissionSemaphore::class, $semaphore->getClass());
        self::assertEquals(new Reference('my.redis.client'), $semaphore->getArgument(0));
        self::assertSame('deployment-a', $semaphore->getArgument(2), 'the configured namespace must reach the semaphore');
        self::assertSame(64, $semaphore->getArgument(4), 'argon2_max_waiters (default 64) must reach the semaphore\'s bounded waiters guard');

        // The verifier consumes the gate through the request-scope-aware
        // wrapper (the validator passes the scope into acquire).
        $verifier = $container->getDefinition('kiwi_captcha.verifier');
        self::assertSame(Verifier::class, $verifier->getClass());
        self::assertSame('kiwi_captcha.argon2_scope_gate', (string) $verifier->getArgument(1), 'the verifier must be wired with the scope-aware gate');
        $scopeGate = $container->getDefinition('kiwi_captcha.argon2_scope_gate');
        self::assertSame(RequestScopeAdmissionGate::class, $scopeGate->getClass());
        self::assertEquals(new Reference('kiwi_captcha.argon2_redis_semaphore'), $scopeGate->getArgument(0), 'the scope gate wraps the Redis semaphore');
    }

    public function testArgon2MaxWaitersFlowsToTheRedisSemaphore(): void
    {
        $container = $this->load(self::ARGON2 + [
            'argon2_max_concurrent_verifications' => 2,
            'argon2_max_waiters' => 12,
            'redis_service' => 'my.redis.client',
        ], static function (ContainerBuilder $c): void {
            $c->register('my.redis.client', \Redis::class);
        });

        $semaphore = $container->getDefinition('kiwi_captcha.argon2_redis_semaphore');
        self::assertSame(12, $semaphore->getArgument(4), 'the configured argon2_max_waiters must reach the semaphore');
    }

    public function testArgon2MaxPerTenantFlowsToTheRedisSemaphore(): void
    {
        $container = $this->load(self::ARGON2 + [
            'argon2_max_concurrent_verifications' => 2,
            'argon2_max_per_tenant' => 15,
            'redis_service' => 'my.redis.client',
        ], static function (ContainerBuilder $c): void {
            $c->register('my.redis.client', \Redis::class);
        });

        $semaphore = $container->getDefinition('kiwi_captcha.argon2_redis_semaphore');
        self::assertSame(15, $semaphore->getArgument(5), 'the configured argon2_max_per_tenant must reach the semaphore');

        $container = $this->load(self::ARGON2 + [
            'argon2_max_concurrent_verifications' => 2,
            'redis_service' => 'my.redis.client',
        ], static function (ContainerBuilder $c): void {
            $c->register('my.redis.client', \Redis::class);
        });
        self::assertSame(8, $container->getDefinition('kiwi_captcha.argon2_redis_semaphore')->getArgument(5), 'argon2_max_per_tenant defaults to 8');
    }

    public function testRedisStorageStorageWiresRedisSemaphoreFromItsClient(): void
    {
        // The storage service is a RedisStorage definition whose first
        // constructor argument is the Redis client: the extension must reuse
        // that client for the semaphore (no redis_service needed).
        $container = $this->load(self::ARGON2 + [
            'argon2_max_concurrent_verifications' => 2,
            'storage' => 'my.redis.storage',
        ], static function (ContainerBuilder $c): void {
            $c->register('my.redis.client', \Redis::class);
            $c->register('my.redis.storage', RedisStorage::class)
                ->setArguments([new Reference('my.redis.client'), 'kiwicaptcha:']);
        });

        self::assertTrue($container->hasDefinition('kiwi_captcha.argon2_redis_semaphore'));
        $semaphore = $container->getDefinition('kiwi_captcha.argon2_redis_semaphore');
        self::assertEquals(new Reference('my.redis.client'), $semaphore->getArgument(0));

        $verifier = $container->getDefinition('kiwi_captcha.verifier');
        self::assertEquals(new Reference('kiwi_captcha.argon2_scope_gate'), $verifier->getArgument(1));
    }

    public function testNonRedisStorageFallsBackToInProcessGate(): void
    {
        // Test/dev default storage is in-memory: the InProcessArgonGate is
        // wired into the verifier (per-process only).
        $container = $this->load(self::ARGON2 + ['argon2_max_concurrent_verifications' => 2]);

        self::assertFalse($container->hasDefinition('kiwi_captcha.argon2_redis_semaphore'));
        self::assertTrue($container->hasDefinition('kiwi_captcha.argon2_inprocess_gate'));
        $gate = $container->getDefinition('kiwi_captcha.argon2_inprocess_gate');
        self::assertSame(InProcessArgonGate::class, $gate->getClass());
        self::assertSame(2, $gate->getArgument(0));

        $verifier = $container->getDefinition('kiwi_captcha.verifier');
        self::assertSame(Verifier::class, $verifier->getClass());
        self::assertEquals(new Reference('kiwi_captcha.argon2_inprocess_gate'), $verifier->getArgument(1));
    }

    public function testSha256ModeStillWiresRedisGateWhenCapConfigured(): void
    {
        // The gate is created whenever the cap is > 0, regardless of the
        // locally configured issuance algorithm — a SHA-issuing service may
        // verify Argon records written by another service (cross-language
        // shared storage), and the verifier consults the gate based on the
        // STORED record. The Redis semaphore must therefore be wired.
        $container = $this->load([
            'redis_service' => 'my.redis.client',
        ], static function (ContainerBuilder $c): void {
            $c->register('my.redis.client', \Redis::class);
        });

        $verifier = $container->getDefinition('kiwi_captcha.verifier');
        self::assertSame(Verifier::class, $verifier->getClass());
        self::assertNotNull($verifier->getArgument(1), 'sha256 mode with a cap must wire the Redis gate');
        self::assertTrue($container->hasDefinition('kiwi_captcha.argon2_redis_semaphore'));
    }

    public function testSha256ModeWithZeroCapWiresNoGate(): void
    {
        // Cap 0 = admission disabled — no gate at all, regardless of algorithm.
        $container = $this->load([
            'redis_service' => 'my.redis.client',
            'argon2_max_concurrent_verifications' => 0,
        ], static function (ContainerBuilder $c): void {
            $c->register('my.redis.client', \Redis::class);
        });

        $verifier = $container->getDefinition('kiwi_captcha.verifier');
        self::assertNull($verifier->getArgument(1));
        self::assertFalse($container->hasDefinition('kiwi_captcha.argon2_redis_semaphore'));
        self::assertFalse($container->hasDefinition('kiwi_captcha.argon2_inprocess_gate'));
    }

    public function testZeroCapNeverWiresAGate(): void
    {
        $container = $this->load(self::ARGON2 + [
            'argon2_max_concurrent_verifications' => 0,
            'redis_service' => 'my.redis.client',
        ], static function (ContainerBuilder $c): void {
            $c->register('my.redis.client', \Redis::class);
        });

        self::assertFalse($container->hasDefinition('kiwi_captcha.argon2_redis_semaphore'));
        self::assertFalse($container->hasDefinition('kiwi_captcha.argon2_inprocess_gate'));
        self::assertNull($container->getDefinition('kiwi_captcha.verifier')->getArgument(1));
    }

    public function testRedisClientWiresAtomicRateLimiterWithGlobalCapAndNamespace(): void
    {
        $container = $this->load([
            'rate_limit' => 10,
            'rate_limit_global' => 500,
            'rate_limit_window_secs' => 60,
            'redis_service' => 'my.redis.client',
            'argon2_semaphore_namespace' => 'deployment-a',
        ], static function (ContainerBuilder $c): void {
            $c->register('my.redis.client', \Redis::class);
        });

        self::assertTrue($container->hasDefinition('kiwi_captcha.rate_limiter'));
        $limiter = $container->getDefinition('kiwi_captcha.rate_limiter');
        self::assertSame(IssuanceRateLimiter::class, $limiter->getClass());
        self::assertSame(10, $limiter->getArgument(0));
        self::assertSame(60, $limiter->getArgument(1));
        self::assertEquals(new Reference('my.redis.client'), $limiter->getArgument(5), 'the Redis client must reach the limiter');
        self::assertSame(500, $limiter->getArgument(6), 'the global cap must reach the limiter');
        self::assertSame('deployment-a', $limiter->getArgument(7), 'the deployment namespace must reach the limiter');

        $controller = $container->getDefinition(\BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController::class);
        self::assertEquals(new Reference('kiwi_captcha.rate_limiter'), $controller->getArgument(1));
    }

    public function testWithoutRedisTheRateLimiterFallsBackToPoolAndInMemory(): void
    {
        $container = $this->load([
            'rate_limit' => 10,
            'rate_limit_global' => 500,
            'rate_limit_cache' => 'my.pool',
        ], static function (ContainerBuilder $c): void {
            $c->register('my.pool', \Psr\Cache\CacheItemPoolInterface::class);
        });

        $limiter = $container->getDefinition('kiwi_captcha.rate_limiter');
        self::assertEquals(new Reference('my.pool'), $limiter->getArgument(2), 'the PSR-6 pool fallback must be wired');
        self::assertNull($limiter->getArgument(5), 'no Redis client available: no Redis backend');

        $container = $this->load(['rate_limit' => 10]);
        $limiter = $container->getDefinition('kiwi_captcha.rate_limiter');
        self::assertNull($limiter->getArgument(2), 'no pool configured: in-memory window');
    }

    public function testDisabledRateLimitsWireNoLimiter(): void
    {
        $container = $this->load(['rate_limit' => 0, 'rate_limit_global' => 0]);

        self::assertFalse($container->hasDefinition('kiwi_captcha.rate_limiter'));
        self::assertNull($container->getDefinition(\BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController::class)->getArgument(1));
    }
}
