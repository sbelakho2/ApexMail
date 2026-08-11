<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore;
use BelConsulting\KiwiCaptchaBundle\Security\ThrottledVerifier;
use KiwiCaptcha\Storage\RedisStorage;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * The extension must wire the Redis-backed Argon2 admission semaphore when a
 * Redis client is available (redis_service option, or RedisStorage as the
 * storage backend), and fall back to the plain ThrottledVerifier
 * (in-process semaphore) otherwise.
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

    public function testRedisServiceOptionWiresRedisSemaphore(): void
    {
        $container = $this->load([
            'algorithm' => 'argon2id',
            'argon_m_kib' => 64,
            'argon_t' => 3,
            'argon_p' => 1,
            'argon2_max_concurrent_verifications' => 2,
            'redis_service' => 'my.redis.client',
        ], static function (ContainerBuilder $c): void {
            $c->register('my.redis.client', \Redis::class);
        });

        self::assertTrue($container->hasDefinition('kiwi_captcha.argon2_redis_semaphore'));
        $semaphore = $container->getDefinition('kiwi_captcha.argon2_redis_semaphore');
        self::assertSame(RedisAdmissionSemaphore::class, $semaphore->getClass());
        self::assertEquals(new Reference('my.redis.client'), $semaphore->getArgument(0));

        $verifier = $container->getDefinition('kiwi_captcha.verifier');
        self::assertSame(ThrottledVerifier::class, $verifier->getClass());
        self::assertEquals(new Reference('kiwi_captcha.argon2_redis_semaphore'), $verifier->getArgument(2));
    }

    public function testRedisStorageStorageWiresRedisSemaphoreFromItsClient(): void
    {
        // The storage service is a RedisStorage definition whose first
        // constructor argument is the Redis client: the extension must reuse
        // that client for the semaphore (no redis_service needed).
        $container = $this->load([
            'algorithm' => 'argon2id',
            'argon_m_kib' => 64,
            'argon_t' => 3,
            'argon_p' => 1,
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
        self::assertEquals(new Reference('kiwi_captcha.argon2_redis_semaphore'), $verifier->getArgument(2));
    }

    public function testNonRedisStorageFallsBackToInProcessSemaphore(): void
    {
        // Test/dev default storage is in-memory: the ThrottledVerifier is
        // still wired, but WITHOUT the Redis semaphore (in-process only).
        $container = $this->load([
            'algorithm' => 'argon2id',
            'argon_m_kib' => 64,
            'argon_t' => 3,
            'argon_p' => 1,
            'argon2_max_concurrent_verifications' => 2,
        ]);

        self::assertFalse($container->hasDefinition('kiwi_captcha.argon2_redis_semaphore'));
        $verifier = $container->getDefinition('kiwi_captcha.verifier');
        self::assertSame(ThrottledVerifier::class, $verifier->getClass());
        self::assertNull($verifier->getArgument(2));
    }

    public function testSha256ModeNeverWrapsTheVerifier(): void
    {
        $container = $this->load([
            'redis_service' => 'my.redis.client',
        ], static function (ContainerBuilder $c): void {
            $c->register('my.redis.client', \Redis::class);
        });

        self::assertSame(\KiwiCaptcha\Verifier::class, $container->getDefinition('kiwi_captcha.verifier')->getClass());
        self::assertFalse($container->hasDefinition('kiwi_captcha.argon2_redis_semaphore'));
    }

    public function testZeroCapNeverWiresSemaphore(): void
    {
        $container = $this->load([
            'algorithm' => 'argon2id',
            'argon_m_kib' => 64,
            'argon_t' => 3,
            'argon_p' => 1,
            'argon2_max_concurrent_verifications' => 0,
            'redis_service' => 'my.redis.client',
        ], static function (ContainerBuilder $c): void {
            $c->register('my.redis.client', \Redis::class);
        });

        self::assertFalse($container->hasDefinition('kiwi_captcha.argon2_redis_semaphore'));
        self::assertSame(\KiwiCaptcha\Verifier::class, $container->getDefinition('kiwi_captcha.verifier')->getClass());
    }
}
