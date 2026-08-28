<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use KiwiCaptcha\Storage\Psr6Storage;
use KiwiCaptcha\Storage\RedisStorage;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;

/**
 * Storage safety contract: the default ArrayStorage is in-memory only
 * (a challenge issued in request A can never be verified in request B
 * under php-fpm) and is refused in any non-test/non-dev environment.
 * Production verification requires an atomic backend
 * (KiwiCaptcha\AtomicStorageInterface); non-atomic storage is only
 * possible through the explicitly-named allow_best_effort_storage: true
 * escape hatch. Siteverify's one-success provider contract requires an
 * atomic backend regardless of the override — Siteverify + Psr6Storage
 * is refused at container compile time.
 */
final class ProdArrayStorageGuardTest extends TestCase
{
    private function load(string $environment): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', $environment);
        (new KiwiCaptchaExtension())->load([['secret_key' => str_repeat('a', 32), 'public_base_url' => 'https://captcha.example.com']], $container);

        return $container;
    }

    public function testArrayStorageRejectedInProd(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('ArrayStorage');
        $this->load('prod');
    }

    public function testArrayStorageAllowedInTestAndDev(): void
    {
        self::assertTrue($this->load('test')->hasDefinition('kiwi_captcha.storage.array'));
        self::assertTrue($this->load('dev')->hasDefinition('kiwi_captcha.storage.array'));
    }

    public function testCustomAtomicStorageServiceIdAllowedInProd(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.shared.storage', new Definition(RedisStorage::class, [new \stdClass()]));
        (new KiwiCaptchaExtension())->load(
            [['secret_key' => str_repeat('a', 32), 'storage' => 'my.shared.storage', 'public_base_url' => 'https://captcha.example.com', 'allow_local_global_limit_fallback' => true, 'allow_local_argon_admission_fallback' => true]],
            $container,
        );

        self::assertFalse($container->hasDefinition('kiwi_captcha.storage.array'));
    }

    public function testUnresolvableStorageClassRefusedInProd(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('unresolvable');
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        (new KiwiCaptchaExtension())->load(
            [['secret_key' => str_repeat('a', 32), 'storage' => 'my.shared.storage', 'public_base_url' => 'https://captcha.example.com']],
            $container,
        );
    }

    public function testPsr6StorageRefusedInProd(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('allow_best_effort_storage');
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        (new KiwiCaptchaExtension())->load(
            [['secret_key' => str_repeat('a', 32), 'storage' => 'my.psr6.storage', 'public_base_url' => 'https://captcha.example.com']],
            $container,
        );
    }

    public function testBestEffortOverrideAllowsNonAtomicStorageInProd(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        (new KiwiCaptchaExtension())->load(
            [['secret_key' => str_repeat('a', 32), 'storage' => 'my.psr6.storage', 'allow_best_effort_storage' => true, 'allow_local_global_limit_fallback' => true, 'allow_local_argon_admission_fallback' => true, 'public_base_url' => 'https://captcha.example.com']],
            $container,
        );

        self::assertFalse($container->hasDefinition('kiwi_captcha.storage.array'));
    }

    public function testProdRequiresPublicBaseUrlWhenSameOriginEnforced(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('REQUIRES public_base_url');
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        (new KiwiCaptchaExtension())->load(
            [['secret_key' => str_repeat('a', 32), 'storage' => 'kiwi_captcha.storage.redis', 'public_base_url' => null]],
            $container,
        );
    }

    public function testProdRejectsHttpPublicBaseUrl(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('absolute https:// URL');
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        (new KiwiCaptchaExtension())->load(
            [['secret_key' => str_repeat('a', 32), 'public_base_url' => 'http://captcha.example.com']],
            $container,
        );
    }

    public function testProdRejectsQueryAndPathInPublicBaseUrl(): void
    {
        $this->expectException(\LogicException::class);
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        (new KiwiCaptchaExtension())->load(
            [['secret_key' => str_repeat('a', 32), 'public_base_url' => 'https://captcha.example.com/app?x=1']],
            $container,
        );
    }

    public function testDevAllowsMissingPublicBaseUrl(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'dev');
        $container->setDefinition('my.storage', new Definition(ArrayStorage::class, []));
        (new KiwiCaptchaExtension())->load(
            [['secret_key' => str_repeat('a', 32), 'storage' => 'my.storage']],
            $container,
        );
        self::assertTrue(true, 'dev must allow the Host-derived fallback');
    }

    public function testSiteverifyRequiresAtomicStorageInTestEnvironment(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('ATOMIC storage backend');
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'risk' => [
                    'redis' => ['ttl_margin_secs' => 90],
                    // The siteverify surface cannot faithfully enforce a
                    // post-solve scope: the mapped scope must have
                    // post_solve_check disabled (enforced at compile
                    // time).
                    'scopes' => ['login' => ['id' => 1, 'post_solve_check' => false]],
                    'siteverify_secrets' => ['compat-secret-42' => 'login'],
                ],
            ]],
            $container,
        );
    }

    public function testSiteverifyRequiresAtomicStorageEvenWithBestEffortOverride(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('cannot override');
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_best_effort_storage' => true,
                'allow_local_global_limit_fallback' => true,
                'allow_local_argon_admission_fallback' => true,
                'risk' => ['redis' => ['ttl_margin_secs' => 90], 'scopes' => ['login' => ['id' => 1, 'post_solve_check' => false]], 'siteverify_secrets' => ['compat-secret-42' => 'login']],
            ]],
            $container,
        );
    }

    public function testKernelBootFailsHardInProdWithArrayStorage(): void
    {
        $kernel = new TestKernel('prod', false);
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('ArrayStorage');
        $kernel->boot();
    }
    public function testProductionGlobalLimitRequiresDistributedBackend(): void
    {
        // The architectural invariant: a deployment-wide issuance limit
        // must not silently fall back to a process-local window. In
        // production (no Redis client, no PSR-6 pool) the container
        // refuses, unless the operator explicitly names the fallback.
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('rate_limit_global');
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_best_effort_storage' => true,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );
    }

    public function testProductionArgonAdmissionRequiresDistributedGate(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('argon2_max_concurrent_verifications');
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_local_global_limit_fallback' => true,
                'allow_best_effort_storage' => true,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );
    }

    public function testProductionExplicitFallbackOptionsAreHonored(): void
    {
        // The named fallbacks accept the weaker semantics explicitly.
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_local_global_limit_fallback' => true,
                'allow_local_argon_admission_fallback' => true,
                'allow_best_effort_storage' => true,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );
        self::addToAssertionCount(1);
    }
}
