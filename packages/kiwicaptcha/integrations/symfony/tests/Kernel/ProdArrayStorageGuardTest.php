<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use KiwiCaptcha\Storage\Psr6Storage;
use KiwiCaptcha\Storage\RedisStorage;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Cache\Adapter\RedisAdapter;
use Symfony\Component\DependencyInjection\Alias;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ChildDefinition;
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
            [['secret_key' => str_repeat('a', 32), 'storage' => 'my.shared.storage', 'public_base_url' => 'https://captcha.example.com', 'allow_nonredis_rate_limit_fallback' => true, 'allow_local_argon_admission_fallback' => true]],
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
            [['secret_key' => str_repeat('a', 32), 'storage' => 'my.psr6.storage', 'allow_best_effort_storage' => true, 'allow_nonredis_rate_limit_fallback' => true, 'allow_local_argon_admission_fallback' => true, 'public_base_url' => 'https://captcha.example.com']],
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
                'allow_nonredis_rate_limit_fallback' => true,
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
                'allow_nonredis_rate_limit_fallback' => true,
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
                'allow_nonredis_rate_limit_fallback' => true,
                'allow_local_argon_admission_fallback' => true,
                'allow_best_effort_storage' => true,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );
        self::addToAssertionCount(1);
    }

    public function testProductionPerClientOnlyLimitRequiresDistributedBackend(): void
    {
        // The generalized guard: ANY temporal issuance limit (the
        // per-client rate_limit included) without Redis and without a
        // rate_limit_cache pool is refused in production, since under
        // conventional PHP-FPM the object-memory window is
        // request-local and provides no cross-request protection.
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('rate_limit=10');
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_best_effort_storage' => true,
                'rate_limit' => 10,
                'rate_limit_global' => 0,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );
    }

    public function testProductionPerClientLimitCompilesWithRateLimitCache(): void
    {
        // A configured rate_limit_cache (a shared PSR-6 pool service id)
        // counts as a cross-request backend: the temporal-limit guard
        // passes even without Redis. The pool carries a concrete,
        // resolvable, genuinely shared class.
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        $container->setDefinition('my.cache.pool', new Definition(FilesystemAdapter::class, []));
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_best_effort_storage' => true,
                'rate_limit' => 10,
                'rate_limit_global' => 0,
                'rate_limit_cache' => 'my.cache.pool',
                'allow_local_argon_admission_fallback' => true,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );

        self::assertTrue($container->hasDefinition('kiwi_captcha.rate_limiter'), 'the limiter is wired with the pool fallback');
    }

    public function testProductionArrayAdapterRateLimitCacheIsRefused(): void
    {
        // Symfony's in-memory ArrayAdapter holds its items per process,
        // so under PHP-FPM the rate-limit state would be request-local
        // while the production guard believes a shared pool exists. The
        // extension refuses the combination when the pool's class is
        // resolvable at extension time.
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('in-memory adapter');
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        $container->setDefinition('my.cache.pool', new Definition(ArrayAdapter::class, []));
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_best_effort_storage' => true,
                'rate_limit' => 10,
                'rate_limit_global' => 0,
                'rate_limit_cache' => 'my.cache.pool',
                'allow_local_argon_admission_fallback' => true,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );
    }

    public function testProductionArrayAdapterRateLimitCacheCompilesWithBothTemporalLimitsDisabled(): void
    {
        // Round-96: the in-memory-adapter refusal fires only when the
        // pool is the effective limiter backend. With both temporal
        // limits disabled the limiter is not wired at all, so an
        // in-memory pool is harmless and the config compiles.
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        $container->setDefinition('my.cache.pool', new Definition(ArrayAdapter::class, []));
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_best_effort_storage' => true,
                'rate_limit' => 0,
                'rate_limit_global' => 0,
                'rate_limit_cache' => 'my.cache.pool',
                'allow_local_argon_admission_fallback' => true,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );

        self::assertFalse($container->hasDefinition('kiwi_captcha.rate_limiter'), 'both temporal limits disabled means the limiter is not wired');
    }

    public function testProductionArrayAdapterRateLimitCacheCompilesWhenRedisIsWired(): void
    {
        // Round-96: the in-memory-adapter refusal fires only when the
        // pool is the effective limiter backend. With a Redis client
        // wired, the atomic distributed limiter wins and the pool is
        // never selected, so an in-memory pool is harmless and the
        // config compiles.
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        $container->setDefinition('my.cache.pool', new Definition(ArrayAdapter::class, []));
        $container->setDefinition('my.redis.client', new Definition(\Predis\Client::class, [['host' => '127.0.0.1']]));
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_best_effort_storage' => true,
                'rate_limit' => 10,
                'rate_limit_global' => 0,
                'rate_limit_cache' => 'my.cache.pool',
                'redis_service' => 'my.redis.client',
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );

        self::assertTrue($container->hasDefinition('kiwi_captcha.rate_limiter'), 'the atomic distributed limiter is wired from the Redis client');
    }

    public function testProductionArrayAdapterSubclassRateLimitCacheIsRefused(): void
    {
        // A subclass of ArrayAdapter is equally per-process: the guard
        // checks instanceof via the definition class.
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('in-memory adapter');
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        $subclass = new class extends ArrayAdapter {
        };
        $container->setDefinition('my.cache.pool', new Definition($subclass::class, []));
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_best_effort_storage' => true,
                'rate_limit_cache' => 'my.cache.pool',
                'allow_local_argon_admission_fallback' => true,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );
    }

    public function testProductionParentDeclaredArrayAdapterRateLimitCacheIsRefused(): void
    {
        // The canonical framework.cache.pools shape: the pool service is
        // a ChildDefinition whose class lives on the parent
        // (cache.adapter.array). The extension loads before
        // ResolveChildDefinitionsPass flattens the chain, so the guard
        // must resolve the parent itself — a class-less child used to
        // slip through as "unresolvable".
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('in-memory adapter');
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        $container->setDefinition('cache.adapter.array', new Definition(ArrayAdapter::class, []));
        $container->setDefinition('my.cache.pool', new ChildDefinition('cache.adapter.array'));
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_best_effort_storage' => true,
                'rate_limit' => 10,
                'rate_limit_global' => 0,
                'rate_limit_cache' => 'my.cache.pool',
                'allow_local_argon_admission_fallback' => true,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );
    }

    public function testProductionGrandparentArrayAdapterClassIsRefused(): void
    {
        // A multi-level chain: the pool inherits the class from its
        // grandparent. The walk must follow the whole chain, not just
        // the immediate parent.
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('in-memory adapter');
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        $container->setDefinition('cache.adapter.base', new Definition(ArrayAdapter::class, []));
        $container->setDefinition('cache.adapter.mid', new ChildDefinition('cache.adapter.base'));
        $container->setDefinition('my.cache.pool', new ChildDefinition('cache.adapter.mid'));
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_best_effort_storage' => true,
                'rate_limit' => 10,
                'rate_limit_global' => 0,
                'rate_limit_cache' => 'my.cache.pool',
                'allow_local_argon_admission_fallback' => true,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );
    }

    public function testProductionChildClassOverrideToSharedAdapterCompiles(): void
    {
        // The child may override the parent's class: a child of the
        // array adapter whose own class is a genuinely shared adapter
        // must pass the guard (the first non-null class in the
        // child->parent chain wins).
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        $container->setDefinition('cache.adapter.array', new Definition(ArrayAdapter::class, []));
        $child = new ChildDefinition('cache.adapter.array');
        $child->setClass(FilesystemAdapter::class);
        $container->setDefinition('my.cache.pool', $child);
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_best_effort_storage' => true,
                'rate_limit' => 10,
                'rate_limit_global' => 0,
                'rate_limit_cache' => 'my.cache.pool',
                'allow_local_argon_admission_fallback' => true,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );

        self::assertTrue($container->hasDefinition('kiwi_captcha.rate_limiter'), 'a child class override to a genuinely shared adapter passes the guard and wires the limiter');
    }

    public function testProductionChildWithUnknownParentFailsClosed(): void
    {
        // A ChildDefinition whose parent id has no definition cannot be
        // inspected at extension time: production fails closed (an
        // uninspectable pool cannot be proven cross-worker) instead of
        // letting an unknown chain silently pass the guard.
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('cannot be resolved');
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        $container->setDefinition('my.cache.pool', new ChildDefinition('unknown.parent.service'));
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_best_effort_storage' => true,
                'rate_limit' => 10,
                'rate_limit_global' => 0,
                'rate_limit_cache' => 'my.cache.pool',
                'allow_local_argon_admission_fallback' => true,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );
    }

    public function testProductionGenuinelySharedPoolClassCompiles(): void
    {
        // A non-memory adapter (e.g. Symfony's FilesystemAdapter, whose
        // items live on disk and are shared by all workers) passes the
        // production guard: the class is resolvable and is not an
        // in-memory adapter.
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        $container->setDefinition('my.cache.pool', new Definition(FilesystemAdapter::class, []));
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_best_effort_storage' => true,
                'rate_limit' => 10,
                'rate_limit_global' => 0,
                'rate_limit_cache' => 'my.cache.pool',
                'allow_local_argon_admission_fallback' => true,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );

        self::assertTrue($container->hasDefinition('kiwi_captcha.rate_limiter'), 'a genuinely shared pool class passes the guard and wires the limiter');
    }

    public function testProductionUnresolvableRateLimitCacheServiceFailsClosed(): void
    {
        // A pool service id without a visible definition (an external
        // service the extension cannot inspect) fails closed in
        // production — consistent with the storage path's unresolvable
        // refusal: an uninspectable pool cannot be proven cross-worker,
        // so the guard refuses with an actionable message instead of
        // silently trusting the id.
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('cannot be resolved to a service class');
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_best_effort_storage' => true,
                'rate_limit' => 10,
                'rate_limit_global' => 0,
                'rate_limit_cache' => 'external.pool',
                'allow_local_argon_admission_fallback' => true,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );
    }

// ── round-97: parameter-indirected ids, alias chains, parameterized classes ──

    public function testProductionParameterIndirectedIdResolvingToArrayAdapterIsRefused(): void
    {
        // `rate_limit_cache: '%kiwi.rate_pool%'` with the parameter
        // pointing at an ArrayAdapter-backed pool: the placeholder must
        // be resolved before the lookup, so the in-memory-adapter refusal
        // fires instead of the unresolved id string slipping past
        // hasDefinition() as an opaque external id.
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('in-memory adapter');
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setParameter('kiwi.rate_pool', 'cache.app');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        $container->setDefinition('cache.app', new Definition(ArrayAdapter::class, []));
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_best_effort_storage' => true,
                'rate_limit' => 10,
                'rate_limit_global' => 0,
                'rate_limit_cache' => '%kiwi.rate_pool%',
                'allow_local_argon_admission_fallback' => true,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );
    }

    public function testProductionTwoHopAliasToArrayAdapterIsRefused(): void
    {
        // Alias chains longer than one hop must be followed to the end:
        // pool -> alias -> alias -> ArrayAdapter definition. A walk that
        // exits after one hop used to resolve null and pass.
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('in-memory adapter');
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        $container->setDefinition('cache.app', new Definition(ArrayAdapter::class, []));
        $container->setAlias('app.cache', new Alias('cache.app'));
        $container->setAlias('app.cache_alias', new Alias('app.cache'));
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_best_effort_storage' => true,
                'rate_limit' => 10,
                'rate_limit_global' => 0,
                'rate_limit_cache' => 'app.cache_alias',
                'allow_local_argon_admission_fallback' => true,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );
    }

    public function testProductionAliasCycleFailsClosed(): void
    {
        // A cyclic alias chain must terminate (bounded, cycle-guarded)
        // and yield the fail-closed unresolvable refusal, never a hang
        // or a silent pass.
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('cannot be resolved');
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        $container->setAlias('alias.a', new Alias('alias.b'));
        $container->setAlias('alias.b', new Alias('alias.a'));
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_best_effort_storage' => true,
                'rate_limit' => 10,
                'rate_limit_global' => 0,
                'rate_limit_cache' => 'alias.a',
                'allow_local_argon_admission_fallback' => true,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );
    }

    public function testProductionParameterizedClassResolvingToArrayAdapterIsRefused(): void
    {
        // `class: '%app.cache.class%'` on the pool definition: the class
        // placeholder must be resolved through the parameter bag before
        // the is_a() check — a parameterized ArrayAdapter class used to
        // fail is_a() silently and pass.
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('in-memory adapter');
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setParameter('app.cache.class', ArrayAdapter::class);
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        $container->setDefinition('my.cache.pool', new Definition('%app.cache.class%', []));
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_best_effort_storage' => true,
                'rate_limit' => 10,
                'rate_limit_global' => 0,
                'rate_limit_cache' => 'my.cache.pool',
                'allow_local_argon_admission_fallback' => true,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );
    }

    public function testProductionUnresolvableParameterIdFailsClosed(): void
    {
        // A parameter-indirected id whose parameter does not exist at
        // extension time: fail closed with the concrete-id message (the
        // same semantics as the storage path's unresolvable class).
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('cannot be resolved');
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_best_effort_storage' => true,
                'rate_limit' => 10,
                'rate_limit_global' => 0,
                'rate_limit_cache' => '%missing.rate.pool.param%',
                'allow_local_argon_admission_fallback' => true,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );
    }

    public function testProductionParameterIndirectedRedisBackedPoolCompiles(): void
    {
        // No over-rejection: a parameter-indirected id pointing at a
        // genuinely shared, Redis-backed pool with a concrete resolvable
        // class passes the hardened guard and wires the limiter.
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setParameter('kiwi.rate_pool', 'my.redis.pool');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        $container->setDefinition('my.redis.pool', new Definition(RedisAdapter::class, []));
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_best_effort_storage' => true,
                'rate_limit' => 10,
                'rate_limit_global' => 0,
                'rate_limit_cache' => '%kiwi.rate_pool%',
                'allow_local_argon_admission_fallback' => true,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );

        self::assertTrue($container->hasDefinition('kiwi_captcha.rate_limiter'), 'a parameter-indirected Redis-backed pool with a concrete class passes the guard');
    }

    public function testProductionParameterizedClassResolvingToSharedAdapterCompiles(): void
    {
        // No over-rejection: a %param% class resolving to a genuinely
        // shared adapter passes (only ArrayAdapter/subclasses refuse).
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setParameter('app.cache.class', FilesystemAdapter::class);
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        $container->setDefinition('my.cache.pool', new Definition('%app.cache.class%', []));
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_best_effort_storage' => true,
                'rate_limit' => 10,
                'rate_limit_global' => 0,
                'rate_limit_cache' => 'my.cache.pool',
                'allow_local_argon_admission_fallback' => true,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );

        self::assertTrue($container->hasDefinition('kiwi_captcha.rate_limiter'), 'a parameterized class resolving to a shared adapter passes the guard');
    }

    public function testDevEnvironmentStillBootsWithArrayPoolsAndParameterIndirectedIds(): void
    {
        // The mirror of the production guard: dev/test never apply the
        // pool guard at all. A parameter-indirected id pointing at an
        // ArrayAdapter pool with temporal limits enabled compiles in dev
        // and wires the limiter (the same wiring the HardenedTestKernel
        // proves end-to-end in the test environment).
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'dev');
        $container->setParameter('kiwi.rate_pool', 'cache.app');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        $container->setDefinition('cache.app', new Definition(ArrayAdapter::class, []));
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_best_effort_storage' => true,
                'rate_limit' => 10,
                'rate_limit_global' => 0,
                'rate_limit_cache' => '%kiwi.rate_pool%',
                'allow_local_argon_admission_fallback' => true,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );

        self::assertTrue($container->hasDefinition('kiwi_captcha.rate_limiter'), 'dev wires the limiter with the array pool (the guard is production-only)');
    }

    public function testProductionPerClientOnlyLimitCompilesWithTheNonRedisFallbackFlag(): void
    {
        // The new flag name explicitly accepts the non-Redis limiter for
        // ANY temporal issuance limit, per-client included.
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        (new KiwiCaptchaExtension())->load(
            [[
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.psr6.storage',
                'allow_best_effort_storage' => true,
                'rate_limit' => 10,
                'rate_limit_global' => 0,
                'allow_nonredis_rate_limit_fallback' => true,
                'allow_local_argon_admission_fallback' => true,
                'public_base_url' => 'https://captcha.example.com',
            ]],
            $container,
        );

        self::assertTrue($container->hasDefinition('kiwi_captcha.rate_limiter'), 'the fallback flag lets the per-client-only config compile');
    }

    /**
     * @group legacy
     */
    public function testLegacyFallbackFlagNameStillEnablesTheFallbackWithDeprecation(): void
    {
        // The old name is a documented deprecated alias: it still
        // enables the non-Redis rate limiter in production (the
        // extension resolves both names), and the config tree raises
        // the Symfony deprecation pointing at the new name.
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        $deprecations = [];
        $previous = set_error_handler(static function (int $errno, string $errstr) use (&$deprecations): bool {
            if ($errno === \E_USER_DEPRECATED) {
                $deprecations[] = $errstr;
            }

            return true;
        });
        try {
            (new KiwiCaptchaExtension())->load(
                [[
                    'secret_key' => str_repeat('a', 32),
                    'storage' => 'my.psr6.storage',
                    'allow_best_effort_storage' => true,
                    'allow_local_global_limit_fallback' => true,
                    'allow_local_argon_admission_fallback' => true,
                    'public_base_url' => 'https://captcha.example.com',
                ]],
                $container,
            );
        } finally {
            restore_error_handler();
        }

        self::assertTrue($container->hasDefinition('kiwi_captcha.rate_limiter'), 'the deprecated alias still enables the non-Redis limiter');
        self::assertNotEmpty($deprecations, 'using the deprecated flag name must raise a Symfony deprecation');
        self::assertStringContainsString('allow_local_global_limit_fallback', implode("\n", $deprecations), 'the deprecation names the deprecated option');
        self::assertStringContainsString('allow_nonredis_rate_limit_fallback', implode("\n", $deprecations), 'the deprecation points at the new option');
    }
}
