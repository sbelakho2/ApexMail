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
 * Storage safety contract (rounds 26-28):
 *  - the default ArrayStorage is in-memory only: a challenge issued in
 *    request A can never be verified in request B under PHP-FPM — refused
 *    in any non-test/non-dev environment;
 *  - round 28 (P1): production verification REQUIRES an atomic backend
 *    (KiwiCaptcha\AtomicStorageInterface); non-atomic storage is only
 *    possible through the explicitly-named allow_best_effort_storage: true
 *    escape hatch;
 *  - Siteverify's one-success provider contract requires an atomic backend
 *    REGARDLESS of the override — Siteverify + Psr6Storage is refused at
 *    container compile time (the documented PSR-6 race would let two
 *    concurrent requests both win).
 */
final class ProdArrayStorageGuardTest extends TestCase
{
    private function load(string $environment): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', $environment);
        (new KiwiCaptchaExtension())->load([['secret_key' => str_repeat('a', 32)]], $container);

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
            [['secret_key' => str_repeat('a', 32), 'storage' => 'my.shared.storage']],
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
            [['secret_key' => str_repeat('a', 32), 'storage' => 'my.shared.storage']],
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
            [['secret_key' => str_repeat('a', 32), 'storage' => 'my.psr6.storage']],
            $container,
        );
    }

    public function testBestEffortOverrideAllowsNonAtomicStorageInProd(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        $container->setDefinition('my.psr6.storage', new Definition(Psr6Storage::class, []));
        (new KiwiCaptchaExtension())->load(
            [['secret_key' => str_repeat('a', 32), 'storage' => 'my.psr6.storage', 'allow_best_effort_storage' => true]],
            $container,
        );

        self::assertFalse($container->hasDefinition('kiwi_captcha.storage.array'));
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
                'risk' => ['siteverify_secrets' => ['compat-secret-42' => 'login']],
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
                'risk' => ['siteverify_secrets' => ['compat-secret-42' => 'login']],
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
}
