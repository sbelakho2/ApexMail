<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * The default ArrayStorage is in-memory only: a challenge issued in request A
 * can never be verified in request B under PHP-FPM. The extension must refuse
 * to boot in any non-test/non-dev environment instead of silently breaking.
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

    public function testCustomStorageServiceIdAllowedInProd(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'prod');
        (new KiwiCaptchaExtension())->load(
            [['secret_key' => str_repeat('a', 32), 'storage' => 'my.shared.storage']],
            $container,
        );

        self::assertFalse($container->hasDefinition('kiwi_captcha.storage.array'));
    }

    public function testKernelBootFailsHardInProdWithArrayStorage(): void
    {
        $kernel = new TestKernel('prod', false);
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('ArrayStorage');
        $kernel->boot();
    }
}
