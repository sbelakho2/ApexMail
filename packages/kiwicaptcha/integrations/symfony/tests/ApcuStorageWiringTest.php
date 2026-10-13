<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use KiwiCaptcha\Storage\ApcuStorage;
use KiwiCaptcha\StorageInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * The object form of the storage knob: storage.apcu.single_process_cli
 * registers the bundled ApcuStorage with the single-process cli
 * acknowledgement riding its constructor flag, and the StorageInterface
 * alias resolves to it. The scalar form (a service id) never registers
 * the adapter, so every existing deployment stays byte-identical. The
 * flag itself stays the adapter's constructor concern: apc.enable_cli=1
 * is the ini precondition and the flag the separate hazard
 * acknowledgement, enforced where the segment is actually opened.
 */
final class ApcuStorageWiringTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    /**
     * @param array<string, mixed> $layer
     */
    private function load(array $layer): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        (new KiwiCaptchaExtension())->load([$layer], $container);

        return $container;
    }

    public function testTheObjectFormRegistersTheAdapterWithTheAcknowledgement(): void
    {
        $container = $this->load([
            'secret_key' => self::SECRET,
            'storage' => ['apcu' => ['single_process_cli' => true]],
        ]);

        $definition = $container->getDefinition('kiwi_captcha.storage.apcu');
        self::assertSame(ApcuStorage::class, $definition->getClass());
        self::assertTrue($definition->getArgument('$allowPrivateCliSegment'), 'the single-process acknowledgement rides the constructor flag the adapter and the doctor both read');
        self::assertSame('kiwi_captcha.storage.apcu', (string) $container->getAlias(StorageInterface::class), 'the StorageInterface alias resolves to the registered adapter');
    }

    public function testTheObjectFormDefaultsTheAcknowledgementToFalse(): void
    {
        $container = $this->load([
            'secret_key' => self::SECRET,
            'storage' => ['apcu' => []],
        ]);

        $definition = $container->getDefinition('kiwi_captcha.storage.apcu');
        self::assertFalse($definition->getArgument('$allowPrivateCliSegment'), 'the web-tier shared segment is the default: the flag is the explicit cli acknowledgement only');
    }

    public function testTheScalarFormNeverRegistersTheAdapter(): void
    {
        $container = $this->load([
            'secret_key' => self::SECRET,
            'storage' => 'kiwicaptcha.storage.redis',
        ]);

        self::assertFalse($container->hasDefinition('kiwi_captcha.storage.apcu'), 'the scalar service-id form is untouched: no adapter is registered behind the operator');
        self::assertSame('kiwicaptcha.storage.redis', (string) $container->getAlias(StorageInterface::class));
    }
}
