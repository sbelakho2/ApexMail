<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Symfony\Kernel;

use KiwiCaptcha\Symfony\KiwiCaptchaBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\TwigBundle\TwigBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Kernel;

/**
 * Minimal real Symfony kernel used by the kernel integration tests.
 *
 * Boots FrameworkBundle + TwigBundle + KiwiCaptchaBundle with a small
 * difficulty (8 bits) so the proof-of-work is solvable in pure PHP.
 */
final class TestKernel extends Kernel
{
    public const SECRET = '0123456789abcdef0123456789abcdef';

    public function registerBundles(): iterable
    {
        return [
            new FrameworkBundle(),
            new TwigBundle(),
            new KiwiCaptchaBundle(),
        ];
    }

    protected function build(ContainerBuilder $container): void
    {
        // Framework 7 keeps validator/form.factory private; expose them so
        // the tests can drive the real services from the test container.
        $container->addCompilerPass(new class implements CompilerPassInterface {
            public function process(ContainerBuilder $container): void
            {
                foreach (['validator', 'form.factory', 'request_stack', 'twig'] as $id) {
                    if ($container->hasDefinition($id)) {
                        $container->getDefinition($id)->setPublic(true);
                    } elseif ($container->hasAlias($id)) {
                        $container->getAlias($id)->setPublic(true);
                    }
                }
            }
        });
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(function (ContainerBuilder $container): void {
            $container->loadFromExtension('framework', [
                'secret' => 'test-secret',
                'test' => true,
            ]);
            $container->loadFromExtension('twig', [
                'paths' => [
                    __DIR__.'/templates' => 'Test',
                    \dirname(__DIR__, 3).'/templates' => 'KiwiCaptcha',
                ],
            ]);
            $container->loadFromExtension('kiwicaptcha', [
                'secret' => self::SECRET,
                'difficulty_bits' => 8,
            ]);
        });
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir().'/kiwicaptcha-php-kernel-'.md5(static::class).'-'.getmypid().'/'.$this->environment;
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir().'/kiwicaptcha-php-kernel-'.md5(static::class).'-'.getmypid().'/logs';
    }
}
