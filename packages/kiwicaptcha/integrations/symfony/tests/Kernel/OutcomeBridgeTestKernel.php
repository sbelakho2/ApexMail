<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Risk\OutcomeReporterInterface;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;

// The security event shims must exist before the container compiles:
// the extension gates the outcome bridge on the event classes being
// present, and the compile happens after this file is loaded.
(require_once __DIR__.'/../Fixtures/security-event-shims.php') || true;

/**
 * Kernel with the risk engine, the outcomes surface and the security
 * auto-bridge armed: the login scope carries a target field and the
 * outcomes scope names it. A compiler pass swaps the reporter seam for
 * the spy so the bridge's real container wiring can be observed. The
 * kill-switch variant leaves auto_bridge off.
 */
final class OutcomeBridgeTestKernel extends TestKernel
{
    public function __construct(
        string $environment,
        bool $debug,
        private readonly bool $autoBridge = true,
    ) {
        parent::__construct($environment, $debug);
    }

    /**
     * The cache dir carries the auto-bridge flag: both variants of this
     * kernel class run in one test process, and a shared cache dir would
     * hand the kill-switch variant the armed variant's compiled container.
     */
    public function getCacheDir(): string
    {
        return parent::getCacheDir().($this->autoBridge ? '-bridge-on' : '-bridge-off');
    }

    protected function build(ContainerBuilder $container): void
    {
        parent::build($container);
        $container->addCompilerPass(new class implements CompilerPassInterface {
            public function process(ContainerBuilder $container): void
            {
                if ($container->hasDefinition(OutcomeReporterInterface::class)) {
                    $container->setDefinition(OutcomeReporterInterface::class, (new Definition(SpyOutcomeReporter::class))->setPublic(true));
                }
            }
        });
    }

    public function registerContainerConfiguration(\Symfony\Component\Config\Loader\LoaderInterface $loader): void
    {
        $autoBridge = $this->autoBridge;
        $loader->load(function (ContainerBuilder $container) use ($autoBridge): void {
            $container->register('fake_redis', \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient::class)
                ->setPublic(true);
            $container->loadFromExtension('framework', [
                'secret' => 'test-secret',
                'test' => true,
            ]);
            $container->loadFromExtension('twig', [
                'form_themes' => ['@KiwiCaptcha/form_div_layout.html.twig'],
                'paths' => [
                    __DIR__.'/templates' => 'Test',
                ],
            ]);
            $container->loadFromExtension('kiwi_captcha', [
                'secret_key' => self::SECRET,
                'difficulty_bits' => 8,
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'fake_redis',
                    'scopes' => [
                        'login' => ['id' => 10, 'target_field' => 'username'],
                    ],
                    'outcomes' => [
                        'auto_bridge' => $autoBridge,
                        'scope' => 'login',
                    ],
                ],
            ]);
        });
    }
}
