<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Risk\OutcomeReporterInterface;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JourneyRiskStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\TokenStoragePrincipalResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\PrincipalResolverInterface;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;

/**
 * Kernel for the admin login_step_up always journey. The admin_login
 * scope configures login_step_up always (the abuse_first posture's
 * critical-scope carrier) and books the outcomes facade under itself,
 * so the wired first-attempt gate reads the always mode from its map.
 * The step-up plane arms the time-based handler; the code sender, the
 * outcome reporter and the engine state store are the test fixtures.
 */
final class AdminStepUpAlwaysTestKernel extends TestKernel
{
    public function getCacheDir(): string
    {
        return parent::getCacheDir().'-admin-always';
    }

    public function getLogDir(): string
    {
        return parent::getLogDir().'-admin-always';
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
                if ($container->hasDefinition('kiwi_captcha.risk.store')) {
                    $container->removeDefinition('kiwi_captcha.risk.store');
                    $container->setDefinition('kiwi_captcha.risk.store', (new Definition(JourneyRiskStore::class))->setPublic(true));
                }
                if ($container->hasAlias('kiwi_captcha.risk.principal_networks')) {
                    $container->removeAlias('kiwi_captcha.risk.principal_networks');
                }
                $container->setAlias('kiwi_captcha.risk.principal_networks', 'kiwi_captcha.risk.store')->setPublic(true);
            }
        });
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(function (ContainerBuilder $container): void {
            $container->register('fake_redis', FakePredisClient::class)
                ->setPublic(true);
            $container->register('security.token_storage', TokenStorage::class)
                ->setPublic(true);
            $container->register(PrincipalResolverInterface::class, TokenStoragePrincipalResolver::class)
                ->setArgument('$tokenStorage', new Reference('security.token_storage'));
            $container->loadFromExtension('framework', [
                'secret' => 'test-secret',
                'test' => true,
            ]);
            $container->loadFromExtension('kiwi_captcha', [
                'secret_key' => self::SECRET,
                'difficulty_bits' => 8,
                'public_base_url' => 'https://captcha.example.com',
                'risk' => [
                    'asn' => ['dataset_path' => RiskStageMatrixTestKernel::asnFixturePath()],
                    'enabled' => true,
                    'redis_service' => 'fake_redis',
                    'scopes' => [
                        'admin_login' => ['id' => 30, 'login_step_up' => 'always'],
                    ],
                    'login_scopes' => ['main' => 'admin_login'],
                    'outcomes' => [
                        'auto_bridge' => true,
                        'scope' => 'admin_login',
                    ],
                    'step_up' => [
                        'enabled' => true,
                        'scope' => 'admin_login',
                        'default_handler' => 'totp',
                        'handlers' => [
                            'totp' => ['enabled' => true],
                        ],
                    ],
                ],
            ]);
        });
    }
}
