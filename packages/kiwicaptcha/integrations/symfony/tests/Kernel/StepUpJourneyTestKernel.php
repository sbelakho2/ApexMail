<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Risk\OutcomeReporterInterface;
use BelConsulting\KiwiCaptchaBundle\Risk\PrincipalResolverInterface;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOtpStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\CapturingStepUpCodeSender;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JourneyRiskStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\TokenStoragePrincipalResolver;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;

/**
 * Kernel for the full-journey gate test. The risk engine and the
 * step-up plane are armed. Novelty enforcement is 'enforce'. An ASN
 * dataset fixture is present. The real TokenStorage is the firewall's
 * storage (security.token_storage),
 * the typical TokenStorage-backed principal resolver ($security->getUser()
 * semantics), and the journey's in-memory risk surface as the engine
 * state store AND the kiwi_captcha.risk.principal_networks seam. The
 * step-up code sender and the outcome reporter are swapped for the
 * capturer and the spy. The outcomes trust gate is fail_closed (the
 * store-backed gate is typed to the concrete Redis store).
 */
final class StepUpJourneyTestKernel extends TestKernel
{
    /**
     * The shared ASN dataset fixture (the IPtoASN tsv shape), written
     * once per process: 10.0.0.0/8 resolves to ASN 64512.
     */
    public static function asnFixturePath(): string
    {
        $path = sys_get_temp_dir().'/kiwicaptcha-asn-fixture.tsv';
        if (!\array_key_exists(__METHOD__, $GLOBALS) || !$GLOBALS[__METHOD__]) {
            file_put_contents($path, "# test dataset\n10.0.0.0\t10.255.255.255\t64512\n192.168.0.0\t192.168.255.255\t64513\n");
            $GLOBALS[__METHOD__] = true;
        }

        return $path;
    }

    public function getCacheDir(): string
    {
        return parent::getCacheDir().'-journey';
    }

    public function getLogDir(): string
    {
        return parent::getLogDir().'-journey';
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
                if ($container->hasDefinition(EmailOtpStepUpHandler::class)) {
                    $container->setDefinition('step_up_code_capturer', (new Definition(CapturingStepUpCodeSender::class))->setPublic(true));
                    $container->getDefinition(EmailOtpStepUpHandler::class)
                        ->replaceArgument(3, new Reference('step_up_code_capturer'));
                }
                // The journey's in-memory risk surface replaces the
                // Redis-backed state store (the engine's real pipeline
                // runs against it) and serves as the
                // kiwi_captcha.risk.principal_networks seam, one
                // shared instance for the engine's novelty read and the
                // step-up session restore's record.
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
            // The firewall's token storage: the services under test
            // (controller, session restorer, principal resolver) all
            // read the same instance.
            $container->register('security.token_storage', TokenStorage::class)
                ->setPublic(true);
            $container->register(PrincipalResolverInterface::class, TokenStoragePrincipalResolver::class)
                ->setArgument('$tokenStorage', new Reference('security.token_storage'));
            $container->loadFromExtension('framework', [
                'secret' => 'test-secret',
                'test' => true,
                'router' => [
                    'resource' => __DIR__.'/Fixtures/step_up_routes.php',
                ],
            ]);
            $container->loadFromExtension('kiwi_captcha', [
                'secret_key' => self::SECRET,
                'difficulty_bits' => 8,
                'public_base_url' => 'https://captcha.example.com',
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'fake_redis',
                    'novelty_enforcement' => 'enforce',
                    'asn' => ['dataset_path' => self::asnFixturePath()],
                    'scopes' => [
                        'login' => ['id' => 10, 'target_field' => 'username'],
                    ],
                    'outcomes' => [
                        'auto_bridge' => true,
                        'scope' => 'login',
                        'trust_gate' => 'fail_closed',
                    ],
                    'step_up' => [
                        'enabled' => true,
                        'scope' => 'login',
                        'default_handler' => 'email_otp',
                        'handlers' => [
                            'email_otp' => ['enabled' => true],
                        ],
                    ],
                ],
            ]);
        });
    }
}
