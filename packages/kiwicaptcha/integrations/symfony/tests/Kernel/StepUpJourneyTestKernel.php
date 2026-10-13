<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Risk\OutcomeReporterInterface;
use BelConsulting\KiwiCaptchaBundle\Risk\PrincipalResolverInterface;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOtpStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\CapturingStepUpCodeSender;
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
 * storage, the security token storage.
 * The typical TokenStorage-backed principal resolver is used, with
 * the getUser semantics. The journey runs on real Redis: the
 * extension's own RedisRiskStateStore and RedisPrincipalNetworkTagStore
 * stay wired (no store replacement, no principal-networks alias), so
 * the engine's novelty read and the step-up restore's record address
 * exactly the deployment's surfaces. Only the step-up code sender and
 * the outcome reporter are swapped for the capturer and the spy — the
 * application's delivery channel and the application's outcome
 * consumer, both app-side. The outcomes trust gate is fail_closed
 * (the store-backed gate is typed to the concrete Redis store).
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

    /**
     * The real-Redis DSN the journey runs on: KC_REDIS_URL, the same
     * env the real-Redis integration suite uses. Null when unset (the
     * test skips).
     */
    public static function redisUrl(): ?string
    {
        $url = getenv('KC_REDIS_URL');

        return \is_string($url) && $url !== '' ? $url : null;
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
                        ->replaceArgument(2, new Reference('step_up_code_capturer'));
                }
                // The risk state store and the principal-network store
                // stay exactly as the extension wired them: the real
                // RedisRiskStateStore and the real
                // RedisPrincipalNetworkTagStore over the journey's own
                // Redis database. No replacement, no alias — a missing
                // seam is a boot failure, never a fixture swap.
                foreach (['kiwi_captcha.risk.store', 'kiwi_captcha.risk.principal_networks'] as $id) {
                    if ($container->hasDefinition($id)) {
                        $container->getDefinition($id)->setPublic(true);
                    }
                }
            }
        });
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(function (ContainerBuilder $container): void {
            $redisUrl = self::redisUrl();
            if ($redisUrl === null) {
                throw new \LogicException('KC_REDIS_URL is not set: the journey kernel runs the real risk engine on real Redis (the test skips without it)');
            }
            $container->register('journey_redis', \Predis\Client::class)
                ->setArguments([$redisUrl])
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
                    'redis_service' => 'journey_redis',
                    'novelty_enforcement' => 'enforce',
                    'login_scopes' => ['main' => 'login'],
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
