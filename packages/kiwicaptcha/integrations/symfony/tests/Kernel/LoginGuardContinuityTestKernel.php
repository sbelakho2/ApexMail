<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Risk\PrincipalResolverInterface;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\TokenStoragePrincipalResolver;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;

/**
 * Kernel for the login-continuity journey over a genuine Redis: the
 * adaptive risk engine, the principal network tag store and the step-up
 * store all run the canonical risk Lua against the live instance. Every
 * binding the journey asserts is the real deployment binding, never an
 * in-memory stand-in.
 *
 * The time-based passcode factor is the step-up handler and the first
 * attempt gate runs in enforce mode. The boot is skipped when
 * KC_REDIS_URL is absent, the same gate as the other real-Redis
 * integration tests.
 */
final class LoginGuardContinuityTestKernel extends TestKernel
{
    /** The raw deployment namespace; every key of this leg lives inside its hash tag. */
    public const NAMESPACE_RAW = 'e2e-login-cont';

    public static function redisUrl(): ?string
    {
        $url = getenv('KC_REDIS_URL');

        return $url === false || $url === '' ? null : $url;
    }

    public function getCacheDir(): string
    {
        return parent::getCacheDir().'-'.md5(self::NAMESPACE_RAW);
    }

    public function getLogDir(): string
    {
        return parent::getLogDir().'-'.md5(self::NAMESPACE_RAW);
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $url = self::redisUrl();
        $loader->load(function (ContainerBuilder $container) use ($url): void {
            $container->setDefinition('kiwi_e2e_redis', new Definition(
                \Predis\Client::class,
                [$url],
            ))->setPublic(true);
            // The firewall's token storage: the guard, the controller and
            // the session restorer all read the same instance.
            $container->register('security.token_storage', TokenStorage::class)
                ->setPublic(true);
            $container->register(PrincipalResolverInterface::class, TokenStoragePrincipalResolver::class)
                ->setArgument('$tokenStorage', new \Symfony\Component\DependencyInjection\Reference('security.token_storage'));
            $container->loadFromExtension('framework', [
                'secret' => 'test-secret',
                'test' => true,
                'router' => [
                    'resource' => __DIR__.'/Fixtures/step_up_routes.php',
                ],
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
                'public_base_url' => 'https://captcha.example.com',
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'kiwi_e2e_redis',
                    'namespace' => self::NAMESPACE_RAW,
                    'novelty_enforcement' => 'enforce',
                    'login_scopes' => ['main' => 'login'],
                    'asn' => ['dataset_path' => StepUpJourneyTestKernel::asnFixturePath()],
                    'scopes' => [
                        'login' => ['id' => 10, 'target_field' => 'username'],
                    ],
                    'outcomes' => [
                        'auto_bridge' => true,
                        'scope' => 'login',
                    ],
                    'step_up' => [
                        'enabled' => true,
                        'scope' => 'login',
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
