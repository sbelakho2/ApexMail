<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Risk\PrincipalResolverInterface;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\TokenStoragePrincipalResolver;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;

/**
 * Kernel for the target-account protection journey over a genuine
 * Redis: the adaptive risk engine, the outcome bridge, the risk store
 * and the step-up store all run the canonical Lua against the live
 * instance. The login scope configures username as its target field,
 * so a stuffing storm against one account books the target dimension
 * end to end. Boot is skipped when KC_REDIS_URL is absent, the same
 * gate as the other real-Redis integration tests.
 */
final class TargetProtectionTestKernel extends TestKernel
{
    /** The raw deployment namespace; every key of this leg lives inside its hash tag. */
    public const NAMESPACE_RAW = 'e2e-tgt-prot';

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
            // The firewall's token storage: the guard and the step-up
            // session restorer share one instance.
            $container->register('security.token_storage', TokenStorage::class)
                ->setPublic(true);
            $container->register(PrincipalResolverInterface::class, TokenStoragePrincipalResolver::class)
                ->setArgument('$tokenStorage', new Reference('security.token_storage'));
            $container->loadFromExtension('framework', [
                'secret' => 'test-secret',
                'test' => true,
            ]);
            $container->loadFromExtension('twig', [
                'form_themes' => ['@KiwiCaptcha/form_div_layout.html.twig'],
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
