<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

/**
 * Kernel for the Plane-2 evidence stage end to end: the abuse_first
 * profile, a post-solve-checked login scope and the real risk Lua over
 * a genuine Redis. The kernel arms the profile under which the
 * evidence stage composes on real assessments (the token's telemetry
 * payload plus the measured solve facts) and the decoy-escalation
 * plane is wired. The boot is skipped when KC_REDIS_URL is absent, the
 * same gate as the other real-Redis integration tests.
 */
final class EvidenceCompositionTestKernel extends TestKernel
{
    public static function redisUrl(): ?string
    {
        $url = getenv('KC_REDIS_URL');

        return $url === false || $url === '' ? null : $url;
    }

    public function registerContainerConfiguration(\Symfony\Component\Config\Loader\LoaderInterface $loader): void
    {
        $url = self::redisUrl();
        $loader->load(function (\Symfony\Component\DependencyInjection\ContainerBuilder $container) use ($url): void {
            $container->setDefinition('kiwi_e2e_redis', new \Symfony\Component\DependencyInjection\Definition(
                \Predis\Client::class,
                [$url],
            ))->setPublic(true);
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
                // The abuse posture: the evidence plane composes with the
                // full telemetry arm, the explanation surface and the
                // decoy-escalation reader.
                'protection_profile' => 'abuse_first',
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'kiwi_e2e_redis',
                    'namespace' => 'e2e-evidence',
                    'scopes' => [
                        // The post-solve check keeps the fresh SolveSuccess
                        // assessment on every valid solve, so the evidence
                        // stage composes on a real assessment surface.
                        'login' => ['id' => 10, 'post_solve_check' => true],
                    ],
                ],
            ]);
        });
    }

    public function getCacheDir(): string
    {
        return parent::getCacheDir().'-'.md5('evidence-composition');
    }

    public function getLogDir(): string
    {
        return parent::getLogDir().'-'.md5('evidence-composition');
    }
}
