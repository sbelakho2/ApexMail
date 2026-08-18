<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Siteverify crash-recovery ordering invariant (enforced at container
 * compile time WHEN risk.siteverify_secrets is configured):
 *
 *   max verification window < Siteverify lease (60s) < waiter bound (90s)
 *                            < effective challenge TTL
 *
 * The controller constructor enforces only waiter > lease; the effective
 * token lifetime (global challenge_ttl_secs and every per-sitekey
 * ttl_secs), the min_duration_ms floor and the Argon admission lease
 * (argon2_lease_ms) complete the ordering. A configuration that breaks it
 * makes crash recovery impossible — refused at compile time. Without
 * siteverify_secrets the native behavior stays unrestricted.
 */
final class SiteVerifyRecoveryInvariantTest extends TestCase
{
    private const SITEVERIFY_SECRET = 'compat-secret-42';

    private function load(array $config = []): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        (new KiwiCaptchaExtension())->load([array_merge([
            'secret_key' => str_repeat('a', 32),
        ], $config)], $container);

        return $container;
    }

    public function testSiteverifyEnabledWithShortGlobalTtlIsRefused(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('waiter bound');
        $this->load([
            'challenge_ttl_secs' => 30,
            'risk' => ['redis' => ['ttl_margin_secs' => 90], 'siteverify_secrets' => [self::SITEVERIFY_SECRET => 'login']],
        ]);
    }

    public function testSiteverifyEnabledWithShortSitekeyTtlIsRefused(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('waiter bound');
        $this->load([
            'risk' => [
                'redis' => ['ttl_margin_secs' => 90],
                'sitekeys' => ['sitekey-k' => ['ttl_secs' => 30]],
                'siteverify_secrets' => [self::SITEVERIFY_SECRET => 'login'],
            ],
        ]);
    }

    public function testSiteverifyEnabledWithMinDurationAboveSitekeyTtlIsRefused(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('min_duration_ms');
        $this->load([
            'privacy_mode' => 'standard',
            'challenge_ttl_secs' => 120,
            'min_duration_ms' => 60000,
            'risk' => [
                'redis' => ['ttl_margin_secs' => 90],
                'sitekeys' => ['sitekey-k' => ['ttl_secs' => 30]],
                'siteverify_secrets' => [self::SITEVERIFY_SECRET => 'login'],
            ],
        ]);
    }

    public function testSiteverifyEnabledWithArgonLeaseAboveSiteverifyLeaseIsRefused(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('ownership lease');
        $this->load([
            'argon2_lease_ms' => 60000,
            'risk' => ['redis' => ['ttl_margin_secs' => 90], 'siteverify_secrets' => [self::SITEVERIFY_SECRET => 'login']],
        ]);
    }

    public function testSiteverifyDisabledKeepsShortTtlValid(): void
    {
        $container = $this->load(['challenge_ttl_secs' => 30]);

        self::assertTrue($container->hasDefinition('kiwi_captcha.config'));
    }

    public function testSiteverifyEnabledWithCompliantDefaultsIsAccepted(): void
    {
        $container = $this->load([
            'risk' => [
                'redis' => ['ttl_margin_secs' => 90],
                'enabled' => false,
                'siteverify_secrets' => [self::SITEVERIFY_SECRET => 'login'],
            ],
        ]);

        self::assertTrue($container->hasDefinition('kiwi_captcha.config'));
    }
}
