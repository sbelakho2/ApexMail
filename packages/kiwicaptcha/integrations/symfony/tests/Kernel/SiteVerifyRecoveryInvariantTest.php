<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\ConsumedRecord;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;

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
 * makes crash recovery impossible — refused at compile time. Siteverify
 * idempotency ALSO requires a recovery-capable storage
 * (SiteVerifyRecoveryCapableStorageInterface — the bundled
 * AtomicStorageInterface + ConsumedStateReadableInterface combination):
 * custom atomic storages without the consumed-state capability are
 * refused, because the takeover path could never reconstruct a crashed
 * owner's committed outcome. Without siteverify_secrets the native
 * behavior stays unrestricted.
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
            'risk' => ['redis' => ['ttl_margin_secs' => 90], 'enabled' => false, 'siteverify_secrets' => [self::SITEVERIFY_SECRET => 'login']],
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
            'risk' => ['redis' => ['ttl_margin_secs' => 90], 'enabled' => false, 'siteverify_secrets' => [self::SITEVERIFY_SECRET => 'login']],
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

    public function testSiteverifyEnabledWithAtomicStorageMissingConsumedStateIsRefused(): void
    {
        // A custom ATOMIC storage WITHOUT the consumed-state capability
        // (KiwiCaptcha\ConsumedStateReadableInterface) is REFUSED for
        // Siteverify idempotency: crash recovery reads the retained
        // consumed state and is unavailable without it. Ordinary
        // verification remains compatible with any StorageInterface.
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('ConsumedStateReadableInterface');
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setDefinition('my.atomic.storage', new Definition($this->atomicWithoutConsumedStateClass(), []));
        (new KiwiCaptchaExtension())->load([[
            'secret_key' => str_repeat('a', 32),
            'storage' => 'my.atomic.storage',
            'risk' => ['redis' => ['ttl_margin_secs' => 90], 'enabled' => false, 'siteverify_secrets' => [self::SITEVERIFY_SECRET => 'login']],
        ]], $container);
    }

    public function testSiteverifyEnabledWithRecoveryCapableCustomStorageIsAccepted(): void
    {
        // A custom storage implementing the bundle's
        // SiteVerifyRecoveryCapableStorageInterface satisfies the
        // capability contract and is accepted.
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setDefinition('my.capable.storage', new Definition($this->recoveryCapableClass(), []));
        (new KiwiCaptchaExtension())->load([[
            'secret_key' => str_repeat('a', 32),
            'storage' => 'my.capable.storage',
            'risk' => ['redis' => ['ttl_margin_secs' => 90], 'enabled' => false, 'siteverify_secrets' => [self::SITEVERIFY_SECRET => 'login']],
        ]], $container);

        self::assertTrue($container->hasDefinition('kiwi_captcha.config'));
    }

    /** A custom AtomicStorageInterface WITHOUT the consumed-state capability. */
    private function atomicWithoutConsumedStateClass(): string
    {
        return get_class(new class implements \KiwiCaptcha\AtomicStorageInterface {
            public function store(ChallengeRecord $record): void
            {
            }

            public function find(string $nonce): ?ChallengeRecord
            {
                return null;
            }

            public function consume(string $nonce): ?ConsumedRecord
            {
                return null;
            }

            public function commitResult(string $nonce, bool $valid, ?string $binding): bool
            {
                return true;
            }

            public function delete(string $nonce): void
            {
            }
        });
    }

    /** A custom storage implementing the bundle's recovery-capable contract. */
    private function recoveryCapableClass(): string
    {
        return get_class(new class implements \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyRecoveryCapableStorageInterface {
            public function store(ChallengeRecord $record): void
            {
            }

            public function find(string $nonce): ?ChallengeRecord
            {
                return null;
            }

            public function consumedState(string $nonce): ?ConsumedRecord
            {
                return null;
            }

            public function consume(string $nonce): ?ConsumedRecord
            {
                return null;
            }

            public function commitResult(string $nonce, bool $valid, ?string $binding): bool
            {
                return true;
            }

            public function delete(string $nonce): void
            {
            }
        });
    }
}
