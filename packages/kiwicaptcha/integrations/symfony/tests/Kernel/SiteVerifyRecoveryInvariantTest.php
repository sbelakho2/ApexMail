<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\ConsumedRecord;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Siteverify crash-recovery ordering invariant (enforced at container
 * compile time when risk.siteverify_secrets is configured):
 *
 *   max verification window < Siteverify lease (60s) < waiter bound (90s)
 *                            <= retained-state recovery retention
 *
 * The controller constructor enforces only waiter > lease. The Argon
 * admission lease (argon2_lease_ms) and the retained consumed-state
 * retention margin (risk.redis.ttl_margin_secs) complete the ordering;
 * a broken configuration is refused at compile time because it makes
 * crash recovery impossible. Signed token expiry is irrelevant to the
 * reconstruction, so short-lived Siteverify profiles (e.g. 30s TTLs) are
 * fully supported. Siteverify idempotency also requires a
 * recovery-capable storage
 * (SiteVerifyRecoveryCapableStorageInterface — the bundled
 * AtomicStorageInterface + ConsumedStateReadableInterface +
 * OperationIdentityAwareStorageInterface + AtomicDeleteIfPendingInterface
 * combination). Custom atomic storages lacking the identity-aware
 * consume capability are refused: the takeover path could never prove
 * that a claim is the nonce's original logical operation. Stores
 * lacking the fused atomic cleanup are refused too, because their
 * read-then-delete cleanup can erase the committed recovery evidence
 * under concurrency. Without siteverify_secrets the native behavior
 * stays unrestricted.
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

    public function testSiteverifyEnabledWithShortGlobalTtlIsAccepted(): void
    {
        // Signed token expiry is irrelevant to the retained-state
        // reconstruction — a short-lived Siteverify profile (30s) is
        // fully supported as long as the retention margin outlives the
        // takeover/retry horizon.
        $container = $this->load([
            'challenge_ttl_secs' => 30,
            'risk' => ['redis' => ['ttl_margin_secs' => 90], 'enabled' => false, 'siteverify_secrets' => [self::SITEVERIFY_SECRET => 'login']],
        ]);

        self::assertTrue($container->hasDefinition('kiwi_captcha.config'));
    }

    public function testSiteverifyEnabledWithShortSitekeyTtlIsAccepted(): void
    {
        $container = $this->load([
            'risk' => [
                'redis' => ['ttl_margin_secs' => 90],
                'enabled' => false,
                'sitekeys' => ['sitekey-k' => ['ttl_secs' => 30]],
                'siteverify_secrets' => [self::SITEVERIFY_SECRET => 'login'],
            ],
        ]);

        self::assertTrue($container->hasDefinition('kiwi_captcha.config'));
    }

    public function testNativeConfigWithPerSitekeyMinDurationAboveTtlIsRefused(): void
    {
        // The per-sitekey min_duration_ms < ttl_secs * 1000 relation is
        // intrinsic to issuance — it is validated even when Siteverify is
        // disabled.
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('min_duration_ms');
        $this->load([
            'privacy_mode' => 'standard',
            'challenge_ttl_secs' => 120,
            'min_duration_ms' => 60000,
            'risk' => [
                'sitekeys' => ['sitekey-k' => ['ttl_secs' => 30]],
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
        // A custom atomic storage without the consumed-state capability
        // (KiwiCaptcha\ConsumedStateReadableInterface) is refused for
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

    public function testSiteverifyEnabledWithAtomicConsumedStateStorageMissingIdentityCapabilityIsRefused(): void
    {
        // A custom storage that is atomic + consumed-state readable but
        // without the identity-aware consume capability is refused for
        // Siteverify idempotency: the takeover path compares the consumed
        // record's OWN operation identity against the claiming
        // fingerprint, and a storage that cannot record the identity
        // could never prove that a claim is the nonce's original logical
        // operation (reconstruction would silently refuse everything).
        // The refusal names the missing capability.
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('OperationIdentityAwareStorageInterface');
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setDefinition('my.identityless.storage', new Definition($this->atomicWithConsumedStateWithoutIdentityClass(), []));
        (new KiwiCaptchaExtension())->load([[
            'secret_key' => str_repeat('a', 32),
            'storage' => 'my.identityless.storage',
            'risk' => ['redis' => ['ttl_margin_secs' => 90], 'enabled' => false, 'siteverify_secrets' => [self::SITEVERIFY_SECRET => 'login']],
        ]], $container);
    }

    public function testSiteverifyEnabledWithOldThreeCapabilitiesMissingAtomicCleanupIsRefused(): void
    {
        // A custom storage implementing the historical three capabilities
        // (atomic, consumed-state readable, identity-aware consume) but
        // NOT the fused delete-if-pending cleanup is refused: its
        // read-then-delete cheap-failure cleanup can erase the committed
        // recovery evidence under concurrency (a concurrent redemption
        // lands between the retained-state read and the best-effort
        // delete), so the capability cannot be advertised for Siteverify
        // idempotency. The refusal names the missing interface.
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('AtomicDeleteIfPendingInterface');
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setDefinition('my.no.cleanup.storage', new Definition($this->atomicIdentityAwareWithoutCleanupClass(), []));
        (new KiwiCaptchaExtension())->load([[
            'secret_key' => str_repeat('a', 32),
            'storage' => 'my.no.cleanup.storage',
            'risk' => ['redis' => ['ttl_margin_secs' => 90], 'enabled' => false, 'siteverify_secrets' => [self::SITEVERIFY_SECRET => 'login']],
        ]], $container);
    }

    public function testSiteverifyEnabledWithTheBundledRedisStorageIsAccepted(): void
    {
        // The bundled Redis storage implements all four capabilities
        // (atomic transition, retained-state read, identity-aware
        // consume, fused delete-if-pending Lua cleanup) and passes the
        // boot guard — no Redis connection is needed at compile time,
        // only the class resolution (the client argument is referenced,
        // never instantiated).
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setDefinition('my.redis.client', new Definition(\Predis\Client::class));
        $container->setDefinition('my.redis.storage', new Definition(\KiwiCaptcha\Storage\RedisStorage::class, [new Reference('my.redis.client')]));
        (new KiwiCaptchaExtension())->load([[
            'secret_key' => str_repeat('a', 32),
            'storage' => 'my.redis.storage',
            'risk' => ['redis' => ['ttl_margin_secs' => 90], 'enabled' => false, 'siteverify_secrets' => [self::SITEVERIFY_SECRET => 'login']],
        ]], $container);

        self::assertTrue($container->hasDefinition('kiwi_captcha.config'));
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

    /** A custom AtomicStorageInterface without the consumed-state capability. */
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

    /** A custom atomic + consumed-state readable storage without the identity-aware consume. */
    private function atomicWithConsumedStateWithoutIdentityClass(): string
    {
        return get_class(new class implements \KiwiCaptcha\AtomicStorageInterface, \KiwiCaptcha\ConsumedStateReadableInterface {
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

    /**
     * A custom storage with the historical three capabilities (atomic,
     * consumed-state readable, identity-aware) but lacking the fused
     * delete-if-pending cleanup.
     */
    private function atomicIdentityAwareWithoutCleanupClass(): string
    {
        return get_class(new class implements \KiwiCaptcha\AtomicStorageInterface, \KiwiCaptcha\ConsumedStateReadableInterface, \KiwiCaptcha\OperationIdentityAwareStorageInterface {
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

            public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?ConsumedRecord
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

    /** A custom storage implementing the bundle's recovery-capable contract (all four capabilities). */
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

            public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?ConsumedRecord
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

            public function deleteIfPending(string $nonce): \KiwiCaptcha\DeleteIfPendingResult
            {
                return new \KiwiCaptcha\DeleteIfPendingResult('missing');
            }
        });
    }
}
