<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Command\KiwiCaptchaDoctorCommand;
use BelConsulting\KiwiCaptchaBundle\Command\KiwiCaptchaHaInitializeCommand;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\AuthorityGuardedPredisClient;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\PinnedPrimaryAuthorityGuard;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * The ha_authority wiring contract (docs/ha-authority.md). Under
 * "pinned_primary" the bundle wraps the storage/limiter/risk clients
 * with the PinnedPrimaryAuthorityGuard: one guard and one pin per
 * distinct Redis authority (the storage/limiter authority pins
 * `{kiwi:<ns>}:authority:pin:storage`, a distinct risk authority pins
 * `{kiwi:<ns>}:authority:pin:risk`), and the clients are decorated
 * with the per-command AuthorityGuardedPredisClient. The optional
 * ha_authority_expected identity flows into every guard. Under "none"
 * (the default) nothing is wired and the current boundary stays
 * byte-identical. Aggregates, phpredis clients and a missing client
 * are refused at build time. The ha_safe protection profile derives
 * ha_authority pinned_primary + replay_durability operator_managed,
 * and an explicit override in any layer wins.
 */
final class PinnedPrimaryWiringTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const PROJECT_DIR = '/tmp/kiwi-pinned-wiring';

    /**
     * @param array<int, array<string, mixed>> $layers
     */
    private function load(array $layers): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', self::PROJECT_DIR);
        $container->register('fake_redis', FakePredisClient::class);
        (new KiwiCaptchaExtension())->load($layers, $container);

        return $container;
    }

    private function guardDefinition(ContainerBuilder $container, string $suffix = 'storage'): array
    {
        $definition = $container->getDefinition('kiwi_captcha.ha_authority_guard.'.$suffix);

        return [
            'class' => $definition->getClass(),
            'arguments' => $definition->getArguments(),
        ];
    }

    public function testDefaultNoneWiresNoGuardAndKeepsTheCurrentBoundary(): void
    {
        $container = $this->load([
            ['secret_key' => self::SECRET, 'redis_service' => 'fake_redis'],
        ]);

        self::assertFalse($container->hasDefinition('kiwi_captcha.ha_authority_guard.storage'), 'ha_authority defaults to none: no guard is wired');
        self::assertFalse($container->hasDefinition('kiwi_captcha.ha_authority_guard.risk'), 'no risk guard without the posture');
        self::assertFalse($container->hasDefinition('kiwi_captcha.redis.authority_guarded'), 'no client decorator is wired');
        $doctorArgs = $container->getDefinition(KiwiCaptchaDoctorCommand::class)->getArguments();
        self::assertSame([], $doctorArgs[9] ?? null, 'the doctor receives no authority guards');
        self::assertTrue($container->hasDefinition(KiwiCaptchaHaInitializeCommand::class), 'the initialize command is always registered');
        self::assertSame([], $container->getDefinition(KiwiCaptchaHaInitializeCommand::class)->getArgument(1), 'without the posture the initialize command has no guards');
    }

    public function testPinnedPrimaryWiresTheGuardAndDecoratesTheCheckedClient(): void
    {
        $container = $this->load([
            [
                'secret_key' => self::SECRET,
                'redis_service' => 'fake_redis',
                'risk' => ['namespace' => 'prod-eu'],
                'ha_authority' => 'pinned_primary',
            ],
        ]);

        $guard = $this->guardDefinition($container);
        self::assertSame(PinnedPrimaryAuthorityGuard::class, $guard['class'], 'the guard service is the PinnedPrimaryAuthorityGuard');
        $guardArgs = $guard['arguments'];
        self::assertInstanceOf(Reference::class, $guardArgs[0], 'the guard binds to the raw (inner) client');
        self::assertSame(
            'kiwi_captcha.redis.checked.inner',
            (string) $guardArgs[0],
            'the guard binds to the checked client\'s raw inner instance, so its INFO/pin commands never recurse through a guarded wrapper',
        );
        self::assertSame(
            'prod-eu',
            $guardArgs[1],
            'the pin key namespace is the sanitized deployment namespace, like every other bundle key',
        );
        self::assertSame(5, $guardArgs[2], 'the default reverify window is 5 seconds');
        self::assertSame('storage', $guardArgs[3], 'the storage authority pins its own key suffix');
        self::assertNull($guardArgs[4] ?? null, 'no expected identity by default');

        $decorator = $container->getDefinition('kiwi_captcha.redis.authority_guarded');
        self::assertSame(AuthorityGuardedPredisClient::class, $decorator->getClass(), 'the client is wrapped with the per-command guard wrapper');
        [$guardRef, $innerRef] = $decorator->getArguments();
        self::assertSame('kiwi_captcha.ha_authority_guard.storage', (string) $guardRef, 'the wrapper consults the storage guard');
        self::assertSame('.inner', (string) $innerRef, 'the wrapper delegates to the raw client through the decorator inner reference');
        [$decoratedId] = $decorator->getDecoratedService();
        self::assertSame('kiwi_captcha.redis.checked', $decoratedId, 'the checked client the bundle components receive is the guarded decorator');

        $doctorArgs = $container->getDefinition(KiwiCaptchaDoctorCommand::class)->getArguments();
        self::assertSame('kiwi_captcha.ha_authority_guard.storage', (string) $doctorArgs[9]['storage'], 'the doctor receives the storage guard for the HA authority state check');
        self::assertArrayNotHasKey('risk', $doctorArgs[9], 'no risk guard when the risk client is not wired');
        $initializeArgs = $container->getDefinition(KiwiCaptchaHaInitializeCommand::class)->getArguments();
        self::assertSame('kiwi_captcha.ha_authority_guard.storage', (string) $initializeArgs[1]['storage'], 'the initialize command receives the storage guard');

        $health = $container->getDefinition(\BelConsulting\KiwiCaptchaBundle\Controller\KiwiHealthController::class);
        self::assertSame(
            'kiwi_captcha.ha_authority_guard.storage',
            (string) $health->getArgument('$authorityGuards')['storage'],
            'the readiness probe receives the storage guard for its fresh authority-eligibility leg',
        );
        self::assertSame(
            'kiwi_captcha.redis.checked',
            (string) $health->getArgument('$riskRedis'),
            'the risk client rides along (risk is enabled and reuses the storage client here; no risk guard is wired for a shared authority)',
        );
    }

    public function testPinnedPrimaryAppliesToTheDsnBuiltClientToo(): void
    {
        $container = $this->load([
            ['secret_key' => self::SECRET, 'redis_dsn' => 'redis://127.0.0.1:6399', 'ha_authority' => 'pinned_primary'],
        ]);

        self::assertTrue($container->hasDefinition('kiwi_captcha.ha_authority_guard.storage'), 'the DSN lane wires the guard');
        $storageClient = $container->getDefinition('kiwi_captcha.storage.redis_dsn')->getArgument(0);
        self::assertSame('kiwi_captcha.redis.checked', (string) $storageClient, 'the DSN-built storage receives the checked (decorated) client');
    }

    public function testPinnedPrimaryWiresARiskGuardWhenTheRiskClientIsSeparate(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', self::PROJECT_DIR);
        $container->register('fake_redis', FakePredisClient::class);
        $container->register('fake_risk_redis', FakePredisClient::class);
        (new KiwiCaptchaExtension())->load([
            [
                'secret_key' => self::SECRET,
                'redis_service' => 'fake_redis',
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'fake_risk_redis',
                    'request_binding_authority' => 'fake_redis',
                ],
                'ha_authority' => 'pinned_primary',
            ],
        ], $container);

        $storageGuard = $this->guardDefinition($container, 'storage');
        self::assertSame(PinnedPrimaryAuthorityGuard::class, $storageGuard['class']);
        self::assertSame('storage', $storageGuard['arguments'][3], 'the storage authority pins the :storage key');
        $riskGuard = $this->guardDefinition($container, 'risk');
        self::assertSame(PinnedPrimaryAuthorityGuard::class, $riskGuard['class']);
        self::assertSame('risk', $riskGuard['arguments'][3], 'the distinct risk authority pins its own :risk key');
        self::assertNotEquals($storageGuard['arguments'][0], $riskGuard['arguments'][0], 'each guard binds its own raw client');

        $storageDecorator = $container->getDefinition('kiwi_captcha.redis.authority_guarded');
        [$storageGuardRef] = $storageDecorator->getArguments();
        self::assertSame('kiwi_captcha.ha_authority_guard.storage', (string) $storageGuardRef, 'the storage client consults the storage guard');
        $riskDecorator = $container->getDefinition('kiwi_captcha.risk.redis.authority_guarded');
        self::assertSame(AuthorityGuardedPredisClient::class, $riskDecorator->getClass(), 'the separate risk client gets its own guarded wrapper');
        [$decoratedId] = $riskDecorator->getDecoratedService();
        self::assertSame('kiwi_captcha.redis.checked.risk', $decoratedId, 'the risk checked client is decorated');
        [$riskGuardRef] = $riskDecorator->getArguments();
        self::assertSame('kiwi_captcha.ha_authority_guard.risk', (string) $riskGuardRef, 'the risk wrapper consults its own risk guard');

        $doctorArgs = $container->getDefinition(KiwiCaptchaDoctorCommand::class)->getArguments();
        self::assertSame('kiwi_captcha.ha_authority_guard.storage', (string) $doctorArgs[9]['storage']);
        self::assertSame('kiwi_captcha.ha_authority_guard.risk', (string) $doctorArgs[9]['risk'], 'the doctor audits each distinct authority');
        $initializeArgs = $container->getDefinition(KiwiCaptchaHaInitializeCommand::class)->getArguments();
        self::assertSame('kiwi_captcha.ha_authority_guard.risk', (string) $initializeArgs[1]['risk'], 'the initialize command pins each distinct authority');

        $health = $container->getDefinition(\BelConsulting\KiwiCaptchaBundle\Controller\KiwiHealthController::class);
        self::assertSame('kiwi_captcha.ha_authority_guard.storage', (string) $health->getArgument('$authorityGuards')['storage']);
        self::assertSame('kiwi_captcha.ha_authority_guard.risk', (string) $health->getArgument('$authorityGuards')['risk'], 'the readiness leg audits each distinct authority');
        self::assertSame('kiwi_captcha.redis.checked.risk', (string) $health->getArgument('$riskRedis'), 'the readiness leg verifies the risk guard against the risk client');
    }

    public function testPinnedPrimarySharesOneGuardWhenTheRiskClientIsTheStorageClient(): void
    {
        $container = $this->load([
            [
                'secret_key' => self::SECRET,
                'redis_service' => 'fake_redis',
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'fake_redis',
                    'request_binding_authority' => 'fake_redis',
                ],
                'ha_authority' => 'pinned_primary',
            ],
        ]);

        self::assertTrue($container->hasDefinition('kiwi_captcha.ha_authority_guard.storage'), 'the shared authority pins the storage key');
        self::assertFalse($container->hasDefinition('kiwi_captcha.ha_authority_guard.risk'), 'one pin per distinct authority: the risk client IS the storage client');
        self::assertFalse($container->hasDefinition('kiwi_captcha.risk.redis.authority_guarded'), 'no second decorator for the same physical client');
    }

    public function testPinnedPrimaryWiresTheExpectedIdentityIntoEveryGuard(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', self::PROJECT_DIR);
        $container->register('fake_redis', FakePredisClient::class);
        $container->register('fake_risk_redis', FakePredisClient::class);
        (new KiwiCaptchaExtension())->load([
            [
                'secret_key' => self::SECRET,
                'redis_service' => 'fake_redis',
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'fake_risk_redis',
                    'request_binding_authority' => 'fake_redis',
                ],
                'ha_authority' => 'pinned_primary',
                'ha_authority_expected' => 'master|'.str_repeat('a', 40),
            ],
        ], $container);

        $storageGuard = $this->guardDefinition($container, 'storage');
        self::assertSame('master|'.str_repeat('a', 40), $storageGuard['arguments'][4], 'the expected identity flows into the storage guard');
        $riskGuard = $this->guardDefinition($container, 'risk');
        self::assertSame('master|'.str_repeat('a', 40), $riskGuard['arguments'][4], 'the expected identity flows into the risk guard too');
    }

    public function testPinnedPrimaryWiresDistinctExpectedIdentitiesPerAuthority(): void
    {
        // The per-authority map form: storage and risk are different
        // Redis servers and cannot share one run_id, so each guard
        // receives its own expected identity.
        $storageIdentity = 'master|'.str_repeat('a', 40);
        $riskIdentity = 'master|'.str_repeat('b', 40);
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', self::PROJECT_DIR);
        $container->register('fake_redis', FakePredisClient::class);
        $container->register('fake_risk_redis', FakePredisClient::class);
        (new KiwiCaptchaExtension())->load([
            [
                'secret_key' => self::SECRET,
                'redis_service' => 'fake_redis',
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'fake_risk_redis',
                    'request_binding_authority' => 'fake_redis',
                ],
                'ha_authority' => 'pinned_primary',
                'ha_authority_expected' => ['storage' => $storageIdentity, 'risk' => $riskIdentity],
            ],
        ], $container);

        $storageGuard = $this->guardDefinition($container, 'storage');
        self::assertSame($storageIdentity, $storageGuard['arguments'][4], 'the storage guard receives its own expected identity');
        $riskGuard = $this->guardDefinition($container, 'risk');
        self::assertSame($riskIdentity, $riskGuard['arguments'][4], 'the risk guard receives its own expected identity');
        self::assertNotSame(
            $storageGuard['arguments'][4],
            $riskGuard['arguments'][4],
            'distinct authorities never share one expected run_id',
        );
    }

    public function testPinnedPrimaryPerAuthorityMapFallsBackToThePinForAnUnlistedAuthority(): void
    {
        // Only the risk entry is mapped: the storage authority falls
        // back to the pin key (null expected identity — it must be
        // initialized), while the risk guard carries its own identity.
        $riskIdentity = 'master|'.str_repeat('b', 40);
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', self::PROJECT_DIR);
        $container->register('fake_redis', FakePredisClient::class);
        $container->register('fake_risk_redis', FakePredisClient::class);
        (new KiwiCaptchaExtension())->load([
            [
                'secret_key' => self::SECRET,
                'redis_service' => 'fake_redis',
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'fake_risk_redis',
                    'request_binding_authority' => 'fake_redis',
                ],
                'ha_authority' => 'pinned_primary',
                'ha_authority_expected' => ['risk' => $riskIdentity],
            ],
        ], $container);

        $storageGuard = $this->guardDefinition($container, 'storage');
        self::assertNull($storageGuard['arguments'][4] ?? null, 'an unlisted authority falls back to the pin key (it must be initialized)');
        $riskGuard = $this->guardDefinition($container, 'risk');
        self::assertSame($riskIdentity, $riskGuard['arguments'][4], 'the listed risk authority carries its own identity');
    }

    public function testPinnedPrimarySharedAuthorityUsesTheStorageEntry(): void
    {
        // When the risk client IS the storage client there is one
        // physical authority: the storage entry of the map covers it,
        // exactly like the pin suffix — no second guard is wired.
        $storageIdentity = 'master|'.str_repeat('a', 40);
        $container = $this->load([
            [
                'secret_key' => self::SECRET,
                'redis_service' => 'fake_redis',
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'fake_redis',
                    'request_binding_authority' => 'fake_redis',
                ],
                'ha_authority' => 'pinned_primary',
                'ha_authority_expected' => ['storage' => $storageIdentity],
            ],
        ]);

        self::assertTrue($container->hasDefinition('kiwi_captcha.ha_authority_guard.storage'), 'the shared authority pins the storage key');
        self::assertFalse($container->hasDefinition('kiwi_captcha.ha_authority_guard.risk'), 'one pin per distinct authority: the risk client IS the storage client');
        $storageGuard = $this->guardDefinition($container, 'storage');
        self::assertSame($storageIdentity, $storageGuard['arguments'][4], 'the storage entry covers the shared authority');
    }

    public function testPinnedPrimaryAcceptsOneExpectedIdentityRepeatedForTheSharedAuthority(): void
    {
        // M6b legitimate form: the map may repeat the same identity for
        // storage and risk even on one shared physical Redis — exactly
        // one expected identity for the shared authority, so the wiring
        // proceeds (the storage guard carries it, no risk guard).
        $identity = 'master|'.str_repeat('a', 40);
        $container = $this->load([
            [
                'secret_key' => self::SECRET,
                'redis_service' => 'fake_redis',
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'fake_redis',
                    'request_binding_authority' => 'fake_redis',
                ],
                'ha_authority' => 'pinned_primary',
                'ha_authority_expected' => ['storage' => $identity, 'risk' => $identity],
            ],
        ]);

        self::assertTrue($container->hasDefinition('kiwi_captcha.ha_authority_guard.storage'));
        self::assertFalse($container->hasDefinition('kiwi_captcha.ha_authority_guard.risk'), 'one shared authority: no second guard');
        self::assertSame($identity, $this->guardDefinition($container, 'storage')['arguments'][4], 'the shared authority carries its one expected identity');
    }

    public function testPinnedPrimaryRefusesConflictingExpectedIdentitiesOnOneSharedRedis(): void
    {
        // M6b: storage and risk resolve to the same physical Redis but
        // ha_authority_expected supplies different identities for them.
        // A shared physical authority must have exactly one expected
        // identity. Rejected at configuration time, never silently
        // resolved.
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', self::PROJECT_DIR);
        $container->register('fake_redis', FakePredisClient::class);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('one shared physical authority can have exactly one expected identity');

        (new KiwiCaptchaExtension())->load([
            [
                'secret_key' => self::SECRET,
                'redis_service' => 'fake_redis',
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'fake_redis',
                    'request_binding_authority' => 'fake_redis',
                ],
                'ha_authority' => 'pinned_primary',
                'ha_authority_expected' => [
                    'storage' => 'master|'.str_repeat('a', 40),
                    'risk' => 'master|'.str_repeat('b', 40),
                ],
            ],
        ], $container);
    }

    public function testPinnedPrimaryAllowsDistinctExpectedIdentitiesForDistinctAuthorities(): void
    {
        // M6b legitimate distinct-authority case: two physical Redises,
        // each with its own expected identity, wire their own guards.
        // (The wiring assertions live in
        // testPinnedPrimaryWiresDistinctExpectedIdentitiesPerAuthority;
        // this test pins the load-time acceptance.)
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', self::PROJECT_DIR);
        $container->register('fake_redis', FakePredisClient::class);
        $container->register('fake_risk_redis', FakePredisClient::class);
        (new KiwiCaptchaExtension())->load([
            [
                'secret_key' => self::SECRET,
                'redis_service' => 'fake_redis',
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'fake_risk_redis',
                    'request_binding_authority' => 'fake_redis',
                ],
                'ha_authority' => 'pinned_primary',
                'ha_authority_expected' => [
                    'storage' => 'master|'.str_repeat('a', 40),
                    'risk' => 'master|'.str_repeat('b', 40),
                ],
            ],
        ], $container);

        self::assertTrue($container->hasDefinition('kiwi_captcha.ha_authority_guard.storage'));
        self::assertTrue($container->hasDefinition('kiwi_captcha.ha_authority_guard.risk'));
        self::assertSame('master|'.str_repeat('a', 40), $this->guardDefinition($container, 'storage')['arguments'][4]);
        self::assertSame('master|'.str_repeat('b', 40), $this->guardDefinition($container, 'risk')['arguments'][4]);
    }

    public function testPinnedPrimaryRefusesAnAggregateClient(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', self::PROJECT_DIR);
        $container->register('agg_redis', \Predis\Client::class)
            ->setArguments([[
                ['scheme' => 'tcp', 'host' => '127.0.0.1', 'port' => 6398],
            ], [
                'replication' => 'sentinel',
                'service' => 'mymaster',
            ]]);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('ha_authority is "pinned_primary"');

        (new KiwiCaptchaExtension())->load([
            ['secret_key' => self::SECRET, 'redis_service' => 'agg_redis', 'ha_authority' => 'pinned_primary'],
        ], $container);
    }

    public function testPinnedPrimaryRefusesAPhpredisClient(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', self::PROJECT_DIR);
        $container->register('php_redis', \Redis::class);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('phpredis \\Redis cannot be mechanically guarded');

        (new KiwiCaptchaExtension())->load([
            ['secret_key' => self::SECRET, 'redis_service' => 'php_redis', 'ha_authority' => 'pinned_primary'],
        ], $container);
    }

    public function testPinnedPrimaryRefusesWithoutAnyRedisClient(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('no storage/limiter Redis client is wired');

        $this->load([
            ['secret_key' => self::SECRET, 'ha_authority' => 'pinned_primary'],
        ]);
    }

    public function testHaSafeProfileDerivesPinnedPrimaryAndOperatorManaged(): void
    {
        $container = $this->load([
            ['secret_key' => self::SECRET, 'redis_service' => 'fake_redis', 'protection_profile' => 'ha_safe'],
        ]);

        $config = $container->getDefinition(KiwiCaptchaDoctorCommand::class)->getArgument(1);
        self::assertSame('pinned_primary', $config['ha_authority'], 'ha_safe derives ha_authority pinned_primary');
        self::assertSame('operator_managed', $config['replay_durability'], 'ha_safe derives replay_durability operator_managed');
        self::assertTrue($container->hasDefinition('kiwi_captcha.ha_authority_guard.storage'), 'ha_safe wires the mechanical guard');
        self::assertSame('ha_safe', $config['protection_profile'], 'the visible profile stays ha_safe');
    }

    public function testAnExplicitHaAuthorityOverrideWinsOverTheHaSafeProfile(): void
    {
        $container = $this->load([
            [
                'secret_key' => self::SECRET,
                'redis_service' => 'fake_redis',
                'protection_profile' => 'ha_safe',
                'ha_authority' => 'none',
            ],
        ]);

        $config = $container->getDefinition(KiwiCaptchaDoctorCommand::class)->getArgument(1);
        self::assertSame('none', $config['ha_authority'], 'an explicit ha_authority always wins over the profile-derived default');
        self::assertFalse($container->hasDefinition('kiwi_captcha.ha_authority_guard.storage'), 'no guard without the effective pinned_primary posture');
    }
}
