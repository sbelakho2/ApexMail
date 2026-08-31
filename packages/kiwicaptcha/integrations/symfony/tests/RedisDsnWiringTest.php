<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Security\ExpectedOrigin;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceRateLimiter;
use BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\EnvDsnTestKernel;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\StorageInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * redis_dsn is the first-class, high-level Redis connection setting.
 * When set (and the corresponding explicit service-id knob is NOT set),
 * the extension constructs the Redis-backed services itself from the
 * DSN. The challenge storage (RedisStorage), the distributed rate
 * limiter, the Argon admission semaphore and (when risk is enabled)
 * the risk state store all run over one Predis\Client built from the
 * DSN. An explicit service id always wins over the DSN for its knob,
 * and every existing wiring stays byte-identical when redis_dsn is
 * absent.
 *
 * Two DSN lanes, both fail-closed. A literal DSN is shape-validated
 * at container build time. A Symfony %env()% placeholder skips the
 * load-time shape check: the client is constructed through a runtime
 * guard that validates the resolved DSN before Predis sees it. A
 * malformed env-resolved DSN then fails closed with the typed
 * LogicException instead of a silent connection to the wrong host.
 */
final class RedisDsnWiringTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';
    private const DSN = 'redis://127.0.0.1:6399/0?password=secret&prefix=kiwi';

    /**
     * @param array<int, array<string, mixed>> $layers
     */
    private function load(array $layers, string $environment = 'test', ?\Closure $register = null): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', $environment);
        if ($register !== null) {
            $register($container);
        }
        (new KiwiCaptchaExtension())->load($layers, $container);

        return $container;
    }

    public function testDsnOnlyConfigBuildsTheClientStorageLimiterAndAdmission(): void
    {
        $container = $this->load([[
            'secret_key' => self::SECRET,
            'redis_dsn' => self::DSN,
            'algorithm' => 'argon2id',
            'argon_m_kib' => 64,
            'argon_t' => 3,
            'argon_p' => 1,
            'argon2_max_concurrent_verifications' => 2,
        ]]);

        // The DSN client is a Predis\Client built from the DSN verbatim.
        $client = $container->getDefinition('kiwi_captcha.redis.dsn');
        self::assertSame(\Predis\Client::class, $client->getClass());
        self::assertSame([self::DSN], $client->getArguments(), 'the DSN is handed to Predis\Client verbatim (scheme, host, db, password and query parameters)');

        // The challenge storage is a RedisStorage over the DSN client,
        // through the checked-client seam (the runtime authority guard
        // runs on the actual client at construction).
        $storage = $container->getDefinition('kiwi_captcha.storage.redis_dsn');
        self::assertSame(RedisStorage::class, $storage->getClass());
        self::assertEquals(new Reference('kiwi_captcha.redis.checked'), $storage->getArgument(0));
        self::assertSame('kiwi_captcha.storage.redis_dsn', (string) $container->getAlias(StorageInterface::class), 'the StorageInterface alias points at the DSN-built storage');

        // The distributed rate limiter and the Argon admission both run
        // on the DSN client, through the same checked seam.
        self::assertSame('kiwi_captcha.redis.checked', (string) $container->getDefinition('kiwi_captcha.rate_limiter')->getArgument(5), 'the atomic rate limiter uses the checked DSN client');
        self::assertSame('kiwi_captcha.redis.checked', (string) $container->getDefinition('kiwi_captcha.argon2_redis_semaphore')->getArgument(0), 'the Argon admission semaphore uses the checked DSN client');
        self::assertTrue($container->hasDefinition('kiwi_captcha.argon2_scope_gate'), 'the scope-aware gate wraps the DSN-backed semaphore');
    }

    public function testDsnWiresTheRiskStoreWhenRiskIsEnabled(): void
    {
        $container = $this->load([[
            'secret_key' => self::SECRET,
            'redis_dsn' => self::DSN,
            'risk' => [
                'enabled' => true,
                'namespace' => 'dsn-risk',
                'scopes' => ['login' => ['id' => 10]],
            ],
        ]]);

        self::assertSame('kiwi_captcha.redis.checked', (string) $container->getDefinition('kiwi_captcha.risk.store')->getArgument(0), 'the risk state store reuses the checked DSN client (Predis, so the canonical risk-v1 EVALSHA store works)');
        self::assertSame('kiwi_captcha.redis.checked', (string) $container->getDefinition('kiwi_captcha.risk.issuance_counter')->getArgument(0), 'the issuance-rate counter uses the checked DSN client');
    }

    public function testExplicitRedisServiceWinsOverTheDsn(): void
    {
        $container = $this->load([[
            'secret_key' => self::SECRET,
            'redis_dsn' => self::DSN,
            'redis_service' => 'my.redis.client',
            'algorithm' => 'argon2id',
            'argon_m_kib' => 64,
            'argon_t' => 3,
            'argon_p' => 1,
            'argon2_max_concurrent_verifications' => 2,
        ]], 'test', static function (ContainerBuilder $c): void {
            $c->register('my.redis.client', \Predis\Client::class);
        });

        // The explicit client wins over the DSN for the limiter and the
        // admission; the DSN storage is NOT built (no storage key set,
        // but the DSN client is not the selected client, so the
        // challenge storage stays the resolved default).
        self::assertSame('kiwi_captcha.redis.checked.my.redis.client', (string) $container->getDefinition('kiwi_captcha.argon2_redis_semaphore')->getArgument(0), 'the explicit redis_service wins over the DSN for the Argon admission, through its own checked wrapper');
        self::assertSame('kiwi_captcha.redis.checked.my.redis.client', (string) $container->getDefinition('kiwi_captcha.rate_limiter')->getArgument(5), 'the explicit redis_service wins over the DSN for the rate limiter, through the checked seam');
        self::assertTrue($container->hasDefinition('kiwi_captcha.redis.dsn'), 'the DSN client is still built (it drives the challenge storage)');
        self::assertTrue($container->hasDefinition('kiwi_captcha.storage.redis_dsn'), 'the DSN still builds the challenge storage when no explicit storage is set');
    }

    public function testExplicitStorageServiceWinsOverTheDsnStorage(): void
    {
        $container = $this->load([[
            'secret_key' => self::SECRET,
            'redis_dsn' => self::DSN,
            'storage' => 'my.redis.storage',
        ]], 'test', static function (ContainerBuilder $c): void {
            $c->register('my.redis.storage', RedisStorage::class)
                ->setArguments([new Reference('my.redis.client')]);
            $c->register('my.redis.client', \Predis\Client::class);
        });

        self::assertFalse($container->hasDefinition('kiwi_captcha.storage.redis_dsn'), 'the explicit storage service wins over the DSN-built storage');
        self::assertSame('my.redis.storage', (string) $container->getAlias(StorageInterface::class), 'the StorageInterface alias follows the explicit storage');
        // The DSN client still drives the unset knobs (limiter/admission).
        self::assertSame('kiwi_captcha.redis.checked', (string) $container->getDefinition('kiwi_captcha.rate_limiter')->getArgument(5), 'the DSN client fills the rate-limit knob no explicit service set, through the checked seam');
    }

    public function testExplicitRiskRedisServiceWinsOverTheDsn(): void
    {
        $container = $this->load([[
            'secret_key' => self::SECRET,
            'redis_dsn' => self::DSN,
            'risk' => [
                'enabled' => true,
                'redis_service' => 'my.predis.client',
                'namespace' => 'dsn-risk',
                'scopes' => ['login' => ['id' => 10]],
            ],
        ]], 'test', static function (ContainerBuilder $c): void {
            $c->register('my.predis.client', \Predis\Client::class);
        });

        self::assertSame('kiwi_captcha.redis.checked.risk', (string) $container->getDefinition('kiwi_captcha.risk.store')->getArgument(0), 'the explicit risk.redis_service wins over the DSN for the risk state, through the checked seam');
    }

    public function testMalformedDsnFailsClosedAtContainerBuild(): void
    {
        foreach (['', 'not-a-url', 'http://127.0.0.1:6399', 'redis://', 'tcp://127.0.0.1:6399'] as $dsn) {
            try {
                $this->load([['secret_key' => self::SECRET, 'redis_dsn' => $dsn]]);
                self::fail(sprintf('the malformed redis_dsn "%s" must fail closed at container build', $dsn));
            } catch (\LogicException $e) {
                self::assertStringContainsString('redis_dsn', $e->getMessage(), 'the refusal names the offending option');
                self::assertStringContainsString('redis://', $e->getMessage(), 'the refusal states the accepted shape');
            }
        }
    }

    public function testDsnSatisfiesTheProductionRedisGuards(): void
    {
        // Without a redis_dsn (and without redis_service), production
        // refuses temporal limits and the Argon admission. The DSN
        // wires a real distributed client, so the same production
        // configuration compiles clean.
        $container = $this->load([[
            'secret_key' => self::SECRET,
            'redis_dsn' => self::DSN,
            'argon2_max_concurrent_verifications' => 2,
            'public_base_url' => 'https://captcha.example.com',
        ]], 'prod');

        self::assertSame('kiwi_captcha.redis.checked', (string) $container->getDefinition('kiwi_captcha.argon2_redis_semaphore')->getArgument(0), 'production Argon admission runs on the checked DSN client');
    }

    public function testNoDsnDefinitionsAreCreatedWhenRedisDsnIsAbsent(): void
    {
        $container = $this->load([['secret_key' => self::SECRET]]);

        self::assertFalse($container->hasDefinition('kiwi_captcha.redis.dsn'), 'no DSN client without redis_dsn');
        self::assertFalse($container->hasDefinition('kiwi_captcha.storage.redis_dsn'), 'no DSN storage without redis_dsn');
        self::assertTrue($container->hasDefinition('kiwi_captcha.storage.array'), 'the existing array-storage wiring is untouched');
    }

    public function testEnvPlaceholderDsnIsAcceptedAtContainerBuild(): void
    {
        // The twelve-factor form: the DSN lives in the environment, not
        // in source-controlled config files. The placeholder is not a
        // literal DSN, so the load-time shape validation skips it and
        // the build succeeds; the client is constructed through the
        // runtime guard once the container resolves the env value.
        $container = $this->load([[
            'secret_key' => self::SECRET,
            'redis_dsn' => '%env(KIWI_REDIS_DSN)%',
        ]]);

        $client = $container->getDefinition('kiwi_captcha.redis.dsn');
        self::assertSame(\Predis\Client::class, $client->getClass(), 'the DSN client stays typed Predis\Client');
        self::assertSame(
            [KiwiCaptchaExtension::class, 'createDsnClient'],
            $client->getFactory(),
            'the env-managed client is constructed through the runtime validation guard',
        );
        self::assertSame(['%env(KIWI_REDIS_DSN)%'], $client->getArguments(), 'the placeholder flows through the container parameter bag untouched');

        self::assertTrue($container->hasDefinition('kiwi_captcha.storage.redis_dsn'), 'the env DSN still builds the challenge storage');
        self::assertSame('kiwi_captcha.redis.checked', (string) $container->getDefinition('kiwi_captcha.rate_limiter')->getArgument(5), 'the atomic rate limiter uses the env-resolved DSN client, through the checked seam');
    }

    public function testEnvPlaceholderPublicBaseUrlPassesTheProductionValidation(): void
    {
        // The production origin guard also tolerates the %env()% form:
        // the resolved value is validated at runtime when the
        // ExpectedOrigin is constructed, never reaching the controller
        // unvalidated.
        $container = $this->load([[
            'secret_key' => self::SECRET,
            'redis_dsn' => self::DSN,
            'public_base_url' => '%env(KIWI_PUBLIC_URL)%',
        ]], 'prod');

        self::assertTrue($container->hasDefinition('kiwi_captcha.redis.dsn'), 'the production build compiles with the placeholder origin');
        $origin = $container->getDefinition('kiwi_captcha.expected_origin');
        self::assertSame(
            [ExpectedOrigin::class, 'fromPublicBaseUrl'],
            $origin->getFactory(),
            'the env-managed origin is constructed through the runtime validation guard',
        );
        self::assertSame(['%env(KIWI_PUBLIC_URL)%'], $origin->getArguments(), 'the placeholder flows through the container parameter bag untouched');
        self::assertEquals(
            new Reference('kiwi_captcha.expected_origin'),
            $container->getDefinition(ChallengeController::class)->getArgument('$expectedOrigin'),
            'the controller receives the validated expected origin, never the raw string',
        );
    }

    public function testEnvPlaceholderPublicBaseUrlInvalidLiteralIsStillRefusedInProduction(): void
    {
        // The placeholder tolerance must not weaken the literal lane: a
        // production literal that is not a clean https origin stays
        // refused at build time.
        $this->expectException(\LogicException::class);
        $this->load([[
            'secret_key' => self::SECRET,
            'redis_dsn' => self::DSN,
            'public_base_url' => 'http://example.com',
        ]], 'prod');
    }

    public function testTheRuntimeGuardValidatesTheResolvedDsnBeforePredisSeesIt(): void
    {
        // The guard factory is the runtime lane for env-managed DSNs: it
        // runs the same fail-closed shape contract on the resolved value.
        // Predis alone is NOT clear enough — a scheme-less string silently
        // defaults to tcp://127.0.0.1 — so the guard must throw the typed
        // LogicException naming the option instead.
        $client = KiwiCaptchaExtension::createDsnClient(self::DSN);
        self::assertInstanceOf(\Predis\Client::class, $client, 'a valid resolved DSN constructs the Predis client');

        foreach (['', 'not-a-url', 'http://127.0.0.1:6399', 'redis://', 'tcp://127.0.0.1:6399'] as $dsn) {
            try {
                KiwiCaptchaExtension::createDsnClient($dsn);
                self::fail(sprintf('the malformed env-resolved DSN "%s" must fail closed at client construction', $dsn));
            } catch (\LogicException $e) {
                self::assertStringContainsString('redis_dsn', $e->getMessage(), 'the runtime refusal names the offending option');
                self::assertStringContainsString('redis://', $e->getMessage(), 'the runtime refusal states the accepted shape');
            }
        }
    }

    public function testEnvPlaceholderDsnResolvedToAMalformedDsnFailsClosedAtRuntime(): void
    {
        // End to end through a real kernel: the config carries the
        // placeholder, the env var resolves to a malformed DSN, and the
        // first construction of the DSN client fails closed with the
        // typed error (the storage's typed failure), never a confusing
        // connection attempt to a defaulted host.
        putenv(EnvDsnTestKernel::REDIS_DSN_ENV.'=not-a-url');
        putenv(EnvDsnTestKernel::PUBLIC_URL_ENV.'=https://captcha.example.com');
        $kernel = new EnvDsnTestKernel('test', true);
        $kernel->boot();
        $container = $kernel->getContainer()->get('test.service_container');

        try {
            try {
                $container->get('kiwi_captcha.redis.dsn');
                self::fail('a malformed env-resolved redis_dsn must fail closed when the client is constructed');
            } catch (\LogicException $e) {
                self::assertStringContainsString('redis_dsn', $e->getMessage(), 'the runtime refusal names the offending option');
                self::assertStringContainsString('redis://', $e->getMessage(), 'the runtime refusal states the accepted shape');
            }
        } finally {
            $kernel->shutdown();
            putenv(EnvDsnTestKernel::REDIS_DSN_ENV);
            putenv(EnvDsnTestKernel::PUBLIC_URL_ENV);
        }
    }
}
