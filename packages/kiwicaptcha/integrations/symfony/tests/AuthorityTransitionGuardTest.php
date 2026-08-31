<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\AuthorityClassification;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\RuntimeAuthorityClassifier;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceRateLimiter;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorBestEffortSentinelTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorFailClosedSingleNodeTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\FailClosedEnvPostureSentinelTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\FailClosedOpaqueFactoryClientTestKernel;
use KiwiCaptcha\Storage\RedisStorage;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * The runtime authority-transition guard: the authoritative fail_closed
 * enforcement point. The classifier judges the actual constructed client
 * instance (its live connection object), so every wiring path (DSN-built,
 * service id, aliases, decorators, custom factories, env-derived
 * constructions) arrives here as the instance that will serve. The
 * compile-time lanes see only definition shapes and skip env-resolved
 * postures; this guard runs at service construction with the resolved
 * posture, so unknown authority-transition semantics are unsafe until
 * proven safe.
 */
final class AuthorityTransitionGuardTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private static function sentinelClient(): \Predis\Client
    {
        return new \Predis\Client([
            ['scheme' => 'tcp', 'host' => '127.0.0.1', 'port' => 6398, 'timeout' => 0.5],
        ], [
            'replication' => 'sentinel',
            'service' => 'mymaster',
        ]);
    }

    private static function clusterClient(): \Predis\Client
    {
        return new \Predis\Client([
            'tcp://127.0.0.1:7001',
            'tcp://127.0.0.1:7002',
        ], [
            'cluster' => 'redis',
        ]);
    }

    private static function singleNodeClient(): \Predis\Client
    {
        return new \Predis\Client('tcp://127.0.0.1:6399');
    }

    private static function retryEnabledDirectClient(): \Predis\Client
    {
        return new \Predis\Client([
            'host' => '127.0.0.1',
            'retry' => new \Predis\Retry\Retry(new \Predis\Retry\Strategy\ExponentialBackoff(), 3),
        ]);
    }

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

    public function testClassifierJudgesTheActualConnectionObject(): void
    {
        $classifier = new RuntimeAuthorityClassifier('best_effort');

        self::assertSame(AuthorityClassification::Unsafe, $classifier->classify(self::sentinelClient()), 'a Sentinel replication aggregate is a proven authority-change topology');
        self::assertSame(AuthorityClassification::Unsafe, $classifier->classify(self::clusterClient()), 'a Redis Cluster aggregate is a proven authority-change topology');
        self::assertSame(AuthorityClassification::Unsafe, $classifier->classify(self::retryEnabledDirectClient()), 'a direct connection with retries enabled can re-execute a mutation on a replacement connection');
        self::assertSame(AuthorityClassification::Safe, $classifier->classify(self::singleNodeClient()), 'a single-node direct connection is the one authority, it cannot change');
        $opaque = new FakePredisClient();
        $opaque->connectionOverride = null;
        self::assertSame(AuthorityClassification::Unknown, $classifier->classify($opaque), 'a Predis client without an inspectable connection is uninspectable');
        self::assertSame(AuthorityClassification::Unknown, $classifier->classify(new \stdClass()), 'an opaque non-Predis object cannot be classified');
        self::assertSame(AuthorityClassification::Unknown, $classifier->classify('not-a-client'), 'a non-object is uninspectable');
    }

    public function testFailClosedServesOnlyProvenSingleNodeClients(): void
    {
        $guard = new RuntimeAuthorityClassifier('fail_closed');

        $guard->assertServeEligible(self::singleNodeClient());
        self::assertTrue(true, 'a single-node direct client serves under fail_closed');

        foreach (['sentinel' => self::sentinelClient(), 'cluster' => self::clusterClient()] as $kind => $client) {
            try {
                $guard->assertServeEligible($client);
                self::fail(sprintf('the %s aggregate must be refused under fail_closed', $kind));
            } catch (\LogicException $e) {
                self::assertStringContainsString('replay_durability is "fail_closed"', $e->getMessage(), 'the refusal names the posture');
                self::assertStringContainsString('pinned-primary/topology adapter', $e->getMessage(), 'the refusal offers the pinned-primary remediation');
                self::assertStringContainsString('operator_managed', $e->getMessage(), 'the refusal names the operator_managed alternative');
                self::assertStringContainsString('best_effort', $e->getMessage(), 'the refusal names the best_effort alternative');
                if ($kind === 'sentinel') {
                    self::assertStringContainsString('replication aggregate (Sentinel or master-slave)', $e->getMessage(), 'the refusal names the aggregate topology');
                } else {
                    self::assertStringContainsString('Predis Redis Cluster aggregate', $e->getMessage(), 'the refusal names the cluster topology');
                }
            }
        }
    }

    public function testFailClosedRefusesUnknownClients(): void
    {
        $guard = new RuntimeAuthorityClassifier('fail_closed');

        try {
            $guard->assertServeEligible(new \stdClass());
            self::fail('an uninspectable client must be refused under fail_closed: unknown is unsafe until proven safe');
        } catch (\LogicException $e) {
            self::assertStringContainsString('replay_durability is "fail_closed"', $e->getMessage());
            self::assertStringContainsString('cannot be classified as a single-node direct connection', $e->getMessage(), 'the refusal names the classification');
            self::assertStringContainsString('until proven safe', $e->getMessage(), 'the refusal states the unknown-is-unsafe invariant');
            self::assertStringContainsString('pinned-primary/topology adapter', $e->getMessage());
        }
    }

    public function testFailClosedRefusesARetryEnabledDirectClient(): void
    {
        $guard = new RuntimeAuthorityClassifier('fail_closed');

        try {
            $guard->assertServeEligible(self::retryEnabledDirectClient());
            self::fail('a retry-enabled direct client must be refused under fail_closed: the retry wrapper can re-execute a durability-critical transition on a replacement connection');
        } catch (\LogicException $e) {
            self::assertStringContainsString('replay_durability is "fail_closed"', $e->getMessage());
            self::assertStringContainsString('retries ENABLED', $e->getMessage(), 'the refusal names the retry state');
            self::assertStringContainsString('pinned-primary/topology adapter', $e->getMessage(), 'the refusal offers the pinned-primary remediation');
        }
    }

    public function testWeakerPosturesServeEveryClassification(): void
    {
        foreach (['best_effort', 'operator_managed'] as $posture) {
            $guard = new RuntimeAuthorityClassifier($posture);
            $guard->assertServeEligible(self::sentinelClient());
            $guard->assertServeEligible(new \stdClass());
            self::assertTrue(true, sprintf('under %s every classification serves: the doctor carries the deployment contract', $posture));
        }
    }

    public function testGuardServiceIsWiredWithThePosture(): void
    {
        $container = $this->load([[
            'secret_key' => self::SECRET,
            'replay_durability' => 'fail_closed',
            'redis_service' => 'my.redis.client',
        ]], 'test', static function (ContainerBuilder $c): void {
            $c->register('my.redis.client', \Predis\Client::class);
        });

        $guard = $container->getDefinition('kiwi_captcha.authority_transition_guard');
        self::assertSame(RuntimeAuthorityClassifier::class, $guard->getClass());
        self::assertSame(['fail_closed'], $guard->getArguments(), 'the guard is constructed with the resolved posture');

        $container = $this->load([[
            'secret_key' => self::SECRET,
            'replay_durability' => '%env(KIWI_REPLAY_DURABILITY)%',
        ]]);
        self::assertSame(
            ['%env(KIWI_REPLAY_DURABILITY)%'],
            $container->getDefinition('kiwi_captcha.authority_transition_guard')->getArguments(),
            'an env placeholder flows into the guard definition and is resolved when the guard is constructed',
        );
    }

    public function testRedisServiceClientsRideTheCheckedSeam(): void
    {
        $container = $this->load([[
            'secret_key' => self::SECRET,
            'redis_service' => 'my.redis.client',
            'algorithm' => 'argon2id',
            'argon_m_kib' => 64,
            'argon_t' => 3,
            'argon_p' => 1,
            'argon2_max_concurrent_verifications' => 2,
            'risk' => ['enabled' => true, 'redis_service' => 'my.redis.client', 'namespace' => 'seam', 'scopes' => ['login' => ['id' => 10]]],
        ]], 'test', static function (ContainerBuilder $c): void {
            $c->register('my.redis.client', \Predis\Client::class);
        });

        self::assertSame('kiwi_captcha.redis.checked', (string) $container->getDefinition('kiwi_captcha.rate_limiter')->getArgument(5), 'the rate limiter receives the checked client');
        self::assertSame('kiwi_captcha.redis.checked', (string) $container->getDefinition('kiwi_captcha.argon2_redis_semaphore')->getArgument(0), 'the Argon admission receives the checked client');
        self::assertSame('kiwi_captcha.redis.checked', (string) $container->getDefinition('kiwi_captcha.risk.store')->getArgument(0), 'the risk state store receives the same checked client when it reuses the bundle client');
    }

    public function testDistinctRiskRedisServiceRidesItsOwnCheckedSeam(): void
    {
        $container = $this->load([[
            'secret_key' => self::SECRET,
            'redis_service' => 'my.redis.client',
            'risk' => ['enabled' => true, 'redis_service' => 'my.predis.client', 'namespace' => 'seam', 'scopes' => ['login' => ['id' => 10]]],
        ]], 'test', static function (ContainerBuilder $c): void {
            $c->register('my.redis.client', \Predis\Client::class);
            $c->register('my.predis.client', \Predis\Client::class);
        });

        self::assertSame('kiwi_captcha.redis.checked.risk', (string) $container->getDefinition('kiwi_captcha.risk.store')->getArgument(0), 'a distinct risk.redis_service rides its own checked wrapper');
    }

    public function testDsnClientRidesTheCheckedSeam(): void
    {
        $container = $this->load([[
            'secret_key' => self::SECRET,
            'redis_dsn' => 'redis://127.0.0.1:6399/0?prefix=kiwi',
            'algorithm' => 'argon2id',
            'argon_m_kib' => 64,
            'argon_t' => 3,
            'argon_p' => 1,
            'argon2_max_concurrent_verifications' => 2,
            'risk' => ['enabled' => true, 'namespace' => 'seam', 'scopes' => ['login' => ['id' => 10]]],
        ]]);

        self::assertEquals(new Reference('kiwi_captcha.redis.checked'), $container->getDefinition('kiwi_captcha.storage.redis_dsn')->getArgument(0), 'the DSN-built storage receives the checked client');
        self::assertSame('kiwi_captcha.redis.checked', (string) $container->getDefinition('kiwi_captcha.rate_limiter')->getArgument(5), 'the rate limiter receives the checked DSN client');
        self::assertSame('kiwi_captcha.redis.checked', (string) $container->getDefinition('kiwi_captcha.risk.store')->getArgument(0), 'the risk state store reuses the same checked DSN client');
        self::assertTrue($container->hasDefinition('kiwi_captcha.redis.checked'), 'one checked wrapper per raw client');
        self::assertFalse($container->hasDefinition('kiwi_captcha.redis.checked.risk'), 'the risk client is the same raw client, so no second wrapper');
    }

    public function testApplicationDefinedRedisStorageClientIsGuarded(): void
    {
        $container = $this->load([[
            'secret_key' => self::SECRET,
            'storage' => 'my.redis.storage',
        ]], 'test', static function (ContainerBuilder $c): void {
            $c->register('my.redis.client', \Predis\Client::class);
            $c->register('my.redis.storage', RedisStorage::class)
                ->setArguments([new Reference('my.redis.client'), 'kiwicaptcha:']);
        });

        self::assertSame(
            'kiwi_captcha.redis.checked',
            (string) $container->getDefinition('my.redis.storage')->getArgument(0),
            'the durability-critical storage client rides the checked seam even in an application-defined RedisStorage (the same raw client already feeds the limiter, so it shares the one checked wrapper)',
        );
        self::assertNotEquals(new Reference('my.redis.client'), $container->getDefinition('my.redis.storage')->getArgument(0), 'the raw client never reaches the storage unguarded');
    }

    public function testEnvPostureFailClosedRefusesASentinelAggregateAtRuntime(): void
    {
        // The env-resolved posture skips every build-time lane, so the
        // kernel boots; the runtime guard refuses the aggregate when
        // the checked client is first constructed, with the resolved
        // posture named.
        putenv(FailClosedEnvPostureSentinelTestKernel::POSTURE_ENV.'=fail_closed');
        $kernel = new FailClosedEnvPostureSentinelTestKernel('test', true);
        try {
            $kernel->boot();
            $container = $kernel->getContainer()->get('test.service_container');

            try {
                $container->get('kiwi_captcha.redis.checked');
                self::fail('fail_closed with an env-resolved posture and a sentinel aggregate must refuse at first service use');
            } catch (\LogicException $e) {
                self::assertStringContainsString('replay_durability is "fail_closed"', $e->getMessage(), 'the runtime refusal names the resolved posture');
                self::assertStringContainsString('replication aggregate (Sentinel or master-slave)', $e->getMessage());
                self::assertStringContainsString('pinned-primary/topology adapter', $e->getMessage());
            }

            try {
                $container->get('kiwi_captcha.rate_limiter');
                self::fail('a Redis-backed consumer must refuse at construction under the same env-resolved posture');
            } catch (\LogicException $e) {
                self::assertStringContainsString('replay_durability is "fail_closed"', $e->getMessage(), 'the consumer construction path runs the same runtime guard');
            }
        } finally {
            $kernel->shutdown();
            putenv(FailClosedEnvPostureSentinelTestKernel::POSTURE_ENV);
        }
    }

    public function testFailClosedRefusesAnOpaqueFactoryClientAtRuntime(): void
    {
        // The build-time lanes classify definitions: a factory result
        // has no inspectable shape, so the kernel boots. The runtime
        // guard classifies the actual instance and refuses it as
        // unknown, which is the invariant the compile-time classifier
        // could not enforce.
        $kernel = new FailClosedOpaqueFactoryClientTestKernel('test', true);
        $kernel->boot();
        $container = $kernel->getContainer()->get('test.service_container');

        try {
            try {
                $container->get('kiwi_captcha.redis.checked');
                self::fail('fail_closed with an opaque custom-factory client must refuse at first service use');
            } catch (\LogicException $e) {
                self::assertStringContainsString('replay_durability is "fail_closed"', $e->getMessage());
                self::assertStringContainsString('cannot be classified as a single-node direct connection', $e->getMessage(), 'the refusal names the unknown classification');
                self::assertStringContainsString('until proven safe', $e->getMessage());
                self::assertStringContainsString('pinned-primary/topology adapter', $e->getMessage());
            }
        } finally {
            $kernel->shutdown();
        }
    }

    public function testFailClosedSingleNodeServesAtRuntime(): void
    {
        $kernel = new DoctorFailClosedSingleNodeTestKernel('test', true);
        $kernel->boot();
        $container = $kernel->getContainer()->get('test.service_container');

        try {
            $client = $container->get('kiwi_captcha.redis.checked');
            self::assertInstanceOf(\Predis\Client::class, $client, 'a single-node direct client serves under fail_closed');
            $limiter = $container->get('kiwi_captcha.rate_limiter');
            self::assertInstanceOf(IssuanceRateLimiter::class, $limiter, 'a Redis-backed consumer constructs normally on the checked single-node client');
        } finally {
            $kernel->shutdown();
        }
    }

    public function testBestEffortAggregateServesAtRuntimeAndTheDoctorWarns(): void
    {
        $kernel = new DoctorBestEffortSentinelTestKernel('test', true);
        $kernel->boot();
        $container = $kernel->getContainer()->get('test.service_container');

        try {
            $client = $container->get('kiwi_captcha.redis.checked');
            self::assertInstanceOf(\Predis\Client::class, $client, 'an aggregate serves under best_effort: the doctor carries the WARN path');

            $tester = new CommandTester($container->get(\BelConsulting\KiwiCaptchaBundle\Command\KiwiCaptchaDoctorCommand::class));
            $tester->execute([]);
            self::assertStringContainsString('[WARN] Replication topology', $tester->getDisplay(), 'the best_effort aggregate keeps the doctor WARN');
            self::assertStringContainsString('replay_durability is "best_effort"', $tester->getDisplay(), 'the WARN names the chosen posture');
        } finally {
            $kernel->shutdown();
        }
    }
}
