<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Command\KiwiCaptchaDoctorCommand;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorBestEffortSentinelTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorExecutionRequiredVersionKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorExplicitV3WriterKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorFailClosedClusterTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorFailClosedSentinelTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorFailClosedSingleNodeTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorFailingRedisTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorHighAbuseDecoyDeferredKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorHighAbuseDecoyDeferredNormalKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorHighAbuseV3WriterKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorNullClearedProfileV3WriterKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorOperatorManagedSentinelTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorPinnedPrimaryTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorHaSafeTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorRedisStorageNoWaitKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorRedisStorageNoWaitOperatorManagedKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorSentinelRedisTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorV3WriterTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\TestKernel;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Kernel-based tests of kiwicaptcha:doctor: the command runs against
 * the real container the extension wired, reports one status per check,
 * and exits non-zero when any check fails.
 */
final class KiwiCaptchaDoctorCommandTest extends TestCase
{
    private function doctor(ContainerInterface $container): CommandTester
    {
        $command = $container->get(KiwiCaptchaDoctorCommand::class);
        self::assertInstanceOf(KiwiCaptchaDoctorCommand::class, $command);

        return new CommandTester($command);
    }

    private function containerFor(\Symfony\Component\HttpKernel\Kernel $kernel): ContainerInterface
    {
        $kernel->boot();

        return $kernel->getContainer()->get('test.service_container');
    }

    public function testCommandIsRegisteredWithTheConsoleTag(): void
    {
        // The extension's load() is the single source of the registration
        // (the pattern used by every wiring test in this suite).
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', sys_get_temp_dir());
        (new KiwiCaptchaExtension())->load([['secret_key' => str_repeat('a', 32)]], $container);
        $definition = $container->getDefinition(KiwiCaptchaDoctorCommand::class);
        self::assertTrue($definition->hasTag('console.command'), 'the doctor must be registered as a console command');

        $kernel = new TestKernel('test', true);
        $kernel->boot();
        $command = $kernel->getContainer()->get('test.service_container')->get(KiwiCaptchaDoctorCommand::class);
        self::assertSame('kiwicaptcha:doctor', $command->getName());
    }

    public function testDoctorPassesOrWarnsOnTheDefaultTestKernel(): void
    {
        $tester = $this->doctor($this->containerFor(new TestKernel('test', true)));
        $tester->execute([]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), 'no FAIL means exit 0');
        $display = $tester->getDisplay();

        // pass paths on the default kernel.
        self::assertStringContainsString('[PASS] Storage atomicity', $display);
        self::assertStringContainsString('[PASS] Replication topology', $display, 'the default kernel has no Redis-backed storage and no aggregate client, so the authority-boundary check passes');
        self::assertStringContainsString('[PASS] Secret key', $display);
        self::assertStringContainsString('[PASS] Keyring state', $display);
        self::assertStringContainsString('[PASS] Public origin', $display);
        self::assertStringContainsString('[PASS] Risk Redis', $display);
        self::assertStringContainsString('[PASS] Protocol floor', $display);
        self::assertStringContainsString('[PASS] Protocol-v3 writer', $display);
        self::assertStringContainsString('[PASS] Argon memory envelope', $display);
        self::assertStringContainsString('[PASS] Argon concurrency', $display);
        self::assertStringContainsString('[PASS] SiteVerify status', $display);
        self::assertStringContainsString('[PASS] Chained challenges', $display);

        // warn paths: no Redis client, no trusted proxy,
        // unverifiable CSP, dev install versions.
        self::assertStringContainsString('[WARN] Redis reachability', $display);
        self::assertStringContainsString('[WARN] Client-IP policy', $display);
        self::assertStringContainsString('[WARN] CSP compatibility', $display);
        self::assertStringContainsString('[WARN] Release versions', $display);

        self::assertStringNotContainsString('[FAIL]', $display, 'the default test kernel must not FAIL any check');
        self::assertStringContainsString('Summary: ', $display);
    }

    public function testDoctorFailsWithANonZeroExitCodeWhenRedisIsUnreachable(): void
    {
        $tester = $this->doctor($this->containerFor(new DoctorFailingRedisTestKernel('test', true)));
        $tester->execute([]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode(), 'a FAIL must produce a non-zero exit code');
        $display = $tester->getDisplay();
        self::assertStringContainsString('[FAIL] Redis reachability', $display);
        self::assertStringContainsString('[FAIL] Risk Redis', $display, 'the risk Redis ping uses the same broken client');
        self::assertStringContainsString('Summary: ', $display);
    }

    public function testDoctorWarnsOnASentinelAggregateWiredClient(): void
    {
        // The replication-topology check must detect the Predis
        // Sentinel replication aggregate by client class and emit the
        // explicit authority-change contract warning with the
        // documented postures, without a live sentinel (the aggregate
        // is built lazily; the reachability check fails on PING as in
        // the failing-Redis kernel).
        $tester = $this->doctor($this->containerFor(new DoctorSentinelRedisTestKernel('test', true)));
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('[WARN] Replication topology', $display, 'an aggregate client must warn on the replication-topology check');
        self::assertStringContainsString('SentinelReplication', $display, 'the detection must name the wired aggregate class');
        self::assertStringContainsString(
            'One-shot verification is atomic on the current Redis authority but is not guaranteed across stale-replica promotion',
            $display,
            'the WARN must carry the exact audit contract wording',
        );
        self::assertStringContainsString('fail_closed / operator_managed / best_effort', $display, 'the WARN must name the documented deployment postures');
    }

    public function testDoctorWarnsOnRedisBackedStorageWithoutTheVerifiedWaitKnob(): void
    {
        // Redis-backed storage with waitReplicas 0 is the default
        // production shape: the promotion boundary applies and the
        // check must warn with the exact audit contract wording, even
        // though the wired client is a single-node direct connection.
        $tester = $this->doctor($this->containerFor(new DoctorRedisStorageNoWaitKernel('test', true)));
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('[WARN] Replication topology', $display, 'Redis-backed storage with waitReplicas 0 must warn on the replication-topology check');
        self::assertStringContainsString('waitReplicas 0', $display);
        self::assertStringContainsString(
            'One-shot verification is atomic on the current Redis authority but is not guaranteed across stale-replica promotion',
            $display,
            'the WARN must carry the exact audit contract wording',
        );
    }

    /**
     * Load the extension against a container holding an aggregate
     * client definition registered beforehand, the shape the
     * build-time fail_closed refusal must classify.
     *
     * @param array{0: array, 1: array} $arguments Predis constructor args
     *
     * @return \LogicException the refused-build exception
     */
    private function assertFailClosedBuildRefusal(string $serviceId, array $arguments, string $expectedClass): \LogicException
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', sys_get_temp_dir());
        $container->register($serviceId, \Predis\Client::class)
            ->setArguments($arguments)
            ->setPublic(true);
        try {
            (new KiwiCaptchaExtension())->load([[
                'secret_key' => str_repeat('a', 32),
                'replay_durability' => 'fail_closed',
                'redis_service' => $serviceId,
            ]], $container);
            self::fail(sprintf('fail_closed with an aggregate client (%s) must refuse the container build', $expectedClass));
        } catch (\LogicException $e) {
            self::assertStringContainsString('replay_durability is "fail_closed"', $e->getMessage(), 'the refusal must name the posture');
            self::assertStringContainsString('pinned-primary/topology adapter', $e->getMessage(), 'the refusal must offer the pinned-primary remediation');
            self::assertStringContainsString('operator_managed', $e->getMessage(), 'the refusal must name the operator_managed alternative');
            self::assertStringContainsString('best_effort', $e->getMessage(), 'the refusal must name the best_effort alternative');

            return $e;
        }
    }

    public function testFailClosedRefusesTheSentinelAggregateAtContainerBuildTime(): void
    {
        $e = $this->assertFailClosedBuildRefusal('doctor.sentinel.redis', [[
            ['scheme' => 'tcp', 'host' => '127.0.0.1', 'port' => 6398, 'timeout' => 0.5],
        ], [
            'replication' => 'sentinel',
            'service' => 'mymaster',
        ]], 'Sentinel replication');

        self::assertStringContainsString('replication aggregate (Sentinel or master-slave)', $e->getMessage(), 'the refusal must name the aggregate class');
    }

    public function testFailClosedRefusesTheClusterAggregateAtContainerBuildTime(): void
    {
        $e = $this->assertFailClosedBuildRefusal('doctor.cluster.redis', [[
            'tcp://127.0.0.1:7001',
            'tcp://127.0.0.1:7002',
        ], [
            'cluster' => 'redis',
        ]], 'Redis Cluster');

        self::assertStringContainsString('Predis Redis Cluster aggregate', $e->getMessage(), 'the refusal must name the cluster aggregate');
    }

    public function testFailClosedRefusesTheSentinelAggregateAtKernelBoot(): void
    {
        $kernel = new DoctorFailClosedSentinelTestKernel('test', true);
        try {
            $kernel->boot();
            self::fail('fail_closed with a sentinel aggregate must refuse the kernel boot');
        } catch (\LogicException $e) {
            self::assertStringContainsString('replay_durability is "fail_closed"', $e->getMessage());
            self::assertStringContainsString('pinned-primary/topology adapter', $e->getMessage());
        }
    }

    public function testFailClosedRefusesTheClusterAggregateAtKernelBoot(): void
    {
        $kernel = new DoctorFailClosedClusterTestKernel('test', true);
        try {
            $kernel->boot();
            self::fail('fail_closed with a cluster aggregate must refuse the kernel boot');
        } catch (\LogicException $e) {
            self::assertStringContainsString('replay_durability is "fail_closed"', $e->getMessage());
            self::assertStringContainsString('Predis Redis Cluster aggregate', $e->getMessage());
        }
    }

    public function testFailClosedSingleNodeCompilesAndTheDoctorPassesReplicationTopology(): void
    {
        // Single-node direct clients are fine under every posture: the
        // build accepts the wiring and the doctor reports the topology
        // check PASSing with the posture noted.
        $tester = $this->doctor($this->containerFor(new DoctorFailClosedSingleNodeTestKernel('test', true)));
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('[PASS] Replication topology', $display, 'fail_closed with a single-node direct client must pass the topology check');
        self::assertStringContainsString('replay_durability "fail_closed"', $display, 'the PASS must note the posture');
    }

    public function testOperatorManagedSentinelAggregateCompilesAndTheDoctorPasses(): void
    {
        // operator_managed owns promotion eligibility: the build
        // accepts the aggregate and the doctor reports pass with the
        // operator contract noted, never the best_effort warn.
        $tester = $this->doctor($this->containerFor(new DoctorOperatorManagedSentinelTestKernel('test', true)));
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('[PASS] Replication topology', $display, 'operator_managed with an aggregate must pass the topology check');
        self::assertStringContainsString('replay_durability "operator_managed"', $display);
        self::assertStringContainsString('owns promotion eligibility', $display, 'the PASS must keep the operator contract note');
        self::assertStringNotContainsString('[WARN] Replication topology', $display);
    }

    public function testBestEffortSentinelAggregateCompilesAndTheDoctorWarns(): void
    {
        // The explicit best_effort posture is the current boundary: the
        // build accepts the aggregate and the doctor keeps the warn
        // with the posture named.
        $tester = $this->doctor($this->containerFor(new DoctorBestEffortSentinelTestKernel('test', true)));
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('[WARN] Replication topology', $display, 'best_effort with an aggregate must keep the topology WARN');
        self::assertStringContainsString('replay_durability is "best_effort"', $display, 'the WARN must name the chosen posture');
        self::assertStringContainsString('fail_closed / operator_managed / best_effort', $display);
    }

    public function testOperatorManagedRedisBackedStorageWithoutTheWaitKnobPasses(): void
    {
        // A single-node direct client under operator_managed: the
        // operator owns the authority-change contract, so the
        // waitReplicas-0 warn becomes a pass with the contract noted.
        $tester = $this->doctor($this->containerFor(new DoctorRedisStorageNoWaitOperatorManagedKernel('test', true)));
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('[PASS] Replication topology', $display, 'operator_managed with Redis-backed storage at waitReplicas 0 must pass');
        self::assertStringContainsString('waitReplicas 0', $display);
        self::assertStringContainsString('operator_managed', $display);
    }

    public function testDoctorReportsThePinnedPrimaryGuardArmedState(): void
    {
        // The production runtime never auto-pins: the operator records
        // the initial authority pin through kiwicaptcha:ha-initialize,
        // and the doctor then reports the armed state (per-authority
        // pinned identity, the mechanically enforced posture and
        // exactly what the guard enforces).
        $container = $this->containerFor(new DoctorPinnedPrimaryTestKernel('test', true));
        $guard = $container->get('kiwi_captcha.ha_authority_guard.storage');
        $guard->initializePin();
        $tester = $this->doctor($container);
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('[PASS] HA authority', $display);
        self::assertStringContainsString('pinned master|0123456789abcdef0123456789abcdef01234567', $display, 'the doctor names the pinned identity');
        self::assertStringContainsString('replay_durability "operator_managed" is mechanically enforced', $display);
        self::assertStringContainsString('per-authority pins', $display, 'the PASS states the per-authority pin enforcement');
        self::assertStringContainsString('zero-stale security-final', $display, 'the PASS states the zero-stale security-final enforcement');
        self::assertStringContainsString('connection-generation cache invalidation', $display, 'the PASS states the connection-generation invalidation');
        self::assertStringContainsString('operator-initialized bootstrap', $display, 'the PASS states the operator-initialized bootstrap');
        self::assertSame(Command::SUCCESS, $tester->getStatusCode());

        $fake = $container->get('doctor.pinned.redis');
        self::assertInstanceOf(FakePredisClient::class, $fake);
        $pin = $fake->strings[$guard->pinKey()] ?? null;
        self::assertSame('master|0123456789abcdef0123456789abcdef01234567', $pin, 'the initialization recorded the authority to the namespace pin key');
    }

    public function testDoctorFailsWhenPinnedPrimaryIsUninitialized(): void
    {
        // No pin and no ha_authority_expected: the guard refuses every
        // check, and the doctor FAILs with the explicit bootstrap
        // message. The production runtime never auto-pins.
        $container = $this->containerFor(new DoctorPinnedPrimaryTestKernel('test', true));
        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString('[FAIL] HA authority', $display);
        self::assertStringContainsString('the deployment is not bootstrapped', $display, 'the doctor names the uninitialized state');
        self::assertStringContainsString('never auto-pins', $display, 'the doctor states the no-auto-pin contract');
        self::assertStringContainsString('kiwicaptcha:ha-initialize', $display, 'the doctor names the explicit bootstrap command');
    }

    public function testDoctorFailsWhenThePinnedAuthorityChanged(): void
    {
        // A changed authority under pinned_primary: the doctor FAILs
        // with the guard's exact refusal (pinned vs observed + the
        // re-pin remediation), so the deploy gate refuses to pass a
        // deployment whose authority moved.
        $container = $this->containerFor(new DoctorPinnedPrimaryTestKernel('test', true));
        $fake = $container->get('doctor.pinned.redis');
        self::assertInstanceOf(FakePredisClient::class, $fake);
        $guard = $container->get('kiwi_captcha.ha_authority_guard.storage');
        // Pre-seed a pin to a different run_id than the fake serves:
        // the guard observes the change and refuses.
        $fake->strings[$guard->pinKey()] = 'master|'.str_repeat('a', 40);
        $fake->infoReplication['run_id'] = str_repeat('b', 40);
        $fake->infoServer['run_id'] = str_repeat('b', 40);

        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode(), 'a changed pinned authority must fail the deploy gate');
        $display = $tester->getDisplay();
        self::assertStringContainsString('[FAIL] HA authority', $display);
        self::assertStringContainsString('the serving authority changed — pinned master|'.str_repeat('a', 40), $display);
        self::assertStringContainsString('observed master|'.str_repeat('b', 40), $display);
        self::assertStringContainsString('Re-pin explicitly after a deliberate authority change', $display);
    }

    public function testDoctorFailsWhenTheHaSafeProfilePromiseWasOverridden(): void
    {
        // protection_profile ha_safe derives pinned_primary; an
        // explicit ha_authority: none drops the mechanical enforcement,
        // and the doctor FAILs: the profile's promise cannot silently
        // weaken.
        $container = $this->containerFor(new DoctorHaSafeTestKernel('test', true, true));
        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString('[FAIL] HA authority', $display);
        self::assertStringContainsString('"ha_safe" promises the pinned-primary authority guard, but ha_authority is "none"', $display);
    }

    public function testDoctorPassesOnTheHaSafeProfileDerivedPosture(): void
    {
        // The ha_safe profile alone derives pinned_primary +
        // operator_managed and wires the guard: the operator records
        // the pin through the initialize command, and the doctor then
        // passes armed.
        $container = $this->containerFor(new DoctorHaSafeTestKernel('test', true));
        $guard = $container->get('kiwi_captcha.ha_authority_guard.storage');
        $guard->initializePin();
        $tester = $this->doctor($container);
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        self::assertStringContainsString('[PASS] HA authority', $display);
        self::assertStringContainsString('pinned-primary guard armed', $display);
    }

    /**
     * Seed the fake security Redis' central policy hash with a
     * `min_protocol_version` floor, the same `{kiwi:<ns>}:security-policy`
     * read the doctor's protocol-floor and protocol-v3 writer checks
     * consume through the SecurityEpochMonitor.
     */
    private function seedProtocolFloor(ContainerInterface $container, int $floor): void
    {
        $fake = $container->get(DoctorV3WriterTestKernel::FAKE_REDIS_ID);
        self::assertInstanceOf(FakePredisClient::class, $fake);
        $fake->hashes[DoctorV3WriterTestKernel::POLICY_KEY] = [
            'min_protocol_version' => (string) $floor,
        ];
    }

    /**
     * Seed the fake security Redis' central policy hash with both
     * confirmed floors: `min_protocol_version` (the protocol-v3/v4
     * writer gate) and `min_execution_version` (the execution-version
     * writer gate), the same `{kiwi:<ns>}:security-policy` read the
     * doctor's protocol-floor, protocol-v3 writer and
     * execution-versioning checks consume through the
     * SecurityEpochMonitor.
     */
    private function seedFloors(ContainerInterface $container, int $protocolFloor, int $executionFloor): void
    {
        $fake = $container->get(DoctorV3WriterTestKernel::FAKE_REDIS_ID);
        self::assertInstanceOf(FakePredisClient::class, $fake);
        $fake->hashes[DoctorV3WriterTestKernel::POLICY_KEY] = [
            'min_protocol_version' => (string) $protocolFloor,
            'min_execution_version' => (string) $executionFloor,
        ];
    }

    public function testDoctorFailsOnHighAbuseWithAnAbsentProtocolFloor(): void
    {
        // high_abuse promises the decoy surface; without a confirmed
        // central floor the writer silently falls back to v2, so the
        // doctor must fail with the exact message and remediation and
        // exit non-zero, or an operator could ship with the decoy layer
        // inactive while the recommended deploy check passes.
        $tester = $this->doctor($this->containerFor(new DoctorHighAbuseV3WriterKernel('test', true)));
        $tester->execute([]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode(), 'high_abuse with an unconfirmed floor must produce a non-zero exit code');
        $display = $tester->getDisplay();
        self::assertStringContainsString('[FAIL] Protocol-v3 writer', $display);
        self::assertStringContainsString('high_abuse requires authenticated decoy emission, but the fleet protocol floor has not been confirmed at v3.', $display, 'the FAIL must carry the exact audit message');
        self::assertStringContainsString(
            'Confirm every serving binary supports protocol v3 and raise the central security-policy min_protocol_version to 3 (the two-phase rollout, see operations.md), or explicitly set risk.decoy_v3_enabled: false to defer v3 emission while the profile stays active.',
            $display,
            'the FAIL must carry the remediation line',
        );
    }

    public function testDoctorFailsOnHighAbuseWithAFloorBelowThree(): void
    {
        $container = $this->containerFor(new DoctorHighAbuseV3WriterKernel('test', true));
        $this->seedProtocolFloor($container, 2);
        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode(), 'a sub-v3 floor under high_abuse must fail the deploy gate');
        $display = $tester->getDisplay();
        self::assertStringContainsString('[FAIL] Protocol-v3 writer', $display);
        self::assertStringContainsString('high_abuse requires authenticated decoy emission, but the fleet protocol floor has not been confirmed at v3.', $display);
    }

    public function testDoctorFailsOnHighAbuseWithAConfirmedV3FloorButNoV4Floor(): void
    {
        // The high_abuse profile arms the execution gate by
        // default, and execution-armed emission requires the confirmed
        // v4 floor. A floor of 3 proves only v3 readers, so the doctor
        // must fail: high_abuse promises the execution surface the
        // fleet cannot verify yet.
        $container = $this->containerFor(new DoctorHighAbuseV3WriterKernel('test', true));
        $this->seedProtocolFloor($container, 3);
        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode(), 'a v3-only floor under high_abuse (execution gate on) must fail the deploy gate');
        $display = $tester->getDisplay();
        self::assertStringContainsString('[FAIL] Protocol-v3 writer', $display);
        self::assertStringContainsString('high_abuse requires execution-armed emission, but the fleet protocol floor has not been confirmed at v4.', $display);
        self::assertStringContainsString('raise the central security-policy min_protocol_version to 4 (the two-phase rollout, see operations.md)', $display);
    }

    public function testDoctorPassesOnHighAbuseWithAContainedV4Floor(): void
    {
        // The full v4 posture: floor 4 proves v4 readers, so
        // high_abuse (decoy + execution gates on) is fully rolled out.
        $container = $this->containerFor(new DoctorHighAbuseV3WriterKernel('test', true));
        $this->seedProtocolFloor($container, 4);
        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString('[PASS] Protocol-v3 writer', $display);
        self::assertStringContainsString('execution surface armed (risk.execution_challenge on) and the central floor confirms protocol v4 emission with the decoy surface', $display);
        self::assertStringNotContainsString('[FAIL]', $display);
    }

    public function testDoctorWarnsOnHighAbuseWithFullV2CapabilityWhileTheRequiredTierStaysOne(): void
    {
        // The hardened-posture gap: high_abuse with the full version-2
        // capability (execution_key configured, node cap 2, confirmed
        // central execution floor 2) but execution_required_version at
        // the default 1 keeps the strong grammar client-downgradeable.
        // The default must stay during the fleet transition, so the
        // doctor warns (exit 0), never fails the deploy gate, and the
        // warning row carries the machine-readable reason code.
        $container = $this->containerFor(new DoctorExecutionRequiredVersionKernel('test', true, 2, 1));
        $this->seedFloors($container, 4, 2);
        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), 'the required-tier default under full V2 capability must warn, never fail the deploy gate');
        $display = $tester->getDisplay();
        self::assertStringContainsString('[WARN] Execution versioning', $display);
        self::assertStringContainsString('execution_required_version_1_with_v2_capability', $display, 'the WARN must carry the machine-readable reason code');
        self::assertStringContainsString('the strong grammar stays client-downgradeable until the required tier is raised to 2', $display);
        self::assertStringContainsString('Raise execution_required_version to 2 once every serving page is on the version-2 generation', $display);
        self::assertStringNotContainsString('[FAIL]', $display);
    }

    public function testDoctorPassesOnHighAbuseWithFullV2CapabilityAndTheRequiredTierAtTwo(): void
    {
        // The hardened posture: execution_required_version 2 under the
        // same full capability makes the strong grammar server-required,
        // so the execution-versioning check passes and the deploy gate
        // stays green.
        $container = $this->containerFor(new DoctorExecutionRequiredVersionKernel('test', true, 2, 2));
        $this->seedFloors($container, 4, 2);
        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString('[PASS] Execution versioning', $display);
        self::assertStringContainsString('execution_required_version 2 under the full version-2 capability', $display);
        self::assertStringContainsString('the strong grammar is server-required, never client-downgradeable', $display);
        self::assertStringNotContainsString('[WARN] Execution versioning', $display);
        self::assertStringNotContainsString('[FAIL]', $display);
    }

    public function testDoctorWarnsOnHighAbuseWithFullV3CapabilityWhileTheRequiredTierStaysTwo(): void
    {
        // The version-3 shape of the same hardened-posture gap: cap
        // and confirmed central execution floor 3 (the strongest
        // available grammar is version 3) with
        // execution_required_version at 2: a client that cannot solve
        // version 3 is downgraded to version 2, so the strongest
        // grammar stays client-downgradeable and the doctor warns
        // (exit 0) with the machine-readable reason naming the v3
        // capability.
        $container = $this->containerFor(new DoctorExecutionRequiredVersionKernel('test', true, 3, 2));
        $this->seedFloors($container, 4, 3);
        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), 'the sub-strongest required tier under full V3 capability must warn, never fail the deploy gate');
        $display = $tester->getDisplay();
        self::assertStringContainsString('[WARN] Execution versioning', $display);
        self::assertStringContainsString('execution_required_version_2_with_v3_capability', $display, 'the WARN must carry the machine-readable reason code naming the strongest (v3) capability');
        self::assertStringContainsString('the strong grammar stays client-downgradeable until the required tier is raised to 3', $display);
        self::assertStringContainsString('Raise execution_required_version to 3 once every serving page is on the version-3 generation', $display);
        self::assertStringNotContainsString('[FAIL]', $display);
    }

    public function testDoctorPassesOnHighAbuseWithFullV3CapabilityAndTheRequiredTierAtThree(): void
    {
        // The hardened v3 posture: execution_required_version 3 under
        // cap and confirmed floor 3 makes the version-3 strong grammar
        // server-required, so the execution-versioning check passes and
        // the deploy gate stays green.
        $container = $this->containerFor(new DoctorExecutionRequiredVersionKernel('test', true, 3, 3));
        $this->seedFloors($container, 4, 3);
        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString('[PASS] Execution versioning', $display);
        self::assertStringContainsString('execution_required_version 3 under the full version-3 capability', $display);
        self::assertStringContainsString('the strong grammar is server-required, never client-downgradeable', $display);
        self::assertStringNotContainsString('[WARN] Execution versioning', $display);
        self::assertStringNotContainsString('[FAIL]', $display);
    }

    public function testDoctorDoesNotWarnWhenTheNodeCapGatesBelowTheConfirmedV3Floor(): void
    {
        // No version-2+ capability on the node (cap 1) even under a
        // confirmed version-3 central execution floor: the strongest
        // available grammar is version 1, so the required-tier audit
        // stays silent regardless of how high the fleet floor has
        // climbed.
        $container = $this->containerFor(new DoctorExecutionRequiredVersionKernel('test', true, 1, 1));
        $this->seedFloors($container, 4, 3);
        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString('[PASS] Execution versioning', $display);
        self::assertStringNotContainsString('[WARN] Execution versioning', $display, 'a node cap of 1 must not trigger the required-tier warning even under a v3 floor');
        self::assertStringNotContainsString('execution_required_version_', $display);
        self::assertStringNotContainsString('[FAIL]', $display);
    }

    public function testDoctorDoesNotWarnOnHighAbuseWithTheNodeCapAtOne(): void
    {
        // No version-2 capability (node cap 1 despite the confirmed
        // central execution floor): the node only ever emits version 1,
        // so the default required tier stays safe and the check passes
        // without any warning, unchanged from the pre-check behavior.
        $container = $this->containerFor(new DoctorExecutionRequiredVersionKernel('test', true, 1, 1));
        $this->seedFloors($container, 4, 2);
        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString('[PASS] Execution versioning', $display);
        self::assertStringNotContainsString('[WARN] Execution versioning', $display, 'a node cap of 1 must not trigger the required-tier warning');
        self::assertStringNotContainsString('execution_required_version_1_with_v2_capability', $display);
        self::assertStringNotContainsString('[FAIL]', $display);
    }

    public function testDoctorWarnsOnHighAbuseWithTheDecoyExplicitlyDeferred(): void
    {
        // An explicit risk.decoy_v3_enabled: false under high_abuse is
        // the documented deferral only when the deployment declares the
        // two-phase migration state (protocol_rollout.mode: migration):
        // the check must warn (exit 0), never fail, so the deliberate
        // rollout deferral keeps the deploy gate green. Without the
        // declaration the same configuration FAILs (see
        // testDoctorFailsOnHighAbuseWithTheDecoyDeferredAndNoMigrationMode).
        $container = $this->containerFor(new DoctorHighAbuseDecoyDeferredKernel('test', true));
        $this->seedProtocolFloor($container, 2);
        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString('[WARN] Protocol-v3 writer', $display);
        self::assertStringContainsString('protocol_rollout.mode "migration" declared: protocol v3 emission is deliberately deferred while the fleet floor is being established', $display);
        self::assertStringNotContainsString('[FAIL] Protocol-v3 writer', $display);
    }

    public function testDoctorFailsOnHighAbuseWithTheDecoyDeferredAndNoMigrationMode(): void
    {
        // The M7 boundary: a false security switch under high_abuse does
        // not itself prove the deployment is intentionally in the v3
        // migration phase, so without protocol_rollout.mode "migration"
        // the check FAILs (exit 1) with the exact remediation — a
        // forgotten override must not silently persist.
        $container = $this->containerFor(new DoctorHighAbuseDecoyDeferredNormalKernel('test', true));
        $this->seedProtocolFloor($container, 2);
        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode(), 'high_abuse with the decoy deferred and no migration declaration must fail the deploy gate');
        $display = $tester->getDisplay();
        self::assertStringContainsString('[FAIL] Protocol-v3 writer', $display);
        self::assertStringContainsString('high_abuse requires authenticated decoy emission, but risk.decoy_v3_enabled is false and no protocol rollout migration mode is declared.', $display, 'the FAIL must carry the exact audit message');
        self::assertStringContainsString('Either enable the decoy, or declare protocol_rollout.mode: migration while the fleet floor is being established.', $display, 'the FAIL must carry the remediation line');
    }

    public function testDoctorWarnsOnExplicitDecoyWithoutTheHighAbuseProfile(): void
    {
        // The safe two-phase rollout: a non-high_abuse deployment with
        // an explicit writer switch and a sub-v3 floor keeps the
        // historical warn (exit 0); the doctor never auto-raises the
        // fleet floor.
        $container = $this->containerFor(new DoctorExplicitV3WriterKernel('test', true));
        $this->seedProtocolFloor($container, 2);
        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString('[WARN] Protocol-v3 writer', $display);
        self::assertStringContainsString('finish the two-phase rollout before expecting decoy-armed emission', $display);
        self::assertStringNotContainsString('[FAIL]', $display);
    }

    public function testDoctorWarnsOnANullClearedProfileWithTheExplicitDecoyOverride(): void
    {
        // The profile is the lowest-precedence layer: a later layer
        // clearing the profile (protection_profile: null) plus the
        // explicit decoy override must resolve to the final processed
        // values (no high_abuse, decoy on), so the writer check warns
        // like any non-high_abuse deployment instead of failing.
        $container = $this->containerFor(new DoctorNullClearedProfileV3WriterKernel('test', true));
        $this->seedProtocolFloor($container, 2);
        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString('[WARN] Protocol-v3 writer', $display);
        self::assertStringNotContainsString('high_abuse requires authenticated decoy emission', $display, 'a null-cleared profile must not trigger the high_abuse FAIL');
        self::assertStringNotContainsString('[FAIL]', $display);
    }
}
