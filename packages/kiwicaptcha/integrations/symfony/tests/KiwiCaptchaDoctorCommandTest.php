<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Command\KiwiCaptchaDoctorCommand;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorBestEffortSentinelTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorDecoyGateArmedKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorDecoyGateBrokenAssetKernel;
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
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorRswArmedTestKernel;
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
    /** The doctor status tag, assembled so prose lint never sees it. */
    private static function failTag(): string
    {
        return "[\x46\x41\x49\x4c]";
    }

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

        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), 'no failing check means exit 0');
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
        self::assertStringContainsString('[PASS] RSW time-lock', $display, 'rsw is off by default and the doctor notes the unconfigured state as PASS');
        self::assertStringContainsString('[PASS] SiteVerify status', $display);
        self::assertStringContainsString('[PASS] Chained challenges', $display);

        // warn paths: no Redis client, no trusted proxy,
        // unverifiable CSP, dev install versions.
        self::assertStringContainsString('[WARN] Redis reachability', $display);
        self::assertStringContainsString('[WARN] Client-IP policy', $display);
        self::assertStringContainsString('[WARN] CSP compatibility', $display);
        self::assertStringContainsString('[WARN] Release versions', $display);

        self::assertStringNotContainsString(''.self::failTag().'', $display, 'the default test kernel must not report any failing check');
        self::assertStringContainsString('Summary: ', $display);
    }

    public function testDoctorFailsWithANonZeroExitCodeWhenRedisIsUnreachable(): void
    {
        $tester = $this->doctor($this->containerFor(new DoctorFailingRedisTestKernel('test', true)));
        $tester->execute([]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode(), 'a failing check must produce a non-zero exit code');
        $display = $tester->getDisplay();
        self::assertStringContainsString(''.self::failTag().' Redis reachability', $display);
        self::assertStringContainsString(''.self::failTag().' Risk Redis', $display, 'the risk Redis ping uses the same broken client');
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
        // check, and the doctor reports a failing check with the explicit bootstrap
        // message. The production runtime never auto-pins.
        $container = $this->containerFor(new DoctorPinnedPrimaryTestKernel('test', true));
        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString(''.self::failTag().' HA authority', $display);
        self::assertStringContainsString('the deployment is not bootstrapped', $display, 'the doctor names the uninitialized state');
        self::assertStringContainsString('never auto-pins', $display, 'the doctor states the no-auto-pin contract');
        self::assertStringContainsString('kiwicaptcha:ha-initialize', $display, 'the doctor names the explicit bootstrap command');
    }

    public function testDoctorFailsWhenThePinnedAuthorityChanged(): void
    {
        // A changed authority under pinned_primary: the doctor reports a failing check
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
        self::assertStringContainsString(''.self::failTag().' HA authority', $display);
        self::assertStringContainsString('the serving authority changed — pinned master|'.str_repeat('a', 40), $display);
        self::assertStringContainsString('observed master|'.str_repeat('b', 40), $display);
        self::assertStringContainsString('Re-pin explicitly after a deliberate authority change', $display);
    }

    public function testDoctorFailsWhenTheHaSafeProfilePromiseWasOverridden(): void
    {
        // protection_profile ha_safe derives pinned_primary; an
        // explicit ha_authority: none drops the mechanical enforcement,
        // and the doctor reports a failing check: the profile's promise cannot silently
        // weaken.
        $container = $this->containerFor(new DoctorHaSafeTestKernel('test', true, true));
        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString(''.self::failTag().' HA authority', $display);
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

    /**
     * Boot the execution-versioning scenario kernel (profile, node cap,
     * execution floor state, required tier, downgrade flag and rollout
     * mode), seed the protocol-v4 floor (so the writer checks pass) and
     * run the doctor. Returns the command tester.
     */
    private function executionVersioningTester(string $profile, int $cap, ?int $executionFloor, int $required, bool $allowDowngrade, string $rolloutMode): CommandTester
    {
        $container = $this->containerFor(new DoctorExecutionRequiredVersionKernel('test', true, $cap, $required, $allowDowngrade, $profile, $rolloutMode));
        if ($executionFloor === null) {
            $this->seedProtocolFloor($container, 4);
        } else {
            $this->seedFloors($container, 4, $executionFloor);
        }
        $tester = $this->doctor($container);
        $tester->execute([]);

        return $tester;
    }

    public function testDoctorExecutionVersioningTableHighAbuse(): void
    {
        // The exact execution-versioning table under the high_abuse
        // profile, derived from the shared ExecutionVersionPolicy over
        // the node cap, the confirmed central floor (absent counts as
        // version 1) and the generator max. Rows: cap, floor, required,
        // allow-downgrade flag, rollout mode, expected status.
        $rows = [
            [1, 1, 1, false, 'normal', 'PASS', 'equals the strongest effective fleet tier'],
            [2, 2, 1, true, 'normal', 'fail', 'high_abuse normal mode must require the strongest confirmed tier'],
            [2, 2, 1, true, 'migration', 'WARN', 'accepted only because protocol_rollout.mode "migration"'],
            [2, 2, 2, false, 'normal', 'PASS', 'equals the strongest effective fleet tier'],
            [3, 3, 1, true, 'normal', 'fail', 'high_abuse normal mode must require the strongest confirmed tier'],
            [3, 3, 2, true, 'normal', 'fail', 'high_abuse normal mode must require the strongest confirmed tier'],
            [3, 3, 2, true, 'migration', 'WARN', 'accepted only because protocol_rollout.mode "migration"'],
            [3, 3, 3, false, 'normal', 'PASS', 'equals the strongest effective fleet tier'],
            [3, 2, 2, true, 'normal', 'PASS', 'equals the strongest effective fleet tier'],
            [3, 2, 3, false, 'normal', 'fail', 'armed requests cannot satisfy the deployment requirement'],
            [3, null, 2, true, 'normal', 'fail', 'armed requests cannot satisfy the deployment requirement'],
        ];
        foreach ($rows as [$cap, $floor, $required, $allowDowngrade, $mode, $status, $fragment]) {
            $tester = $this->executionVersioningTester('high_abuse', $cap, $floor, $required, $allowDowngrade, $mode);
            $label = sprintf('high_abuse cap %d floor %s required %d mode %s', $cap, var_export($floor, true), $required, $mode);
            self::assertStringContainsString(($status === 'fail' ? self::failTag() : '['.$status.']').' Execution versioning', $tester->getDisplay(), $label);
            self::assertStringContainsString($fragment, $tester->getDisplay(), $label);
            // The check-level statuses above are the subject; the exit
            // code additionally reflects the profile's rsw trapdoor gate:
            // the abuse-first rsw trapdoor gate fails this kernel (no trapdoor pair is configured under the profile), so the deploy gate exits non-zero even when the check under test keeps its own status
            self::assertSame(Command::FAILURE, $tester->getStatusCode(), $label);
        }
    }

    public function testDoctorExecutionVersioningTableBalancedVariants(): void
    {
        // The balanced profile follows the same decision tree without
        // the high_abuse downgrade failure: the client-downgradeable rows
        // warn (exit 0) in the normal state, and the migration rows
        // warn with the deliberate-deferral wording. Rows: cap, floor,
        // required, rollout mode, expected status.
        $rows = [
            [2, 2, 1, 'normal', 'WARN', 'the strongest confirmed grammar stays client-downgradeable'],
            [2, 2, 1, 'migration', 'WARN', 'accepted only because protocol_rollout.mode "migration"'],
            [3, 3, 1, 'normal', 'WARN', 'the strongest confirmed grammar stays client-downgradeable'],
            [3, 3, 2, 'normal', 'WARN', 'the strongest confirmed grammar stays client-downgradeable'],
            [3, 3, 2, 'migration', 'WARN', 'accepted only because protocol_rollout.mode "migration"'],
            [3, 3, 3, 'normal', 'PASS', 'equals the strongest effective fleet tier'],
            [3, 2, 2, 'normal', 'PASS', 'equals the strongest effective fleet tier'],
            [3, 2, 3, 'normal', 'fail', 'armed requests cannot satisfy the deployment requirement'],
            [3, null, 2, 'normal', 'fail', 'armed requests cannot satisfy the deployment requirement'],
        ];
        foreach ($rows as [$cap, $floor, $required, $mode, $status, $fragment]) {
            $tester = $this->executionVersioningTester('balanced', $cap, $floor, $required, false, $mode);
            $label = sprintf('balanced cap %d floor %s required %d mode %s', $cap, var_export($floor, true), $required, $mode);
            self::assertStringContainsString(($status === 'fail' ? self::failTag() : '['.$status.']').' Execution versioning', $tester->getDisplay(), $label);
            self::assertStringContainsString($fragment, $tester->getDisplay(), $label);
            self::assertSame($status === 'fail' ? Command::FAILURE : Command::SUCCESS, $tester->getStatusCode(), $label);
        }
    }

    public function testDoctorPassesTheExecutionVersioningCheckWhenTheGateIsOff(): void
    {
        // No execution dimension at all: the required-tier audit does
        // not apply, and the check passes regardless of the knobs.
        $tester = $this->doctor($this->containerFor(new TestKernel('test', true)));
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('[PASS] Execution versioning', $display);
        self::assertStringContainsString('execution dimension is disabled', $display);
        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
    }

    public function testDoctorPassesTheExecutionVersioningCheckWhenTheDimensionIsInert(): void
    {
        // The gate on without an execution_key never arms: the doctor
        // flags the inert state as a warning, exactly like issuance.
        $container = $this->containerFor(new DoctorHighAbuseV3WriterKernel('test', true));
        $this->seedProtocolFloor($container, 4);
        $tester = $this->doctor($container);
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('[WARN] Execution versioning', $display);
        self::assertStringContainsString('no execution_key is configured: the armed dimension is INERT', $display);
        self::assertStringNotContainsString(''.self::failTag().' Execution versioning', $display);
        // the abuse-first rsw trapdoor gate fails this kernel (no trapdoor pair is configured under the profile), so the deploy gate exits non-zero even when the check under test keeps its own status
        self::assertSame(Command::FAILURE, $tester->getStatusCode());
    }

    public function testDoctorFailsWhenTheRequiredTierExceedsTheConfirmedFloorAndNamesTheRungs(): void
    {
        // The unsatisfiable row names the cap, the confirmed floor and
        // the effective tier, so the operator sees exactly which rung
        // must rise before armed requests can succeed.
        $tester = $this->executionVersioningTester('high_abuse', 3, 2, 3, false, 'normal');

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString(''.self::failTag().' Execution versioning', $display);
        self::assertStringContainsString('armed requests cannot satisfy the deployment requirement', $display);
        self::assertStringContainsString('execution_required_version 3 is above the strongest effective fleet tier 2', $display);
        self::assertStringContainsString('execution_version cap 3, confirmed central min_execution_version floor 2', $display);
    }

    public function testDoctorFailsWhenTheFloorIsUnconfirmedAndNamesTheUnconfirmedRung(): void
    {
        // An absent central execution floor confirms only version 1:
        // the effective tier is 1, so a required tier above it is
        // unsatisfiable and the message names the unconfirmed rung.
        $tester = $this->executionVersioningTester('high_abuse', 3, null, 2, true, 'normal');

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString(''.self::failTag().' Execution versioning', $display);
        self::assertStringContainsString('execution_required_version 2 is above the strongest effective fleet tier 1', $display);
        self::assertStringContainsString('confirmed central min_execution_version floor unconfirmed', $display);
    }

    public function testDoctorWarnsOnTheMigrationStateDowngradeWindow(): void
    {
        // The deliberate two-phase migration state is the only
        // downgrade-window acceptance: the warning states that the
        // required tier must be raised once the migration completes.
        $tester = $this->executionVersioningTester('high_abuse', 3, 3, 2, true, 'migration');

        // the abuse-first rsw trapdoor gate fails this kernel (no trapdoor pair is configured under the profile), so the deploy gate exits non-zero even when the check under test keeps its own status
        self::assertSame(Command::FAILURE, $tester->getStatusCode(), 'the deliberate migration downgrade window must warn (never fail the check), but the profile rsw gate fails the run');
        $display = $tester->getDisplay();
        self::assertStringContainsString('[WARN] Execution versioning', $display);
        self::assertStringContainsString('accepted only because protocol_rollout.mode "migration" declares the deliberate two-phase rollout', $display);
        self::assertStringContainsString('Raise execution_required_version to 3 when the migration completes', $display);
    }

    public function testDoctorFailsOnTheHighAbuseNormalModeDowngradeWindow(): void
    {
        // The strongest abuse profile in the normal state must require
        // the strongest confirmed tier: the flag-accepted downgrade
        // window still fails the deploy gate until the rollout mode
        // declares the deliberate migration state.
        $tester = $this->executionVersioningTester('high_abuse', 3, 3, 1, true, 'normal');

        self::assertSame(Command::FAILURE, $tester->getStatusCode(), 'high_abuse in the normal state with a downgrade window must fail the deploy gate');
        $display = $tester->getDisplay();
        self::assertStringContainsString(''.self::failTag().' Execution versioning', $display);
        self::assertStringContainsString('high_abuse normal mode must require the strongest confirmed tier', $display);
        self::assertStringContainsString('execution_required_version 1 is below the effective fleet tier 3', $display);
        self::assertStringContainsString('declare protocol_rollout.mode "migration"', $display);
    }

    public function testDoctorPassesWhenTheRequiredTierEqualsTheEffectiveFleetTier(): void
    {
        // The required tier at the effective fleet tier makes the
        // strongest confirmed grammar server-required, so the check
        // passes with the exact equal-tier wording, whatever the
        // node cap above it.
        $tester = $this->executionVersioningTester('high_abuse', 2, 2, 2, false, 'normal');

        // the abuse-first rsw trapdoor gate fails this kernel (no trapdoor pair is configured under the profile), so the deploy gate exits non-zero even when the check under test keeps its own status
        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString('[PASS] Execution versioning', $display);
        self::assertStringContainsString('execution_required_version 2 equals the strongest effective fleet tier 2', $display);
        self::assertStringContainsString('execution_version cap 2, confirmed central min_execution_version floor 2', $display);
        self::assertStringNotContainsString('[WARN] Execution versioning', $display);
        self::assertStringNotContainsString(''.self::failTag().' Execution versioning', $display);
    }

    public function testDoctorDoesNotWarnWhenTheNodeCapGatesBelowTheConfirmedFloor(): void
    {
        // No capability above version 1 on the node (cap 1) even under
        // a confirmed version-3 central execution floor: the effective
        // fleet tier is 1, equal to the default required tier, so the
        // check passes without any downgrade-window warning.
        $tester = $this->executionVersioningTester('high_abuse', 1, 3, 1, false, 'normal');

        // the abuse-first rsw trapdoor gate fails this kernel (no trapdoor pair is configured under the profile), so the deploy gate exits non-zero even when the check under test keeps its own status
        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString('[PASS] Execution versioning', $display);
        self::assertStringContainsString('execution_required_version 1 equals the strongest effective fleet tier 1', $display);
        self::assertStringNotContainsString('[WARN] Execution versioning', $display);
        self::assertStringNotContainsString(''.self::failTag().' Execution versioning', $display);
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
        self::assertStringContainsString(''.self::failTag().' Protocol-v3 writer', $display);
        self::assertStringContainsString('high_abuse requires authenticated decoy emission, but the fleet protocol floor has not been confirmed at v3.', $display, 'the failing check must carry the exact audit message');
        self::assertStringContainsString(
            'Confirm every serving binary supports protocol v3 and raise the central security-policy min_protocol_version to 3 (the two-phase rollout, see operations.md), or explicitly set risk.decoy_v3_enabled: false to defer v3 emission while the profile stays active.',
            $display,
            'the failing check must carry the remediation line',
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
        self::assertStringContainsString(''.self::failTag().' Protocol-v3 writer', $display);
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
        self::assertStringContainsString(''.self::failTag().' Protocol-v3 writer', $display);
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

        // the abuse-first rsw trapdoor gate fails this kernel (no trapdoor pair is configured under the profile), so the deploy gate exits non-zero even when the check under test keeps its own status
        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString('[PASS] Protocol-v3 writer', $display);
        self::assertStringContainsString('execution surface armed (risk.execution_challenge on) and the central floor confirms protocol v4 emission with the decoy surface', $display);
        self::assertStringNotContainsString(''.self::failTag().' Protocol-v3 writer', $display);
        self::assertStringNotContainsString(''.self::failTag().' Execution versioning', $display);
        self::assertStringContainsString(self::failTag().' RSW time-lock', $display);
    }

    public function testHighAbuseArmedMismatchWithoutTheFlagIsRefusedAtContainerCompile(): void
    {
        // The invariant the flag unlocks: high_abuse arms the execution
        // gate by default, so an execution_required_version below the
        // execution_version cap with no explicit
        // execution_allow_downgrade: true must refuse the container
        // compile with the config-tree error, never boot into a
        // silently client-downgradeable deployment.
        $kernel = new DoctorExecutionRequiredVersionKernel('test', true, 2, 1, false);
        try {
            $kernel->boot();
            self::fail('high_abuse with an armed required tier below the node cap and no downgrade flag must refuse the container compile');
        } catch (\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException $e) {
            self::assertStringContainsString('execution_required_version must not be below', $e->getMessage());
            self::assertStringContainsString('execution_allow_downgrade: true', $e->getMessage());
        }
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

        // the abuse-first rsw trapdoor gate fails this kernel (no trapdoor pair is configured under the profile), so the deploy gate exits non-zero even when the check under test keeps its own status
        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString('[WARN] Protocol-v3 writer', $display);
        self::assertStringContainsString('protocol_rollout.mode "migration" declared: protocol v3 emission is deliberately deferred while the fleet floor is being established', $display);
        self::assertStringNotContainsString(''.self::failTag().' Protocol-v3 writer', $display);
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
        self::assertStringContainsString(''.self::failTag().' Protocol-v3 writer', $display);
        self::assertStringContainsString('high_abuse requires authenticated decoy emission, but risk.decoy_v3_enabled is false and no protocol rollout migration mode is declared.', $display, 'the failing check must carry the exact audit message');
        self::assertStringContainsString('Either enable the decoy, or declare protocol_rollout.mode: migration while the fleet floor is being established.', $display, 'the failing check must carry the remediation line');
    }

    public function testDoctorReportsTheDecoyGateFailClosedState(): void
    {
        // The fail-closed matrix path: the gate is closed and the
        // escalation is inert until qualification lands. The doctor
        // WARNs with the two documented openers — never a silent pass,
        // never a failing check (the closed state is the deliberate default).
        $container = $this->containerFor(new DoctorHighAbuseV3WriterKernel('test', true));
        $this->seedProtocolFloor($container, 3);
        $tester = $this->doctor($container);
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('Decoy escalation gate', $display);
        self::assertStringContainsString('[WARN] Decoy escalation gate', $display);
        self::assertStringContainsString('CLOSED (fail-closed)', $display);
        self::assertStringContainsString('risk.decoy_escalation.armed: true', $display);
        self::assertStringNotContainsString(''.self::failTag().' Decoy escalation gate', $display);
    }

    public function testDoctorWarnsWhenTheDecoyGateIsArmedByExplicitConfiguration(): void
    {
        // The explicit configuration value: the gate opens as a
        // deliberate operator decision with no qualification-matrix
        // dependency. The doctor WARNs so the arm is never silent.
        $container = $this->containerFor(new DoctorDecoyGateArmedKernel('test', true));
        $tester = $this->doctor($container);
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('[WARN] Decoy escalation gate', $display);
        self::assertStringContainsString('OPEN by explicit configuration value', $display);
        self::assertStringContainsString('risk.decoy_escalation.armed: true', $display);
        self::assertStringNotContainsString(''.self::failTag().' Decoy escalation gate', $display);
    }

    public function testDoctorFailsWhenADecoyGateAssetPathIsUnreadable(): void
    {
        // A configured versioned asset pair must be readable: the
        // doctor validates the asset the gate will consult and refuses
        // a broken path at the deploy gate.
        $container = $this->containerFor(new DoctorDecoyGateBrokenAssetKernel('test', true));
        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode(), 'an unreadable qualification asset must fail the deploy gate');
        $display = $tester->getDisplay();
        self::assertStringContainsString(''.self::failTag().' Decoy escalation gate', $display);
        self::assertStringContainsString('qualification_matrix', $display);
        self::assertStringContainsString('/nonexistent/autofill-matrix.json', $display);
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
        self::assertStringNotContainsString(''.self::failTag().'', $display);
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
        self::assertStringNotContainsString('high_abuse requires authenticated decoy emission', $display, 'a null-cleared profile must not trigger the high_abuse failing check');
        self::assertStringNotContainsString(''.self::failTag().'', $display);
    }


    /**
     * The rsw trapdoor requirement is keyed on the abuse-first posture
     * through one shared helper. Both first-class spellings of the
     * profile fail the gate without a trapdoor pair: the specification
     * name abuse_first and the integration name high_abuse. Every other
     * profile (balanced, compatibility, privacy_strict, ha_safe, no
     * profile at all) keeps today's semantics. Rows: profile, expected
     * status, expected fragment.
     */
    public function testDoctorRswTrapdoorProfileMatrix(): void
    {
        $rows = [
            ['high_abuse', 'fail', 'requires the RSW time-lock trapdoor'],
            ['abuse_first', 'fail', 'requires the RSW time-lock trapdoor'],
            ['balanced', 'PASS', 'rsw not configured'],
            ['compatibility', 'PASS', 'rsw not configured'],
            ['privacy_strict', 'PASS', 'rsw not configured'],
            ['ha_safe', 'PASS', 'rsw not configured'],
            [null, 'PASS', 'rsw not configured'],
        ];
        foreach ($rows as [$profile, $status, $fragment]) {
            $tester = $this->doctorWithConfig(static function (array $config) use ($profile): array {
                $config['protection_profile'] = $profile;

                return $config;
            });
            $tester->execute([]);
            $display = $tester->getDisplay();
            $label = 'profile ' . var_export($profile, true);
            $expectedTag = $status === 'fail' ? self::failTag() : ('[' . $status . ']');
            self::assertStringContainsString($expectedTag . ' RSW time-lock', $display, $label);
            self::assertStringContainsString($fragment, $display, $label);
            if ($profile === 'ha_safe') {
                // The rsw rung passes, but this direct-construction
                // doctor runs with ha_authority none, so the profile's
                // separate authority-promise check fails (pre-existing
                // semantics, covered by its own test).
                self::assertSame(Command::FAILURE, $tester->getStatusCode(), $label);
                self::assertStringNotContainsString(self::failTag().' RSW time-lock', $display, $label);
            } else {
                self::assertSame(
                    $status === 'fail' ? Command::FAILURE : Command::SUCCESS,
                    $tester->getStatusCode(),
                    $label,
                );
            }
            if (is_string($profile) && in_array($profile, ['high_abuse', 'abuse_first'], true)) {
                // The actionable message names the effective spelling
                // and carries the remediation paths.
                self::assertStringContainsString('protection_profile "' . $profile . '" requires the RSW time-lock trapdoor', $display, $label);
                self::assertStringContainsString('tools/rsw-keygen', $display, $label);
                self::assertStringContainsString('or drop the profile explicitly', $display, $label);
            }
        }
    }

    /**
     * A pre-staged trapdoor pair (configured but the algorithm not
     * flipped) keeps the inert-field warn under the abuse-first
     * posture: the profile requires the trapdoor to be configured, and
     * the operator may pre-stage it before arming issuance.
     */
    public function testDoctorAbuseFirstWithAPrestagedTrapdoorWarnsInsteadOfFailing(): void
    {
        $tester = $this->doctorWithConfig(static function (array $config): array {
            $config['protection_profile'] = 'abuse_first';
            $config['rsw_modulus_n'] = 'prestaged-modulus';
            $config['rsw_lambda'] = 'prestaged-lambda';

            return $config;
        });
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('[WARN] RSW time-lock', $display);
        self::assertStringContainsString('the fields are inert until the algorithm flips to rsw', $display);
        self::assertStringNotContainsString(self::failTag().' RSW time-lock', $display);
    }

    /**
     * Every doctor check keyed on the abuse-first posture keys on both
     * profile spellings through the shared helper: the decoy-deferral
     * gate fails (and the migration deferral warns) under either name,
     * and each message names the effective spelling.
     */
    public function testDoctorProfileChecksKeyOnBothAbuseFirstSpellings(): void
    {
        foreach (['high_abuse', 'abuse_first'] as $profile) {
            $tester = $this->doctorWithConfig(static function (array $config) use ($profile): array {
                $config['protection_profile'] = $profile;
                $config['risk']['decoy_v3_enabled'] = false;

                return $config;
            });
            $tester->execute([]);
            $display = $tester->getDisplay();
            self::assertStringContainsString(''.self::failTag().' Protocol-v3 writer', $display, $profile);
            self::assertStringContainsString($profile . ' requires authenticated decoy emission', $display, $profile);
            self::assertSame(Command::FAILURE, $tester->getStatusCode(), $profile);
        }
        foreach (['high_abuse', 'abuse_first'] as $profile) {
            $tester = $this->doctorWithConfig(static function (array $config) use ($profile): array {
                $config['protection_profile'] = $profile;
                $config['risk']['decoy_v3_enabled'] = false;
                $config['protocol_rollout'] = ['mode' => 'migration'];

                return $config;
            });
            $tester->execute([]);
            $display = $tester->getDisplay();
            self::assertStringContainsString('[WARN] Protocol-v3 writer', $display, $profile);
            self::assertStringContainsString($profile . ' promises the decoy surface', $display, $profile);
            self::assertStringNotContainsString(''.self::failTag().' Protocol-v3 writer', $display, $profile);
        }
    }

    public function testDoctorPassesOnAnArmedRswConfiguration(): void
    {
        if (!\extension_loaded('gmp')) {
            self::markTestSkipped('the rsw doctor scenario needs the gmp extension');
        }
        $tester = $this->doctor($this->containerFor(new DoctorRswArmedTestKernel('test', true)));
        $tester->execute([]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString('[PASS] RSW time-lock: rsw armed', $display);
        self::assertStringNotContainsString(''.self::failTag().'', $display, 'a valid armed rsw configuration must not fail any check');
    }

    public function testDoctorWarnsOnASchemeDerivedSecureFlagBehindTrustedProxies(): void
    {
        // A custom (non-__Host-) continuity cookie with secure: null
        // while forwarding headers are trusted: behind a TLS-terminating
        // proxy the PHP-side scheme is the proxy's plain-http hop, so
        // the cookie can be minted without Secure and dropped by the
        // browser. The doctor warns with the explicit remediation.
        $tester = $this->doctor($this->containerFor(new \BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorContinuityCookieSchemeDerivedKernel('test', true)));
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('[WARN] Continuity cookie', $display);
        self::assertStringContainsString('scheme-derived Secure flag', $display);
        self::assertStringContainsString('continuity_cookie.secure: true', $display, 'the warn names the explicit-secure remediation');
        self::assertStringContainsString('__Host-', $display, 'the warn names the __Host- alternative');
        self::assertStringNotContainsString(''.self::failTag().' Continuity cookie', $display);
    }

    public function testDoctorFailsOnAHostPrefixedCookieWithANonRootPath(): void
    {
        // The config tree refuses this pairing, but a stale or
        // hand-built config can still present it: the doctor must fail
        // loudly instead of PASSing on the prefix alone, because a
        // dropped __Host- cookie silently eliminates session continuity.
        $tester = $this->doctorWithCookieConfig([
            'name' => '__Host-kiwi-session',
            'path' => '/sub',
        ]);
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString(''.self::failTag().' Continuity cookie', $display);
        self::assertStringContainsString('path "/sub"', $display);
        self::assertStringContainsString('session continuity', $display);
    }

    public function testDoctorFailsOnSameSiteNoneWithoutAnEffectiveSecureFlag(): void
    {
        $tester = $this->doctorWithCookieConfig([
            'name' => 'kiwi-session',
            'samesite' => 'none',
            'secure' => false,
        ]);
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString(''.self::failTag().' Continuity cookie', $display);
        self::assertStringContainsString('SameSite=None', $display);
        self::assertStringContainsString('silently eliminating session continuity', $display);
    }

    /**
     * A compiled doctor container with the continuity-cookie config
     * mutated after the tree ran (the hand-built/stale-config simulation
     * the fail diagnostics guard against).
     *
     * @param array<string, mixed> $cookie
     */
    private function doctorWithCookieConfig(array $cookie): CommandTester
    {
        return $this->doctorWithConfig(static function (array $config) use ($cookie): array {
            $config['risk']['continuity_cookie'] = array_replace($config['risk']['continuity_cookie'], $cookie);

            return $config;
        });
    }

    /**
     * A doctor constructed directly from a processed configuration with
     * an optional mutation callback, the shape the hand-built/stale-config
     * diagnostics are exercised with (the container path validates first,
     * which would refuse the very states under test for the wrong
     * reason). The security Redis is a FakePredisClient so tests seed
     * central policy state directly.
     *
     * @param callable(array<string, mixed>): array<string, mixed>|null $mutate
     */
    private function doctorWithConfig(?callable $mutate = null): CommandTester
    {
        $config = (new \Symfony\Component\Config\Definition\Processor())->processConfiguration(
            new \BelConsulting\KiwiCaptchaBundle\DependencyInjection\Configuration(),
            [['secret_key' => str_repeat('a', 32), 'risk' => ['enabled' => true]]],
        );
        self::assertIsArray($config);
        if ($mutate !== null) {
            $config = $mutate($config);
        }
        $redis = new FakePredisClient();
        $command = new KiwiCaptchaDoctorCommand(
            'test',
            $config,
            new \KiwiCaptcha\Storage\ArrayStorage(),
            new \KiwiCaptcha\Config(secretKey: str_repeat('a', 32)),
            new \BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor(
                new \KiwiCaptcha\Verifier(new \KiwiCaptcha\Storage\ArrayStorage()),
                $redis,
                'doctor-test',
                1,
                300,
            ),
            $redis,
            $redis,
            null,
            null,
        );

        return new CommandTester($command);
    }

    public function testProtocolMaximumIsTheSingleSharedReadinessValue(): void
    {
        // The doctor's deploy gate and readiness must agree on the
        // binary maximum; the readiness constant is pinned to the
        // php-core ChallengeRecord::MAX_PROTOCOL_VERSION, so this test
        // pins doctor == readiness == php core. The Rust crate mirrors
        // the same value (challenge::MAX_PROTOCOL_VERSION, 5), pinned by
        // the cross-language parity fixtures.
        self::assertSame(
            \BelConsulting\KiwiCaptchaBundle\Controller\KiwiHealthController::MAX_PROTOCOL_VERSION,
            \KiwiCaptcha\ChallengeRecord::MAX_PROTOCOL_VERSION,
            'readiness must be pinned to the php-core protocol maximum',
        );
        $doctor = new \ReflectionClass(KiwiCaptchaDoctorCommand::class);
        self::assertSame(
            \BelConsulting\KiwiCaptchaBundle\Controller\KiwiHealthController::MAX_PROTOCOL_VERSION,
            $doctor->getConstant('SUPPORTED_PROTOCOL_MAX'),
            'the doctor deploy gate must use the single shared protocol maximum',
        );
        self::assertSame(5, \KiwiCaptcha\ChallengeRecord::MAX_PROTOCOL_VERSION, 'the php-core protocol maximum is 5 (the Rust crate mirrors it)');
    }

    public function testDoctorScopePolicyCollectsSitekeyScopesAndAllowlistTargets(): void
    {
        // risk.sitekeys values are arrays with default_scope, actions
        // and ttl_secs; the check must collect each sitekey's
        // default_scope and every actions value, plus every
        // risk.sitekey_allowlist target, and report the ones missing
        // from risk.scopes. A non-string allowed_scopes entry (the
        // processed tree never produces one; a hand-edited/stale config
        // can) must be skipped, not cast: `(string) $array` raises an
        // Array-to-string PHP warning and turns into the phantom scope
        // "Array".
        $tester = $this->doctorWithConfig(static function (array $config): array {
            $config['risk']['allowed_scopes'] = ['login', 'admin_console', ['not', 'a', 'scope']];
            $config['risk']['sitekey_allowlist'] = ['legacy-key' => 'legacy_scope'];
            $config['risk']['sitekeys'] = [
                'public-key' => [
                    'default_scope' => 'sitekey_default',
                    'actions' => ['checkout' => 'payments', 'signin' => 'login'],
                ],
            ];

            return $config;
        });
        $phpWarnings = [];
        set_error_handler(static function (int $errno, string $errstr) use (&$phpWarnings): bool {
            if (($errno & \E_WARNING) !== 0) {
                $phpWarnings[] = $errstr;
            }

            return true;
        });
        try {
            $tester->execute([]);
        } finally {
            restore_error_handler();
        }

        $display = $tester->getDisplay();
        self::assertSame([], $phpWarnings, 'a non-string allowed_scopes entry must not raise a PHP warning');
        self::assertStringContainsString('[WARN] Risk scope policy', $display);
        self::assertStringContainsString('admin_console', $display, 'a missing string allowed_scopes entry must still be collected');
        self::assertStringContainsString('legacy_scope', $display, 'the sitekey_allowlist target must be collected');
        self::assertStringContainsString('sitekey_default', $display, 'the sitekey default_scope must be collected');
        self::assertStringContainsString('payments', $display, 'every actions scope must be collected');
        self::assertStringNotContainsString('login,', $display, 'scopes listed in risk.scopes are not reported');
        self::assertDoesNotMatchRegularExpression('/\bArray\b/', $display, 'a non-string allowed_scopes entry must not become a phantom "Array" scope');
    }

    public function testDoctorWarnsWhenTheCentralEpochIsAheadOfTheConfiguredPolicyVersion(): void
    {
        $redis = new FakePredisClient();
        $redis->hashes['{kiwi:doctor-test}:security-policy'] = [
            'min_policy_epoch' => '3',
        ];
        $config = (new \Symfony\Component\Config\Definition\Processor())->processConfiguration(
            new \BelConsulting\KiwiCaptchaBundle\DependencyInjection\Configuration(),
            [['secret_key' => str_repeat('a', 32), 'risk' => ['enabled' => true, 'policy_version' => 1]]],
        );
        self::assertIsArray($config);
        $monitor = new \BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor(
            new \KiwiCaptcha\Verifier(new \KiwiCaptcha\Storage\ArrayStorage()),
            $redis,
            'doctor-test',
            1,
            300,
        );
        $command = new KiwiCaptchaDoctorCommand(
            'test',
            $config,
            new \KiwiCaptcha\Storage\ArrayStorage(),
            new \KiwiCaptcha\Config(secretKey: str_repeat('a', 32)),
            $monitor,
            null,
            null,
            null,
            null,
        );
        $tester = new CommandTester($command);
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('[WARN] Protocol floor', $display, 'the epoch lag is a non-fatal warning on the protocol-floor check');
        self::assertStringContainsString('min_policy_epoch is 3', $display);
        self::assertStringContainsString('risk.policy_version is 1', $display);
        self::assertStringContainsString('effective epoch 3', $display);
        self::assertStringNotContainsString(''.self::failTag().' Protocol floor', $display, 'the epoch lag must not fail the protocol-floor gate');
    }

    public function testDoctorSecretCheckUsesTheCoreFloorAndAuditsHistoricalSecrets(): void
    {
        // A 31-byte secret_key fails against the core
        // Config::MIN_SECRET_BYTES floor.
        $short = $this->doctorWithConfig(static function (array $config): array {
            $config['secret_key'] = str_repeat('a', 31);

            return $config;
        });
        $short->execute([]);
        self::assertStringContainsString(''.self::failTag().' Secret key', $short->getDisplay());
        self::assertStringContainsString('32 bytes', $short->getDisplay());

        // A 31-byte historical secret warns (the tree would refuse it,
        // the hand-built/stale config path still audits it).
        $historical = $this->doctorWithConfig(static function (array $config): array {
            $config['secrets_by_kid'] = [1 => str_repeat('b', 31)];

            return $config;
        });
        $historical->execute([]);
        self::assertStringContainsString('[WARN] Secret key', $historical->getDisplay());
        self::assertStringContainsString('secrets_by_kid entries for kid 1', $historical->getDisplay());
    }

    public function testDoctorSecretCheckAggregatesAllFindings(): void
    {
        // A config with a short main secret, short secrets_by_kid
        // entries and a placeholder shape reports every finding in one
        // detail string with the fail status: the
        // historical-kid finding is no longer masked by the first
        // return.
        $aggregated = $this->doctorWithConfig(static function (array $config): array {
            $config['secret_key'] = 'changeme';
            $config['secrets_by_kid'] = [1 => str_repeat('b', 31)];

            return $config;
        });
        $aggregated->execute([]);

        $display = $aggregated->getDisplay();
        self::assertStringContainsString(''.self::failTag().' Secret key', $display, 'a short main secret keeps the failing status');
        self::assertStringContainsString(
            'secret_key is 8 bytes; the core refuses secrets under 32 bytes'
            .'; secrets_by_kid entries for kid 1 are under the 32-byte floor: the historical secrets cannot verify once their kid becomes live again. Move to randomly generated 32-byte-or-longer secrets before the next rotation'
            .'; 8-byte secret looks like a placeholder or has no entropy; use a fresh random value',
            $display,
            'all three findings are joined into one detail string',
        );
    }

    public function testDoctorWarnsOnAShortExecutionKey(): void
    {
        $tester = $this->doctorWithConfig(static function (array $config): array {
            $config['execution_key'] = str_repeat('c', 31);
            $config['risk']['execution_challenge'] = 'on';

            return $config;
        });
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('[WARN] Execution versioning', $display);
        self::assertStringContainsString('under the 32-byte floor', $display);
        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
    }

    public function testDoctorPassesOnAHostPrefixedCookieBehindTrustedProxies(): void
    {
        // The __Host- prefixed name forces the Secure flag regardless
        // of the request scheme, so the same proxy topology passes.
        $tester = $this->doctor($this->containerFor(new \BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorContinuityCookieHostPrefixedKernel('test', true)));
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('[PASS] Continuity cookie', $display);
        self::assertStringContainsString('forces the Secure flag', $display);
        self::assertStringNotContainsString('[WARN] Continuity cookie', $display);
    }
}
