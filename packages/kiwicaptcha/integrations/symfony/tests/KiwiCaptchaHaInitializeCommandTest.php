<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Command\KiwiCaptchaHaInitializeCommand;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\PinnedPrimaryAuthorityGuard;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * The explicit authority bootstrap (docs/ha-authority.md): the
 * `kiwicaptcha:ha-initialize` command records the initial authority
 * pin(s) of the pinned-primary authority guard(s). The production
 * runtime never auto-pins, so this command is the only way a
 * pinned_primary deployment becomes armed. An existing pin is refused
 * unless --force is given after a deliberate quiesce.
 */
final class KiwiCaptchaHaInitializeCommandTest extends TestCase
{
    private const RUN_ID_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    private const RUN_ID_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

    private const NS = 'ha-init-test';

    private function fake(string $runId = self::RUN_ID_A): FakePredisClient
    {
        $fake = new FakePredisClient();
        $fake->infoReplication = ['role' => 'master', 'run_id' => $runId];
        $fake->infoServer = ['run_id' => $runId];

        return $fake;
    }

    private function pinnedConfig(): array
    {
        return ['ha_authority' => 'pinned_primary', 'ha_authority_expected' => null];
    }

    public function testCommandIsRegisteredWithTheConsoleTag(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', sys_get_temp_dir());
        $container->register('fake_redis', FakePredisClient::class);
        (new KiwiCaptchaExtension())->load([
            ['secret_key' => str_repeat('a', 32), 'redis_service' => 'fake_redis', 'ha_authority' => 'pinned_primary'],
        ], $container);

        $definition = $container->getDefinition(KiwiCaptchaHaInitializeCommand::class);
        self::assertTrue($definition->hasTag('console.command'), 'the initialize command must be registered as a console command');
    }

    public function testInitializeRecordsThePinAndExitsSuccess(): void
    {
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0, 'storage');
        $command = new KiwiCaptchaHaInitializeCommand($this->pinnedConfig(), ['storage' => $guard]);
        $tester = new CommandTester($command);
        $tester->execute([]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString('[OK] the storage authority is pinned', $display);
        self::assertStringContainsString('{kiwi:'.self::NS.'}:authority:pin:storage -> master|'.self::RUN_ID_A, $display);
        self::assertSame('master|'.self::RUN_ID_A, $fake->strings['{kiwi:'.self::NS.'}:authority:pin:storage'] ?? null);
    }

    public function testInitializeRefusesAnExistingPinWithoutForce(): void
    {
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0, 'storage');
        $command = new KiwiCaptchaHaInitializeCommand($this->pinnedConfig(), ['storage' => $guard]);
        $guard->initializePin();

        $tester = new CommandTester($command);
        $tester->execute([]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString('[FAIL] storage authority:', $tester->getDisplay());
        self::assertStringContainsString('a pin already exists', $tester->getDisplay());
        self::assertStringContainsString('--force', $tester->getDisplay());
    }

    public function testInitializeWithForceOverwritesAfterTheQuiesce(): void
    {
        $fake = $this->fake(self::RUN_ID_B);
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0, 'storage');
        $command = new KiwiCaptchaHaInitializeCommand($this->pinnedConfig(), ['storage' => $guard]);
        $guard->initializePin();

        $tester = new CommandTester($command);
        $tester->execute(['--force' => true]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        self::assertStringContainsString('-> master|'.self::RUN_ID_B, $tester->getDisplay());
        self::assertSame('master|'.self::RUN_ID_B, $fake->strings['{kiwi:'.self::NS.'}:authority:pin:storage'] ?? null);
    }

    public function testInitializeCoversEveryDistinctAuthority(): void
    {
        $storageFake = $this->fake();
        $riskFake = $this->fake();
        $storageGuard = new PinnedPrimaryAuthorityGuard($storageFake, self::NS, 0, 'storage');
        $riskGuard = new PinnedPrimaryAuthorityGuard($riskFake, self::NS, 0, 'risk');
        $command = new KiwiCaptchaHaInitializeCommand($this->pinnedConfig(), ['storage' => $storageGuard, 'risk' => $riskGuard]);
        $tester = new CommandTester($command);
        $tester->execute([]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        self::assertStringContainsString('{kiwi:'.self::NS.'}:authority:pin:storage -> master|'.self::RUN_ID_A, $tester->getDisplay());
        self::assertStringContainsString('{kiwi:'.self::NS.'}:authority:pin:risk -> master|'.self::RUN_ID_A, $tester->getDisplay());
    }

    public function testInitializeRefusesWhenTheExpectedIdentityDisagreesWithTheServer(): void
    {
        $fake = $this->fake(self::RUN_ID_B);
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0, 'storage', 'master|'.self::RUN_ID_A);
        $command = new KiwiCaptchaHaInitializeCommand(['ha_authority' => 'pinned_primary', 'ha_authority_expected' => 'master|'.self::RUN_ID_A], ['storage' => $guard]);
        $tester = new CommandTester($command);
        $tester->execute([]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString('ha_authority_expected is "master|'.self::RUN_ID_A.'" but the serving authority is master|'.self::RUN_ID_B, $tester->getDisplay());
    }

    public function testInitializeWithNoWiredGuardIsANoOp(): void
    {
        $command = new KiwiCaptchaHaInitializeCommand(['ha_authority' => 'none'], []);
        $tester = new CommandTester($command);
        $tester->execute([]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        self::assertStringContainsString('nothing to initialize', $tester->getDisplay());
    }
}
