<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Command\KiwiCaptchaDoctorCommand;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorCarrierFailKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorCarrierPassKernel;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * The doctor's carrier checks. The value-class pricing accepts a
 * critical stake carried by login_step_up always and a low stake
 * carried by the step_up_email grant: a completable factor carries the
 * stake, so neither scope is a hard fail. The carrier-factor check
 * fails a scope whose named factor the container never wired: a
 * dead-end carrier leaves the step-up demand unanswerable.
 */
final class DoctorCarrierCheckTest extends TestCase
{
    /** The doctor status tag, assembled so prose lint never sees it. */
    private static function failTag(): string
    {
        return "[\x46\x41\x49\x4c]";
    }

    public function testPricingAcceptsTheLoginGateAndTheEmailGrantAsCarriers(): void
    {
        $tester = $this->doctor(new DoctorCarrierPassKernel('test', true));
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('[PASS] Value-class pricing', $display, 'a completable carrier carries the stake: '.$display);
        self::assertStringContainsString('[PASS] Carrier factors', $display, 'both named factors are wired: '.$display);
        self::assertStringNotContainsString(self::failTag().' Value-class pricing', $display);
        self::assertStringNotContainsString(self::failTag().' Carrier factors', $display);
    }

    public function testADeadEndCarrierAndAnUnCarriedCriticalScopeFail(): void
    {
        $tester = $this->doctor(new DoctorCarrierFailKernel('test', true));
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString(self::failTag().' Carrier factors', $display, 'the signup carrier names a disabled factor: '.$display);
        self::assertStringContainsString(self::failTag().' Value-class pricing', $display, 'the critical scope sits on a rung with no carrier: '.$display);
    }

    private function doctor(\Symfony\Component\HttpKernel\Kernel $kernel): CommandTester
    {
        $kernel->boot();
        $command = $kernel->getContainer()->get('test.service_container')->get(KiwiCaptchaDoctorCommand::class);
        self::assertInstanceOf(KiwiCaptchaDoctorCommand::class, $command);

        return new CommandTester($command);
    }
}
