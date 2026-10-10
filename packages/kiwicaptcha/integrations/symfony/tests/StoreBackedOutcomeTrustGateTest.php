<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\AuthOutcomeWindowInterface;
use BelConsulting\KiwiCaptchaBundle\Risk\MemoryAuthOutcomeWindow;
use BelConsulting\KiwiCaptchaBundle\Risk\StoreBackedOutcomeTrustGate;
use PHPUnit\Framework\TestCase;

/**
 * The data-backed success-trust gate: session and source credit ride
 * only an identity whose windowed failure ratio sits below the
 * threshold and whose target carries no live mark. Every unreadable
 * input refuses the credit, and the principal credit is not this
 * gate's to make.
 */
final class StoreBackedOutcomeTrustGateTest extends TestCase
{
    private const SESSION = '0123456789abcdef0123456789abcdef';

    public function testACleanIdentityEarnsTheCredit(): void
    {
        $window = new MemoryAuthOutcomeWindow();
        $window->recordSuccess(self::SESSION);
        $window->recordSuccess('principal');
        $gate = new StoreBackedOutcomeTrustGate($window);

        self::assertTrue($gate->allowsSessionSourceCredit('principal', self::SESSION, 'target'));
    }

    public function testAFreshSessionEarnsNothingFromOneSuccess(): void
    {
        $window = new MemoryAuthOutcomeWindow();
        $window->recordSuccess('principal');
        $gate = new StoreBackedOutcomeTrustGate($window);

        self::assertFalse($gate->allowsSessionSourceCredit('principal', 'brand-new-session', 'target'));
    }

    public function testAFailingPrincipalRefusesCreditOnACleanSession(): void
    {
        $window = new MemoryAuthOutcomeWindow();
        $window->recordSuccess(self::SESSION);
        $window->recordFailure('principal');
        $window->recordFailure('principal');
        $window->recordSuccess('principal');
        $gate = new StoreBackedOutcomeTrustGate($window, null, 0.25);

        self::assertFalse($gate->allowsSessionSourceCredit('principal', self::SESSION, 'target'));
    }

    public function testAFailureHeavyIdentityIsRefused(): void
    {
        $window = new MemoryAuthOutcomeWindow();
        $window->recordFailure(self::SESSION);
        $window->recordSuccess(self::SESSION);
        $window->recordSuccess('principal');
        $gate = new StoreBackedOutcomeTrustGate($window, null, 0.25);

        self::assertFalse($gate->allowsSessionSourceCredit('principal', self::SESSION, 'target'), 'a ratio at the ceiling is not below it');

        $window2 = new MemoryAuthOutcomeWindow();
        $window2->recordFailure(self::SESSION);
        $window2->recordFailure(self::SESSION);
        foreach (range(1, 8) as $_) {
            $window2->recordSuccess(self::SESSION);
            $window2->recordSuccess('principal');
        }
        $gate2 = new StoreBackedOutcomeTrustGate($window2, null, 0.05);
        self::assertFalse($gate2->allowsSessionSourceCredit('principal', self::SESSION, 'target'), '0.2 is above the default ceiling');
    }

    public function testATargetUnderAttackRefusesTheCredit(): void
    {
        $window = new MemoryAuthOutcomeWindow();
        $window->recordSuccess(self::SESSION);
        $window->recordSuccess('principal');
        $gate = new StoreBackedOutcomeTrustGate($window, static fn (string $target): bool => $target === 'marked-target');

        self::assertFalse($gate->allowsSessionSourceCredit('principal', self::SESSION, 'marked-target'));
        self::assertTrue($gate->allowsSessionSourceCredit('principal', self::SESSION, 'clean-target'));
    }

    public function testAnUnreadableWindowRefusesTheCredit(): void
    {
        $window = new class implements AuthOutcomeWindowInterface {
            public function recordFailure(string $sessionPseudonym): void
            {
            }

            public function recordSuccess(string $sessionPseudonym): void
            {
            }

            public function failureRatio(string $sessionPseudonym): ?float
            {
                return null;
            }
        };
        $gate = new StoreBackedOutcomeTrustGate($window);

        self::assertFalse($gate->allowsSessionSourceCredit('principal', self::SESSION, null), 'no evidence means no credit');
    }

    public function testAMissingSessionRefusesTheCredit(): void
    {
        $gate = new StoreBackedOutcomeTrustGate(new MemoryAuthOutcomeWindow());

        self::assertFalse($gate->allowsSessionSourceCredit('principal', null, null));
        self::assertFalse($gate->allowsSessionSourceCredit('principal', '', null));
    }

    public function testAThrowingMarkReadRefusesTheCredit(): void
    {
        $window = new MemoryAuthOutcomeWindow();
        $window->recordSuccess(self::SESSION);
        $window->recordSuccess('principal');
        $gate = new StoreBackedOutcomeTrustGate($window, static function (string $target): bool {
            throw new \RuntimeException('marks unreachable');
        });

        self::assertFalse($gate->allowsSessionSourceCredit('principal', self::SESSION, 'target'), 'unreadable marks fail closed');
    }
}
