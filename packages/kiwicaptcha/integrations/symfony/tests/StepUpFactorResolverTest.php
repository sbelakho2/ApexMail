<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\FactorRequirement;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFactorContext;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFactorResolver;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskDecision;
use KiwiCaptcha\Risk\RiskReason;
use PHPUnit\Framework\TestCase;

/**
 * The factor requirement source: the demand plane has exactly one
 * authority for "which factor does this step-up require", the ladder
 * email_otp < totp < webauthn with the ranks 1, 2 and 3. A demand
 * minted after a completed one escalates strictly past the completed
 * rank; when the ladder offers no higher rung the child stays on the
 * completed rank. The requirement rides the demand as a snapshot, so
 * the stored record keeps the factor the demand was raised for.
 */
final class StepUpFactorResolverTest extends TestCase
{
    public function testACompletedEmailOtpDemandEscalatesTheChildToTotp(): void
    {
        $resolver = new StepUpFactorResolver('email_otp');

        $child = $resolver->requiredFactor(
            'login',
            $this->decision(),
            new StepUpFactorContext(FactorRequirement::EMAIL_OTP),
        );

        self::assertSame(FactorRequirement::TOTP, $child->family, 'the child must demand the strictly stronger totp factor');
        self::assertSame('totp', $child->factorId);
        self::assertSame(2, $child->assuranceRank, 'totp carries the rank 2 rung of the ladder');
    }

    public function testACompletedWebauthnDemandKeepsTheChildOnWebauthn(): void
    {
        $resolver = new StepUpFactorResolver('email_otp');

        $child = $resolver->requiredFactor(
            'login',
            $this->decision(),
            new StepUpFactorContext(FactorRequirement::WEBAUTHN),
        );

        self::assertSame(FactorRequirement::WEBAUTHN, $child->family, 'no higher rung exists: the child stays on webauthn');
        self::assertSame(3, $child->assuranceRank, 'the child never drops below the completed rank');
    }

    public function testAFirstDemandCarriesTheConfiguredBaseFactor(): void
    {
        $resolver = new StepUpFactorResolver('totp');

        $base = $resolver->requiredFactor('login', $this->decision(), new StepUpFactorContext(null));

        self::assertSame(FactorRequirement::TOTP, $base->family);
        self::assertSame(2, $base->assuranceRank, 'the base factor rides its ladder rank');
    }

    public function testAScopeOverrideDemandsTheConfiguredFactorOfThatScope(): void
    {
        $resolver = new StepUpFactorResolver('email_otp', ['signup' => FactorRequirement::WEBAUTHN]);

        $base = $resolver->requiredFactor('signup', $this->decision(), new StepUpFactorContext(null));

        self::assertSame(FactorRequirement::WEBAUTHN, $base->family, 'the scope entry wins over the default handler');
        self::assertSame(3, $base->assuranceRank);
    }

    public function testACompletedEmailOtpNeverDowngradesAWebauthnScopeFloor(): void
    {
        $resolver = new StepUpFactorResolver('webauthn');

        $child = $resolver->requiredFactor(
            'login',
            $this->decision(),
            new StepUpFactorContext(FactorRequirement::EMAIL_OTP),
        );

        self::assertSame(FactorRequirement::WEBAUTHN, $child->family, 'the escalation floor never weakens the configured factor');
        self::assertSame(3, $child->assuranceRank, 'the answer is strictly stronger than the completed rank 1');
    }

    public function testAnUnknownCompletedFamilyResolvesTheBase(): void
    {
        $resolver = new StepUpFactorResolver('totp');

        $child = $resolver->requiredFactor('login', $this->decision(), new StepUpFactorContext(null));

        self::assertSame(FactorRequirement::TOTP, $child->family);
    }

    public function testTheResolverRefusesADefaultOutsideTheLadder(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new StepUpFactorResolver('sms');
    }

    public function testTheRequirementRefusesARankItsFamilyDoesNotCarry(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new FactorRequirement(FactorRequirement::EMAIL_OTP, 'email_otp', 2);
    }

    public function testTheRankOfAnUnknownFamilyIsZero(): void
    {
        self::assertSame(0, FactorRequirement::rankOf('sms'));
        self::assertFalse(FactorRequirement::isFamily('sms'));
    }

    private function decision(): RiskDecision
    {
        return new RiskDecision(950, RiskAction::StepUp, [RiskReason::NovelNetwork], 1, 0);
    }
}
