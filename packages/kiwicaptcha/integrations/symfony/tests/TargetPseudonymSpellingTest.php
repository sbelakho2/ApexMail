<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\StepUpController;
use BelConsulting\KiwiCaptchaBundle\Risk\TargetMarkKey;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOtpStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\KiwiStepUpHandlerRegistry;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpCompletionCredit;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpContext;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpTicket;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\CapturingStepUpCodeSender;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use KiwiCaptcha\Risk\Outcomes\OutcomeHandle;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\TargetIdentifierNormalizer;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The one-spelling pin across the target-pseudonym components: the
 * engine derives 64 hex, and the step-up plane carries 64 hex end to end
 * (controller attribute, context, challenge record, credit). The
 * only narrowing is the outcomes handle / mark key, a single
 * documented projection. A regression that re-opens the 32-vs-64
 * disagreement (a 422 on target-scoped step-up, a try-both handle
 * fallback, a mark read that misses its write) fails this test.
 */
final class TargetPseudonymSpellingTest extends TestCase
{
    private const MASTER = '0123456789abcdef0123456789abcdef';
    private const SCOPE = 'login';

    private function identityFactory(): RiskIdentityFactory
    {
        return new RiskIdentityFactory(RiskKeys::fromMaster(self::MASTER));
    }

    /** The engine's target pseudonym is the canonical 64-hex spelling. */
    public function testEngineDerivesTheCanonical64HexTarget(): void
    {
        $target = $this->identityFactory()->targetId(TargetIdentifierNormalizer::normalize('victim@example.com'));
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/D', $target);
        self::assertNotSame($target, substr($target, 0, 32), 'the canonical form is never the truncated form');
    }

    /** The step-up context and the challenge record both accept exactly that spelling. */
    public function testStepUpContextAndChallengeCarryTheCanonicalSpelling(): void
    {
        $target = $this->identityFactory()->targetId(TargetIdentifierNormalizer::normalize('victim@example.com'));
        $context = new StepUpContext(
            $this->identityFactory()->principalId('user-42'),
            $target,
            self::SCOPE,
            '/back',
            'post_solve_step_up_required',
        );
        self::assertSame($target, $context->targetPseudonym);

        $challenge = \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::begin(
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(),
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind::EmailOtp,
            $context->principalPseudonym,
            $target,
            self::SCOPE,
            null,
            'post_solve_step_up_required',
            1700000000,
            300,
            5,
            'hash',
        );
        self::assertSame($target, $challenge->targetPseudonym);

        // The 32-hex truncation is NOT a valid target anywhere in the
        // step-up plane any more.
        foreach (
            [
                static fn () => new StepUpContext($context->principalPseudonym, substr($target, 0, 32), self::SCOPE, null, 'post_solve_step_up_required'),
                static fn () => \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::begin(
                    \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(),
                    \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind::EmailOtp,
                    $context->principalPseudonym,
                    substr($target, 0, 32),
                    self::SCOPE,
                    null,
                    'post_solve_step_up_required',
                    1700000000,
                    300,
                    5,
                    'hash',
                ),
            ] as $mustRefuse
        ) {
            try {
                $mustRefuse();
                self::fail('the truncated 32-hex target spelling must be refused');
            } catch (\InvalidArgumentException) {
                // refused, fail closed
            }
        }
    }

    /**
     * The StepUpController accepts the engine spelling for
     * _kiwi_step_up_target — the exact value the application sets from
     * RiskGateway::targetPseudonym() — and refuses the truncated form.
     */
    public function testControllerAcceptsTheEngineSpellingAndRefusesTheTruncatedOne(): void
    {
        $target = $this->identityFactory()->targetId(TargetIdentifierNormalizer::normalize('victim@example.com'));
        $controller = $this->controller();

        $request = Request::create('/kiwi/step-up/begin?mode=json');
        $request->attributes->set('_kiwi_step_up_target', $target);
        self::assertSame(200, $controller->begin($request)->getStatusCode());

        $truncated = Request::create('/kiwi/step-up/begin?mode=json');
        $truncated->attributes->set('_kiwi_step_up_target', substr($target, 0, 32));
        self::assertSame(422, $controller->begin($truncated)->getStatusCode());
    }

    /**
     * The completion credit and the mark key agree: one projection,
     * pinned against the outcomes handle gate's own 32-hex rule.
     */
    public function testCreditAndMarkKeyShareOneProjection(): void
    {
        $target = $this->identityFactory()->targetId(TargetIdentifierNormalizer::normalize('victim@example.com'));
        $markKey = TargetMarkKey::of($target);
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/D', $markKey);
        self::assertSame(substr($target, 0, 32), $markKey);

        // The handle gate accepts exactly that spelling.
        self::assertSame($markKey, OutcomeHandle::target($markKey)->id);

        // The credit books the projected key, never the raw 64 digest.
        $reporter = new SpyOutcomeReporter();
        $credit = new StepUpCompletionCredit($reporter, self::MASTER);
        $challenge = \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::begin(
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(),
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind::EmailOtp,
            $this->identityFactory()->principalId('user-42'),
            $target,
            self::SCOPE,
            null,
            'post_solve_step_up_required',
            1700000000,
            300,
            5,
            'hash',
            targetOwned: true,
        );
        $credit->credit($challenge->id, $challenge);
        self::assertCount(2, $reporter->reports);
        self::assertSame($markKey, $reporter->reports[1]['handle']->id, 'the target credit carries the mark key');

        // The projection is total: a non-canonical input is refused,
        // never silently truncated into a usable key.
        foreach (['', substr($target, 0, 32), $target.'ff', 'not-hex-'.$target, strtoupper($target)] as $bad) {
            try {
                TargetMarkKey::of($bad);
                self::fail('TargetMarkKey must refuse non-canonical inputs');
            } catch (\InvalidArgumentException) {
                // refused, fail closed
            }
        }
    }

    private function controller(): StepUpController
    {
        $store = new ArrayStepUpChallengeStore(static fn (): int => 1700000000);
        $handler = new EmailOtpStepUpHandler(
            $store,
            new StepUpTicket(self::MASTER),
            new StepUpCompletionCredit(new SpyOutcomeReporter(), self::MASTER),
            new CapturingStepUpCodeSender(),
            self::MASTER,
        );

        return new StepUpController(
            new KiwiStepUpHandlerRegistry(['email_otp' => $handler], 'email_otp'),
            $this->identityFactory(),
            self::SCOPE,
            new \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePrincipalResolver('user-42'),
        );
    }
}
