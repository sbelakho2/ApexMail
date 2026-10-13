<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Form\Type\KiwiCaptchaType;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandViewRegistry;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Form\FormFactoryBuilder;
use Symfony\Component\Form\FormFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * The per-form routing of the step-up demand: the validator files a
 * minted demand under the validating field's own constraint instance,
 * and that field's view claims exactly its entry. On a page with two
 * captcha fields, each refused form surfaces its own demand id and a
 * form whose validation minted none renders none.
 */
final class StepUpDemandViewRoutingTest extends TestCase
{
    public function testTwoFormsRouteTheirOwnDemandsIndependently(): void
    {
        $requestStack = new RequestStack();
        $request = Request::create('/signup');
        $requestStack->push($request);
        $registry = new StepUpDemandViewRegistry($requestStack);

        $factory = $this->factory($registry);
        $loginForm = $factory->createNamed('login', KiwiCaptchaType::class, null, ['scope' => 'login']);
        $signupForm = $factory->createNamed('signup', KiwiCaptchaType::class, null, ['scope' => 'signup']);

        // The two fields carry distinct constraint instances: the
        // stable server-side field-instance identity the validator and
        // the form integration share.
        $loginConstraint = $this->constraintOf($loginForm);
        $signupConstraint = $this->constraintOf($signupForm);
        self::assertNotNull($loginConstraint);
        self::assertNotNull($signupConstraint);
        self::assertNotSame($loginConstraint, $signupConstraint);

        // Both validations were answered with a step-up demand: each is
        // filed under its own field's identity.
        $registry->record($loginConstraint, 'demand-login-000000001');
        $registry->record($signupConstraint, 'demand-signup-00000001');

        $loginView = $loginForm->createView();
        $signupView = $signupForm->createView();
        self::assertSame('demand-login-000000001', $loginView->vars['step_up_demand'], 'the login form surfaces its own demand');
        self::assertSame('demand-signup-00000001', $signupView->vars['step_up_demand'], 'the signup form never sees the login demand');

        // The claim removed both entries: a re-render renders nothing.
        $loginAgain = $loginForm->createView();
        $signupAgain = $signupForm->createView();
        self::assertNull($loginAgain->vars['step_up_demand']);
        self::assertNull($signupAgain->vars['step_up_demand']);
    }

    public function testAFieldWithoutAMintedDemandRendersNone(): void
    {
        $requestStack = new RequestStack();
        $requestStack->push(Request::create('/mixed'));
        $registry = new StepUpDemandViewRegistry($requestStack);

        $factory = $this->factory($registry);
        $refused = $factory->createNamed('refused', KiwiCaptchaType::class, null, ['scope' => 'login']);
        $clean = $factory->createNamed('clean', KiwiCaptchaType::class, null, ['scope' => 'newsletter']);

        $registry->record($this->constraintOf($refused), 'demand-refused-0000001');

        self::assertSame('demand-refused-0000001', $refused->createView()->vars['step_up_demand']);
        self::assertNull($clean->createView()->vars['step_up_demand'], 'a form whose validation minted nothing renders no demand');
    }

    public function testASecondRecordReplacesTheFirstForTheSameField(): void
    {
        $requestStack = new RequestStack();
        $requestStack->push(Request::create('/once'));
        $registry = new StepUpDemandViewRegistry($requestStack);
        $factory = $this->factory($registry);
        $form = $factory->createNamed('solo', KiwiCaptchaType::class, null, ['scope' => 'login']);
        $constraint = $this->constraintOf($form);

        $registry->record($constraint, 'demand-stale-000000001');
        $registry->record($constraint, 'demand-live-000000001');
        self::assertSame('demand-live-000000001', $form->createView()->vars['step_up_demand'], 'one field, one live demand');
    }

    public function testWithoutAMainRequestTheRegistryIsInert(): void
    {
        $registry = new StepUpDemandViewRegistry(new RequestStack());
        $constraint = new KiwiCaptcha(['scope' => 'login']);
        $registry->record($constraint, 'demand-nowhere-0000001');
        self::assertNull($registry->claim($constraint), 'no request, no routing surface');
    }

    // ── helpers ─────────────────────────────────────────────────────

    private function factory(StepUpDemandViewRegistry $registry): FormFactoryInterface
    {
        return (new FormFactoryBuilder())
            ->addType(new KiwiCaptchaType(null, '/kiwi-captcha', 'off', null, $registry))
            ->getFormFactory();
    }

    /** The field's own constraint instance: the shared routing identity. */
    private function constraintOf(\Symfony\Component\Form\FormInterface $form): ?KiwiCaptcha
    {
        $constraints = $form->getConfig()->getOption('constraints');
        if (!\is_iterable($constraints)) {
            return null;
        }
        foreach ($constraints as $constraint) {
            if ($constraint instanceof KiwiCaptcha) {
                return $constraint;
            }
        }

        return null;
    }
}
