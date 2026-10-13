<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Form\Type\KiwiCaptchaType;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandViewRegistry;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * The rendered widget must carry its field's step-up demand. The form
 * theme renders the claimed demand id as data-kiwi-step-up-demand on
 * the widget container, so the browser finally receives what the
 * validator minted and the driver can present it to the begin and
 * complete endpoints. A field whose validation minted no demand
 * renders no attribute at all.
 */
final class StepUpDemandThemeRenderTest extends TestCase
{
    private function container(): ContainerInterface
    {
        $kernel = new PrefixedTestKernel('test', true);
        $kernel->boot();

        return $kernel->getContainer()->get('test.service_container');
    }

    private function constraintOf(\Symfony\Component\Form\FormInterface $form): KiwiCaptcha
    {
        foreach ($form->getConfig()->getOption('constraints') as $candidate) {
            if ($candidate instanceof KiwiCaptcha) {
                return $candidate;
            }
        }
        self::fail('the form field carries no KiwiCaptcha constraint');
    }

    public function testTheClaimedDemandRendersOnTheContainer(): void
    {
        $container = $this->container();
        $container->get('request_stack')->push(Request::create('/signup'));

        $factory = $container->get('form.factory');
        $form = $factory->createNamed('signup', KiwiCaptchaType::class, null, ['scope' => 'signup']);
        $constraint = $this->constraintOf($form);
        $container->get(StepUpDemandViewRegistry::class)->record($constraint, 'demand-theme-0000000001');

        $html = $container->get('twig')->render('@Test/form.html.twig', ['form' => $form->createView()]);
        self::assertStringContainsString('data-kiwi-step-up-demand="demand-theme-0000000001"', $html);
    }

    public function testAFieldWithoutAMintedDemandRendersNoAttribute(): void
    {
        $container = $this->container();
        $container->get('request_stack')->push(Request::create('/signup'));

        $factory = $container->get('form.factory');
        $form = $factory->createNamed('signup', KiwiCaptchaType::class, null, ['scope' => 'signup']);

        $html = $container->get('twig')->render('@Test/form.html.twig', ['form' => $form->createView()]);
        self::assertStringNotContainsString('data-kiwi-step-up-demand', $html);
    }

    public function testAFieldOfAnotherFormNeverRendersASiblingDemand(): void
    {
        $container = $this->container();
        $container->get('request_stack')->push(Request::create('/mixed'));

        // The sibling form's constraint holds the only record; the signup
        // form below carries its own constraint instance, so its view
        // claims nothing and renders no demand.
        $sibling = $container->get('form.factory')->createNamed('login', KiwiCaptchaType::class, null, ['scope' => 'login']);
        $container->get(StepUpDemandViewRegistry::class)->record($this->constraintOf($sibling), 'demand-sibling-00000001');

        $factory = $container->get('form.factory');
        $form = $factory->createNamed('signup', KiwiCaptchaType::class, null, ['scope' => 'signup']);

        $html = $container->get('twig')->render('@Test/form.html.twig', ['form' => $form->createView()]);
        self::assertStringNotContainsString('demand-sibling-00000001', $html);
        self::assertStringNotContainsString('data-kiwi-step-up-demand', $html);
    }
}
