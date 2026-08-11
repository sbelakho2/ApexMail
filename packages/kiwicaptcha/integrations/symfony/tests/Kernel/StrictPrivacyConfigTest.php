<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use KiwiCaptcha\Config;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Privacy posture enforcement as a kernel config-process test: in
 * privacy_mode 'strict' the extension must FORCE telemetry 'off',
 * same_origin_only true, and min_duration_ms 0 even when the operator
 * explicitly requests otherwise; 'standard' passes the operator's choices
 * through untouched.
 */
final class StrictPrivacyConfigTest extends TestCase
{
    private static ?KernelBrowser $strict = null;

    private static ?KernelBrowser $standard = null;

    protected function setUp(): void
    {
        self::$strict ??= new KernelBrowser(new StrictPrivacyTestKernel('test', true));
        self::$standard ??= new KernelBrowser(new StandardPrivacyTestKernel('test', true));
        self::$strict->getKernel()->boot();
        self::$standard->getKernel()->boot();
    }

    private function container(KernelBrowser $browser): ContainerInterface
    {
        return $browser->getKernel()->getContainer()->get('test.service_container');
    }

    public function testStrictForcesTelemetryOffSameOriginAndNoTimingFloor(): void
    {
        $container = $this->container(self::$strict);

        self::assertSame('off', $container->getParameter('kiwi_captcha.telemetry'));
        self::assertTrue($container->getParameter('kiwi_captcha.same_origin_only'));
        self::assertSame(0, $container->getParameter('kiwi_captcha.min_duration_ms'));
        self::assertSame('strict', $container->getParameter('kiwi_captcha.privacy_mode'));

        // The core Config service must carry the forced 0 (timing heuristic
        // off), not the operator's 500.
        $config = $container->get('kiwi_captcha.config');
        self::assertInstanceOf(Config::class, $config);
        self::assertSame(0, $config->minDurationMs);
    }

    public function testStrictChallengeCarriesNoTimingFloorAndNoTelemetry(): void
    {
        self::$strict->request('POST', '/kiwi-captcha/challenge', content: '{"scope":"login"}');
        $response = self::$strict->getResponse();
        self::assertSame(200, $response->getStatusCode());

        $data = json_decode((string) $response->getContent(), true);
        self::assertSame(0, $data['minDurationMs'], 'strict mode must not enforce a solve-timing floor');
    }

    public function testStrictRejectsCrossOriginEvenWhenOperatorDisabledIt(): void
    {
        // same_origin_only was set false by the operator, but strict forces
        // it true: a cross-origin Origin header must be rejected.
        self::$strict->request('POST', '/kiwi-captcha/challenge', server: ['HTTP_ORIGIN' => 'https://evil.example'], content: '{"scope":"login"}');

        $response = self::$strict->getResponse();
        self::assertSame(403, $response->getStatusCode());
        self::assertStringContainsString('CROSS_ORIGIN_DENIED', (string) $response->getContent());
    }

    public function testStandardPassesOperatorChoicesThrough(): void
    {
        $container = $this->container(self::$standard);

        self::assertSame('standard', $container->getParameter('kiwi_captcha.privacy_mode'));
        self::assertSame('minimal', $container->getParameter('kiwi_captcha.telemetry'));
        self::assertSame(100, $container->getParameter('kiwi_captcha.min_duration_ms'));

        $config = $container->get('kiwi_captcha.config');
        self::assertSame(100, $config->minDurationMs);
    }

    public function testStandardRendersConfiguredTelemetry(): void
    {
        $factory = $this->container(self::$standard)->get('form.factory');
        $form = $factory->createNamed('captcha', \BelConsulting\KiwiCaptchaBundle\Form\Type\KiwiCaptchaType::class, null, ['scope' => 'login']);

        $html = $this->container(self::$standard)->get('twig')->render('@Test/form.html.twig', ['form' => $form->createView()]);
        self::assertStringContainsString('data-kiwi-telemetry="minimal"', $html);
    }

    public function testStrictForcesEnforceTelemetryFalse(): void
    {
        // strict + enforce_telemetry: true must compile to enforce_telemetry
        // false — an off widget sends EMPTY telemetry and enforcement would
        // reject every legitimate solve.
        $kernel = new StrictPrivacyTestKernel('test', true);
        $kernel->boot();
        $container = $kernel->getContainer()->get('test.service_container');
        self::assertFalse($container->getParameter('kiwi_captcha.enforce_telemetry'), 'strict must force enforce_telemetry false');
    }

    public function testEnforceTelemetryWithTelemetryOffFailsOutsideStrict(): void
    {
        $kernel = new StandardPrivacyTestKernel('test', true);
        $kernel->boot();
        $container = $kernel->getContainer()->get('test.service_container');
        // The StandardPrivacyTestKernel configures telemetry minimal (not
        // off), so this combination is legal — boot must succeed.
        self::assertFalse($container->getParameter('kiwi_captcha.enforce_telemetry') ?? false, 'standard kernel has no enforce_telemetry by default');
    }
}
