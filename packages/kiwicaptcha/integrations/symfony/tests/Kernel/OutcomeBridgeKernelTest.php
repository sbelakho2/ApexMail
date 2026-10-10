<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\EventSubscriber\KiwiOutcomeBridgeSubscriber;
use BelConsulting\KiwiCaptchaBundle\Risk\OutcomeReporterInterface;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use KiwiCaptcha\Risk\Outcomes\Outcome;
use KiwiCaptcha\Risk\Outcomes\OutcomeHandleDimension;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Event\LoginFailureEvent;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

(require_once __DIR__.'/../Fixtures/security-event-shims.php') || true;

/**
 * The auto-wiring contract of the outcome bridge on a real compiled
 * container. The subscriber is registered when the surface allows it
 * (risk on, outcomes scope configured, security events present). The
 * events reach it through the real event dispatcher, and the
 * risk.outcomes.auto_bridge kill-switch removes it entirely.
 */
final class OutcomeBridgeKernelTest extends TestCase
{
    private ?OutcomeBridgeTestKernel $kernel = null;

    private function boot(bool $autoBridge = true): ContainerInterface
    {
        $this->kernel = new OutcomeBridgeTestKernel('test', true, $autoBridge);
        $this->kernel->boot();

        return $this->kernel->getContainer()->get('test.service_container');
    }

    private function dispatcher(ContainerInterface $container): EventDispatcherInterface
    {
        return $container->get('event_dispatcher');
    }

    private function spy(ContainerInterface $container): SpyOutcomeReporter
    {
        return $container->get(OutcomeReporterInterface::class);
    }

    private function user(string $identifier): object
    {
        return new class ($identifier) {
            public function __construct(private readonly string $identifier)
            {
            }

            public function getUserIdentifier(): string
            {
                return $this->identifier;
            }
        };
    }

    public function testTheBridgeIsAutoEnabledAndTranslatesLoginSuccess(): void
    {
        $container = $this->boot();
        self::assertTrue($container->has(KiwiOutcomeBridgeSubscriber::class), 'the subscriber is registered when the outcomes surface allows it');
        self::assertNotEmpty($this->dispatcher($container)->getListeners(LoginSuccessEvent::class));
        self::assertNotEmpty($this->dispatcher($container)->getListeners(LoginFailureEvent::class));

        $request = Request::create('https://example.com/login', 'POST', [], [], [], [
            'REQUEST_TIME_FLOAT' => 1234567890.5,
            'REMOTE_ADDR' => '198.51.100.7',
            'REMOTE_PORT' => '54321',
        ]);
        $event = new LoginSuccessEvent($request, $this->user('user-42'));
        $this->dispatcher($container)->dispatch($event, LoginSuccessEvent::class);

        $reports = $this->spy($container)->reports;
        self::assertCount(1, $reports);
        self::assertSame(Outcome::AuthenticationSuccess, $reports[0]['outcome']);
        self::assertSame(OutcomeHandleDimension::Principal, $reports[0]['handle']->dimension);
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $reports[0]['handle']->id);
        self::assertNotNull($reports[0]['idempotencyKey']);

        // The replayed event: the same request id must produce the same
        // idempotency key, so the engine books one event.
        $this->dispatcher($container)->dispatch($event, LoginSuccessEvent::class);
        self::assertCount(2, $this->spy($container)->reports);
        self::assertSame($reports[0]['idempotencyKey'], $this->spy($container)->reports[1]['idempotencyKey']);
    }

    public function testLoginFailureCarriesTheConfiguredTargetFieldPseudonym(): void
    {
        $container = $this->boot();
        $request = Request::create('https://example.com/login', 'POST', [], [], [], [
            'REQUEST_TIME_FLOAT' => 1234567890.5,
            'REMOTE_ADDR' => '198.51.100.7',
            'REMOTE_PORT' => '54321',
        ]);
        $request->attributes->set('_security.last_username', 'kernel-canary@example.com');

        $this->dispatcher($container)->dispatch(new LoginFailureEvent(new \Exception('bad credentials'), $request), LoginFailureEvent::class);

        $reports = $this->spy($container)->reports;
        self::assertCount(1, $reports);
        self::assertSame(Outcome::AuthenticationFailure, $reports[0]['outcome']);
        self::assertSame(OutcomeHandleDimension::Target, $reports[0]['handle']->dimension, 'the configured target field addresses the failure report');
        self::assertMatchesRegularExpression('/^[0-9a-f]{32,64}$/', $reports[0]['handle']->id);
        self::assertStringNotContainsString('kernel-canary', serialize($reports), 'the raw claimed identifier never reaches the report');
    }

    public function testTheAutoBridgeKillSwitchRemovesTheSubscriber(): void
    {
        $container = $this->boot(autoBridge: false);
        self::assertFalse($container->has(KiwiOutcomeBridgeSubscriber::class), 'risk.outcomes.auto_bridge=false removes the listener');

        $request = Request::create('https://example.com/login', 'POST');
        $request->server->set('REMOTE_ADDR', '198.51.100.7');
        $this->dispatcher($container)->dispatch(new LoginSuccessEvent($request, $this->user('user-42')), LoginSuccessEvent::class);

        // The bridge is gone (no listener, no reports), but the reporter
        // seam itself stays: the engine's marks stage composes the typed
        // outcomes facade on its own, so the application's own abuse
        // confirmations keep a writer even with the framework bridge
        // switched off. The kill-switch governs the bridge, never the
        // facade.
        self::assertCount(0, $this->spy($container)->reports);
        self::assertTrue($container->has(OutcomeReporterInterface::class), 'the outcomes facade rides the marks stage, not the bridge');
    }
}
