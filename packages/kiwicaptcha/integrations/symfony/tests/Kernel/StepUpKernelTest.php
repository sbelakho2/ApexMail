<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Controller\StepUpController;
use BelConsulting\KiwiCaptchaBundle\Risk\OutcomeReporterInterface;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\KiwiStepUpHandlerRegistry;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpCode;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\CapturingStepUpCodeSender;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use KiwiCaptcha\Risk\Outcomes\Outcome;
use KiwiCaptcha\Risk\Outcomes\OutcomeHandleDimension;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpKernel\HttpKernelBrowser;

/**
 * The step-up plane on a real compiled container: begin and complete
 * through the HTTP kernel for both reference handlers, the completion
 * credit through the spy reporter, the canary scan of every stored
 * payload, and the kill-switch.
 */
final class StepUpKernelTest extends TestCase
{
    private ?StepUpTestKernel $kernel = null;

    protected function tearDown(): void
    {
        $this->kernel = null;
    }

    public function testTheEmailOtpFlowRunsBeginToCompleteOverHttp(): void
    {
        $client = $this->client();
        $client->request('GET', '/kiwi/step-up/begin?return_to=/back&mode=json');
        $begin = $client->getResponse();
        self::assertSame(200, $begin->getStatusCode());
        $document = json_decode((string) $begin->getContent(), true);
        self::assertIsArray($document);
        self::assertSame('email_otp', $document['handler']);
        $ticket = (string) $document['challenge'];

        /** @var CapturingStepUpCodeSender $sender */
        $sender = $this->container()->get('step_up_code_capturer');
        $code = $sender->lastCode();
        self::assertMatchesRegularExpression('/^[0-9]{6}$/D', (string) $code);

        $client->request('POST', '/kiwi/step-up/complete?return_to=/back', [
            'kiwi_step_up_ticket' => $ticket,
            'kiwi_step_up_code' => $code,
        ]);
        $complete = $client->getResponse();
        self::assertSame(303, $complete->getStatusCode(), 'the html mode redirects to the same-site return path');
        self::assertSame('/back', $complete->headers->get('Location'));

        // The completion credit: stepUpCompleted on the derived
        // principal pseudonym, exactly once for the flow.
        $principal = $this->principalPseudonym();
        $reports = $this->spy()->reports;
        self::assertCount(1, $reports);
        self::assertSame(Outcome::StepUpCompleted, $reports[0]['outcome']);
        self::assertSame(OutcomeHandleDimension::Principal, $reports[0]['handle']->dimension);
        self::assertSame($principal, $reports[0]['handle']->id);
        self::assertNotNull($reports[0]['idempotencyKey']);

        // The replayed completion through HTTP: refused, no second
        // credit.
        $client->request('POST', '/kiwi/step-up/complete', [
            'kiwi_step_up_ticket' => $ticket,
            'kiwi_step_up_code' => $code,
        ]);
        $replay = $client->getResponse();
        self::assertSame(422, $replay->getStatusCode());
        self::assertCount(1, $this->spy()->reports);

        $this->assertNoCanaryInStore();
    }

    public function testTheTotpFlowRunsBeginToCompleteOverHttp(): void
    {
        $container = $this->container();
        $principal = $this->principalPseudonym();
        /** @var TotpStepUpHandler $totp */
        $totp = $container->get(TotpStepUpHandler::class);
        // First enrollment is gated: only a session-scoped step-up
        // completed in the enrolling session authorizes it (the
        // stuffing-takeover fix), so the test books that proof first.
        $store = $container->get('kiwi_captcha.step_up.store');
        \assert($store instanceof \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeStore);
        $store->markSessionStepUpSuccess('sess-kernel', $principal, 'email_otp', 900, time());
        $secret32 = $totp->enroll($principal, 'sess-kernel');

        $client = $this->client();
        $client->request('GET', '/kiwi/step-up/begin?handler=totp&mode=json');
        $begin = $client->getResponse();
        self::assertSame(200, $begin->getStatusCode());
        $document = json_decode((string) $begin->getContent(), true);
        self::assertSame('totp', $document['handler']);
        $ticket = (string) $document['challenge'];

        $code = TotpCode::at((string) TotpCode::base32Decode($secret32), TotpCode::stepOf(time()));
        $client->request('POST', '/kiwi/step-up/complete?handler=totp&mode=json', [
            'kiwi_step_up_ticket' => $ticket,
            'kiwi_step_up_code' => $code,
        ]);
        $complete = $client->getResponse();
        self::assertSame(200, $complete->getStatusCode(), 'the json mode answers the succeeded document');
        $verdict = json_decode((string) $complete->getContent(), true);
        self::assertSame('succeeded', $verdict['status']);
        self::assertTrue($verdict['credited']['principal']);

        self::assertCount(1, $this->spy()->reports);
        self::assertSame(Outcome::StepUpCompleted, $this->spy()->reports[0]['outcome']);

        $this->assertNoCanaryInStore();
    }

    public function testTheDefaultHandlerAndRegistryResolve(): void
    {
        $container = $this->container();
        self::assertTrue($container->has(KiwiStepUpHandlerRegistry::class));
        self::assertTrue($container->has(StepUpController::class));
        /** @var KiwiStepUpHandlerRegistry $registry */
        $registry = $container->get(KiwiStepUpHandlerRegistry::class);
        self::assertSame(['email_otp', 'totp'], $registry->names());
        $unknown = false;
        try {
            $registry->get('sms');
        } catch (\InvalidArgumentException) {
            $unknown = true;
        }
        self::assertTrue($unknown, 'an unknown handler name is refused');
    }

    public function testTheKillSwitchRegistersNothing(): void
    {
        $this->kernel = new StepUpTestKernel('test', true, false);
        $this->kernel->boot();
        $container = $this->kernel->getContainer()->get('test.service_container');
        self::assertFalse($container->has(KiwiStepUpHandlerRegistry::class));
        self::assertFalse($container->has(StepUpController::class));
        self::assertFalse($container->has(TotpStepUpHandler::class));
    }

    private function client(): HttpKernelBrowser
    {
        $this->kernel ??= new StepUpTestKernel('test', true, true);
        $this->kernel->boot();

        // Every request in a kernel flow carries the same started
        // session: the completion is bound to the session that began the
        // challenge, so a sessionless request is refused (fail closed).
        return new class ($this->kernel) extends HttpKernelBrowser {
            protected function filterRequest(\Symfony\Component\BrowserKit\Request $request): \Symfony\Component\HttpFoundation\Request
            {
                $httpRequest = parent::filterRequest($request);
                $session = new \Symfony\Component\HttpFoundation\Session\Session(
                    new \Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage(),
                );
                $session->setId('sess-kernel-http-000000000001');
                $session->start();
                $httpRequest->setSession($session);

                return $httpRequest;
            }
        };
    }

    private function container(): \Symfony\Component\DependencyInjection\ContainerInterface
    {
        $this->client();

        return $this->kernel->getContainer()->get('test.service_container');
    }

    private function spy(): SpyOutcomeReporter
    {
        $spy = $this->container()->get(OutcomeReporterInterface::class);
        \assert($spy instanceof SpyOutcomeReporter);

        return $spy;
    }

    private function principalPseudonym(): string
    {
        /** @var RiskIdentityFactory $factory */
        $factory = $this->container()->get('kiwi_captcha.risk.identity_factory');

        return $factory->principalId(StepUpTestKernel::CANARY_PRINCIPAL);
    }

    /**
     * The canary scan: no key or value of any store family carries the
     * raw canary identifier, and every principal-bearing key or payload
     * fragment is the derived pseudonym.
     */
    private function assertNoCanaryInStore(): void
    {
        $redis = $this->redis();
        $haystack = [];
        foreach ([$redis->strings, $redis->counters, $redis->hashes, $redis->zsets] as $family) {
            foreach ($family as $key => $value) {
                $haystack[] = (string) $key;
                $haystack[] = \is_array($value) ? implode("\n", array_map('strval', $value)) : (string) $value;
            }
        }
        $blob = implode("\n", $haystack);
        self::assertStringNotContainsString('canary', $blob, 'no raw identifier is ever stored');
        self::assertStringNotContainsString('@example.com', $blob);
        if (preg_match_all('/"principal":"([0-9a-f]+)"/', $blob, $m) !== false) {
            foreach ($m[1] as $pseudonym) {
                self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/D', $pseudonym);
            }
        }
    }

    private function redis(): FakePredisClient
    {
        $redis = $this->container()->get('fake_redis');
        \assert($redis instanceof FakePredisClient);

        return $redis;
    }
}
