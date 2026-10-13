<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOwnershipStepUp;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpKernel\HttpKernelBrowser;

/**
 * The anonymous email-grant journey over the real kernel. The signup
 * challenge answers the typed step-up 403 carrying the demand id, and
 * the visitor begins and completes the factor against that demand. The
 * redemption runs the shared finalizer: the fresh completion
 * assessment rides the signup scope's step-up minimum, so it re-raises
 * over the completed grant and the assurance escalates to the strictly
 * stronger child demand, which the refusal advertises. The same grant
 * on the non-carrier login scope is a violation.
 */
final class EmailGrantJourneyKernelTest extends TestCase
{
    private const EMAIL = 'visitor@example.com';

    private ?EmailGrantJourneyTestKernel $kernel = null;

    private ?HttpKernelBrowser $browser = null;

    protected function tearDown(): void
    {
        $this->kernel = null;
        $this->browser = null;
    }

    public function testAnonymousSignupFortyThreeDemandBeginCompleteSubmit(): void
    {
        $container = $this->boot();
        $client = $this->browser ??= new HttpKernelBrowser($this->kernel);

        // (1) The anonymous signup issuance: the typed 403 names the
        // email carrier, its begin path and the minted demand id. The
        // continuity cookie rides the response, so the demand binds the
        // browser that follows it.
        $client->request('POST', '/kiwi-captcha/challenge', server: [
            'CONTENT_TYPE' => 'application/json',
        ], content: '{"scope":"signup"}');
        $refused = $client->getResponse();
        self::assertSame(403, $refused->getStatusCode(), (string) $refused->getContent());
        $refusal = json_decode((string) $refused->getContent(), true);
        self::assertSame('STEP_UP_REQUIRED', $refusal['error']['code'] ?? null);
        self::assertSame('email_ownership', $refusal['error']['step_up']['kind'] ?? null);
        self::assertSame(EmailOwnershipStepUp::BEGIN_PATH, $refusal['error']['step_up']['begin'] ?? null);
        $demand = (string) $refusal['error']['step_up']['demand'];
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{16,43}$/D', $demand, 'the 403 carries the demand id');

        // (2) The begin against that demand: the code is delivered to
        // the captured seam.
        $client->request('POST', EmailOwnershipStepUp::BEGIN_PATH, [
            EmailOwnershipStepUp::EMAIL_FIELD => self::EMAIL,
            EmailOwnershipStepUp::DEMAND_FIELD => $demand,
        ]);
        $begin = $client->getResponse();
        self::assertSame(200, $begin->getStatusCode(), (string) $begin->getContent());
        $beginDocument = json_decode((string) $begin->getContent(), true);
        $ticket = (string) $beginDocument['challenge'];

        // (3) The completion answers the single-use grant.
        /** @var EmailJourneyCapturingSender $sender */
        $sender = $container->get('kiwi.email.code_capturer');
        $code = (string) $sender->lastCode();
        self::assertMatchesRegularExpression('/^[0-9]{6}$/D', $code);
        $client->request('POST', EmailOwnershipStepUp::COMPLETE_PATH, [
            'kiwi_step_up_ticket' => $ticket,
            'kiwi_step_up_code' => $code,
            EmailOwnershipStepUp::DEMAND_FIELD => $demand,
        ]);
        $complete = $client->getResponse();
        self::assertSame(200, $complete->getStatusCode(), (string) $complete->getContent());
        $grant = (string) json_decode((string) $complete->getContent(), true)['grant'];

        // (4) The submission: the grant redeems into the shared
        // finalizer, and the fresh completion assessment runs under the
        // signup scope's step-up minimum. The assessment re-raises over
        // the completed grant, the assurance escalates to the strictly
        // stronger child demand, and the completion is never authorized:
        // the refusal advertises exactly that child demand.
        $violations = $this->submit($container, $grant, 'signup', self::EMAIL);
        self::assertCount(1, $violations, 'a step-up minimum re-raises over the completed grant: '.var_export($violations, true));
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations[0]->getCode());
        $child = (string) ($violations[0]->getParameters()['{{ step_up_demand }}'] ?? '');
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{16,43}$/D', $child, 'the refusal advertises the escalation child demand');
        self::assertNotSame($demand, $child, 'the child demand is its own record');

        // (5) The same grant on the non-carrier login scope: a
        // violation, never a pass (the grant was spent by the redeemed
        // leg above).
        $misused = $this->submit($container, $grant, 'login', self::EMAIL);
        self::assertCount(1, $misused, 'a grant is worthless on a scope that did not name the carrier');
    }

    /**
     * The protected-form submission: the grant rides the request with
     * the scope's email field, the real container validator answers.
     *
     * @return \Symfony\Component\Validator\ConstraintViolationListInterface
     */
    private function submit(
        \Symfony\Component\DependencyInjection\ContainerInterface $container,
        string $grant,
        string $scope,
        string $email,
    ): \Symfony\Component\Validator\ConstraintViolationListInterface {
        $requestStack = $container->get('request_stack');
        \assert($requestStack instanceof RequestStack);
        // The submit leg is its own main request: the kernel's earlier
        // legs (challenge, begin, complete) leave the stack first. The
        // continuity cookie rides along, so the session-bound grant
        // sees the same browser.
        while ($requestStack->getCurrentRequest() !== null) {
            $requestStack->pop();
        }
        $request = new Request(request: [
            'kiwi__token' => $grant,
            'email' => $email,
        ], server: ['REMOTE_ADDR' => '198.51.100.7']);
        $cookie = $this->browser->getCookieJar()->get('__Host-kiwi-session');
        if ($cookie !== null) {
            $request->cookies->set('__Host-kiwi-session', (string) $cookie->getValue());
        }
        $requestStack->push($request);

        try {
            return $container->get('validator')->validate($grant, new KiwiCaptcha(['scope' => $scope]));
        } finally {
            $requestStack->pop();
        }
    }

    private function boot(): \Symfony\Component\DependencyInjection\ContainerInterface
    {
        if ($this->kernel === null) {
            $this->kernel = new EmailGrantJourneyTestKernel('test', true);
            $this->kernel->boot();
        }

        return $this->kernel->getContainer()->get('test.service_container');
    }
}
