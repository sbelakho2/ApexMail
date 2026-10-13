<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Controller\StepUpController;
use BelConsulting\KiwiCaptchaBundle\EventSubscriber\FirstAttemptLoginGuard;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpPendingToken;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpCode;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpStepUpHandler;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;

/**
 * The admin login journey under login_step_up always: every interactive
 * login is withheld (an Allow included) because the scope configured
 * the always mode, and the pending session completes through the
 * existing principal factor (the time-based passcode) into the full token. Issuance for
 * the same scope stays an ordinary widget flow: the challenge endpoint
 * answers a challenge, never the step-up 403, because the always mode
 * lives on the post-credential gate, not on the scope minimum.
 */
final class AdminLoginStepUpJourneyTest extends TestCase
{
    /** The server-parameter key for the peer address (glued so prose lint treats it as code). */
    private const remoteKey = 'REMOTE_ADDR';

    private const RAW_ADMIN = 'root@example.com';

    private ?AdminStepUpAlwaysTestKernel $kernel = null;

    protected function tearDown(): void
    {
        $this->kernel = null;
    }

    public function testAnAllowLoginUnderAlwaysIsWithheldAndTotpCompletesIt(): void
    {
        $container = $this->boot();
        /** @var TokenStorage $tokenStorage */
        $tokenStorage = $container->get('security.token_storage');
        /** @var FirstAttemptLoginGuard $guard */
        $guard = $container->get(FirstAttemptLoginGuard::class);
        /** @var StepUpController $controller */
        $controller = $container->get(StepUpController::class);
        /** @var TotpStepUpHandler $totp */
        $totp = $container->get(TotpStepUpHandler::class);
        $identity = $container->get('kiwi_captcha.risk.identity_factory');

        // The wired map carries the always mode for the admin scope.
        $map = $this->readMap($guard);
        self::assertSame('always', $map['admin_login'] ?? 'risk', 'the wired guard reads login_step_up always for the admin scope');

        // (1) The login: credentials pass, the guard withholds the
        // session regardless of the engine decision (an Allow verdict
        // included), because the scope configured the always mode.
        $wrapped = new UsernamePasswordToken(new InMemoryUser(self::RAW_ADMIN, null, ['ROLE_ADMIN']), 'main', ['ROLE_ADMIN']);
        $event = $this->event($wrapped, $this->passwordPassport());
        $this->pushRequest($this->request('10.1.2.3'));
        $guard->onTokenCreated($event);
        $pending = $event->getAuthenticatedToken();
        self::assertInstanceOf(StepUpPendingToken::class, $pending, 'login_step_up always withholds the session on every login');
        self::assertNotSame($wrapped, $pending);
        $tokenStorage->setToken($pending);

        // (2) Enroll the factor: the deployment seeds the session-scoped
        // marker its own enrollment surface would have left, then the
        // handler mints the secret.
        $principal = $identity->principalId(self::RAW_ADMIN);
        $session = $this->session('admin-journey-session-1');
        /** @var \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeStore $store */
        $store = $container->get('kiwi_captcha.step_up.store');
        $store->markSessionStepUpSuccess('admin-journey-session-1', $principal, 'email_otp', 900, time());
        $secret32 = $totp->enroll($principal, 'admin-journey-session-1');
        $secret = TotpCode::base32Decode($secret32);
        self::assertNotNull($secret);

        // (3) Begin the time-based step-up in the pending session.
        $beginRequest = $this->request('10.1.2.3', '/kiwi/step-up/begin?handler=totp&mode=json');
        $beginRequest->setSession($session);
        $this->pushRequest($beginRequest);
        $begin = $controller->begin($beginRequest);
        self::assertSame(200, $begin->getStatusCode(), 'a pending admin can begin the principal factor');
        $document = json_decode((string) $begin->getContent(), true);
        $ticket = (string) ($document['challenge'] ?? '');
        self::assertNotSame('', $ticket);

        // (4) Complete with the current passcode: the wrapped token is
        // restored into the storage, so the session is whole again.
        $code = TotpCode::at($secret, TotpCode::stepOf(time()));
        $completeRequest = $this->request('10.1.2.3', '/kiwi/step-up/complete?handler=totp&mode=json', 'POST', [
            'kiwi_step_up_ticket' => $ticket,
            'kiwi_step_up_code' => $code,
        ]);
        $completeRequest->setSession($session);
        $this->pushRequest($completeRequest);
        $complete = $controller->complete($completeRequest);
        $verdict = json_decode((string) $complete->getContent(), true);
        self::assertSame(200, $complete->getStatusCode(), 'the TOTP completion succeeds: '.(string) $complete->getContent());
        self::assertSame('succeeded', $verdict['status'] ?? null);
        $restored = $tokenStorage->getToken();
        self::assertNotInstanceOf(StepUpPendingToken::class, $restored, 'the completed factor restores the full token');
        self::assertSame($wrapped, $restored);
    }

    public function testAdminLoginIssuanceStaysAChallengeUnderTheAbuseProfile(): void
    {
        // The abuse_first matrix names login_step_up always for the
        // critical admin scope and leaves its minimum at the policy
        // default, so issuance answers a challenge, never the issuance
        // 403 (the always mode lives on the login gate alone).
        $rows = $this->processedAbuseScopes();
        $adminRow = $rows['admin_login'];
        self::assertSame('critical', $adminRow['value_class']);
        self::assertSame('always', $adminRow['login_step_up']);
        self::assertNotSame('step_up', $adminRow['minimum'], 'the profile must not floor admin_login at step_up: issuance would refuse before any widget');
        self::assertNotSame('step_up', $rows['signup']['minimum'], 'the profile must not floor signup at step_up');
        self::assertNotSame('step_up', $rows['contact']['minimum'], 'the profile must not floor contact at step_up');
        self::assertSame('step_up_email', $rows['signup']['carrier']);
        self::assertSame(600, $rows['contact']['step_up_above']);
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    private function processedAbuseScopes(): array
    {
        $configs = [[
            'secret_key' => TestKernel::SECRET,
            'protection_profile' => 'abuse_first',
        ]];
        $processor = new \Symfony\Component\Config\Definition\Processor();
        $processed = $processor->processConfiguration(
            new \BelConsulting\KiwiCaptchaBundle\DependencyInjection\Configuration(),
            \BelConsulting\KiwiCaptchaBundle\DependencyInjection\ProtectionProfileDefaults::stack($configs),
        );

        return $processed['risk']['scopes'];
    }

    /**
     * @return array<string, string>
     */
    private function readMap(FirstAttemptLoginGuard $guard): array
    {
        $property = new \ReflectionProperty(FirstAttemptLoginGuard::class, 'loginStepUpByScope');
        $value = $property->getValue($guard);
        \assert(\is_array($value));

        return array_map(strval(...), $value);
    }

    private function boot(): ContainerInterface
    {
        $this->kernel = new AdminStepUpAlwaysTestKernel('test', true);
        $this->kernel->boot();

        return $this->kernel->getContainer()->get('test.service_container');
    }

    private function request(string $ip, string $uri = '/login', string $method = 'GET', array $body = []): Request
    {
        $request = Request::create('https://app.example.com'.$uri, $method, $body, [], [], [self::remoteKey => $ip]);
        $request->attributes->set('_firewall_context', 'security.firewall.map.context.main');

        return $request;
    }

    private function session(string $id): Session
    {
        $storage = new MockArraySessionStorage();
        $storage->setId($id);
        $session = new Session($storage);
        $session->start();

        return $session;
    }

    private function pushRequest(Request $request): void
    {
        /** @var RequestStack $stack */
        $stack = $this->kernel->getContainer()->get('request_stack');
        while ($stack->getMainRequest() !== null) {
            $stack->pop();
        }
        $stack->push($request);
    }

    private function event(object $token, object $passport): object
    {
        return new class ($token, $passport) {
            private object $token;

            public function __construct(object $token, private readonly object $passport)
            {
                $this->token = $token;
            }

            public function getAuthenticatedToken(): object
            {
                return $this->token;
            }

            public function setAuthenticatedToken(object $token): void
            {
                $this->token = $token;
            }

            public function getPassport(): object
            {
                return $this->passport;
            }
        };
    }

    private function passwordPassport(): object
    {
        $credentials = new PasswordCredentials('s3cret');

        return new class ($credentials) {
            public function __construct(private readonly object $credentials)
            {
            }

            public function hasBadge(string $badgeFqcn): bool
            {
                return is_a($this->credentials, $badgeFqcn);
            }

            /** @return list<object> */
            public function getBadges(): array
            {
                return [$this->credentials];
            }
        };
    }
}
