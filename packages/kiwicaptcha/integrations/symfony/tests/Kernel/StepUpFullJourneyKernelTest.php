<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Controller\StepUpController;
use BelConsulting\KiwiCaptchaBundle\EventSubscriber\FirstAttemptLoginGuard;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpPendingToken;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpPendingTokenVoter;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpSessionBinding;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\CapturingStepUpCodeSender;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolver;
use Symfony\Component\Security\Core\Authentication\Token\RememberMeToken;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManager;
use Symfony\Component\Security\Core\Authorization\Voter\AuthenticatedVoter;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * The full-journey gate test. Everything under the security plane is
 * real. The container wires the real FirstAttemptLoginGuard. It uses
 * the real RiskGateway and engine. Novelty enforcement is set to
 * enforce. The real StepUpController and email handler are used. A
 * real StepUpPendingToken wraps a real UsernamePasswordToken in a
 * real TokenStorage. The real SessionRestorer is wired. The default
 * affirmative AccessDecisionManager is used.
 *
 * The journey: a novel login yields a pending token. Begin step-up.
 * A cross-session complete with a planted secret is refused. An
 * in-session complete succeeds. The session is restored. The second
 * login from the same ASN needs no step-up.
 */
final class StepUpFullJourneyKernelTest extends TestCase
{
    /** The server-parameter key for the peer address (glued so prose lint treats it as code). */
    private const remoteKey = 'REMOTE_ADDR';
    private const RAW_USER = 'alice@example.com';

    private ?StepUpJourneyTestKernel $kernel = null;

    protected function setUp(): void
    {
        // The journey runs on real Redis (KC_REDIS_URL, the real-Redis
        // suite's env): without it there is no honest journey to walk.
        if (StepUpJourneyTestKernel::redisUrl() === null) {
            self::markTestSkipped('KC_REDIS_URL not set — the full step-up journey runs on real Redis and is skipped');
        }
        // A fresh database per test: the journey's first login must be
        // novel, which stale principal-network history would defeat.
        (new \Predis\Client(StepUpJourneyTestKernel::redisUrl()))->flushdb();
    }

    protected function tearDown(): void
    {
        $this->kernel = null;
    }

    /**
     * The journey itself. One walk that would have caught findings 1, 2,
     * 4 and 6. Finding 1: the controller could not resolve a principal
     * on a pending token. Finding 2: the restore compared a raw
     * identifier against a pseudonym and refused every restore.
     * Finding 4: the gate swapped remember-me and stateless tokens for
     * pending tokens. Finding 6: the completion binding was optional.
     */
    public function testTheFullStepUpJourneyFromNovelLoginToRestoredSession(): void
    {
        $container = $this->boot();
        /** @var TokenStorage $tokenStorage */
        $tokenStorage = $container->get('security.token_storage');
        /** @var FirstAttemptLoginGuard $guard */
        $guard = $container->get(FirstAttemptLoginGuard::class);
        /** @var StepUpController $controller */
        $controller = $container->get(StepUpController::class);
        // The real principal-network store the extension wired (the
        // engine's novelty read and the restore's record address it).
        $riskStore = $container->get('kiwi_captcha.risk.principal_networks');
        self::assertInstanceOf(\KiwiCaptcha\Risk\Storage\RedisPrincipalNetworkTagStore::class, $riskStore);
        /** @var CapturingStepUpCodeSender $sender */
        $sender = $container->get('step_up_code_capturer');

        // (0) A remember-me login never enters the gate (finding 4).
        $remembered = new RememberMeToken(new InMemoryUser(self::RAW_USER, null, ['ROLE_USER']), 'main');
        $rememberedEvent = $this->event($remembered, $this->selfValidatingPassport());
        $guard->onTokenCreated($rememberedEvent);
        self::assertSame($remembered, $rememberedEvent->getAuthenticatedToken(), 'a remember-me login is never swapped for a pending token');

        // (1) Novel login: a password credential from a network the
        // principal has never proven. The real engine's first-attempt
        // evidence (novelty_enforcement=enforce) answers StepUp before
        // the session is granted.
        $user = new InMemoryUser(self::RAW_USER, null, ['ROLE_USER']);
        $passwordToken = new UsernamePasswordToken($user, 'main', ['ROLE_USER']);
        $loginEvent = $this->event($passwordToken, $this->passwordPassport());
        $this->pushRequest($this->request('10.1.2.3'));
        $guard->onTokenCreated($loginEvent);
        $pending = $loginEvent->getAuthenticatedToken();
        self::assertInstanceOf(StepUpPendingToken::class, $pending, 'a novel-network password login is withheld pending step-up');
        $tokenStorage->setToken($pending);

        // (2) The default affirmative access decision: a pending token
        // is never IS_AUTHENTICATED_FULLY.
        $access = new AccessDecisionManager([
            new StepUpPendingTokenVoter(),
            new AuthenticatedVoter(new AuthenticationTrustResolver()),
        ]);
        self::assertFalse($access->decide($tokenStorage->getToken(), ['IS_AUTHENTICATED_FULLY']), 'the affirmative strategy denies a pending token');

        // (3) Begin step-up. The controller unwraps the pending token
        // for the resolver, the typical $security->getUser() resolver
        // would otherwise resolve nothing (finding 1).
        $session = $this->session('journey-session-00000000000001');
        $beginRequest = $this->request('10.1.2.3', '/kiwi/step-up/begin?mode=json');
        $beginRequest->setSession($session);
        $this->pushRequest($beginRequest);
        $begin = $controller->begin($beginRequest);
        self::assertSame(200, $begin->getStatusCode(), 'a pending user can begin step-up');
        $document = json_decode((string) $begin->getContent(), true);
        self::assertIsArray($document);
        $ticket = (string) $document['challenge'];
        self::assertArrayNotHasKey('client_secret', $document, 'a session-bound begin mints no client secret (exactly one binding)');

        // (4) A stolen ticket completed under another session is
        // refused even with the code and a planted secret (finding 6).
        $code = (string) $sender->lastCode();
        $foreignSession = $this->session('journey-session-00000000000002');
        $foreignRequest = $this->request('10.1.2.3', '/kiwi/step-up/complete?mode=json', 'POST', [
            'kiwi_step_up_ticket' => $ticket,
            'kiwi_step_up_code' => $code,
            StepUpSessionBinding::CLIENT_SECRET_FIELD => \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::clientSecret(),
        ]);
        $foreignRequest->setSession($foreignSession);
        $this->pushRequest($foreignRequest);
        $foreign = $controller->complete($foreignRequest);
        $foreignBody = json_decode((string) $foreign->getContent(), true);
        self::assertSame(422, $foreign->getStatusCode(), 'a cross-session completion is refused');
        self::assertSame('session_mismatch', $foreignBody['failure_code'] ?? null);

        // (5) The real completion in the session that began it.
        $completeRequest = $this->request('10.1.2.3', '/kiwi/step-up/complete?mode=json', 'POST', [
            'kiwi_step_up_ticket' => $ticket,
            'kiwi_step_up_code' => $code,
        ]);
        $completeRequest->setSession($session);
        $this->pushRequest($completeRequest);
        $sessionIdBefore = (string) $session->getId();
        $complete = $controller->complete($completeRequest);
        $verdict = json_decode((string) $complete->getContent(), true);
        self::assertSame(200, $complete->getStatusCode(), 'the in-session completion succeeds');
        self::assertSame('succeeded', $verdict['status'] ?? null);

        // (6) The restored session (finding 2): the token is no longer
        // pending and the network was recorded under the challenge's
        // principal pseudonym.
        $restored = $tokenStorage->getToken();
        self::assertNotInstanceOf(StepUpPendingToken::class, $restored, 'a successful step-up restores the wrapped token');
        self::assertSame($passwordToken, $restored);
        self::assertTrue($access->decide($restored, ['IS_AUTHENTICATED_FULLY']), 'the affirmative strategy grants the restored token');
        $principalPseudonym = $container->get('kiwi_captcha.risk.identity_factory')->principalId(self::RAW_USER);
        $network = bin2hex("\x04".inet_pton('10.1.2.3'));
        self::assertTrue($riskStore->principalNetworkSeen($principalPseudonym, $network), 'the step-up records the network');
        self::assertTrue($riskStore->principalNetworkSeen($principalPseudonym, 'asn:64512'), 'the step-up records the ASN under the engine spelling');
        self::assertNotSame($sessionIdBefore, (string) $session->getId(), 'the session id rotated on the privilege upgrade (finding 3)');

        // (7) The second login from the same ASN: no step-up, the
        // network is proven now.
        $secondToken = new UsernamePasswordToken(new InMemoryUser(self::RAW_USER, null, ['ROLE_USER']), 'main', ['ROLE_USER']);
        $secondEvent = $this->event($secondToken, $this->passwordPassport());
        $this->pushRequest($this->request('10.1.2.3'));
        $guard->onTokenCreated($secondEvent);
        self::assertSame($secondToken, $secondEvent->getAuthenticatedToken(), 'the second login from the same ASN needs no step-up');
    }

    /**
     * Finding 4's second case in the journey kernel: a stateless API
     * token (self-validating passport, no PasswordCredentials badge)
     * never gets a pending token it could never clear.
     */
    public function testAStatelessApiLoginNeverGetsAPendingToken(): void
    {
        $container = $this->boot();
        /** @var FirstAttemptLoginGuard $guard */
        $guard = $container->get(FirstAttemptLoginGuard::class);
        $token = new UsernamePasswordToken(new InMemoryUser('api-client', null, ['ROLE_API']), 'api');
        $event = $this->event($token, $this->selfValidatingPassport());
        $this->pushRequest($this->request('10.1.2.3'));
        $guard->onTokenCreated($event);

        self::assertSame($token, $event->getAuthenticatedToken(), 'a stateless API token must never be swapped for a pending token it can never clear');
    }

    private function boot(): ContainerInterface
    {
        $this->kernel = new StepUpJourneyTestKernel('test', true);
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

    /**
     * A duck-typed AuthenticationTokenCreatedEvent carrying a real
     * security token and a passport exposing the real badge surface
     * (this suite's security-event shims reserve the Passport class
     * name for the bridge tests).
     */
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
        $credentials = new \Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials('s3cret');

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

    private function selfValidatingPassport(): object
    {
        return new class {
            public function hasBadge(string $badgeFqcn): bool
            {
                return false;
            }

            /** @return list<object> */
            public function getBadges(): array
            {
                return [];
            }
        };
    }
}
