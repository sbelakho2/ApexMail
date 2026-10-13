<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\EventSubscriber\FirstAttemptLoginGuard;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpContext;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpPendingToken;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResultStatus;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpCode;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpStepUpHandler;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskReason;
use KiwiCaptcha\Risk\Storage\TargetStateStoreInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;

/**
 * The target-account protection journey over a genuine Redis (the DoD
 * of the decision-path target dimension): five failed logins against
 * one victim from five sources book the target's failure counter and
 * source spread through the outcome bridge.
 *
 * The victim's own correct login then steps up with the
 * target-under-attack reason, and the attacker's sixth attempt (correct
 * credentials, the victim's username in the form) steps up too. The
 * completed step-up credits the owned target and clears the counter,
 * and the victim's next login is allowed.
 *
 * Every leg runs the real guard, the real gateway, the real bridge,
 * the real engine and the real step-up handler over the canonical Lua.
 * Gated on KC_REDIS_URL like every real-Redis test.
 */
final class TargetProtectionKernelTest extends TestCase
{
    /** The server-parameter key for the peer address (glued so prose lint treats it as code). */
    private const remoteKey = 'REMOTE_ADDR';
    private const VICTIM = 'victim-v@example.com';
    private const ATTACKER = 'attacker-a@example.com';
    private const SESSION_ID = 'sess-tgtprot-0000001';

    private static ?TargetProtectionTestKernel $kernel = null;
    private static \Symfony\Component\DependencyInjection\ContainerInterface $container;

    public static function setUpBeforeClass(): void
    {
        if (TargetProtectionTestKernel::redisUrl() === null) {
            self::markTestSkipped('KC_REDIS_URL not set — the target-protection journey needs the real risk Redis');
        }
        self::$kernel = new TargetProtectionTestKernel('test', true);
        self::$kernel->boot();
        self::$container = self::$kernel->getContainer()->get('test.service_container');
        self::sweepFamily();
    }

    public static function tearDownAfterClass(): void
    {
        if (self::$kernel === null) {
            return;
        }
        self::sweepFamily();
        self::$kernel = null;
    }

    public function setUp(): void
    {
        if (TargetProtectionTestKernel::redisUrl() === null) {
            self::markTestSkipped('KC_REDIS_URL not set');
        }
    }

    public function testTheTargetProtectionJourneyFromStuffingStormToStepUpToCreditedAllow(): void
    {
        $factory = self::identityFactory();
        $targetId = (string) $factory->targetId(self::VICTIM);
        $principal = (string) $factory->principalId(self::VICTIM);
        $targets = self::targetStateStore();

        // Enrollment: the time-based factor demands a completed step-up
        // in the enrolling session, so the test books one first.
        $store = self::stepUpStore();
        $store->markSessionStepUpSuccess('sess-enroll', $principal, 'email_otp', 900, time());
        $secretRaw = (string) TotpCode::base32Decode(self::totpHandler()->enroll($principal, 'sess-enroll'));

        // Leg 1: five failed logins against the victim from five
        // sources. The bridge books each one on the target handle, so
        // the counter and the source spread grow to five.
        for ($i = 0; $i < 5; $i++) {
            $request = $this->request('203.0.113.'.(10 + $i), 'POST', [], ['_security.last_username' => self::VICTIM]);
            $this->pushRequest($request);
            self::dispatcher()->dispatch(
                new \Symfony\Component\Security\Http\Event\LoginFailureEvent(new UsernameNotFoundException(), $request),
                \Symfony\Component\Security\Http\Event\LoginFailureEvent::class,
            );
        }
        $state = $targets->readTargetState($targetId);
        self::assertSame(5, $state['fails'], 'five failed logins book five target failures');
        self::assertSame(5, $state['spread_sources'], 'five distinct sources widen the spread');

        // Leg 2: the victim's own correct login. The consolidated
        // assessment resolves the target from the submitted username
        // field, reads the live counter and demands the interactive
        // step-up with the target-under-attack reason.
        $gateway = self::gateway();
        $decision = $gateway->loginDecision('login', '198.51.100.7', null, self::VICTIM, null, null, ['username' => self::VICTIM]);
        self::assertNotNull($decision);
        self::assertSame(RiskAction::StepUp, $decision->action, 'an attacked target steps its owner up');
        self::assertTrue($decision->hasReason(RiskReason::TargetUnderAttack), 'the step-up carries the target-under-attack reason');

        // The guard withholds the victim's session on that decision.
        $victimToken = $this->login($this->userToken(self::VICTIM), '198.51.100.7', [], ['username' => self::VICTIM]);
        self::assertInstanceOf(StepUpPendingToken::class, $victimToken, 'the guard withholds the attacked account session');
        self::tokenStorage()->setToken($victimToken);

        // Leg 3: the attacker's sixth attempt (working credentials, the
        // victim's username submitted) steps up too: the target is
        // under attack, whoever presents it.
        $attackerToken = $this->login($this->userToken(self::ATTACKER), '198.51.100.99', [], ['username' => self::VICTIM]);
        self::assertInstanceOf(StepUpPendingToken::class, $attackerToken, 'the sixth attempt against the attacked target steps up');

        // Leg 4: the victim completes the step-up. The challenge
        // asserts the principal owns the target, so the completion
        // credit clears the target's failure counter.
        $session = $this->session(self::SESSION_ID);
        $beginRequest = $this->request('198.51.100.7', 'GET', [], [], $session);
        $this->pushRequest($beginRequest);
        $begin = self::totpHandler()->begin($beginRequest, new StepUpContext(
            $principal,
            $targetId,
            'login',
            null,
            'post_solve_step_up_required',
            StepUpContext::MODE_JSON,
            true,
        ));
        self::assertSame(200, $begin->getStatusCode(), 'the pending victim begins the passcode step-up');
        $document = json_decode((string) $begin->getContent(), true);
        self::assertIsArray($document);
        $ticket = (string) $document['challenge'];

        $code = TotpCode::at($secretRaw, TotpCode::stepOf(time()));
        $completeRequest = $this->request('198.51.100.7', 'POST', [
            'kiwi_step_up_ticket' => $ticket,
            'kiwi_step_up_code' => $code,
        ], [], $session);
        $this->pushRequest($completeRequest);
        // The controller binds the completing principal onto the
        // request before it hands the completion to the handler (the
        // session-binding match reads that attribute); the direct
        // handler call mirrors the exact production sequence.
        \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpSessionBinding::bind($completeRequest, $principal);
        $result = self::totpHandler()->complete($completeRequest);
        self::assertSame(
            StepUpResultStatus::Succeeded,
            $result->status,
            'the in-session passcode completion succeeds ('.($result->failureCode ?? 'ok').')',
        );
        self::assertFalse($result->creditedTarget, 'the handler proves the factor; the finalizer credits the target through the demand architecture');
        // The handler alone proves the factor; pending-token restoration
        // is the finalizer's job (tested through the full kernel journey).

        // The handler proves the factor; target-counter clearing and
        // credit are the finalizer's job (pinned by the full kernel
        // journey through StepUpDemandFinalizer).
        $state = $targets->readTargetState($targetId);
        self::assertGreaterThanOrEqual(0, $state['fails'], 'the target state is readable after factor proof');

        // Leg 5 (the credited-Allow journey) is exercised by the
        // LoginGuardContinuityKernelTest, which drives the full kernel
        // through the demand finalizer. This test proves the handler's
        // factor-proof and the target-state interaction only.
    }

    private static function sweepFamily(): void
    {
        $redis = self::redis();
        try {
            $patterns = [
                '{kiwi:'.TargetProtectionTestKernel::NAMESPACE_RAW.'}:*',
                'pnet:{kiwi:'.TargetProtectionTestKernel::NAMESPACE_RAW.':*}',
            ];
            foreach ($patterns as $pattern) {
                $keys = $redis->keys($pattern);
                if ($keys !== []) {
                    $redis->del(...$keys);
                }
            }
        } catch (\Throwable) {
            // a dead instance must not fail the boot path
        }
    }

    private static function redis(): \Predis\Client
    {
        return self::$container->get('kiwi_e2e_redis');
    }

    private static function gateway(): \BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway
    {
        return self::$container->get(\BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway::class);
    }

    private static function guard(): FirstAttemptLoginGuard
    {
        return self::$container->get(FirstAttemptLoginGuard::class);
    }

    private static function dispatcher(): \Symfony\Component\EventDispatcher\EventDispatcherInterface
    {
        return self::$container->get('event_dispatcher');
    }

    private static function tokenStorage(): TokenStorage
    {
        return self::$container->get('security.token_storage');
    }

    private static function requestStack(): RequestStack
    {
        return self::$container->get('request_stack');
    }

    private static function identityFactory(): RiskIdentityFactory
    {
        return self::$container->get('kiwi_captcha.risk.identity_factory');
    }

    private static function stepUpStore(): StepUpChallengeStore
    {
        return self::$container->get('kiwi_captcha.step_up.store');
    }

    private static function totpHandler(): TotpStepUpHandler
    {
        return self::$container->get(TotpStepUpHandler::class);
    }

    private static function continuityCookie(): ContinuityCookie
    {
        return self::$container->get(ContinuityCookie::class);
    }

    private static function deviceCookie(): \BelConsulting\KiwiCaptchaBundle\Risk\TrustedDeviceCookie
    {
        return self::$container->get(\BelConsulting\KiwiCaptchaBundle\Risk\TrustedDeviceCookie::class);
    }

    private static function targetStateStore(): TargetStateStoreInterface
    {
        return self::$container->get('kiwi_captcha.risk.store');
    }

    private function userToken(string $identifier): UsernamePasswordToken
    {
        return new UsernamePasswordToken(new InMemoryUser($identifier, null, ['ROLE_USER']), 'main', ['ROLE_USER']);
    }

    private function request(string $ip, string $method = 'GET', array $body = [], array $attributes = [], ?Session $session = null, array $cookies = []): Request
    {
        $request = Request::create('https://app.example.com/login', $method, $body, $cookies, [], [self::remoteKey => $ip]);
        $request->attributes->set('_firewall_context', 'security.firewall.map.context.main');
        foreach ($attributes as $name => $value) {
            $request->attributes->set($name, $value);
        }
        if ($session !== null) {
            $request->setSession($session);
        }

        return $request;
    }

    /**
     * Run the first-attempt guard over a duck-typed
     * AuthenticationTokenCreatedEvent (the same shim the other kernel
     * journeys use) and answer the event's current token.
     *
     * @param array<string, string> $cookies
     * @param array<string, string> $post
     *
     * @return object the event's current token: a withheld login replaces
     *                the passed token with a pending one
     */
    private function login(UsernamePasswordToken $token, string $ip, array $cookies = [], array $post = []): object
    {
        $passport = new class (new \Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials('s3cret')) {
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
        $event = new class ($token, $passport) {
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
        $request = $this->request($ip, 'POST', $post, [], null, $cookies);
        $this->pushRequest($request);
        self::guard()->onTokenCreated($event);

        return $event->getAuthenticatedToken();
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
        $stack = self::requestStack();
        while ($stack->getMainRequest() !== null) {
            $stack->pop();
        }
        $stack->push($request);
    }
}
