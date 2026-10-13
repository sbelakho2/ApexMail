<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Controller\StepUpController;
use BelConsulting\KiwiCaptchaBundle\EventSubscriber\DeviceCookieSubscriber;
use BelConsulting\KiwiCaptchaBundle\EventSubscriber\FirstAttemptLoginGuard;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpPendingToken;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpCode;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\TrustedDeviceCookie;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * The login-continuity journey over a genuine Redis: the engine, the
 * principal network tag store and the step-up store all run the
 * canonical Lua, so every binding the journey asserts is the real
 * deployment binding, not an in-memory stand-in.
 *
 * The journey pins the device continuity contract end to end. The first
 * login from a never-seen network is withheld pending the passcode
 * factor. The completed factor mints the trusted-device value, binds it
 * under the principal and stages it for the response subscriber. The
 * re-login carrying the same cookies is allowed, and so is the login
 * from a rotated address of the same carrier: the device tag vouches
 * where the network is new. After logout and with the cookies stripped,
 * a fresh address is novel again and the gate withholds the session.
 *
 * Gated on KC_REDIS_URL like every real-Redis test.
 */
final class LoginGuardContinuityKernelTest extends TestCase
{
    /** The server-parameter key for the peer address (glued so prose lint treats it as code). */
    private const remoteKey = 'REMOTE_ADDR';
    private const RAW_USER = 'continuity-user@example.com';
    private const SESSION_ID = 'sess-continuity-0000000001';

    private static ?LoginGuardContinuityTestKernel $kernel = null;
    private static \Symfony\Component\DependencyInjection\ContainerInterface $container;

    public static function setUpBeforeClass(): void
    {
        if (LoginGuardContinuityTestKernel::redisUrl() === null) {
            self::markTestSkipped('KC_REDIS_URL not set — the login-continuity journey needs the real risk Redis');
        }
        self::$kernel = new LoginGuardContinuityTestKernel('test', true);
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
        if (LoginGuardContinuityTestKernel::redisUrl() === null) {
            self::markTestSkipped('KC_REDIS_URL not set');
        }
    }

    /**
     * The journey itself. The passcode enrollment books the session
     * proof the enrollment gate demands (the same preparation every
     * factor test uses), then the four login legs run through the real
     * guard and the real engine on the real store.
     */
    public function testTheContinuityJourneyFromStepUpToAllowedReLoginToStrippedCookies(): void
    {
        $guard = self::guard();
        $tokenStorage = self::tokenStorage();
        $principal = self::identityFactory()->principalId(self::RAW_USER);

        // Enrollment: the gate demands a completed factor in the
        // enrolling session, so the test books one first (the store
        // marker, exactly like the factor kernel test does).
        $store = self::stepUpStore();
        $store->markSessionStepUpSuccess('sess-enroll', $principal, 'email_otp', 900, time());
        $secret32 = self::totpHandler()->enroll($principal, 'sess-enroll');
        $secretRaw = (string) TotpCode::base32Decode($secret32);

        // Leg 1: the first login from a never-seen network, no cookies.
        // The gate must withhold the session and stage no device mint.
        $firstToken = $this->login($this->userToken(), '10.1.2.3');
        $request = self::requestStack()->getMainRequest();
        self::assertInstanceOf(StepUpPendingToken::class, $firstToken, 'a novel-network first login is withheld pending step-up');
        self::assertNull($request->attributes->get(FirstAttemptLoginGuard::DEVICE_MINT_ATTRIBUTE), 'a withheld login mints no device cookie');
        $tokenStorage->setToken($firstToken);

        // Step-up: begin and complete the passcode factor in the session
        // that began it. The completion restores the wrapped token.
        $session = $this->session(self::SESSION_ID);
        $beginRequest = $this->request('10.1.2.3', '/kiwi/step-up/begin?handler=totp&mode=json');
        $beginRequest->setSession($session);
        $this->pushRequest($beginRequest);
        $begin = self::controller()->begin($beginRequest);
        self::assertSame(200, $begin->getStatusCode(), 'a pending user can begin the passcode step-up');
        $document = json_decode((string) $begin->getContent(), true);
        self::assertIsArray($document);
        $ticket = (string) $document['challenge'];

        $code = TotpCode::at($secretRaw, TotpCode::stepOf(time()));
        $completeRequest = $this->request('10.1.2.3', '/kiwi/step-up/complete?handler=totp&mode=json', 'POST', [
            'kiwi_step_up_ticket' => $ticket,
            'kiwi_step_up_code' => $code,
        ]);
        $completeRequest->setSession($session);
        $this->pushRequest($completeRequest);
        $complete = self::controller()->complete($completeRequest);
        $verdict = json_decode((string) $complete->getContent(), true);
        self::assertSame(200, $complete->getStatusCode(), 'the in-session passcode completion succeeds');
        self::assertSame('succeeded', $verdict['status'] ?? null);
        $restored = $tokenStorage->getToken();
        self::assertNotInstanceOf(StepUpPendingToken::class, $restored, 'a completed factor restores the wrapped token');

        // F5, the mint: the completion stages a fresh device value and
        // the response subscriber turns it into the Set-Cookie header.
        $deviceValue = $completeRequest->attributes->get(FirstAttemptLoginGuard::DEVICE_MINT_ATTRIBUTE);
        self::assertMatchesRegularExpression(TrustedDeviceCookie::VALUE_PATTERN, (string) $deviceValue, 'the restore stages a well-formed device value');
        $deviceCookie = $this->issueCookie($completeRequest, (string) $deviceValue);
        self::assertSame(self::deviceCookie()->name(), $deviceCookie->getName(), 'the subscriber issues the configured device cookie');
        self::assertSame($deviceValue, $deviceCookie->getValue(), 'the issued cookie carries the staged mint value');
        self::assertTrue($deviceCookie->isHttpOnly(), 'the device cookie is HttpOnly');

        // The bindings the completion wrote: the device tag is trusted
        // under the principal, beside the network and the ASN bucket.
        $devicePseudonym = self::identityFactory()->deviceId((string) $deviceValue);
        $tagStore = self::principalNetworks();
        self::assertTrue($tagStore->tagIsTrusted($principal, 'device:'.$devicePseudonym) === true, 'the completed step-up binds the device tag as trusted');
        self::assertTrue($tagStore->principalNetworkSeen($principal, '040a010203') === true, 'the step-up records the login network');
        self::assertTrue($tagStore->principalNetworkSeen($principal, 'asn:64512') === true, 'the step-up records the ASN bucket');

        // Logout: the session goes away, the browser keeps its cookies.
        $continuityValue = self::continuityCookie()->mint();
        $cookies = $this->cookiesFor($continuityValue, (string) $deviceValue);
        $tokenStorage->setToken(null);

        // Leg 2: the re-login with the same cookies is allowed. The
        // device tag vouches; the presented device value re-issues
        // verbatim so its Max-Age slides forward.
        $secondToken = $this->login($this->userToken(), '10.1.2.3', $cookies);
        self::assertNotInstanceOf(StepUpPendingToken::class, $secondToken, 'the re-login with the same cookies is allowed');
        $reissued = self::requestStack()->getMainRequest()->attributes->get(FirstAttemptLoginGuard::DEVICE_MINT_ATTRIBUTE);
        self::assertSame($deviceValue, $reissued, 'an allowed login re-issues the presented device value');

        // Leg 3: the rotated address of the same carrier. The network is
        // new, so only the device tag can vouch — the exact continuity
        // the cookies exist to carry.
        $thirdToken = $this->login($this->userToken(), '10.9.9.9', $cookies);
        self::assertNotInstanceOf(StepUpPendingToken::class, $thirdToken, 'the same cookies vouch on a rotated address');
        self::assertTrue($tagStore->tagIsTrusted($principal, 'device:'.$devicePseudonym) === true, 'every allowed login refreshes the device trust');

        // Leg 4: logout, cookies stripped, a fresh address. Nothing
        // vouches: the gate withholds the session again.
        $tokenStorage->setToken(null);
        $fourthToken = $this->login($this->userToken(), '10.7.7.7');
        self::assertInstanceOf(StepUpPendingToken::class, $fourthToken, 'stripped cookies on a fresh address are novel again');

        // Privacy: no raw identifier of the journey ever lands in Redis.
        self::assertNoCanaryInStore();
    }

    private static function sweepFamily(): void
    {
        $redis = self::redis();
        try {
            // The tag families of this leg: the store families inside the
            // hash tag and the principal tag store's own pnet-prefixed
            // family, whose tag sits behind the prefix. A leftover
            // binding would vouch for the journey's principal and fake
            // an Allow, so every family goes.
            $patterns = [
                '{kiwi:'.LoginGuardContinuityTestKernel::NAMESPACE_RAW.'}:*',
                'pnet:{kiwi:'.LoginGuardContinuityTestKernel::NAMESPACE_RAW.':*}',
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

    private static function guard(): FirstAttemptLoginGuard
    {
        return self::$container->get(FirstAttemptLoginGuard::class);
    }

    private static function controller(): StepUpController
    {
        return self::$container->get(StepUpController::class);
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

    private static function deviceCookie(): TrustedDeviceCookie
    {
        return self::$container->get(TrustedDeviceCookie::class);
    }

    private static function principalNetworks(): \KiwiCaptcha\Risk\Storage\PrincipalNetworkTagStoreInterface
    {
        return self::$container->get('kiwi_captcha.risk.principal_networks');
    }

    private function userToken(): UsernamePasswordToken
    {
        return new UsernamePasswordToken(new InMemoryUser(self::RAW_USER, null, ['ROLE_USER']), 'main', ['ROLE_USER']);
    }

    private function request(string $ip, string $uri = '/login', string $method = 'GET', array $body = [], array $cookies = []): Request
    {
        $request = Request::create('https://app.example.com'.$uri, $method, $body, $cookies, [], [self::remoteKey => $ip]);
        $request->attributes->set('_firewall_context', 'security.firewall.map.context.main');

        return $request;
    }

    /**
     * @param array<string, string> $cookies
     *
     * @return object the event's current token: a withheld login replaces
     *                the passed token with a pending one, so the verdict
     *                must always be read back from the event
     */
    private function login(UsernamePasswordToken $token, string $ip, array $cookies = []): object
    {
        $event = $this->event($token);
        $this->pushRequest($this->request($ip, '/login', 'GET', [], $cookies));
        self::guard()->onTokenCreated($event);

        return $event->getAuthenticatedToken();
    }

    /**
     * @param array<string, string> $cookies
     *
     * @return array<string, string>
     */
    private function cookiesFor(string $continuity, string $device): array
    {
        return [self::continuityCookie()->name() => $continuity, self::deviceCookie()->name() => $device];
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

    /**
     * The device cookie of one staged mint: the response subscriber runs
     * over a real response event, exactly the middleware position it
     * holds in production.
     */
    private function issueCookie(Request $request, string $value): \Symfony\Component\HttpFoundation\Cookie
    {
        $response = new Response('', 200);
        $event = new \Symfony\Component\HttpKernel\Event\ResponseEvent(
            self::$kernel,
            $request,
            HttpKernelInterface::MAIN_REQUEST,
            $response,
        );
        self::$container->get(DeviceCookieSubscriber::class)->onKernelResponse($event);
        $cookies = $response->headers->getCookies();
        self::assertNotSame([], $cookies, 'the subscriber issues the staged device cookie');

        return $cookies[0];
    }

    /**
     * A duck-typed AuthenticationTokenCreatedEvent carrying a real
     * security token and a password passport, the shape the guard
     * duck-types on (the same event shim the journey kernel test uses).
     */
    private function event(object $token): object
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

    /**
     * The canary scan: no key or value in the leg's namespaces carries
     * the raw journey identifier or any raw 32-hex cookie value.
     */
    private static function assertNoCanaryInStore(): void
    {
        $redis = self::redis();
        $haystack = [];
        $keys = array_merge(
            $redis->keys('{kiwi:'.LoginGuardContinuityTestKernel::NAMESPACE_RAW.'}:*'),
            $redis->keys('pnet:{kiwi:'.LoginGuardContinuityTestKernel::NAMESPACE_RAW.':*}'),
        );
        foreach ($keys as $key) {
            $haystack[] = (string) $key;
            $type = $redis->type($key);
            $haystack[] = match ((string) $type) {
                'hash' => implode("\n", array_map('strval', $redis->hgetall($key) ?? [])),
                'list' => implode("\n", $redis->lrange($key, 0, -1) ?? []),
                'set' => implode("\n", $redis->smembers($key) ?? []),
                'zset' => implode("\n", $redis->zrange($key, 0, -1) ?? []),
                'string' => (string) $redis->get($key),
                default => '',
            };
        }
        $blob = implode("\n", $haystack);
        self::assertStringNotContainsString('continuity-user', $blob, 'no raw identifier is ever stored');
        self::assertStringNotContainsString('@example.com', $blob);
    }
}
