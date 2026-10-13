<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\EventSubscriber\FirstAttemptLoginGuard;
use BelConsulting\KiwiCaptchaBundle\Risk\LoginDecisionGate;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpPendingToken;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskDecision;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * The first-attempt gate (P0-1): a LoginSuccessEvent runs the engine
 * pipeline with the principal id, and a StepUp decision replaces the
 * success response so the session is never granted. The scope resolves
 * per event through the login_scopes map (the request's firewall
 * context attribute), and an unmapped firewall skips the gate.
 */
final class FirstAttemptLoginGuardTest extends TestCase
{
    /** The server-parameter key for the peer address (glued so prose lint treats it as code). */
    private const remoteKey = 'REMOTE_ADDR';

    /** The firewall context attribute shape the framework stamps on a login request. */
    private const MAIN_CONTEXT = 'security.firewall.map.context.main';

    private function identity(): RiskIdentityFactory
    {
        return new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat("\x11", 32)));
    }

    private function request(): Request
    {
        $request = Request::create('https://example.com/login', 'POST', [], [], [], [self::remoteKey => '203.0.113.10']);
        $request->attributes->set('_firewall_context', self::MAIN_CONTEXT);

        return $request;
    }

    /**
     * A duck-typed AuthenticationTokenCreatedEvent carrying a duck-typed
     * authenticated token. The test asserts the token is replaced (the
     * session is withheld), not just that a response was swapped.
     */
    private function event(): object
    {
        return $this->eventFor($this->request());
    }

    /** The same event shape over a caller-supplied request. */
    private function eventFor(Request $request): object
    {
        return new class ($request, $this->token()) {
            private ?object $token;

            public function __construct(private readonly Request $request, object $token)
            {
                $this->token = $token;
            }

            public function getRequest(): Request
            {
                return $this->request;
            }

            public function getAuthenticatedToken(): ?object
            {
                return $this->token;
            }

            public function setAuthenticatedToken(object $token): void
            {
                $this->token = $token;
            }
        };
    }

    /**
     * An event whose setter refuses the pending replacement (the
     * simulated wiring failure inside the guard's exception handler)
     * but accepts the null clear: the shape the refused-login path must
     * answer with a cleared token and an AuthenticationException.
     */
    private function refusingEvent(): object
    {
        return new class ($this->request(), $this->token()) {
            private ?object $token;

            public function __construct(private readonly Request $request, object $token)
            {
                $this->token = $token;
            }

            public function getRequest(): Request
            {
                return $this->request;
            }

            public function getAuthenticatedToken(): ?object
            {
                return $this->token;
            }

            public function setAuthenticatedToken(?object $token): void
            {
                if ($token !== null) {
                    throw new \RuntimeException('the pending replacement is refused');
                }
                $this->token = null;
            }
        };
    }

    /** The duck-typed authenticated token the events carry. */
    private function token(): TokenInterface
    {
        return new class implements TokenInterface {
            private array $attributes = [];

            public function __toString(): string
            {
                return 'authenticated(user-42)';
            }

            public function getUserIdentifier(): string
            {
                return 'user-42';
            }

            public function getRoleNames(): array
            {
                return ['ROLE_USER'];
            }

            public function getUser(): ?UserInterface
            {
                return null;
            }

            public function setUser(UserInterface $user): void
            {
            }

            public function eraseCredentials(): void
            {
            }

            public function getAttributes(): array
            {
                return $this->attributes;
            }

            public function setAttributes(array $attributes): void
            {
                $this->attributes = $attributes;
            }

            public function hasAttribute(string $name): bool
            {
                return isset($this->attributes[$name]);
            }

            public function getAttribute(string $name): mixed
            {
                return $this->attributes[$name] ?? null;
            }

            public function setAttribute(string $name, mixed $value): void
            {
                $this->attributes[$name] = $value;
            }

            public function __serialize(): array
            {
                return ['attributes' => $this->attributes];
            }

            public function __unserialize(array $data): void
            {
                $this->attributes = $data['attributes'] ?? [];
            }
        };
    }

    private function decision(RiskAction $action): RiskDecision
    {
        return new RiskDecision(
            score: 100,
            action: $action,
            reasons: [],
            policyVersion: 3,
            globalLevel: 0,
            decisionId: 'd-1',
        );
    }

    private function stubGateway(?RiskDecision $result, bool $throw = false): LoginDecisionGate
    {
        return new class ($result, $throw) implements LoginDecisionGate {
            public ?array $seenTargetFields = null;
            public ?string $seenScope = null;

            public function __construct(private readonly ?RiskDecision $result, private readonly bool $throw)
            {
            }

            public function loginDecision(string $scope, string $ip, ?string $session = null, ?string $principal = null, ?string $idempotencyKey = null, ?string $device = null, array $targetFields = []): ?RiskDecision
            {
                $this->seenScope = $scope;
                $this->seenTargetFields = $targetFields;
                if ($this->throw) {
                    throw new \RuntimeException('redis down');
                }

                return $this->result;
            }
        };
    }

    public function testAStepUpDecisionWithholdsTheSessionToken(): void
    {
        $guard = new FirstAttemptLoginGuard($this->stubGateway($this->decision(RiskAction::StepUp)), $this->identity(), ['main' => '1']);

        $event = $this->event();
        $guard->onTokenCreated($event);

        $token = $event->getAuthenticatedToken();
        self::assertInstanceOf(StepUpPendingToken::class, $token, 'a StepUp decision must withhold the session token');
        self::assertSame([StepUpPendingToken::ROLE], $token->getRoleNames(), 'the pending token grants only the step-up role');
        self::assertSame('1', $token->scope(), 'the pending token carries the scope the demand was raised under');
    }

    public function testAnAllowDecisionLeavesTheTokenIntact(): void
    {
        $guard = new FirstAttemptLoginGuard($this->stubGateway($this->decision(RiskAction::Allow)), $this->identity(), ['main' => '1']);

        $event = $this->event();
        $guard->onTokenCreated($event);

        self::assertNotInstanceOf(StepUpPendingToken::class, $event->getAuthenticatedToken(), 'an Allow decision must not touch the token');
    }

    public function testAGatewayErrorFailsClosedToThePendingToken(): void
    {
        $guard = new FirstAttemptLoginGuard($this->stubGateway(null, true), $this->identity(), ['main' => '1']);

        $event = $this->event();
        $guard->onTokenCreated($event);

        self::assertInstanceOf(
            StepUpPendingToken::class,
            $event->getAuthenticatedToken(),
            'a gate error must fail closed to the pending token, never hand out a full session',
        );
    }

    /**
     * The refused-login invariant: when the exception handler cannot
     * install the pending state either, the authenticated token is
     * cleared and the login is refused outright. An authentication that
     * stays authenticated on an undetermined outcome would hand the
     * full session the gate exists to withhold.
     */
    public function testAFailedPendingReplacementClearsTheTokenAndRefusesTheLogin(): void
    {
        $guard = new FirstAttemptLoginGuard($this->stubGateway(null, true), $this->identity(), ['main' => '1']);

        $event = $this->refusingEvent();
        try {
            $guard->onTokenCreated($event);
            self::fail('a replacement failure inside the exception handler must refuse the login');
        } catch (AuthenticationException $e) {
            self::assertNull($event->getAuthenticatedToken(), 'the authenticated token must be cleared when the pending state cannot be installed');
        }
    }

    public function testConfiguredTargetFieldRidesTheLoginDecision(): void
    {
        $gateway = $this->stubGateway($this->decision(RiskAction::Allow));
        $guard = new FirstAttemptLoginGuard($gateway, $this->identity(), ['main' => '1'], targetFieldsByScope: ['1' => ['username']]);

        $request = Request::create('https://example.com/login', 'POST', ['username' => 'victim@example.com'], [], [], [self::remoteKey => '203.0.113.10']);
        $request->attributes->set('_firewall_context', self::MAIN_CONTEXT);
        $guard->onTokenCreated($this->eventFor($request));

        self::assertSame(
            ['username' => 'victim@example.com'],
            $gateway->seenTargetFields,
            'the guard must pass the submitted target-field value into the decision so the target dimension books on the first-attempt path',
        );
    }

    public function testAnEmptyOrUnconfiguredTargetFieldPassesNothing(): void
    {
        $gateway = $this->stubGateway($this->decision(RiskAction::Allow));
        $guard = new FirstAttemptLoginGuard($gateway, $this->identity(), ['main' => '1'], targetFieldsByScope: ['1' => ['username']]);

        $request = Request::create('https://example.com/login', 'POST', ['username' => ''], [], [], [self::remoteKey => '203.0.113.10']);
        $request->attributes->set('_firewall_context', self::MAIN_CONTEXT);
        $guard->onTokenCreated($this->eventFor($request));

        self::assertSame([], $gateway->seenTargetFields, 'an empty submitted field carries no target dimension');

        // No configured target field at all: the same empty shape.
        $plainGateway = $this->stubGateway($this->decision(RiskAction::Allow));
        $plain = new FirstAttemptLoginGuard($plainGateway, $this->identity(), ['main' => '1']);
        $plain->onTokenCreated($this->eventFor($this->request()));
        self::assertSame([], $plainGateway->seenTargetFields);
    }

    /**
     * The target field reads the request's full payload, not just the
     * form body: a json_login request posts its fields as a JSON body,
     * and a deployment whose login is JSON must keep the target
     * dimension exactly like a form login.
     */
    public function testAJsonBodyTargetFieldRidesTheDecision(): void
    {
        $gateway = $this->stubGateway($this->decision(RiskAction::Allow));
        $guard = new FirstAttemptLoginGuard($gateway, $this->identity(), ['main' => '1'], targetFieldsByScope: ['1' => ['username']]);

        $request = Request::create('https://example.com/login', 'POST', [], [], [], [self::remoteKey => '203.0.113.10'], json_encode(['username' => 'victim@example.com', 'password' => 'correct horse']));
        $request->headers->set('CONTENT_TYPE', 'application/json');
        $request->attributes->set('_firewall_context', self::MAIN_CONTEXT);
        $guard->onTokenCreated($this->eventFor($request));

        self::assertSame(
            ['username' => 'victim@example.com'],
            $gateway->seenTargetFields,
            'a json_login body carries the target dimension like a form body',
        );
    }

    /**
     * A malformed (array-shaped) value under the configured field name
     * resolves no target and never throws inside the guard: the login
     * flow must survive a hostile body untouched.
     */
    public function testAnArrayShapedTargetFieldValueIsSkipped(): void
    {
        $gateway = $this->stubGateway($this->decision(RiskAction::Allow));
        $guard = new FirstAttemptLoginGuard($gateway, $this->identity(), ['main' => '1'], targetFieldsByScope: ['1' => ['username']]);

        $request = Request::create('https://example.com/login', 'POST', ['username' => ['a' => 'b'], 'password' => 'x'], [], [], [self::remoteKey => '203.0.113.10']);
        $request->attributes->set('_firewall_context', self::MAIN_CONTEXT);
        $guard->onTokenCreated($this->eventFor($request));

        self::assertSame([], $gateway->seenTargetFields, 'an array-shaped field value carries no target dimension and raises nothing');
    }

    /**
     * The resolved scope books the decision: the request's firewall
     * context attribute selects the login_scopes entry, so the engine
     * assesses the login under the mapped scope's policy.
     */
    public function testTheDecisionBooksUnderTheMappedScopeOfTheEventFirewall(): void
    {
        $gateway = $this->stubGateway($this->decision(RiskAction::Allow));
        $guard = new FirstAttemptLoginGuard($gateway, $this->identity(), ['main' => 'login', 'admin' => 'admin_login']);

        $adminRequest = Request::create('https://example.com/admin/login', 'POST', [], [], [], [self::remoteKey => '203.0.113.10']);
        $adminRequest->attributes->set('_firewall_context', 'security.firewall.map.context.admin');
        $guard->onTokenCreated($this->eventFor($adminRequest));
        self::assertSame('admin_login', $gateway->seenScope, 'the admin firewall books under its own scope');

        $guard->onTokenCreated($this->event());
        self::assertSame('login', $gateway->seenScope, 'the user firewall books under the login scope');
    }

    /**
     * An unmapped firewall is outside the guard's mandate: the token
     * stays untouched and the skip is counted, so a deployment can see
     * the logins that bypass the gate through a missing entry.
     */
    public function testAnUnmappedFirewallSkipsTheGateAndCounts(): void
    {
        $gateway = $this->stubGateway($this->decision(RiskAction::StepUp));
        $counters = new \BelConsulting\KiwiCaptchaBundle\Risk\MetricsCounterStore('kiwicaptcha.tests.unmapped');
        $guard = new FirstAttemptLoginGuard($gateway, $this->identity(), ['main' => 'login'], counters: $counters);

        $request = Request::create('https://example.com/sso', 'POST', [], [], [], [self::remoteKey => '203.0.113.10']);
        $request->attributes->set('_firewall_context', 'security.firewall.map.context.sso');
        $event = $this->eventFor($request);
        $guard->onTokenCreated($event);

        self::assertNotInstanceOf(StepUpPendingToken::class, $event->getAuthenticatedToken(), 'an unmapped firewall is skipped, not withheld');
        self::assertSame(1, $counters->all()['kiwi_login_guard_unmapped_total'] ?? 0, 'the unmapped skip is counted');
    }
}
