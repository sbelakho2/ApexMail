<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\EventSubscriber\FirstAttemptLoginGuard;
use BelConsulting\KiwiCaptchaBundle\Risk\LoginDecisionGate;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskDecision;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use PHPUnit\Framework\TestCase;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpPendingToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * The first-attempt gate (P0-1): a LoginSuccessEvent runs the engine
 * pipeline with the principal id, and a StepUp decision replaces the
 * success response so the session is never granted.
 */
final class FirstAttemptLoginGuardTest extends TestCase
{
    private function identity(): RiskIdentityFactory
    {
        return new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat("\x11", 32)));
    }

    private function request(): Request
    {
        return Request::create('https://example.com/login', 'POST', [], [], [], ['REMOTE_ADDR' => '203.0.113.10']);
    }

    /**
     * A duck-typed AuthenticationTokenCreatedEvent carrying a duck-typed
     * authenticated token. The test asserts the TOKEN is replaced (the
     * session is withheld), not merely that a response was swapped.
     */
    private function event(): object
    {
        $request = $this->request();
        $token = new class implements TokenInterface {
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

        return new class ($request, $token) {
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
            public function __construct(private readonly ?RiskDecision $result, private readonly bool $throw)
            {
            }

            public function loginDecision(string $scope, string $ip, ?string $session = null, ?string $principal = null, ?string $idempotencyKey = null): ?RiskDecision
            {
                if ($this->throw) {
                    throw new \RuntimeException('redis down');
                }

                return $this->result;
            }
        };
    }

    public function testAStepUpDecisionWithholdsTheSessionToken(): void
    {
        $guard = new FirstAttemptLoginGuard($this->stubGateway($this->decision(RiskAction::StepUp)), $this->identity(), '1');

        $event = $this->event();
        $guard->onTokenCreated($event);

        $token = $event->getAuthenticatedToken();
        self::assertInstanceOf(StepUpPendingToken::class, $token, 'a StepUp decision must withhold the session token');
        self::assertSame([StepUpPendingToken::ROLE], $token->getRoleNames(), 'the pending token grants only the step-up role');
    }

    public function testAnAllowDecisionLeavesTheTokenIntact(): void
    {
        $guard = new FirstAttemptLoginGuard($this->stubGateway($this->decision(RiskAction::Allow)), $this->identity(), '1');

        $event = $this->event();
        $guard->onTokenCreated($event);

        self::assertNotInstanceOf(StepUpPendingToken::class, $event->getAuthenticatedToken(), 'an Allow decision must not touch the token');
    }

    public function testAGatewayErrorFailsClosedToThePendingToken(): void
    {
        $guard = new FirstAttemptLoginGuard($this->stubGateway(null, true), $this->identity(), '1');

        $event = $this->event();
        $guard->onTokenCreated($event);

        self::assertInstanceOf(
            StepUpPendingToken::class,
            $event->getAuthenticatedToken(),
            'a gate error must fail closed to the pending token, never hand out a full session',
        );
    }
}
