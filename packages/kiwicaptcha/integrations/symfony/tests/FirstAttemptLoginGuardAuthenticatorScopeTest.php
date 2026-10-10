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
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authentication\Token\RememberMeToken;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;

/**
 * The interactive-authenticator scope of the first-attempt gate
 * (finding 4), against the real security tokens and the real
 * PasswordCredentials badge the FormLogin / JsonLogin / HttpBasic
 * authenticators put on their passports. Only an interactive password
 * login may be swapped for a pending token: a remember-me token or a
 * stateless (self-validating, non-password) passport carries no
 * interactive step-up completion path, so a pending token would strand
 * that client forever.
 *
 * The passport is duck-typed around hasBadge()/getBadges() (the same
 * duck-typing the guard itself applies): this suite's security-event
 * shims reserve the Passport class name for the bridge tests, so the
 * guard contract is asserted on the badge surface the real Passport
 * exposes.
 */
final class FirstAttemptLoginGuardAuthenticatorScopeTest extends TestCase
{
    public function testARememberMeLoginNeverGetsAPendingToken(): void
    {
        $guard = $this->guard($this->decision(RiskAction::StepUp));
        $token = new RememberMeToken(new InMemoryUser('alice', null, ['ROLE_USER']), 'main');
        // The remember-me authenticator's passport is self-validating
        // (no password credentials).
        $event = $this->event($token, $this->selfValidatingPassport());

        $guard->onTokenCreated($event);

        self::assertSame($token, $event->getAuthenticatedToken(), 'a remember-me login must never be swapped for a pending token the client cannot clear');
    }

    public function testAStatelessApiLoginNeverGetsAPendingToken(): void
    {
        $guard = $this->guard($this->decision(RiskAction::StepUp));
        $token = new UsernamePasswordToken(new InMemoryUser('api-client', null, ['ROLE_API']), 'api');
        // The stateless / token authenticator shape: a passport with no
        // PasswordCredentials badge.
        $event = $this->event($token, $this->selfValidatingPassport());

        $guard->onTokenCreated($event);

        self::assertSame($token, $event->getAuthenticatedToken(), 'a stateless API token must never be swapped for a pending token it can never clear');
    }

    /**
     * The positive control: a password-login passport (the FormLogin /
     * JsonLogin / HttpBasic shape) on a StepUp decision is withheld —
     * the pending token is the conservative outcome.
     */
    public function testAPasswordLoginOnAStepUpDecisionIsWithheld(): void
    {
        $guard = $this->guard($this->decision(RiskAction::StepUp));
        $token = new UsernamePasswordToken(new InMemoryUser('alice', null, ['ROLE_USER']), 'main', ['ROLE_USER']);
        $event = $this->event($token, $this->passwordPassport());

        $guard->onTokenCreated($event);

        $replaced = $event->getAuthenticatedToken();
        self::assertInstanceOf(StepUpPendingToken::class, $replaced, 'an interactive password login must be withheld on a StepUp decision');
        self::assertSame($token, $replaced->getWrapped());
    }

    /**
     * The positive control's counterpart: the same password passport on
     * an Allow decision is left intact.
     */
    public function testAPasswordLoginOnAnAllowDecisionIsLeftIntact(): void
    {
        $guard = $this->guard($this->decision(RiskAction::Allow));
        $token = new UsernamePasswordToken(new InMemoryUser('alice', null, ['ROLE_USER']), 'main', ['ROLE_USER']);
        $event = $this->event($token, $this->passwordPassport());

        $guard->onTokenCreated($event);

        self::assertSame($token, $event->getAuthenticatedToken());
    }

    private function guard(RiskDecision $decision): FirstAttemptLoginGuard
    {
        $gateway = new class ($decision) implements LoginDecisionGate {
            public function __construct(private readonly RiskDecision $result)
            {
            }

            public function loginDecision(string $scope, string $ip, ?string $session = null, ?string $principal = null, ?string $idempotencyKey = null): ?RiskDecision
            {
                return $this->result;
            }
        };
        $stack = new RequestStack();
        $stack->push(Request::create('https://example.com/login', 'POST', [], [], [], ['Remote_ADDR' => '203.0.113.10']));

        return new FirstAttemptLoginGuard(
            $gateway,
            new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat("\x11", 32))),
            'login',
            requestStack: $stack,
        );
    }

    /**
     * A duck-typed AuthenticationTokenCreatedEvent carrying a real
     * token and a passport exposing the real badge surface.
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

    /** The real PasswordCredentials badge on a passport (FormLogin shape). */
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

    /** The self-validating (remember-me / stateless API) passport shape. */
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
}
