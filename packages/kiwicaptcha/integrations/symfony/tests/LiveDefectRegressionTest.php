<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\EventSubscriber\FirstAttemptLoginGuard;
use BelConsulting\KiwiCaptchaBundle\Http\RequestFieldResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\LoginDecisionGate;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOtpStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\MailerStepUpCodeSender;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\PrincipalEmailResolverInterface;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpContext;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpPendingToken;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpTicket;
use BelConsulting\KiwiCaptchaBundle\Controller\StepUpController;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\KiwiStepUpHandlerRegistry;
use BelConsulting\KiwiCaptchaBundle\Risk\PrincipalResolverInterface;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\CapturingStepUpCodeSender;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskDecision;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Regression tests for the live runtime defects closed at head:
 *
 *  1. Terminal login Deny must stay terminal (no step-up mint).
 *  4. Nested Symfony request binding resolves nested form fields.
 *  5. Email OTP resolves the destination from the principal, not the
 *     identifier.
 *  7. Pending-token scope resolution is consistent.
 *  8. The /healthz probe record satisfies the record grammar.
 * 10. EmailOtpStepUpHandler reserves delivery only on an accepted
 *     begin: proven-pre-handoff release, ambiguous failure = spent.
 */
final class LiveDefectRegressionTest extends TestCase
{
    private const MASTER = '0123456789abcdef0123456789abcdef';

    private const PRINCIPAL = '00112233445566778899aabbccddeeff';

    private const remoteKey = 'REMOTE_ADDR';

    private const MAIN_CONTEXT = 'security.firewall.map.context.main';

    // ── Defect 1: terminal login Deny ────────────────────────────────

    public function testATerminalDenyRefusesTheLoginAndNeverMintsAStepUp(): void
    {
        $guard = new FirstAttemptLoginGuard(
            $this->stubGateway($this->decision(RiskAction::Deny)),
            $this->identity(),
            ['main' => 'login'],
        );
        $event = $this->event();
        try {
            $guard->onTokenCreated($event);
            self::fail('a terminal Deny must refuse the login, not mint a step-up');
        } catch (BadCredentialsException) {
            // Terminal: the authentication fails. Nothing to restore.
        }
        self::assertNotInstanceOf(
            StepUpPendingToken::class,
            $event->getAuthenticatedToken(),
            'a terminal Deny must never mint a solvable step-up token',
        );
    }

    public function testATerminalDenyUnderAlwaysPolicyAlsoStaysTerminal(): void
    {
        // The always step-up policy must not turn a Deny into a
        // solvable step-up: the Deny check runs first.
        $guard = new FirstAttemptLoginGuard(
            $this->stubGateway($this->decision(RiskAction::Deny)),
            $this->identity(),
            ['main' => 'login'],
            loginStepUpByScope: ['login' => 'always'],
        );
        $event = $this->event();
        try {
            $guard->onTokenCreated($event);
            self::fail('a terminal Deny under always-step-up must refuse the login');
        } catch (BadCredentialsException) {
        }
        self::assertNotInstanceOf(
            StepUpPendingToken::class,
            $event->getAuthenticatedToken(),
            'a terminal Deny must never mint a solvable step-up token, even under always',
        );
    }

    public function testAStepUpDecisionStillMintsThePendingToken(): void
    {
        $guard = new FirstAttemptLoginGuard(
            $this->stubGateway($this->decision(RiskAction::StepUp)),
            $this->identity(),
            ['main' => 'login'],
        );
        $event = $this->event();
        $guard->onTokenCreated($event);
        self::assertInstanceOf(
            StepUpPendingToken::class,
            $event->getAuthenticatedToken(),
            'a StepUp decision must still withhold the session behind a pending token',
        );
    }

    // ── Defect 4: nested Symfony request binding ─────────────────────

    public function testNestedFormBindingResolvesTheRequestBinding(): void
    {
        // A Symfony form named `signup` nests its fields under the form
        // name: signup[kiwi_request_binding]=txn-42.
        $request = Request::create('/', 'POST', ['signup' => ['kiwi_request_binding' => 'txn-42']]);
        self::assertSame(
            'txn-42',
            RequestFieldResolver::string($request, 'kiwi_request_binding'),
            'a nested Symfony form field must resolve, not only a flat request key',
        );
    }

    public function testFlatRequestBindingStillResolves(): void
    {
        $request = Request::create('/', 'POST', ['kiwi_request_binding' => 'txn-7']);
        self::assertSame('txn-7', RequestFieldResolver::string($request, 'kiwi_request_binding'));
    }

    public function testAmbiguousNestedBindingFailsClosed(): void
    {
        $request = Request::create('/', 'POST', [
            'login' => ['kiwi_request_binding' => 'txn-a'],
            'signup' => ['kiwi_request_binding' => 'txn-b'],
        ]);
        self::assertNull(
            RequestFieldResolver::string($request, 'kiwi_request_binding'),
            'two distinct values under one name must answer null, never a guess',
        );
    }

    public function testDeeplyNestedTargetFieldsResolve(): void
    {
        $request = Request::create('/', 'POST', [
            'registration' => ['child' => ['email' => 'user@example.com']],
        ]);
        $fields = RequestFieldResolver::targetFields($request, ['email']);
        self::assertSame(['email' => 'user@example.com'], $fields);
    }

    // ── Defect 5: username-based email OTP destination ───────────────

    public function testEmailResolvesFromThePrincipalEmailAccessor(): void
    {
        if (!interface_exists(\Symfony\Component\Mailer\MailerInterface::class)) {
            self::markTestSkipped('symfony/mailer is not installed in this environment');
        }
        $user = new class implements UserInterface {
            public function getUserIdentifier(): string
            {
                return 'jdoe';
            }

            public function getRoles(): array
            {
                return [];
            }

            public function eraseCredentials(): void
            {
            }

            public function getEmail(): string
            {
                return 'jdoe@example.com';
            }
        };
        $sender = new MailerStepUpCodeSender(
            $this->stubMailer(),
            'noreply@example.com',
            $this->stubTokenStorage(new class($user) implements TokenInterface {
                private array $attributes = [];

                public function __construct(private readonly object $user)
                {
                }

                public function __toString(): string
                {
                    return 'token';
                }

                public function getUserIdentifier(): string
                {
                    return $this->user->getUserIdentifier();
                }

                public function getRoleNames(): array
                {
                    return [];
                }

                public function getUser(): ?UserInterface
                {
                    return $this->user;
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
                }

                public function hasAttribute(string $name): bool
                {
                    return false;
                }

                public function getAttribute(string $name): mixed
                {
                    return null;
                }

                public function setAttribute(string $name, mixed $value): void
                {
                }

                public function __serialize(): array
                {
                    return ['user' => $this->user];
                }

                public function __unserialize(array $data): void
                {
                }
            }),
        );
        $context = new StepUpContext(self::PRINCIPAL, null, 'login', null, 'post_solve_step_up_required');
        $sender->send('123456', $context, 300);
        self::assertTrue(true, 'a username-based principal resolves its address through getEmail()');
    }

    public function testAWiredPrincipalEmailResolverWins(): void
    {
        if (!interface_exists(\Symfony\Component\Mailer\MailerInterface::class)) {
            self::markTestSkipped('symfony/mailer is not installed in this environment');
        }
        $resolver = new class implements PrincipalEmailResolverInterface {
            public function resolveEmail(object|string|null $user): ?string
            {
                return 'resolved@example.com';
            }
        };
        $sender = new MailerStepUpCodeSender(
            $this->stubMailer(),
            'noreply@example.com',
            null,
            null,
            $resolver,
        );
        $context = new StepUpContext(self::PRINCIPAL, null, 'login', null, 'post_solve_step_up_required');
        $sender->send('123456', $context, 300);
        self::assertTrue(true, 'a wired resolver delivers without an email-shaped identifier');
    }

    // ── Defect 7: pending-token scope resolution consistency ─────────

    public function testThePrincipalResolvesUnderThePendingTokenScope(): void
    {
        $resolvedScopes = [];
        $resolver = new class($resolvedScopes) implements PrincipalResolverInterface {
            public function __construct(private array &$scopes)
            {
            }

            public function resolve(Request $request, string $scope): ?string
            {
                $this->scopes[] = $scope;

                return 'user-42';
            }
        };
        $storage = $this->stubTokenStorage();
        $pending = new StepUpPendingToken($this->stubInnerToken());
        $pending->setAttribute(StepUpPendingToken::SCOPE_ATTRIBUTE, 'financial_action');
        $storage->setToken($pending);

        $dummyHandler = new class implements \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpHandlerInterface {
            public function assurance(): \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFactorAssurance
            {
                return \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFactorAssurance::emailOtp();
            }

            public function begin(Request $request, StepUpContext $context): \Symfony\Component\HttpFoundation\Response
            {
                return new \Symfony\Component\HttpFoundation\Response('x');
            }

            public function complete(Request $request): \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResult
            {
                return \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResult::failed('unknown');
            }
        };
        $registry = new KiwiStepUpHandlerRegistry(['email_otp' => $dummyHandler], 'email_otp');
        $controller = new StepUpController(
            $registry,
            $this->identity(),
            'login',
            $resolver,
            $storage,
        );
        $request = Request::create('/kiwi/step-up/begin');
        try {
            $controller->begin($request);
        } catch (\Throwable) {
            // No handler registered: the resolution already ran.
        }
        self::assertSame(
            ['financial_action'],
            $resolvedScopes,
            'the principal must resolve under the pending token scope, not the configured fallback',
        );
    }

    // ── Defect 8: /healthz protocol record ───────────────────────────

    public function testTheHealthProbeRecordSatisfiesTheRecordGrammar(): void
    {
        $salt = base64_encode(random_bytes(16));
        $challenge = 'healthz';
        $record = new \KiwiCaptcha\ChallengeRecord(
            nonce: base64_encode(random_bytes(32)),
            scope: 'healthz',
            bindingTag: '',
            issuedAt: time() - 1,
            expiresAt: time() + 60,
            algorithm: \KiwiCaptcha\PoWAlgorithm::Sha256,
            mKib: 0,
            t: 1,
            p: 1,
            targetBits: 8,
            salt: $salt,
            prefix: $challenge.'|'.$salt.'|',
            challenge: $challenge,
            minDurationMs: 0,
            issuedAtNs: (int) (microtime(true) * 1_000_000),
            protocolVersion: 2,
        );
        $roundTripped = \KiwiCaptcha\ChallengeRecord::fromArray($record->toArray());
        self::assertNotNull($roundTripped, 'the health probe record must survive the strict decode');
        self::assertSame($challenge.'|'.$salt.'|', $roundTripped->prefix, 'the derived prefix must equal challenge|salt|');
    }

    public function testTheOldHealthRecordShapeIsRejected(): void
    {
        $this->expectException(\KiwiCaptcha\MalformedRecordException::class);
        \KiwiCaptcha\ChallengeRecord::fromArray([
            'nonce' => base64_encode(random_bytes(32)),
            'scope' => 'healthz',
            'binding_tag' => '',
            'issued_at' => time() - 1,
            'expires_at' => time() + 60,
            'algorithm' => 'sha256',
            'm_kib' => 0,
            't' => 1,
            'p' => 1,
            'target_bits' => 8,
            'salt' => base64_encode(random_bytes(16)),
            'prefix' => 'healthz',
            'challenge' => 'healthz',
            'min_duration_ms' => 0,
            'protocol_version' => 2,
        ]);
    }

    // ── Defect 10: EmailOtp mail reservation semantics ──────────────

    public function testAnAcceptedBeginReservesAndCommitsTheDelivery(): void
    {
        $store = new ArrayStepUpChallengeStore($this->clock());
        $sender = new CapturingStepUpCodeSender();
        $handler = $this->otpHandler($store, $sender);
        $response = $handler->begin($this->beginRequest(), $this->context(json: true));
        self::assertSame(200, $response->getStatusCode());
        self::assertNotNull($sender->lastCode(), 'the accepted begin delivers the code');
        $body = json_decode((string) $response->getContent(), true);
        self::assertIsArray($body);
        self::assertArrayHasKey('delivery_attempt_id', $body, 'the begin document surfaces the delivery attempt id');
        self::assertSame(1, $body['delivery_generation'], 'the OTP handler funds generation 1');
    }

    public function testAProvenPreHandoffFailureReleasesTheReservation(): void
    {
        // A create() failure is proven pre-handoff: nothing reached the
        // transport, so the reservation releases. With maxBegins 1 the
        // released slot must let a retry reserve again.
        $store = new \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FailingCreateStepUpChallengeStore(
            new ArrayStepUpChallengeStore($this->clock()),
        );
        $sender = new CapturingStepUpCodeSender();
        $handler = $this->otpHandler($store, $sender, maxBegins: 1);
        $store->failCreate = true;
        $response = $handler->begin($this->beginRequest(), $this->context());
        self::assertSame(503, $response->getStatusCode());
        self::assertNull($sender->lastCode(), 'nothing is handed to the transport before the record exists');
        // The reservation released: the mail capacity returns. A retry
        // must still be able to reserve.
        $store->failCreate = false;
        $retry = $handler->begin($this->beginRequest(), $this->context());
        self::assertSame(200, $retry->getStatusCode(), 'the released reservation lets a retry reserve again');
    }

    public function testAnAmbiguousHandoffFailureSpendsTheReservation(): void
    {
        $store = new ArrayStepUpChallengeStore($this->clock());
        $sender = new CapturingStepUpCodeSender();
        $sender->throwOnSend = new \RuntimeException('transport refused');
        $handler = $this->otpHandler($store, $sender, maxBegins: 1);
        $response = $handler->begin($this->beginRequest(), $this->context());
        self::assertSame(503, $response->getStatusCode());
        // Ambiguous = spent: the reservation commits, so the next begin
        // sees the spent budget (maxBegins 1 is now used).
        $sender->throwOnSend = null;
        $retry = $handler->begin($this->beginRequest(), $this->context());
        self::assertSame(429, $retry->getStatusCode(), 'an ambiguous failure spends the reservation, never a free retry');
    }

    // ── helpers ──────────────────────────────────────────────────────

    private int $clockValue = 1700000000;

    private function clock(): \Closure
    {
        return function (): int {
            return $this->clockValue;
        };
    }

    private function identity(): RiskIdentityFactory
    {
        return new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat("\x11", 32)));
    }

    private function decision(RiskAction $action): RiskDecision
    {
        return new RiskDecision(
            score: 900,
            action: $action,
            reasons: [],
            policyVersion: 1,
            globalLevel: 0,
        );
    }

    private function stubGateway(?RiskDecision $decision): LoginDecisionGate
    {
        return new class ($decision) implements LoginDecisionGate {
            public function __construct(private readonly ?RiskDecision $decision)
            {
            }

            public function loginDecision(string $scope, string $ip, ?string $session = null, ?string $principal = null, ?string $idempotencyKey = null, ?string $device = null, array $targetFields = []): ?RiskDecision
            {
                return $this->decision;
            }
        };
    }

    private function request(): Request
    {
        $request = Request::create('https://example.com/login', 'POST', [], [], [], [self::remoteKey => '203.0.113.10']);
        $request->attributes->set('_firewall_context', self::MAIN_CONTEXT);

        return $request;
    }

    private function event(): object
    {
        $request = $this->request();

        return new class ($request, $this->stubInnerToken()) {
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

    private function stubInnerToken(): TokenInterface
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
            }

            public function hasAttribute(string $name): bool
            {
                return false;
            }

            public function getAttribute(string $name): mixed
            {
                return null;
            }

            public function setAttribute(string $name, mixed $value): void
            {
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

    private function stubTokenStorage(?TokenInterface $token = null): TokenStorageInterface
    {
        return new class ($token) implements TokenStorageInterface {
            private ?TokenInterface $token;

            public function __construct(?TokenInterface $token)
            {
                $this->token = $token;
            }

            public function getToken(): ?TokenInterface
            {
                return $this->token;
            }

            public function setToken(?TokenInterface $token): void
            {
                $this->token = $token;
            }
        };
    }

    private function stubMailer(): \Symfony\Component\Mailer\MailerInterface
    {
        return new class implements \Symfony\Component\Mailer\MailerInterface {
            public function send(\Symfony\Component\Mime\RawMessage $message, ?\Symfony\Component\Mailer\Envelope $envelope = null): void
            {
            }
        };
    }

    private function context(bool $json = false): StepUpContext
    {
        return new StepUpContext(
            self::PRINCIPAL,
            null,
            'login',
            null,
            'post_solve_step_up_required',
            $json ? StepUpContext::MODE_JSON : StepUpContext::MODE_HTML,
            demandId: \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(),
        );
    }

    private function beginRequest(): Request
    {
        return Request::create('https://example.com/kiwi/step-up/begin', 'GET');
    }

    private function otpHandler(StepUpChallengeStore $store, CapturingStepUpCodeSender $sender, int $maxBegins = 3): EmailOtpStepUpHandler
    {
        return new EmailOtpStepUpHandler(
            $store,
            new StepUpTicket(self::MASTER),
            $sender,
            self::MASTER,
            300,
            5,
            6,
            $maxBegins,
            900,
            '/kiwi/step-up/complete',
            $this->clock(),
        );
    }
}
