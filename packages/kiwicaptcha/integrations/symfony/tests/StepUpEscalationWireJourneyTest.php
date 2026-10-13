<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\StepUpController;
use BelConsulting\KiwiCaptchaBundle\Risk\PrincipalResolverInterface;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOtpStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpBootstrapGate;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpCompletionCredit;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandFinalizer;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandState;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFactorResolver;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpPendingToken;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResultStatus;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpTicket;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpCode;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\CapturingStepUpCodeSender;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePrincipalResolver;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * The controller-level escalation journey, every step on the wire. A
 * pending login begins its email one-time-passcode factor and completes
 * it. The fresh reassessment re-raises the step-up, the parent demand
 * is superseded by its strictly stronger child, and the completion
 * answers a structured step_up_required document that names the child
 * demand, the factor it requires, its assurance rank and the begin
 * path. The browser then begins the child through the same endpoint:
 * the begin follows the family from the pending token's superseded
 * parent to the child, so the child demand is beginnable. The child's
 * stronger factor completes, the reassessment allows, and the demand
 * settles authorized: the child demand survives the wire boundary it
 * used to be dropped at.
 */
final class StepUpEscalationWireJourneyTest extends TestCase
{
    private const MASTER = 'kiwi-journey-master-0123456789abcdef';

    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const RAW_USER = 'user-42';

    private const SCOPE = 'login';

    private const SESSION_ID = 'journey-session-0000000000001';

    private const BEGIN_PATH = '/kiwi/step-up/begin';

    private const COMPLETE_PATH = '/kiwi/step-up/complete';

    /** The store clock of the journey, advanced explicitly. */
    private int $now = 1700000000;

    private ArrayStepUpChallengeStore $store;

    private CapturingStepUpCodeSender $sender;

    private SpyOutcomeReporter $reporter;

    private StepUpTicket $ticket;

    private RiskIdentityFactory $identity;

    private TokenStorage $tokenStorage;

    private EmailOtpStepUpHandler $otp;

    private TotpStepUpHandler $totp;

    /** The request stack the bootstrap gate reads its granted request from. */
    private RequestStack $enrollStack;

    protected function setUp(): void
    {
        $this->store = new ArrayStepUpChallengeStore(fn (): int => $this->now);
        $this->sender = new CapturingStepUpCodeSender();
        $this->reporter = new SpyOutcomeReporter();
        $this->ticket = new StepUpTicket(self::MASTER);
        $this->identity = new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat("\x11", 32)));
        $this->tokenStorage = new TokenStorage();
        $this->enrollStack = new RequestStack();
        $this->otp = new EmailOtpStepUpHandler(
            $this->store,
            $this->ticket,
            $this->sender,
            self::MASTER,
            300,
            5,
            6,
            6,
            900,
            self::COMPLETE_PATH,
            fn (): int => $this->now,
        );
        $this->totp = new TotpStepUpHandler(
            $this->store,
            $this->ticket,
            'sha1',
            6,
            1,
            300,
            5,
            6,
            900,
            self::COMPLETE_PATH,
            fn (): int => $this->now,
            self::MASTER,
            null,
            null,
            new StepUpBootstrapGate(true, $this->enrollStack, $this->identity),
        );
    }

    public function testTheEscalationChildSurvivesTheWireAndAuthorizes(): void
    {
        $principal = $this->identity->principalId(self::RAW_USER);
        $parentDemandId = StepUpPendingToken::mintDemandId();
        $this->tokenStorage->setToken($this->pendingToken($parentDemandId));

        $escalating = $this->controller($this->finalizer('step_up'));
        $allowing = $this->controller($this->finalizer('allow'));

        // (1) The email factor begins against the fresh parent demand.
        $session = $this->session();
        $beginRequest = $this->request('/kiwi/step-up/begin?mode=json&handler=email_otp', 'GET');
        $beginRequest->setSession($session);
        $begin = $escalating->begin($beginRequest);
        self::assertSame(200, $begin->getStatusCode(), (string) $begin->getContent());
        $beginDocument = $this->document($begin);
        self::assertSame('email_otp', $beginDocument['handler']);
        $parent = $this->store->readDemand($parentDemandId);
        self::assertNotNull($parent, 'the begin minted the demand the pending token named');
        self::assertTrue($parent->state->isOpen());
        self::assertNotNull($parent->requiredFactor, 'the mint snapshot the factor requirement');
        self::assertSame('email_otp', $parent->requiredFactor->family);

        // (2) The email completion verifies, the reassessment re-raises
        // the step-up, and the wire answer is the structured escalation:
        // the child demand, its required factor and rank, the begin
        // path. The parent sits superseded.
        $code = (string) $this->sender->lastCode();
        $completeRequest = $this->request('/kiwi/step-up/complete?mode=json', 'POST', [
            EmailOtpStepUpHandler::TICKET_FIELD => (string) $beginDocument['challenge'],
            EmailOtpStepUpHandler::CODE_FIELD => $code,
        ]);
        $completeRequest->setSession($session);
        $complete = $escalating->complete($completeRequest);
        self::assertSame(422, $complete->getStatusCode(), (string) $complete->getContent());
        $answer = $this->document($complete);
        self::assertSame('step_up_required', $answer['status'], 'the escalation answers step_up_required on the wire');
        self::assertSame('escalated', $answer['reason']);
        self::assertArrayHasKey('demand', $answer, 'the child demand id rides the answer');
        $childDemandId = (string) $answer['demand'];
        self::assertNotSame($parentDemandId, $childDemandId);
        self::assertSame('totp', $answer['required_factor'], 'the child demands the rung past the completed email otp');
        self::assertSame(2, $answer['required_rank']);
        self::assertSame(self::BEGIN_PATH, $answer['begin_path'], 'the answer names where the child begins');
        self::assertTrue($this->store->readDemand($parentDemandId)?->superseded(), 'the parent handed the family over');
        $child = $this->store->readDemand($childDemandId);
        self::assertNotNull($child);
        self::assertTrue($child->state->isOpen(), 'the child stands open for its own completion');
        self::assertNotNull($child->requiredFactor);
        self::assertSame('totp', $child->requiredFactor->family);

        // (3) The browser begins the child: the pending token still
        // names the superseded parent, and the begin follows the family
        // to the child, so the fresh challenge binds the child demand.
        $this->enrollTotp($principal, $session);
        $childBeginRequest = $this->request('/kiwi/step-up/begin?mode=json&handler=totp', 'GET');
        $childBeginRequest->setSession($session);
        $childBegin = $allowing->begin($childBeginRequest);
        self::assertSame(200, $childBegin->getStatusCode(), (string) $childBegin->getContent());
        $childDocument = $this->document($childBegin);
        $childChallengeId = (string) $this->ticket->look((string) $childDocument['challenge'])['challengeId'];
        $childChallenge = $this->store->read($childChallengeId);
        self::assertNotNull($childChallenge);
        self::assertSame($childDemandId, $childChallenge->demandId, 'the child challenge is bound to the child demand');

        // (4) The stronger factor completes, the reassessment allows,
        // and the child demand settles authorized: the completion
        // credit books, the enrollment marker lands.
        $totpCode = TotpCode::at($this->totpSecret($principal), TotpCode::stepOf($this->now), 'sha1', 6);
        $childCompleteRequest = $this->request('/kiwi/step-up/complete?mode=json&handler=totp', 'POST', [
            TotpStepUpHandler::TICKET_FIELD => (string) $childDocument['challenge'],
            TotpStepUpHandler::CODE_FIELD => $totpCode,
        ]);
        $childCompleteRequest->setSession($session);
        $childComplete = $allowing->complete($childCompleteRequest);
        self::assertSame(200, $childComplete->getStatusCode(), (string) $childComplete->getContent());
        $verdict = $this->document($childComplete);
        self::assertSame(StepUpResultStatus::Succeeded->value, $verdict['status']);
        self::assertSame(StepUpDemandState::Authorized, $this->store->readDemand($childDemandId)?->state, 'the child settles authorized');
        self::assertCount(1, $this->reporter->reports, 'the authorized settlement books the completion credit');
        self::assertTrue($this->store->recentStepUpSuccess($principal, 900, $this->now), 'the authorized settlement books the enrollment marker');
    }

    // ── helpers ─────────────────────────────────────────────────────

    private function controller(StepUpDemandFinalizer $finalizer): StepUpController
    {
        return new StepUpController(
            new \BelConsulting\KiwiCaptchaBundle\Security\StepUp\KiwiStepUpHandlerRegistry([
                'email_otp' => $this->otp,
                'totp' => $this->totp,
            ], 'email_otp'),
            $this->identity,
            self::SCOPE,
            new FakePrincipalResolver(self::RAW_USER),
            $this->tokenStorage,
            null,
            $finalizer,
            self::BEGIN_PATH,
        );
    }

    private function finalizer(string $minimum): StepUpDemandFinalizer
    {
        return new StepUpDemandFinalizer(
            $this->store,
            new StepUpCompletionCredit($this->reporter, self::MASTER),
            null,
            $this->gateway($minimum),
            null,
            null,
            null,
            null,
            fn (): int => $this->now,
            self::MASTER,
            new StepUpFactorResolver('email_otp'),
        );
    }

    /**
     * The reassessment gateway of one phase: the scope minimum is the
     * knob the journey moves, so the fresh decision answers StepUp for
     * the parent completion and Allow for the child completion.
     */
    private function gateway(string $minimum): RiskGateway
    {
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => $minimum, 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $engine = new AdaptiveRiskEngine(new \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore(), $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);

        return new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), [self::SCOPE => 1], policy: $policy);
    }

    /**
     * The totp enrollment of the journey principal: the bootstrap gate
     * arms the first enrollment (no prior step-up exists), the sealed
     * secret is returned in base32 and kept for the completion.
     */
    private function enrollTotp(string $principal, Session $session): void
    {
        $gate = new StepUpBootstrapGate(true, $this->enrollStack, $this->identity);
        $enrollRequest = new Request();
        $enrollRequest->setSession($session);
        $this->enrollStack->push($enrollRequest);
        $gate->grant($enrollRequest, self::RAW_USER);
        $secret = $this->totp->enroll($principal, self::SESSION_ID);
        self::assertNotSame('', $secret, 'the bootstrap-armed enrollment returned the base32 secret');
        $this->enrollStack->pop();
    }

    /** The raw totp secret of the principal, unsealed for the code computation. */
    private function totpSecret(string $principal): string
    {
        $sealed = $this->store->findTotpSecret($principal);
        self::assertNotNull($sealed);
        $blob = base64_decode($sealed, true);
        self::assertIsString($blob);
        $sealKey = hash_hkdf('sha256', self::MASTER, 32, 'kiwi/v2/totp-seal|'.$principal, 'kiwicaptcha/deploy-salt/v1');
        $plain = sodium_crypto_secretbox_open(
            substr($blob, \SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            substr($blob, 0, \SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            $sealKey,
        );
        self::assertNotFalse($plain, 'the journey unsealed the enrolled secret');

        return (string) $plain;
    }

    private function pendingToken(string $demandId): StepUpPendingToken
    {
        $inner = new class implements TokenInterface {
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
                return \array_key_exists($name, $this->attributes);
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
        $pending = new StepUpPendingToken($inner, $demandId);
        $pending->setAttribute(StepUpPendingToken::SCOPE_ATTRIBUTE, self::SCOPE);

        return $pending;
    }

    private function session(): Session
    {
        $storage = new MockArraySessionStorage();
        $storage->setId(self::SESSION_ID);
        $session = new Session($storage);
        $session->start();

        return $session;
    }

    private function request(string $uri, string $method, array $body = []): Request
    {
        $server = ['REMOTE_ADDR' => '203.0.113.10'];

        return Request::create('https://app.example.com'.$uri, $method, $body, [], [], $server);
    }

    /** @return array<string, mixed> */
    private function document(\Symfony\Component\HttpFoundation\Response $response): array
    {
        $decoded = json_decode((string) $response->getContent(), true);
        self::assertIsArray($decoded, 'the journey speaks json on every step');

        return $decoded;
    }
}
