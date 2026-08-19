<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Risk\ArrayChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceRateLimiter;
use BelConsulting\KiwiCaptchaBundle\Security\OutstandingChallenges;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyMetadataStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadataStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\RiskStateStoreInterface;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Storage\ReplicaWaitException;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Validator\ConstraintValidatorFactory;
use Symfony\Component\Validator\ConstraintViolationListInterface;
use Symfony\Component\Validator\Validation;

/**
 * Selective chained challenges (risk.chaining): a valid stage-1 proof
 * whose post-solve reassessment demands a stronger stage returns a signed
 * one-shot chain ticket (CHAIN_REQUIRED violation, {{ chain_ticket }}
 * parameter) binding the REQUIRED action, the stage-1 request binding and
 * the chain depth; the stage-2 challenge request validates the ticket
 * FIRST (before any admission counter), reserves the one-shot chain state,
 * issues at least the promised strength, and consumes the chain exactly
 * once — a replayed/invalid/expired/wrong-scope/wrong-binding/wrong-depth
 * ticket is refused and a ticket-bearing request is NEVER downgraded to an
 * unchained issuance. StepUp is terminal (never a ticket), the chain ends
 * at stage 2, and a failed issuance releases the reservation (the ticket
 * stays reusable). Also covers the form-submission honeypot evidence path
 * (bound to the verified nonce) and the trusted-edge TLS header path
 * (bound to the direct peer).
 */
final class ChainedChallengeTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    /** The post-solve vector that demands Argon32 (score 813). */
    private const ARGON32_VECTOR = ['source_fast' => 900, 'subnet_fast' => 1000, 'issue_debt' => 1000, 'replay' => 699, 'network_risk' => 890];

    /** The post-solve vector that demands Argon64 (score 908, no deny reason). */
    private const ARGON64_VECTOR = ['source_fast' => 900, 'subnet_fast' => 1000, 'issue_debt' => 1000, 'replay' => 695, 'network_risk' => 895, 'action_failure' => 800];

    /** The post-solve vector that demands StepUp (score 933, no deny reason). */
    private const STEP_UP_VECTOR = ['source_fast' => 900, 'subnet_fast' => 1000, 'issue_debt' => 1000, 'replay' => 699, 'network_risk' => 890, 'action_failure' => 1000];

    private function issuer(StorageInterface $storage): Issuer
    {
        return new Issuer(new Config(
            secretKey: self::SECRET,
            algorithm: PoWAlgorithm::Sha256,
            targetBits: 8, // fast solve for tests
            ttlSecs: 120,
        ), $storage);
    }

    /**
     * A risk stack (gateway + engine + fake store) for ONE 'login' scope;
     * the store's SignalVector drives the assessments.
     *
     * @return array{gateway: RiskGateway, store: FakeRiskStateStore}
     */
    private function riskStack(?SignalVector $vector = null, ?RiskProfileResolver $resolver = null): array
    {
        return $this->riskStackWithScopes(['login' => 1], $vector, $resolver);
    }

    /**
     * @param array<string, int> $scopes
     *
     * @return array{gateway: RiskGateway, store: FakeRiskStateStore}
     */
    private function riskStackWithScopes(array $scopes, ?SignalVector $vector = null, ?RiskProfileResolver $resolver = null): array
    {
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policyConfig = [
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [],
        ];
        foreach ($scopes as $name => $id) {
            $policyConfig['scopes'][$id] = ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'];
        }
        $policy = RiskPolicy::fromConfig($policyConfig);
        $store = new FakeRiskStateStore($vector);
        $engine = new AdaptiveRiskEngine($store, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);
        $gateway = new RiskGateway($engine, $classifier, $resolver ?? new RiskProfileResolver(PoWAlgorithm::Sha256, 8), $scopes, policy: $policy);

        return ['gateway' => $gateway, 'store' => $store];
    }

    private function chainService(ArrayChainedChallengeStateStore $store, ?\Closure $now = null): ChainedChallengeTicketService
    {
        return new ChainedChallengeTicketService($store, self::SECRET, 300, $now);
    }

    private function solveToken(array $challenge): string
    {
        $saltBytes = base64_decode($challenge['salt'], true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge['prefix'].$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge['targetBits']);
        --$counter;

        return \KiwiCaptcha\SolutionToken::create($challenge['nonce'], $counter, 5000, [])->encode();
    }

    /**
     * Solve an ARGON2id challenge in pure PHP (libsodium): the same
     * password/salt construction the core verifier re-derives.
     */
    private function solveArgon(array $challenge): string
    {
        $saltBytes = base64_decode($challenge['salt'], true);
        $counter = 0;
        do {
            $hash = sodium_crypto_pwhash(
                32,
                $challenge['prefix'].$counter,
                $saltBytes,
                $challenge['t'],
                $challenge['mKib'] * 1024,
                SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
            );
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge['targetBits']);
        --$counter;

        return \KiwiCaptcha\SolutionToken::create($challenge['nonce'], $counter, 5000, [])->encode();
    }

    /** Solve whichever algorithm the challenge carries. */
    private function solveChallenge(array $challenge): string
    {
        return ($challenge['algorithm'] ?? 'sha256') === 'argon2id'
            ? $this->solveArgon($challenge)
            : $this->solveToken($challenge);
    }

    /**
     * Validate a token through the FULL Symfony pipeline with a
     * chaining-enabled validator.
     *
     * @return array{0: ConstraintViolationListInterface, 1: KiwiCaptchaValidator}
     */
    private function validateChained(string $token, RequestStack $stack, RiskGateway $gateway, ArrayStorage $storage, ?ArrayChainedChallengeStateStore $chainStore = null, ?SiteVerifyMetadataStore $metadataStore = null, ?\Closure $now = null): array
    {
        $validator = new KiwiCaptchaValidator(
            new Verifier($storage),
            $stack,
            self::SECRET,
            false,
            $gateway,
            new ContinuityCookie(),
            null,
            null,
            $storage,
            null,
            null,
            null,
            $this->chainService($chainStore ?? new ArrayChainedChallengeStateStore(), $now),
            1,
            $metadataStore,
        );
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        return [$engine->validate($dto), $validator];
    }

    private function challengeRequest(string $body, array $headers = [], array $cookies = []): Request
    {
        return JsonRequest::create(
            '/kiwi-captcha/challenge',
            'POST',
            [],
            $cookies,
            [],
            array_merge(['REMOTE_ADDR' => '198.51.100.7'], $headers),
            $body,
        );
    }

    /**
     * A stage-1 solved token: an ordinary unchained issuance + solved
     * challenge.
     */
    private function solvedStage1(ArrayStorage $storage, ?string $requestBinding = null): array
    {
        $issuer = $this->issuer($storage);
        $challenge = $issuer->issue('login', '198.51.100.7', $requestBinding)->toArray();
        usleep(($challenge['minDurationMs'] + 10) * 1000);
        $token = $this->solveToken($challenge);

        return ['token' => $token, 'nonce' => \KiwiCaptcha\SolutionToken::decode($token)->nonce];
    }

    /** The chain state records of an in-memory store (reflection). */
    private function chainRecords(ArrayChainedChallengeStateStore $store): array
    {
        return (new \ReflectionObject($store))->getProperty('records')->getValue($store);
    }

    // ── Chained issuance flow ──────────────────────────────────────────

    public function testStage1VerifyIssuesChainTicketWhenReassessmentDemandsStrongerStage(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $challenge = $this->issuer($storage)->issue('login', '198.51.100.7')->toArray();
        usleep(($challenge['minDurationMs'] + 10) * 1000);
        $token = $this->solveToken($challenge);

        // The reassessment (score 813) demands Argon32 — above the
        // first-stage Sha16 class.
        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));

        [$violations] = $this->validateChained($token, $stack, $risk['gateway'], $storage, $chainStore);

        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $ticket = $violations[0]->getParameters()['{{ chain_ticket }}'] ?? null;
        self::assertIsString($ticket);
        self::assertNotEmpty($ticket);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9._:-]{1,256}$/D', $ticket);

        // The ticket signs the REQUIRED action, the chain depth (2) and
        // the stage-1 binding (null — the stage-1 challenge was unbound).
        $payload = $this->chainService($chainStore)->verify($ticket);
        self::assertIsArray($payload);
        self::assertSame('argon32', $payload['requiredAction'], 'the ticket must bind the reassessed required action');
        self::assertSame(2, $payload['chainDepth'], 'the chain is a depth-2 selective extension');
        self::assertNull($payload['requestBinding'], 'an unbound stage-1 challenge signs a null binding');
    }

    public function testChainTicketBindsTheStage1RequestBinding(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $stage1 = $this->solvedStage1($storage, 'txn-alpha');

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [
            'kiwi__token' => $stage1['token'],
            'kiwi_request_binding' => 'txn-alpha',
        ], [], [], ['REMOTE_ADDR' => '198.51.100.7']));

        [$violations] = $this->validateChained($stage1['token'], $stack, $risk['gateway'], $storage, $chainStore);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $ticket = $violations[0]->getParameters()['{{ chain_ticket }}'] ?? null;
        self::assertIsString($ticket);

        $payload = $this->chainService($chainStore)->verify($ticket);
        self::assertIsArray($payload);
        self::assertSame('txn-alpha', $payload['requestBinding'], 'the ticket must sign the stage-1 challenge\'s request binding');
    }

    public function testChainTicketReserveConsumeReleaseStateMachine(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $nonce = bin2hex(random_bytes(16));
        $ticket = $service->issue($nonce, 'login', 1, requiredAction: 'argon32');
        self::assertIsString($ticket);

        $payload = $service->verify($ticket);
        self::assertIsArray($payload);
        self::assertSame($nonce, $payload['stage1Nonce'], 'the chain ticket signs the ACTUAL verified stage-1 nonce');
        self::assertSame('login', $payload['scope']);
        self::assertSame(1, $payload['policyVersion']);
        self::assertSame($payload['issuedAt'] + 300, $payload['expiresAt']);
        self::assertSame('argon32', $payload['requiredAction']);
        self::assertNull($payload['requestBinding']);
        self::assertSame(2, $payload['chainDepth']);

        // available -> reserved (the reservation is the issuance claim).
        self::assertSame('available', $store->reserve((string) $payload['chainId'], 300), 'the first reserve transitions available -> reserved');
        self::assertSame('reserved', $store->reserve((string) $payload['chainId'], 300), 'reserve is idempotent for the same chain id (retry)');

        // The one-shot completion consumes exactly once.
        $consumed = $service->consume((string) $payload['chainId'], $payload);
        self::assertIsArray($consumed);
        self::assertSame($nonce, $consumed['stage1Nonce']);
        self::assertSame('argon32', $consumed['requiredAction']);
        self::assertSame('consumed', $store->reserve((string) $payload['chainId'], 300), 'a replayed ticket lands on the consumed state');
        self::assertNull($service->consume((string) $payload['chainId'], $payload), 'a chain ticket is one-shot: the second consume must be refused');
        self::assertNull($service->reserve($ticket), 'a consumed chain never gates a second issuance');
    }

    public function testChainTicketReleaseUndoesTheReservation(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $ticket = $service->issue(bin2hex(random_bytes(16)), 'login', 1, requiredAction: 'argon32');
        self::assertIsString($ticket);

        self::assertSame('available', $store->reserve((string) $service->verify($ticket)['chainId'], 300));
        $service->release((string) $service->verify($ticket)['chainId']);
        self::assertSame('available', $store->reserve((string) $service->verify($ticket)['chainId'], 300), 'release returns the chain to the available state — the ticket stays reusable');
    }

    public function testStage2IssuanceWithTicketSucceedsAndSecondIssuanceIsRefused(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $issuer = $this->issuer($storage);

        // Stage-1 proof: the ordinary unchained issuance + a solved token.
        $stage1 = $issuer->issue('login', '198.51.100.7')->toArray();
        usleep(($stage1['minDurationMs'] + 10) * 1000);
        $token = $this->solveToken($stage1);
        $stage1Nonce = \KiwiCaptcha\SolutionToken::decode($token)->nonce;

        // The chain: ticket for the verified stage-1 nonce.
        $ticket = $chainService->issue($stage1Nonce, 'login', 1, requiredAction: 'argon32');
        self::assertIsString($ticket);

        // Stage-2 issuance with the ticket: the required action is the
        // floor — the vector keeps demanding Argon32, so the issued
        // challenge is the stronger stage.
        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = new ChallengeController(
            $issuer,
            null,
            true,
            $risk['gateway'],
            new ContinuityCookie(),
            chainTickets: $chainService,
            policyVersion: 1,
        );
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), sprintf('stage-2 issuance must accept the valid ticket: %s', (string) $response->getContent()));
        $stage2 = json_decode((string) $response->getContent(), true);
        self::assertSame('argon2id', $stage2['algorithm'], 'the stage-2 issuance follows the ordinary risk profile selection (Argon32)');
        self::assertSame(4, $stage2['targetBits'], 'the issued stage-2 profile is the Argon32 rung of the fixed-envelope ladder');
        self::assertNotSame($stage1Nonce, $stage2['nonce'], 'the ticket holder can never re-run the same stage');

        // A SECOND issuance with the SAME (now consumed) ticket is refused.
        $second = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $second->getStatusCode());
        self::assertStringContainsString('INVALID_METADATA', (string) $second->getContent());
    }

    public function testTicketRequiredActionIsTheStage2FloorAgainstTransientRiskDecay(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $stage1 = $this->solvedStage1($storage);

        // The ticket demands Argon32 — but the CURRENT pre-issue
        // assessment (replay 690 -> score 320) only says Sha18. The
        // issued stage must be the STRONGER of the two: Argon32.
        $ticket = $chainService->issue($stage1['nonce'], 'login', 1, requiredAction: 'argon32');
        self::assertIsString($ticket);

        $risk = $this->riskStack(SignalVector::fromArray(['replay' => 690]));
        $controller = new ChallengeController(
            $this->issuer($storage),
            null,
            true,
            $risk['gateway'],
            new ContinuityCookie(),
            chainTickets: $chainService,
            policyVersion: 1,
        );
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), sprintf('the ticket must still be honored: %s', (string) $response->getContent()));
        $stage2 = json_decode((string) $response->getContent(), true);
        self::assertSame('argon2id', $stage2['algorithm'], 'the required Argon32 stage is enforced, not the transient Sha18 assessment');
        self::assertSame(4, $stage2['targetBits']);
    }

    public function testStepUpPostSolveDecisionNeverBecomesAChainTicket(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $stage1 = $this->solvedStage1($storage);

        // The reassessment demands StepUp (score 933): the violation is
        // the TERMINAL application step-up — NO chain ticket can ever
        // convert it into ordinary PoW.
        $risk = $this->riskStack(SignalVector::fromArray(self::STEP_UP_VECTOR));
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));

        [$violations] = $this->validateChained($stage1['token'], $stack, $risk['gateway'], $storage, $chainStore);

        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations[0]->getCode(), 'a StepUp post-solve decision stays the terminal step-up violation');
        self::assertArrayNotHasKey('{{ chain_ticket }}', $violations[0]->getParameters(), 'StepUp must NEVER produce a chain ticket');
        self::assertSame([], $this->chainRecords($chainStore), 'a StepUp decision creates no chain state at all');
    }

    public function testTicketScopeAndPolicyEpochAreBound(): void
    {
        $storage = new ArrayStorage();
        $issuer = $this->issuer($storage);
        $risk = $this->riskStack();

        // Wrong scope: a 'login' ticket presented for 'signup' is refused
        // (the policy covers both scopes so the refusal comes from the
        // chain gate, not the unknown-scope policy).
        $chainService = $this->chainService(new ArrayChainedChallengeStateStore());
        $ticket = $chainService->issue(bin2hex(random_bytes(16)), 'login', 1, requiredAction: 'argon32');
        $risk2 = $this->riskStackWithScopes(['login' => 1, 'signup' => 2]);
        $controller = new ChallengeController($issuer, null, true, $risk2['gateway'], new ContinuityCookie(), chainTickets: $chainService, policyVersion: 1);
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'signup', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode(), 'a chain ticket is scope-bound: a different scope must be refused');

        // Wrong policy epoch: the controller expects 2, the ticket says 1.
        $chainService2 = $this->chainService(new ArrayChainedChallengeStateStore());
        $ticket2 = $chainService2->issue(bin2hex(random_bytes(16)), 'login', 1, requiredAction: 'argon32');
        $controller2 = new ChallengeController($issuer, null, true, $risk['gateway'], new ContinuityCookie(), chainTickets: $chainService2, policyVersion: 2);
        $response = $controller2->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket2], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode(), 'a chain ticket is bound to the policy epoch it was issued under');
    }

    public function testTicketBindingIdentityIsEnforcedExactly(): void
    {
        $storage = new ArrayStorage();
        $issuer = $this->issuer($storage);
        $risk = $this->riskStack();
        $chainService = $this->chainService(new ArrayChainedChallengeStateStore());
        $bound = $chainService->issue(bin2hex(random_bytes(16)), 'login', 1, requiredAction: 'argon32', requestBinding: 'txn-alpha');
        self::assertIsString($bound);
        $unbound = $chainService->issue(bin2hex(random_bytes(16)), 'login', 1, requiredAction: 'argon32');
        self::assertIsString($unbound);
        $controller = new ChallengeController($issuer, null, true, $risk['gateway'], new ContinuityCookie(), chainTickets: $chainService, policyVersion: 1);

        // A ticket WITH a binding presented WITH a DIFFERENT binding.
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $bound, 'request_binding' => 'txn-beta'], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode(), 'a bound ticket with a different request binding must be refused');

        // A ticket WITH a binding presented WITHOUT one.
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $bound], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode(), 'a bound ticket presented without its request binding must be refused');

        // A ticket WITHOUT a binding presented WITH a request binding.
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $unbound, 'request_binding' => 'txn-x'], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode(), 'an unbound ticket presented with a request binding must be refused');

        // Control: the EXACT identity match succeeds.
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $bound, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), 'the exact binding identity match must be accepted');
    }

    public function testTicketChainDepthMustBeTwo(): void
    {
        $storage = new ArrayStorage();
        $issuer = $this->issuer($storage);
        $risk = $this->riskStack();
        $chainService = $this->chainService(new ArrayChainedChallengeStateStore());

        // A depth-3 ticket signed with the same secret: the chain is a
        // selective extension of depth 2 — a third stage can never exist.
        $depth3 = $this->craftTicket(bin2hex(random_bytes(16)), 'login', 1, 'argon32', null, 3);
        $controller = new ChallengeController($issuer, null, true, $risk['gateway'], new ContinuityCookie(), chainTickets: $chainService, policyVersion: 1);
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $depth3], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode(), 'a ticket with chain depth != 2 must be refused');
        self::assertStringContainsString('INVALID_METADATA', (string) $response->getContent());

        // The depth-2 ticket is the only accepted shape.
        $depth2 = $chainService->issue(bin2hex(random_bytes(16)), 'login', 1, requiredAction: 'argon32');
        self::assertIsString($depth2);
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $depth2], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode());
    }

    /**
     * Craft a signed ticket with an arbitrary payload (test-only): the
     * same compact JSON-array body + raw-digest base64url HMAC the ticket
     * service signs.
     */
    private function craftTicket(string $nonce, string $scope, int $policyVersion, string $requiredAction, ?string $requestBinding, int $chainDepth): string
    {
        $chainId = rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');
        $now = time();
        $body = (string) json_encode([$chainId, $nonce, $scope, $policyVersion, $now, $now + 300, $requestBinding, $requiredAction, $chainDepth], JSON_THROW_ON_ERROR);
        $encoded = rtrim(strtr(base64_encode($body), '+/', '-_'), '=');
        $sig = rtrim(strtr(base64_encode(hash_hmac('sha256', $encoded, self::SECRET, true)), '+/', '-_'), '=');

        return $encoded.'.'.$sig;
    }

    public function testStage2VerifiedChallengeCannotOpenThirdStage(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $metaStore = new ArraySiteVerifyMetadataStore();
        $chainService = $this->chainService($chainStore);
        $issuer = $this->issuer($storage);

        // The fixed-envelope Argon ladder is flattened to target bits 1 so
        // the stage-2 Argon challenge solves fast in the test (the
        // strength ladder itself is covered elsewhere).
        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR), new RiskProfileResolver(PoWAlgorithm::Sha256, 8, 16384, [1, 1, 1]));

        // Stage 1: solve + CHAIN_REQUIRED ticket (the reassessment
        // demands Argon32).
        $stage1 = $this->solvedStage1($storage);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations] = $this->validateChained($stage1['token'], $stack, $risk['gateway'], $storage, $chainStore, $metaStore);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $ticket = $violations[0]->getParameters()['{{ chain_ticket }}'];
        self::assertIsString($ticket);

        // Stage 2: the ticket issues the Argon32 stage; the controller
        // STAMPS the chain marker into the challenge's stored cdata.
        $controller = new ChallengeController(
            $issuer,
            null,
            true,
            $risk['gateway'],
            new ContinuityCookie(),
            metadataStore: $metaStore,
            chainTickets: $chainService,
            policyVersion: 1,
        );
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode());
        $stage2 = json_decode((string) $response->getContent(), true);
        self::assertSame('argon2id', $stage2['algorithm']);

        // The marker is server-stamped into the metadata sidecar.
        $metadata = $metaStore->find($stage2['nonce']);
        self::assertNotNull($metadata);
        self::assertStringStartsWith(ChallengeController::CHAIN_CDATA_PREFIX, (string) $metadata->cdata, 'the stage-2 challenge must carry the server-stamped chain marker');

        // Stage 2 solve: the reassessment (Argon64 — stronger than the
        // stage-2 profile) would demand a THIRD stage — the chain marker
        // refuses it: the verification passes with NO ticket.
        usleep(($stage2['minDurationMs'] + 10) * 1000);
        $stage2Token = $this->solveChallenge($stage2);
        $risk['store']->setVector(SignalVector::fromArray(self::ARGON64_VECTOR));
        $stack2 = new RequestStack();
        $stack2->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations2] = $this->validateChained($stage2Token, $stack2, $risk['gateway'], $storage, $chainStore, $metaStore);

        self::assertCount(0, $violations2, 'a stage-2 verified challenge passes — the chain ends at stage 2');
        $records = array_values($this->chainRecords($chainStore));
        self::assertCount(1, $records, 'no third-stage chain state may ever be created');
        self::assertSame('consumed', $records[0]['state'], 'the only remaining record is the consumed stage-1 chain');
    }

    public function testIssuanceFailureAfterReservationReleasesTheTicket(): void
    {
        $storage = new FailingMintStorage(new ArrayStorage());
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $stage1 = $this->solvedStage1(new ArrayStorage());

        $ticket = $chainService->issue($stage1['nonce'], 'login', 1, requiredAction: 'argon32');
        self::assertIsString($ticket);

        // The first attempt fails AT THE MINT STEP (the replica-wait
        // durability barrier), AFTER the chain was reserved.
        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = new ChallengeController(
            $this->issuer($storage),
            null,
            true,
            $risk['gateway'],
            new ContinuityCookie(),
            storage: $storage,
            chainTickets: $chainService,
            policyVersion: 1,
        );
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(503, $response->getStatusCode(), 'a mint-step failure after the reservation must fail closed with the retryable 503');

        // The failed issuance RELEASED the reservation: the SAME ticket
        // succeeds on retry — the chain is not burned.
        $storage->mintFails = false;
        $retry = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $retry->getStatusCode(), sprintf('the same ticket must succeed on retry after a released failure: %s', (string) $retry->getContent()));
    }

    public function testInvalidTicketsDoNotTouchOutstandingCounters(): void
    {
        $storage = new ArrayStorage();
        $client = new FakePredisClient();
        $outstanding = new OutstandingChallenges($client, '{kiwi:chain-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $issuer = $this->issuer($storage);
        $risk = $this->riskStack();
        $controller = new ChallengeController(
            $issuer,
            null,
            true,
            $risk['gateway'],
            new ContinuityCookie(),
            outstanding: $outstanding,
            storage: $storage,
            challengeTtlSecs: 120,
            chainTickets: $chainService,
            policyVersion: 1,
        );
        $sourceKey = '{kiwi:chain-test}:outstanding:'.hash_hmac('sha256', Issuer::canonicalIpFamily('198.51.100.7'), RiskKeys::fromMaster(self::SECRET)->event);

        // Forged signature.
        $forger = new ChainedChallengeTicketService(new ArrayChainedChallengeStateStore(), str_repeat('f', 32), 300);
        $forged = $forger->issue(bin2hex(random_bytes(16)), 'login', 1, requiredAction: 'argon32');
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $forged], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode());

        // Wrong scope.
        $wrongScope = $chainService->issue(bin2hex(random_bytes(16)), 'login', 1, requiredAction: 'argon32');
        $risk2 = $this->riskStackWithScopes(['login' => 1, 'signup' => 2]);
        $controller2 = new ChallengeController(
            $issuer,
            null,
            true,
            $risk2['gateway'],
            new ContinuityCookie(),
            outstanding: $outstanding,
            storage: $storage,
            challengeTtlSecs: 120,
            chainTickets: $chainService,
            policyVersion: 1,
        );
        $response = $controller2->challenge($this->challengeRequest(json_encode(['scope' => 'signup', 'chain_ticket' => $wrongScope], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode());

        // A CONSUMED ticket (valid signature, chain already spent).
        $consumed = $chainService->issue(bin2hex(random_bytes(16)), 'login', 1, requiredAction: 'argon32');
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $consumed], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), 'the control ticket must issue first');
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $consumed], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode(), 'the replayed (consumed) ticket must be refused');

        // NONE of the invalid tickets moved the outstanding counters:
        // validation (and the consumed-state check) run BEFORE any
        // admission counter is touched.
        self::assertSame(1, $client->counters[$sourceKey] ?? 0, 'only the ONE valid issuance may move the outstanding counter');
    }

    public function testRateLimitedStage2RequestLeavesTheTicketReusable(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $issuer = $this->issuer($storage);
        $risk = $this->riskStack();
        $stage1 = $this->solvedStage1($storage);
        $ticket = $chainService->issue($stage1['nonce'], 'login', 1, requiredAction: 'argon32');
        self::assertIsString($ticket);

        // A saturated per-client rate limiter (cap 1) refuses the
        // ticket-bearing request with 429 — the reservation is released,
        // the ticket stays usable. The control request saturates the
        // single-slot window first.
        $client = new FakePredisClient();
        $limiter = new IssuanceRateLimiter(1, 60, null, null, 'pepper', $client, 500, 'chain-test-ns');
        $limited = new ChallengeController(
            $issuer,
            rateLimiter: $limiter,
            sameOriginOnly: true,
            risk: $risk['gateway'],
            continuityCookie: new ContinuityCookie(),
            storage: $storage,
            challengeTtlSecs: 120,
            chainTickets: $chainService,
            policyVersion: 1,
        );
        $control = $limited->challenge($this->challengeRequest('{"scope":"login"}'));
        self::assertSame(200, $control->getStatusCode(), 'the control request must saturate the limiter window');
        $response = $limited->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(429, $response->getStatusCode(), 'the saturated limiter must refuse the stage-2 request');

        // The SAME ticket succeeds on a controller without the limiter —
        // the refused admission never burned it.
        $open = new ChallengeController(
            $issuer,
            null,
            true,
            $risk['gateway'],
            new ContinuityCookie(),
            storage: $storage,
            challengeTtlSecs: 120,
            chainTickets: $chainService,
            policyVersion: 1,
        );
        $retry = $open->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $retry->getStatusCode(), sprintf('a rate-limited stage-2 request must leave the ticket reusable: %s', (string) $retry->getContent()));
    }

    public function testTicketBearingRequestIsRefusedWhenChainingIsDisabled(): void
    {
        $storage = new ArrayStorage();
        $issuer = $this->issuer($storage);
        $risk = $this->riskStack();
        $controller = new ChallengeController($issuer, null, true, $risk['gateway'], new ContinuityCookie());

        // A syntactically valid ticket shape (never issued by this
        // deployment — chaining is disabled, so no service is wired).
        $ticket = 'AAAA.BBBB';
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode());
        self::assertStringContainsString('INVALID_METADATA', (string) $response->getContent());
    }

    public function testNormalIssuanceWithoutTicketIsUnchanged(): void
    {
        $storage = new ArrayStorage();
        $issuer = $this->issuer($storage);
        $risk = $this->riskStack();
        $chainService = $this->chainService(new ArrayChainedChallengeStateStore());
        $controller = new ChallengeController($issuer, null, true, $risk['gateway'], new ContinuityCookie(), chainTickets: $chainService, policyVersion: 1);

        $response = $controller->challenge($this->challengeRequest('{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode(), 'issuance without a ticket is unchanged by chaining');
    }

    // ── Ticket format (raw-digest signature, wire bound, expiry) ───────

    public function testTicketSignatureIsTheRawDigestBase64url(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $ticket = $service->issue(bin2hex(random_bytes(16)), 'login', 1, requiredAction: 'argon32');
        self::assertIsString($ticket);

        $parts = explode('.', $ticket);
        self::assertCount(2, $parts);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/D', $parts[1], 'the signature is the RAW 32-byte HMAC digest, base64url (43 chars — not the 64-char hex digest)');
        self::assertSame($parts[0].'.'.$parts[1], $ticket);
    }

    public function testLongScopeTicketNowFitsTheWireBound(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        // 45 chars of scope: with the superseded hex-digest signature the
        // same payload produced a 265-char ticket (over the 256 bound);
        // the raw-digest signature (43 chars) keeps it inside the bound.
        $scope = 'sc-'.str_repeat('x', 42);
        $ticket = $service->issue(bin2hex(random_bytes(16)), $scope, 1, requiredAction: 'argon32');
        self::assertIsString($ticket);
        self::assertLessThanOrEqual(256, \strlen($ticket), 'the long-scope ticket must fit the accepted wire bound');
        self::assertIsArray($service->verify($ticket));
        self::assertSame($scope, $service->verify($ticket)['scope']);
    }

    public function testOverlongTicketCreatesNoChainState(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $ticket = $service->issue(bin2hex(random_bytes(16)), str_repeat('x', 100), 1, requiredAction: 'argon32');
        self::assertNull($ticket, 'an over-length ticket is not offered');
        self::assertSame([], $this->chainRecords($store), 'an over-length ticket must create NO server-held chain state (no unreachable record)');
    }

    public function testTicketExpiringExactlyNowIsExpired(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $issuing = new ChainedChallengeTicketService($store, self::SECRET, 300, static fn (): int => 1000);
        $ticket = $issuing->issue(bin2hex(random_bytes(16)), 'login', 1, requiredAction: 'argon32');
        self::assertIsString($ticket);

        // expiresAt == 1300; a verify at exactly 1300 must refuse (<= now).
        $boundary = new ChainedChallengeTicketService($store, self::SECRET, 300, static fn (): int => 1300);
        self::assertNull($boundary->verify($ticket), 'a ticket expiring exactly now is expired');
        $justBefore = new ChainedChallengeTicketService($store, self::SECRET, 300, static fn (): int => 1299);
        self::assertIsArray($justBefore->verify($ticket), 'a ticket one second before expiry is still valid');
    }

    // ── Form-submission honeypot (bound to the verified nonce) ─────────

    public function testExpectedDecoyNameDerivationMatchesTheControllerEmission(): void
    {
        $storage = new ArrayStorage();
        $issuer = $this->issuer($storage);
        $risk = $this->riskStack();
        $controller = new ChallengeController($issuer, null, true, $risk['gateway'], new ContinuityCookie());

        $response = $controller->challenge($this->challengeRequest('{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode());
        $data = json_decode((string) $response->getContent(), true);

        self::assertSame(
            'decoy_'.substr(hash('sha256', $data['nonce']), 0, 8),
            $data['decoy_field'],
            'the validator\'s expected decoy name must be the EXACT same derivation the controller emits',
        );
    }

    public function testFilledExactDecoyFieldRaisesThePostSolveScore(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();

        // Without the decoy the post-solve assessment is neutral (score
        // 100, allow) — the valid solve passes with NO chain ticket.
        // (A FRESH risk stack per validation: the engine's per-scope
        // action hysteresis holds one-band steps, so each assessment
        // starts from a clean band.)
        $plain = $this->solvedStage1($storage);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', ['kiwi__token' => $plain['token']], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations] = $this->validateChained($plain['token'], $stack, $this->riskStack()['gateway'], $storage, $chainStore);
        self::assertCount(0, $violations, 'without honeypot evidence the neutral post-solve assessment passes');

        // With the EXACT expected decoy field filled, the honeypot signal
        // rides the post-solve v2 assessment (score 100 + 200 = 300 ->
        // Sha18, stronger than the stage-1 Sha16): the score ROSE and the
        // chain opens.
        $marked = $this->solvedStage1($storage);
        $expected = 'decoy_'.substr(hash('sha256', $marked['nonce']), 0, 8);
        $stack2 = new RequestStack();
        $stack2->push(Request::create('/', 'POST', ['kiwi__token' => $marked['token'], $expected => 'bot@example.com'], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $risk2 = $this->riskStack();
        [$violations2] = $this->validateChained($marked['token'], $stack2, $risk2['gateway'], $storage, $chainStore);

        self::assertCount(1, $violations2, 'the filled exact decoy field must raise the post-solve score into a stronger action');
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations2[0]->getCode(), 'the raised score demands the stronger stage (the chain opens)');

        // The evidence event kind is recorded at form-submission time.
        $events = array_map(static fn ($o): RiskEventKind => $o->event, $risk2['store']->observations);
        self::assertContains(RiskEventKind::DecoyFieldSubmitted, $events);
    }

    public function testFilledDecoyFieldRecordsEvidenceAndRaisesThePostSolveScore(): void
    {
        $storage = new ArrayStorage();
        $issuer = $this->issuer($storage);
        $challenge = $issuer->issue('login', '198.51.100.7')->toArray();
        usleep(($challenge['minDurationMs'] + 10) * 1000);
        $token = $this->solveToken($challenge);
        $expected = 'decoy_'.substr(hash('sha256', \KiwiCaptcha\SolutionToken::decode($token)->nonce), 0, 8);

        $risk = $this->riskStack();
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [
            'kiwi__token' => $token,
            $expected => 'bot@example.com',
            'username' => 'alice',
        ], [], [], ['REMOTE_ADDR' => '198.51.100.7']));

        [$violations] = $this->validateChained($token, $stack, $risk['gateway'], $storage);

        // The exact decoy field is evidence at form-submission time: the
        // DecoyFieldSubmitted event kind is recorded AND the post-solve v2
        // score rises (the chain opens — never a hard rejection gate).
        self::assertCount(1, $violations, 'the filled exact decoy field must raise the post-solve score');
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $events = array_map(static fn ($o): RiskEventKind => $o->event, $risk['store']->observations);
        self::assertContains(RiskEventKind::DecoyFieldSubmitted, $events, 'the form submission must record DecoyFieldSubmitted evidence');
    }

    public function testEmptyDecoyFieldFeedsNoHoneypotEvidence(): void
    {
        $storage = new ArrayStorage();
        $issuer = $this->issuer($storage);
        $challenge = $issuer->issue('login', '198.51.100.7')->toArray();
        usleep(($challenge['minDurationMs'] + 10) * 1000);
        $token = $this->solveToken($challenge);
        $expected = 'decoy_'.substr(hash('sha256', \KiwiCaptcha\SolutionToken::decode($token)->nonce), 0, 8);

        $risk = $this->riskStack();
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [
            'kiwi__token' => $token,
            $expected => '',
        ], [], [], ['REMOTE_ADDR' => '198.51.100.7']));

        [$violations] = $this->validateChained($token, $stack, $risk['gateway'], $storage);
        self::assertCount(0, $violations);
        $events = array_map(static fn ($o): RiskEventKind => $o->event, $risk['store']->observations);
        self::assertNotContains(RiskEventKind::DecoyFieldSubmitted, $events, 'an EMPTY decoy field is no evidence');
    }

    public function testWrongOrMalformedDecoyFieldNamesProduceNoEvidence(): void
    {
        $storage = new ArrayStorage();
        $issuer = $this->issuer($storage);
        $challenge = $issuer->issue('login', '198.51.100.7')->toArray();
        usleep(($challenge['minDurationMs'] + 10) * 1000);
        $token = $this->solveToken($challenge);

        $risk = $this->riskStack();
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [
            'kiwi__token' => $token,
            // A VALID-SYNTAX decoy_<8 hex> name that is NOT the expected
            // nonce-derived name — the decoy is server-issued and
            // nonce-bound, so a mismatched name is not this challenge's
            // decoy: no evidence, no score change.
            'decoy_12345678' => 'filled',
            'decoy_nothex' => 'filled',      // not decoy_<8 hex>
            'decoy_12345678_' => 'filled',   // trailing char
            'decoy_123456789' => 'filled',   // 9 hex chars
        ], [], [], ['REMOTE_ADDR' => '198.51.100.7']));

        [$violations] = $this->validateChained($token, $stack, $risk['gateway'], $storage);
        self::assertCount(0, $violations);
        $events = array_map(static fn ($o): RiskEventKind => $o->event, $risk['store']->observations);
        self::assertNotContains(RiskEventKind::DecoyFieldSubmitted, $events, 'only the EXACT expected decoy name is honeypot evidence — any other field is ignored');
    }

    // ── Trusted-edge TLS header (bound to the direct peer) ─────────────

    public function testConfiguredTlsHeaderFlowsIntoTheRiskV2Context(): void
    {
        $storage = new ArrayStorage();
        $issuer = $this->issuer($storage);
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $store = new TlsRecordingRiskStateStore();
        $engine = new AdaptiveRiskEngine($store, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], policy: $policy);

        $controller = new ChallengeController($issuer, null, true, $gateway, new ContinuityCookie(), trustedTlsHeader: 'X-Tls-Class', trustedTlsProxies: ['198.51.100.0/24']);
        $session = str_repeat('ab', 16);
        $response = $controller->challenge($this->challengeRequest(
            '{"scope":"login","client_context":"v1,t0,lde,z2"}',
            ['HTTP_X_TLS_CLASS' => 'tls13-http2'],
            ['__Host-kiwi-session' => $session],
        ));

        self::assertSame(200, $response->getStatusCode());
        self::assertNotEmpty($store->tlsTags, 'the configured header must flow into the risk-v2 client-context');
        self::assertSame('tls13-http2', $store->tlsTags[array_key_first($store->tlsTags)]);
    }

    public function testTlsHeaderIsIgnoredWhenTheDirectPeerIsUntrusted(): void
    {
        $storage = new ArrayStorage();
        $issuer = $this->issuer($storage);
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $store = new TlsRecordingRiskStateStore();
        $engine = new AdaptiveRiskEngine($store, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], policy: $policy);

        // The direct peer (198.51.100.7) is OUTSIDE the trusted CIDR: the
        // header is ignored — a client talking to the app directly can
        // never forge the trusted-edge classification.
        $controller = new ChallengeController($issuer, null, true, $gateway, new ContinuityCookie(), trustedTlsHeader: 'X-Tls-Class', trustedTlsProxies: ['10.0.0.0/8']);
        $session = str_repeat('cd', 16);
        $response = $controller->challenge($this->challengeRequest(
            '{"scope":"login","client_context":"v1,t0,lde,z2"}',
            ['HTTP_X_TLS_CLASS' => 'tls13-http2'],
            ['__Host-kiwi-session' => $session],
        ));

        self::assertSame(200, $response->getStatusCode());
        self::assertSame([], $store->tlsTags, 'the TLS header must be ignored from an untrusted direct peer');
    }

    public function testTlsHeaderIsIgnoredWhenTheProxyListIsEmpty(): void
    {
        $storage = new ArrayStorage();
        $issuer = $this->issuer($storage);
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $store = new TlsRecordingRiskStateStore();
        $engine = new AdaptiveRiskEngine($store, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], policy: $policy);

        // The default empty proxy list trusts NO direct peer: the header
        // is never read.
        $controller = new ChallengeController($issuer, null, true, $gateway, new ContinuityCookie(), trustedTlsHeader: 'X-Tls-Class');
        $session = str_repeat('ef', 16);
        $response = $controller->challenge($this->challengeRequest(
            '{"scope":"login","client_context":"v1,t0,lde,z2"}',
            ['HTTP_X_TLS_CLASS' => 'tls13-http2'],
            ['__Host-kiwi-session' => $session],
        ));

        self::assertSame(200, $response->getStatusCode());
        self::assertSame([], $store->tlsTags, 'with an empty trusted-proxy list the TLS header is never read');
    }

    public function testMalformedTlsHeaderValueIsIgnored(): void
    {
        $storage = new ArrayStorage();
        $issuer = $this->issuer($storage);
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $store = new TlsRecordingRiskStateStore();
        $engine = new AdaptiveRiskEngine($store, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], policy: $policy);

        $controller = new ChallengeController($issuer, null, true, $gateway, new ContinuityCookie(), trustedTlsHeader: 'X-Tls-Class', trustedTlsProxies: ['198.51.100.0/24']);
        $session = str_repeat('ab', 16);
        // Spaces, uppercase and '!' are outside the bounded pattern; the
        // value must be ignored (the assessment runs without a TLS tag).
        $response = $controller->challenge($this->challengeRequest(
            '{"scope":"login","client_context":"v1,t0,lde,z2"}',
            ['HTTP_X_TLS_CLASS' => 'BAD VALUE!!!'],
            ['__Host-kiwi-session' => $session],
        ));

        self::assertSame(200, $response->getStatusCode());
        self::assertSame([], $store->tlsTags, 'a malformed TLS header value must be ignored');
    }

    public function testUnconfiguredTlsHeaderCarriesNoTag(): void
    {
        $storage = new ArrayStorage();
        $issuer = $this->issuer($storage);
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $store = new TlsRecordingRiskStateStore();
        $engine = new AdaptiveRiskEngine($store, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], policy: $policy);

        // No trustedTlsHeader configured — the header (whatever its name)
        // is never read.
        $controller = new ChallengeController($issuer, null, true, $gateway, new ContinuityCookie());
        $session = str_repeat('ef', 16);
        $response = $controller->challenge($this->challengeRequest(
            '{"scope":"login","client_context":"v1,t0,lde,z2"}',
            ['HTTP_X_TLS_CLASS' => 'tls13-http2'],
            ['__Host-kiwi-session' => $session],
        ));

        self::assertSame(200, $response->getStatusCode());
        self::assertSame([], $store->tlsTags, 'without risk.trusted_tls_header no header is ever read');
    }

    public function testReservedChainCdataPrefixIsRefusedAtEveryIssuance(): void
    {
        $storage = new ArrayStorage();
        $issuer = $this->issuer($storage);
        $risk = $this->riskStack();
        $controller = new ChallengeController($issuer, null, true, $risk['gateway'], new ContinuityCookie());

        // The chain-marker prefix is SERVER-OWNED: a client-supplied cdata
        // starting with it is refused — the marker can never be forged.
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'cdata' => ChallengeController::CHAIN_CDATA_PREFIX.'forged'], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode());
        self::assertStringContainsString('INVALID_METADATA', (string) $response->getContent());
    }
}

/**
 * A storage that fails the MINT step on demand: store() throws the
 * replica-wait durability barrier failure (the same operational failure
 * the controller maps to the retryable 503) while every other operation
 * delegates to the wrapped storage.
 */
final class FailingMintStorage implements StorageInterface
{
    public bool $mintFails = true;

    public function __construct(private readonly StorageInterface $inner)
    {
    }

    public function store(\KiwiCaptcha\ChallengeRecord $record): void
    {
        if ($this->mintFails) {
            throw new ReplicaWaitException('simulated replica-wait barrier failure');
        }
        $this->inner->store($record);
    }

    public function find(string $nonce): ?\KiwiCaptcha\ChallengeRecord
    {
        return $this->inner->find($nonce);
    }

    public function consume(string $nonce): ?\KiwiCaptcha\ConsumedRecord
    {
        return $this->inner->consume($nonce);
    }

    public function commitResult(string $nonce, bool $valid, ?string $binding): bool
    {
        return $this->inner->commitResult($nonce, $valid, $binding);
    }

    public function delete(string $nonce): void
    {
        $this->inner->delete($nonce);
    }
}

/**
 * In-memory risk state store that RECORDS the trusted-edge TLS tags and
 * client-context tags it is asked to record (the engine's session-first
 * records), so the tests can assert the TLS classification flowed from the
 * controller's configured header through the risk-v2 client context into
 * the engine. Implements the risk-v2 session-record capability interfaces
 * the engine probes for.
 */
final class TlsRecordingRiskStateStore implements RiskStateStoreInterface, \KiwiCaptcha\Risk\Storage\SessionContextTagStoreInterface, \KiwiCaptcha\Risk\Storage\SessionTlsTagStoreInterface
{
    /** @var array<string, string> session pseudonym => first-seen TLS tag */
    public array $tlsTags = [];

    /** @var array<string, string> session pseudonym => first-seen client-context tag */
    public array $contextTags = [];

    /** @var list<RiskObservation> */
    public array $observations = [];

    public function observe(RiskObservation $observation): SignalVector
    {
        $this->observations[] = $observation;

        return SignalVector::zero();
    }

    public function registerOutcome(string $decisionId, int $scope, int $decisionHour, int $score): bool
    {
        return true;
    }

    public function confirmOutcome(string $decisionId, bool $legitimate): int
    {
        return 1;
    }

    public function correctOutcome(string $decisionId, bool $legitimate): bool
    {
        return true;
    }

    public function sessionFirstContextTag(string $sessionId, string $tag): ?string
    {
        return $this->contextTags[$sessionId] ??= $tag;
    }

    public function sessionFirstTlsTag(string $sessionId, string $tag): ?string
    {
        return $this->tlsTags[$sessionId] ??= $tag;
    }
}
