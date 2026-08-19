<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Risk\ArrayChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
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
 * parameter); the stage-2 challenge request presents the ticket for an
 * atomic one-shot issuance — a replayed/invalid/expired ticket is refused
 * and a ticket-bearing request is NEVER downgraded to an unchained
 * issuance. Also covers the form-submission honeypot evidence path and
 * the trusted-edge TLS header path.
 */
final class ChainedChallengeTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private function issuer(ArrayStorage $storage): Issuer
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
    private function riskStack(?SignalVector $vector = null): array
    {
        return $this->riskStackWithScopes(['login' => 1], $vector);
    }

    /**
     * @param array<string, int> $scopes
     *
     * @return array{gateway: RiskGateway, store: FakeRiskStateStore}
     */
    private function riskStackWithScopes(array $scopes, ?SignalVector $vector = null): array
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
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), $scopes, policy: $policy);

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
     * Validate a token through the FULL Symfony pipeline with a
     * chaining-enabled validator.
     *
     * @return array{0: ConstraintViolationListInterface, 1: KiwiCaptchaValidator}
     */
    private function validateChained(string $token, RequestStack $stack, RiskGateway $gateway, ArrayStorage $storage, ?\Closure $now = null): array
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
            $this->chainService(new ArrayChainedChallengeStateStore(), $now),
            1,
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

    // ── Chained issuance flow ──────────────────────────────────────────

    public function testStage1VerifyIssuesChainTicketWhenReassessmentDemandsStrongerStage(): void
    {
        $storage = new ArrayStorage();
        $issuer = $this->issuer($storage);
        $challenge = $issuer->issue('login', '198.51.100.7')->toArray();
        usleep(($challenge['minDurationMs'] + 10) * 1000);
        $token = $this->solveToken($challenge);

        // The reassessment (network_risk 700 -> score 800) demands Argon32
        // — above the first-stage Sha16 class.
        $risk = $this->riskStack(SignalVector::fromArray(['source_fast' => 900, 'subnet_fast' => 1000, 'issue_debt' => 1000, 'replay' => 699, 'network_risk' => 890]));
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));

        [$violations, $validator] = $this->validateChained($token, $stack, $risk['gateway'], $storage);

        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $ticket = $violations[0]->getParameters()['{{ chain_ticket }}'] ?? null;
        self::assertIsString($ticket);
        self::assertNotEmpty($ticket);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9._:-]{1,256}$/D', $ticket);
    }

    public function testChainTicketStage1NonceEqualsTheVerifiedNonceAndConsumeIsOneShot(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $nonce = bin2hex(random_bytes(16));
        $ticket = $service->issue($nonce, 'login', 1);
        self::assertIsString($ticket);

        $payload = $service->verify($ticket);
        self::assertIsArray($payload);
        self::assertSame($nonce, $payload['stage1Nonce'], 'the chain ticket signs the ACTUAL verified stage-1 nonce');
        self::assertSame('login', $payload['scope']);
        self::assertSame(1, $payload['policyVersion']);
        self::assertSame($payload['issuedAt'] + 300, $payload['expiresAt']);

        $consumed = $service->consume($ticket);
        self::assertIsArray($consumed);
        self::assertSame($nonce, $consumed['stage1Nonce']);
        self::assertNull($service->consume($ticket), 'a chain ticket is one-shot: the second consume must be refused');
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
        $ticket = $chainService->issue($stage1Nonce, 'login', 1);
        self::assertIsString($ticket);

        // Stage-2 issuance with the ticket: the ordinary risk preIssue
        // path runs (the reassessment already happened at verify) — the
        // vector keeps demanding Argon32, so the issued challenge is the
        // stronger stage.
        $risk = $this->riskStack(SignalVector::fromArray(['source_fast' => 900, 'subnet_fast' => 1000, 'issue_debt' => 1000, 'replay' => 699, 'network_risk' => 890]));
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
        self::assertNotSame($stage1Nonce, $stage2['nonce'], 'the ticket holder can never re-run the same stage');

        // A SECOND issuance with the SAME (now consumed) ticket is refused.
        $second = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $second->getStatusCode());
        self::assertStringContainsString('INVALID_METADATA', (string) $second->getContent());
    }

    public function testInvalidExpiredAndForgedTicketsAreRefused(): void
    {
        $storage = new ArrayStorage();
        $issuer = $this->issuer($storage);
        $risk = $this->riskStack();
        $chainService = $this->chainService(new ArrayChainedChallengeStateStore());
        $controller = new ChallengeController($issuer, null, true, $risk['gateway'], new ContinuityCookie(), chainTickets: $chainService, policyVersion: 1);

        // Forged: a valid shape but signed with a different secret.
        $forger = new ChainedChallengeTicketService(new ArrayChainedChallengeStateStore(), str_repeat('f', 32), 300);
        $forged = $forger->issue(bin2hex(random_bytes(16)), 'login', 1);
        self::assertIsString($forged);
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $forged], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode());

        // Expired: the issuing clock says 1000; the consuming clock is
        // past expiresAt (1000 + 300).
        $expiredStore = new ArrayChainedChallengeStateStore();
        $issuing = new ChainedChallengeTicketService($expiredStore, self::SECRET, 300, static fn (): int => 1000);
        $expired = $issuing->issue(bin2hex(random_bytes(16)), 'login', 1);
        self::assertIsString($expired);
        $late = new ChainedChallengeTicketService($expiredStore, self::SECRET, 300, static fn (): int => 2000);
        self::assertNull($late->consume($expired), 'an expired ticket must be refused');
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $expired], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode());

        // Garbage / malformed shapes.
        foreach (['not-a-ticket', 'a.b.c', str_repeat('x', 300), '!!bad!!'] as $malformed) {
            $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $malformed], JSON_THROW_ON_ERROR)));
            self::assertSame(422, $response->getStatusCode(), sprintf('malformed ticket %s must be refused', $malformed));
        }
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
        $ticket = $chainService->issue(bin2hex(random_bytes(16)), 'login', 1);
        $risk2 = $this->riskStackWithScopes(['login' => 1, 'signup' => 2]);
        $controller = new ChallengeController($issuer, null, true, $risk2['gateway'], new ContinuityCookie(), chainTickets: $chainService, policyVersion: 1);
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'signup', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode(), 'a chain ticket is scope-bound: a different scope must be refused');

        // Wrong policy epoch: the controller expects 2, the ticket says 1.
        $chainService2 = $this->chainService(new ArrayChainedChallengeStateStore());
        $ticket2 = $chainService2->issue(bin2hex(random_bytes(16)), 'login', 1);
        $controller2 = new ChallengeController($issuer, null, true, $risk['gateway'], new ContinuityCookie(), chainTickets: $chainService2, policyVersion: 2);
        $response = $controller2->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket2], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode(), 'a chain ticket is bound to the policy epoch it was issued under');
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

    // ── Form-submission honeypot ───────────────────────────────────────

    public function testFilledDecoyFieldFeedsDecoyFieldSubmittedEvidenceAtSubmit(): void
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
            'decoy_12345678' => 'bot@example.com',
            'username' => 'alice',
        ], [], [], ['REMOTE_ADDR' => '198.51.100.7']));

        [$violations] = $this->validateChained($token, $stack, $risk['gateway'], $storage);

        // Evidence at form-submission time; never a gate — the valid solve
        // passes.
        self::assertCount(0, $violations, 'a filled decoy field is evidence, never a gate');
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

        $risk = $this->riskStack();
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [
            'kiwi__token' => $token,
            'decoy_12345678' => '',
        ], [], [], ['REMOTE_ADDR' => '198.51.100.7']));

        [$violations] = $this->validateChained($token, $stack, $risk['gateway'], $storage);
        self::assertCount(0, $violations);
        $events = array_map(static fn ($o): RiskEventKind => $o->event, $risk['store']->observations);
        self::assertNotContains(RiskEventKind::DecoyFieldSubmitted, $events, 'an EMPTY decoy field is no evidence');
    }

    public function testMalformedDecoyFieldNamesAreIgnored(): void
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
            'decoy_nothex' => 'filled',      // not decoy_<8 hex>
            'decoy_12345678_' => 'filled',   // trailing char
            'decoy_123456789' => 'filled',   // 9 hex chars
        ], [], [], ['REMOTE_ADDR' => '198.51.100.7']));

        [$violations] = $this->validateChained($token, $stack, $risk['gateway'], $storage);
        self::assertCount(0, $violations);
        $events = array_map(static fn ($o): RiskEventKind => $o->event, $risk['store']->observations);
        self::assertNotContains(RiskEventKind::DecoyFieldSubmitted, $events, 'only /^decoy_[0-9a-f]{8}$/ fields are honeypot evidence');
    }

    // ── Trusted-edge TLS header ────────────────────────────────────────

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

        $controller = new ChallengeController($issuer, null, true, $gateway, new ContinuityCookie(), trustedTlsHeader: 'X-Tls-Class');
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

        $controller = new ChallengeController($issuer, null, true, $gateway, new ContinuityCookie(), trustedTlsHeader: 'X-Tls-Class');
        $session = str_repeat('cd', 16);
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
}

/**
 * In-memory risk state store that RECORDS the trusted-edge TLS tags and
 * client-context tags it is asked to record (the engine's session-first
 * records), so the tests can assert the TLS classification flowed from the
 * controller's configured header through the risk-v2 client context into
 * the engine.
 */
final class TlsRecordingRiskStateStore implements RiskStateStoreInterface
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
