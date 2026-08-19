<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Risk\ArrayChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceRateLimiter;
use BelConsulting\KiwiCaptchaBundle\Security\OutstandingChallenges;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyMetadataStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadata;
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
 * whose post-solve reassessment demands an action the solved challenge
 * does NOT already satisfy (the resolver's ACTUAL configured ladders)
 * returns a signed one-shot chain ticket (CHAIN_REQUIRED violation,
 * {{ chain_ticket }} parameter). The ticket is MINIMAL (version, chain
 * id, signed expiry — the full server-held state owns the identity
 * fields), the stage-2 request validates the ticket FIRST (before any
 * admission counter), claims an OWNER-SCOPED reservation (a second
 * request while the lease is live gets the retryable in-progress 503 and
 * never enters the pipeline; a non-owner release is an atomic no-op; an
 * expired lease is taken over), issues at least the promised strength,
 * and COMPLETES the chain as a TERMINAL state (never a delete): a replay
 * RECOVERS the already-issued challenge (identical bytes, no re-mint, no
 * re-admission). A replayed/invalid/expired/wrong-scope/wrong-binding/
 * wrong-depth ticket is refused and a ticket-bearing request is NEVER
 * downgraded to an unchained issuance. StepUp is terminal (never a
 * ticket), Deny rejects, the chain ends at stage 2 (the private metadata
 * chainId field — the application's cdata is preserved untouched), and a
 * failed issuance releases the reservation (the ticket stays reusable).
 * Also covers the form-submission honeypot evidence path (bound to the
 * verified nonce) and the trusted-edge TLS header path (bound to the
 * direct peer).
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

    /** The post-solve vector that demands Sha16 (score 228). */
    private const SHA16_VECTOR = ['replay' => 400];

    /** The custom argon ladder [1, 5, 10] (Argon16 -> 1, Argon32 -> 5, Argon64 -> 10). */
    private const CUSTOM_ARGON_LADDER = [1, 5, 10];

    private function issuer(StorageInterface $storage): Issuer
    {
        return new Issuer(new Config(
            secretKey: self::SECRET,
            algorithm: PoWAlgorithm::Sha256,
            targetBits: 8, // fast solve for tests
            ttlSecs: 120,
        ), $storage);
    }

    private function argonIssuer(StorageInterface $storage, int $argon2TargetBits, int $mKib = 1024): Issuer
    {
        return new Issuer(new Config(
            secretKey: self::SECRET,
            algorithm: PoWAlgorithm::Argon2id,
            mKib: $mKib,
            t: 3,
            p: 1,
            argon2TargetBits: $argon2TargetBits,
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

    private function chainService(ChainedChallengeStateStore $store, ?\Closure $now = null): ChainedChallengeTicketService
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
    private function validateChained(string $token, RequestStack $stack, RiskGateway $gateway, ArrayStorage $storage, ?ArrayChainedChallengeStateStore $chainStore = null, ?SiteVerifyMetadataStore $metadataStore = null, ?\Closure $now = null, ?RiskProfileResolver $resolver = null, ?StorageInterface $validatorStorage = null): array
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
            $validatorStorage ?? $storage,
            null,
            null,
            null,
            $this->chainService($chainStore ?? new ArrayChainedChallengeStateStore(), $now),
            1,
            $metadataStore,
            $resolver,
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

    /** The records of an in-memory challenge storage (reflection). */
    private function storageRecordCount(ArrayStorage $storage): int
    {
        return \count((new \ReflectionObject($storage))->getProperty('records')->getValue($storage));
    }

    // ── Chained issuance flow ──────────────────────────────────────────

    public function testStage1VerifyIssuesChainTicketWhenReassessmentDemandsStrongerStage(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $challenge = $this->issuer($storage)->issue('login', '198.51.100.7')->toArray();
        usleep(($challenge['minDurationMs'] + 10) * 1000);
        $token = $this->solveToken($challenge);

        // The reassessment (score 813) demands Argon32 — the solved SHA-8
        // does not satisfy it under the configured ladders.
        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR), $resolver);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));

        [$violations] = $this->validateChained($token, $stack, $risk['gateway'], $storage, $chainStore, resolver: $resolver);

        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $ticket = $violations[0]->getParameters()['{{ chain_ticket }}'] ?? null;
        self::assertIsString($ticket);
        self::assertNotEmpty($ticket);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9._:-]{1,256}$/D', $ticket);

        // The MINIMAL ticket payload: version 1, chain id, signed expiry
        // — nothing else.
        $payload = $this->chainService($chainStore)->verify($ticket);
        self::assertIsArray($payload);
        self::assertSame(1, $payload['version'], 'the ticket format version is 1');
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{1,64}$/D', (string) $payload['chainId']);
        self::assertGreaterThan(time(), $payload['expiresAt'], 'the ticket carries the signed expiry');

        // The FULL identity lives in the SERVER-HELD state, written at
        // issue() time by the validator.
        $state = $this->chainService($chainStore)->read($ticket);
        self::assertIsArray($state);
        self::assertSame('argon32', $state['requiredAction'], 'the server-held state binds the reassessed required action');
        self::assertSame(2, $state['chainDepth'], 'the chain is a depth-2 selective extension');
        self::assertNull($state['requestBinding'], 'an unbound stage-1 challenge holds a null binding');
        self::assertSame('login', $state['scope']);
        self::assertSame(1, $state['policyVersion']);
        self::assertSame('available', $state['state']);
    }

    public function testChainTicketBindsTheStage1RequestBinding(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $stage1 = $this->solvedStage1($storage, 'txn-alpha');

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR), $resolver);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [
            'kiwi__token' => $stage1['token'],
            'kiwi_request_binding' => 'txn-alpha',
        ], [], [], ['REMOTE_ADDR' => '198.51.100.7']));

        [$violations] = $this->validateChained($stage1['token'], $stack, $risk['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $ticket = $violations[0]->getParameters()['{{ chain_ticket }}'] ?? null;
        self::assertIsString($ticket);

        $state = $this->chainService($chainStore)->read($ticket);
        self::assertIsArray($state);
        self::assertSame('txn-alpha', $state['requestBinding'], 'the server-held state records the stage-1 challenge\'s request binding');
    }

    public function testChainTicketReserveCompleteReleaseStateMachine(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $nonce = bin2hex(random_bytes(16));
        $ticket = $service->issue($nonce, 'login', 1, requiredAction: 'argon32');
        self::assertIsString($ticket);

        $payload = $service->verify($ticket);
        self::assertIsArray($payload);
        self::assertSame(1, $payload['version']);
        $state = $service->read($ticket);
        self::assertIsArray($state);
        self::assertSame($nonce, $state['stage1Nonce'], 'the server-held state records the ACTUAL verified stage-1 nonce');
        self::assertSame('login', $state['scope']);
        self::assertSame(1, $state['policyVersion']);
        self::assertSame('argon32', $state['requiredAction']);
        self::assertNull($state['requestBinding']);
        self::assertSame(2, $state['chainDepth']);

        // available -> reserved(ownerA) (the reservation is the issuance claim).
        self::assertSame('available', $store->reserve((string) $payload['chainId'], 'owner-a', 300), 'the first reserve transitions available -> reserved');
        self::assertSame('retry', $store->reserve((string) $payload['chainId'], 'owner-a', 300), 'reserve by the SAME owner is a retry');
        self::assertSame('busy', $store->reserve((string) $payload['chainId'], 'owner-b', 300), 'reserve by another owner with a live lease is busy');

        // A non-owner can neither complete nor release the reservation.
        self::assertNull($store->complete((string) $payload['chainId'], 'owner-b', 'n2'), 'a non-owner complete is an atomic no-op');
        $store->release((string) $payload['chainId'], 'owner-b');
        self::assertSame('reserved', $service->read($ticket)['state'], 'a non-owner release does not free the reservation');
        self::assertSame('owner-a', $service->read($ticket)['owner']);

        // The owner completes: a TERMINAL state transition, never a delete.
        $completed = $store->complete((string) $payload['chainId'], 'owner-a', 'n2');
        self::assertIsArray($completed);
        self::assertSame('completed', $completed['state']);
        self::assertSame('n2', $completed['stage2Nonce']);
        self::assertSame('completed', $store->reserve((string) $payload['chainId'], 'owner-c', 300), 'a replayed ticket lands on the completed state');
        self::assertNull($store->complete((string) $payload['chainId'], 'owner-a', 'n3'), 'a completed chain NEVER allows a second completion (no second mint)');
        $store->release((string) $payload['chainId'], 'owner-a');
        self::assertSame('completed', $service->read($ticket)['state'], 'a release cannot undo the terminal completed state');
    }

    public function testChainTicketReleaseUndoesTheReservationForItsOwner(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $ticket = $service->issue(bin2hex(random_bytes(16)), 'login', 1, requiredAction: 'argon32');
        self::assertIsString($ticket);
        $chainId = (string) $service->verify($ticket)['chainId'];

        self::assertSame('available', $store->reserve($chainId, 'owner-a', 300));
        $store->release($chainId, 'owner-b');
        self::assertSame('busy', $store->reserve($chainId, 'owner-c', 300), 'a non-owner release leaves the reservation live');
        $store->release($chainId, 'owner-a');
        self::assertSame('available', $store->reserve($chainId, 'owner-c', 300), 'the owner\'s release returns the chain to the available state — the ticket stays reusable');
    }

    public function testStage2IssuanceWithTicketSucceedsAndReplayRecoversTheSameChallenge(): void
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
            storage: $storage,
            challengeTtlSecs: 120,
            chainTickets: $chainService,
            policyVersion: 1,
        );
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), sprintf('stage-2 issuance must accept the valid ticket: %s', (string) $response->getContent()));
        $stage2 = json_decode((string) $response->getContent(), true);
        self::assertSame('argon2id', $stage2['algorithm'], 'the stage-2 issuance follows the ordinary risk profile selection (Argon32)');
        self::assertSame(4, $stage2['targetBits'], 'the issued stage-2 profile is the Argon32 rung of the fixed-envelope ladder');
        self::assertNotSame($stage1Nonce, $stage2['nonce'], 'the ticket holder can never re-run the same stage');

        // A SECOND request with the SAME ticket: the chain is COMPLETED —
        // the retry RECOVERS the already-issued challenge: the SAME
        // nonce, byte-identical response, and NO second challenge record.
        $recordCount = $this->storageRecordCount($storage);
        $second = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $second->getStatusCode(), sprintf('a completed chain recovers the issued challenge: %s', (string) $second->getContent()));
        self::assertSame((string) $response->getContent(), (string) $second->getContent(), 'the recovery response must be byte-identical to the original issuance response');
        self::assertSame($stage2['nonce'], json_decode((string) $second->getContent(), true)['nonce'], 'the recovery returns the SAME issued nonce');
        self::assertSame($recordCount, $this->storageRecordCount($storage), 'a completed chain NEVER re-mints — no second challenge record');
    }

    public function testTicketRequiredActionIsTheStage2FloorAgainstTransientRiskDecay(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $stage1 = $this->solvedStage1($storage);

        // The chain demands Argon32 — but the CURRENT pre-issue
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

        // Wrong policy epoch: the controller expects 2, the state says 1.
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

        // A chain WITH a binding presented WITH a DIFFERENT binding.
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $bound, 'request_binding' => 'txn-beta'], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode(), 'a bound chain with a different request binding must be refused');

        // A chain WITH a binding presented WITHOUT one.
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $bound], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode(), 'a bound chain presented without its request binding must be refused');

        // A chain WITHOUT a binding presented WITH a request binding.
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $unbound, 'request_binding' => 'txn-x'], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode(), 'an unbound chain presented with a request binding must be refused');

        // Control: the EXACT identity match succeeds.
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $bound, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), 'the exact binding identity match must be accepted');
    }

    public function testTicketChainDepthMustBeTwo(): void
    {
        $storage = new ArrayStorage();
        $issuer = $this->issuer($storage);
        $risk = $this->riskStack();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);

        // The ticket format cannot carry a chain depth — the depth lives
        // in the SERVER-HELD state, written by the validator as 2 (a
        // client can never alter it). A state record with any other depth
        // (defense-in-depth) is refused: the chain is a selective
        // extension of depth 2 — a third stage can never exist.
        $ticket = $chainService->issue(bin2hex(random_bytes(16)), 'login', 1, requiredAction: 'argon32');
        self::assertIsString($ticket);
        $records = $this->chainRecords($chainStore);
        $records[array_key_first($records)]['chainDepth'] = 3;
        (new \ReflectionObject($chainStore))->getProperty('records')->setValue($chainStore, $records);
        $controller = new ChallengeController($issuer, null, true, $risk['gateway'], new ContinuityCookie(), chainTickets: $chainService, policyVersion: 1);
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode(), 'a chain whose server-held depth is not 2 must be refused');
        self::assertStringContainsString('INVALID_METADATA', (string) $response->getContent());

        // The depth-2 chain is the only accepted shape.
        $depth2 = $chainService->issue(bin2hex(random_bytes(16)), 'login', 1, requiredAction: 'argon32');
        self::assertIsString($depth2);
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $depth2], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode());
    }

    public function testStage2VerifiedChallengeCannotOpenThirdStage(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $metaStore = new ArraySiteVerifyMetadataStore();
        $chainService = $this->chainService($chainStore);
        $issuer = $this->issuer($storage);

        // The fixed-envelope Argon ladder is flattened to [1, 2, 3] so
        // the stage-2 Argon challenge solves fast in the test (the
        // strength ladder itself is covered elsewhere).
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8, 16384, [1, 2, 3]);
        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR), $resolver);

        // Stage 1: solve + CHAIN_REQUIRED ticket (the reassessment
        // demands Argon32).
        $stage1 = $this->solvedStage1($storage);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations] = $this->validateChained($stage1['token'], $stack, $risk['gateway'], $storage, $chainStore, $metaStore, resolver: $resolver);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $ticket = $violations[0]->getParameters()['{{ chain_ticket }}'];
        self::assertIsString($ticket);

        // Stage 2: the ticket issues the Argon32 stage; the controller
        // STAMPS the chain identity into the PRIVATE metadata fields.
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

        // The chain identity is server-stamped into the metadata sidecar.
        $metadata = $metaStore->find($stage2['nonce']);
        self::assertNotNull($metadata);
        self::assertSame($this->chainService($chainStore)->verify($ticket)['chainId'], $metadata->chainId, 'the stage-2 challenge must carry the server-stamped chain id in the private metadata field');
        self::assertSame(2, $metadata->chainDepth);

        // Stage 2 solve: the reassessment (Argon64 — stronger than the
        // stage-2 profile) would demand a THIRD stage — the metadata
        // chainId refuses it: the verification passes with NO ticket.
        usleep(($stage2['minDurationMs'] + 10) * 1000);
        $stage2Token = $this->solveChallenge($stage2);
        $risk['store']->setVector(SignalVector::fromArray(self::ARGON64_VECTOR));
        $stack2 = new RequestStack();
        $stack2->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations2] = $this->validateChained($stage2Token, $stack2, $risk['gateway'], $storage, $chainStore, $metaStore, resolver: $resolver);

        self::assertCount(0, $violations2, 'a stage-2 verified challenge passes — the chain ends at stage 2');
        $records = array_values($this->chainRecords($chainStore));
        self::assertCount(1, $records, 'no third-stage chain state may ever be created');
        self::assertSame('completed', $records[0]['state'], 'the only remaining record is the completed stage-1 chain');
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

        // The failed issuance RELEASED the reservation (with its owner
        // token): the SAME ticket succeeds on retry — the chain is not
        // burned.
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

        // A COMPLETED ticket (valid signature, chain already spent):
        // the control issuance completes it, the replay RECOVERS the
        // issued challenge — neither touches the counters again.
        $consumed = $chainService->issue(bin2hex(random_bytes(16)), 'login', 1, requiredAction: 'argon32');
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $consumed], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), 'the control ticket must issue first');
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $consumed], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), 'the replayed (completed) ticket recovers the issued challenge');

        // NONE of the invalid tickets moved the outstanding counters:
        // validation (and the completed-state recovery) run BEFORE any
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

    // ── Owner-scoped reservation (the in-progress 503 boundary) ────────

    public function testSecondRequestWithTheSameTicketWhileReservedGetsTheInProgress503(): void
    {
        $storage = new ArrayStorage();
        $client = new FakePredisClient();
        $outstanding = new OutstandingChallenges($client, '{kiwi:chain-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $interceptor = new ChainStateStoreInterceptor(new ArrayChainedChallengeStateStore());
        $chainService = $this->chainService($interceptor);
        $stage1 = $this->solvedStage1($storage);
        $ticket = $chainService->issue($stage1['nonce'], 'login', 1, requiredAction: 'argon32');
        self::assertIsString($ticket);

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = new ChallengeController(
            $this->issuer($storage),
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

        // While the FIRST request holds its reservation, a SECOND request
        // with the same ticket must get the retryable in-progress 503 and
        // NEVER enter the issuance pipeline. The seam fires ONCE (only
        // the first request's reserve triggers it — a nested reserve
        // would recurse).
        $secondResponse = null;
        $interceptor->afterReserve = function () use ($interceptor, $controller, $ticket, &$secondResponse): void {
            $interceptor->afterReserve = null;
            $secondResponse = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        };
        $first = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $first->getStatusCode(), 'the first request still succeeds while the reservation is held');
        self::assertNotNull($secondResponse);
        self::assertSame(503, $secondResponse->getStatusCode(), 'a second request while the first holds the reservation must get the in-progress 503');
        self::assertStringContainsString('already in progress', (string) $secondResponse->getContent());

        // The busy refusal never touched the outstanding counters: only
        // the first request's mint may have incremented them.
        $sourceKey = '{kiwi:chain-test}:outstanding:'.hash_hmac('sha256', Issuer::canonicalIpFamily('198.51.100.7'), RiskKeys::fromMaster(self::SECRET)->event);
        self::assertSame(1, $client->counters[$sourceKey] ?? 0, 'the in-progress 503 must never enter the issuance pipeline');
    }

    public function testBusyReservationRefusesBeforeAnyAdmissionAndOwnerReleaseFreesIt(): void
    {
        $storage = new ArrayStorage();
        $client = new FakePredisClient();
        $outstanding = new OutstandingChallenges($client, '{kiwi:chain-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $stage1 = $this->solvedStage1($storage);
        $ticket = $chainService->issue($stage1['nonce'], 'login', 1, requiredAction: 'argon32');
        self::assertIsString($ticket);
        $chainId = (string) $chainService->verify($ticket)['chainId'];

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = new ChallengeController(
            $this->issuer($storage),
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

        // A LIVE reservation by another owner (never this request):
        // every request with the ticket gets the in-progress 503.
        self::assertSame('available', $chainStore->reserve($chainId, 'owner-a', 300));
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(503, $response->getStatusCode(), 'a live reservation by another owner refuses with the in-progress 503');

        // A NON-OWNER release does not free it (the controller's failing
        // request can never free another owner's live reservation).
        $chainStore->release($chainId, 'not-the-owner');
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(503, $response->getStatusCode(), 'a non-owner release leaves the reservation live');

        // After the OWNER releases, the retry succeeds.
        $chainStore->release($chainId, 'owner-a');
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), sprintf('after the owner\'s release the retry succeeds: %s', (string) $response->getContent()));

        // None of the busy refusals touched the outstanding counters.
        $sourceKey = '{kiwi:chain-test}:outstanding:'.hash_hmac('sha256', Issuer::canonicalIpFamily('198.51.100.7'), RiskKeys::fromMaster(self::SECRET)->event);
        self::assertSame(1, $client->counters[$sourceKey] ?? 0, 'the in-progress 503 must never enter the issuance pipeline');
    }

    public function testExpiredLeaseIsTakenOverByTheNextReservingOwner(): void
    {
        // The clock variant: the Array store runs on an explicit clock so
        // the reservation lease expiry is enforceable (mirroring redis
        // TIME on the production store). The lease equals the record's
        // remaining TTL; within the sub-second remainder of the record
        // lifetime an expired lease is TAKEN OVER by the next reserving
        // owner.
        // Fractional seconds: the int-truncated lease (1300) can expire
        // inside the float record lifetime (1300.5) — the window where a
        // takeover is observable.
        $clock = 1000.5;
        $store = new ArrayChainedChallengeStateStore(static function () use (&$clock): float {
            return $clock;
        });
        $service = new ChainedChallengeTicketService($store, self::SECRET, 300, static fn (): int => 1000);
        $ticket = $service->issue(bin2hex(random_bytes(16)), 'login', 1, requiredAction: 'argon32');
        self::assertIsString($ticket);
        $chainId = (string) $service->verify($ticket)['chainId'];

        self::assertSame('available', $store->reserve($chainId, 'owner-a', 300));
        $clock = 1000.9;
        self::assertSame('busy', $store->reserve($chainId, 'owner-b', 300), 'the live lease refuses another owner');
        self::assertIsArray($store->read($chainId), 'the chain record is still live');

        // Past the lease (1300) but inside the record's remaining
        // lifetime (1300.5): the expired lease is taken over.
        $clock = 1300.25;
        self::assertSame('available', $store->reserve($chainId, 'owner-b', 300), 'an expired lease is taken over by the next reserving owner');
        self::assertSame('retry', $store->reserve($chainId, 'owner-b', 300), 'the takeover owner now holds the reservation');

        // Past the record TTL the chain is gone entirely.
        $clock = 1300.6;
        self::assertSame('missing', $store->reserve($chainId, 'owner-c', 300), 'the whole record expires with the signed ticket');
        self::assertNull($store->read($chainId));
    }

    // ── Terminal completion recovery (the response-loss retry) ─────────

    public function testCompletedChainRecoversTheIssuedChallengeAfterResponseLoss(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $stage1 = $this->solvedStage1($storage);
        $ticket = $chainService->issue($stage1['nonce'], 'login', 1, requiredAction: 'argon32');
        self::assertIsString($ticket);

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = new ChallengeController(
            $this->issuer($storage),
            null,
            true,
            $risk['gateway'],
            new ContinuityCookie(),
            storage: $storage,
            challengeTtlSecs: 120,
            chainTickets: $chainService,
            policyVersion: 1,
        );

        // The FIRST request completes the chain durably and returns 200 —
        // the response is then LOST (simulated by the client never
        // seeing it; the chain state is already terminal).
        $first = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $first->getStatusCode());
        $firstNonce = json_decode((string) $first->getContent(), true)['nonce'];

        // Drive the state directly: complete() already ran (the state is
        // 'completed' with the issued stage2Nonce). The retry with the
        // SAME ticket returns the SAME issued nonce + the IDENTICAL
        // response bytes, WITHOUT a second challenge record.
        $records = array_values($this->chainRecords($chainStore));
        self::assertSame('completed', $records[0]['state']);
        self::assertSame($firstNonce, $records[0]['stage2Nonce'], 'the completed state holds the durably issued challenge nonce');

        $recordCount = $this->storageRecordCount($storage);
        $retry = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $retry->getStatusCode(), sprintf('a completed chain must recover on retry: %s', (string) $retry->getContent()));
        self::assertSame((string) $first->getContent(), (string) $retry->getContent(), 'the recovery response must be byte-identical to the lost response');
        self::assertSame($firstNonce, json_decode((string) $retry->getContent(), true)['nonce'], 'the recovery returns the SAME issued nonce');
        self::assertSame($recordCount, $this->storageRecordCount($storage), 'the recovery never re-mints — no second challenge record');
    }

    public function testCompletedStateNeverMintsAgainEvenUnderAdmissionPressure(): void
    {
        $storage = new ArrayStorage();
        $client = new FakePredisClient();
        $outstanding = new OutstandingChallenges($client, '{kiwi:chain-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $stage1 = $this->solvedStage1($storage);
        $ticket = $chainService->issue($stage1['nonce'], 'login', 1, requiredAction: 'argon32');
        self::assertIsString($ticket);

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = new ChallengeController(
            $this->issuer($storage),
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
        $first = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $first->getStatusCode());
        $firstNonce = json_decode((string) $first->getContent(), true)['nonce'];

        // Saturate the admission counter: a completed state must NEVER
        // re-mint — the recovery does not re-run admission.
        $sourceKey = '{kiwi:chain-test}:outstanding:'.hash_hmac('sha256', Issuer::canonicalIpFamily('198.51.100.7'), RiskKeys::fromMaster(self::SECRET)->event);
        $client->counters[$sourceKey] = 5;
        $recordCount = $this->storageRecordCount($storage);
        $retry = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $retry->getStatusCode(), sprintf('the completed-state recovery must not re-run admission: %s', (string) $retry->getContent()));
        self::assertSame($firstNonce, json_decode((string) $retry->getContent(), true)['nonce']);
        self::assertSame(5, $client->counters[$sourceKey], 'the recovery never touches the admission counters');
        self::assertSame($recordCount, $this->storageRecordCount($storage), 'the recovery never re-mints');
    }

    public function testCompletedStateWithMissingChallengeRecordIsTheRetryable503(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $stage1 = $this->solvedStage1($storage);
        $ticket = $chainService->issue($stage1['nonce'], 'login', 1, requiredAction: 'argon32');
        self::assertIsString($ticket);
        $chainId = (string) $chainService->verify($ticket)['chainId'];

        // The chain is completed with a stage2Nonce whose challenge
        // record does NOT exist (a storage anomaly): the recovery cannot
        // rebuild the response — the retryable 503.
        self::assertSame('available', $chainStore->reserve($chainId, 'owner-a', 300));
        self::assertNotNull($chainStore->complete($chainId, 'owner-a', 'missing-stage2-nonce'));

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = new ChallengeController(
            $this->issuer($storage),
            null,
            true,
            $risk['gateway'],
            new ContinuityCookie(),
            storage: $storage,
            challengeTtlSecs: 120,
            chainTickets: $chainService,
            policyVersion: 1,
        );
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(503, $response->getStatusCode(), 'a completed chain whose challenge record is missing is a retryable storage anomaly');
    }

    // ── Ticket format (minimal payload, raw-digest signature, bound) ───

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

    public function testTicketPayloadIsMinimalVersionChainIdExpiryOnly(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $now = time();
        $ticket = $service->issue(bin2hex(random_bytes(16)), 'login', 1, requiredAction: 'argon32');
        self::assertIsString($ticket);

        // The signed body is EXACTLY [version, chainId, expiresAt] — no
        // scope/binding/action/depth can ever ride the client-carrying
        // half of the chain; the server-held state owns them.
        $encoded = explode('.', $ticket)[0];
        $decoded = json_decode((string) base64_decode(strtr($encoded, '-_', '+/'), true), true, 8, JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);
        self::assertCount(3, $decoded, 'the ticket payload is the minimal [version, chainId, expiresAt]');
        self::assertSame(1, $decoded[0]);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{1,64}$/D', (string) $decoded[1]);
        self::assertIsInt($decoded[2]);
        self::assertGreaterThan($now, $decoded[2]);

        // The ticket is ~60 bytes — far below the accepted 256-byte wire
        // bound regardless of scope/binding length.
        self::assertLessThan(100, \strlen($ticket), 'the minimal ticket stays compact');
        self::assertLessThanOrEqual(256, \strlen($ticket), 'the ticket fits the accepted wire bound');
    }

    public function testMaxLengthBindingIssuesAndWorksEndToEndAtStage2(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $binding = 'b'.str_repeat('x', 127); // 128 chars — the identifier ceiling
        $scope = 'sc'.str_repeat('y', 126); // 128 chars — the scope ceiling

        // A legitimate 128-char request binding must produce a ticket
        // well under the wire bound (the same holds for a 128-char
        // scope — the minimal ticket never carries either).
        $stage1 = $this->solvedStage1($storage, $binding);
        $ticket = $chainService->issue($stage1['nonce'], $scope, 1, requiredAction: 'argon32', requestBinding: $binding);
        self::assertIsString($ticket, 'a 128-char binding must not overflow the ticket');
        self::assertLessThanOrEqual(256, \strlen($ticket), 'the ticket fits the accepted wire bound');
        self::assertLessThan(100, \strlen($ticket), 'the minimal ticket is ~60 bytes — a 128-char binding changes nothing');
        self::assertIsArray($chainService->verify($ticket));

        // The end-to-end stage-2 chain uses the configured 'login' scope
        // with the full-length binding (the identity match is exact).
        $stage1 = $this->solvedStage1($storage, $binding);
        $ticket = $chainService->issue($stage1['nonce'], 'login', 1, requiredAction: 'argon32', requestBinding: $binding);
        self::assertIsString($ticket);

        // And the chain WORKS end-to-end at stage 2 with the full-length
        // binding (the identity match is exact).
        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = new ChallengeController(
            $this->issuer($storage),
            null,
            true,
            $risk['gateway'],
            new ContinuityCookie(),
            storage: $storage,
            challengeTtlSecs: 120,
            chainTickets: $chainService,
            policyVersion: 1,
        );
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => $binding], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), sprintf('a 128-char binding must issue end-to-end at stage 2: %s', (string) $response->getContent()));
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

    // ── Stage-strength comparison (the ACTUAL configured ladders) ──────

    public function testLowShaBaselineOpensTheChainWhenRequiredSha16IsNotSatisfied(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);

        // The baseline difficulty is 8 bits: the client's solved SHA-8 is
        // NOT the Sha16 rung — the reassessment (Sha16) opens the chain.
        $stage1 = $this->solvedStage1($storage);
        $risk = $this->riskStack(SignalVector::fromArray(self::SHA16_VECTOR), $resolver);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations] = $this->validateChained($stage1['token'], $stack, $risk['gateway'], $storage, $chainStore, resolver: $resolver);

        self::assertCount(1, $violations, 'a solved SHA-8 must NOT satisfy the required Sha16 rung — the chain opens');
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $ticket = $violations[0]->getParameters()['{{ chain_ticket }}'];
        self::assertIsString($ticket);
        self::assertSame('sha16', $this->chainService($chainStore)->read($ticket)['requiredAction']);
    }

    public function testCustomArgonLadderOpensForSolvedArgonBelowTheRequiredRung(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8, 16384, self::CUSTOM_ARGON_LADDER);

        // Stage-1 proof: an Argon challenge at 8 target bits (the solved
        // record carries targetBits 8 — BELOW the Argon64 rung 10 of the
        // custom ladder [1, 5, 10]).
        $challenge = $this->argonIssuer($storage, 8)->issue('login', '198.51.100.7')->toArray();
        usleep(($challenge['minDurationMs'] + 10) * 1000);
        $token = $this->solveArgon($challenge);
        $nonce = \KiwiCaptcha\SolutionToken::decode($token)->nonce;

        // The reassessment demands Argon64 (rung 10): the solved argon-8
        // does NOT satisfy it under the CONFIGURED ladder — the chain
        // opens.
        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON64_VECTOR), $resolver);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations] = $this->validateChained($token, $stack, $risk['gateway'], $storage, $chainStore, resolver: $resolver);

        self::assertCount(1, $violations, 'a solved argon-8 must NOT satisfy the Argon64 rung 10 — the chain opens');
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $ticket = $violations[0]->getParameters()['{{ chain_ticket }}'];
        self::assertIsString($ticket);
        self::assertSame($nonce, $this->chainService($chainStore)->read($ticket)['stage1Nonce']);

        // At stage 2 the effective floor is the rung-10 profile: the
        // issued challenge carries the Argon64 rung of the custom ladder.
        $controller = new ChallengeController(
            $this->argonIssuer($storage, 8),
            null,
            true,
            $risk['gateway'],
            new ContinuityCookie(),
            chainTickets: $this->chainService($chainStore),
            policyVersion: 1,
        );
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), sprintf('the custom-ladder chain must issue at stage 2: %s', (string) $response->getContent()));
        $stage2 = json_decode((string) $response->getContent(), true);
        self::assertSame('argon2id', $stage2['algorithm']);
        self::assertSame(10, $stage2['targetBits'], 'the stage-2 floor is the Argon64 rung (10) of the configured ladder');
    }

    public function testSolvedSha16AtTheRequiredRungProducesNoTicket(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);

        // Stage-1 proof at 16 bits: the solved SHA-16 IS the Sha16 rung —
        // the reassessment (Sha16) is already satisfied, no chain opens.
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 16, ttlSecs: 120), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7')->toArray();
        usleep(($challenge['minDurationMs'] + 10) * 1000);
        $token = $this->solveToken($challenge);

        $risk = $this->riskStack(SignalVector::fromArray(self::SHA16_VECTOR), $resolver);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations] = $this->validateChained($token, $stack, $risk['gateway'], $storage, $chainStore, resolver: $resolver);

        self::assertCount(0, $violations, 'a solved SHA-16 satisfies the required Sha16 rung — no chain ticket');
        self::assertSame([], $this->chainRecords($chainStore), 'a satisfied action creates no chain state');
    }

    public function testSolvedArgonAtTheRequiredRungProducesNoTicket(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8, 16384, self::CUSTOM_ARGON_LADDER);

        // Stage-1 proof at 5 bits: the solved argon-5 IS the Argon32 rung
        // (5) of the custom ladder [1, 5, 10] — the reassessment (Argon32)
        // is already satisfied, no chain opens.
        $challenge = $this->argonIssuer($storage, 5)->issue('login', '198.51.100.7')->toArray();
        usleep(($challenge['minDurationMs'] + 10) * 1000);
        $token = $this->solveArgon($challenge);

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR), $resolver);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations] = $this->validateChained($token, $stack, $risk['gateway'], $storage, $chainStore, resolver: $resolver);

        self::assertCount(0, $violations, 'a solved argon-5 satisfies the required Argon32 rung (5) — no chain ticket');
        self::assertSame([], $this->chainRecords($chainStore), 'a satisfied action creates no chain state');
    }

    public function testMissingRecordOpensTheChain(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);

        // A valid solve whose CONSUMED RECORD cannot be read (the
        // validator has no storage wiring) is treated as NOT satisfied —
        // the chain OPENS with the required action (fail toward more
        // security: an unknown solve strength is never assumed to have
        // met the reassessed action).
        $stage1 = $this->solvedStage1($storage);
        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR), $resolver);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations] = $this->validateChained($stage1['token'], $stack, $risk['gateway'], $storage, $chainStore, resolver: $resolver, validatorStorage: null);

        self::assertCount(1, $violations, 'a missing record must NOT suppress the required chain');
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
    }

    // ── Stage-2 metadata identity (the app cdata is preserved) ─────────

    public function testStage2ChainMetadataKeepsTheAppCdataAndTheChainIdPrivate(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $metaStore = new ArraySiteVerifyMetadataStore();
        $chainService = $this->chainService($chainStore);
        $stage1 = $this->solvedStage1($storage);
        $ticket = $chainService->issue($stage1['nonce'], 'login', 1, requiredAction: 'argon32');
        self::assertIsString($ticket);

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = new ChallengeController(
            $this->issuer($storage),
            null,
            true,
            $risk['gateway'],
            new ContinuityCookie(),
            metadataStore: $metaStore,
            chainTickets: $chainService,
            policyVersion: 1,
        );
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'cdata' => 'customer_123'], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode());
        $nonce = json_decode((string) $response->getContent(), true)['nonce'];

        // The stored metadata: the application's OWN cdata is preserved
        // untouched, and the chain identity lives ONLY in the private
        // chainId/chainDepth fields — never in the cdata.
        $metadata = $metaStore->find($nonce);
        self::assertNotNull($metadata);
        self::assertSame('customer_123', $metadata->cdata, 'the stage-2 issuance must preserve the application cdata');
        self::assertSame((string) $chainService->verify($ticket)['chainId'], $metadata->chainId, 'the chain id lives in the private metadata field');
        self::assertSame(2, $metadata->chainDepth);
        self::assertNotSame($metadata->chainId, $metadata->cdata);
        self::assertSame('customer_123', $metadata->toArray()['cdata'], 'the wire metadata keeps the app cdata in the cdata field');
        self::assertSame($metadata->chainId, $metadata->toArray()['chainId'], 'the chain id is a first-class private metadata field');

        // Round-trip through a persisted store preserves both.
        $roundTripped = SiteVerifyMetadata::fromArray($metadata->toArray());
        self::assertNotNull($roundTripped);
        self::assertSame('customer_123', $roundTripped->cdata);
        self::assertSame($metadata->chainId, $roundTripped->chainId);
        self::assertSame(2, $roundTripped->chainDepth);

        // Records written WITHOUT the chain fields parse with nulls/0.
        $legacy = SiteVerifyMetadata::fromArray(['action' => 'a', 'cdata' => 'c', 'sitekey' => 's']);
        self::assertNotNull($legacy);
        self::assertNull($legacy->chainId);
        self::assertSame(0, $legacy->chainDepth);
    }

    public function testClientCdataWithTheChainPrefixIsAcceptedAsOrdinaryCdata(): void
    {
        $storage = new ArrayStorage();
        $metaStore = new ArraySiteVerifyMetadataStore();
        $risk = $this->riskStack();
        $controller = new ChallengeController(
            $this->issuer($storage),
            null,
            true,
            $risk['gateway'],
            new ContinuityCookie(),
            metadataStore: $metaStore,
        );

        // The cdata slot is the application's payload: a client-supplied
        // value that merely LOOKS like the internal marker is ordinary
        // app cdata — no forgery surface exists (the chain identity never
        // travels in cdata).
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'cdata' => 'kiwi_chain_abc'], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), 'a client cdata beginning with kiwi_chain_ is accepted as ordinary cdata');
        $nonce = json_decode((string) $response->getContent(), true)['nonce'];
        $metadata = $metaStore->find($nonce);
        self::assertNotNull($metadata);
        self::assertSame('kiwi_chain_abc', $metadata->cdata, 'the client value is stored as the application cdata');
        self::assertNull($metadata->chainId, 'an unchained issuance carries no chain identity');
    }

    public function testMetadataReadFailureDuringVerificationIssuesNoChainTicket(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $throwing = new ThrowingMetadataStore();

        // A valid solve with a metadata sidecar that THROWS on read:
        // the chain marker is treated as possibly present — NO chain
        // ticket is issued, and the verification itself still passes
        // (a metadata-read failure must never open a third stage or a
        // repeated-challenge loop).
        $stage1 = $this->solvedStage1($storage);
        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations] = $this->validateChained($stage1['token'], $stack, $risk['gateway'], $storage, $chainStore, $throwing);

        self::assertCount(0, $violations, 'the verification outcome is unchanged — the solve still passes');
        self::assertSame([], $this->chainRecords($chainStore), 'a metadata-read failure must not open a chain');

        // The same for a STAGE-2 verification: the metadata read throws
        // (the marker may be present) — no third-stage ticket.
        $metaStore = new ArraySiteVerifyMetadataStore();
        $chainService = $this->chainService(new ArrayChainedChallengeStateStore());
        $ticket = $chainService->issue($stage1['nonce'], 'login', 1, requiredAction: 'argon32');
        self::assertIsString($ticket);
        $controller = new ChallengeController(
            $this->issuer($storage),
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
        usleep(($stage2['minDurationMs'] + 10) * 1000);
        $stage2Token = $this->solveChallenge($stage2);
        $stack2 = new RequestStack();
        $stack2->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations2] = $this->validateChained($stage2Token, $stack2, $risk['gateway'], $storage, $chainStore, $throwing);

        self::assertCount(0, $violations2, 'a stage-2 solve with an unreadable metadata sidecar passes — no third-stage ticket');
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
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);

        // Without the decoy the post-solve assessment is neutral (score
        // 100, allow) — the valid solve passes with NO chain ticket
        // (Allow is satisfied by any solved challenge).
        // (A FRESH risk stack per validation: the engine's per-scope
        // action hysteresis holds one-band steps, so each assessment
        // starts from a clean band.)
        $plain = $this->solvedStage1($storage);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', ['kiwi__token' => $plain['token']], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations] = $this->validateChained($plain['token'], $stack, $this->riskStack()['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertCount(0, $violations, 'without honeypot evidence the neutral post-solve assessment passes');

        // With the EXACT expected decoy field filled, the honeypot signal
        // rides the post-solve v2 assessment (score 100 + 200 = 300 ->
        // Sha18, not satisfied by the solved SHA-8): the score ROSE and
        // the chain opens.
        $marked = $this->solvedStage1($storage);
        $expected = 'decoy_'.substr(hash('sha256', $marked['nonce']), 0, 8);
        $stack2 = new RequestStack();
        $stack2->push(Request::create('/', 'POST', ['kiwi__token' => $marked['token'], $expected => 'bot@example.com'], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $risk2 = $this->riskStack(null, $resolver);
        [$violations2] = $this->validateChained($marked['token'], $stack2, $risk2['gateway'], $storage, $chainStore, resolver: $resolver);

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

        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(null, $resolver);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [
            'kiwi__token' => $token,
            $expected => 'bot@example.com',
            'username' => 'alice',
        ], [], [], ['REMOTE_ADDR' => '198.51.100.7']));

        [$violations] = $this->validateChained($token, $stack, $risk['gateway'], $storage, resolver: $resolver);

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
 * A chained-challenge state store decorator with a test seam: after every
 * reserve() the optional callback runs (while the reservation is HELD),
 * so a test can interleave a second request with the SAME ticket and
 * observe the in-progress 503 boundary.
 */
final class ChainStateStoreInterceptor implements ChainedChallengeStateStore
{
    /** @var \Closure|null (string $chainId, string $ownerToken, string $status): void */
    public ?\Closure $afterReserve = null;

    public function __construct(private readonly ChainedChallengeStateStore $inner)
    {
    }

    public function create(string $chainId, string $stage1Nonce, string $scope, int $ttlSecs, ?string $requestBinding = null, ?string $requiredAction = null, int $policyVersion = 1): void
    {
        $this->inner->create($chainId, $stage1Nonce, $scope, $ttlSecs, $requestBinding, $requiredAction, $policyVersion);
    }

    public function read(string $chainId): ?array
    {
        return $this->inner->read($chainId);
    }

    public function reserve(string $chainId, string $ownerToken, int $ttlSecs): string
    {
        $status = $this->inner->reserve($chainId, $ownerToken, $ttlSecs);
        if ($this->afterReserve !== null) {
            ($this->afterReserve)($chainId, $ownerToken, $status);
        }

        return $status;
    }

    public function release(string $chainId, string $ownerToken): void
    {
        $this->inner->release($chainId, $ownerToken);
    }

    public function complete(string $chainId, string $ownerToken, string $stage2Nonce): ?array
    {
        return $this->inner->complete($chainId, $ownerToken, $stage2Nonce);
    }
}

/**
 * A metadata sidecar that THROWS on every read (simulated transient
 * outage): the validator's third-stage detection must fail closed — no
 * chain ticket is issued, the verification outcome is unchanged.
 */
final class ThrowingMetadataStore implements SiteVerifyMetadataStore
{
    public function store(string $nonce, SiteVerifyMetadata $metadata, int $ttlSeconds): void
    {
    }

    public function find(string $nonce): ?SiteVerifyMetadata
    {
        throw new \RuntimeException('simulated metadata store outage');
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
