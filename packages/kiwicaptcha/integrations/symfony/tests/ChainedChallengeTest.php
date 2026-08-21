<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Risk\ArrayChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ArrayPostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\MalformedChainedChallengeStateException;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind;
use BelConsulting\KiwiCaptchaBundle\Risk\RequestBindingAuthorityInterface;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\TransactionalChainedChallengeStateStore;
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
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Storage\ReplicaWaitException;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Validator\ConstraintValidatorFactory;
use Symfony\Component\Validator\ConstraintViolationListInterface;
use Symfony\Component\Validator\Validation;

/**
 * Selective chained challenges (risk.chaining) — the transaction-obligation
 * redesign: a valid stage-1 proof whose post-solve reassessment demands an
 * action the solved challenge does NOT already satisfy (the resolver's
 * ACTUAL configured ladders) opens a chain ANCHORED on a server-side
 * OBLIGATION (the bounded pseudonymous obligation id of the
 * (policy-epoch, scope, AUTHORITATIVE binding) triple — never a raw
 * binding in a key), created ATOMICALLY with the chain. The ticket is
 * MINIMAL (version, chain id, signed expiry), the stage-2 request
 * validates the ticket FIRST (before any admission counter) and REQUIRES
 * its obligation to match the current transaction (a malicious different
 * ticket -> 422); a request WITHOUT a ticket but WITH an open obligation
 * AUTO-RESUMES the chain (never issue stage 1). The machine is available
 * -> reserved(owner, SHORT lease) -> issued(stage2Nonce) -> verified(
 * stage2Nonce) — verified TERMINAL (the obligation is cleared atomically):
 * an issued retry RECOVERS the exact already-issued challenge (identical
 * bytes, no re-mint, no re-admission), an expired/invalid stage-2 REARMS
 * for a fresh stage-2 mint (never a stage-1), a consumed-valid stage-2
 * VERIFIES the chain, a consumed-without-result stage-2 is the retryable
 * 503 (never rearm). The chain state decodes ALL-OR-NOTHING against the
 * strict v2 schema (a corrupt server record fails closed with 503, never
 * a defaulted chain), and an ADMITTED-but-proven-not-handed-out failure
 * returns the outstanding slot (an INDETERMINATE chain issuance does
 * NOT). StepUp is terminal (never a ticket), Deny rejects, the chain ends
 * at stage 2 (the private metadata chainId field — the application's
 * cdata is preserved untouched), and a failed issuance releases the
 * reservation (the ticket stays reusable).
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

    /** The post-solve vector that demands Sha18 (score 327 — no deny reason). */
    private const SHA18_VECTOR = ['source_fast' => 900, 'subnet_fast' => 700];

    /** The post-solve vector that demands Sha20 (score 453 — no deny reason). */
    private const SHA20_VECTOR = ['source_fast' => 900, 'issue_debt' => 1000, 'subnet_fast' => 400];

    private function issuer(StorageInterface $storage): Issuer
    {
        return new Issuer(new Config(
            secretKey: self::SECRET,
            algorithm: PoWAlgorithm::Sha256,
            targetBits: 8, // fast solve for tests
            ttlSecs: 120,
        ), $storage);
    }

    /** A Kiwi-shaped challenge nonce (base64 of 32 random bytes). */
    private function nonce(): string
    {
        return base64_encode(random_bytes(32));
    }

    /**
     * A DETERMINISTIC Kiwi-shaped stage-2 nonce for a literal seed (the
     * strict v2 decode requires the Kiwi base64 nonce shape for
     * stage2Nonce, so the tests never use arbitrary strings).
     */
    private function stageNonce(string $seed): string
    {
        return base64_encode(hash('sha256', 'stage2:'.$seed, true));
    }

    /**
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
        $classifier = new \KiwiCaptcha\Risk\Network\CidrNetworkClassifier([]);
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
        $engine = new \KiwiCaptcha\Risk\AdaptiveRiskEngine($store, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);
        $gateway = new RiskGateway($engine, $classifier, $resolver ?? new RiskProfileResolver(PoWAlgorithm::Sha256, 8), $scopes, policy: $policy);

        return ['gateway' => $gateway, 'store' => $store];
    }

    private function chainService(ChainedChallengeStateStore $store, int $leaseSecs = 15, ?RequestBindingAuthorityInterface $authority = null, ?\Closure $now = null): ChainedChallengeTicketService
    {
        return new ChainedChallengeTicketService(
            $store,
            self::SECRET,
            300,
            $leaseSecs,
            $authority,
            $now,
        );
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
    private function validateChained(string $token, RequestStack $stack, RiskGateway $gateway, ArrayStorage $storage, ?ArrayChainedChallengeStateStore $chainStore = null, ?SiteVerifyMetadataStore $metadataStore = null, ?\Closure $now = null, ?RiskProfileResolver $resolver = null, ?StorageInterface $validatorStorage = null, ?RequestBindingAuthorityInterface $authority = null): array
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
            $this->chainService($chainStore ?? new ArrayChainedChallengeStateStore(), now: $now),
            1,
            $metadataStore,
            $resolver,
            null,
            $authority ?? new FixtureBindingAuthority('txn-alpha'),
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

    /** The obligation map of an in-memory store (reflection). */
    private function chainObligations(ArrayChainedChallengeStateStore $store): array
    {
        return (new \ReflectionObject($store))->getProperty('obligations')->getValue($store);
    }

    /** The records of an in-memory challenge storage (reflection). */
    private function storageRecordCount(ArrayStorage $storage): int
    {
        return \count((new \ReflectionObject($storage))->getProperty('records')->getValue($storage));
    }

    /**
     * A controller wired for a bound or unbound stage-2 flow.
     */
    private function chainController(StorageInterface $storage, ChainedChallengeTicketService $service, RiskGateway $gateway, ?OutstandingChallenges $outstanding = null, ?SiteVerifyMetadataStore $metadataStore = null, ?RequestBindingAuthorityInterface $authority = null, ?\BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionStore $postSolveDispositionStore = null): ChallengeController
    {
        return new ChallengeController(
            $this->issuer($storage),
            null,
            true,
            $gateway,
            new ContinuityCookie(),
            outstanding: $outstanding,
            storage: $storage,
            challengeTtlSecs: 120,
            chainTickets: $service,
            metadataStore: $metadataStore,
            bindingAuthority: $authority,
            policyVersion: 1,
            postSolveDispositionStore: $postSolveDispositionStore,
        );
    }

    // ── Stage-1 verification opens the obligation-anchored chain ───────

    public function testStage1VerifyIssuesChainTicketAndCreatesTheTransactionObligation(): void
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

        // The MINIMAL ticket payload: version 1, chain id, signed expiry.
        $payload = $this->chainService($chainStore)->verify($ticket);
        self::assertIsArray($payload);
        self::assertSame(1, $payload['version'], 'the ticket format version is 1');
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{1,64}$/D', (string) $payload['chainId']);
        self::assertGreaterThan(time(), $payload['expiresAt'], 'the ticket carries the signed expiry');

        // The transaction OBLIGATION exists (one per transaction — a
        // client cannot restart at stage 1 by discarding the ticket),
        // anchored on the AUTHORITATIVE binding the authority resolved.
        $requirement = $this->chainService($chainStore)->findOpenRequirement('login', 'txn-alpha', 1);
        self::assertNotNull($requirement);
        self::assertSame((string) $payload['chainId'], $requirement->chainId, 'the open obligation IS the ticket\'s chain');
        self::assertSame(RiskAction::Argon32, $requirement->requiredAction, 'the server-held state binds the reassessed required action');
        self::assertSame(5, $requirement->requiredRank);
        self::assertSame(2, $requirement->chainDepth, 'the chain is a depth-2 selective extension');
        self::assertSame('txn-alpha', $requirement->requestBinding, 'the chain is anchored on the AUTHORITATIVE transaction binding');
        self::assertSame('login', $requirement->scope);
        self::assertSame(1, $requirement->policyVersion);
        self::assertSame('available', $requirement->state);
        self::assertNull($requirement->stage2Nonce);
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

        $requirement = $this->chainService($chainStore)->findOpenRequirement('login', 'txn-alpha', 1);
        self::assertNotNull($requirement);
        self::assertSame('txn-alpha', $requirement->requestBinding, 'the server-held state records the stage-1 challenge\'s request binding');
        self::assertNull($this->chainService($chainStore)->findOpenRequirement('login', 'txn-beta', 1), 'a different binding is a different obligation');
    }

    // ── CHAIN_REQUIRED disposition replay (expiry-preserving re-sign) ───

    public function testChainRequiredDispositionReplayReSignsWithTheOriginalExpiry(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR), $resolver);
        $disposition = new ArrayPostSolveDispositionStore();

        $stage1 = $this->solvedStage1($storage);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));

        $validator = new KiwiCaptchaValidator(
            new Verifier($storage),
            $stack,
            self::SECRET,
            enforceTelemetry: false,
            risk: $risk['gateway'],
            continuityCookie: new ContinuityCookie(),
            storage: $storage,
            chainTickets: $chainService,
            riskResolver: $resolver,
            dispositionStore: $disposition,
            bindingAuthority: new FixtureBindingAuthority('txn-alpha'),
        );
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $stage1['token'];
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        // FRESH: the reassessment demands Argon32, the canonical binding
        // resolves, the chain opens — CHAIN_REQUIRED with the signed
        // ticket and a persisted disposition.
        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $ticket = $violations[0]->getParameters()['{{ chain_ticket }}'];
        self::assertIsString($ticket);
        $payload = $this->chainService($chainStore)->verify($ticket);
        self::assertIsArray($payload);
        self::assertSame(PostSolveDispositionKind::ChainRequired, $disposition->read($stage1['nonce'])?->disposition?->kind, 'the CHAIN_REQUIRED disposition is persisted per nonce');

        // REPLAY (the SAME token — the core replays its stored result):
        // the persisted disposition reproduces CHAIN_REQUIRED and the
        // ticket is re-signed with the requirement's ORIGINAL expiry —
        // the deterministic ticket is byte-identical (a re-signed ticket
        // can never outlive its chain state).
        $violations2 = $engine->validate($dto);
        self::assertCount(1, $violations2);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations2[0]->getCode(), 'a replay of a CHAIN_REQUIRED token must be CHAIN_REQUIRED again — never a pass');
        $ticket2 = $violations2[0]->getParameters()['{{ chain_ticket }}'];
        self::assertSame($ticket, $ticket2, 'the replay re-signs with the requirement\'s ORIGINAL expiry — the deterministic ticket is byte-identical');
        $requirement = $this->chainService($chainStore)->requirementFor((string) $payload['chainId']);
        self::assertNotNull($requirement);
        self::assertSame((int) $payload['expiresAt'], $requirement->expiresAt, 'the replayed ticket carries the requirement\'s ORIGINAL expiry');
        self::assertSame(1, \count($risk['store']->observations), 'the replay must not re-run the reassessment');
    }

    public function testChainRequiredReplayWithExpiredChainIsTemporaryUnavailable(): void
    {
        $storage = new ArrayStorage();
        $chainClock = (float) time();
        $chainStore = new ArrayChainedChallengeStateStore(static function () use (&$chainClock): float {
            return $chainClock;
        });
        $chainService = $this->chainService($chainStore);
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR), $resolver);
        $disposition = new ArrayPostSolveDispositionStore();

        $stage1 = $this->solvedStage1($storage);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));

        $validator = new KiwiCaptchaValidator(
            new Verifier($storage),
            $stack,
            self::SECRET,
            enforceTelemetry: false,
            risk: $risk['gateway'],
            continuityCookie: new ContinuityCookie(),
            storage: $storage,
            chainTickets: $chainService,
            riskResolver: $resolver,
            dispositionStore: $disposition,
            bindingAuthority: new FixtureBindingAuthority('txn-alpha'),
        );
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $stage1['token'];
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        // FRESH: the chain opens and the disposition is persisted.
        $violations = $engine->validate($dto);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());

        // The chain EXPIRES with its own lifetime while the disposition
        // record survives: the replay cannot re-sign a ticket for a chain
        // that no longer exists — fail closed temporary_unavailable, never
        // a fresh ticket that outlives its chain state, never a silent
        // pass.
        $chainClock += 3600;
        $violations2 = $engine->validate($dto);
        self::assertCount(1, $violations2);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations2[0]->getCode(), 'a replay whose chain requirement is gone must be temporary_unavailable — never a ticket that outlives its chain');
        self::assertSame(PostSolveDispositionKind::ChainRequired, $disposition->read($stage1['nonce'])?->disposition?->kind, 'the persisted disposition is untouched');
    }

    public function testChainRequiredSigningIsBoundToTheDispositionsExactChain(): void
    {
        // THE CONCURRENCY SCENARIO (DEFECT A): a stage-1 token B durably
        // finalizes a CHAIN_REQUIRED(X) disposition carrying X's ORIGINAL
        // expiry (chain_expires_at); X's stage-2 challenge then VERIFIES
        // (the obligation is cleared, the chain record retained) and a
        // FRESH chain Y opens for the same transaction identity — B's
        // signing MUST reproduce (X, X.expiresAt), never Y's expiry, and
        // without any current-obligation lookup. A dead chain record (X
        // expired) is fail-closed temporary_unavailable.
        $storage = new ArrayStorage();
        $chainClock = (float) time();
        $chainStore = new ArrayChainedChallengeStateStore(static function () use (&$chainClock): float {
            return $chainClock;
        });
        $chainService = $this->chainService($chainStore, now: static function () use (&$chainClock): int {
            return (int) $chainClock;
        });
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR), $resolver);
        $disposition = new ArrayPostSolveDispositionStore();

        $stage1 = $this->solvedStage1($storage);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));

        $validator = new KiwiCaptchaValidator(
            new Verifier($storage),
            $stack,
            self::SECRET,
            enforceTelemetry: false,
            risk: $risk['gateway'],
            continuityCookie: new ContinuityCookie(),
            storage: $storage,
            chainTickets: $chainService,
            riskResolver: $resolver,
            dispositionStore: $disposition,
            bindingAuthority: new FixtureBindingAuthority('txn-alpha'),
        );
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $stage1['token'];
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        // FRESH: the reassessment opens chain X and the CHAIN_REQUIRED
        // disposition is durably finalized WITH X's expiry bound.
        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $ticket = $violations[0]->getParameters()['{{ chain_ticket }}'];
        self::assertIsString($ticket);
        $payloadX = $chainService->verify($ticket);
        self::assertIsArray($payloadX);
        $chainX = (string) $payloadX['chainId'];
        $expiryX = (int) $payloadX['expiresAt'];
        $record = $disposition->read($stage1['nonce']);
        self::assertNotNull($record);
        self::assertSame($chainX, $record->disposition?->chainId);
        self::assertSame($expiryX, $record->disposition?->chainExpiresAt, 'the disposition carries the chain\'s ORIGINAL expiry bound');

        // X's stage-2 challenge VERIFIES: the obligation is CLEARED, the
        // chain RECORD is retained and NO new chain exists — the replay of
        // B must STILL re-sign the byte-identical ticket from the
        // disposition-carried bound (no obligation lookup needed — the
        // completed-chain case).
        $stage2Nonce = $this->stageNonce('x-stage2');
        self::assertSame(ChainReservationResult::Available, $chainService->reserveStage2($chainX, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $chainService->markIssued($chainX, 'owner-a', $stage2Nonce));
        self::assertSame(ChainVerifiedResult::VerifiedNew, $chainService->markVerified($chainX, $stage2Nonce));
        self::assertNull($chainService->findOpenRequirement('login', 'txn-alpha', 1), 'X\'s obligation is cleared');
        self::assertNotNull($chainService->requirementFor($chainX), 'X\'s chain record is retained');

        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode(), 'the completed-chain replay is still CHAIN_REQUIRED — never temporary_unavailable');
        $ticket2 = $violations[0]->getParameters()['{{ chain_ticket }}'];
        self::assertSame($ticket, $ticket2, 'the completed-chain replay re-signs the byte-identical ticket from the disposition-carried bound');
        $payload2 = $chainService->verify($ticket2);
        self::assertIsArray($payload2);
        self::assertSame($chainX, (string) $payload2['chainId']);
        self::assertSame($expiryX, (int) $payload2['expiresAt']);

        // A FRESH chain Y opens for the SAME transaction identity (a new
        // stage-1 token would re-open it): B's signing MUST still produce
        // (X, X.expiresAt) — never Y's expiry, whatever the obligation now
        // points at.
        $chainY = $chainService->requireStage2($this->stageNonce('y-stage1'), 'login', 'txn-alpha', 1, RiskAction::Argon64, time() + 600);
        self::assertNotSame($chainX, $chainY->chainId, 'the cleared obligation opens a FRESH chain');
        self::assertSame($chainY->chainId, $chainService->findOpenRequirement('login', 'txn-alpha', 1)?->chainId, 'Y now owns the transaction obligation');

        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $ticket3 = $violations[0]->getParameters()['{{ chain_ticket }}'];
        self::assertSame($ticket, $ticket3, 'the ticket stays byte-identical with a concurrent chain Y open');
        $payload3 = $chainService->verify($ticket3);
        self::assertIsArray($payload3);
        self::assertSame($chainX, (string) $payload3['chainId'], 'the signing stays bound to the disposition\'s exact chain — never Y');
        self::assertSame($expiryX, (int) $payload3['expiresAt'], 'the signed expiry is X\'s ORIGINAL bound — never Y\'s');
        self::assertNotSame($chainY->expiresAt, (int) $payload3['expiresAt'], 'Y\'s expiry must never leak into X\'s ticket');

        // The record-gone case: X's chain RECORD expires with its own
        // lifetime while the disposition survives — the replay must fail
        // closed temporary_unavailable, never a ticket that outlives its
        // chain state.
        $chainClock += 3600;
        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'a disposition whose chain record is gone is temporary_unavailable — never a ticket');
        self::assertSame(PostSolveDispositionKind::ChainRequired, $disposition->read($stage1['nonce'])?->disposition?->kind, 'the persisted disposition is untouched');
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

    // ── The transaction obligation (create-or-get, never stage 1) ─────

    public function testRequireStage2CreatesExactlyOneObligationAndReturnsTheSameChain(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $nonce = $this->nonce();
        $expiry = time() + 300;

        $first = $service->requireStage2($nonce, 'login', 'txn-alpha', 1, RiskAction::Argon32, $expiry);
        $second = $service->requireStage2($nonce, 'login', 'txn-alpha', 1, RiskAction::Argon32, $expiry);

        self::assertSame($first->chainId, $second->chainId, 'a repeated stage-1 token of the same transaction returns the SAME chain');
        self::assertCount(1, $this->chainRecords($store), 'exactly ONE chain record exists');
        self::assertCount(1, $this->chainObligations($store), 'exactly ONE obligation exists');

        // A DIFFERENT policy version is a DIFFERENT obligation — an
        // old-policy chain never blocks a new-policy flow.
        $newPolicy = $service->requireStage2($nonce, 'login', 'txn-alpha', 2, RiskAction::Argon32, $expiry);
        self::assertNotSame($first->chainId, $newPolicy->chainId, 'the policy version participates in the obligation id');
        self::assertCount(2, $this->chainObligations($store));
    }

    public function testRequireStage2RaisesTheRequiredRankNeverLowers(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $nonce = $this->nonce();
        $expiry = time() + 300;

        $base = $service->requireStage2($nonce, 'login', '', 1, RiskAction::Argon32, $expiry);
        self::assertSame(RiskAction::Argon32, $base->requiredAction);
        self::assertSame(5, $base->requiredRank);

        // A STRONGER reassessment raises the floor (action + rank).
        $raised = $service->requireStage2($nonce, 'login', '', 1, RiskAction::Argon64, $expiry);
        self::assertSame($base->chainId, $raised->chainId, 'the same chain is reassessed');
        self::assertSame(RiskAction::Argon64, $raised->requiredAction, 'the floor RAISES to the stronger reassessment');
        self::assertSame(6, $raised->requiredRank);

        // A WEAKER reassessment never lowers the floor.
        $decayed = $service->requireStage2($nonce, 'login', '', 1, RiskAction::Sha16, $expiry);
        self::assertSame($base->chainId, $decayed->chainId);
        self::assertSame(RiskAction::Argon64, $decayed->requiredAction, 'the floor can never decay');
        self::assertSame(6, $decayed->requiredRank);
    }

    public function testRequireStage2RefusesNonChainableActions(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $expiry = time() + 300;

        foreach ([RiskAction::StepUp, RiskAction::Deny, RiskAction::Allow] as $action) {
            try {
                $service->requireStage2($this->nonce(), 'login', '', 1, $action, $expiry);
                self::fail('a non-chainable action must be refused: '.$action->value);
            } catch (\InvalidArgumentException $e) {
                self::assertStringContainsString('not chainable', $e->getMessage());
            }
        }
        self::assertSame([], $this->chainRecords($store), 'no chain state may be created for a non-chainable action');
    }

    public function testStaleObligationPointingAtMissingChainIsRepaired(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $expiry = time() + 300;

        $requirement = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, $expiry);
        // The chain record vanishes (its TTL passed) while the obligation
        // mapping stays — the next create-or-get compare-deletes the stale
        // mapping and creates the chain fresh (never a silent stage-1).
        $records = $this->chainRecords($store);
        unset($records[$requirement->chainId]);
        (new \ReflectionObject($store))->getProperty('records')->setValue($store, $records);

        $fresh = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, $expiry);
        self::assertNotSame($requirement->chainId, $fresh->chainId, 'the stale mapping is repaired with a fresh chain');
        self::assertSame($fresh->chainId, $service->findOpenRequirement('login', '', 1)?->chainId, 'the obligation now points at the fresh chain');
    }

    public function testChallengeRequestWithoutTicketAutoResumesTheOpenChain(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $stage1 = $this->solvedStage1($storage);
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', '', 1, RiskAction::Argon32, time() + 300);
        self::assertNotNull($requirement);

        // NO chain_ticket in the request — the open obligation resumes the
        // chain at stage 2 (never an unchained stage-1 issuance).
        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = $this->chainController($storage, $chainService, $risk['gateway']);
        $response = $controller->challenge($this->challengeRequest('{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode(), sprintf('the open chain must auto-resume: %s', (string) $response->getContent()));
        $stage2 = json_decode((string) $response->getContent(), true);
        self::assertSame('argon2id', $stage2['algorithm'], 'the auto-resumed issuance is the stronger stage-2, never a stage-1');
        self::assertSame(4, $stage2['targetBits'], 'the stage-2 floor is the Argon32 rung of the fixed-envelope ladder');
        self::assertNotSame($stage1['nonce'], $stage2['nonce'], 'the stage-2 issuance can never re-run the same stage');

        $state = $chainService->requirementFor($requirement->chainId);
        self::assertSame('issued', $state?->state, 'the auto-resumed issuance durably issued the chain');
        self::assertSame($stage2['nonce'], $state?->stage2Nonce);
    }

    public function testMaliciousDifferentTicketIsRefused(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $expiry = time() + 300;

        // Two transactions: txn-alpha and txn-beta each have their own
        // chain + ticket.
        $chainA = $chainService->requireStage2($this->nonce(), 'login', 'txn-alpha', 1, RiskAction::Argon32, $expiry);
        $chainB = $chainService->requireStage2($this->nonce(), 'login', 'txn-beta', 1, RiskAction::Argon32, $expiry);
        $ticketB = $chainService->ticketFor($chainB->chainId, $expiry);

        $risk = $this->riskStack();
        $controller = $this->chainController($storage, $chainService, $risk['gateway']);

        // Presenting txn-B's ticket for the txn-alpha transaction: the
        // obligation of the CURRENT transaction is txn-alpha's chain — the
        // foreign ticket cannot match it (its own record binds txn-beta)
        // and is refused BEFORE any admission counter moves.
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticketB, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode(), 'a malicious different ticket must be refused');
        self::assertStringContainsString('INVALID_METADATA', (string) $response->getContent());

        // The correct ticket of the same transaction still works.
        $ticketA = $chainService->ticketFor($chainA->chainId, $expiry);
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticketA, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), sprintf('the matching ticket must be honored: %s', (string) $response->getContent()));
    }

    public function testTicketForADifferentScopeIsRefused(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $expiry = time() + 300;
        $requirement = $chainService->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, $expiry);
        $ticket = $chainService->ticketFor($requirement->chainId, $expiry);

        $risk = $this->riskStackWithScopes(['login' => 1, 'signup' => 2]);
        $controller = $this->chainController($storage, $chainService, $risk['gateway']);
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'signup', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode(), 'a chain ticket is scope-bound: a different scope must be refused');
    }

    public function testTicketForADifferentPolicyEpochIsRefused(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $expiry = time() + 300;
        $requirement = $chainService->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, $expiry);
        $ticket = $chainService->ticketFor($requirement->chainId, $expiry);

        $risk = $this->riskStack();
        $controller = new ChallengeController(
            $this->issuer($storage),
            null,
            true,
            $risk['gateway'],
            new ContinuityCookie(),
            storage: $storage,
            challengeTtlSecs: 120,
            chainTickets: $chainService,
            policyVersion: 2,
        );
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode(), 'a chain ticket is bound to the policy epoch it was issued under');
    }

    // ── The AUTHORITATIVE request binding (the authority, never the
    //    client string) ─────────────────────────────────────────────────

    public function testClientChangedPresentedBindingIsRejectedByTheAuthority(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore, authority: new FixtureBindingAuthority('txn-alpha'));
        $stage1 = $this->solvedStage1($storage);
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', 'txn-alpha', 1, RiskAction::Argon32, time() + 300);
        $ticket = $chainService->ticketFor($requirement->chainId, time() + 300);

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = $this->chainController($storage, $chainService, $risk['gateway'], authority: new FixtureBindingAuthority('txn-alpha'));

        // The client presents a CHANGED binding: the authority refuses it
        // (422) BEFORE any state is touched — the raw client string is
        // never signed.
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => 'txn-beta'], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode(), 'a client-changed presented binding refused by the authority must be refused');
        self::assertStringContainsString('INVALID_REQUEST_BINDING', (string) $response->getContent());

        // The authoritative binding is accepted end-to-end.
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), sprintf('the authoritative binding must be honored: %s', (string) $response->getContent()));
    }

    public function testMaliciousDifferentAuthoritativeBindingIsRefused(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore, authority: new FixtureBindingAuthority('txn-alpha'));
        $stage1 = $this->solvedStage1($storage);
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', 'txn-alpha', 1, RiskAction::Argon32, time() + 300);
        $ticket = $chainService->ticketFor($requirement->chainId, time() + 300);

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        // The transaction's authoritative binding MOVED to txn-beta (the
        // authority now resolves it): the chain anchored on txn-alpha can
        // no longer match the current transaction — the ticket is refused.
        $controller = $this->chainController($storage, $chainService, $risk['gateway'], authority: new FixtureBindingAuthority('txn-beta'));
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode(), 'a ticket whose chain anchors a DIFFERENT authoritative binding must be refused');
        self::assertStringContainsString('INVALID_METADATA', (string) $response->getContent());
    }

    public function testAuthorityResolvedBindingIsTheAnchorNeverThePresentedString(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        // The authority IGNORES the presented value and resolves the fixed
        // authoritative binding 'txn-auth' for this transaction.
        $chainService = $this->chainService($chainStore, authority: new FixtureBindingAuthority('txn-auth', ignorePresented: true));
        $stage1 = $this->solvedStage1($storage);
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', 'txn-auth', 1, RiskAction::Argon32, time() + 300);
        $ticket = $chainService->ticketFor($requirement->chainId, time() + 300);

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = $this->chainController($storage, $chainService, $risk['gateway'], authority: new FixtureBindingAuthority('txn-auth', ignorePresented: true));

        // The client presents a DIFFERENT string ('txn-client'): it is a
        // HINT only — the issuance anchors on the authority's resolution
        // and succeeds (the presented string was never signed).
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => 'txn-client'], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), sprintf('the authority (not the presented string) anchors the transaction: %s', (string) $response->getContent()));
        $state = $chainService->requirementFor($requirement->chainId);
        self::assertSame('issued', $state?->state);
        self::assertSame('txn-auth', $state?->requestBinding, 'the chain stays anchored on the AUTHORITATIVE binding');
    }

    // ── The state machine (available/reserved/issued/verified) ─────────

    public function testReserveAvailableRetryBusyAndOwnerReleaseFreesIt(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $requirement = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, time() + 300);

        // available -> reserved(ownerA) (the reservation is the issuance claim).
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'), 'the first reserve transitions available -> reserved');
        self::assertSame(ChainReservationResult::Retry, $service->reserveStage2($requirement->chainId, 'owner-a'), 'reserve by the SAME owner is a retry');
        self::assertSame(ChainReservationResult::Busy, $service->reserveStage2($requirement->chainId, 'owner-b'), 'reserve by another owner with a live lease is busy');

        // A non-owner can neither issue nor release the reservation.
        self::assertSame(ChainIssuedResult::NotOwner, $service->markIssued($requirement->chainId, 'owner-b', 'n2'), 'a non-owner markIssued is an atomic no-op');
        $service->release($requirement->chainId, 'owner-b');
        self::assertSame('reserved', $service->requirementFor($requirement->chainId)?->state, 'a non-owner release does not free the reservation');
        self::assertSame('owner-a', $service->requirementFor($requirement->chainId)?->owner);

        // The owner's release returns the chain to available — the ticket
        // stays reusable.
        $service->release($requirement->chainId, 'owner-a');
        self::assertSame('available', $service->requirementFor($requirement->chainId)?->state);
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-c'), 'the released chain is reservable again');
    }

    public function testExpiredLeaseIsTakenOverBeforeTicketExpiry(): void
    {
        // The clock variant: the Array store runs on an explicit clock so
        // the SHORT reservation lease expiry is enforceable (mirroring
        // redis TIME on the production store). t=0: owner A reserves with
        // the 15s lease; t=10: owner B -> busy; t=16: owner B's takeover
        // succeeds — while the ticket still has ~284s of its 300s life.
        $clock = 1000;
        $store = new ArrayChainedChallengeStateStore(static function () use (&$clock): float {
            return $clock;
        });
        $service = new ChainedChallengeTicketService(
            $store,
            self::SECRET,
            300,
            15,
            now: static fn (): int => 1000,
        );
        $requirement = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, 1300);

        // t=0: owner A reserves with the SHORT 15s lease.
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
        self::assertSame(1015, $service->requirementFor($requirement->chainId)?->leaseUntil, 'the lease is now + min(15, remaining TTL)');

        // t=10: the lease is live — owner B is busy.
        $clock = 1010;
        self::assertSame(ChainReservationResult::Busy, $service->reserveStage2($requirement->chainId, 'owner-b'), 'the live lease refuses another owner');

        // t=16: the 15s lease expired — owner B TAKES OVER with a fresh
        // lease while the ticket still has ~284s of its 300s life.
        $clock = 1016;
        self::assertSame(ChainReservationResult::TakenOver, $service->reserveStage2($requirement->chainId, 'owner-b'), 'an expired lease is taken over by the next reserving owner');
        $requirementB = $service->requirementFor($requirement->chainId);
        self::assertSame('owner-b', $requirementB?->owner);
        self::assertSame(1031, $requirementB?->leaseUntil, 'the takeover owner holds a fresh SHORT lease');
        self::assertSame(1300, $requirementB?->expiresAt, 'the whole record still expires with the signed ticket (t+300)');
        self::assertGreaterThanOrEqual(284, 1300 - 1016, 'the ticket still has ~284s at the takeover moment');

        // Past the record TTL the chain is gone entirely.
        $clock = 1301;
        self::assertSame(ChainReservationResult::Missing, $service->reserveStage2($requirement->chainId, 'owner-c'), 'the whole record expires with the signed ticket');
        self::assertNull($service->requirementFor($requirement->chainId));
    }

    public function testReserveAnswersIssuedVerifiedAndMissing(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $requirement = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, time() + 300);

        // issued: the reserve answers 'issued' (recover, never re-mint).
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', $this->stageNonce('stage2-nonce')));
        self::assertSame(ChainReservationResult::Issued, $service->reserveStage2($requirement->chainId, 'owner-b'));

        // verified: the reserve answers 'verified' (terminal).
        self::assertSame(ChainVerifiedResult::VerifiedNew, $service->markVerified($requirement->chainId, $this->stageNonce('stage2-nonce')));
        self::assertSame(ChainReservationResult::Verified, $service->reserveStage2($requirement->chainId, 'owner-b'));

        // absent.
        self::assertSame(ChainReservationResult::Missing, $service->reserveStage2('no-such-chain', 'owner-a'));
    }

    public function testChainRecordWithoutExpiryIsCorruptedStateFailClosed(): void
    {
        // A chain record WITHOUT an expiry must fail closed (Malformed —
        // the reserve transition throws) — never manufacture a lifetime
        // from the configured TTL.
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $requirement = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, time() + 300);

        $records = $this->chainRecords($store);
        unset($records[$requirement->chainId]['expiresAt']);
        (new \ReflectionObject($store))->getProperty('records')->setValue($store, $records);

        $this->expectException(MalformedChainedChallengeStateException::class);
        $store->reserve($requirement->chainId, 'owner-a', 15);
    }

    // ── markIssued (idempotent, lost-reply, issued-not-terminal) ───────

    public function testMarkIssuedIdempotentSameNonceRetry(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $requirement = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, time() + 300);

        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', $this->stageNonce('stage2-nonce')));
        self::assertSame('issued', $service->requirementFor($requirement->chainId)?->state);
        self::assertSame($this->stageNonce('stage2-nonce'), $service->requirementFor($requirement->chainId)?->stage2Nonce);

        // The same-nonce retry is CONFIRMED, never a second mint.
        self::assertSame(ChainIssuedResult::IssuedSame, $service->markIssued($requirement->chainId, 'owner-a', $this->stageNonce('stage2-nonce')), 'a same-nonce retry is idempotent');
        self::assertSame(ChainIssuedResult::IssuedSame, $service->markIssued($requirement->chainId, 'owner-b', $this->stageNonce('stage2-nonce')), 'the idempotent confirmation does not need the owner');
    }

    public function testMarkIssuedDifferentNonceConflict(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $requirement = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, time() + 300);

        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', $this->stageNonce('stage2-nonce')));
        self::assertSame(ChainIssuedResult::Conflict, $service->markIssued($requirement->chainId, 'owner-a', $this->stageNonce('other-nonce')), 'a different nonce is a conflict — one issuance per chain');
        self::assertSame($this->stageNonce('stage2-nonce'), $service->requirementFor($requirement->chainId)?->stage2Nonce, 'the first issuance stays authoritative');
    }

    public function testMarkIssuedLostReplyIsRecoveredByReadingTheState(): void
    {
        $storage = new ArrayStorage();
        $client = new AbortAwareFakeRedis();
        $outstanding = new OutstandingChallenges($client, '{kiwi:chain-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $lostReply = new LostReplyChainStore(new ArrayChainedChallengeStateStore(), throwAfterIssued: true);
        $chainService = $this->chainService($lostReply);
        $stage1 = $this->solvedStage1($storage);
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', '', 1, RiskAction::Argon32, time() + 300);
        $ticket = $chainService->ticketFor($requirement->chainId, time() + 300);

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = $this->chainController($storage, $chainService, $risk['gateway'], outstanding: $outstanding);

        // The FIRST request's markIssued runs the REAL transition then
        // throws (a lost reply). The controller READS the chain state:
        // issued with the current nonce -> the operation SUCCEEDED —
        // continue, never delete the minted challenge.
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), sprintf('a lost-reply issuance must be recovered by reading the state: %s', (string) $response->getContent()));
        $nonce = json_decode((string) $response->getContent(), true)['nonce'];

        $state = $chainService->requirementFor($requirement->chainId);
        self::assertSame('issued', $state?->state, 'the chain is durably issued');
        self::assertSame($nonce, $state?->stage2Nonce);
        self::assertNotNull($storage->find($nonce), 'the minted challenge is RETAINED (never delete state that may be authoritative)');

        // The challenge WAS handed out: the outstanding slot is NOT rolled
        // back.
        $sourceKey = '{kiwi:chain-test}:outstanding:'.hash_hmac('sha256', Issuer::canonicalIpFamily('198.51.100.7'), RiskKeys::fromMaster(self::SECRET)->event);
        self::assertSame(1, $client->counters[$sourceKey] ?? 0);
    }

    public function testIssuedResponseLostNextRequestReturnsTheExactSameChallenge(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $stage1 = $this->solvedStage1($storage);
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', '', 1, RiskAction::Argon32, time() + 300);
        $ticket = $chainService->ticketFor($requirement->chainId, time() + 300);

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = $this->chainController($storage, $chainService, $risk['gateway']);

        // The FIRST request issues the stage-2 challenge — the response is
        // then LOST (simulated by a second request instead of a solve).
        $first = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $first->getStatusCode());
        $firstNonce = json_decode((string) $first->getContent(), true)['nonce'];

        // The SECOND request with the SAME ticket: the chain is ISSUED —
        // the retry RECOVERS the already-issued challenge: the SAME
        // nonce, byte-identical response, NO second challenge record, NO
        // re-admission.
        $recordCount = $this->storageRecordCount($storage);
        $second = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $second->getStatusCode(), sprintf('an issued chain must recover on retry: %s', (string) $second->getContent()));
        self::assertSame((string) $first->getContent(), (string) $second->getContent(), 'the recovery response must be byte-identical to the lost response');
        self::assertSame($firstNonce, json_decode((string) $second->getContent(), true)['nonce'], 'the recovery returns the SAME issued nonce');
        self::assertSame($recordCount, $this->storageRecordCount($storage), 'an issued chain NEVER re-mints — no second challenge record');
    }

    public function testIssuedStateIsNotTerminal(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $requirement = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, time() + 300);

        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', $this->stageNonce('stage2-nonce')));

        // issued is NOT terminal: the chain can be REARMED for a fresh
        // stage-2 mint and VERIFIED by a solved stage-2.
        self::assertTrue($service->rearmIssued($requirement->chainId, $this->stageNonce('stage2-nonce')), 'an issued chain rearms for a fresh stage-2 mint');
        self::assertSame('available', $service->requirementFor($requirement->chainId)?->state);
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-b'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-b', $this->stageNonce('stage2-nonce-b')));
        self::assertSame(ChainVerifiedResult::VerifiedNew, $service->markVerified($requirement->chainId, $this->stageNonce('stage2-nonce-b')), 'the issued stage verifies — the chain ends');
    }

    // ── markVerified (TERMINAL, obligation cleared atomically) ─────────

    public function testMarkVerifiedIssuedToVerifiedAndIdempotent(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $requirement = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, time() + 300);

        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', $this->stageNonce('stage2-nonce')));
        self::assertSame(ChainVerifiedResult::VerifiedNew, $service->markVerified($requirement->chainId, $this->stageNonce('stage2-nonce')));

        $state = $service->requirementFor($requirement->chainId);
        self::assertSame('verified', $state?->state, 'verified is the TERMINAL state');
        self::assertSame($this->stageNonce('stage2-nonce'), $state?->stage2Nonce);
        self::assertSame(ChainVerifiedResult::VerifiedSame, $service->markVerified($requirement->chainId, $this->stageNonce('stage2-nonce')), 'a same-nonce retry is idempotent');
        self::assertNull($service->findOpenRequirement('login', '', 1), 'the verified transition cleared the obligation — the transaction is complete');
    }

    public function testMarkVerifiedClearsTheObligationOnlyWhenItStillPointsAtThisChain(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $expiry = time() + 300;
        $chainA = $service->requireStage2($this->nonce(), 'login', 'txn-a', 1, RiskAction::Argon32, $expiry);
        $chainB = $service->requireStage2($this->nonce(), 'login', 'txn-b', 1, RiskAction::Argon32, $expiry);

        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($chainA->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($chainA->chainId, 'owner-a', $this->stageNonce('n-a')));
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($chainB->chainId, 'owner-b'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($chainB->chainId, 'owner-b', $this->stageNonce('n-b')));

        // The obligation id of chain A (captured BEFORE the verification
        // clears it).
        $obligations = $this->chainObligations($store);
        $obligationA = array_search($chainA->chainId, $obligations, true);
        self::assertIsString($obligationA);

        // Verify chain A: ONLY A's obligation is cleared — B's stays.
        self::assertSame(ChainVerifiedResult::VerifiedNew, $service->markVerified($chainA->chainId, $this->stageNonce('n-a')));
        self::assertNull($service->findOpenRequirement('login', 'txn-a', 1));
        self::assertSame($chainB->chainId, $service->findOpenRequirement('login', 'txn-b', 1)?->chainId, 'B\'s obligation is untouched');

        // The compare-delete guard: when the obligation NO LONGER points
        // at this chain (repointed at B), a stale delete must never unlink
        // B's live mapping.
        $obligations = $this->chainObligations($store);
        $obligations[$obligationA] = $chainB->chainId;
        (new \ReflectionObject($store))->getProperty('obligations')->setValue($store, $obligations);
        $store->deleteObligation($chainA->chainId, $obligationA);
        self::assertSame($chainB->chainId, $service->findOpenRequirement('login', 'txn-b', 1)?->chainId, 'a stale compare-delete must never unlink a live mapping');
    }

    public function testMarkVerifiedDifferentNonceConflict(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $requirement = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, time() + 300);

        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', $this->stageNonce('stage2-nonce')));
        self::assertSame(ChainVerifiedResult::Conflict, $service->markVerified($requirement->chainId, $this->stageNonce('other-nonce')), 'a different nonce is a conflict');
        self::assertSame('issued', $service->requirementFor($requirement->chainId)?->state, 'the chain stays issued — nothing was verified');
    }

    // ── markStepUpRequired / markDenied (TERMINAL, obligation KEPT) ────

    public function testMarkStepUpRequiredIsTerminalIdempotentAndKeepsTheObligation(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $requirement = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, time() + 300);

        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', $this->stageNonce('stage2-nonce')));
        self::assertSame(ChainVerifiedResult::StepUpRequiredNew, $service->markStepUpRequired($requirement->chainId, $this->stageNonce('stage2-nonce')));

        $state = $service->requirementFor($requirement->chainId);
        self::assertSame('step_up_required', $state?->state, 'step_up_required is the TERMINAL state');
        self::assertSame($this->stageNonce('stage2-nonce'), $state?->stage2Nonce);
        self::assertSame(ChainVerifiedResult::StepUpRequiredSame, $service->markStepUpRequired($requirement->chainId, $this->stageNonce('stage2-nonce')), 'a same-nonce retry is idempotent');
        self::assertSame(ChainVerifiedResult::Conflict, $service->markStepUpRequired($requirement->chainId, $this->stageNonce('other-nonce')), 'a different nonce on a TERMINAL state is a conflict');
        self::assertSame(ChainVerifiedResult::Conflict, $service->markVerified($requirement->chainId, $this->stageNonce('stage2-nonce')), 'a terminal step-up chain can never verify');
        self::assertSame(ChainVerifiedResult::Conflict, $service->markDenied($requirement->chainId, $this->stageNonce('stage2-nonce')), 'a terminal step-up chain can never be denied');
        self::assertNotNull($service->findOpenRequirement('login', '', 1), 'the step-up transition KEEPS the obligation — the transaction stays bound');
        self::assertSame(ChainReservationResult::StepUpRequired, $service->reserveStage2($requirement->chainId, 'owner-b'), 'the reserve answers the TERMINAL step_up_required state');
    }

    public function testMarkDeniedIsTerminalIdempotentAndKeepsTheObligation(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $requirement = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, time() + 300);

        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', $this->stageNonce('stage2-nonce')));
        self::assertSame(ChainVerifiedResult::DeniedNew, $service->markDenied($requirement->chainId, $this->stageNonce('stage2-nonce')));

        $state = $service->requirementFor($requirement->chainId);
        self::assertSame('denied', $state?->state, 'denied is the TERMINAL state');
        self::assertSame($this->stageNonce('stage2-nonce'), $state?->stage2Nonce);
        self::assertSame(ChainVerifiedResult::DeniedSame, $service->markDenied($requirement->chainId, $this->stageNonce('stage2-nonce')), 'a same-nonce retry is idempotent');
        self::assertSame(ChainVerifiedResult::Conflict, $service->markDenied($requirement->chainId, $this->stageNonce('other-nonce')), 'a different nonce on a TERMINAL state is a conflict');
        self::assertSame(ChainVerifiedResult::Conflict, $service->markVerified($requirement->chainId, $this->stageNonce('stage2-nonce')), 'a terminal denied chain can never verify');
        self::assertSame(ChainVerifiedResult::Conflict, $service->markStepUpRequired($requirement->chainId, $this->stageNonce('stage2-nonce')), 'a terminal denied chain can never step up');
        self::assertSame(ChainIssuedResult::Conflict, $service->markIssued($requirement->chainId, 'owner-b', $this->stageNonce('stage2-nonce')), 'a terminal chain can never be issued again');
        self::assertFalse($service->rearmIssued($requirement->chainId, $this->stageNonce('stage2-nonce')), 'a terminal chain can never rearm');
        self::assertNotNull($service->findOpenRequirement('login', '', 1), 'the denied transition KEEPS the obligation — the transaction stays bound');
        self::assertSame(ChainReservationResult::Denied, $service->reserveStage2($requirement->chainId, 'owner-b'), 'the reserve answers the TERMINAL denied state');
    }

    public function testMarkStepUpRequiredAndMarkDeniedAcceptTheLegacyCompletedState(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $requirement = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, time() + 300);
        $nonce = $this->stageNonce('stage2-nonce');

        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
        $completed = $service->complete($requirement->chainId, 'owner-a', $nonce);
        self::assertIsArray($completed);

        // The legacy 'completed' state is semantically identical to
        // 'issued': the disposition terminal transitions accept it.
        self::assertSame(ChainVerifiedResult::StepUpRequiredNew, $service->markStepUpRequired($requirement->chainId, $nonce));
        self::assertSame('step_up_required', $service->requirementFor($requirement->chainId)?->state);
    }

    public function testMarkVerifiedLostReplyReadConfirmsTheTransition(): void
    {
        $storage = new ArrayStorage();
        $lostReply = new LostReplyChainStore(new ArrayChainedChallengeStateStore(), throwAfterVerified: true);
        $chainService = $this->chainService($lostReply);
        $dispositions = new \BelConsulting\KiwiCaptchaBundle\Risk\ArrayPostSolveDispositionStore();
        $stage1 = $this->solvedStage1($storage);
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', '', 1, RiskAction::Argon32, time() + 300);
        $ticket = $chainService->ticketFor($requirement->chainId, time() + 300);

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = $this->chainController($storage, $chainService, $risk['gateway'], postSolveDispositionStore: $dispositions);

        // Request 1: issue the stage-2 challenge.
        $first = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $first->getStatusCode());
        $nonce = json_decode((string) $first->getContent(), true)['nonce'];

        // The client SOLVES the stage-2 challenge: the validator commits
        // the consumed VALID result AND durably finalizes the PASS
        // disposition (the FINAL disposition — the chain transition runs
        // only after the finalize).
        $storage->consume($nonce);
        $storage->commitResult($nonce, true, null);
        $dispositions->claim($nonce, 'disposition-owner', 300);
        $dispositions->finalize($nonce, 'disposition-owner', new \BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDisposition(\BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind::Pass));

        // Request 2: the issued stage-2 is consumed+VALID with a committed
        // PASS disposition — the controller transitions to verified; the
        // transition runs the REAL transition then throws (a lost reply):
        // the state is read + the exact nonce confirmed — the chain ends
        // (the obligation is cleared) and the same challenge is recovered.
        $second = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $second->getStatusCode(), sprintf('a lost markVerified reply must be read-confirmed: %s', (string) $second->getContent()));
        self::assertSame($nonce, json_decode((string) $second->getContent(), true)['nonce'], 'the verified stage recovers the same challenge');

        $state = $chainService->requirementFor($requirement->chainId);
        self::assertSame('verified', $state?->state, 'the chain is TERMINAL verified');
        self::assertNull($chainService->findOpenRequirement('login', '', 1), 'the obligation is cleared atomically with the verified transition');
    }

    // ── rearm (fresh stage-2, never stage 1) ───────────────────────────

    public function testExpiredStage2ChallengeIsRearmedNeverStage1(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $stage1 = $this->solvedStage1($storage);
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', '', 1, RiskAction::Argon32, time() + 300);
        $ticket = $chainService->ticketFor($requirement->chainId, time() + 300);

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = $this->chainController($storage, $chainService, $risk['gateway']);

        // Request 1: issue the stage-2 challenge, then the record
        // EXPIRES/vanishes (never reached the client).
        $first = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $first->getStatusCode());
        $oldNonce = json_decode((string) $first->getContent(), true)['nonce'];
        $storage->delete($oldNonce);

        // Request 2: the issued stage-2 is missing — the chain REARMS and
        // mints a FRESH stage-2 challenge (the argon floor, never a
        // stage-1 sha).
        $second = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $second->getStatusCode(), sprintf('an expired stage-2 must rearm for a fresh stage-2: %s', (string) $second->getContent()));
        $stage2 = json_decode((string) $second->getContent(), true);
        self::assertSame('argon2id', $stage2['algorithm'], 'the rearmed issuance is STILL the stage-2 floor — never a stage-1');
        self::assertSame(4, $stage2['targetBits']);
        self::assertNotSame($oldNonce, $stage2['nonce'], 'the rearmed issuance is a NEW stage-2 challenge');

        $state = $chainService->requirementFor($requirement->chainId);
        self::assertSame('issued', $state?->state, 'the rearmed issuance durably issued the chain again');
        self::assertSame($stage2['nonce'], $state?->stage2Nonce);
        self::assertNotNull($chainService->findOpenRequirement('login', '', 1), 'the transaction obligation stays open at stage 2');
    }

    public function testConsumedValidStage2VerifiesInsteadOfReissuing(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $dispositions = new \BelConsulting\KiwiCaptchaBundle\Risk\ArrayPostSolveDispositionStore();
        $stage1 = $this->solvedStage1($storage);
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', '', 1, RiskAction::Argon32, time() + 300);
        $ticket = $chainService->ticketFor($requirement->chainId, time() + 300);

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = $this->chainController($storage, $chainService, $risk['gateway'], postSolveDispositionStore: $dispositions);

        // Request 1: issue the stage-2 challenge.
        $first = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $first->getStatusCode());
        $nonce = json_decode((string) $first->getContent(), true)['nonce'];

        // The client SOLVES it: consumed + committed VALID, and the
        // validator durably finalized the PASS disposition (the FINAL
        // disposition — the chain transition runs only after the
        // finalize).
        $storage->consume($nonce);
        $storage->commitResult($nonce, true, null);
        $dispositions->claim($nonce, 'disposition-owner', 300);
        $dispositions->finalize($nonce, 'disposition-owner', new \BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDisposition(\BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind::Pass));
        $recordCount = $this->storageRecordCount($storage);

        // Request 2: consumed+VALID with a committed PASS disposition —
        // the chain VERIFIES (no re-issue), the same challenge is
        // recovered and the obligation is cleared.
        $second = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $second->getStatusCode(), sprintf('a consumed-valid stage-2 must verify the chain: %s', (string) $second->getContent()));
        self::assertSame((string) $first->getContent(), (string) $second->getContent(), 'the verified stage recovers the exact challenge');
        self::assertSame($recordCount, $this->storageRecordCount($storage), 'no re-mint for a consumed-valid stage');
        self::assertSame('verified', $chainService->requirementFor($requirement->chainId)?->state);
        self::assertNull($chainService->findOpenRequirement('login', '', 1), 'a verified chain has no open obligation');
    }

    public function testConsumedValidStage2WithoutCommittedDispositionIs503AndObligationIntact(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $dispositions = new \BelConsulting\KiwiCaptchaBundle\Risk\ArrayPostSolveDispositionStore();
        $stage1 = $this->solvedStage1($storage);
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', '', 1, RiskAction::Argon32, time() + 300);
        $ticket = $chainService->ticketFor($requirement->chainId, time() + 300);

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = $this->chainController($storage, $chainService, $risk['gateway'], postSolveDispositionStore: $dispositions);

        // Request 1: issue the stage-2 challenge.
        $first = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $first->getStatusCode());
        $nonce = json_decode((string) $first->getContent(), true)['nonce'];

        // The CRASH WINDOW: the validator committed the consumed VALID
        // core result but DIED before finalizing the disposition — the
        // core result alone can never decide transaction terminality.
        $storage->consume($nonce);
        $storage->commitResult($nonce, true, null);

        // The retry: consumed+VALID WITHOUT a committed disposition — the
        // retryable 503, and the obligation is NEVER cleared.
        $second = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(503, $second->getStatusCode(), 'a consumed-valid stage-2 without a committed disposition is the retryable 503');
        self::assertSame('issued', $chainService->requirementFor($requirement->chainId)?->state, 'the chain is NOT verified without the final disposition');
        self::assertSame($nonce, $chainService->requirementFor($requirement->chainId)?->stage2Nonce);
        self::assertNotNull($chainService->findOpenRequirement('login', '', 1), 'the obligation SURVIVES the crash window');

        // The disposition is durably finalized as PASS: the next retry
        // ends the chain and clears the obligation.
        $dispositions->claim($nonce, 'disposition-owner', 300);
        $dispositions->finalize($nonce, 'disposition-owner', new \BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDisposition(\BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind::Pass));
        $third = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $third->getStatusCode(), sprintf('after the PASS disposition is committed the retry verifies the chain: %s', (string) $third->getContent()));
        self::assertSame('verified', $chainService->requirementFor($requirement->chainId)?->state);
        self::assertNull($chainService->findOpenRequirement('login', '', 1), 'the PASS disposition cleared the obligation');
    }

    public function testConsumedValidStage2StepUpDispositionTerminalStepUpResponse(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $dispositions = new \BelConsulting\KiwiCaptchaBundle\Risk\ArrayPostSolveDispositionStore();
        $stage1 = $this->solvedStage1($storage);
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', '', 1, RiskAction::Argon32, time() + 300);
        $ticket = $chainService->ticketFor($requirement->chainId, time() + 300);

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = $this->chainController($storage, $chainService, $risk['gateway'], postSolveDispositionStore: $dispositions);

        // Request 1: issue the stage-2 challenge.
        $first = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $first->getStatusCode());
        $nonce = json_decode((string) $first->getContent(), true)['nonce'];

        // The validator committed the consumed VALID result AND durably
        // finalized the STEP-UP disposition (the chain transition runs
        // only after the finalize).
        $storage->consume($nonce);
        $storage->commitResult($nonce, true, null);
        $dispositions->claim($nonce, 'disposition-owner', 300);
        $dispositions->finalize($nonce, 'disposition-owner', new \BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDisposition(\BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind::StepUp));

        // The retry: consumed+VALID with a STEP-UP disposition — the
        // chain transitions to the TERMINAL step_up_required and the
        // request answers the terminal STEP_UP_REQUIRED — never a
        // challenge.
        $second = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(403, $second->getStatusCode(), 'a consumed-valid stage-2 with a STEP-UP disposition is the terminal STEP_UP_REQUIRED');
        self::assertStringContainsString('STEP_UP_REQUIRED', (string) $second->getContent());
        $state = $chainService->requirementFor($requirement->chainId);
        self::assertSame('step_up_required', $state?->state, 'the chain is TERMINAL step_up_required');
        self::assertSame($nonce, $state?->stage2Nonce);
        self::assertNotNull($chainService->findOpenRequirement('login', '', 1), 'the obligation SURVIVES the step-up — the transaction stays bound');

        // A LATER request for the same transaction re-encounters the
        // TERMINAL state (the obligation is kept — never a new stage-1,
        // never a challenge).
        $third = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(403, $third->getStatusCode(), 'a later request re-encounters the terminal step-up response');
        self::assertStringContainsString('STEP_UP_REQUIRED', (string) $third->getContent());
        self::assertSame('step_up_required', $chainService->requirementFor($requirement->chainId)?->state);
    }

    public function testConsumedValidStage2DenyDispositionTerminalDenialResponse(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $dispositions = new \BelConsulting\KiwiCaptchaBundle\Risk\ArrayPostSolveDispositionStore();
        $stage1 = $this->solvedStage1($storage);
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', '', 1, RiskAction::Argon32, time() + 300);
        $ticket = $chainService->ticketFor($requirement->chainId, time() + 300);

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = $this->chainController($storage, $chainService, $risk['gateway'], postSolveDispositionStore: $dispositions);

        // Request 1: issue the stage-2 challenge.
        $first = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $first->getStatusCode());
        $nonce = json_decode((string) $first->getContent(), true)['nonce'];

        // The validator committed the consumed VALID result AND durably
        // finalized the DENY disposition.
        $storage->consume($nonce);
        $storage->commitResult($nonce, true, null);
        $dispositions->claim($nonce, 'disposition-owner', 300);
        $dispositions->finalize($nonce, 'disposition-owner', new \BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDisposition(\BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind::Deny));

        // The retry: consumed+VALID with a DENY disposition — the chain
        // transitions to the TERMINAL denied and the request answers the
        // terminal risk-denied response — never a challenge.
        $second = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(429, $second->getStatusCode(), 'a consumed-valid stage-2 with a DENY disposition is the terminal risk-denied response');
        self::assertStringContainsString('RISK_DENIED', (string) $second->getContent());
        $state = $chainService->requirementFor($requirement->chainId);
        self::assertSame('denied', $state?->state, 'the chain is TERMINAL denied');
        self::assertSame($nonce, $state?->stage2Nonce);
        self::assertNotNull($chainService->findOpenRequirement('login', '', 1), 'the obligation SURVIVES the denial — the transaction stays bound');

        // A LATER request for the same transaction re-encounters the
        // TERMINAL state (the obligation is kept — never a new stage-1,
        // never a challenge).
        $third = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(429, $third->getStatusCode(), 'a later request re-encounters the terminal denial response');
        self::assertStringContainsString('RISK_DENIED', (string) $third->getContent());
        self::assertSame('denied', $chainService->requirementFor($requirement->chainId)?->state);
    }

    public function testConsumedStage2WithoutCommittedResultIsTemporaryUnavailableNeverRearms(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $stage1 = $this->solvedStage1($storage);
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', '', 1, RiskAction::Argon32, time() + 300);
        $ticket = $chainService->ticketFor($requirement->chainId, time() + 300);

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = $this->chainController($storage, $chainService, $risk['gateway']);

        // Request 1: issue the stage-2 challenge.
        $first = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $first->getStatusCode());
        $nonce = json_decode((string) $first->getContent(), true)['nonce'];

        // The challenge is CONSUMED but the result is NOT committed (the
        // verifying request crashed mid-flight) — INDETERMINATE: NEVER
        // rearm while the first may have been consumed successfully.
        $storage->consume($nonce);

        $second = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(503, $second->getStatusCode(), 'a consumed-without-result stage-2 is the retryable temporary_unavailable');
        $state = $chainService->requirementFor($requirement->chainId);
        self::assertSame('issued', $state?->state, 'the chain is NOT rearmed — the first consumption may have succeeded');
        self::assertSame($nonce, $state?->stage2Nonce);
        self::assertNotNull($storage->find($nonce), 'the consumed record is retained');
    }

    public function testConsumedInvalidStage2RearmsSubjectToAdmission(): void
    {
        $storage = new ArrayStorage();
        $client = new AbortAwareFakeRedis();
        $outstanding = new OutstandingChallenges($client, '{kiwi:chain-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $stage1 = $this->solvedStage1($storage);
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', '', 1, RiskAction::Argon32, time() + 300);
        $ticket = $chainService->ticketFor($requirement->chainId, time() + 300);

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = $this->chainController($storage, $chainService, $risk['gateway'], outstanding: $outstanding);

        // Request 1: issue the stage-2 challenge; the client's solve was
        // committed INVALID (consumed + result false).
        $first = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $first->getStatusCode());
        $oldNonce = json_decode((string) $first->getContent(), true)['nonce'];
        $storage->consume($oldNonce);
        $storage->commitResult($oldNonce, false, null);

        // Request 2: the committed-INVALID stage REARMS and the pipeline
        // runs again (subject to admission) — a fresh stage-2 challenge.
        $second = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $second->getStatusCode(), sprintf('a committed-INVALID stage-2 rearms subject to admission: %s', (string) $second->getContent()));
        $newNonce = json_decode((string) $second->getContent(), true)['nonce'];
        self::assertNotSame($oldNonce, $newNonce);
        self::assertSame('argon2id', json_decode((string) $second->getContent(), true)['algorithm'], 'the rearmed issuance is still the stage-2 floor');

        // ADMISSION-REFUSED rearm: saturate the outstanding counter and
        // let the invalid-committed stage try again — the rearm is subject
        // to the pipeline: 429, and the chain is released back to
        // available (the ticket stays usable).
        $storage->consume($newNonce);
        $storage->commitResult($newNonce, false, null);
        $sourceKey = '{kiwi:chain-test}:outstanding:'.hash_hmac('sha256', Issuer::canonicalIpFamily('198.51.100.7'), RiskKeys::fromMaster(self::SECRET)->event);
        $client->counters[$sourceKey] = 5;

        $third = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(429, $third->getStatusCode(), 'the rearmed issuance is subject to the outstanding admission');
        self::assertSame('available', $chainService->requirementFor($requirement->chainId)?->state, 'the refused pipeline released the reservation — the ticket stays usable');
    }

    // ── Strict v2 decoding (ALL-OR-NOTHING, one test per corruption) ───

    /**
     * @return iterable<string, array{0: string, 1: array{0: string, 1: string, 2: mixed}, 2: string}>
     */
    public static function corruptRecordProvider(): iterable
    {
        $set = static fn (string $field, mixed $value): array => ['set', $field, $value];
        $unset = static fn (string $field): array => ['unset', $field, null];

        yield 'unknown schema version' => ['v', $set('v', 1), 'available'];
        yield 'missing schema version' => ['v', $unset('v'), 'available'];
        yield 'non-integer schema version' => ['v', $set('v', '2'), 'available'];
        yield 'bad nonce shape (hex, not Kiwi base64)' => ['stage1Nonce', $set('stage1Nonce', bin2hex(random_bytes(32))), 'available'];
        yield 'missing stage1Nonce' => ['stage1Nonce', $unset('stage1Nonce'), 'available'];
        yield 'bad scope shape' => ['scope', $set('scope', 'bad scope!'), 'available'];
        yield 'missing scope' => ['scope', $unset('scope'), 'available'];
        yield 'bad obligationId shape' => ['obligationId', $set('obligationId', 'not-hex'), 'available'];
        yield 'missing obligationId' => ['obligationId', $unset('obligationId'), 'available'];
        yield 'wrong action (StepUp is never chainable)' => ['requiredAction', $set('requiredAction', 'step_up'), 'available'];
        yield 'wrong action (Allow is never chainable)' => ['requiredAction', $set('requiredAction', 'allow'), 'available'];
        yield 'missing requiredAction' => ['requiredAction', $unset('requiredAction'), 'available'];
        yield 'rank does not match the action' => ['requiredRank', $set('requiredRank', 1), 'available'];
        yield 'rank out of bounds' => ['requiredRank', $set('requiredRank', 99), 'available'];
        yield 'non-positive policyVersion' => ['policyVersion', $set('policyVersion', 0), 'available'];
        yield 'missing policyVersion' => ['policyVersion', $unset('policyVersion'), 'available'];
        yield 'bad chain depth' => ['chainDepth', $set('chainDepth', 3), 'available'];
        yield 'missing chainDepth' => ['chainDepth', $unset('chainDepth'), 'available'];
        yield 'wrong state' => ['state', $set('state', 'bogus'), 'available'];
        yield 'missing state' => ['state', $unset('state'), 'available'];
        yield 'owner set in the available state' => ['owner', $set('owner', 'x'), 'available'];
        yield 'leaseUntil set in the available state' => ['leaseUntil', $set('leaseUntil', 1234), 'available'];
        yield 'owner missing in the reserved state' => ['owner', $unset('owner'), 'reserved'];
        yield 'leaseUntil missing in the reserved state' => ['leaseUntil', $unset('leaseUntil'), 'reserved'];
        yield 'stage2Nonce set in the reserved state' => ['stage2Nonce', $set('stage2Nonce', 'n'), 'reserved'];
        yield 'stage2Nonce missing in the issued state' => ['stage2Nonce', $unset('stage2Nonce'), 'issued'];
        yield 'bad stage2Nonce shape (hex, not Kiwi base64)' => ['stage2Nonce', $set('stage2Nonce', bin2hex(random_bytes(32))), 'issued'];
        // The terminal states carry an OPTIONAL stage-2 nonce (a valid
        // Kiwi nonce OR null — the nonce-agnostic transaction
        // terminalizations run WITHOUT the exact stage-2 nonce): a
        // MISSING nonce is valid there; a non-null malformed shape is
        // still corrupt.
        yield 'bad stage2Nonce shape (hex, not Kiwi base64) in the step_up_required state' => ['stage2Nonce', $set('stage2Nonce', bin2hex(random_bytes(32))), 'step_up_required'];
        yield 'owner set in the step_up_required state' => ['owner', $set('owner', 'x'), 'step_up_required'];
        yield 'leaseUntil set in the denied state' => ['leaseUntil', $set('leaseUntil', 1234), 'denied'];
        yield 'bad stage2Nonce shape (hex, not Kiwi base64) in the denied state' => ['stage2Nonce', $set('stage2Nonce', bin2hex(random_bytes(32))), 'denied'];
        yield 'bad expiresAt' => ['expiresAt', $set('expiresAt', 'soon'), 'available'];
        yield 'missing expiresAt' => ['expiresAt', $unset('expiresAt'), 'available'];
        yield 'bad requestBinding shape' => ['requestBinding', $set('requestBinding', 'bad binding!'), 'available'];
    }

    #[DataProvider('corruptRecordProvider')]
    public function testCorruptChainRecordFailsClosed(string $label, array $mutation, string $prepare): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $requirement = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, time() + 300);
        if ($prepare === 'reserved') {
            self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
        } elseif ($prepare === 'issued') {
            self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
            self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', $this->stageNonce('stage2-nonce')));
        } elseif ($prepare === 'step_up_required') {
            self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
            self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', $this->stageNonce('stage2-nonce')));
            self::assertSame(ChainVerifiedResult::StepUpRequiredNew, $service->markStepUpRequired($requirement->chainId, $this->stageNonce('stage2-nonce')));
        } elseif ($prepare === 'denied') {
            self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
            self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', $this->stageNonce('stage2-nonce')));
            self::assertSame(ChainVerifiedResult::DeniedNew, $service->markDenied($requirement->chainId, $this->stageNonce('stage2-nonce')));
        }

        $records = $this->chainRecords($store);
        $record = $records[$requirement->chainId];
        if ($mutation[0] === 'unset') {
            unset($record[$mutation[1]]);
        } else {
            $record[$mutation[1]] = $mutation[2];
        }
        $records[$requirement->chainId] = $record;
        (new \ReflectionObject($store))->getProperty('records')->setValue($store, $records);

        // ALL-OR-NOTHING decode: a corrupt record is NEVER a defaulted
        // valid chain — read (and every transition) throws.
        try {
            $store->read($requirement->chainId);
            self::fail('a corrupt chain record must never decode into valid state: '.$label);
        } catch (MalformedChainedChallengeStateException $e) {
            self::assertStringContainsString('chain record', $e->getMessage());
        }
    }

    public function testCorruptAutoResumeChainIsTheRetryable503Never422(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $stage1 = $this->solvedStage1($storage);
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', '', 1, RiskAction::Argon32, time() + 300);

        // Corrupt the chain record (a server-side anomaly): the auto-resume
        // read fails closed with the retryable 503 — NEVER a defaulted
        // chain, NEVER a 422 client fault.
        $records = $this->chainRecords($chainStore);
        $records[$requirement->chainId]['requiredAction'] = 'step_up';
        (new \ReflectionObject($chainStore))->getProperty('records')->setValue($chainStore, $records);

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = $this->chainController($storage, $chainService, $risk['gateway']);
        $response = $controller->challenge($this->challengeRequest('{"scope":"login"}'));
        self::assertSame(503, $response->getStatusCode(), 'a corrupt server chain record is the retryable 503, never a 422');
        self::assertStringContainsString('SERVICE_UNAVAILABLE', (string) $response->getContent());
    }

    // ── Outstanding admission rollback (proven vs indeterminate) ───────

    public function testAdmittedIssuanceKeepsTheSlotOnHandoff(): void
    {
        $storage = new ArrayStorage();
        $client = new AbortAwareFakeRedis();
        $outstanding = new OutstandingChallenges($client, '{kiwi:chain-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $risk = $this->riskStack();
        $controller = $this->chainController($storage, $this->chainService(new ArrayChainedChallengeStateStore()), $risk['gateway'], outstanding: $outstanding);

        $response = $controller->challenge($this->challengeRequest('{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode());
        $sourceKey = '{kiwi:chain-test}:outstanding:'.hash_hmac('sha256', Issuer::canonicalIpFamily('198.51.100.7'), RiskKeys::fromMaster(self::SECRET)->event);
        self::assertSame(1, $client->counters[$sourceKey] ?? 0, 'a handed-out challenge keeps its outstanding slot');
    }

    public function testAdmittedSolveDecrementsTheSourceSlot(): void
    {
        $storage = new ArrayStorage();
        $client = new AbortAwareFakeRedis();
        $outstanding = new OutstandingChallenges($client, '{kiwi:chain-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $risk = $this->riskStack();
        $controller = $this->chainController($storage, $this->chainService(new ArrayChainedChallengeStateStore()), $risk['gateway'], outstanding: $outstanding);

        $controller->challenge($this->challengeRequest('{"scope":"login"}'));
        $outstanding->solved('198.51.100.7');
        $sourceKey = '{kiwi:chain-test}:outstanding:'.hash_hmac('sha256', Issuer::canonicalIpFamily('198.51.100.7'), RiskKeys::fromMaster(self::SECRET)->event);
        self::assertSame(0, $client->counters[$sourceKey] ?? 0, 'a valid solve decrements the per-source slot');
        self::assertSame(1, $client->counters['{kiwi:chain-test}:outstanding:global'] ?? 0, 'the GLOBAL counter is never decremented — it decays by EXPIRE');
    }

    public function testAdmittedMintFailureRollsBackTheSlot(): void
    {
        $storage = new FailingMintStorage(new ArrayStorage());
        $client = new AbortAwareFakeRedis();
        $outstanding = new OutstandingChallenges($client, '{kiwi:chain-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $risk = $this->riskStack();
        $controller = $this->chainController($storage, $this->chainService(new ArrayChainedChallengeStateStore()), $risk['gateway'], outstanding: $outstanding);

        $response = $controller->challenge($this->challengeRequest('{"scope":"login"}'));
        self::assertSame(503, $response->getStatusCode(), 'the replica-wait barrier failure is the retryable 503');
        $sourceKey = '{kiwi:chain-test}:outstanding:'.hash_hmac('sha256', Issuer::canonicalIpFamily('198.51.100.7'), RiskKeys::fromMaster(self::SECRET)->event);
        self::assertSame(0, $client->counters[$sourceKey] ?? 0, 'a proven-not-handed-out mint failure returns the slot');
    }

    public function testAdmittedMetadataFailureRollsBackTheSlot(): void
    {
        $storage = new ArrayStorage();
        $client = new AbortAwareFakeRedis();
        $outstanding = new OutstandingChallenges($client, '{kiwi:chain-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $risk = $this->riskStack();
        $controller = new ChallengeController(
            $this->issuer($storage),
            null,
            true,
            $risk['gateway'],
            new ContinuityCookie(),
            outstanding: $outstanding,
            storage: $storage,
            challengeTtlSecs: 120,
            metadataStore: new FailingMetadataStore(),
        );

        $response = $controller->challenge($this->challengeRequest('{"scope":"login","action":"checkout"}'));
        self::assertSame(503, $response->getStatusCode(), 'a metadata-sidecar failure is the retryable 503');
        $sourceKey = '{kiwi:chain-test}:outstanding:'.hash_hmac('sha256', Issuer::canonicalIpFamily('198.51.100.7'), RiskKeys::fromMaster(self::SECRET)->event);
        self::assertSame(0, $client->counters[$sourceKey] ?? 0, 'a proven-not-handed-out metadata failure returns the slot');
    }

    public function testKnownFailedChainIssuanceRollsBackTheSlot(): void
    {
        $storage = new ArrayStorage();
        $client = new AbortAwareFakeRedis();
        $outstanding = new OutstandingChallenges($client, '{kiwi:chain-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $conflict = new ConflictChainStore(new ArrayChainedChallengeStateStore());
        $chainService = $this->chainService($conflict);
        $stage1 = $this->solvedStage1($storage);
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', '', 1, RiskAction::Argon32, time() + 300);
        $ticket = $chainService->ticketFor($requirement->chainId, time() + 300);

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = $this->chainController($storage, $chainService, $risk['gateway'], outstanding: $outstanding);

        // The chain-state transition POSITIVELY fails (a different nonce
        // already won the chain): the minted challenge is discarded and
        // the admitted slot is returned.
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(503, $response->getStatusCode(), 'a known-failed chain issuance is the retryable 503');
        $sourceKey = '{kiwi:chain-test}:outstanding:'.hash_hmac('sha256', Issuer::canonicalIpFamily('198.51.100.7'), RiskKeys::fromMaster(self::SECRET)->event);
        self::assertSame(0, $client->counters[$sourceKey] ?? 0, 'a KNOWN chain-state failure returns the slot');
    }

    public function testIndeterminateChainIssuanceDoesNotRollBackPrematurely(): void
    {
        $storage = new ArrayStorage();
        $client = new AbortAwareFakeRedis();
        $outstanding = new OutstandingChallenges($client, '{kiwi:chain-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $indeterminate = new LostReplyChainStore(new ArrayChainedChallengeStateStore(), throwAfterIssued: true);
        $chainService = $this->chainService($indeterminate);
        $stage1 = $this->solvedStage1($storage);
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', '', 1, RiskAction::Argon32, time() + 300);
        $ticket = $chainService->ticketFor($requirement->chainId, time() + 300);
        // From here on the chain state is UNREADABLE: the issuance
        // transition throws AND the recovery read fails — INDETERMINATE.
        $indeterminate->readThrows = true;

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = $this->chainController($storage, $chainService, $risk['gateway'], outstanding: $outstanding);

        // markIssued THROWS and the state CANNOT be read: INDETERMINATE —
        // the challenge may be the authoritative issued stage-2. The
        // minted challenge is RETAINED and the slot is NOT rolled back.
        $recordsBefore = $this->storageRecordCount($storage);
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(503, $response->getStatusCode(), 'an indeterminate chain issuance is the retryable 503');
        $sourceKey = '{kiwi:chain-test}:outstanding:'.hash_hmac('sha256', Issuer::canonicalIpFamily('198.51.100.7'), RiskKeys::fromMaster(self::SECRET)->event);
        self::assertSame(1, $client->counters[$sourceKey] ?? 0, 'an INDETERMINATE chain issuance must NOT prematurely roll back the slot');
        self::assertSame($recordsBefore + 1, $this->storageRecordCount($storage), 'the minted challenge is retained (never delete state that may be authoritative)');
    }

    // ── The in-progress 503 boundary ───────────────────────────────────

    public function testSecondRequestWithTheSameTicketWhileReservedGetsTheInProgress503(): void
    {
        $storage = new ArrayStorage();
        $client = new AbortAwareFakeRedis();
        $outstanding = new OutstandingChallenges($client, '{kiwi:chain-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $interceptor = new ChainStateStoreInterceptor(new ArrayChainedChallengeStateStore());
        $chainService = $this->chainService($interceptor);
        $stage1 = $this->solvedStage1($storage);
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', '', 1, RiskAction::Argon32, time() + 300);
        $ticket = $chainService->ticketFor($requirement->chainId, time() + 300);

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = $this->chainController($storage, $chainService, $risk['gateway'], outstanding: $outstanding);

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
        $client = new AbortAwareFakeRedis();
        $outstanding = new OutstandingChallenges($client, '{kiwi:chain-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $stage1 = $this->solvedStage1($storage);
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', '', 1, RiskAction::Argon32, time() + 300);
        $ticket = $chainService->ticketFor($requirement->chainId, time() + 300);

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = $this->chainController($storage, $chainService, $risk['gateway'], outstanding: $outstanding);

        // A LIVE reservation by another owner (never this request):
        // every request with the ticket gets the in-progress 503.
        self::assertSame(ChainReservationResult::Available, $chainService->reserveStage2($requirement->chainId, 'owner-a'));
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(503, $response->getStatusCode(), 'a live reservation by another owner refuses with the in-progress 503');

        // A NON-OWNER release does not free it (the controller's failing
        // request can never free another owner's live reservation).
        $chainService->release($requirement->chainId, 'not-the-owner');
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(503, $response->getStatusCode(), 'a non-owner release leaves the reservation live');

        // After the OWNER releases, the retry succeeds.
        $chainService->release($requirement->chainId, 'owner-a');
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), sprintf('after the owner\'s release the retry succeeds: %s', (string) $response->getContent()));

        // None of the busy refusals touched the outstanding counters.
        $sourceKey = '{kiwi:chain-test}:outstanding:'.hash_hmac('sha256', Issuer::canonicalIpFamily('198.51.100.7'), RiskKeys::fromMaster(self::SECRET)->event);
        self::assertSame(1, $client->counters[$sourceKey] ?? 0, 'the in-progress 503 must never enter the issuance pipeline');
    }

    // ── Ticket format + lifetime ───────────────────────────────────────

    public function testTicketSignatureIsTheRawDigestBase64url(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $requirement = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, time() + 300);
        $ticket = $service->ticketFor($requirement->chainId, time() + 300);

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
        $requirement = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, $now + 300);
        $ticket = $service->ticketFor($requirement->chainId, $now + 300);

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

        // ticketFor() reconstructs the EXACT deterministic ticket.
        self::assertSame($ticket, $service->ticketFor($requirement->chainId, $now + 300), 'the ticket is deterministic from (chainId, expiresAt)');
    }

    public function testMaxLengthBindingIssuesAndWorksEndToEndAtStage2(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $binding = 'b'.str_repeat('x', 127); // 128 chars — the identifier ceiling

        // A legitimate 128-char request binding must produce a ticket
        // well under the wire bound (the minimal ticket never carries it).
        $stage1 = $this->solvedStage1($storage, $binding);
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', $binding, 1, RiskAction::Argon32, time() + 300);
        $ticket = $chainService->ticketFor($requirement->chainId, time() + 300);
        self::assertLessThan(100, \strlen($ticket), 'the minimal ticket is ~60 bytes — a 128-char binding changes nothing');
        self::assertIsArray($chainService->verify($ticket));

        // The chain WORKS end-to-end at stage 2 with the full-length
        // binding (the obligation equality is exact).
        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = $this->chainController($storage, $chainService, $risk['gateway']);
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => $binding], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), sprintf('a 128-char binding must issue end-to-end at stage 2: %s', (string) $response->getContent()));
    }

    public function testTicketExpiringExactlyNowIsExpired(): void
    {
        $clock = 1000;
        $store = new ArrayChainedChallengeStateStore(static function () use (&$clock): float {
            return $clock;
        });
        $issuing = new ChainedChallengeTicketService($store, self::SECRET, 300, 15, now: static fn (): int => 1000);
        $requirement = $issuing->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, 1300);
        $ticket = $issuing->ticketFor($requirement->chainId, 1300);

        // expiresAt == 1300; a verify at exactly 1300 must refuse (<= now).
        $boundary = new ChainedChallengeTicketService($store, self::SECRET, 300, 15, now: static fn (): int => 1300);
        self::assertNull($boundary->verify($ticket), 'a ticket expiring exactly now is expired');
        $justBefore = new ChainedChallengeTicketService($store, self::SECRET, 300, 15, now: static fn (): int => 1299);
        self::assertIsArray($justBefore->verify($ticket), 'a ticket one second before expiry is still valid');
    }

    // ── Stage-2 lifetime bound: the TTL clip + the expired-chain refusal ──

    public function testStage2ChallengeTtlIsClippedToTheChainRemainingLifetime(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore(static fn (): float => 1000.0);
        $chainService = new ChainedChallengeTicketService($chainStore, self::SECRET, 300, 15, now: static fn (): int => 1000);
        $stage1 = $this->solvedStage1($storage);
        // 5 seconds of chain lifetime left when the ticket is presented.
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', '', 1, RiskAction::Argon32, 1005);
        $ticket = $chainService->ticketFor($requirement->chainId, 1005);

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
            now: static fn (): int => 1000,
        );
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), sprintf('the stage-2 mint with 5 seconds of chain life left must succeed: %s', (string) $response->getContent()));
        $stage2 = json_decode((string) $response->getContent(), true);
        self::assertSame(5, $stage2['ttlSecs'], 'the minted TTL is min(configured 120, remaining 5) = 5 — NEVER the full configured TTL');

        // The PRACTICAL FLOOR: exactly 1 second of chain life left (a
        // DIFFERENT transaction — a different obligation) is BELOW the
        // practical minimum (the configured solve floor, here unset = 0,
        // plus the solver/transport margin of 5 seconds): the mint is
        // REFUSED as expired — a 1-second challenge cannot be solved
        // within its own clipped lifetime, so the chain can no longer
        // hold a usable stage-2 challenge.
        $floor = $chainService->requireStage2($stage1['nonce'], 'login', 'txn-floor', 1, RiskAction::Argon32, 1001);
        $floorTicket = $chainService->ticketFor($floor->chainId, 1001);
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $floorTicket, 'request_binding' => 'txn-floor'], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode(), sprintf('a chain with 1 second of life left must refuse the stage-2 mint (below the practical minimum): %s', (string) $response->getContent()));
        self::assertStringContainsString('INVALID_METADATA', (string) $response->getContent());
        self::assertStringContainsString('expired', (string) $response->getContent());
        self::assertSame(2, $this->storageRecordCount($storage), 'no NEW challenge record may be created for a chain that cannot hold a usable stage-2 challenge (the solved stage-1 record and the earlier 5-second mint are all that exist)');
        $floorAfter = $chainService->requirementFor($floor->chainId);
        self::assertNotNull($floorAfter);
        self::assertSame(1001, $floorAfter->expiresAt, 'the chain is never re-created or re-signed with a fresh expiry');
        self::assertSame('available', $floorAfter->state, 'the refused request releases its reservation');
        self::assertNull($floorAfter->owner);
    }

    public function testStage2ClipMintsWithTheClippedTtlEqualToTheRemainingLifetime(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore(static fn (): float => 1000.0);
        $chainService = new ChainedChallengeTicketService($chainStore, self::SECRET, 300, 15, now: static fn (): int => 1000);
        $stage1 = $this->solvedStage1($storage);
        // 6 seconds of chain lifetime left — ABOVE the practical minimum
        // (no explicit minimum solve duration -> 0 + the 5-second
        // solver/transport margin).
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', 'txn-above-min', 1, RiskAction::Argon32, 1006);
        $ticket = $chainService->ticketFor($requirement->chainId, 1006);

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
            now: static fn (): int => 1000,
        );
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => 'txn-above-min'], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), sprintf('the stage-2 mint with 6 seconds of chain life left (>= the practical minimum) must succeed: %s', (string) $response->getContent()));
        $stage2 = json_decode((string) $response->getContent(), true);
        self::assertSame(6, $stage2['ttlSecs'], 'remaining >= the practical minimum mints with the clipped TTL == the remaining lifetime');
    }

    public function testStage2ClipMinimumRemainingIncludesTheConfiguredMinDurationFloor(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore(static fn (): float => 1000.0);
        $chainService = new ChainedChallengeTicketService($chainStore, self::SECRET, 300, 15, now: static fn (): int => 1000);
        $stage1 = $this->solvedStage1($storage);
        // An explicit 1500 ms minimum solve duration: the practical
        // minimum remaining lifetime is ceil(1500/1000) + 5 = 7 seconds.
        // Exactly AT the boundary (7 seconds) the mint succeeds with the
        // clipped TTL == 7; one second below (6) it is refused as
        // expired — the configured floor participates in the boundary.
        $issuer = new Issuer(new Config(
            secretKey: self::SECRET,
            algorithm: PoWAlgorithm::Sha256,
            targetBits: 8,
            ttlSecs: 120,
            minDurationMs: 1500,
        ), $storage);

        $boundary = $chainService->requireStage2($stage1['nonce'], 'login', 'txn-boundary', 1, RiskAction::Argon32, 1007);
        $boundaryTicket = $chainService->ticketFor($boundary->chainId, 1007);
        $below = $chainService->requireStage2($stage1['nonce'], 'login', 'txn-below', 1, RiskAction::Argon32, 1006);
        $belowTicket = $chainService->ticketFor($below->chainId, 1006);

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
            now: static fn (): int => 1000,
        );

        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $boundaryTicket, 'request_binding' => 'txn-boundary'], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), sprintf('the stage-2 mint exactly at the practical minimum (7s with a 1500 ms floor) must succeed: %s', (string) $response->getContent()));
        $stage2 = json_decode((string) $response->getContent(), true);
        self::assertSame(7, $stage2['ttlSecs'], 'the minted TTL equals the remaining 7 seconds at the practical-minimum boundary');

        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $belowTicket, 'request_binding' => 'txn-below'], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode(), sprintf('a chain with 6 seconds of life left (below the 7s practical minimum with a 1500 ms floor) must refuse the stage-2 mint: %s', (string) $response->getContent()));
        self::assertStringContainsString('INVALID_METADATA', (string) $response->getContent());
        self::assertStringContainsString('expired', (string) $response->getContent());
        self::assertSame(2, $this->storageRecordCount($storage), 'no NEW challenge record may be created below the practical minimum (the solved stage-1 record and the earlier boundary mint are all that exist)');
        $belowAfter = $chainService->requirementFor($below->chainId);
        self::assertNotNull($belowAfter);
        self::assertSame(1006, $belowAfter->expiresAt, 'the chain is never re-created or re-signed with a fresh expiry');
        self::assertSame('available', $belowAfter->state, 'the refused request releases its reservation');
        self::assertNull($belowAfter->owner);
    }

    public function testStage2TicketWithInsufficientChainLifetimeIsRefusedAsExpired(): void
    {
        $storage = new ArrayStorage();
        $client = new AbortAwareFakeRedis();
        $outstanding = new OutstandingChallenges($client, '{kiwi:chain-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $chainClock = 1000.0;
        $chainStore = new ArrayChainedChallengeStateStore(static function () use (&$chainClock): float {
            return $chainClock;
        });
        $chainService = new ChainedChallengeTicketService($chainStore, self::SECRET, 300, 15, now: static fn (): int => 1000);
        $stage1 = $this->solvedStage1($storage);
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', '', 1, RiskAction::Argon32, 1001);
        $ticket = $chainService->ticketFor($requirement->chainId, 1001);

        // The ticket is presented when the controller's clock has already
        // ticked PAST the chain's absolute expiry (less than the
        // practical minimum challenge lifetime — the configured solve
        // floor plus the solver/transport margin — remains): the mint is
        // refused with the expired-chain response — no challenge record,
        // no outstanding admission, no re-sign, no re-created expiry.
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
            now: static fn (): int => 1001,
        );
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode(), sprintf('a chain with no usable lifetime left must refuse the stage-2 mint (below the practical minimum): %s', (string) $response->getContent()));
        self::assertStringContainsString('INVALID_METADATA', (string) $response->getContent());
        self::assertStringContainsString('expired', (string) $response->getContent());
        self::assertSame(1, $this->storageRecordCount($storage), 'no NEW challenge record may be created for a chain that cannot hold it (only the solved stage-1 record exists)');
        $sourceKey = '{kiwi:chain-test}:outstanding:'.hash_hmac('sha256', Issuer::canonicalIpFamily('198.51.100.7'), RiskKeys::fromMaster(self::SECRET)->event);
        self::assertSame(0, $client->counters[$sourceKey] ?? 0, 'no outstanding admission may be held');
        self::assertSame(0, $client->counters['{kiwi:chain-test}:outstanding:global'] ?? 0, 'the global counter is untouched');

        // The chain is NOT extended: it still expires at its signed
        // expiry, and the refused request released its reservation (the
        // ticket stays reusable — the chain is not burned).
        $after = $chainService->requirementFor($requirement->chainId);
        self::assertNotNull($after);
        self::assertSame(1001, $after->expiresAt, 'the chain is never re-created or re-signed with a fresh expiry');
        self::assertSame('available', $after->state, 'the refused request releases its reservation');
        self::assertNull($after->owner);
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
        $chainId = (string) $this->chainService($chainStore)->verify($ticket)['chainId'];
        self::assertSame(RiskAction::Sha16, $this->chainService($chainStore)->requirementFor($chainId)?->requiredAction);
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
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', '', 1, RiskAction::Argon32, time() + 300);
        $ticket = $chainService->ticketFor($requirement->chainId, time() + 300);

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $controller = $this->chainController($storage, $chainService, $risk['gateway'], metadataStore: $metaStore);
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'cdata' => 'customer_123'], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode());
        $nonce = json_decode((string) $response->getContent(), true)['nonce'];

        // The stored metadata: the application's OWN cdata is preserved
        // untouched, and the chain identity lives ONLY in the private
        // chainId/chainDepth fields — never in the cdata.
        $metadata = $metaStore->find($nonce);
        self::assertNotNull($metadata);
        self::assertSame('customer_123', $metadata->cdata, 'the stage-2 issuance must preserve the application cdata');
        self::assertSame($requirement->chainId, $metadata->chainId, 'the chain id lives in the private metadata field');
        self::assertSame(2, $metadata->chainDepth);
        self::assertNotSame($metadata->chainId, $metadata->cdata);
        self::assertSame('customer_123', $metadata->toArray()['cdata'], 'the wire metadata keeps the app cdata in the cdata field');
        self::assertSame($metadata->chainId, $metadata->toArray()['chainId'], 'the chain id is a first-class private metadata field');
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
        // STAMPS the chain identity into the PRIVATE metadata fields. The
        // stage-2 request resolves the SAME authoritative binding through
        // the SAME authority (the chain anchor).
        $controller = new ChallengeController(
            $issuer,
            null,
            true,
            $risk['gateway'],
            new ContinuityCookie(),
            metadataStore: $metaStore,
            storage: $storage,
            challengeTtlSecs: 120,
            chainTickets: $chainService,
            bindingAuthority: new FixtureBindingAuthority('txn-alpha'),
            policyVersion: 1,
        );
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode());
        $stage2 = json_decode((string) $response->getContent(), true);
        self::assertSame('argon2id', $stage2['algorithm']);

        // The chain identity is server-stamped into the metadata sidecar.
        $metadata = $metaStore->find($stage2['nonce']);
        self::assertNotNull($metadata);
        self::assertSame((string) $chainService->verify($ticket)['chainId'], $metadata->chainId, 'the stage-2 challenge must carry the server-stamped chain id in the private metadata field');
        self::assertSame(2, $metadata->chainDepth);

        // Stage 2 solve: a NEUTRAL reassessment — the stage-2
        // verification detects the open requirement (its stage2Nonce IS
        // the solved nonce). Even WITHOUT a reassessment (post_solve_check
        // false + no honeypot + no chain-eligible scope — the metadata
        // chainId marker forbids a third stage), the PASS disposition of a
        // recognized stage-2 nonce STILL transitions the chain to VERIFIED
        // (the obligation is cleared — the chain ends at stage 2, never a
        // third stage) and passes.
        usleep(($stage2['minDurationMs'] + 10) * 1000);
        $stage2Token = $this->solveChallenge($stage2);
        $risk['store']->setVector(SignalVector::zero());
        $stack2 = new RequestStack();
        // The bound stage-2 challenge is redeemed WITH its transaction
        // binding (the signed request_binding the controller issued).
        $stack2->push(Request::create('/', 'POST', ['kiwi__token' => $stage2Token, 'kiwi_request_binding' => 'txn-alpha'], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations2] = $this->validateChained($stage2Token, $stack2, $risk['gateway'], $storage, $chainStore, $metaStore, resolver: $resolver);

        self::assertCount(0, $violations2, 'a stage-2 verified challenge passes — the chain ends at stage 2 (the metadata chainId marker forbids a third stage, so no reassessment runs and no new ticket can ever be issued)');
        $records = array_values($this->chainRecords($chainStore));
        self::assertCount(1, $records, 'no third-stage chain state may ever be created');
        self::assertSame('verified', $records[0]['state'], 'the chain ends TERMINAL verified — the no-reassessment PASS still performs the stage-2 transition');
        self::assertSame($stage2['nonce'], $records[0]['stage2Nonce'], 'no re-issued challenge may ever replace the stage-2 nonce');
        self::assertNull($chainService->findOpenRequirement('login', 'txn-alpha', 1), 'the verified transition cleared the obligation — the transaction is complete');
    }

    // ── Stage-2 final disposition -> terminal transition (validator) ───

    public function testStage2StepUpDispositionMarksStepUpRequiredAndTheObligationSurvives(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $stage1 = $this->solvedStage1($storage);

        // Stage 1: the reassessment (Argon32) opens the chain.
        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations] = $this->validateChained($stage1['token'], $stack, $risk['gateway'], $storage, $chainStore);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $ticket = $violations[0]->getParameters()['{{ chain_ticket }}'];

        // Stage 2: issue the stronger challenge through the controller.
        $controller = $this->chainController($storage, $chainService, $risk['gateway'], authority: new FixtureBindingAuthority('txn-alpha'));
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), sprintf('the stage-2 issuance must succeed: %s', (string) $response->getContent()));
        $stage2 = json_decode((string) $response->getContent(), true);

        // Stage 2 solve with a STEP-UP post-solve decision: the FINAL
        // disposition is STEP-UP — the chain transitions to the TERMINAL
        // step_up_required (the obligation is KEPT) and the application
        // sees the terminal step-up violation.
        usleep(($stage2['minDurationMs'] + 10) * 1000);
        $stage2Token = $this->solveChallenge($stage2);
        $risk['store']->setVector(SignalVector::fromArray(self::STEP_UP_VECTOR));
        $stack2 = new RequestStack();
        $stack2->push(Request::create('/', 'POST', ['kiwi__token' => $stage2Token, 'kiwi_request_binding' => 'txn-alpha'], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations2] = $this->validateChained($stage2Token, $stack2, $risk['gateway'], $storage, $chainStore);
        self::assertCount(1, $violations2);
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations2[0]->getCode(), 'a stage-2 solve with a StepUp post-solve decision is terminal step-up');

        $state = $chainService->requirementFor((string) $chainService->verify($ticket)['chainId']);
        self::assertSame('step_up_required', $state?->state, 'the chain is TERMINAL step_up_required');
        self::assertSame($stage2['nonce'], $state?->stage2Nonce);
        self::assertNotNull($chainService->findOpenRequirement('login', 'txn-alpha', 1), 'the step-up transition KEEPS the obligation — the transaction stays bound');

        // A SUBSEQUENT challenge request for the same transaction returns
        // the TERMINAL STEP_UP_REQUIRED — never a new stage-1, never a
        // stage-2 challenge.
        $later = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
        self::assertSame(403, $later->getStatusCode(), 'a later request for the same transaction re-encounters the terminal step-up');
        self::assertStringContainsString('STEP_UP_REQUIRED', (string) $later->getContent());
        self::assertSame('step_up_required', $chainService->requirementFor((string) $chainService->verify($ticket)['chainId'])?->state, 'the terminal state survives the later request');
    }

    public function testStage2DenyDispositionMarksDeniedAndTheObligationSurvives(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $stage1 = $this->solvedStage1($storage);

        // Stage 1: the reassessment (Argon32) opens the chain.
        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations] = $this->validateChained($stage1['token'], $stack, $risk['gateway'], $storage, $chainStore);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $ticket = $violations[0]->getParameters()['{{ chain_ticket }}'];

        // Stage 2: issue the stronger challenge through the controller.
        $controller = $this->chainController($storage, $chainService, $risk['gateway'], authority: new FixtureBindingAuthority('txn-alpha'));
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), sprintf('the stage-2 issuance must succeed: %s', (string) $response->getContent()));
        $stage2 = json_decode((string) $response->getContent(), true);

        // Stage 2 solve with a DENY post-solve decision: the FINAL
        // disposition is DENY — the chain transitions to the TERMINAL
        // denied (the obligation is KEPT) and the application sees the
        // post-solve rejection.
        usleep(($stage2['minDurationMs'] + 10) * 1000);
        $stage2Token = $this->solveChallenge($stage2);
        $risk['store']->setVector(SignalVector::fromArray(['network_risk' => 900]));
        $stack2 = new RequestStack();
        $stack2->push(Request::create('/', 'POST', ['kiwi__token' => $stage2Token, 'kiwi_request_binding' => 'txn-alpha'], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations2] = $this->validateChained($stage2Token, $stack2, $risk['gateway'], $storage, $chainStore);
        self::assertCount(1, $violations2);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violations2[0]->getCode(), 'a stage-2 solve with a Deny post-solve decision is rejected');

        $state = $chainService->requirementFor((string) $chainService->verify($ticket)['chainId']);
        self::assertSame('denied', $state?->state, 'the chain is TERMINAL denied');
        self::assertSame($stage2['nonce'], $state?->stage2Nonce);
        self::assertNotNull($chainService->findOpenRequirement('login', 'txn-alpha', 1), 'the denied transition KEEPS the obligation — the transaction stays bound');

        // A SUBSEQUENT challenge request for the same transaction returns
        // the TERMINAL denial — never a new stage-1, never a stage-2
        // challenge.
        $later = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
        self::assertSame(429, $later->getStatusCode(), 'a later request for the same transaction re-encounters the terminal denial');
        self::assertStringContainsString('RISK_DENIED', (string) $later->getContent());
        self::assertSame('denied', $chainService->requirementFor((string) $chainService->verify($ticket)['chainId'])?->state, 'the terminal state survives the later request');
    }

    public function testStage2PassDispositionMarksVerifiedAndDeletesTheObligation(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $stage1 = $this->solvedStage1($storage);

        // Stage 1: the reassessment (Argon32) opens the chain.
        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR));
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations] = $this->validateChained($stage1['token'], $stack, $risk['gateway'], $storage, $chainStore);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $ticket = $violations[0]->getParameters()['{{ chain_ticket }}'];

        // Stage 2: issue the stronger challenge through the controller.
        $controller = $this->chainController($storage, $chainService, $risk['gateway'], authority: new FixtureBindingAuthority('txn-alpha'));
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), sprintf('the stage-2 issuance must succeed: %s', (string) $response->getContent()));
        $stage2 = json_decode((string) $response->getContent(), true);

        // Stage 2 solve with a NEUTRAL post-solve decision: the FINAL
        // disposition is PASS — the chain VERIFIES (the obligation is
        // deleted) and the solve passes. A FRESH risk stack (a fresh
        // scope-action hysteresis) so the neutral assessment is actually
        // neutral.
        usleep(($stage2['minDurationMs'] + 10) * 1000);
        $stage2Token = $this->solveChallenge($stage2);
        $neutral = $this->riskStack();
        $stack2 = new RequestStack();
        $stack2->push(Request::create('/', 'POST', ['kiwi__token' => $stage2Token, 'kiwi_request_binding' => 'txn-alpha'], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations2] = $this->validateChained($stage2Token, $stack2, $neutral['gateway'], $storage, $chainStore);
        self::assertCount(0, $violations2, 'a stage-2 solve with a Pass disposition passes');

        $state = $chainService->requirementFor((string) $chainService->verify($ticket)['chainId']);
        self::assertSame('verified', $state?->state, 'the chain is TERMINAL verified');
        self::assertSame($stage2['nonce'], $state?->stage2Nonce);
        self::assertNull($chainService->findOpenRequirement('login', 'txn-alpha', 1), 'the verified transition DELETED the obligation — the transaction is complete');
    }

    // ── Admission ordering + refusals ──────────────────────────────────

    public function testInvalidTicketsDoNotTouchOutstandingCounters(): void
    {
        $storage = new ArrayStorage();
        $client = new AbortAwareFakeRedis();
        $outstanding = new OutstandingChallenges($client, '{kiwi:chain-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $risk = $this->riskStack();
        $controller = $this->chainController($storage, $chainService, $risk['gateway'], outstanding: $outstanding);
        $sourceKey = '{kiwi:chain-test}:outstanding:'.hash_hmac('sha256', Issuer::canonicalIpFamily('198.51.100.7'), RiskKeys::fromMaster(self::SECRET)->event);

        // Forged signature.
        $forger = new ChainedChallengeTicketService(new ArrayChainedChallengeStateStore(), str_repeat('f', 32), 300);
        $forged = $forger->ticketFor($this->nonce(), time() + 300);
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $forged], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode());

        // Wrong scope.
        $wrongScope = $chainService->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, time() + 300);
        $wrongScopeTicket = $chainService->ticketFor($wrongScope->chainId, time() + 300);
        $risk2 = $this->riskStackWithScopes(['login' => 1, 'signup' => 2]);
        $controller2 = $this->chainController($storage, $chainService, $risk2['gateway'], outstanding: $outstanding);
        $response = $controller2->challenge($this->challengeRequest(json_encode(['scope' => 'signup', 'chain_ticket' => $wrongScopeTicket], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode());

        // An ISSUED ticket (valid signature, chain already issued): the
        // control issuance issues it, the replay RECOVERS the issued
        // challenge — neither touches the counters again.
        $consumed = $chainService->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, time() + 300);
        $consumedTicket = $chainService->ticketFor($consumed->chainId, time() + 300);
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $consumedTicket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), 'the control ticket must issue first');
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $consumedTicket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), 'the replayed (issued) ticket recovers the issued challenge');

        // NONE of the invalid tickets moved the outstanding counters:
        // validation (and the issued-state recovery) run BEFORE any
        // admission counter is touched.
        self::assertSame(1, $client->counters[$sourceKey] ?? 0, 'only the ONE valid issuance may move the outstanding counter');
    }

    public function testRateLimitedStage2RequestLeavesTheTicketReusable(): void
    {
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $risk = $this->riskStack();
        $stage1 = $this->solvedStage1($storage);
        // The chain is anchored on txn-alpha; the control request below
        // uses a DIFFERENT transaction (txn-control) so it can never
        // auto-resume this chain (the open-obligation gate).
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', 'txn-alpha', 1, RiskAction::Argon32, time() + 300);
        $ticket = $chainService->ticketFor($requirement->chainId, time() + 300);

        // A saturated per-client rate limiter (cap 1) refuses the
        // ticket-bearing request with 429 — the reservation is released,
        // the ticket stays usable. The control request saturates the
        // single-slot window first (as an UNRELATED transaction).
        $client = new FakePredisClient();
        $limiter = new IssuanceRateLimiter(1, 60, null, null, 'pepper', $client, 500, 'chain-test-ns');
        $limited = new ChallengeController(
            $this->issuer($storage),
            rateLimiter: $limiter,
            sameOriginOnly: true,
            risk: $risk['gateway'],
            continuityCookie: new ContinuityCookie(),
            storage: $storage,
            challengeTtlSecs: 120,
            chainTickets: $chainService,
            policyVersion: 1,
        );
        $control = $limited->challenge($this->challengeRequest('{"scope":"login","request_binding":"txn-control"}'));
        self::assertSame(200, $control->getStatusCode(), 'the control request must saturate the limiter window');
        $response = $limited->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
        self::assertSame(429, $response->getStatusCode(), 'the saturated limiter must refuse the stage-2 request');

        // The SAME ticket succeeds on a controller without the limiter —
        // the refused admission never burned it.
        $open = $this->chainController($storage, $chainService, $risk['gateway']);
        $retry = $open->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
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
        $risk = $this->riskStack();
        $chainService = $this->chainService(new ArrayChainedChallengeStateStore());
        $controller = $this->chainController($storage, $chainService, $risk['gateway']);

        $response = $controller->challenge($this->challengeRequest('{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode(), 'issuance without a ticket is unchanged by chaining');
    }

    // ── Trusted-edge TLS tag ingress (the cross-language contract bound) ──

    public function testTrustedTlsTagIngressMatchesTheCrateContractBound(): void
    {
        $storage = new ArrayStorage();
        $risk = $this->riskStack();
        $controller = new ChallengeController(
            $this->issuer($storage),
            null,
            true,
            $risk['gateway'],
            new ContinuityCookie(),
            storage: $storage,
            challengeTtlSecs: 120,
            trustedTlsHeader: 'X-Tls-Class',
            trustedTlsProxies: ['198.51.100.0/24'],
        );

        // A 64-character pipe-separated tag (the "tls13|http2" shape the
        // cross-language risk-v2 contract documents) passes the ingress
        // and reaches the risk context: the engine records it as the
        // session's first-seen TLS tag.
        $tag64 = 'tls13|http2|'.str_repeat('x', 52);
        self::assertSame(64, \strlen($tag64));
        $response = $controller->challenge($this->challengeRequest('{"scope":"login"}', ['HTTP_X_TLS_CLASS' => $tag64]));
        self::assertSame(200, $response->getStatusCode());
        self::assertContains($tag64, $risk['store']->tlsTags, 'a 64-char pipe-separated TLS tag must pass the ingress and ride the risk context');

        // A 65-character tag is DROPPED: the request is assessed without
        // a TLS tag (the signal stays neutral) — the ingress bound is
        // the contract bound, never wider.
        $tag65 = 'tls13|http2|'.str_repeat('y', 53);
        self::assertSame(65, \strlen($tag65));
        $response = $controller->challenge($this->challengeRequest('{"scope":"login"}', ['HTTP_X_TLS_CLASS' => $tag65]));
        self::assertSame(200, $response->getStatusCode());
        self::assertNotContains($tag65, $risk['store']->tlsTags, 'a 65-char TLS tag must be dropped by the ingress');
        self::assertCount(1, $risk['store']->tlsTags, 'only the valid tag reaches the risk context');
    }

    // ── Legacy interface compatibility (deprecated-for-removal) ────────

    public function testLegacyDeprecatedSurfaceStillWorksThroughTheRetainedMachine(): void
    {
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $nonce = $this->nonce();

        // The deprecated issue()/read()/reserve()/complete() surface is
        // retained (deprecated-for-removal-in-a-major) and drives the SAME
        // obligation-anchored machine.
        $ticket = $service->issue($nonce, 'login', 1, requiredAction: 'argon32');
        self::assertIsString($ticket);
        $state = $service->read($ticket);
        self::assertIsArray($state);
        self::assertSame('available', $state['state']);
        self::assertSame('argon32', $state['requiredAction']);
        self::assertSame(2, $state['chainDepth']);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/D', (string) $state['obligationId'], 'every v2 record carries a well-shaped obligation id');

        $chainId = (string) $service->verify($ticket)['chainId'];
        self::assertSame('available', $service->reserve($ticket, 'owner-a'), 'the deprecated reserve still claims the chain');
        $completed = $service->complete($chainId, 'owner-a', $this->stageNonce('stage2-nonce'));
        self::assertIsArray($completed);
        self::assertSame('completed', $completed['state'], 'the legacy terminal state is retained');
        self::assertSame($this->stageNonce('stage2-nonce'), $completed['stage2Nonce']);

        // The legacy 'completed' record is reported as the ISSUED state by
        // the typed surface (semantically identical — recoverable), and a
        // replay reserve answers 'completed' (the legacy answer).
        self::assertSame('issued', $service->requirementFor($chainId)?->state, 'legacy completed == issued at the typed surface');
        self::assertSame(ChainReservationResult::Issued, $service->reserveStage2($chainId, 'owner-b'));
        self::assertSame('completed', $store->reserve($chainId, 'owner-c', 15), 'the store-level legacy answer is retained');

        // The legacy chain verifies (markVerified accepts the legacy
        // terminal state) and its obligation-independent mapping is
        // cleared only if it points at the chain (the legacy create()
        // wrote no obligation, so nothing is linked).
        self::assertSame(ChainVerifiedResult::VerifiedNew, $service->markVerified($chainId, $this->stageNonce('stage2-nonce')));
        self::assertSame('verified', $service->requirementFor($chainId)?->state);
    }

    // ── Adversarial validator: fail-closed chain-state reads ──────────

    public function testChainStateReadFailureIsTemporaryUnavailableInTheStage1Path(): void
    {
        // A chain-state READ failure (backend error / decoding /
        // corruption) must never be indistinguishable from an
        // authoritative "no open requirement": the ordinary stage-1 path
        // (mapPostSolveDecision) fails closed with the retryable
        // temporary_unavailable violation — never a silent pass.
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $failing = new FailingObligationLookupStore($chainStore);
        $failing->failObligationLookup = true;
        $chainService = $this->chainService($failing);
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(resolver: $resolver);

        $stage1 = $this->solvedStage1($storage);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations] = $this->validateWithService($stage1['token'], $stack, $risk['gateway'], $storage, $chainService, resolver: $resolver);

        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'a chain-state read failure must be the retryable temporary_unavailable — never a silent pass');

        // The store recovers: the retry of the SAME valid token replays
        // the stored result, the clean null lookup is the normal
        // stage-1 flow and the solve passes.
        $failing->failObligationLookup = false;
        $recovered = $this->riskStack(resolver: $resolver);
        [$retry] = $this->validateWithService($stage1['token'], $stack, $recovered['gateway'], $storage, $chainService, resolver: $resolver);
        self::assertCount(0, $retry, 'after the store recovers the retry passes normally');
        self::assertSame([], $this->chainRecords($chainStore), 'a failed obligation read must never create chain state');
    }

    public function testChainStateReadFailureIsTemporaryUnavailableInTheStage2Path(): void
    {
        // The stage-2 detection (applyStage2Disposition) reads the SAME
        // chain state: with a recognized stage-2 nonce (the EXACT
        // stage2Nonce match) the read failure must fail closed — the
        // recognized stage-2 nonce is NEVER left behind a Pass while the
        // obligation may be uncleared.
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $metaStore = new ArraySiteVerifyMetadataStore();
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR), $resolver);

        // Stage 1: the reassessment (Argon32) opens the chain.
        $stage1 = $this->solvedStage1($storage);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $service = $this->chainService($chainStore);
        [$violations] = $this->validateWithService($stage1['token'], $stack, $risk['gateway'], $storage, $service, resolver: $resolver);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $ticket = $violations[0]->getParameters()['{{ chain_ticket }}'];
        $chainId = (string) $service->verify((string) $ticket)['chainId'];

        // Stage 2: a REAL challenge is issued and the chain identity is
        // stamped into the metadata sidecar (the marker ends the chain at
        // stage 2 — the no-reassessment Pass path).
        $stage2 = $this->issuer($storage)->issue('login', '198.51.100.7');
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($chainId, 'owner-a', $stage2->nonce));
        $metaStore->store($stage2->nonce, new \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadata(null, null, 'login', $chainId, 2), 300);

        // The OBLIGATION READ now fails: the stage-2 detection cannot
        // confirm the exact stage2Nonce match — fail closed, never a Pass
        // while the obligation may be uncleared.
        $failing = new FailingObligationLookupStore($chainStore);
        $failing->failObligationLookup = true;
        $failingService = $this->chainService($failing);
        usleep(($stage2->minDurationMs + 10) * 1000);
        $stage2Token = $this->solveToken($stage2->toArray());
        $stack2 = new RequestStack();
        $stack2->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations2] = $this->validateWithService($stage2Token, $stack2, $risk['gateway'], $storage, $failingService, $metaStore, $resolver);

        self::assertCount(1, $violations2);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations2[0]->getCode(), 'a chain-state read failure on the stage-2 detection path must be temporary_unavailable — never a pass');
        self::assertSame('issued', $chainStore->read($chainId)['state'], 'the chain stays issued — the obligation is never cleared without the transition');
    }

    public function testMetadataMarkerReadFailureIsTemporaryUnavailableNeverPass(): void
    {
        // The exact adversarial configuration: post_solve_check=false, NO
        // honeypot, chaining enabled (the chain service + the binding
        // authority wired) — but the PRIVATE chain-marker read (the
        // metadata sidecar) FAILS. The verified challenge's stage cannot
        // be established: fail CLOSED with the temporary_unavailable
        // violation — never acceptance, never silently treating the
        // challenge as stage-1-eligible (which would suppress the
        // reassessment).
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $failingMeta = new FailingReadMetadataStore();
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(resolver: $resolver);

        $stage1 = $this->solvedStage1($storage);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $chainService = $this->chainService($chainStore);
        [$violations] = $this->validateWithService($stage1['token'], $stack, $risk['gateway'], $storage, $chainService, $failingMeta, $resolver);

        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'a metadata-marker read failure with chaining enabled must be temporary_unavailable — never a pass');

        // ONLY the failure path fails closed: a successful read without a
        // marker keeps the normal stage-1 flow — a fresh token passes.
        $failingMeta->findFails = false;
        $challenge = $this->issuer($storage)->issue('login', '198.51.100.7')->toArray();
        usleep(($challenge['minDurationMs'] + 10) * 1000);
        $token2 = $this->solveToken($challenge);
        $stack2 = new RequestStack();
        $stack2->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations2] = $this->validateWithService($token2, $stack2, $risk['gateway'], $storage, $chainService, $failingMeta, $resolver);
        self::assertCount(0, $violations2, 'a successful marker read (absent) keeps the normal behavior');
    }

    public function testSuccessfulEmptyObligationLookupKeepsNormalBehavior(): void
    {
        // Only a SUCCESSFUL lookup returning no record is an
        // authoritative "no open requirement" — the normal dispositions
        // (Pass / StepUp / ...) are unchanged.
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(resolver: $resolver);

        $stage1 = $this->solvedStage1($storage);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations] = $this->validateChained($stage1['token'], $stack, $risk['gateway'], $storage, $chainStore, resolver: $resolver);

        self::assertCount(0, $violations, 'no open requirement + a neutral assessment = the normal Pass');
        self::assertNull($this->chainService($chainStore)->findOpenRequirement('login', 'txn-alpha', 1), 'the clean lookup is an authoritative no-obligation');
        self::assertSame([], $this->chainRecords($chainStore), 'a neutral assessment with no open requirement opens no chain');
    }

    // ── Adversarial validator: the open obligation is authoritative ───

    public function testSecondStage1TokenOfAnOpenObligationNeverPasses(): void
    {
        // TWO PRE-ISSUED stage-1 tokens of one binding: the first solve
        // opens the transaction obligation; the SECOND solve (a different
        // nonce, the same binding) must NEVER Pass — the open obligation
        // is authoritative: the transaction still needs its stage 2
        // (CHAIN_REQUIRED with the SAME chain id).
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);

        $issuer = $this->issuer($storage);
        $c1 = $issuer->issue('login', '198.51.100.7', 'txn-alpha')->toArray();
        $c2 = $issuer->issue('login', '198.51.100.7', 'txn-alpha')->toArray();
        usleep(($c1['minDurationMs'] + 10) * 1000);
        $token1 = $this->solveToken($c1);
        usleep(($c2['minDurationMs'] + 10) * 1000);
        $token2 = $this->solveToken($c2);

        // Solve 1: the fresh reassessment (Argon32) opens the chain.
        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR), $resolver);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations1] = $this->validateChained($token1, $stack, $risk['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations1[0]->getCode());
        $chainId = (string) $this->chainService($chainStore)->verify((string) $violations1[0]->getParameters()['{{ chain_ticket }}'])['chainId'];

        // Solve 2: a NEUTRAL fresh assessment would be a plain Pass — the
        // OPEN OBLIGATION is authoritative: CHAIN_REQUIRED with the SAME
        // chain, never a Pass for a stage-1 token on a chained
        // transaction.
        $neutral = $this->riskStack(resolver: $resolver);
        $stack2 = new RequestStack();
        $stack2->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations2] = $this->validateChained($token2, $stack2, $neutral['gateway'], $storage, $chainStore, resolver: $resolver);

        self::assertCount(1, $violations2, 'a stage-1 token of an open obligation must never pass');
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations2[0]->getCode(), 'the open obligation demands its stage 2 — CHAIN_REQUIRED');
        self::assertSame($chainId, (string) $this->chainService($chainStore)->verify((string) $violations2[0]->getParameters()['{{ chain_ticket }}'])['chainId'], 'the obligation-driven CHAIN_REQUIRED carries the SAME chain id');
        $requirement = $this->chainService($chainStore)->findOpenRequirement('login', 'txn-alpha', 1);
        self::assertNotNull($requirement);
        self::assertSame($chainId, $requirement->chainId, 'the open obligation is the same chain');
    }

    public function testOpenObligationFloorNeverDecaysWithALaterWeakerAssessment(): void
    {
        // THREE PRE-ISSUED stage-1 tokens of one binding: after the
        // obligation opens at the Argon32 floor, a LATER WEAKER
        // assessment (Sha16, then a neutral Allow) must never lower the
        // recorded requirement — the obligation-driven disposition reuses
        // the requirement's RECORDED requiredAction/rank, so the floor
        // survives and the solve never passes.
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);

        $issuer = $this->issuer($storage);
        $tokens = [];
        for ($i = 0; $i < 3; ++$i) {
            $c = $issuer->issue('login', '198.51.100.7', 'txn-alpha')->toArray();
            usleep(($c['minDurationMs'] + 10) * 1000);
            $tokens[] = $this->solveToken($c);
        }

        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR), $resolver);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations1] = $this->validateChained($tokens[0], $stack, $risk['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations1[0]->getCode());
        $chainId = (string) $this->chainService($chainStore)->verify((string) $violations1[0]->getParameters()['{{ chain_ticket }}'])['chainId'];

        // A WEAKER-but-still-chainable reassessment (Sha16): the SAME
        // chain, the floor NEVER decays.
        $weaker = $this->riskStack(SignalVector::fromArray(self::SHA16_VECTOR), $resolver);
        $stack2 = new RequestStack();
        $stack2->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations2] = $this->validateChained($tokens[1], $stack2, $weaker['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations2[0]->getCode(), 'a weaker chainable reassessment still demands the open chain');
        self::assertSame($chainId, (string) $this->chainService($chainStore)->verify((string) $violations2[0]->getParameters()['{{ chain_ticket }}'])['chainId'], 'the weaker reassessment returns the SAME chain');

        // A NEUTRAL reassessment (would be a plain Pass): the recorded
        // floor is authoritative — CHAIN_REQUIRED, never a Pass, and the
        // requirement keeps its RECORDED stronger action/rank.
        $neutral = $this->riskStack(resolver: $resolver);
        $stack3 = new RequestStack();
        $stack3->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations3] = $this->validateChained($tokens[2], $stack3, $neutral['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertCount(1, $violations3, 'a stage-1 token must never pass while the obligation is open');
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations3[0]->getCode());
        self::assertSame($chainId, (string) $this->chainService($chainStore)->verify((string) $violations3[0]->getParameters()['{{ chain_ticket }}'])['chainId'], 'the neutral reassessment returns the SAME chain');
        $requirement = $this->chainService($chainStore)->findOpenRequirement('login', 'txn-alpha', 1);
        self::assertNotNull($requirement);
        self::assertSame(RiskAction::Argon32, $requirement->requiredAction, 'the recorded floor NEVER decays to a weaker action');
        self::assertSame(5, $requirement->requiredRank, 'the recorded rank NEVER decays');
    }

    // ── The open obligation ESCALATES (monotonic max security) ─────────

    public function testOpenObligationRaisesToAFreshStrongerAssessment(): void
    {
        // An open SHA18 obligation + a fresh STRICTLY STRONGER SHA20
        // assessment: the recorded floor RAISES ATOMICALLY (the store's
        // raise-only create-or-get — the SAME chain id, the ORIGINAL
        // expiry preserved) and the disposition is CHAIN_REQUIRED with
        // that same chain — the obligation never freezes its security
        // level.
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);

        $issuer = $this->issuer($storage);
        $c1 = $issuer->issue('login', '198.51.100.7', 'txn-alpha')->toArray();
        $c2 = $issuer->issue('login', '198.51.100.7', 'txn-alpha')->toArray();
        usleep(($c1['minDurationMs'] + 10) * 1000);
        $token1 = $this->solveToken($c1);
        usleep(($c2['minDurationMs'] + 10) * 1000);
        $token2 = $this->solveToken($c2);

        // Solve 1: the fresh assessment (Sha18) opens the chain at the
        // SHA18 floor.
        $risk = $this->riskStack(SignalVector::fromArray(self::SHA18_VECTOR), $resolver);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations1] = $this->validateChained($token1, $stack, $risk['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations1[0]->getCode());
        $chainId = (string) $this->chainService($chainStore)->verify((string) $violations1[0]->getParameters()['{{ chain_ticket }}'])['chainId'];
        $requirement = $this->chainService($chainStore)->findOpenRequirement('login', 'txn-alpha', 1);
        self::assertNotNull($requirement);
        self::assertSame(RiskAction::Sha18, $requirement->requiredAction);
        self::assertSame(2, $requirement->requiredRank);
        $originalExpiry = $requirement->expiresAt;

        // The SECOND solve lands in a LATER second (a fresh now+chainTtl
        // would differ): the raise must still preserve the ORIGINAL
        // expiry.
        usleep(1_100_000);

        // Solve 2: a fresh STRICTLY STRONGER SHA20 assessment — the
        // obligation RAISES to SHA20 (the SAME chain id, the ORIGINAL
        // expiry preserved), never a freeze at SHA18.
        $stronger = $this->riskStack(SignalVector::fromArray(self::SHA20_VECTOR), $resolver);
        $stack2 = new RequestStack();
        $stack2->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations2] = $this->validateChained($token2, $stack2, $stronger['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertCount(1, $violations2, 'a stage-1 token of the raised obligation still demands its stage 2');
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations2[0]->getCode());
        $payload2 = $this->chainService($chainStore)->verify((string) $violations2[0]->getParameters()['{{ chain_ticket }}']);
        self::assertIsArray($payload2);
        self::assertSame($chainId, (string) $payload2['chainId'], 'the raise returns the SAME chain id — never a replacement chain');
        $requirement = $this->chainService($chainStore)->findOpenRequirement('login', 'txn-alpha', 1);
        self::assertNotNull($requirement);
        self::assertSame(RiskAction::Sha20, $requirement->requiredAction, 'the floor RAISES to the stronger fresh assessment');
        self::assertSame(3, $requirement->requiredRank, 'the rank RAISES with the action');
        self::assertSame($chainId, $requirement->chainId, 'the raised chain is the SAME chain');
        self::assertSame($originalExpiry, $requirement->expiresAt, 'the raise preserves the ORIGINAL chain expiry — it never moves');
        self::assertSame($originalExpiry, (int) $payload2['expiresAt'], 'the raised ticket is signed from the requirement\'s ACTUAL server-held expiry — never a fresh now+chainTtl');
    }

    public function testOpenObligationRaisesToAFreshArgon32Assessment(): void
    {
        // An open SHA18 obligation + a fresh STRICTLY STRONGER Argon32
        // assessment: the floor RAISES to Argon32 on the SAME chain with
        // the ORIGINAL expiry — the store's raise-only mechanism is
        // applied, the security level never freezes at SHA18.
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);

        $issuer = $this->issuer($storage);
        $c1 = $issuer->issue('login', '198.51.100.7', 'txn-alpha')->toArray();
        $c2 = $issuer->issue('login', '198.51.100.7', 'txn-alpha')->toArray();
        usleep(($c1['minDurationMs'] + 10) * 1000);
        $token1 = $this->solveToken($c1);
        usleep(($c2['minDurationMs'] + 10) * 1000);
        $token2 = $this->solveToken($c2);

        // Solve 1: the fresh assessment (Sha18) opens the chain at the
        // SHA18 floor.
        $risk = $this->riskStack(SignalVector::fromArray(self::SHA18_VECTOR), $resolver);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations1] = $this->validateChained($token1, $stack, $risk['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations1[0]->getCode());
        $chainId = (string) $this->chainService($chainStore)->verify((string) $violations1[0]->getParameters()['{{ chain_ticket }}'])['chainId'];
        $requirement = $this->chainService($chainStore)->findOpenRequirement('login', 'txn-alpha', 1);
        self::assertNotNull($requirement);
        self::assertSame(RiskAction::Sha18, $requirement->requiredAction);
        $originalExpiry = $requirement->expiresAt;

        // Solve 2: a fresh STRICTLY STRONGER Argon32 assessment raises
        // the obligation to Argon32 (the SAME chain id, the ORIGINAL
        // expiry preserved).
        $stronger = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR), $resolver);
        $stack2 = new RequestStack();
        $stack2->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations2] = $this->validateChained($token2, $stack2, $stronger['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations2[0]->getCode());
        $payload2 = $this->chainService($chainStore)->verify((string) $violations2[0]->getParameters()['{{ chain_ticket }}']);
        self::assertIsArray($payload2);
        self::assertSame($chainId, (string) $payload2['chainId'], 'the raise returns the SAME chain id');
        $requirement = $this->chainService($chainStore)->findOpenRequirement('login', 'txn-alpha', 1);
        self::assertNotNull($requirement);
        self::assertSame(RiskAction::Argon32, $requirement->requiredAction, 'the floor RAISES to the stronger Argon32 assessment');
        self::assertSame(5, $requirement->requiredRank, 'the rank RAISES with the action');
        self::assertSame($chainId, $requirement->chainId, 'the raised chain is the SAME chain');
        self::assertSame($originalExpiry, $requirement->expiresAt, 'the raise preserves the ORIGINAL chain expiry');
    }

    public function testFreshDenyBeatsAnOpenChainableObligation(): void
    {
        // An open SHA18 obligation + a fresh DENY assessment: the fresh
        // terminal rejection wins over the chainable obligation — the
        // post-solve rejection, never a CHAIN_REQUIRED ticket — AND the
        // open obligation itself is TERMINALIZED (markTransactionDenied:
        // the chain becomes TERMINAL denied WITHOUT any stage-2 nonce,
        // the obligation mapping KEPT, chainId + expiry preserved), so
        // the denial is durable for the transaction's lifetime.
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);

        $issuer = $this->issuer($storage);
        $c1 = $issuer->issue('login', '198.51.100.7', 'txn-alpha')->toArray();
        $c2 = $issuer->issue('login', '198.51.100.7', 'txn-alpha')->toArray();
        usleep(($c1['minDurationMs'] + 10) * 1000);
        $token1 = $this->solveToken($c1);
        usleep(($c2['minDurationMs'] + 10) * 1000);
        $token2 = $this->solveToken($c2);

        // Solve 1: the fresh assessment (Sha18) opens the chain.
        $risk = $this->riskStack(SignalVector::fromArray(self::SHA18_VECTOR), $resolver);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations1] = $this->validateChained($token1, $stack, $risk['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations1[0]->getCode());
        $chainId = (string) $this->chainService($chainStore)->verify((string) $violations1[0]->getParameters()['{{ chain_ticket }}'])['chainId'];
        $requirement = $this->chainService($chainStore)->findOpenRequirement('login', 'txn-alpha', 1);
        self::assertNotNull($requirement);
        $originalExpiry = $requirement->expiresAt;

        // Solve 2: a fresh DENY assessment — the terminal rejection wins
        // (the obligation is chainable, not terminal): the post-solve
        // rejection, never CHAIN_REQUIRED, and the chainable obligation
        // is TERMINALIZED (denied — durable, keyed by the chain id).
        $deny = $this->riskStack(SignalVector::fromArray(['network_risk' => 900]), $resolver);
        $stack2 = new RequestStack();
        $stack2->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations2] = $this->validateChained($token2, $stack2, $deny['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertCount(1, $violations2);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violations2[0]->getCode(), 'a fresh Deny over a chainable obligation is the terminal rejection');
        self::assertArrayNotHasKey('{{ chain_ticket }}', $violations2[0]->getParameters(), 'a fresh Deny never becomes a chain ticket');
        $requirement = $this->chainService($chainStore)->findOpenRequirement('login', 'txn-alpha', 1);
        self::assertNotNull($requirement);
        self::assertSame($chainId, $requirement->chainId, 'the SAME chain is terminalized — the obligation mapping is KEPT');
        self::assertSame(RiskAction::Sha18, $requirement->requiredAction, 'the recorded floor is preserved');
        self::assertSame('denied', $requirement->state, 'the fresh Deny TERMINALIZES the open obligation — never left available for a later weak assessment');
        self::assertNull($requirement->stage2Nonce, 'a terminalized chain without a stage-2 issuance carries NO stage-2 nonce');
        self::assertSame($originalExpiry, $requirement->expiresAt, 'the original expiry is preserved');
        self::assertSame(ChainReservationResult::Denied, $this->chainService($chainStore)->reserveStage2($chainId, 'owner-b'), 'the reserve answers the TERMINAL denied state');
    }

    public function testFreshStepUpBeatsAnOpenChainableObligation(): void
    {
        // An open SHA18 obligation + a fresh STEP_UP assessment: StepUp
        // is TERMINAL application-level step-up — it wins over the
        // chainable obligation (the terminal step-up violation, never a
        // chain ticket, never continuing the chain) AND the open
        // obligation itself is TERMINALIZED (markTransactionStepUpRequired:
        // the chain becomes TERMINAL step_up_required WITHOUT any stage-2
        // nonce, the obligation mapping KEPT), so the step-up is durable
        // for the transaction's lifetime.
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);

        $issuer = $this->issuer($storage);
        $c1 = $issuer->issue('login', '198.51.100.7', 'txn-alpha')->toArray();
        $c2 = $issuer->issue('login', '198.51.100.7', 'txn-alpha')->toArray();
        usleep(($c1['minDurationMs'] + 10) * 1000);
        $token1 = $this->solveToken($c1);
        usleep(($c2['minDurationMs'] + 10) * 1000);
        $token2 = $this->solveToken($c2);

        // Solve 1: the fresh assessment (Sha18) opens the chain.
        $risk = $this->riskStack(SignalVector::fromArray(self::SHA18_VECTOR), $resolver);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations1] = $this->validateChained($token1, $stack, $risk['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations1[0]->getCode());
        $chainId = (string) $this->chainService($chainStore)->verify((string) $violations1[0]->getParameters()['{{ chain_ticket }}'])['chainId'];
        $requirement = $this->chainService($chainStore)->findOpenRequirement('login', 'txn-alpha', 1);
        self::assertNotNull($requirement);
        $originalExpiry = $requirement->expiresAt;

        // Solve 2: a fresh STEP_UP assessment — the terminal
        // application-level step-up wins (never a CHAIN_REQUIRED ticket),
        // and the chainable obligation is TERMINALIZED (step_up_required —
        // durable, keyed by the chain id).
        $stepUp = $this->riskStack(SignalVector::fromArray(self::STEP_UP_VECTOR), $resolver);
        $stack2 = new RequestStack();
        $stack2->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations2] = $this->validateChained($token2, $stack2, $stepUp['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertCount(1, $violations2);
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations2[0]->getCode(), 'a fresh StepUp over a chainable obligation is the terminal step-up');
        self::assertArrayNotHasKey('{{ chain_ticket }}', $violations2[0]->getParameters(), 'a fresh StepUp never becomes a chain ticket');
        $requirement = $this->chainService($chainStore)->findOpenRequirement('login', 'txn-alpha', 1);
        self::assertNotNull($requirement);
        self::assertSame($chainId, $requirement->chainId, 'the SAME chain is terminalized — the obligation mapping is KEPT');
        self::assertSame(RiskAction::Sha18, $requirement->requiredAction, 'the recorded floor is preserved');
        self::assertSame('step_up_required', $requirement->state, 'the fresh StepUp TERMINALIZES the open obligation — never left available for a later weak assessment');
        self::assertNull($requirement->stage2Nonce, 'a terminalized chain without a stage-2 issuance carries NO stage-2 nonce');
        self::assertSame($originalExpiry, $requirement->expiresAt, 'the original expiry is preserved');
        self::assertSame(ChainReservationResult::StepUpRequired, $this->chainService($chainStore)->reserveStage2($chainId, 'owner-b'), 'the reserve answers the TERMINAL step_up_required state');
    }

    public function testThreeTokenFreshDenyTerminalizesTheOpenChainAndLaterTokensStayDenied(): void
    {
        // THE DURABILITY INVARIANT: token A opens the SHA18 chain; token
        // B's FRESH DENY (a DIFFERENT stage-1 token — never the exact
        // stage-2 nonce) terminalizes the OBLIGATION itself (the chain
        // becomes TERMINAL denied, the obligation mapping KEPT, chainId +
        // original expiry preserved) and B's solve is denied; later
        // tokens of the same transaction — a fresh Allow/neutral, a
        // weaker Sha16 and a stronger Argon32 assessment alike — STILL
        // receive the terminal denial: never CHAIN_REQUIRED, never Pass,
        // the chain stays denied. The terminality is DURABLE, keyed by
        // the chain/obligation identity, and never relies on the
        // volatile risk condition remaining present.
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);

        $issuer = $this->issuer($storage);
        $tokens = [];
        for ($i = 0; $i < 5; ++$i) {
            $c = $issuer->issue('login', '198.51.100.7', 'txn-alpha')->toArray();
            usleep(($c['minDurationMs'] + 10) * 1000);
            $tokens[] = $this->solveToken($c);
        }

        // A: the fresh assessment (Sha18) opens the chain.
        $risk = $this->riskStack(SignalVector::fromArray(self::SHA18_VECTOR), $resolver);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violationsA] = $this->validateChained($tokens[0], $stack, $risk['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violationsA[0]->getCode());
        $chainId = (string) $this->chainService($chainStore)->verify((string) $violationsA[0]->getParameters()['{{ chain_ticket }}'])['chainId'];
        $requirement = $this->chainService($chainStore)->findOpenRequirement('login', 'txn-alpha', 1);
        self::assertNotNull($requirement);
        $originalExpiry = $requirement->expiresAt;

        // B: the FRESH DENY (a DIFFERENT stage-1 token) — the denial AND
        // the durable terminalization of the open obligation.
        $deny = $this->riskStack(SignalVector::fromArray(['network_risk' => 900]), $resolver);
        $stackB = new RequestStack();
        $stackB->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violationsB] = $this->validateChained($tokens[1], $stackB, $deny['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violationsB[0]->getCode(), 'B\'s fresh Deny is the terminal rejection');
        self::assertArrayNotHasKey('{{ chain_ticket }}', $violationsB[0]->getParameters());
        $requirement = $this->chainService($chainStore)->findOpenRequirement('login', 'txn-alpha', 1);
        self::assertNotNull($requirement, 'the obligation mapping is KEPT');
        self::assertSame($chainId, $requirement->chainId, 'the SAME chain is terminalized');
        self::assertSame('denied', $requirement->state, 'the chain state is TERMINAL denied');
        self::assertNull($requirement->stage2Nonce, 'no stage-2 nonce exists — the terminality is keyed by the chain identity alone');
        self::assertSame($originalExpiry, $requirement->expiresAt, 'chainId + original expiry preserved');

        // C1/C2/C3: later tokens — neutral (Allow), weaker (Sha16) and
        // stronger (Argon32) — STILL receive the terminal denial (never
        // CHAIN_REQUIRED, never Pass); the chain stays denied.
        $assessments = [
            'neutral allow' => null,
            'weaker sha16' => self::SHA16_VECTOR,
            'stronger argon32' => self::ARGON32_VECTOR,
        ];
        $index = 2;
        foreach ($assessments as $label => $vector) {
            $fresh = $this->riskStack($vector !== null ? SignalVector::fromArray($vector) : null, $resolver);
            $stack = new RequestStack();
            $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
            [$violations] = $this->validateChained($tokens[$index], $stack, $fresh['gateway'], $storage, $chainStore, resolver: $resolver);
            ++$index;
            self::assertCount(1, $violations, 'a later token of the denied transaction must never pass: '.$label);
            self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violations[0]->getCode(), 'the durable terminal denial wins — never CHAIN_REQUIRED, never Pass: '.$label);
            self::assertArrayNotHasKey('{{ chain_ticket }}', $violations[0]->getParameters(), 'a terminal denial never becomes a chain ticket: '.$label);
            self::assertSame('denied', $this->chainService($chainStore)->requirementFor($chainId)?->state, 'the chain stays denied: '.$label);
        }
    }

    public function testThreeTokenFreshStepUpTerminalizesTheOpenChainAndLaterTokensStayStepUp(): void
    {
        // The StepUp mirror: token A opens the SHA18 chain; token B's
        // FRESH STEP-UP (a DIFFERENT stage-1 token) terminalizes the
        // obligation (step_up_required — durable, keyed by the chain
        // identity) and B's solve is the terminal step-up; a later
        // neutral token of the same transaction STILL receives the
        // terminal STEP_UP_REQUIRED — never CHAIN_REQUIRED, never Pass.
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);

        $issuer = $this->issuer($storage);
        $tokens = [];
        for ($i = 0; $i < 3; ++$i) {
            $c = $issuer->issue('login', '198.51.100.7', 'txn-alpha')->toArray();
            usleep(($c['minDurationMs'] + 10) * 1000);
            $tokens[] = $this->solveToken($c);
        }

        // A: the fresh assessment (Sha18) opens the chain.
        $risk = $this->riskStack(SignalVector::fromArray(self::SHA18_VECTOR), $resolver);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violationsA] = $this->validateChained($tokens[0], $stack, $risk['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violationsA[0]->getCode());
        $chainId = (string) $this->chainService($chainStore)->verify((string) $violationsA[0]->getParameters()['{{ chain_ticket }}'])['chainId'];

        // B: the FRESH STEP-UP — the terminal step-up AND the durable
        // terminalization of the open obligation.
        $stepUp = $this->riskStack(SignalVector::fromArray(self::STEP_UP_VECTOR), $resolver);
        $stackB = new RequestStack();
        $stackB->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violationsB] = $this->validateChained($tokens[1], $stackB, $stepUp['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violationsB[0]->getCode(), 'B\'s fresh StepUp is the terminal step-up');
        self::assertArrayNotHasKey('{{ chain_ticket }}', $violationsB[0]->getParameters());
        $requirement = $this->chainService($chainStore)->findOpenRequirement('login', 'txn-alpha', 1);
        self::assertNotNull($requirement, 'the obligation mapping is KEPT');
        self::assertSame($chainId, $requirement->chainId, 'the SAME chain is terminalized');
        self::assertSame('step_up_required', $requirement->state, 'the chain state is TERMINAL step_up_required');
        self::assertNull($requirement->stage2Nonce, 'no stage-2 nonce exists — the terminality is keyed by the chain identity alone');

        // C: a later NEUTRAL token — STILL the terminal step-up (never
        // CHAIN_REQUIRED, never Pass); the chain stays step_up_required.
        $neutral = $this->riskStack(resolver: $resolver);
        $stackC = new RequestStack();
        $stackC->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violationsC] = $this->validateChained($tokens[2], $stackC, $neutral['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertCount(1, $violationsC, 'a later token of the step-up transaction must never pass');
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violationsC[0]->getCode(), 'the durable terminal step-up wins — never CHAIN_REQUIRED, never Pass');
        self::assertArrayNotHasKey('{{ chain_ticket }}', $violationsC[0]->getParameters(), 'a terminal step-up never becomes a chain ticket');
        self::assertSame('step_up_required', $this->chainService($chainStore)->requirementFor($chainId)?->state, 'the chain stays step_up_required');
    }

    // ── NONCE-AGNOSTIC transaction terminalization (the store surface) ─

    public function testMarkTransactionDeniedTerminalizesAnOpenObligationWithoutTheStage2Nonce(): void
    {
        // The NONCE-AGNOSTIC transaction terminalization: an OPEN
        // obligation (state available) -> denied WITHOUT the exact
        // stage-2 nonce — the obligation mapping KEPT, chainId + original
        // expiry preserved, the stage2Nonce null (the terminal state
        // carries an OPTIONAL nonce).
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $expiry = time() + 300;
        $requirement = $service->requireStage2($this->nonce(), 'login', 'txn-alpha', 1, RiskAction::Sha18, $expiry);
        $chainId = $requirement->chainId;
        $obligationId = $service->obligationIdFor('login', 'txn-alpha', 1);

        self::assertSame(ChainVerifiedResult::DeniedNew, $service->markTransactionDenied($chainId, $obligationId));
        $state = $service->requirementFor($chainId);
        self::assertSame('denied', $state?->state);
        self::assertNull($state?->stage2Nonce, 'a terminalized chain without a stage-2 issuance carries NO stage-2 nonce');
        self::assertNull($state?->owner);
        self::assertNull($state?->leaseUntil);
        self::assertSame($expiry, $state?->expiresAt, 'the original expiry is preserved');
        self::assertSame(RiskAction::Sha18, $state?->requiredAction, 'the recorded floor is preserved');
        $requirement = $service->findOpenRequirement('login', 'txn-alpha', 1);
        self::assertNotNull($requirement, 'the obligation mapping is KEPT');
        self::assertSame($chainId, $requirement->chainId, 'the obligation keeps the SAME chain id');
        self::assertSame('denied', $requirement->state);

        // The terminalized-available-chain reserve answers the terminal
        // result.
        self::assertSame(ChainReservationResult::Denied, $service->reserveStage2($chainId, 'owner-b'), 'the reserve on the terminalized chain answers the terminal result');

        // markIssued / markVerified on the terminal state are conflicts.
        self::assertSame(ChainIssuedResult::Conflict, $service->markIssued($chainId, 'owner-b', $this->stageNonce('stage2-nonce')), 'markIssued on a terminal state is a conflict');
        self::assertSame(ChainVerifiedResult::Conflict, $service->markVerified($chainId, $this->stageNonce('stage2-nonce')), 'markVerified on a terminal state is a conflict');
        self::assertFalse($service->rearmIssued($chainId, $this->stageNonce('stage2-nonce')), 'a terminal chain can never rearm');

        // Idempotency: a repeated fresh Deny is denied_same with no state
        // change; the OTHER terminal disposition can never flip it.
        self::assertSame(ChainVerifiedResult::DeniedSame, $service->markTransactionDenied($chainId, $obligationId), 'a repeated fresh Deny is idempotent');
        self::assertSame('denied', $service->requirementFor($chainId)?->state, 'no state change');
        self::assertSame(ChainVerifiedResult::Conflict, $service->markTransactionStepUpRequired($chainId, $obligationId), 'a fresh StepUp on a denied chain is a conflict — terminal states never flip');
        self::assertSame('denied', $service->requirementFor($chainId)?->state, 'the denial wins');

        // Absent -> missing.
        self::assertSame(ChainVerifiedResult::Missing, $service->markTransactionDenied('no-such-chain', $obligationId));
        self::assertSame(ChainVerifiedResult::Missing, $service->markTransactionStepUpRequired('no-such-chain', $obligationId));
    }

    public function testMarkTransactionStepUpRequiredTerminalizesAReservedChainAndClearsTheReservation(): void
    {
        // reserved(owner, lease) -> step_up_required: the reservation
        // fields are cleared (the strict v2 decode requires
        // owner/leaseUntil null outside the reserved state).
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $requirement = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Sha18, time() + 300);
        $obligationId = $service->obligationIdFor('login', '', 1);

        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
        self::assertSame(ChainVerifiedResult::StepUpRequiredNew, $service->markTransactionStepUpRequired($requirement->chainId, $obligationId));
        $state = $service->requirementFor($requirement->chainId);
        self::assertSame('step_up_required', $state?->state);
        self::assertNull($state?->owner, 'the reservation owner is cleared');
        self::assertNull($state?->leaseUntil, 'the reservation lease is cleared');
        self::assertNull($state?->stage2Nonce);
        self::assertSame(ChainReservationResult::StepUpRequired, $service->reserveStage2($requirement->chainId, 'owner-b'), 'the reserve answers the TERMINAL step_up_required state');
        self::assertSame(ChainVerifiedResult::StepUpRequiredSame, $service->markTransactionStepUpRequired($requirement->chainId, $obligationId), 'a repeated fresh StepUp is idempotent');
        self::assertSame(ChainVerifiedResult::Conflict, $service->markTransactionDenied($requirement->chainId, $obligationId), 'a fresh Deny on a step_up_required chain is a conflict — terminal states never flip');
    }

    public function testMarkTransactionTerminalizationsPreserveAnExistingStage2Nonce(): void
    {
        // issued(stage2Nonce) -> denied/step_up_required PRESERVES the
        // exact stage-2 nonce (the terminal state carries an OPTIONAL
        // nonce — a valid Kiwi nonce when one exists). The legacy
        // 'completed' state preserves it too.
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $nonce = $this->stageNonce('stage2-nonce');

        $issued = $service->requireStage2($this->nonce(), 'login', 'txn-issued', 1, RiskAction::Sha18, time() + 300);
        $issuedObligationId = $service->obligationIdFor('login', 'txn-issued', 1);
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($issued->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($issued->chainId, 'owner-a', $nonce));
        self::assertSame(ChainVerifiedResult::DeniedNew, $service->markTransactionDenied($issued->chainId, $issuedObligationId));
        self::assertSame('denied', $service->requirementFor($issued->chainId)?->state);
        self::assertSame($nonce, $service->requirementFor($issued->chainId)?->stage2Nonce, 'the exact stage-2 nonce is PRESERVED by the nonce-agnostic terminalization');

        $completed = $service->requireStage2($this->nonce(), 'login', 'txn-completed', 1, RiskAction::Sha18, time() + 300);
        $completedObligationId = $service->obligationIdFor('login', 'txn-completed', 1);
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($completed->chainId, 'owner-a'));
        $legacy = $service->complete($completed->chainId, 'owner-a', $nonce);
        self::assertIsArray($legacy);
        self::assertSame(ChainVerifiedResult::StepUpRequiredNew, $service->markTransactionStepUpRequired($completed->chainId, $completedObligationId));
        self::assertSame('step_up_required', $service->requirementFor($completed->chainId)?->state);
        self::assertSame($nonce, $service->requirementFor($completed->chainId)?->stage2Nonce, 'the legacy completed state preserves the nonce too');
    }

    public function testMarkTransactionDeniedAfterPassAnswersAlreadyVerified(): void
    {
        // verified -> already_verified: the transaction already ended via
        // Pass — its obligation is gone, there is no chain left to
        // terminalize (defensive: a fresh Deny after a Pass has no chain
        // to terminalize).
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $nonce = $this->stageNonce('stage2-nonce');
        $requirement = $service->requireStage2($this->nonce(), 'login', 'txn-alpha', 1, RiskAction::Sha18, time() + 300);
        $obligationId = $service->obligationIdFor('login', 'txn-alpha', 1);

        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', $nonce));
        self::assertSame(ChainVerifiedResult::VerifiedNew, $service->markVerified($requirement->chainId, $nonce));

        self::assertSame(ChainVerifiedResult::AlreadyVerified, $service->markTransactionDenied($requirement->chainId, $obligationId), 'the post-Pass terminalization answers already_verified');
        self::assertSame(ChainVerifiedResult::AlreadyVerified, $service->markTransactionStepUpRequired($requirement->chainId, $obligationId));
        self::assertSame('verified', $service->requirementFor($requirement->chainId)?->state, 'the terminal verified record is untouched');
        self::assertSame($nonce, $service->requirementFor($requirement->chainId)?->stage2Nonce);
        self::assertNull($service->findOpenRequirement('login', 'txn-alpha', 1), 'the obligation was cleared by the Pass');
    }

    public function testTerminalizedChainWithoutStage2NonceStrictlyDecodes(): void
    {
        // The strict v2 decode accepts step_up_required/denied with
        // EITHER a valid Kiwi nonce OR null — a terminalized (nonce-less)
        // chain record is readable and re-readable through the full
        // machine (read, obligation lookup, transitions).
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $requirement = $service->requireStage2($this->nonce(), 'login', 'txn-alpha', 1, RiskAction::Sha18, time() + 300);
        $obligationId = $service->obligationIdFor('login', 'txn-alpha', 1);
        $expiry = $requirement->expiresAt;

        self::assertSame(ChainVerifiedResult::DeniedNew, $service->markTransactionDenied($requirement->chainId, $obligationId));
        $read = $store->read($requirement->chainId);
        self::assertIsArray($read, 'the terminalized record strictly decodes');
        self::assertSame('denied', $read['state']);
        self::assertNull($read['stage2Nonce'], 'the terminal state accepts a NULL stage-2 nonce');
        self::assertNull($read['owner']);
        self::assertNull($read['leaseUntil']);
        self::assertSame($expiry, $read['expiresAt'], 'the original expiry is preserved');

        // The full machine re-reads the record: a repeated
        // terminalization, the obligation lookup and the typed
        // requirement all decode it.
        self::assertSame(ChainVerifiedResult::DeniedSame, $service->markTransactionDenied($requirement->chainId, $obligationId));
        $requirement = $service->findOpenRequirement('login', 'txn-alpha', 1);
        self::assertNotNull($requirement);
        self::assertSame('denied', $requirement->state);
        self::assertNull($requirement->stage2Nonce);
        self::assertSame(ChainReservationResult::Denied, $service->reserveStage2($requirement->chainId, 'owner-b'));
    }

    public function testObligationBoundTerminalizationRefusesAStaleChainId(): void
    {
        // OBLIGATION-BOUND terminalization (atomic over BOTH keys): the
        // store's terminalization takes the transaction's obligation id
        // and the transition verifies the chain record STILL agrees on
        // the obligation id AND the obligation mapping STILL points at
        // this chain. A STALE chainId (the obligation moved to a
        // different chain between the read and the transition) answers
        // 'obligation_moved' at the store (Conflict at the service) and
        // NOTHING is transitioned — the transaction's real chain is
        // never left open behind a stale terminalization; the happy path
        // (the mapping intact) transitions.
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $expiry = time() + 300;

        // The transaction's chain + its obligation mapping agree.
        $requirement = $service->requireStage2($this->nonce(), 'login', 'txn-alpha', 1, RiskAction::Sha18, $expiry);
        $obligationId = $service->obligationIdFor('login', 'txn-alpha', 1);
        $chainId = $requirement->chainId;
        self::assertSame($chainId, $store->obligationChainId($obligationId), 'the obligation maps the chain');

        // The obligation MOVES to a fresh chain (a re-created chain of
        // the same transaction) while the stale chain record survives.
        $fresh = $service->requireStage2($this->nonce(), 'login', 'txn-beta', 1, RiskAction::Sha18, $expiry);
        $store->deleteObligation($chainId, $obligationId);
        $store->createWithObligation($fresh->chainId, $obligationId, $this->nonce(), 'login', 'txn-alpha', 'sha18', 1, 300);

        // The stale-chainId terminalization is refused atomically:
        // NOTHING transitioned, the mapping untouched.
        self::assertSame('obligation_moved', $store->markTransactionDenied($chainId, $obligationId), 'a stale chainId (the obligation moved) is refused at the store');
        self::assertSame('available', $service->requirementFor($chainId)?->state, 'the stale chain is untouched');
        self::assertSame($fresh->chainId, $store->obligationChainId($obligationId), 'the obligation mapping is untouched');
        self::assertSame(ChainVerifiedResult::Conflict, $service->markTransactionDenied($chainId, $obligationId), 'the service surfaces the refused terminalization as Conflict');
        self::assertSame('available', $service->requirementFor($chainId)?->state, 'still untouched');

        // The happy path (the mapping intact) transitions.
        self::assertSame('denied_new', $store->markTransactionDenied($fresh->chainId, $obligationId), 'the happy path transitions');
        self::assertSame('denied', $service->requirementFor($fresh->chainId)?->state);

        // The RECORD-AGREES guard: an obligation id the chain record does
        // NOT carry is refused too (the transaction's chain is not this
        // record's chain).
        $other = $service->requireStage2($this->nonce(), 'login', 'txn-gamma', 1, RiskAction::Sha18, $expiry);
        $otherObligationId = $service->obligationIdFor('login', 'txn-gamma', 1);
        self::assertSame($otherObligationId, $store->read($other->chainId)['obligationId'], 'the record carries its own obligation id');
        self::assertSame('obligation_moved', $store->markTransactionDenied($other->chainId, $obligationId), 'a mismatched obligation id is refused — the record does not agree');
        self::assertSame('available', $service->requirementFor($other->chainId)?->state, 'the record is untouched');

        // The VERIFIED chain (the obligation was cleared atomically at
        // verification): the gone mapping is the already-completed
        // anomaly — there is no chain left to terminalize.
        $verified = $service->requireStage2($this->nonce(), 'login', 'txn-verified-2', 1, RiskAction::Sha18, $expiry);
        $verifiedObligationId = $service->obligationIdFor('login', 'txn-verified-2', 1);
        $nonce = $this->stageNonce('stage2-nonce');
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($verified->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($verified->chainId, 'owner-a', $nonce));
        self::assertSame(ChainVerifiedResult::VerifiedNew, $service->markVerified($verified->chainId, $nonce));
        self::assertSame('already_completed', $store->markTransactionDenied($verified->chainId, $verifiedObligationId), 'a gone obligation is the already-completed anomaly at the store');
        self::assertSame(ChainVerifiedResult::AlreadyVerified, $service->markTransactionStepUpRequired($verified->chainId, $verifiedObligationId), 'the service surfaces it as AlreadyVerified');
    }

    // ── The atomic races: terminalization vs reservation/issuance/verify ─

    public function testTerminalizationVersusReservationBothOrdersAreConsistent(): void
    {
        // The atomic race terminalization vs stage-2 reservation, both
        // orders: whichever lands first, the final state is consistent —
        // the terminalized chain answers the TERMINAL result on reserve.
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);

        // Order 1: the reservation lands FIRST, the terminalization
        // second — the terminalization WINS against the in-flight
        // reservation (the reservation is moot) and the reserve after it
        // answers the terminal result.
        $a = $service->requireStage2($this->nonce(), 'login', 'txn-race-a', 1, RiskAction::Sha18, time() + 300);
        $aObligationId = $service->obligationIdFor('login', 'txn-race-a', 1);
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($a->chainId, 'owner-a'));
        self::assertSame(ChainVerifiedResult::DeniedNew, $service->markTransactionDenied($a->chainId, $aObligationId));
        self::assertSame('denied', $service->requirementFor($a->chainId)?->state, 'the terminalization wins against the in-flight reservation');
        self::assertNull($service->requirementFor($a->chainId)?->owner, 'the reservation fields are cleared');
        self::assertSame(ChainReservationResult::Denied, $service->reserveStage2($a->chainId, 'owner-b'), 'the reserve on the terminalized chain answers the terminal result');

        // Order 2: the terminalization lands FIRST, the reservation
        // second — the reserve answers the terminal result (never
        // available).
        $b = $service->requireStage2($this->nonce(), 'login', 'txn-race-b', 1, RiskAction::Sha18, time() + 300);
        $bObligationId = $service->obligationIdFor('login', 'txn-race-b', 1);
        self::assertSame(ChainVerifiedResult::StepUpRequiredNew, $service->markTransactionStepUpRequired($b->chainId, $bObligationId));
        self::assertSame(ChainReservationResult::StepUpRequired, $service->reserveStage2($b->chainId, 'owner-a'), 'a reserve on the terminalized chain returns the terminal result');
        self::assertSame('step_up_required', $service->requirementFor($b->chainId)?->state);
    }

    public function testTerminalizationVersusMarkVerifiedBothOrdersAreConsistent(): void
    {
        // The atomic race terminalization vs markVerified, both orders:
        // the FIRST writer wins — verified -> 'already_verified' (the
        // obligation is already gone); terminal -> markVerified
        // 'conflict'.
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $nonce = $this->stageNonce('stage2-nonce');

        // Order 1: markVerified lands FIRST — the terminalization answers
        // 'already_verified' and the chain stays verified.
        $a = $service->requireStage2($this->nonce(), 'login', 'txn-race-verify-a', 1, RiskAction::Sha18, time() + 300);
        $aObligationId = $service->obligationIdFor('login', 'txn-race-verify-a', 1);
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($a->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($a->chainId, 'owner-a', $nonce));
        self::assertSame(ChainVerifiedResult::VerifiedNew, $service->markVerified($a->chainId, $nonce));
        self::assertSame(ChainVerifiedResult::AlreadyVerified, $service->markTransactionDenied($a->chainId, $aObligationId), 'the terminalization on a verified chain answers already_verified');
        self::assertSame('verified', $service->requirementFor($a->chainId)?->state, 'the verified terminal state is untouched');

        // Order 2: the terminalization lands FIRST — the later
        // markVerified is a conflict (a terminal state can never verify).
        $b = $service->requireStage2($this->nonce(), 'login', 'txn-race-verify-b', 1, RiskAction::Sha18, time() + 300);
        $bObligationId = $service->obligationIdFor('login', 'txn-race-verify-b', 1);
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($b->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($b->chainId, 'owner-a', $nonce));
        self::assertSame(ChainVerifiedResult::DeniedNew, $service->markTransactionDenied($b->chainId, $bObligationId));
        self::assertSame(ChainVerifiedResult::Conflict, $service->markVerified($b->chainId, $nonce), 'a markVerified on the terminalized chain is a conflict');
        self::assertSame('denied', $service->requirementFor($b->chainId)?->state);
    }

    public function testTerminalizationVersusMarkIssuedBothOrdersAreConsistent(): void
    {
        // The atomic race terminalization vs markIssued, both orders:
        // issued -> terminal still terminalizes (the exact nonce is
        // preserved); terminal -> markIssued answers 'conflict' (a
        // terminal chain can never be issued again).
        $store = new ArrayChainedChallengeStateStore();
        $service = $this->chainService($store);
        $nonce = $this->stageNonce('stage2-nonce');

        // Order 1: markIssued lands FIRST — the terminalization on the
        // issued chain still terminalizes, PRESERVING the exact nonce.
        $a = $service->requireStage2($this->nonce(), 'login', 'txn-race-issue-a', 1, RiskAction::Sha18, time() + 300);
        $aObligationId = $service->obligationIdFor('login', 'txn-race-issue-a', 1);
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($a->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($a->chainId, 'owner-a', $nonce));
        self::assertSame(ChainVerifiedResult::DeniedNew, $service->markTransactionDenied($a->chainId, $aObligationId));
        self::assertSame('denied', $service->requirementFor($a->chainId)?->state);
        self::assertSame($nonce, $service->requirementFor($a->chainId)?->stage2Nonce, 'the issued nonce is preserved');

        // Order 2: the terminalization lands FIRST — the later markIssued
        // is a conflict.
        $b = $service->requireStage2($this->nonce(), 'login', 'txn-race-issue-b', 1, RiskAction::Sha18, time() + 300);
        $bObligationId = $service->obligationIdFor('login', 'txn-race-issue-b', 1);
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($b->chainId, 'owner-a'));
        self::assertSame(ChainVerifiedResult::StepUpRequiredNew, $service->markTransactionStepUpRequired($b->chainId, $bObligationId));
        self::assertSame(ChainIssuedResult::Conflict, $service->markIssued($b->chainId, 'owner-a', $nonce), 'a markIssued on the terminalized chain is a conflict');
        self::assertSame('step_up_required', $service->requirementFor($b->chainId)?->state);
    }

    public function testOpenObligationSurvivesFreshWeakerAndNeutralAssessments(): void
    {
        // An open SHA18 obligation + fresh WEAKER (Sha16) and NEUTRAL
        // (Allow) assessments: the obligation stays UNCHANGED (its
        // recorded SHA18 floor, the SAME chain id, the ORIGINAL expiry)
        // and every solve is CHAIN_REQUIRED — a stage-1 token of a
        // chained transaction can never pass, and the floor never
        // decays.
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);

        $issuer = $this->issuer($storage);
        $tokens = [];
        for ($i = 0; $i < 3; ++$i) {
            $c = $issuer->issue('login', '198.51.100.7', 'txn-alpha')->toArray();
            usleep(($c['minDurationMs'] + 10) * 1000);
            $tokens[] = $this->solveToken($c);
        }

        // Solve 1: the fresh assessment (Sha18) opens the chain at the
        // SHA18 floor.
        $risk = $this->riskStack(SignalVector::fromArray(self::SHA18_VECTOR), $resolver);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations1] = $this->validateChained($tokens[0], $stack, $risk['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations1[0]->getCode());
        $chainId = (string) $this->chainService($chainStore)->verify((string) $violations1[0]->getParameters()['{{ chain_ticket }}'])['chainId'];
        $requirement = $this->chainService($chainStore)->findOpenRequirement('login', 'txn-alpha', 1);
        self::assertNotNull($requirement);
        $originalExpiry = $requirement->expiresAt;

        // Solve 2: a fresh WEAKER-but-still-chainable Sha16 assessment —
        // the SAME chain, the floor NEVER decays.
        $weaker = $this->riskStack(SignalVector::fromArray(self::SHA16_VECTOR), $resolver);
        $stack2 = new RequestStack();
        $stack2->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations2] = $this->validateChained($tokens[1], $stack2, $weaker['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations2[0]->getCode(), 'a weaker chainable reassessment still demands the open chain');
        $payload2 = $this->chainService($chainStore)->verify((string) $violations2[0]->getParameters()['{{ chain_ticket }}']);
        self::assertIsArray($payload2);
        self::assertSame($chainId, (string) $payload2['chainId'], 'the weaker reassessment returns the SAME chain');
        self::assertSame($originalExpiry, (int) $payload2['expiresAt'], 'the ticket keeps the requirement\'s ORIGINAL expiry');

        // Solve 3: a NEUTRAL assessment (would be a plain Pass) — the
        // recorded floor is authoritative: CHAIN_REQUIRED, never a Pass,
        // and the requirement keeps its RECORDED stronger action/rank.
        $neutral = $this->riskStack(resolver: $resolver);
        $stack3 = new RequestStack();
        $stack3->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations3] = $this->validateChained($tokens[2], $stack3, $neutral['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertCount(1, $violations3, 'a stage-1 token must never pass while the obligation is open');
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations3[0]->getCode());
        $payload3 = $this->chainService($chainStore)->verify((string) $violations3[0]->getParameters()['{{ chain_ticket }}']);
        self::assertIsArray($payload3);
        self::assertSame($chainId, (string) $payload3['chainId'], 'the neutral reassessment returns the SAME chain');
        self::assertSame($originalExpiry, (int) $payload3['expiresAt'], 'the ticket keeps the requirement\'s ORIGINAL expiry');
        $requirement = $this->chainService($chainStore)->findOpenRequirement('login', 'txn-alpha', 1);
        self::assertNotNull($requirement);
        self::assertSame(RiskAction::Sha18, $requirement->requiredAction, 'the recorded floor NEVER decays to a weaker action');
        self::assertSame(2, $requirement->requiredRank, 'the recorded rank NEVER decays');
        self::assertSame($chainId, $requirement->chainId, 'the obligation is the SAME chain');
        self::assertSame($originalExpiry, $requirement->expiresAt, 'the obligation keeps the ORIGINAL expiry');
    }

    public function testTerminalStepUpObligationWinsOverAFreshDeny(): void
    {
        // The transaction is bound to its TERMINAL step-up: even a fresh
        // DENY assessment cannot change it — the terminal state wins
        // PERMANENTLY (the terminal step-up violation), never the fresh
        // rejection.
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);

        $stage1 = $this->solvedStage1($storage, 'txn-alpha');
        $requirement = $chainService->requireStage2($stage1['nonce'], 'login', 'txn-alpha', 1, RiskAction::Sha18, time() + 300);
        self::assertSame(ChainReservationResult::Available, $chainService->reserveStage2($requirement->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $chainService->markIssued($requirement->chainId, 'owner-a', $this->stageNonce('stage2-nonce')));
        self::assertSame(ChainVerifiedResult::StepUpRequiredNew, $chainService->markStepUpRequired($requirement->chainId, $this->stageNonce('stage2-nonce')));
        self::assertSame('step_up_required', $chainService->requirementFor($requirement->chainId)?->state);

        // A PRE-ISSUED stage-1 token of the same transaction solved under
        // a fresh DENY assessment: the recorded terminal step-up wins.
        $c = $this->issuer($storage)->issue('login', '198.51.100.7', 'txn-alpha')->toArray();
        usleep(($c['minDurationMs'] + 10) * 1000);
        $token = $this->solveToken($c);
        $deny = $this->riskStack(SignalVector::fromArray(['network_risk' => 900]), $resolver);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations] = $this->validateChained($token, $stack, $deny['gateway'], $storage, $chainStore, resolver: $resolver);

        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations[0]->getCode(), 'the recorded terminal step-up wins PERMANENTLY over a fresh Deny');
        self::assertArrayNotHasKey('{{ chain_ticket }}', $violations[0]->getParameters(), 'a terminal step-up never becomes a chain ticket');
        self::assertSame('step_up_required', $chainService->requirementFor($requirement->chainId)?->state, 'the terminal state survives');
    }

    public function testSecondStage1TokenOfTheSameChainGetsTheByteIdenticalTicket(): void
    {
        // TWO PRE-ISSUED stage-1 tokens of one binding: the FIRST solve
        // creates the chain and returns its ticket; the SECOND solve (the
        // obligation-first path) returns a disposition referencing the
        // SAME chain with a BYTE-IDENTICAL ticket — the re-sign ALWAYS
        // uses the requirement's ACTUAL server-held expiresAt, never a
        // fresh now+chainTtl (the deterministic-retry design: the same
        // verified nonce + the same persisted disposition always
        // reproduce the same ticket).
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);

        $issuer = $this->issuer($storage);
        $c1 = $issuer->issue('login', '198.51.100.7', 'txn-alpha')->toArray();
        $c2 = $issuer->issue('login', '198.51.100.7', 'txn-alpha')->toArray();
        usleep(($c1['minDurationMs'] + 10) * 1000);
        $token1 = $this->solveToken($c1);
        usleep(($c2['minDurationMs'] + 10) * 1000);
        $token2 = $this->solveToken($c2);

        // Solve 1: the reassessment (Argon32) opens the chain and the
        // ticket is signed from the requirement's server-held expiry.
        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR), $resolver);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations1] = $this->validateChained($token1, $stack, $risk['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations1[0]->getCode());
        $ticket1 = $violations1[0]->getParameters()['{{ chain_ticket }}'];
        self::assertIsString($ticket1);
        $payload1 = $this->chainService($chainStore)->verify($ticket1);
        self::assertIsArray($payload1);
        $requirement = $this->chainService($chainStore)->findOpenRequirement('login', 'txn-alpha', 1);
        self::assertNotNull($requirement);
        self::assertSame((int) $payload1['expiresAt'], $requirement->expiresAt, 'the fresh ticket carries the requirement\'s server-held expiry');

        // The SECOND solve lands in a LATER second (a fresh now+chainTtl
        // would differ): the obligation-first CHAIN_REQUIRED re-signs
        // with the requirement's ACTUAL expiry — the byte-identical
        // ticket.
        usleep(1_100_000);
        $risk2 = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR), $resolver);
        $stack2 = new RequestStack();
        $stack2->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations2] = $this->validateChained($token2, $stack2, $risk2['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertCount(1, $violations2, 'the second stage-1 token of the same chain must never pass');
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations2[0]->getCode(), 'the second stage-1 token of the same chain is CHAIN_REQUIRED');
        $ticket2 = $violations2[0]->getParameters()['{{ chain_ticket }}'];
        self::assertIsString($ticket2);
        self::assertSame($ticket1, $ticket2, 'the obligation-first ticket is BYTE-IDENTICAL to the original — both sign from the requirement\'s server-held expiry, never a fresh now+chainTtl');
        $payload2 = $this->chainService($chainStore)->verify($ticket2);
        self::assertIsArray($payload2);
        self::assertSame((string) $payload1['chainId'], (string) $payload2['chainId'], 'the disposition references the SAME chain');
        $requirement = $this->chainService($chainStore)->findOpenRequirement('login', 'txn-alpha', 1);
        self::assertNotNull($requirement);
        self::assertSame((int) $payload2['expiresAt'], $requirement->expiresAt, 'both tickets decode to the requirement\'s server-held expiry — never now+chainTtl');
    }

    public function testOpenObligationInTerminalStepUpNeverPasses(): void
    {
        // The transaction is bound to its TERMINAL step-up: a later
        // stage-1 token of the same transaction must NEVER pass — the
        // requirement's recorded terminal step-up is authoritative (the
        // terminal step-up violation), never a Pass, never a chain
        // ticket.
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);

        // The third token is PRE-ISSUED with the same binding BEFORE the
        // chain exists.
        $issuer = $this->issuer($storage);
        $c3 = $issuer->issue('login', '198.51.100.7', 'txn-alpha')->toArray();
        usleep(($c3['minDurationMs'] + 10) * 1000);
        $token3 = $this->solveToken($c3);

        // Stage 1: the reassessment (Argon32) opens the chain.
        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR), $resolver);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $stage1 = $this->solvedStage1($storage, 'txn-alpha');
        [$violations] = $this->validateChained($stage1['token'], $stack, $risk['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $ticket = $violations[0]->getParameters()['{{ chain_ticket }}'];

        // Stage 2: issue the stronger challenge through the controller
        // and solve it with a STEP-UP post-solve decision — the chain
        // becomes TERMINAL step_up_required (the obligation is KEPT).
        $controller = $this->chainController($storage, $chainService, $risk['gateway'], authority: new FixtureBindingAuthority('txn-alpha'));
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), sprintf('the stage-2 issuance must succeed: %s', (string) $response->getContent()));
        $stage2 = json_decode((string) $response->getContent(), true);
        usleep(($stage2['minDurationMs'] + 10) * 1000);
        $stage2Token = $this->solveChallenge($stage2);
        $risk['store']->setVector(SignalVector::fromArray(self::STEP_UP_VECTOR));
        $stack2 = new RequestStack();
        $stack2->push(Request::create('/', 'POST', ['kiwi__token' => $stage2Token, 'kiwi_request_binding' => 'txn-alpha'], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations2] = $this->validateChained($stage2Token, $stack2, $risk['gateway'], $storage, $chainStore);
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations2[0]->getCode(), 'the stage-2 solve with a StepUp decision is the terminal step-up');
        self::assertSame('step_up_required', $chainService->requirementFor((string) $chainService->verify((string) $ticket)['chainId'])?->state);

        // The PRE-ISSUED stage-1 token of the same transaction: the
        // requirement's recorded terminal step-up is authoritative.
        $neutral = $this->riskStack(resolver: $resolver);
        $stack3 = new RequestStack();
        $stack3->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations3] = $this->validateChained($token3, $stack3, $neutral['gateway'], $storage, $chainStore, resolver: $resolver);

        self::assertCount(1, $violations3, 'a stage-1 token of a terminal step-up transaction must never pass');
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations3[0]->getCode(), 'the recorded terminal step-up is authoritative');
        self::assertArrayNotHasKey('{{ chain_ticket }}', $violations3[0]->getParameters(), 'a terminal step-up never becomes a chain ticket');
        self::assertSame('step_up_required', $chainService->requirementFor((string) $chainService->verify((string) $ticket)['chainId'])?->state, 'the terminal state survives');
    }

    public function testOpenObligationInTerminalDenialNeverPasses(): void
    {
        // The transaction is bound to its TERMINAL denial: a later
        // stage-1 token of the same transaction must NEVER pass — the
        // requirement's recorded terminal denial is authoritative (the
        // post-solve rejection), never a Pass, never a chain ticket.
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);

        // The third token is PRE-ISSUED with the same binding BEFORE the
        // chain exists.
        $issuer = $this->issuer($storage);
        $c3 = $issuer->issue('login', '198.51.100.7', 'txn-alpha')->toArray();
        usleep(($c3['minDurationMs'] + 10) * 1000);
        $token3 = $this->solveToken($c3);

        // Stage 1: the reassessment (Argon32) opens the chain.
        $risk = $this->riskStack(SignalVector::fromArray(self::ARGON32_VECTOR), $resolver);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $stage1 = $this->solvedStage1($storage, 'txn-alpha');
        [$violations] = $this->validateChained($stage1['token'], $stack, $risk['gateway'], $storage, $chainStore, resolver: $resolver);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $ticket = $violations[0]->getParameters()['{{ chain_ticket }}'];

        // Stage 2: issue the stronger challenge through the controller
        // and solve it with a DENY post-solve decision — the chain
        // becomes TERMINAL denied (the obligation is KEPT).
        $controller = $this->chainController($storage, $chainService, $risk['gateway'], authority: new FixtureBindingAuthority('txn-alpha'));
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), sprintf('the stage-2 issuance must succeed: %s', (string) $response->getContent()));
        $stage2 = json_decode((string) $response->getContent(), true);
        usleep(($stage2['minDurationMs'] + 10) * 1000);
        $stage2Token = $this->solveChallenge($stage2);
        $risk['store']->setVector(SignalVector::fromArray(['network_risk' => 900]));
        $stack2 = new RequestStack();
        $stack2->push(Request::create('/', 'POST', ['kiwi__token' => $stage2Token, 'kiwi_request_binding' => 'txn-alpha'], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations2] = $this->validateChained($stage2Token, $stack2, $risk['gateway'], $storage, $chainStore);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violations2[0]->getCode(), 'the stage-2 solve with a Deny decision is the terminal denial');
        self::assertSame('denied', $chainService->requirementFor((string) $chainService->verify((string) $ticket)['chainId'])?->state);

        // The PRE-ISSUED stage-1 token of the same transaction: the
        // requirement's recorded terminal denial is authoritative.
        $neutral = $this->riskStack(resolver: $resolver);
        $stack3 = new RequestStack();
        $stack3->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        [$violations3] = $this->validateChained($token3, $stack3, $neutral['gateway'], $storage, $chainStore, resolver: $resolver);

        self::assertCount(1, $violations3, 'a stage-1 token of a terminally denied transaction must never pass');
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violations3[0]->getCode(), 'the recorded terminal denial is authoritative');
        self::assertArrayNotHasKey('{{ chain_ticket }}', $violations3[0]->getParameters(), 'a terminal denial never becomes a chain ticket');
        self::assertSame('denied', $chainService->requirementFor((string) $chainService->verify((string) $ticket)['chainId'])?->state, 'the terminal state survives');
    }

    /**
     * A chaining-enabled validator over an EXPLICIT chain service (the
     * decorated-store seam of the failure-injection tests) through the
     * full Symfony pipeline.
     *
     * @return array{0: ConstraintViolationListInterface, 1: KiwiCaptchaValidator}
     */
    private function validateWithService(string $token, RequestStack $stack, RiskGateway $gateway, ArrayStorage $storage, ChainedChallengeTicketService $chainService, ?SiteVerifyMetadataStore $metadataStore = null, ?RiskProfileResolver $resolver = null): array
    {
        $validator = new KiwiCaptchaValidator(
            new Verifier($storage),
            $stack,
            self::SECRET,
            enforceTelemetry: false,
            risk: $gateway,
            continuityCookie: new ContinuityCookie(),
            storage: $storage,
            chainTickets: $chainService,
            policyVersion: 1,
            metadataStore: $metadataStore,
            riskResolver: $resolver,
            bindingAuthority: new FixtureBindingAuthority('txn-alpha'),
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
}
/**
 * A transactional chain-state decorator with a test seam: the OBLIGATION
 * LOOKUP (findOpenRequirement's backend read) fails on demand — the
 * validator's fail-closed chain-state read path. All other operations
 * delegate to the wrapped store.
 */
final class FailingObligationLookupStore implements TransactionalChainedChallengeStateStore
{
    public bool $failObligationLookup = false;

    public function __construct(private readonly TransactionalChainedChallengeStateStore $inner)
    {
    }

    public function create(string $chainId, string $stage1Nonce, string $scope, int $ttlSecs, ?string $requestBinding = null, ?string $requiredAction = null, int $policyVersion = 1): void
    {
        $this->inner->create($chainId, $stage1Nonce, $scope, $ttlSecs, $requestBinding, $requiredAction, $policyVersion);
    }

    public function createWithObligation(string $chainId, string $obligationId, string $stage1Nonce, string $scope, ?string $requestBinding, string $requiredAction, int $policyVersion, int $ttlSecs): void
    {
        $this->inner->createWithObligation($chainId, $obligationId, $stage1Nonce, $scope, $requestBinding, $requiredAction, $policyVersion, $ttlSecs);
    }

    public function createOrGetObligation(string $obligationId, string $chainId, string $stage1Nonce, string $scope, string $requestBinding, string $requiredAction, int $requiredRank, int $policyVersion, int $expiresAt, int $ttlSecs): string
    {
        return $this->inner->createOrGetObligation($obligationId, $chainId, $stage1Nonce, $scope, $requestBinding, $requiredAction, $requiredRank, $policyVersion, $expiresAt, $ttlSecs);
    }

    public function obligationChainId(string $obligationId): ?string
    {
        if ($this->failObligationLookup) {
            throw new \RuntimeException('simulated chain obligation read outage');
        }

        return $this->inner->obligationChainId($obligationId);
    }

    public function read(string $chainId): ?array
    {
        return $this->inner->read($chainId);
    }

    public function reserve(string $chainId, string $ownerToken, int $leaseSecs): string
    {
        return $this->inner->reserve($chainId, $ownerToken, $leaseSecs);
    }

    public function release(string $chainId, string $ownerToken): void
    {
        $this->inner->release($chainId, $ownerToken);
    }

    public function markIssued(string $chainId, string $ownerToken, string $stage2Nonce): string
    {
        return $this->inner->markIssued($chainId, $ownerToken, $stage2Nonce);
    }

    public function markVerified(string $chainId, string $stage2Nonce): string
    {
        return $this->inner->markVerified($chainId, $stage2Nonce);
    }

    public function markStepUpRequired(string $chainId, string $stage2Nonce): string
    {
        return $this->inner->markStepUpRequired($chainId, $stage2Nonce);
    }

    public function markDenied(string $chainId, string $stage2Nonce): string
    {
        return $this->inner->markDenied($chainId, $stage2Nonce);
    }

    public function markTransactionDenied(string $chainId, string $obligationId): string
    {
        return $this->inner->markTransactionDenied($chainId, $obligationId);
    }

    public function markTransactionStepUpRequired(string $chainId, string $obligationId): string
    {
        return $this->inner->markTransactionStepUpRequired($chainId, $obligationId);
    }

    public function rearmIssued(string $chainId, string $expectedStage2Nonce): bool
    {
        return $this->inner->rearmIssued($chainId, $expectedStage2Nonce);
    }

    public function deleteObligation(string $chainId, string $obligationId): void
    {
        $this->inner->deleteObligation($chainId, $obligationId);
    }

    public function complete(string $chainId, string $ownerToken, string $stage2Nonce): ?array
    {
        return $this->inner->complete($chainId, $ownerToken, $stage2Nonce);
    }
}

/**
 * A metadata sidecar whose READ fails on demand (simulated transient
 * outage): the validator's fail-closed chain-marker detection.
 */
final class FailingReadMetadataStore implements SiteVerifyMetadataStore
{
    public bool $findFails = true;

    public function store(string $nonce, \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadata $metadata, int $ttlSeconds): void
    {
    }

    public function find(string $nonce): ?\BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadata
    {
        if ($this->findFails) {
            throw new \RuntimeException('simulated metadata read outage');
        }

        return null;
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
 * A metadata sidecar that THROWS on every store() (simulated transient
 * outage): the controller's proven-not-handed-out metadata failure path.
 */
final class FailingMetadataStore implements SiteVerifyMetadataStore
{
    public function store(string $nonce, \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadata $metadata, int $ttlSeconds): void
    {
        throw new \RuntimeException('simulated metadata store outage');
    }

    public function find(string $nonce): ?\BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadata
    {
        return null;
    }
}

/**
 * The AUTHORITATIVE transaction-binding fixture: resolves the FIXED
 * authoritative binding of the transaction and REFUSES (throws
 * \InvalidArgumentException) a presented binding that differs from it —
 * the controller then answers 422 INVALID_REQUEST_BINDING before any
 * state is touched. With $ignorePresented the presented value is a pure
 * HINT (never examined) — the authority's resolution is the anchor.
 */
final class FixtureBindingAuthority implements RequestBindingAuthorityInterface
{
    public function __construct(
        private readonly string $authoritativeBinding,
        private readonly bool $ignorePresented = false,
    ) {
    }

    public function resolve(Request $request, string $scope, ?string $presentedBinding): ?string
    {
        if (!$this->ignorePresented && $presentedBinding !== null && $presentedBinding !== '' && $presentedBinding !== $this->authoritativeBinding) {
            throw new \InvalidArgumentException(sprintf('presented binding %s does not match the authoritative binding %s', $presentedBinding, $this->authoritativeBinding));
        }

        return $this->authoritativeBinding;
    }
}

/**
 * A chained-challenge state store decorator with a test seam: after every
 * reserve() the optional callback runs (while the reservation is HELD),
 * so a test can interleave a second request with the SAME ticket and
 * observe the in-progress 503 boundary.
 */
final class ChainStateStoreInterceptor implements TransactionalChainedChallengeStateStore
{
    /** @var \Closure|null (string $chainId, string $ownerToken, string $status): void */
    public ?\Closure $afterReserve = null;

    public function __construct(private readonly TransactionalChainedChallengeStateStore $inner)
    {
    }

    public function create(string $chainId, string $stage1Nonce, string $scope, int $ttlSecs, ?string $requestBinding = null, ?string $requiredAction = null, int $policyVersion = 1): void
    {
        $this->inner->create($chainId, $stage1Nonce, $scope, $ttlSecs, $requestBinding, $requiredAction, $policyVersion);
    }

    public function createWithObligation(string $chainId, string $obligationId, string $stage1Nonce, string $scope, ?string $requestBinding, string $requiredAction, int $policyVersion, int $ttlSecs): void
    {
        $this->inner->createWithObligation($chainId, $obligationId, $stage1Nonce, $scope, $requestBinding, $requiredAction, $policyVersion, $ttlSecs);
    }

    public function createOrGetObligation(string $obligationId, string $chainId, string $stage1Nonce, string $scope, string $requestBinding, string $requiredAction, int $requiredRank, int $policyVersion, int $expiresAt, int $ttlSecs): string
    {
        return $this->inner->createOrGetObligation($obligationId, $chainId, $stage1Nonce, $scope, $requestBinding, $requiredAction, $requiredRank, $policyVersion, $expiresAt, $ttlSecs);
    }

    public function obligationChainId(string $obligationId): ?string
    {
        return $this->inner->obligationChainId($obligationId);
    }

    public function read(string $chainId): ?array
    {
        return $this->inner->read($chainId);
    }

    public function reserve(string $chainId, string $ownerToken, int $leaseSecs): string
    {
        $status = $this->inner->reserve($chainId, $ownerToken, $leaseSecs);
        if ($this->afterReserve !== null) {
            ($this->afterReserve)($chainId, $ownerToken, $status);
        }

        return $status;
    }

    public function release(string $chainId, string $ownerToken): void
    {
        $this->inner->release($chainId, $ownerToken);
    }

    public function markIssued(string $chainId, string $ownerToken, string $stage2Nonce): string
    {
        return $this->inner->markIssued($chainId, $ownerToken, $stage2Nonce);
    }

    public function markVerified(string $chainId, string $stage2Nonce): string
    {
        return $this->inner->markVerified($chainId, $stage2Nonce);
    }

    public function markStepUpRequired(string $chainId, string $stage2Nonce): string
    {
        return $this->inner->markStepUpRequired($chainId, $stage2Nonce);
    }

    public function markDenied(string $chainId, string $stage2Nonce): string
    {
        return $this->inner->markDenied($chainId, $stage2Nonce);
    }

    public function markTransactionDenied(string $chainId, string $obligationId): string
    {
        return $this->inner->markTransactionDenied($chainId, $obligationId);
    }

    public function markTransactionStepUpRequired(string $chainId, string $obligationId): string
    {
        return $this->inner->markTransactionStepUpRequired($chainId, $obligationId);
    }

    public function rearmIssued(string $chainId, string $expectedStage2Nonce): bool
    {
        return $this->inner->rearmIssued($chainId, $expectedStage2Nonce);
    }

    public function deleteObligation(string $chainId, string $obligationId): void
    {
        $this->inner->deleteObligation($chainId, $obligationId);
    }

    public function complete(string $chainId, string $ownerToken, string $stage2Nonce): ?array
    {
        return $this->inner->complete($chainId, $ownerToken, $stage2Nonce);
    }
}

/**
 * A chained-challenge state store decorator with a test seam: after every
 * reserve() the optional callback runs (while the reservation is HELD),
 * so a test can interleave a second request with the SAME ticket and
 * observe the in-progress 503 boundary.
 */
final class LostReplyChainStore implements TransactionalChainedChallengeStateStore
{
    /** Whether the issuance transition throws AFTER the real transition. */
    public bool $throwAfterIssued = false;

    /** Whether the verification transition throws AFTER the real transition. */
    public bool $throwAfterVerified = false;

    /** Whether the recovery read throws (the INDETERMINATE outcome). */
    public bool $readThrows = false;

    public function __construct(
        private readonly TransactionalChainedChallengeStateStore $inner,
        bool $throwAfterIssued = false,
        bool $throwAfterVerified = false,
        bool $readThrows = false,
    ) {
        $this->throwAfterIssued = $throwAfterIssued;
        $this->throwAfterVerified = $throwAfterVerified;
        $this->readThrows = $readThrows;
    }

    public function create(string $chainId, string $stage1Nonce, string $scope, int $ttlSecs, ?string $requestBinding = null, ?string $requiredAction = null, int $policyVersion = 1): void
    {
        $this->inner->create($chainId, $stage1Nonce, $scope, $ttlSecs, $requestBinding, $requiredAction, $policyVersion);
    }

    public function createWithObligation(string $chainId, string $obligationId, string $stage1Nonce, string $scope, ?string $requestBinding, string $requiredAction, int $policyVersion, int $ttlSecs): void
    {
        $this->inner->createWithObligation($chainId, $obligationId, $stage1Nonce, $scope, $requestBinding, $requiredAction, $policyVersion, $ttlSecs);
    }

    public function createOrGetObligation(string $obligationId, string $chainId, string $stage1Nonce, string $scope, string $requestBinding, string $requiredAction, int $requiredRank, int $policyVersion, int $expiresAt, int $ttlSecs): string
    {
        return $this->inner->createOrGetObligation($obligationId, $chainId, $stage1Nonce, $scope, $requestBinding, $requiredAction, $requiredRank, $policyVersion, $expiresAt, $ttlSecs);
    }

    public function obligationChainId(string $obligationId): ?string
    {
        return $this->inner->obligationChainId($obligationId);
    }

    public function read(string $chainId): ?array
    {
        $record = $this->inner->read($chainId);
        // The INDETERMINATE seam: after the issuance transition the record
        // is issued/terminal — the recovery read of such a record fails.
        if ($this->readThrows && $record !== null && \in_array($record['state'], ['issued', 'verified', 'step_up_required', 'denied'], true)) {
            throw new \RuntimeException('simulated chain state read outage');
        }

        return $record;
    }

    public function reserve(string $chainId, string $ownerToken, int $leaseSecs): string
    {
        return $this->inner->reserve($chainId, $ownerToken, $leaseSecs);
    }

    public function release(string $chainId, string $ownerToken): void
    {
        $this->inner->release($chainId, $ownerToken);
    }

    public function markIssued(string $chainId, string $ownerToken, string $stage2Nonce): string
    {
        $result = $this->inner->markIssued($chainId, $ownerToken, $stage2Nonce);
        if ($this->throwAfterIssued) {
            throw new \RuntimeException('simulated lost markIssued reply');
        }

        return $result;
    }

    public function markVerified(string $chainId, string $stage2Nonce): string
    {
        $result = $this->inner->markVerified($chainId, $stage2Nonce);
        if ($this->throwAfterVerified) {
            throw new \RuntimeException('simulated lost markVerified reply');
        }

        return $result;
    }

    public function markStepUpRequired(string $chainId, string $stage2Nonce): string
    {
        return $this->inner->markStepUpRequired($chainId, $stage2Nonce);
    }

    public function markDenied(string $chainId, string $stage2Nonce): string
    {
        return $this->inner->markDenied($chainId, $stage2Nonce);
    }

    public function markTransactionDenied(string $chainId, string $obligationId): string
    {
        return $this->inner->markTransactionDenied($chainId, $obligationId);
    }

    public function markTransactionStepUpRequired(string $chainId, string $obligationId): string
    {
        return $this->inner->markTransactionStepUpRequired($chainId, $obligationId);
    }

    public function rearmIssued(string $chainId, string $expectedStage2Nonce): bool
    {
        return $this->inner->rearmIssued($chainId, $expectedStage2Nonce);
    }

    public function deleteObligation(string $chainId, string $obligationId): void
    {
        $this->inner->deleteObligation($chainId, $obligationId);
    }

    public function complete(string $chainId, string $ownerToken, string $stage2Nonce): ?array
    {
        return $this->inner->complete($chainId, $ownerToken, $stage2Nonce);
    }
}

/**
 * A transactional chain-state decorator that runs the REAL transition and
 * THEN throws (a lost reply), and can additionally make the recovery read
 * fail (the INDETERMINATE outcome).
 */
final class ConflictChainStore implements TransactionalChainedChallengeStateStore
{
    public function __construct(private readonly TransactionalChainedChallengeStateStore $inner)
    {
    }

    public function create(string $chainId, string $stage1Nonce, string $scope, int $ttlSecs, ?string $requestBinding = null, ?string $requiredAction = null, int $policyVersion = 1): void
    {
        $this->inner->create($chainId, $stage1Nonce, $scope, $ttlSecs, $requestBinding, $requiredAction, $policyVersion);
    }

    public function createWithObligation(string $chainId, string $obligationId, string $stage1Nonce, string $scope, ?string $requestBinding, string $requiredAction, int $policyVersion, int $ttlSecs): void
    {
        $this->inner->createWithObligation($chainId, $obligationId, $stage1Nonce, $scope, $requestBinding, $requiredAction, $policyVersion, $ttlSecs);
    }

    public function createOrGetObligation(string $obligationId, string $chainId, string $stage1Nonce, string $scope, string $requestBinding, string $requiredAction, int $requiredRank, int $policyVersion, int $expiresAt, int $ttlSecs): string
    {
        return $this->inner->createOrGetObligation($obligationId, $chainId, $stage1Nonce, $scope, $requestBinding, $requiredAction, $requiredRank, $policyVersion, $expiresAt, $ttlSecs);
    }

    public function obligationChainId(string $obligationId): ?string
    {
        return $this->inner->obligationChainId($obligationId);
    }

    public function read(string $chainId): ?array
    {
        return $this->inner->read($chainId);
    }

    public function reserve(string $chainId, string $ownerToken, int $leaseSecs): string
    {
        return $this->inner->reserve($chainId, $ownerToken, $leaseSecs);
    }

    public function release(string $chainId, string $ownerToken): void
    {
        $this->inner->release($chainId, $ownerToken);
    }

    public function markIssued(string $chainId, string $ownerToken, string $stage2Nonce): string
    {
        // A DIFFERENT nonce durably wins the chain first: the caller's
        // issuance POSITIVELY cannot be established.
        $this->inner->markIssued($chainId, $ownerToken, base64_encode(hash('sha256', 'different-nonce-won', true)));

        return $this->inner->markIssued($chainId, $ownerToken, $stage2Nonce);
    }

    public function markVerified(string $chainId, string $stage2Nonce): string
    {
        return $this->inner->markVerified($chainId, $stage2Nonce);
    }

    public function markStepUpRequired(string $chainId, string $stage2Nonce): string
    {
        return $this->inner->markStepUpRequired($chainId, $stage2Nonce);
    }

    public function markDenied(string $chainId, string $stage2Nonce): string
    {
        return $this->inner->markDenied($chainId, $stage2Nonce);
    }

    public function markTransactionDenied(string $chainId, string $obligationId): string
    {
        return $this->inner->markTransactionDenied($chainId, $obligationId);
    }

    public function markTransactionStepUpRequired(string $chainId, string $obligationId): string
    {
        return $this->inner->markTransactionStepUpRequired($chainId, $obligationId);
    }

    public function rearmIssued(string $chainId, string $expectedStage2Nonce): bool
    {
        return $this->inner->rearmIssued($chainId, $expectedStage2Nonce);
    }

    public function deleteObligation(string $chainId, string $obligationId): void
    {
        $this->inner->deleteObligation($chainId, $obligationId);
    }

    public function complete(string $chainId, string $ownerToken, string $stage2Nonce): ?array
    {
        return $this->inner->complete($chainId, $ownerToken, $stage2Nonce);
    }
}

/**
 * A transactional chain-state decorator that makes the issuance transition
 * POSITIVELY fail: a DIFFERENT nonce wins the chain first, so the
 * controller's own markIssued answers 'conflict' (the known-failed
 * rollback path).
 */
final class AbortAwareFakeRedis extends \Predis\Client
{
    /** @var array<string, int> plain INCR counters */
    public array $counters = [];

    public function __construct()
    {
        // Deliberately skip the parent constructor: no connection setup.
    }

    public function __call($commandID, $arguments)
    {
        if (strtoupper((string) $commandID) !== 'EVAL') {
            throw new \LogicException('unexpected command '.$commandID);
        }
        $script = (string) $arguments[0];
        $numKeys = (int) $arguments[1];
        $keys = \array_slice($arguments, 2, $numKeys);
        $rest = \array_slice($arguments, 2 + $numKeys);

        if (str_contains($script, 'Outstanding challenge issuance')) {
            // OutstandingChallenges::issue: KEYS[1] per-source counter,
            // KEYS[2] global counter; ARGV[1] source cap, ARGV[2] global
            // cap, ARGV[3] TTL seconds. GET both caps -> refuse 0/-1
            // BEFORE anything is written -> INCR both.
            $source = (string) $keys[0];
            $global = (string) $keys[1];
            if (($this->counters[$source] ?? 0) >= (int) $rest[0]) {
                return 0;
            }
            if (($this->counters[$global] ?? 0) >= (int) $rest[1]) {
                return -1;
            }
            $this->counters[$source] = ($this->counters[$source] ?? 0) + 1;
            $this->counters[$global] = ($this->counters[$global] ?? 0) + 1;

            return 1;
        }

        if (str_contains($script, 'Outstanding challenge solve') || str_contains($script, 'Outstanding challenge aborted')) {
            // OutstandingChallenges::solved / ::abortedBeforeHandoff:
            // KEYS[1] per-source counter; best-effort DECR floored at 0.
            $key = (string) $keys[0];
            $v = $this->counters[$key] ?? 0;
            if ($v > 0) {
                $this->counters[$key] = $v - 1;
            }

            return 1;
        }

        throw new \LogicException('unexpected script');
    }
}
