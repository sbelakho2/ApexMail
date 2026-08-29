<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use BelConsulting\KiwiCaptchaBundle\Risk\ArrayChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ArrayPostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult;
use BelConsulting\KiwiCaptchaBundle\Risk\MalformedPostSolveDispositionException;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDisposition;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveFinalizeOutcome;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionRecord;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\Risk\RequestBindingAuthorityInterface;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\TransactionalChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Security\OutstandingChallenges;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\ConsumedStateStorage;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore;
use KiwiCaptcha\BindingMode;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\RiskV2Weights;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Validator\ConstraintValidatorFactory;
use Symfony\Component\Validator\ConstraintViolationListInterface;
use Symfony\Component\Validator\Mapping\ClassMetadata;
use Symfony\Component\Validator\Validation;

/**
 * Validator constraint test: the KiwiCaptcha constraint verifies tokens
 * locally (never via an external http call). Tested through the full
 * Symfony validation pipeline, exactly as a form submission would be.
 */
final class ValidatorTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    /** The post-solve vector that demands Argon32 (score 813). */
    private const ARGON32_VECTOR = ['source_fast' => 900, 'subnet_fast' => 1000, 'issue_debt' => 1000, 'replay' => 699, 'network_risk' => 890];

    /** The post-solve vector that demands StepUp (score 933, no deny reason). */
    private const STEP_UP_VECTOR = ['source_fast' => 900, 'subnet_fast' => 1000, 'issue_debt' => 1000, 'replay' => 699, 'network_risk' => 890, 'action_failure' => 1000];

    private Issuer $issuer;
    private Verifier $verifier;

    protected function setUp(): void
    {
        $storage = new ArrayStorage();
        $this->issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $this->verifier = new Verifier($storage);
    }

    /**
     * @return array{0: \Symfony\Component\Validator\Validator\ValidatorInterface, 1: RequestStack}
     */
    private function buildEngine(): array
    {
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));

        $validator = new KiwiCaptchaValidator($this->verifier, $stack, self::SECRET);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);

        return [Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator(), $stack];
    }

    private function solveToken(string $prefix, string $salt, int $targetBits, string $nonce, string $algorithm = 'sha256'): string
    {
        $saltBytes = base64_decode($salt, true);
        $counter = 0;
        do {
            $h = $algorithm === 'argon2id'
                ? sodium_crypto_pwhash(32, $prefix.$counter, $saltBytes, 3, 64 * 1024, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13)
                : hash('sha256', $prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($h) < $targetBits);
        --$counter;

        return \KiwiCaptcha\SolutionToken::create($nonce, $counter, 5000, [])->encode();
    }

    /**
     * A deterministic near-miss solve: the hash meets targetBits minus 2
     * leading zero bits but not the full targetBits, so the verifier
     * always answers InsufficientWork. The scan skips full-valid
     * counters (a counter meeting targetBits minus 2 lands on a valid
     * proof 25% of the time), bounding the search so the test can never
     * flake on the proof strength.
     */
    private function solveInsufficientWorkToken(string $prefix, string $salt, int $targetBits, string $nonce): string
    {
        $saltBytes = base64_decode($salt, true);
        $counter = null;
        for ($i = 0; $i < 100_000; $i++) {
            $bits = Verifier::leadingZeroBits(hash('sha256', $prefix.$i.$saltBytes, true));
            if ($bits >= $targetBits - 2 && $bits < $targetBits) {
                $counter = $i;
                break;
            }
        }
        self::assertNotNull($counter, 'a near-miss proof must exist within the bounded scan');

        return \KiwiCaptcha\SolutionToken::create($nonce, (int) $counter, 5000, [])->encode();
    }

    /**
     * Validate one token through the full Symfony validation pipeline
     * with a risk-wired validator, observing the recorded risk feedback.
     * The request carries the given server array; pass null to run with
     * no request at all.
     *
     * @param array<string, string|null>|null $server
     *
     * @return array{0: ConstraintViolationListInterface, 1: FakeRiskStateStore}
     */
    private function validateWithRisk(Verifier $verifier, string $token, ?array $server): array
    {
        $risk = $this->riskStack(1, 'allow', 'allow', false);
        $stack = new RequestStack();
        if ($server !== null) {
            $stack->push(Request::create('/', 'POST', [], [], [], $server));
        }
        $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET, false, $risk['gateway']);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        return [$engine->validate($dto), $risk['store']];
    }

    /**
     * The expected source pseudonym of a recorded observation: the same
     * deterministic HMAC the engine derives from the raw client IP at
     * the observation's epoch, so the feedback's IP is proven to be the
     * canonical client IP.
     */
    private function expectedSourcePseudonym(string $ip, RiskObservation $observation): string
    {
        return (new RiskIdentityFactory(RiskKeys::fromMaster(self::SECRET)))->sourceId($ip, $observation->sourceEpoch * 900);
    }

    /**
     * A full risk stack (engine + gateway with a wired policy) over a fake
     * state store for ONE 'login' scope.
     *
     * @return array{gateway: RiskGateway, store: FakeRiskStateStore}
     */
    private function riskStack(int $scopeId, string $minimum, string $degraded, bool $postSolveCheck, ?RiskV2Weights $v2Weights = null, ?RiskProfileResolver $resolver = null, ?\Predis\Client $decisionRedis = null, ?RequestStack $requestStack = null): array
    {
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                $scopeId => ['base_risk' => 100, 'minimum' => $minimum, 'post_solve_check' => $postSolveCheck, 'degraded' => $degraded],
            ],
        ]);
        $store = new FakeRiskStateStore();
        $engine = new AdaptiveRiskEngine($store, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);
        $gateway = new RiskGateway($engine, $classifier, $resolver ?? new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => $scopeId], null, null, ['login' => $postSolveCheck], 'reject', null, null, $requestStack, $decisionRedis, '{kiwi:validator-test}:decision:', 300, $policy, null, null, $v2Weights);

        return ['gateway' => $gateway, 'store' => $store];
    }

    /**
     * Solve a challenge issued with BindingMode::None and validate it
     * against a request carrying NO usable client IP (bogus/missing), so the
     * post-solve assessment throws InvalidArgumentException and the
     * validator must fall back to the scope's degraded decision.
     */
    private function validateUnboundSolveWithoutIp(int $scopeId, string $minimum, string $degraded, ?string $badIp, KiwiCaptcha $constraint): ConstraintViolationListInterface
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, bindingMode: BindingMode::None), $storage);
        $verifier = new Verifier($storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        usleep(((int) $challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $stack = new RequestStack();
        // Request::create defaults remote_addr to 127.0.0.1 — null it
        // explicitly to simulate a request with NO client IP at all.
        $server = $badIp !== null ? ['REMOTE_ADDR' => $badIp] : ['REMOTE_ADDR' => null];
        $stack->push(Request::create('/', 'POST', [], [], [], $server));

        $gateway = $this->riskStack($scopeId, $minimum, $degraded, true)['gateway'];
        $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET, false, $gateway);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();

        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', $constraint);

        return $engine->validate($dto);
    }

    /**
     * A post-solve assessment with no usable risk signal (bogus or
     * missing client IP — e.g. BindingMode::None deployments) must NOT
     * silently skip the adaptive re-check. The scope's degraded decision
     * applies exactly like on the pre-issue path: degraded=deny fails the
     * valid solve with post_solve_rejected_error instead of passing with
     * zero adaptive friction.
     */
    public function testPostSolveNoIpEnforcesDegradedDeny(): void
    {
        // Bogus client IP.
        $violations = $this->validateUnboundSolveWithoutIp(1, 'allow', 'deny', 'not-an-ip', new KiwiCaptcha(['scope' => 'login']));
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violations[0]->getCode(), 'a degraded=deny scope must reject the valid solve when the client IP is unusable');

        // Missing client IP entirely.
        $violations = $this->validateUnboundSolveWithoutIp(1, 'allow', 'deny', null, new KiwiCaptcha(['scope' => 'login']));
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violations[0]->getCode(), 'a degraded=deny scope must reject the valid solve when NO client IP exists');
    }

    /**
     * With a degraded=sha20 scope the degraded fallback applies a PoW
     * action the solved sha-8 challenge does not satisfy under the
     * configured ladders. A stronger PoW requirement must never silently
     * disappear — with chaining unavailable (no binding authority) it is
     * terminal StepUp, never a silent pass with zero adaptive friction.
     */
    public function testPostSolveNoIpStrongerDegradedActionIsTerminalStepUp(): void
    {
        $violations = $this->validateUnboundSolveWithoutIp(1, 'allow', 'sha20', 'not-an-ip', new KiwiCaptcha(['scope' => 'login']));
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations[0]->getCode(), 'a degraded=sha20 decision is a stronger-PoW requirement — terminal StepUp when chaining is unavailable, never a silent pass');

        $violations = $this->validateUnboundSolveWithoutIp(1, 'allow', 'sha20', null, new KiwiCaptcha(['scope' => 'login']));
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations[0]->getCode(), 'missing IP: same stronger-PoW contract');
    }

    private function validate(object $object, array $metadata): ConstraintViolationListInterface
    {
        [$engine] = $this->buildEngine();
        $meta = $engine->getMetadataFor($object::class);
        foreach ($metadata as $property => $constraints) {
            $meta->addPropertyConstraint($property, ...$constraints);
        }

        return $engine->validate($object);
    }

    public function testValidTokenPasses(): void
    {
        $challenge = $this->issuer->issue('login', '198.51.100.7');
        // The core enforces the minimum solve duration with a server-measured
        // clock; wait out the floor before verifying.
        usleep(($challenge->minDurationMs + 10) * 1000);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $violations = $this->validate($dto, ['captcha' => [new KiwiCaptcha(['scope' => 'login'])]]);

        self::assertCount(0, $violations);
    }

    public function testWrongScopeFails(): void
    {
        $challenge = $this->issuer->issue('login', '198.51.100.7');
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $violations = $this->validate($dto, ['captcha' => [new KiwiCaptcha(['scope' => 'signup'])]]);

        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::NOT_SOLVED_ERROR, $violations[0]->getCode());
    }

    public function testEmptyTokenFails(): void
    {
        $dto = new class {
            public ?string $captcha = '';
        };

        $violations = $this->validate($dto, ['captcha' => [new KiwiCaptcha()]]);

        self::assertCount(1, $violations);
    }

    public function testGarbageTokenFailsWithoutError(): void
    {
        $dto = new class {
            public ?string $captcha = 'not-a-token';
        };

        $violations = $this->validate($dto, ['captcha' => [new KiwiCaptcha()]]);

        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::NOT_SOLVED_ERROR, $violations[0]->getCode());
    }

    public function testArgon2CapacityExhaustionFailsClosedAsViolation(): void
    {
        \BelConsulting\KiwiCaptchaBundle\Security\InProcessArgonGate::resetForTests();
        try {
            // The core gate is consulted only for Argon2id records, so the
            // challenge itself must be argon2id for exhaustion to matter.
            $storage = new ArrayStorage();
            $gate = new \BelConsulting\KiwiCaptchaBundle\Security\InProcessArgonGate(1);
            $issuer = new Issuer(new Config(
                secretKey: self::SECRET,
                algorithm: \KiwiCaptcha\PoWAlgorithm::Argon2id,
                mKib: 64,
                t: 3,
                p: 1,
                argon2TargetBits: 4,
            ), $storage);
            $verifier = new Verifier($storage, $gate);

            $challenge = $issuer->issue('login', '198.51.100.7');
            usleep(($challenge->minDurationMs + 10) * 1000);
            $dto = new class {
                public ?string $captcha = null;
            };
            $dto->captcha = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce, 'argon2id');

            // Saturate the gate so the verification is refused with
            // CapacityExceeded (surfaced as a regular captcha violation).
            $gate->acquire();

            $stack = new RequestStack();
            $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));

            $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET);
            $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
            $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();

            $meta = $engine->getMetadataFor($dto::class);
            $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

            $violations = $engine->validate($dto);

            self::assertCount(1, $violations);
            // Capacity exhaustion keeps its distinct public code
            // (rate_limited — a retryable refusal, not a burned token).
            self::assertSame(KiwiCaptcha::RATE_LIMITED_ERROR, $violations[0]->getCode());
        } finally {
            \BelConsulting\KiwiCaptchaBundle\Security\InProcessArgonGate::resetForTests();
        }
    }

    public function testValidSolveExposesTheCanonicalJti(): void
    {
        $challenge = $this->issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $validator = new KiwiCaptchaValidator($this->verifier, $stack, self::SECRET);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engine->validate($dto);
        self::assertCount(0, $violations);

        $jti = $stack->getMainRequest()?->attributes->get(KiwiCaptchaValidator::VERIFIED_JTI_ATTRIBUTE);
        self::assertSame($challenge->nonce, $jti, 'the verified jti must be the canonical challenge nonce of the consumed record');
        self::assertSame($challenge->nonce, $validator->verifiedJti(), 'verifiedJti() must expose the same canonical jti');
    }

    public function testFailedSolveNeverExposesAJti(): void
    {
        $challenge = $this->issuer->issue('login', '198.51.100.7');
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $validator = new KiwiCaptchaValidator($this->verifier, $stack, self::SECRET);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
        $dto = new class {
            public ?string $captcha = null;
        };
        // Wrong scope: the token is structurally fine but must NOT verify —
        // no jti may leak on a failed verification.
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'signup']));

        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);

        self::assertNull($stack->getMainRequest()?->attributes->get(KiwiCaptchaValidator::VERIFIED_JTI_ATTRIBUTE), 'a failed verification must never expose a jti');
        self::assertNull($validator->verifiedJti());
    }

// ── failure-path risk feedback (round-95) ─────────────────────────────────

    public function testFailedSolveWithRiskEnabledRecordsFailureFeedbackAndViolates(): void
    {
        $challenge = $this->issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveInsufficientWorkToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        [$violations, $store] = $this->validateWithRisk($this->verifier, $token, ['REMOTE_ADDR' => '198.51.100.7']);

        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode(), 'a failed verification is a form violation, never a 500');
        $events = array_map(static fn ($o): RiskEventKind => $o->event, $store->observations);
        self::assertSame([RiskEventKind::InvalidProof], $events, 'the failed solve must enrich the model with the InvalidProof event');
        $obs = $store->observations[0];
        self::assertSame($this->expectedSourcePseudonym('198.51.100.7', $obs), $obs->sourceId, 'the failure feedback must carry the canonical client IP pseudonym');
        self::assertNull($obs->sessionId, 'the validator has no session: the feedback session must be null');
        self::assertSame(1, $obs->scope, 'the feedback must carry the configured scope id');
    }

    public function testMalformedTokenWithRiskEnabledRecordsMalformedFeedbackAndViolates(): void
    {
        [$violations, $store] = $this->validateWithRisk($this->verifier, 'not-a-token', ['REMOTE_ADDR' => '198.51.100.7']);

        self::assertCount(1, $violations);
        $events = array_map(static fn ($o): RiskEventKind => $o->event, $store->observations);
        self::assertSame([RiskEventKind::MalformedToken], $events, 'an undecodable token must record the MalformedToken event, never a 500');
    }

    public function testFailedSolveWithoutClientIpRecordsNoRiskFeedbackButStillViolates(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, bindingMode: BindingMode::None), $storage);
        $verifier = new Verifier($storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveInsufficientWorkToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        // No request at all: $clientIp is null.
        [$violations, $store] = $this->validateWithRisk($verifier, $token, null);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode());
        self::assertSame([], $store->observations, 'no client IP means no per-IP risk evidence, never an empty-string pseudonym');

        // A request without a remote_addr server variable: $clientIp is
        // null too.
        [$violations, $store] = $this->validateWithRisk($verifier, $token, ['REMOTE_ADDR' => null]);
        self::assertCount(1, $violations);
        self::assertSame([], $store->observations, 'a request without a client IP must record no risk evidence either');
    }

    public function testFailedSolveWithRiskDisabledStillViolatesWithoutFeedback(): void
    {
        $challenge = $this->issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveInsufficientWorkToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $validator = new KiwiCaptchaValidator($this->verifier, $stack, self::SECRET);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode(), 'the risk-gateway-absent path stays a plain violation (the optional call is a no-op)');
    }

// ── success-path risk feedback (round-95) ────────────────────────────────

    public function testValidSolveWithoutReassessmentRecordsSolveSuccessFeedbackWithClientIp(): void
    {
        $challenge = $this->issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        [$violations, $store] = $this->validateWithRisk($this->verifier, $token, ['REMOTE_ADDR' => '198.51.100.7']);

        self::assertCount(0, $violations);
        $events = array_map(static fn ($o): RiskEventKind => $o->event, $store->observations);
        self::assertSame([RiskEventKind::SolveSuccess], $events, 'the no-reassessment valid solve must feed SolveSuccess feedback');
        $obs = $store->observations[0];
        self::assertSame($this->expectedSourcePseudonym('198.51.100.7', $obs), $obs->sourceId, 'the SolveSuccess feedback must carry the canonical client IP pseudonym');
        self::assertNull($obs->sessionId, 'the success feedback session must be null like the provider surface');
        self::assertSame(1, $obs->scope, 'the success feedback must carry the configured scope id');
    }

    public function testValidSolveWithoutClientIpRecordsNoSolveSuccessFeedback(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, bindingMode: BindingMode::None), $storage);
        $verifier = new Verifier($storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        [$violations, $store] = $this->validateWithRisk($verifier, $token, null);

        self::assertCount(0, $violations, 'a valid solve passes without a client IP');
        self::assertSame([], $store->observations, 'no client IP means no per-IP evidence, never an empty-string pseudonym');
    }

    public function testValidSolveDecrementsTheOutstandingCounter(): void
    {
        $client = new FakePredisClient();
        $outstanding = new OutstandingChallenges($client, '{kiwi:validator-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 3, 100, 0);

        // Two outstanding challenges for the source (the 3rd would hit the cap).
        $challengeA = $this->issuer->issue('login', '198.51.100.7');
        $challengeB = $this->issuer->issue('login', '198.51.100.7');
        self::assertSame(1, $outstanding->issue('198.51.100.7', $challengeA->nonce, 120));
        self::assertSame(1, $outstanding->issue('198.51.100.7', $challengeB->nonce, 120));
        $sourceKey = $outstanding->sourceKey('198.51.100.7');
        self::assertSame(2, $client->counters[$sourceKey]);

        // A valid solve of an actually-issued nonce releases its original
        // source slot (the nonce-authoritative one-shot model).
        $challenge = $challengeA;
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $validator = new KiwiCaptchaValidator($this->verifier, $stack, self::SECRET, false, null, null, $outstanding);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        self::assertCount(0, $engine->validate($dto));
        self::assertSame(1, $client->counters[$sourceKey], 'a valid solve must decrement the source\'s outstanding counter');

        // A failed solve must NOT decrement (the challenge stays outstanding).
        $challenge2 = $this->issuer->issue('login', '198.51.100.7');
        usleep(($challenge2->minDurationMs + 10) * 1000);
        $token2 = $this->solveToken($challenge2->prefix, $challenge2->salt, $challenge2->targetBits, $challenge2->nonce);
        $dto2 = new class {
            public ?string $captcha = null;
        };
        $dto2->captcha = $token2;
        $meta2 = $engine->getMetadataFor($dto2::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'signup']));
        self::assertCount(1, $engine->validate($dto2));
        self::assertSame(1, $client->counters[$sourceKey], 'a failed verification must not decrement the outstanding counter');
    }

// ── transaction binding ───────────────────────────────────────────────────

    /**
     * @return array{0: \Symfony\Component\Validator\Validator\ValidatorInterface, 1: RequestStack, 2: KiwiCaptchaValidator}
     */
    private function buildBindingEngine(?Verifier $verifier = null, ?string $requestBinding = 'txn-123', bool $asAttribute = true, ?RequestBindingAuthorityInterface $authority = null): array
    {
        $stack = new RequestStack();
        $request = Request::create('/', 'POST', ['kiwi_request_binding' => $requestBinding], [], [], ['REMOTE_ADDR' => '198.51.100.7']);
        if ($asAttribute) {
            // The application controller copies the POSTed field into the
            // request attribute before validation (the documented contract).
            $request->attributes->set(KiwiCaptchaValidator::REQUEST_BINDING_ATTRIBUTE, $requestBinding);
        }
        $stack->push($request);

        $validator = new KiwiCaptchaValidator($verifier ?? $this->verifier, $stack, self::SECRET, enforceTelemetry: false, bindingAuthority: $authority);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();

        return [$engine, $stack, $validator];
    }

    public function testBoundChallengeWithMatchingBindingPasses(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $verifier = new Verifier($storage);
        $challenge = $issuer->issue('login', '198.51.100.7', 'txn-123');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        [$engine] = $this->buildBindingEngine($verifier, 'txn-123');
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        self::assertCount(0, $engine->validate($dto), 'a bound challenge with the matching request binding must pass');
    }

    public function testBoundChallengeWithMismatchedBindingFailsInvalidOrExpired(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $verifier = new Verifier($storage);
        $challenge = $issuer->issue('login', '198.51.100.7', 'txn-123');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        [$engine] = $this->buildBindingEngine($verifier, 'txn-OTHER');
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode(), 'a binding mismatch must collapse to the SAME invalid_or_expired code');
    }

    public function testBoundChallengeWithNoRequestBindingFails(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $verifier = new Verifier($storage);
        $challenge = $issuer->issue('login', '198.51.100.7', 'txn-123');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        // Request carries neither the attribute nor the POSTed field.
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engine->validate($dto);
        self::assertCount(1, $violations, 'a bound record with NO request binding must fail closed');
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode());
    }

    public function testUnboundChallengeWithAnExpectedBindingIsRefused(): void
    {
        // The exact request-binding contract (RequestBindingExpectation):
        // an authoritative transaction binding is Option-equality — an
        // explicitly unbound record under a canonical binding expectation
        // is a mismatch (the deployment configured a binding context, so
        // a challenge with no transaction anchor cannot redeem it). An
        // unbound record passes only under an explicitly unbound
        // transaction context (exact null).
        $challenge = $this->issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        [$engine] = $this->buildBindingEngine(requestBinding: 'txn-123');
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engine->validate($dto);
        self::assertCount(1, $violations, 'an unbound record under a canonical binding expectation is refused');
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode());
    }

    public function testUnboundChallengePassesUnderAnExplicitlyUnboundTransaction(): void
    {
        // The exact contract's null row: an unbound record passes under
        // an explicitly unbound transaction context (exact null).
        $challenge = $this->issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        [$engine] = $this->buildBindingEngine(requestBinding: null);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        self::assertCount(0, $engine->validate($dto), 'an unbound record passes under an explicitly unbound transaction context');
    }

    public function testBindingMismatchFailsBeforeTheConsume(): void
    {
        // P2/P3 regression: the request-binding enforcement moved into the
        // core's pre-consume phase. A wrong-transaction proof must fail
        // without consuming the challenge (no deterministic result is
        // committed and nothing is released), so the valid proof is not
        // burned by the mismatch.
        $storage = new ArrayStorage();
        $challenge = $this->issueBoundChallenge('txn-alpha', $storage);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        [$engine] = $this->buildBindingEngine(requestBinding: 'txn-OTHER');
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engine->validate($dto);
        self::assertCount(1, $violations, 'the wrong-transaction proof is refused');
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode());
        self::assertNull($storage->consumedState($challenge->nonce), 'the binding mismatch fails BEFORE the consume — the challenge is never consumed or burned');
    }

    public function testStoredResultRetryRepairsTheOutstandingRelease(): void
    {
        // P2 regression: the release used to be skipped for stored-result
        // retries, so a transient release failure during the original
        // verification could never be repaired by the same logical
        // operation's retry. solved() is idempotent and ZREM-gated, so
        // every accepted successful outcome — stored-result retries
        // included — re-releases.
        $client = new FakePredisClient();
        $outstanding = new OutstandingChallenges($client, '{kiwi:validator-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 3, 100, 0);
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7', 'txn-123');
        self::assertSame(1, $outstanding->issue('198.51.100.7', $challenge->nonce, 120));
        $sourceKey = $outstanding->sourceKey('198.51.100.7');
        self::assertSame(1, $client->counters[$sourceKey]);

        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $verifier = new Verifier($storage);
        $stack = new RequestStack();
        $request = Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']);
        $request->attributes->set(KiwiCaptchaValidator::REQUEST_BINDING_ATTRIBUTE, 'txn-123');
        $request->attributes->set(KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE, 'op-retry-1');
        $stack->push($request);
        $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET, false, null, null, $outstanding, null, $storage);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        // The original verification succeeds but the release fails (a
        // transient Redis outage): the solve must still be accepted.
        $client->failCommand = 'EVAL';
        self::assertCount(0, $engine->validate($dto), 'a transient release failure never fails a valid solve');
        $client->failCommand = null;
        self::assertSame(1, $client->counters[$sourceKey], 'the transient failure left the slot charged');

        // The same logical operation retries: the core recovers the
        // committed success and the validator re-releases — the
        // stored-result retry repairs the accounting.
        self::assertCount(0, $engine->validate($dto), 'the stored-result retry recovers the same success');
        self::assertSame(0, $client->counters[$sourceKey], 'the stored-result retry repairs the release');
    }

    public function testReleaseSidecarReadFailureIsBestEffort(): void
    {
        // P2: the entire release — the plain sidecar GET included — sits
        // inside the exception boundary, so a Redis failure on the read
        // can never fail a valid solve (the memberships decay by their
        // deadlines and the same logical operation's retry re-releases).
        $client = new FakePredisClient();
        $outstanding = new OutstandingChallenges($client, '{kiwi:validator-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 3, 100, 0);
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        self::assertSame(1, $outstanding->issue('198.51.100.7', $challenge->nonce, 120));
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $validator = new KiwiCaptchaValidator(new Verifier($storage), $stack, self::SECRET, false, null, null, $outstanding);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $client->failCommand = 'GET';
        self::assertCount(0, $engine->validate($dto), 'a failed sidecar GET never fails a valid solve');
    }

    public function testOutstandingCountsTheCompleteVerifierValidityEnvelopeUnderIssuerSkew(): void
    {
        // P1/P2: the accounting lifetime is the nominal TTL plus the core
        // verifier's permitted future-issuance skew (MAX_CLOCK_SKEW), so a
        // distributed issuer clock ahead of the Redis clock can never make
        // the anti-stockpiling caps undercount a still-verifier-valid
        // challenge: at real t+11 a token minted at t+30 (inside the
        // permitted +60s skew) with a 10s TTL is still valid, and the
        // outstanding memberships must still count it.
        $client = new FakePredisClient();
        $client->setTimeMs(1_800_000_000_000);
        $base = 1_800_000_000;
        $outstanding = new OutstandingChallenges($client, '{kiwi:skew-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 2, 100, 0);
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 10), $storage, now: static fn (): int => $base + 30);
        $challenge = $issuer->issue('login', '198.51.100.7');
        self::assertSame(1, $outstanding->issue('198.51.100.7', $challenge->nonce, 10 + Verifier::MAX_CLOCK_SKEW), 'the controller admission adds the verifier skew grace');
        $sourceKey = $outstanding->sourceKey('198.51.100.7');
        self::assertSame(1, $client->counters[$sourceKey]);

        // Real t+11: the token is still verifier-valid...
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $verifier = new Verifier($storage, now: static fn (): int => $base + 11);
        $outcome = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk(), sprintf('the token is still verifier-valid at t+11 under the permitted issuer skew, got %s', $outcome->code()));

        // ...and the outstanding accounting still counts it: the members
        // expire at Redis-now + ttl + skew, so the cap holds at 2 even
        // after the nominal TTL passed.
        $client->setTimeMs(1_800_000_011_000);
        self::assertSame(1, $client->counters[$sourceKey], 'the outstanding membership still counts the challenge at t+11');
        self::assertSame(1, $outstanding->issue('198.51.100.7', 'Y'.str_repeat('y', 43), 10 + Verifier::MAX_CLOCK_SKEW), 'a second challenge is admitted');
        self::assertSame(0, $outstanding->issue('198.51.100.7', 'Z'.str_repeat('z', 43), 10 + Verifier::MAX_CLOCK_SKEW), 'the cap counts BOTH live members — the skew can never undercount the bound');
    }

    public function testPostFieldFallbackCarriesTheBindingWithoutTheAttribute(): void
    {
        // The documented attribute is preferred, but the plain POSTed field
        // (the widget's hidden kiwi_request_binding input) must work out of
        // the box when the application controller does not copy it.
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $verifier = new Verifier($storage);
        $challenge = $issuer->issue('login', '198.51.100.7', 'txn-123');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        [$engine] = $this->buildBindingEngine($verifier, 'txn-123', asAttribute: false);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        self::assertCount(0, $engine->validate($dto), 'the POSTed kiwi_request_binding field must satisfy the binding without the attribute');
    }

    public function testBindingMismatchNeverExposesJtiOrBinding(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $verifier = new Verifier($storage);
        $challenge = $issuer->issue('login', '198.51.100.7', 'txn-123');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        [$engine, $stack, $validator] = $this->buildBindingEngine($verifier, 'txn-OTHER');
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        self::assertCount(1, $engine->validate($dto));
        self::assertNull($stack->getMainRequest()?->attributes->get(KiwiCaptchaValidator::VERIFIED_JTI_ATTRIBUTE), 'a binding-mismatch validation must not expose a jti');
        self::assertNull($validator->verifiedJti());
        self::assertNull($validator->verifiedRequestBinding());
    }

    public function testValidSolveExposesTheVerifiedRequestBinding(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $verifier = new Verifier($storage);
        $challenge = $issuer->issue('login', '198.51.100.7', 'txn-123');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        [$engine, , $validator] = $this->buildBindingEngine($verifier, 'txn-123');
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        self::assertCount(0, $engine->validate($dto));
        self::assertSame('txn-123', $validator->verifiedRequestBinding(), 'the record\'s SIGNED request binding must be exposed after a valid solve');
    }

    /**
     * The business-level regression: one solved token funds exactly ONE
     * logical operation. The operation identity is (scope, authoritative
     * transaction binding): the same token submitted to a different
     * operation — a different transaction binding or a different scope —
     * derives a different identity, and the core refuses the stored
     * success as AlreadyConsumed. The validator surfaces that refusal
     * through its core-failure path as invalid_or_expired, never a Pass,
     * so an isOk()-gated branch can never fund a second protected
     * action from one solve.
     */
    public function testSameSolvedTokenForTwoDifferentOperationsSecondIsRejectedNeverPass(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $verifier = new Verifier($storage);
        $challenge = $issuer->issue('login', '198.51.100.7', 'txn-123');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;

        // Operation 1: (scope login, binding txn-123) — the first Pass.
        [$engine1] = $this->buildBindingEngine($verifier, 'txn-123');
        $meta1 = $engine1->getMetadataFor($dto::class);
        $meta1->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        self::assertCount(0, $engine1->validate($dto), 'the first operation passes');

        // Operation 2: the same token under a different authoritative
        // binding (a different transaction): a different logical operation
        // — the second submission MUST be rejected, never Pass.
        [$engine2] = $this->buildBindingEngine($verifier, 'txn-OTHER');
        $meta2 = $engine2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations2 = $engine2->validate($dto);
        self::assertCount(1, $violations2);
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations2[0]->getCode(), 'a different transaction presenting the same token is rejected (AlreadyConsumed), never Pass');

        // Operation 3: the same token under a different scope — also a
        // different logical operation, refused the same way.
        [$engine3] = $this->buildBindingEngine($verifier, 'txn-123');
        $meta3 = $engine3->getMetadataFor($dto::class);
        $meta3->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'signup']));
        $violations3 = $engine3->validate($dto);
        self::assertCount(1, $violations3);
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations3[0]->getCode(), 'a different scope presenting the same token is rejected (AlreadyConsumed), never Pass');

        // The consumed recovery evidence survives both rejections.
        $state = $storage->consumedState($challenge->nonce);
        self::assertNotNull($state, 'the consumed evidence is retained');
        self::assertTrue($state->consumedResult?->valid ?? false, 'the committed success is retained');
    }

// ── the authoritative transaction binding (end-to-end) ─────────────────────

    public function testBindingAuthorityMapsThePresentedHintToTheCanonicalBinding(): void
    {
        // The challenge is issued against the canonical value (the
        // controller signs the authority's resolution), while the request
        // presents only the client hint. The authority maps the hint to
        // the canonical value — the validator's primary binding check must
        // compare against that, so the legitimately issued challenge
        // validates end-to-end.
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $verifier = new Verifier($storage);
        $challenge = $issuer->issue('login', '198.51.100.7', 'server-transaction');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $authority = new MappingBindingAuthority();
        [$engine] = $this->buildBindingEngine($verifier, 'client-hint', authority: $authority);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        self::assertCount(0, $engine->validate($dto), 'a challenge issued against the canonical binding must validate when the authority maps the presented hint to it');
        self::assertSame(1, $authority->calls, 'the authority is consulted EXACTLY once per validation');
    }

    public function testBindingAuthorityIsCalledExactlyOnceEvenWhenTheChainOpens(): void
    {
        // A chain-opening validation exercises the stage-2 lookup AND the
        // chain creation — both must thread the already-resolved canonical
        // binding, never re-consult the authority (the pre-fix flow called
        // it twice on this path).
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(1, 'allow', 'allow', false, null, $resolver);
        $risk['store']->setVector(SignalVector::fromArray(self::ARGON32_VECTOR));
        [$store] = $this->clockedDispositionStore();

        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = new ChainedChallengeTicketService($chainStore, self::SECRET, 300, 15, $this->bindingAuthority());
        $authority = new MappingBindingAuthority();

        $challenge = $this->issuer->issue('login', '198.51.100.7', 'server-transaction');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, resolver: $resolver, bindingAuthority: $authority);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engine->validate($dto);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        self::assertSame(1, $authority->calls, 'the chain paths thread the resolved canonical binding — the authority is consulted exactly once, never again');
    }

    public function testBindingAuthorityFailureIsTemporaryUnavailableNeverAPass(): void
    {
        // The authority's backend is down (it throws): the binding cannot
        // be attested — the valid solve fails closed with the retryable
        // temporary_unavailable violation, never a silent pass, never a
        // raw exception.
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $verifier = new Verifier($storage);
        $challenge = $issuer->issue('login', '198.51.100.7', 'server-transaction');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $authority = new ThrowingBindingAuthority();
        [$engine] = $this->buildBindingEngine($verifier, 'client-hint', authority: $authority);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'an authority outage must fail closed as temporary_unavailable — never a silent pass');
        self::assertSame(1, $authority->calls, 'the authority is consulted exactly once before failing closed');
    }

    public function testEpochBumpedReplayOfTheSameOperationFailsWrongPolicyVersion(): void
    {
        // Epoch 1: a valid solve under an explicit operation id and
        // binding commits the stored success (the identity is derived
        // under epoch 1). The central policy then bumps the epoch to 2;
        // the monitor observes it and rotates the shared verifier's
        // expectation. The same token + kiwi_operation_id + binding must
        // NOT replay the stored success: the epoch rotation is a
        // security verdict about this request (the challenge died with
        // the policy that authorized it), so with the replay-exemption
        // split it fails WrongPolicyVersion — the hard failure wins over
        // the matching identity.
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $verifier = new Verifier($storage);
        $challenge = $issuer->issue('login', '198.51.100.7', 'txn-123');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $redis = new FakePredisClient();
        $nowMs = microtime(true) * 1000.0;
        $monitor = new \BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor(
            $verifier,
            $redis,
            'test-ns',
            1,
            1,
            static function () use (&$nowMs): float {
                return $nowMs;
            },
        );
        $validate = function () use ($verifier, $monitor, $token): array {
            $stack = new RequestStack();
            $request = Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']);
            $request->attributes->set(KiwiCaptchaValidator::REQUEST_BINDING_ATTRIBUTE, 'txn-123');
            $request->attributes->set(KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE, 'op-123');
            $stack->push($request);
            $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET, policyVersion: 1, epochMonitor: $monitor);
            $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
            $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
            $dto = new class {
                public ?string $captcha = null;
            };
            $dto->captcha = $token;
            $meta = $engine->getMetadataFor($dto::class);
            $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
            $violations = $engine->validate($dto);
            $codes = [];
            foreach ($violations as $violation) {
                $codes[] = (string) $violation->getCode();
            }

            return $codes;
        };

        self::assertSame([], $validate(), 'the epoch-1 solve passes under the explicit operation id');

        // The central epoch bumps to 2 and the monitor's cache window
        // (1 s) elapses: the next validation's refresh observes the bump.
        $redis->hset('{kiwi:test-ns}:security-policy', \BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD, '2');
        $nowMs += 2000.0;

        self::assertSame([KiwiCaptcha::INVALID_OR_EXPIRED_ERROR], $validate(), 'the same operation after the epoch bump never replays the stored success');

        // The collapsed code hides the core reason, so the verdict is
        // asserted directly on the rotated verifier: the same inputs
        // fail the policy epoch check specifically — the hard security
        // verdict wins over the matching operation identity.
        $outcome = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7', operationIdentity: 'op-123', expectedRequestBinding: 'txn-123');
        self::assertSame(\KiwiCaptcha\VerifyError::WrongPolicyVersion, $outcome->error, 'the refusal is specifically the WrongPolicyVersion verdict');
        self::assertNotNull($storage->consumedState($challenge->nonce)?->consumedResult, 'the committed evidence survives the refusal');
    }

    public function testOperationIdentityBindsTheEffectiveEpoch(): void
    {
        // The identity hash itself carries the effective epoch (exactly
        // like Siteverify's idempotency fingerprint), so even an
        // exempt-failure replay (expiry below) with the same operation id
        // and binding must not resolve through the consumed branch after
        // an epoch bump: the derived identity no longer matches the one
        // the consume recorded, and the replay is refused.
        $storage = new ArrayStorage();
        $now = 1_800_000_000;
        $nowFn = static function () use (&$now): int {
            return $now;
        };
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage, now: $nowFn);
        $verifier = new Verifier($storage, now: $nowFn);
        $challenge = $issuer->issue('login', '198.51.100.7', 'txn-123');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $redis = new FakePredisClient();
        $nowMs = microtime(true) * 1000.0;
        $monitor = new \BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor(
            $verifier,
            $redis,
            'test-ns',
            1,
            1,
            static function () use (&$nowMs): float {
                return $nowMs;
            },
        );

        $validate = function () use ($verifier, $monitor, $token): array {
            $stack = new RequestStack();
            $request = Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']);
            $request->attributes->set(KiwiCaptchaValidator::REQUEST_BINDING_ATTRIBUTE, 'txn-123');
            $request->attributes->set(KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE, 'op-123');
            $stack->push($request);
            $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET, policyVersion: 1, epochMonitor: $monitor);
            $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
            $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
            $dto = new class {
                public ?string $captcha = null;
            };
            $dto->captcha = $token;
            $meta = $engine->getMetadataFor($dto::class);
            $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
            $violations = $engine->validate($dto);
            $codes = [];
            foreach ($violations as $violation) {
                $codes[] = (string) $violation->getCode();
            }

            return $codes;
        };

        self::assertSame([], $validate(), 'the epoch-1 solve passes');

        // The epoch bumps; the token expires (an exempt failure, which
        // would otherwise route to the identity-gated replay branch).
        $redis->hset('{kiwi:test-ns}:security-policy', \BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD, '2');
        $nowMs += 2000.0;
        $now = 1_800_000_130;

        self::assertContains(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $validate(), 'the expired same-id replay after the epoch bump is refused — the epoch-bound identity no longer matches');
    }

    public function testExpiredReplayWithRotatedRegionAndSameOperationIdFailsWrongRegion(): void
    {
        // Region is NOT part of the Symfony operation identity (the
        // identity is scope + binding + epoch + operation id), so a
        // region rotation cannot change the derived identity the way an
        // epoch bump can: the matching-identity replay still unlocks the
        // consumed branch. The boundary therefore relies on the core's
        // compositional replay gate: an expired retry (the exempt
        // circumstance, first in the cheap-phase order) with a rotated
        // verifier region must fail the hard verdict — the stored success
        // never replays around the region check.
        $storage = new ArrayStorage();
        $now = 1_800_000_000;
        $nowFn = static function () use (&$now): int {
            return $now;
        };
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage, now: $nowFn);
        $verifier = new Verifier($storage, now: $nowFn);
        $challenge = $issuer->issue('login', '198.51.100.7', 'txn-123');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $validate = function () use ($verifier, $token): array {
            $stack = new RequestStack();
            $request = Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']);
            $request->attributes->set(KiwiCaptchaValidator::REQUEST_BINDING_ATTRIBUTE, 'txn-123');
            $request->attributes->set(KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE, 'op-123');
            $stack->push($request);
            $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET, policyVersion: 1);
            $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
            $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
            $dto = new class {
                public ?string $captcha = null;
            };
            $dto->captcha = $token;
            $meta = $engine->getMetadataFor($dto::class);
            $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
            $violations = $engine->validate($dto);
            $codes = [];
            foreach ($violations as $violation) {
                $codes[] = (string) $violation->getCode();
            }

            return $codes;
        };

        self::assertSame([], $validate(), 'the solve passes under the explicit operation id');

        // The verifier's region expectation rotates (the epoch stays 1, so
        // the derived identity is unchanged) and the token expires: the
        // exempt expiry sits before the region check in the cheap-phase
        // order, but the hard verdict must still win.
        $verifier->rotateDeploymentExpectations(1, 'eu', null);
        $now = 1_800_000_130;

        self::assertContains(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $validate(), 'the expired same-id replay after the region rotation never replays the stored success');

        // The collapsed code hides the core reason, so the verdict is
        // asserted directly on the rotated verifier: WrongRegion, not
        // Expired and not a stored-success replay.
        $outcome = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7', operationIdentity: hash('sha256', 'login'."\0".'txn-123'."\0".'epoch:1'."\0".'opid:op-123'), expectedRequestBinding: 'txn-123');
        self::assertSame(\KiwiCaptcha\VerifyError::WrongRegion, $outcome->error, 'the refusal is specifically the WrongRegion verdict, never the exempt expiry');
        self::assertNotNull($storage->consumedState($challenge->nonce)?->consumedResult, 'the committed evidence survives the refusal');
    }

    public function testExpiredReplayWithRotatedIssuerAndSameOperationIdFailsWrongIssuer(): void
    {
        // The issuer twin of the region test: issuer is not part of the
        // Symfony identity either, so the matching-identity expired retry
        // after an issuer rotation must fail the hard WrongIssuer verdict
        // through the core's compositional replay gate, never replay the
        // stored success.
        $storage = new ArrayStorage();
        $now = 1_800_000_000;
        $nowFn = static function () use (&$now): int {
            return $now;
        };
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage, now: $nowFn);
        $verifier = new Verifier($storage, now: $nowFn);
        $challenge = $issuer->issue('login', '198.51.100.7', 'txn-123');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $validate = function () use ($verifier, $token): array {
            $stack = new RequestStack();
            $request = Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']);
            $request->attributes->set(KiwiCaptchaValidator::REQUEST_BINDING_ATTRIBUTE, 'txn-123');
            $request->attributes->set(KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE, 'op-123');
            $stack->push($request);
            $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET, policyVersion: 1);
            $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
            $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
            $dto = new class {
                public ?string $captcha = null;
            };
            $dto->captcha = $token;
            $meta = $engine->getMetadataFor($dto::class);
            $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
            $violations = $engine->validate($dto);
            $codes = [];
            foreach ($violations as $violation) {
                $codes[] = (string) $violation->getCode();
            }

            return $codes;
        };

        self::assertSame([], $validate(), 'the solve passes under the explicit operation id');

        // The verifier's issuer expectation rotates; the token expires.
        $verifier->rotateDeploymentExpectations(1, null, 'prod');
        $now = 1_800_000_130;

        self::assertContains(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $validate(), 'the expired same-id replay after the issuer rotation never replays the stored success');

        $outcome = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7', operationIdentity: hash('sha256', 'login'."\0".'txn-123'."\0".'epoch:1'."\0".'opid:op-123'), expectedRequestBinding: 'txn-123');
        self::assertSame(\KiwiCaptcha\VerifyError::WrongIssuer, $outcome->error, 'the refusal is specifically the WrongIssuer verdict, never the exempt expiry');
        self::assertNotNull($storage->consumedState($challenge->nonce)?->consumedResult, 'the committed evidence survives the refusal');
    }

    public function testBindingAuthorityDecliningTheTransactionIsTheInvalidBindingOutcome(): void
    {
        // The authority returns null (the transaction is invalid/unknown):
        // the signed record binding can never match a null canonical
        // binding — the normal invalid-binding outcome applies.
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $verifier = new Verifier($storage);
        $challenge = $issuer->issue('login', '198.51.100.7', 'server-transaction');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $authority = new NullBindingAuthority();
        [$engine, $stack] = $this->buildBindingEngine($verifier, 'client-hint', authority: $authority);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode(), 'a null authority resolution is the normal invalid-binding outcome');
        self::assertNull($stack->getMainRequest()?->attributes->get(KiwiCaptchaValidator::VERIFIED_JTI_ATTRIBUTE), 'a declined transaction must not expose a jti');
        self::assertSame(1, $authority->calls, 'the authority is consulted exactly once');

        // An unbound record with a null resolution stays the unbound
        // contract: no signed binding -> no check -> pass.
        $unbound = $issuer->issue('login', '198.51.100.7');
        usleep(($unbound->minDurationMs + 10) * 1000);
        $unboundToken = $this->solveToken($unbound->prefix, $unbound->salt, $unbound->targetBits, $unbound->nonce);
        $authority2 = new NullBindingAuthority();
        [$engine2] = $this->buildBindingEngine($verifier, 'client-hint', authority: $authority2);
        $dto2 = new class {
            public ?string $captcha = null;
        };
        $dto2->captcha = $unboundToken;
        $meta2 = $engine2->getMetadataFor($dto2::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        self::assertCount(0, $engine2->validate($dto2), 'a null canonical binding leaves the unbound record contract unchanged');
        self::assertSame(1, $authority2->calls);
    }

// ── security-policy epoch ──────────────────────────────────────────────────

    public function testWrongPolicyVersionSurfacesAsInvalidOrExpired(): void
    {
        // Issue at policy_version 1 (the default), verify with an expected
        // epoch of 2 — the verifier rejects the record (WrongPolicyVersion)
        // and the validator collapses it to invalid_or_expired.
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $verifier = new Verifier($storage, null, null, false, null, 2);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode(), 'WrongPolicyVersion must collapse to invalid_or_expired');
        self::assertNull($stack->getMainRequest()?->attributes->get(KiwiCaptchaValidator::VERIFIED_JTI_ATTRIBUTE), 'a policy-rejected solve must not expose a jti');
    }

    public function testSamePolicyVersionVerifies(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $verifier = new Verifier($storage, null, null, false, null, 1);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        self::assertCount(0, $engine->validate($dto), 'a record issued at the expected policy epoch must verify');
    }

// ── public code collapsing ─────────────────────────────────────────────────

    public function testTokenLevelFailuresCollapseToInvalidOrExpired(): void
    {
        // WrongScope (a token-level failure) must surface as
        // invalid_or_expired — the client gets no oracle for which check
        // failed.
        $challenge = $this->issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $violations = $this->validate($dto, ['captcha' => [new KiwiCaptcha(['scope' => 'signup'])]]);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode(), 'WrongScope must collapse to invalid_or_expired');

        // Garbage token: MalformedToken -> invalid_or_expired too.
        $dto = new class {
            public ?string $captcha = 'not-a-token';
        };
        $violations = $this->validate($dto, ['captcha' => [new KiwiCaptcha()]]);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode());
    }

// ── ambiguous-consume deterministic retry ─────────────────────────────────

    /**
     * @return array{0: \Symfony\Component\Validator\Validator\ValidatorInterface, 1: RequestStack, 2: KiwiCaptchaValidator}
     */
    private function buildRetryEngine(Verifier $verifier, ?StorageInterface $storage, string $ip = '198.51.100.7', ?string $binding = null, ?string $operationId = null): array
    {
        $stack = new RequestStack();
        $request = Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => $ip]);
        if ($binding !== null) {
            $request->attributes->set(KiwiCaptchaValidator::REQUEST_BINDING_ATTRIBUTE, $binding);
        }
        if ($operationId !== null) {
            $request->attributes->set(KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE, $operationId);
        }
        $stack->push($request);

        $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET, false, null, null, null, null, $storage);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();

        return [$engine, $stack, $validator];
    }

    private function issueBoundChallenge(string $binding, StorageInterface $storage): \KiwiCaptcha\Challenge
    {
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);

        return $issuer->issue('login', '198.51.100.7', $binding);
    }

    /**
     * Retryable contract (runs on the current core): a
     * ConsumeIndeterminate (lost consume response) never burns the token and
     * never re-derives — the first attempt surfaces as temporary_unavailable
     * (the record is still pending), and a retry consumes + derives exactly
     * once.
     */
    public function testConsumeIndeterminateIsRetryableAndNeverBurnsTheToken(): void
    {
        $storage = new ConsumedStateStorage();
        $verifier = new Verifier($storage);
        $challenge = $this->issueBoundChallenge('txn-123', $storage);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        [$engine, $stack] = $this->buildRetryEngine($verifier, $storage, binding: 'txn-123');
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        // Lost response: the consume transition threw mid-flight.
        $storage->throwOnConsume = true;
        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'an unresolvable indeterminate outcome must be temporary_unavailable — never invalid_or_expired');
        self::assertNull($stack->getMainRequest()?->attributes->get(KiwiCaptchaValidator::VERIFIED_JTI_ATTRIBUTE));
        self::assertSame(0, $storage->consumes, 'the ambiguous attempt must not consume');

        // The client retries the same token: the storage recovered — exactly
        // one consume + one derive, then success with the canonical jti.
        $storage->throwOnConsume = false;
        self::assertCount(0, $engine->validate($dto), 'the retry of the same token must succeed once storage recovers');
        self::assertSame($challenge->nonce, $stack->getMainRequest()?->attributes->get(KiwiCaptchaValidator::VERIFIED_JTI_ATTRIBUTE));
        self::assertSame(1, $storage->consumes, 'the retry consumed exactly once');
        self::assertSame(0, $storage->deletes, 'the ambiguous flow must never delete the record');
    }

    public function testConsumeIndeterminateWithoutStorageWiredIsTemporaryUnavailable(): void
    {
        $storage = new ConsumedStateStorage();
        $storage->throwOnConsume = true;
        $verifier = new Verifier($storage);
        $challenge = $this->issueBoundChallenge('txn-123', $storage);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        // No storage is wired into the validator: the indeterminate outcome
        // cannot be resolved — it collapses to temporary_unavailable.
        [$engine] = $this->buildRetryEngine($verifier, null, binding: 'txn-123');
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode());
    }

    /**
     * (a) the full stored-result retry: first verification succeeds
     * (consume transition + derive + committed result) under an explicit
     * operation id; a lost response makes the client re-submit the same
     * token with the same binding and the same operation id. The retry
     * resolves from the stored result — the same success (jti + binding
     * exposed) with no second consume and no second derive. Without the
     * operation id the same retry is refused (strict single-use: the
     * binding alone is derivable by any holder of the token).
     */
    public function testStoredResultRetryWithSameBindingAndOperationIdSucceedsWithoutSecondDerive(): void
    {
        $storage = new ConsumedStateStorage();
        $verifier = new Verifier($storage);
        $challenge = $this->issueBoundChallenge('txn-123', $storage);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        // first verification: real derive — consume transition + committed
        // result (the verifier commits after deriving). The operation id
        // names the logical operation, so the retry can prove it.
        [$engine, $stack, $validator] = $this->buildRetryEngine($verifier, $storage, binding: 'txn-123', operationId: 'op-123');
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        self::assertCount(0, $engine->validate($dto));
        self::assertSame($challenge->nonce, $stack->getMainRequest()?->attributes->get(KiwiCaptchaValidator::VERIFIED_JTI_ATTRIBUTE));
        self::assertSame(1, $storage->consumes);
        self::assertSame(1, $storage->commits, 'the verifier must commit the derivation result');

        // lost response: the client never saw the reply and re-submits the
        // same token with the same binding and the same operation id.
        [$engine2, $stack2, $validator2] = $this->buildRetryEngine($verifier, $storage, binding: 'txn-123', operationId: 'op-123');
        $dto2 = new class {
            public ?string $captcha = null;
        };
        $dto2->captcha = $token;
        $meta2 = $engine2->getMetadataFor($dto2::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        self::assertCount(0, $engine2->validate($dto2), 'a retry with the SAME binding and operation id must produce the SAME success');
        self::assertSame($challenge->nonce, $stack2->getMainRequest()?->attributes->get(KiwiCaptchaValidator::VERIFIED_JTI_ATTRIBUTE), 'the retry must expose the SAME canonical jti');
        self::assertSame('txn-123', $validator2->verifiedRequestBinding(), 'the retry must expose the stored signed binding');
        self::assertSame(2, $storage->consumes, 'the retry reached the consume transition (consumedBefore), but...');
        self::assertSame(1, $storage->commits, 'the retry must NOT commit again — the outcome came from the STORED RESULT, no second derive');
        self::assertSame(0, $storage->deletes);

        // The same retry without the operation id: the derived identity no
        // longer matches the stored one (which carries the opid component),
        // so the core refuses the stored success as AlreadyConsumed —
        // invalid_or_expired, never a pass. (The pure binding-only replay
        // gate, where the identities DO match, is covered by
        // OperationIdentityReplayTest.)
        [$engine3, $stack3] = $this->buildRetryEngine($verifier, $storage, binding: 'txn-123');
        $dto3 = new class {
            public ?string $captcha = null;
        };
        $dto3->captcha = $token;
        $meta3 = $engine3->getMetadataFor($dto3::class);
        $meta3->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine3->validate($dto3);
        self::assertCount(1, $violations, 'a binding-only retry (no operation id) must be refused');
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode());
    }

    /**
     * (b) the retry with a different request binding is refused
     * with invalid_or_expired — a challenge bound to one transaction is
     * never redeemable for another, retries included (the derived
     * operation identity differs, so the core refuses the stored success
     * as AlreadyConsumed).
     */
    public function testStoredResultRetryWithDifferentBindingFailsInvalidOrExpired(): void
    {
        $storage = new ConsumedStateStorage();
        $verifier = new Verifier($storage);
        $challenge = $this->issueBoundChallenge('txn-123', $storage);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        // First verification succeeds (bound to txn-123).
        [$engine] = $this->buildRetryEngine($verifier, $storage, binding: 'txn-123');
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        self::assertCount(0, $engine->validate($dto));

        // Retry with a different binding: a different logical operation —
        // the derived identity no longer matches the stored one.
        [$engine2, $stack2] = $this->buildRetryEngine($verifier, $storage, binding: 'txn-OTHER');
        $dto2 = new class {
            public ?string $captcha = null;
        };
        $dto2->captcha = $token;
        $meta2 = $engine2->getMetadataFor($dto2::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engine2->validate($dto2);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode(), 'a stored-result retry with a different binding must be invalid_or_expired');
        self::assertNull($stack2->getMainRequest()?->attributes->get(KiwiCaptchaValidator::VERIFIED_JTI_ATTRIBUTE));
    }

    /**
     * A consumed record whose committed result is invalid (the original
     * derivation failed, response lost) resolves the retry to
     * invalid_or_expired — the failed outcome is authoritative.
     */
    public function testStoredResultRetryOfAFailedDeriveFailsInvalidOrExpired(): void
    {
        $storage = new ConsumedStateStorage();
        $verifier = new Verifier($storage);
        $challenge = $this->issueBoundChallenge('txn-123', $storage);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        // Simulate the original attempt: consumed, derivation failed,
        // committed result invalid, response lost.
        $storage->transitionConsumed($challenge->nonce);
        $storage->commitResult($challenge->nonce, false, null);

        [$engine, $stack] = $this->buildRetryEngine($verifier, $storage, binding: 'txn-123');
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode(), 'a stored INVALID result must resolve the retry to invalid_or_expired');
        self::assertNull($stack->getMainRequest()?->attributes->get(KiwiCaptchaValidator::VERIFIED_JTI_ATTRIBUTE));
        self::assertSame(1, $storage->commits, 'the retry must not re-derive a record with a committed result — no second commit (the consume transition only reads the stored outcome)');
    }

    /**
     * A consumed record without a committed result (the original attempt
     * died mid-proof) stays genuinely indeterminate — the retry collapses
     * to temporary_unavailable, never to a guessed success.
     */
    public function testConsumedWithoutCommittedResultStaysTemporaryUnavailable(): void
    {
        $storage = new ConsumedStateStorage();
        $verifier = new Verifier($storage);
        $challenge = $this->issueBoundChallenge('txn-123', $storage);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        // Consumed mid-proof, no result committed.
        $storage->transitionConsumed($challenge->nonce);

        [$engine] = $this->buildRetryEngine($verifier, $storage, binding: 'txn-123');
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'consumed-without-result must stay indeterminate (temporary_unavailable)');
    }

    /**
     * The ambiguous-consume stored-valid normalization is identity-gated.
     * A ConsumeIndeterminate outcome resolves to the stored success only
     * when the retained operation identity equals this validation's
     * derived identity. A different operation's identity, or a plain
     * consume that recorded none, is refused as invalid_or_expired —
     * never a replayed success for a different operation.
     */
    public function testAmbiguousConsumeNormalizationIsIdentityGated(): void
    {
        $storage = new ConsumedStateStorage();
        $verifier = new Verifier($storage);
        $challenge = $this->issueBoundChallenge('txn-123', $storage);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        // The original attempt consumed, derived, committed a valid
        // result... but its response was lost after the commit. Model the
        // lost response on the retry: the first validation succeeds here,
        // then a later attempt throws on consume while the record already
        // carries the committed valid result.
        [$engine] = $this->buildRetryEngine($verifier, $storage, binding: 'txn-123', operationId: 'op-123');
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        self::assertCount(0, $engine->validate($dto));
        self::assertNotNull($storage->consumedState($challenge->nonce)?->consumedResult);

        // The same logical operation retries, and this time the consume
        // response is lost: ConsumeIndeterminate, normalized from the
        // stored record — the retained identity matches the derived one,
        // so the stored success resolves (and the replay gate accepts it:
        // explicit operation id).
        $storage->throwOnConsume = true;
        [$engine2, $stack2] = $this->buildRetryEngine($verifier, $storage, binding: 'txn-123', operationId: 'op-123');
        $dto2 = new class {
            public ?string $captcha = null;
        };
        $dto2->captcha = $token;
        $meta2 = $engine2->getMetadataFor($dto2::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        self::assertCount(0, $engine2->validate($dto2), 'the identity-matching stored success resolves the ambiguous retry');
        self::assertSame($challenge->nonce, $stack2->getMainRequest()?->attributes->get(KiwiCaptchaValidator::VERIFIED_JTI_ATTRIBUTE));

        // A different operation's retry under the same lost-response
        // conditions (a different binding derives a different identity):
        // refused, never the stored success.
        [$engine3, $stack3] = $this->buildRetryEngine($verifier, $storage, binding: 'txn-OTHER', operationId: 'op-123');
        $dto3 = new class {
            public ?string $captcha = null;
        };
        $dto3->captcha = $token;
        $meta3 = $engine3->getMetadataFor($dto3::class);
        $meta3->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine3->validate($dto3);
        self::assertCount(1, $violations, 'a different operation must never resolve the ambiguous retry to the stored success');
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode());
        self::assertNull($stack3->getMainRequest()?->attributes->get(KiwiCaptchaValidator::VERIFIED_JTI_ATTRIBUTE));
    }

    /**
     * KCA-79-02: the ambiguous-consume normalization synthesizes the
     * stored Valid only behind the causal replication fence — the consume
     * and commit mutations may have landed with their WAIT failing, so a
     * read-only synthesis would return an authorization a stale-replica
     * promotion could resurrect. A shortfalling fence leaves the outcome
     * indeterminate (retryable temporary_unavailable), never a
     * synthesized Valid; a satisfied fence resolves the stored success.
     */
    public function testAmbiguousConsumeNormalizationFencesTheStoredAcceptance(): void
    {
        $storage = new ConsumedStateStorage();
        $verifier = new Verifier($storage);
        $challenge = $this->issueBoundChallenge('txn-123', $storage);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        // The original attempt consumes, derives and commits the valid
        // result.
        [$engine] = $this->buildRetryEngine($verifier, $storage, binding: 'txn-123', operationId: 'op-123');
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        self::assertCount(0, $engine->validate($dto));
        self::assertNotNull($storage->consumedState($challenge->nonce)?->consumedResult);

        // The retry loses the consume response AND the replication fence
        // shortfalls: the normalization must NOT synthesize the Valid —
        // the outcome stays indeterminate (temporary_unavailable).
        $storage->throwOnConsume = true;
        $storage->throwOnFence = true;
        [$engine2] = $this->buildRetryEngine($verifier, $storage, binding: 'txn-123', operationId: 'op-123');
        $dto2 = new class {
            public ?string $captcha = null;
        };
        $dto2->captcha = $token;
        $meta2 = $engine2->getMetadataFor($dto2::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine2->validate($dto2);
        self::assertCount(1, $violations, 'a shortfalling fence must never synthesize the stored Valid');
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'the failed fence leaves the retryable temporary_unavailable outcome');

        // The satisfied fence resolves the stored success.
        $storage->throwOnFence = false;
        [$engine3] = $this->buildRetryEngine($verifier, $storage, binding: 'txn-123', operationId: 'op-123');
        $dto3 = new class {
            public ?string $captcha = null;
        };
        $dto3->captcha = $token;
        $meta3 = $engine3->getMetadataFor($dto3::class);
        $meta3->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        self::assertCount(0, $engine3->validate($dto3), 'a satisfied fence resolves the stored success');
    }

// ── quic IP-migration policy ───────────────────────────────────────────────

    /**
     * Documentation test: the strict binding stays — a challenge
     * bound to IP A verified from IP B fails closed with IpMismatch at the
     * core level (the collapsed invalid_or_expired through the validator).
     * The documented migration policy (readme): exact IP -> normal; same
     * network -> acceptable with a risk penalty (the engine's subnet
     * dimension); different network -> fresh challenge or stronger
     * request_binding/session check; mobile clients prefer request_binding
     * over IP. The IP binding itself is a nonce-bound hmac tag, never a
     * stable identifier.
     */
    public function testIpMismatchFailsClosedDocumentingTheQuicMigrationPolicy(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $verifier = new Verifier($storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        usleep(((int) $challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        // Same exact IP: valid.
        self::assertTrue($verifier->verify($token, self::SECRET, 'login', '198.51.100.7')->isOk(), 'the exact bound IP verifies');
        // A different network: the nonce-bound tag cannot match — the
        // cheap phase fails, but the record is already consumed, so the
        // retained consumed evidence is preserved and the replay resolves
        // through the consumed branch: with no identity proven, the
        // stored success is refused as AlreadyConsumed (fail closed,
        // one-shot — the challenge is burned by the first attempt).
        $outcome = $verifier->verify($token, self::SECRET, 'login', '203.0.113.9');
        self::assertFalse($outcome->isOk());
        self::assertSame(\KiwiCaptcha\VerifyError::AlreadyConsumed, $outcome->error, 'an IP-mismatch replay of a consumed record is AlreadyConsumed, never a replay of the stored success');
        self::assertNotNull($storage->find($challenge->nonce), 'the consumed recovery evidence survives the IP-mismatch replay');

        // Through the validator: the same mismatch collapses to
        // invalid_or_expired — the client never learns which
        // check failed (no oracle).
        $challenge2 = $issuer->issue('login', '198.51.100.7');
        usleep(((int) $challenge2->minDurationMs + 10) * 1000);
        $token2 = $this->solveToken($challenge2->prefix, $challenge2->salt, $challenge2->targetBits, $challenge2->nonce);

        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '203.0.113.9']));
        $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engineValidator = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();

        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token2;
        $meta = $engineValidator->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engineValidator->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode());
    }

// ── post-solve disposition store (durable final disposition) ──────────────

    /**
     * A fixed clock for the in-memory disposition store: the closure
     * captures the variable BY reference, so tests advance the store's time
     * to exercise lease expiry.
     *
     * @return array{0: ArrayPostSolveDispositionStore, 1: \Closure}
     */
    private function clockedDispositionStore(?\ArrayAccess $decisionMap = null): array
    {
        $clock = 1_800_000_000;
        $store = new ArrayPostSolveDispositionStore(
            static function () use (&$clock): int {
                return $clock;
            },
            0,
            $decisionMap,
        );
        $advance = static function (int $seconds) use (&$clock): void {
            $clock += $seconds;
        };

        return [$store, $advance];
    }

    /**
     * The shared nonce -> decision map of the in-memory disposition store:
     * an ArrayAccess mirror of the FakePredisClient's decision strings (the
     * same keys, the same json shape) — the fixture wiring of the Array
     * store's atomic claim transfer.
     */
    private function decisionMap(FakePredisClient $decisionRedis): \ArrayAccess
    {
        return new class($decisionRedis) implements \ArrayAccess {
            public function __construct(private readonly FakePredisClient $redis)
            {
            }

            public function offsetExists(mixed $offset): bool
            {
                return isset($this->redis->strings[$offset]);
            }

            public function offsetGet(mixed $offset): mixed
            {
                return $this->redis->strings[$offset] ?? null;
            }

            public function offsetSet(mixed $offset, mixed $value): void
            {
                $this->redis->strings[$offset] = (string) $value;
            }

            public function offsetUnset(mixed $offset): void
            {
                unset($this->redis->strings[$offset]);
            }
        };
    }

    /**
     * A store wrapper that fails claim/read/finalize on demand — the crash
     * simulation for the fail-closed disposition tests.
     */
    private function faultedStore(PostSolveDispositionStore $inner, bool $failClaim = false, bool $failRead = false, bool $failFinalize = false): PostSolveDispositionStore
    {
        return new class($inner, $failClaim, $failRead, $failFinalize) implements PostSolveDispositionStore {
            public function __construct(
                private PostSolveDispositionStore $inner,
                private bool $failClaim,
                private bool $failRead,
                private bool $failFinalize,
            ) {
            }

            public function claim(string $nonce, string $owner, int $ttlSeconds, ?string $decisionKey = null, ?string $obligationId = null, ?string $snapshotChainId = null, ?string $expectedStage2Nonce = null): array
            {
                if ($this->failClaim) {
                    throw new \RuntimeException('simulated claim outage');
                }

                return $this->inner->claim($nonce, $owner, $ttlSeconds, $decisionKey, $obligationId, $snapshotChainId, $expectedStage2Nonce);
            }

            public function read(string $nonce): ?PostSolveDispositionRecord
            {
                if ($this->failRead) {
                    throw new \RuntimeException('simulated read outage');
                }

                return $this->inner->read($nonce);
            }

            public function finalize(string $nonce, string $owner, PostSolveDisposition $disposition): bool
            {
                if ($this->failFinalize) {
                    throw new \RuntimeException('simulated finalize outage');
                }

                return $this->inner->finalize($nonce, $owner, $disposition);
            }

            public function finalizeGuarded(string $nonce, string $owner, PostSolveDisposition $disposition, ?string $obligationId, ?string $snapshotChainId, ?string $expectedStage2Nonce): PostSolveFinalizeOutcome
            {
                if ($this->failFinalize) {
                    throw new \RuntimeException('simulated finalize outage');
                }

                return $this->inner->finalizeGuarded($nonce, $owner, $disposition, $obligationId, $snapshotChainId, $expectedStage2Nonce);
            }
        };
    }

    /**
     * A well-formed pending record for the corruption seam (the lease is
     * already expired, so the claim path exercises the strict decoder
     * too).
     *
     * @return array<string, mixed>
     */
    private function pendingDispositionRecord(): array
    {
        return [
            'ttl' => 305,
            'created' => 1_800_000_000,
            'v' => 1,
            'state' => 'pending',
            'owner' => 'owner-a',
            'leaseUntil' => 1_799_999_999,
            'disposition' => null,
            'decisionId' => null,
        ];
    }

    /**
     * A well-formed complete record for the corruption seam.
     *
     * @return array<string, mixed>
     */
    private function completeDispositionRecord(): array
    {
        return [
            'ttl' => 305,
            'created' => 1_800_000_000,
            'v' => 1,
            'state' => 'complete',
            'owner' => null,
            'leaseUntil' => null,
            'disposition' => new PostSolveDisposition(PostSolveDispositionKind::Pass, 'decision-1'),
            'decisionId' => 'decision-1',
        ];
    }

    /**
     * Inject a raw record into the in-memory disposition store (reflection)
     * — the corruption seam of the strict-decoder tests.
     *
     * @param array<string, mixed> $record
     */
    private function injectDispositionRecord(ArrayPostSolveDispositionStore $store, string $nonce, array $record): void
    {
        $prop = new \ReflectionProperty(ArrayPostSolveDispositionStore::class, 'records');
        $records = $prop->getValue($store);
        $records[$nonce] = $record;
        $prop->setValue($store, $records);
    }

    /**
     * Drive ONE corruption through the full validation pipeline: a fresh
     * valid token whose nonce's disposition record is corrupt must fail
     * closed with temporary_unavailable — never a silent pass, never a
     * 422 (the client did not corrupt the server's record structure).
     *
     * @param array<string, mixed> $corruptRecord
     *
     * @return array{0: string, 1: ArrayPostSolveDispositionStore, 2: string} the
     *         violation code, the store and the nonce
     */
    private function validateCorruptDisposition(array $corruptRecord): array
    {
        $risk = $this->riskStack(1, 'allow', 'allow', false);
        [$store] = $this->clockedDispositionStore();
        $challenge = $this->issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $this->injectDispositionRecord($store, $challenge->nonce, $corruptRecord);

        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine->validate($dto);

        return [$violations[0]->getCode(), $store, $challenge->nonce];
    }

    /**
     * A validator wired with the risk gateway + a durable disposition store
     * over the shared challenge storage, driving the full Symfony
     * validation pipeline for one token.
     *
     * @param array<string, string> $post the post body (decoy fields, ...)
     *
     * @return array{0: \Symfony\Component\Validator\Validator\ValidatorInterface, 1: RequestStack, 2: KiwiCaptchaValidator}
     */
    private function dispositionEngine(Verifier $verifier, RiskGateway $gateway, PostSolveDispositionStore $store, array $post = [], int $ttlMargin = 0, ?ChainedChallengeTicketService $chainTickets = null, ?RiskProfileResolver $resolver = null, ?RequestBindingAuthorityInterface $bindingAuthority = null, int $chainTtlSecs = 300, ?\BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadataStore $metadataStore = null, ?RequestStack $requestStack = null, ?string $operationId = null): array
    {
        $stack = $requestStack ?? new RequestStack();
        $request = Request::create('/', 'POST', $post, [], [], ['REMOTE_ADDR' => '198.51.100.7']);
        if ($operationId !== null) {
            $request->attributes->set(KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE, $operationId);
        }
        $stack->push($request);
        $validator = new KiwiCaptchaValidator(
            $verifier,
            $stack,
            self::SECRET,
            enforceTelemetry: false,
            risk: $gateway,
            chainTickets: $chainTickets,
            riskResolver: $resolver,
            dispositionStore: $store,
            bindingAuthority: $bindingAuthority,
            postSolveDispositionTtlMarginSecs: $ttlMargin,
            chainTtlSecs: $chainTtlSecs,
            metadataStore: $metadataStore,
        );
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();

        return [$engine, $stack, $validator];
    }

    /**
     * The authoritative transaction-binding authority: the chain can open
     * only when it resolves a binding (a raw client-supplied binding
     * without an authority is never sufficient).
     */
    private function bindingAuthority(): RequestBindingAuthorityInterface
    {
        return new class implements RequestBindingAuthorityInterface {
            public function resolve(Request $request, string $scope, ?string $presentedBinding): ?string
            {
                return 'auth-txn-1';
            }
        };
    }

    /**
     * The normalized event id the engine derives from a caller idempotency
     * key (hmac-sha256 of the domain-separated message, keyed by the
     * master-derived event key) — the dedupe identity a crash-taken-over
     * re-assessment must reproduce.
     */
    private function expectedEventId(RiskEventKind $event, int $scope, string $key): string
    {
        return hash_hmac('sha256', pack('N', $scope).chr($event->value).$key, RiskKeys::fromMaster(self::SECRET)->event);
    }

    /**
     * A store wrapper that counts the claim/read/finalize interactions —
     * the call-pattern proof that the common fresh path runs exactly
     * claim -> compute -> finalize (no read before or after the claim).
     *
     * @return array{0: PostSolveDispositionStore, 1: object}
     */
    private function countingStore(PostSolveDispositionStore $inner): array
    {
        $counting = new class($inner) implements PostSolveDispositionStore {
            public int $claims = 0;

            public int $reads = 0;

            public int $finalizes = 0;

            public function __construct(private readonly PostSolveDispositionStore $inner)
            {
            }

            public function claim(string $nonce, string $owner, int $ttlSeconds, ?string $decisionKey = null, ?string $obligationId = null, ?string $snapshotChainId = null, ?string $expectedStage2Nonce = null): array
            {
                ++$this->claims;

                return $this->inner->claim($nonce, $owner, $ttlSeconds, $decisionKey, $obligationId, $snapshotChainId, $expectedStage2Nonce);
            }

            public function read(string $nonce): ?PostSolveDispositionRecord
            {
                ++$this->reads;

                return $this->inner->read($nonce);
            }

            public function finalize(string $nonce, string $owner, PostSolveDisposition $disposition): bool
            {
                ++$this->finalizes;

                return $this->inner->finalize($nonce, $owner, $disposition);
            }

            public function finalizeGuarded(string $nonce, string $owner, PostSolveDisposition $disposition, ?string $obligationId, ?string $snapshotChainId, ?string $expectedStage2Nonce): PostSolveFinalizeOutcome
            {
                ++$this->finalizes;

                return $this->inner->finalizeGuarded($nonce, $owner, $disposition, $obligationId, $snapshotChainId, $expectedStage2Nonce);
            }
        };

        return [$counting, $counting];
    }

    /**
     * The fresh path issues exactly claim + finalize (two interactions).
     * The claim transition itself carries the validated state, the
     * decision handle and the record info the caller needs, so the
     * validator performs no read before or after the claim; the common
     * path is claim -> compute -> finalize.
     */
    public function testFreshPathIssuesExactlyClaimAndFinalize(): void
    {
        $risk = $this->riskStack(1, 'allow', 'allow', true);
        $risk['store']->setVector(SignalVector::fromArray(['network_risk' => 900]));
        [$inner] = $this->clockedDispositionStore();
        [$counting] = $this->countingStore($inner);

        $challenge = $this->issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $counting, operationId: 'op-retry');
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violations[0]->getCode(), 'the fresh assessment denies — the disposition is computed and persisted');
        self::assertSame(1, $counting->claims, 'exactly one claim');
        self::assertSame(1, $counting->finalizes, 'exactly one finalize');
        self::assertSame(0, $counting->reads, 'the fresh path issues NO read — the claim response carries the state and the decision handle');
    }

    public function testPostSolveDispositionStoreClaimMachine(): void
    {
        [$store, $advance] = $this->clockedDispositionStore();

        // Missing -> pending(me, 15s lease): claimed.
        self::assertSame('claimed', $store->claim('nonce-a', 'owner-1', 300)[0]);
        // pending+me -> 'pending' (the same owner re-enters).
        self::assertSame('pending', $store->claim('nonce-a', 'owner-1', 300)[0]);
        // pending+other+live -> 'pending' (busy).
        self::assertSame('pending', $store->claim('nonce-a', 'owner-2', 300)[0]);
        $record = $store->read('nonce-a');
        self::assertNotNull($record);
        self::assertSame('pending', $record->state);
        self::assertSame('owner-1', $record->owner);
        self::assertNull($record->disposition);

        // pending+other+expired -> takeover -> 'taken_over'.
        $advance(16);
        self::assertSame('taken_over', $store->claim('nonce-a', 'owner-2', 300)[0]);
        self::assertSame('owner-2', $store->read('nonce-a')?->owner, 'the takeover must move the claim to the new owner');

        // pending(me) -> complete(disposition), then 'complete' forever.
        self::assertTrue($store->finalize('nonce-a', 'owner-2', new PostSolveDisposition(PostSolveDispositionKind::Deny, 'decision-1')));
        self::assertSame('complete', $store->claim('nonce-a', 'owner-3', 300)[0], 'a completed disposition replays as complete');
        $record = $store->read('nonce-a');
        self::assertSame('complete', $record->state);
        self::assertNull($record->owner);
        self::assertNull($record->leaseUntil);
        self::assertNotNull($record->disposition);
        self::assertSame(PostSolveDispositionKind::Deny, $record->disposition->kind);
        self::assertSame('decision-1', $record->disposition->decisionId);

        // finalize on a complete record is refused (never overwritten).
        self::assertFalse($store->finalize('nonce-a', 'owner-3', new PostSolveDisposition(PostSolveDispositionKind::Pass)));
        self::assertSame(PostSolveDispositionKind::Deny, $store->read('nonce-a')?->disposition?->kind, 'a completed disposition is terminal');
    }

    public function testPostSolveDispositionStoreFinalizeIsOwnerGated(): void
    {
        [$store] = $this->clockedDispositionStore();

        self::assertSame('claimed', $store->claim('nonce-b', 'owner-1', 300)[0]);
        // A non-owner finalize is an atomic no-op.
        self::assertFalse($store->finalize('nonce-b', 'owner-2', new PostSolveDisposition(PostSolveDispositionKind::Pass)));
        self::assertSame('pending', $store->read('nonce-b')?->state, 'a refused finalize leaves the claim pending');
        // The owner's finalize still succeeds.
        self::assertTrue($store->finalize('nonce-b', 'owner-1', new PostSolveDisposition(PostSolveDispositionKind::Pass)));
        // finalize on an absent record is refused.
        self::assertFalse($store->finalize('nonce-missing', 'owner-1', new PostSolveDisposition(PostSolveDispositionKind::Pass)));
    }

    public function testPostSolveDispositionStoreRecordTtlIsIndependentOfTheLease(): void
    {
        [$store, $advance] = $this->clockedDispositionStore();

        self::assertSame('claimed', $store->claim('nonce-c', 'owner-1', 300)[0]);
        $advance(20);
        // The lease (15 s) expired -> takeover, while the record TTL (300 s) is still live.
        self::assertSame('taken_over', $store->claim('nonce-c', 'owner-2', 300)[0]);
        self::assertTrue($store->finalize('nonce-c', 'owner-2', new PostSolveDisposition(PostSolveDispositionKind::Pass)));

        // The record TTL is independent of the lease: it expires with its
        // own configured lifetime (Config::MAX_TTL_secs + margin via the
        // validator's claim TTL), never with the 15 s lease.
        $advance(301);
        self::assertNull($store->read('nonce-c'), 'the record expires with its own TTL, not with the lease');
        self::assertSame('claimed', $store->claim('nonce-c', 'owner-3', 300)[0], 'an expired record is claimable fresh');
    }

    public function testPostSolveDispositionStoreHonorsTheConfiguredRecordTtl(): void
    {
        $clock = 1_800_000_000;
        $store = new ArrayPostSolveDispositionStore(
            static function () use (&$clock): int {
                return $clock;
            },
            Config::MAX_TTL_SECS + 7,
        );
        self::assertSame('claimed', $store->claim('nonce-d', 'owner-1', 9999)[0]);
        $clock += Config::MAX_TTL_SECS + 6;
        self::assertNotNull($store->read('nonce-d'), 'the configured TTL = MAX_TTL_SECS + margin keeps the record alive');
        $clock += 2;
        self::assertNull($store->read('nonce-d'), 'the configured TTL = MAX_TTL_SECS + margin bounds the record');
    }

    public function testFreshDenyReplaysAsDenyNeverPass(): void
    {
        // The post-solve vector with a deny reason (LocalNetworkRisk).
        $risk = $this->riskStack(1, 'allow', 'allow', true);
        $risk['store']->setVector(SignalVector::fromArray(['network_risk' => 900]));
        [$store] = $this->clockedDispositionStore();

        $challenge = $this->issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, operationId: 'op-retry');
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        // fresh: the post-solve assessment denies the valid solve.
        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violations[0]->getCode());
        $record = $store->read($challenge->nonce);
        self::assertNotNull($record);
        self::assertSame(PostSolveDispositionKind::Deny, $record->disposition?->kind, 'the denied disposition must be persisted per nonce');
        $firstDecision = $record->disposition?->decisionId;
        self::assertNotNull($firstDecision);

        // replay (the same token — the core replays its stored result): the
        // persisted disposition reproduces the same deny — never a pass.
        [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, operationId: 'op-retry');
        $meta2 = $engine2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine2->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violations[0]->getCode(), 'a replay of a denied token must be denied again — never a silent pass');
        self::assertSame(1, \count($risk['store']->observations), 'the replay must NOT re-run the post-solve assessment — the persisted disposition answers');
        $record = $store->read($challenge->nonce);
        self::assertSame(PostSolveDispositionKind::Deny, $record?->disposition?->kind);
        self::assertSame($firstDecision, $record?->disposition?->decisionId, 'the replay reproduces the SAME decision id');
    }

    public function testFreshStepUpReplaysAsStepUp(): void
    {
        $risk = $this->riskStack(1, 'allow', 'allow', true);
        $risk['store']->setVector(SignalVector::fromArray(['source_fast' => 900, 'subnet_fast' => 1000, 'issue_debt' => 1000, 'replay' => 699, 'network_risk' => 890, 'action_failure' => 1000]));
        [$store] = $this->clockedDispositionStore();

        $challenge = $this->issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, operationId: 'op-retry');
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations[0]->getCode());
        self::assertSame(PostSolveDispositionKind::StepUp, $store->read($challenge->nonce)?->disposition?->kind, 'the StepUp disposition must be persisted per nonce');

        [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, operationId: 'op-retry');
        $meta2 = $engine2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine2->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations[0]->getCode(), 'a replay of a StepUp token must be StepUp again — never a pass');
        self::assertSame(1, \count($risk['store']->observations), 'the replay must NOT re-run the assessment');
    }

    public function testFreshPassReplaysAsPassWithTheSameApplicationOutcome(): void
    {
        // No post_solve_check, no chaining, no honeypot: nothing to
        // reassess — the disposition is a plain pass.
        $risk = $this->riskStack(1, 'allow', 'allow', false);
        [$store] = $this->clockedDispositionStore();

        $challenge = $this->issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        [$engine, $stack] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, operationId: 'op-retry');
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        self::assertCount(0, $engine->validate($dto));
        self::assertSame($challenge->nonce, $stack->getMainRequest()?->attributes->get(KiwiCaptchaValidator::VERIFIED_JTI_ATTRIBUTE), 'a fresh pass exposes the canonical jti');
        self::assertSame(PostSolveDispositionKind::Pass, $store->read($challenge->nonce)?->disposition?->kind, 'the pass disposition must be persisted per nonce');

        [$engine2, $stack2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, operationId: 'op-retry');
        $meta2 = $engine2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        self::assertCount(0, $engine2->validate($dto), 'a replay of a passed token must pass again');
        self::assertSame($challenge->nonce, $stack2->getMainRequest()?->attributes->get(KiwiCaptchaValidator::VERIFIED_JTI_ATTRIBUTE), 'the replay exposes the SAME canonical jti (the application outcome is identical)');
        self::assertSame(1, \count($risk['store']->observations), 'the replay must not re-record the solve signal');
    }

    public function testCrashAfterCoreCommitBeforeTheClaimRetryComputesTheDisposition(): void
    {
        $risk = $this->riskStack(1, 'allow', 'allow', true);
        $risk['store']->setVector(SignalVector::fromArray(['network_risk' => 900]));
        [$inner] = $this->clockedDispositionStore();

        $challenge = $this->issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        // request 1: the core commits the valid result, then the process
        // dies before the post-solve claim (the store is unreachable) — the
        // client sees temporary_unavailable, the token is NOT burned.
        $failing = $this->faultedStore($inner, failClaim: true);
        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $failing, operationId: 'op-retry');
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'a crash before the claim is retryable temporary_unavailable');
        self::assertSame(0, \count($risk['store']->observations), 'no assessment ran before the crash');
        self::assertNull($inner->read($challenge->nonce), 'no disposition state exists before the claim');

        // request 2 (retry, store recovered): the retry claims the nonce
        // fresh, computes the disposition (deny) and persists it — the
        // post-solve policy runs exactly once.
        [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $inner, operationId: 'op-retry');
        $meta2 = $engine2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine2->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violations[0]->getCode(), 'the retry must compute and apply the post-solve disposition');
        self::assertSame(1, \count($risk['store']->observations), 'exactly one assessment ran');
        self::assertSame(PostSolveDispositionKind::Deny, $inner->read($challenge->nonce)?->disposition?->kind);
    }

    public function testCrashAfterAssessmentBeforeFinalizeTakeoverDoesNotDoubleTheRiskSignal(): void
    {
        $risk = $this->riskStack(1, 'allow', 'allow', true);
        $risk['store']->setVector(SignalVector::fromArray(['network_risk' => 900]));
        [$inner, $advance] = $this->clockedDispositionStore();

        $challenge = $this->issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;

        // request 1: the claim is won, the post-solve assessment runs, then
        // the process dies before the finalize — temporary_unavailable.
        $crashed = $this->faultedStore($inner, failFinalize: true);
        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $crashed, operationId: 'op-retry');
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine->validate($dto);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'a crash before the finalize is retryable temporary_unavailable');
        self::assertSame(1, \count($risk['store']->observations));
        self::assertSame('pending', $inner->read($challenge->nonce)?->state, 'the claim is left pending with its lease');

        // request 2 (retry after the 15 s lease expires): the retry takes
        // over the claim and re-runs the assessment — with the same
        // nonce-derived idempotency key, so the risk signal is NOT doubled
        // (the dedupe identity is identical; a deduping backend applies it
        // exactly once).
        $advance(16);
        [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $inner, operationId: 'op-retry');
        $meta2 = $engine2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine2->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violations[0]->getCode(), 'the takeover retry must produce the SAME final disposition');
        self::assertSame(PostSolveDispositionKind::Deny, $inner->read($challenge->nonce)?->disposition?->kind);

        $observations = $risk['store']->observations;
        self::assertCount(2, $observations, 'the takeover re-ran the assessment exactly once');
        self::assertSame(
            $observations[0]->eventId,
            $observations[1]->eventId,
            'the takeover must re-use the SAME nonce-derived idempotency key — the risk signal is never double-booked',
        );
        self::assertSame(
            $this->expectedEventId(RiskEventKind::SolveSuccess, 1, 'postsolve:'.hash('sha256', $challenge->nonce)),
            $observations[1]->eventId,
            'the post-solve assessment must carry the nonce-derived postsolve:<sha256(nonce)> idempotency key',
        );
    }

    public function testConcurrentSameTokenExactlyOneOwnerComputes(): void
    {
        $risk = $this->riskStack(1, 'allow', 'allow', true);
        $risk['store']->setVector(SignalVector::fromArray(['network_risk' => 900]));
        [$inner, $advance] = $this->clockedDispositionStore();

        $challenge = $this->issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;

        // request 1 wins the claim, runs the assessment, dies before the
        // finalize (lease left live).
        $crashed = $this->faultedStore($inner, failFinalize: true);
        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $crashed, operationId: 'op-retry');
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $engine->validate($dto)[0]->getCode());
        self::assertSame(1, \count($risk['store']->observations));

        // request 2 (concurrent, same token, claim still live): the busy
        // claim is temporary_unavailable — never a second assessment, never
        // a silent pass.
        [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $inner, operationId: 'op-retry');
        $meta2 = $engine2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine2->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'a concurrent same-token request must never pass while the claim is live');
        self::assertSame(1, \count($risk['store']->observations), 'exactly ONE owner computes — the concurrent request never assessed');

        // The owner still completes after its lease expires: exactly one
        // more assessment, then the final disposition.
        $advance(16);
        [$engine3] = $this->dispositionEngine($this->verifier, $risk['gateway'], $inner, operationId: 'op-retry');
        $meta3 = $engine3->getMetadataFor($dto::class);
        $meta3->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine3->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violations[0]->getCode(), 'the lease takeover completes the disposition');
        self::assertSame(2, \count($risk['store']->observations), 'the takeover was the second and final assessment');
        self::assertSame(PostSolveDispositionKind::Deny, $inner->read($challenge->nonce)?->disposition?->kind);
    }

    public function testPostSolveStoreUnavailableIsTemporaryUnavailableNeverPass(): void
    {
        $risk = $this->riskStack(1, 'allow', 'allow', true);
        $risk['store']->setVector(SignalVector::fromArray(['network_risk' => 900]));
        [$inner] = $this->clockedDispositionStore();

        $challenge = $this->issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        // The store is unavailable for every operation: the valid solve
        // must fail closed with temporary_unavailable — never a silent pass.
        $down = $this->faultedStore($inner, failClaim: true, failRead: true, failFinalize: true);
        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $down);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'an unavailable disposition store must never silently pass a valid solve');
        self::assertSame(0, \count($risk['store']->observations), 'no assessment ran — the disposition could not be persisted');
    }

    public function testHoneypotOnlyReassessmentAndDecoyExactness(): void
    {
        // post_solve_check=false AND chaining disabled: only a filled exact
        // decoy triggers the fresh v2 assessment. The tuned honeypot weight
        // keeps the v2 score inside the Argon32 band (813 + 10), so the
        // stronger-PoW demand must surface as terminal StepUp — never a
        // silent pass.
        $risk = $this->riskStack(1, 'allow', 'allow', false, new RiskV2Weights(honeypot: 10));
        $risk['store']->setVector(SignalVector::fromArray(['source_fast' => 900, 'subnet_fast' => 1000, 'issue_debt' => 1000, 'replay' => 699, 'network_risk' => 890]));
        [$store] = $this->clockedDispositionStore();

        $challenge = $this->issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $nonce = \KiwiCaptcha\SolutionToken::decode($token)->nonce;
        $decoy = 'decoy_'.substr(hash('sha256', $nonce), 0, 8);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;

        // filled exact decoy: reassesses through the risk-v2 path; the
        // stronger-PoW demand with chaining disabled is terminal StepUp.
        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, [$decoy => 'filled'], operationId: 'op-retry');
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations[0]->getCode(), 'a filled exact decoy must reassess — a stronger-PoW demand is terminal StepUp, never a silent pass');
        self::assertSame(PostSolveDispositionKind::StepUp, $store->read($nonce)?->disposition?->kind);

        // The honeypot evidence carries the nonce-derived
        // honeypot:<sha256(nonce)> idempotency key.
        $decoyEvents = array_values(array_filter(
            $risk['store']->observations,
            static fn ($o): bool => $o->event === RiskEventKind::DecoyFieldSubmitted,
        ));
        self::assertCount(1, $decoyEvents, 'the filled exact decoy records DecoyFieldSubmitted evidence');
        self::assertSame(
            $this->expectedEventId(RiskEventKind::DecoyFieldSubmitted, 1, 'honeypot:'.hash('sha256', $nonce)),
            $decoyEvents[0]->eventId,
            'the honeypot evidence must be keyed honeypot:<sha256(nonce)> — a crash-taken-over retry never double-books the signal',
        );
        $solveEvents = array_values(array_filter(
            $risk['store']->observations,
            static fn ($o): bool => $o->event === RiskEventKind::SolveSuccess,
        ));
        self::assertCount(1, $solveEvents);
        self::assertSame(
            $this->expectedEventId(RiskEventKind::SolveSuccess, 1, 'postsolve:'.hash('sha256', $nonce)),
            $solveEvents[0]->eventId,
            'the honeypot-triggered reassessment must carry the postsolve:<sha256(nonce)> idempotency key',
        );

        // replay of the same token: the persisted StepUp disposition
        // reproduces — the honeypot is never re-scored.
        [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, [$decoy => 'filled'], operationId: 'op-retry');
        $meta2 = $engine2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine2->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations[0]->getCode(), 'a replay of the honeypot-hit token is StepUp again — never a pass');
        self::assertSame(2, \count($risk['store']->observations), 'the replay must not re-record evidence or reassess');

        // mismatched decoy name: NOT this challenge's decoy — ignored, no
        // reassessment, plain pass.
        $other = $this->issuer->issue('login', '198.51.100.7');
        usleep(($other->minDurationMs + 10) * 1000);
        $otherToken = $this->solveToken($other->prefix, $other->salt, $other->targetBits, $other->nonce);
        $dto2 = new class {
            public ?string $captcha = null;
        };
        $dto2->captcha = $otherToken;
        [$engine3] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, ['decoy_00000000' => 'filled'], operationId: 'op-retry');
        $meta3 = $engine3->getMetadataFor($dto2::class);
        $meta3->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        self::assertCount(0, $engine3->validate($dto2), 'a mismatched decoy name is not this challenge\'s decoy — no reassessment');
        self::assertSame(PostSolveDispositionKind::Pass, $store->read($other->nonce)?->disposition?->kind);

        // empty exact decoy: no evidence, no reassessment, plain pass.
        $third = $this->issuer->issue('login', '198.51.100.7');
        usleep(($third->minDurationMs + 10) * 1000);
        $thirdToken = $this->solveToken($third->prefix, $third->salt, $third->targetBits, $third->nonce);
        $thirdDecoy = 'decoy_'.substr(hash('sha256', $third->nonce), 0, 8);
        $dto3 = new class {
            public ?string $captcha = null;
        };
        $dto3->captcha = $thirdToken;
        [$engine4] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, [$thirdDecoy => ''], operationId: 'op-retry');
        $meta4 = $engine4->getMetadataFor($dto3::class);
        $meta4->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        self::assertCount(0, $engine4->validate($dto3), 'an EMPTY exact decoy is no honeypot evidence — no reassessment');
    }

    public function testChainRequiredDispositionReplaysWithTheSameChainId(): void
    {
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(1, 'allow', 'allow', false, null, $resolver);
        $risk['store']->setVector(SignalVector::fromArray(self::ARGON32_VECTOR));
        [$store] = $this->clockedDispositionStore();

        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = new ChainedChallengeTicketService($chainStore, self::SECRET, 300, 15, $this->bindingAuthority());

        $challenge = $this->issuer->issue('login', '198.51.100.7', 'auth-txn-1');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $nonce = \KiwiCaptcha\SolutionToken::decode($token)->nonce;
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;

        // fresh: the reassessment demands Argon32 — the solved sha-8 does
        // not satisfy it, the authoritative binding resolves, the chain
        // opens: chain_required with the persisted chain id.
        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, resolver: $resolver, bindingAuthority: $this->bindingAuthority(), operationId: 'op-retry');
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $record = $store->read($nonce);
        self::assertNotNull($record);
        self::assertSame(PostSolveDispositionKind::ChainRequired, $record->disposition?->kind, 'the CHAIN_REQUIRED disposition must be persisted per nonce');
        $chainId = $record->disposition?->chainId;
        self::assertIsString($chainId);
        self::assertNotEmpty($chainId);
        $ticket = $violations[0]->getParameters()['{{ chain_ticket }}'] ?? null;
        self::assertIsString($ticket);
        self::assertNotEmpty($ticket);

        // replay (the same token — the core replays its stored result): the
        // persisted disposition reproduces chain_required with the same
        // chain id — never a pass, never a second chain. The replay
        // re-signs the ticket with the requirement's original expiry, so
        // the deterministic ticket is byte-identical (a re-signed ticket
        // can never outlive its chain state).
        [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, resolver: $resolver, bindingAuthority: $this->bindingAuthority(), operationId: 'op-retry');
        $meta2 = $engine2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine2->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode(), 'a replay of a CHAIN_REQUIRED token must be CHAIN_REQUIRED again — never a pass');
        $ticket2 = $violations[0]->getParameters()['{{ chain_ticket }}'] ?? null;
        self::assertIsString($ticket2);
        self::assertNotEmpty($ticket2);
        self::assertSame($ticket, $ticket2, 'the replay re-signs with the requirement\'s ORIGINAL expiry — the deterministic ticket is byte-identical to the original');
        self::assertSame($chainId, $store->read($nonce)?->disposition?->chainId, 'the replay reproduces the SAME chain id');
        self::assertSame(1, \count($risk['store']->observations), 'the replay must not re-run the reassessment');
    }

    public function testChainRequiredReplayWithExpiredChainIsTemporaryUnavailable(): void
    {
        // A replayed chain_required disposition whose chain requirement is
        // gone (the chain expired with its own lifetime) must fail closed
        // as temporary_unavailable — never a fresh ticket that outlives
        // its chain state, never a silent pass.
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(1, 'allow', 'allow', false, null, $resolver);
        $risk['store']->setVector(SignalVector::fromArray(self::ARGON32_VECTOR));
        [$store] = $this->clockedDispositionStore();

        $chainClock = (float) time();
        $chainStore = new ArrayChainedChallengeStateStore(static function () use (&$chainClock): float {
            return $chainClock;
        });
        $chainService = new ChainedChallengeTicketService($chainStore, self::SECRET, 300, 15, $this->bindingAuthority());

        $challenge = $this->issuer->issue('login', '198.51.100.7', 'auth-txn-1');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;

        // fresh: the chain opens and the disposition is persisted.
        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, resolver: $resolver, bindingAuthority: $this->bindingAuthority(), operationId: 'op-retry');
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine->validate($dto);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        self::assertSame(PostSolveDispositionKind::ChainRequired, $store->read($challenge->nonce)?->disposition?->kind);

        // The chain expires with its own lifetime (the disposition record
        // survives): the replay cannot re-sign a ticket for a chain that
        // no longer exists — fail closed.
        $chainClock += 3600;
        [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, resolver: $resolver, bindingAuthority: $this->bindingAuthority(), operationId: 'op-retry');
        $meta2 = $engine2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine2->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'a replay whose chain requirement is gone must be temporary_unavailable — never a ticket that outlives its chain');
        self::assertSame(PostSolveDispositionKind::ChainRequired, $store->read($challenge->nonce)?->disposition?->kind, 'the persisted disposition is untouched');
    }

// ── strict post-solve disposition decoding (all-or-nothing) ────────────────

    public function testCorruptDispositionRecordWithUnknownSchemaVersionFailsClosed(): void
    {
        $record = $this->pendingDispositionRecord();
        $record['v'] = 3;
        [$code, $store, $nonce] = $this->validateCorruptDisposition($record);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $code, 'an unknown disposition schema version must fail closed as temporary_unavailable — never a pass, never a 422');
        try {
            $store->read($nonce);
            self::fail('the strict decoder must refuse an unknown schema version');
        } catch (MalformedPostSolveDispositionException $e) {
            self::assertStringContainsString('schema version', $e->getMessage());
        }
    }

    public function testCorruptDispositionRecordWithUnknownStateFailsClosed(): void
    {
        $record = $this->pendingDispositionRecord();
        $record['state'] = 'weird';
        [$code, $store, $nonce] = $this->validateCorruptDisposition($record);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $code, 'an unknown disposition state must fail closed as temporary_unavailable — never a defaulted record');
        try {
            $store->read($nonce);
            self::fail('the strict decoder must refuse an unknown state');
        } catch (MalformedPostSolveDispositionException $e) {
            self::assertStringContainsString('state', $e->getMessage());
        }
    }

    public function testCorruptDispositionRecordWithMissingPendingOwnerFailsClosed(): void
    {
        $record = $this->pendingDispositionRecord();
        $record['owner'] = null;
        [$code, $store, $nonce] = $this->validateCorruptDisposition($record);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $code, 'a pending record without an owner must fail closed as temporary_unavailable — the claim never heals it');
        try {
            $store->read($nonce);
            self::fail('the strict decoder must refuse a pending record without an owner');
        } catch (MalformedPostSolveDispositionException $e) {
            self::assertStringContainsString('owner', $e->getMessage());
        }
    }

    public function testCorruptDispositionRecordWithMissingCompleteDispositionFailsClosed(): void
    {
        $record = $this->completeDispositionRecord();
        $record['disposition'] = null;
        [$code, $store, $nonce] = $this->validateCorruptDisposition($record);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $code, 'a complete record without a disposition must fail closed as temporary_unavailable — never a silent pass');
        try {
            $store->read($nonce);
            self::fail('the strict decoder must refuse a complete record without a disposition');
        } catch (MalformedPostSolveDispositionException $e) {
            self::assertStringContainsString('disposition', $e->getMessage());
        }
    }

    public function testCorruptDispositionRecordWithBadKindFailsClosed(): void
    {
        $record = $this->completeDispositionRecord();
        $record['disposition'] = 'not-a-disposition';
        [$code, $store, $nonce] = $this->validateCorruptDisposition($record);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $code, 'a corrupt disposition kind must fail closed as temporary_unavailable — never a Pass');
        try {
            $store->read($nonce);
            self::fail('the strict decoder must refuse a bad disposition kind');
        } catch (MalformedPostSolveDispositionException $e) {
            self::assertStringContainsString('disposition', $e->getMessage());
        }
    }

    public function testCorruptDispositionRecordWithBadChainIdShapeFailsClosed(): void
    {
        $record = $this->completeDispositionRecord();
        $record['disposition'] = new PostSolveDisposition(PostSolveDispositionKind::ChainRequired, 'decision-1', 'not a chain id!');
        [$code, $store, $nonce] = $this->validateCorruptDisposition($record);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $code, 'a malformed chain id in a ChainRequired disposition must fail closed as temporary_unavailable');
        try {
            $store->read($nonce);
            self::fail('the strict decoder must refuse a malformed chain id');
        } catch (MalformedPostSolveDispositionException $e) {
            self::assertStringContainsString('chain_id', $e->getMessage());
        }
    }

// ── the decision handle survives the disposition takeover ──────────────────

    public function testTakeoverCompletingThePassKeepsTheOriginalDecisionHandle(): void
    {
        $decisionRedis = new FakePredisClient();
        $risk = $this->riskStack(1, 'allow', 'allow', false, null, null, $decisionRedis);
        // The Array disposition store's claim consumes the mapping through
        // the shared decision map (the mirror of the gateway's decision
        // Redis, keyed by the full decision key).
        [$store, $advance] = $this->clockedDispositionStore($this->decisionMap($decisionRedis));

        $challenge = $this->issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $decisionRedis->strings['{kiwi:validator-test}:decision:'.$challenge->nonce] = (string) json_encode(['decision_id' => 'original-decision']);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;

        // request 1: the claim atomically consumes the nonce -> decision
        // mapping (getdel inside the same operation) and stores the handle
        // in the pending claim, then dies before the finalize —
        // temporary_unavailable.
        $crashed = $this->faultedStore($store, failFinalize: true);
        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $crashed, operationId: 'op-retry');
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine->validate($dto);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'a crash before the finalize is retryable temporary_unavailable');
        self::assertSame('original-decision', $store->read($challenge->nonce)?->decisionId, 'the pending claim carries the consumed decision handle');
        self::assertArrayNotHasKey('{kiwi:validator-test}:decision:'.$challenge->nonce, $decisionRedis->strings, 'the mapping is consumed in the SAME atomic operation as the claim');

        // request 2 (takeover after the lease): the new owner's getdel is
        // empty (the mapping is already consumed) — the stored handle still
        // completes the pass with the original decision id, never a fresh
        // one.
        $advance(16);
        [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, operationId: 'op-retry');
        $meta2 = $engine2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        self::assertCount(0, $engine2->validate($dto), 'the takeover completes the pass');
        $record = $store->read($challenge->nonce);
        self::assertSame('original-decision', $record?->decisionId, 'the complete record keeps the ORIGINAL decision handle');
        self::assertSame('original-decision', $record?->disposition?->decisionId, 'the completed pass keeps the ORIGINAL decision id — not a new one');
    }

    public function testChainRequirementReadFailureNeverConsumesTheDecisionMapping(): void
    {
        // THE reorder (the fallible chain requirement lookup runs before
        // the nonce -> decision consumption): a chain-backend failure must
        // never consume the decision handle — the retry re-runs the lookup
        // with the mapping intact and the final disposition completes with
        // the original decision id (never a null handle).
        $decisionRedis = new FakePredisClient();
        $stack = new RequestStack();
        $risk = $this->riskStack(1, 'allow', 'allow', false, null, null, $decisionRedis, $stack);
        [$store] = $this->clockedDispositionStore($this->decisionMap($decisionRedis));
        $inner = new ArrayChainedChallengeStateStore();
        $failing = new FailingTerminalChainStore($inner);
        $chainService = new ChainedChallengeTicketService($failing, self::SECRET, 300, 15, $this->bindingAuthority());

        $challenge = $this->issuer->issue('login', '198.51.100.7', 'auth-txn-1');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $decisionRedis->strings['{kiwi:validator-test}:decision:'.$challenge->nonce] = (string) json_encode(['decision_id' => 'decision-D']);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;

        // The verified challenge carries the server-stamped chain marker
        // (a stage-2 challenge): with chaining wired the no-reassessment
        // pass path applies — the original pre-issue decision id becomes
        // the request's current confirmation target (the contract the
        // decision handle protects).
        $metaStore = new \BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyMetadataStore();
        $metaStore->store(\KiwiCaptcha\SolutionToken::decode($token)->nonce, new \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadata(null, null, 'login', 'marker-chain', 2), 300);

        // The chain-state read throws (a backend outage): the valid solve
        // fails closed temporary_unavailable — and the decision mapping is
        // NOT consumed (the requirement lookup ran before the atomic
        // claim-with-decision).
        $failing->failObligationChainId = true;
        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, bindingAuthority: $this->bindingAuthority(), metadataStore: $metaStore, requestStack: $stack, operationId: 'op-retry');
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'a chain-state read failure is fail-closed temporary_unavailable');
        self::assertArrayHasKey('{kiwi:validator-test}:decision:'.$challenge->nonce, $decisionRedis->strings, 'the decision mapping is NOT consumed by the failed attempt');
        self::assertNull($store->read($challenge->nonce), 'no disposition state exists before the claim');
        self::assertNull($risk['gateway']->currentDecisionId(), 'no decision was confirmed for the failed attempt');

        // The backend recovers: the retry consumes the mapping atomically
        // with the claim and the final disposition confirms the original
        // decision id — never a null handle.
        $failing->failObligationChainId = false;
        [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, bindingAuthority: $this->bindingAuthority(), metadataStore: $metaStore, requestStack: $stack, operationId: 'op-retry');
        $meta2 = $engine2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        self::assertCount(0, $engine2->validate($dto), 'the retry passes after the backend recovers');
        self::assertSame('decision-D', $risk['gateway']->currentDecisionId(), 'the final disposition confirms the ORIGINAL decision id — the mapping survived the outage');
        self::assertSame('decision-D', $store->read($challenge->nonce)?->decisionId, 'the pending record carries the ORIGINAL decision id');
        self::assertArrayNotHasKey('{kiwi:validator-test}:decision:'.$challenge->nonce, $decisionRedis->strings, 'the retry consumed the mapping exactly once');
    }

    public function testArrayClaimConsumesTheDecisionMappingAtomically(): void
    {
        // THE array mirror of the atomic claim: the claim GETDELs the
        // shared decision mapping (at most one winner) and persists the
        // paired decision id in the pending record in the same operation —
        // exactly like the Redis claim Lua.
        $decisionRedis = new FakePredisClient();
        [$store] = $this->clockedDispositionStore($this->decisionMap($decisionRedis));

        $decisionRedis->strings['{kiwi:validator-test}:decision:nonce-atomic'] = (string) json_encode(['decision_id' => 'decision-atomic']);
        self::assertSame('claimed', $store->claim('nonce-atomic', 'owner-a', 305, '{kiwi:validator-test}:decision:nonce-atomic')[0]);
        self::assertArrayNotHasKey('{kiwi:validator-test}:decision:nonce-atomic', $decisionRedis->strings, 'the winning claim consumed the mapping');
        self::assertSame('decision-atomic', $store->read('nonce-atomic')?->decisionId, 'the pending record carries the decision id from the SAME atomic transition');

        // A second mapping for a concurrent claim: the loser is 'pending'
        // (busy) — its claim never touches the decision key, so the
        // mapping stays resolvable for the caller who will win the next
        // claim.
        $decisionRedis->strings['{kiwi:validator-test}:decision:nonce-race'] = (string) json_encode(['decision_id' => 'decision-first']);
        self::assertSame('claimed', $store->claim('nonce-race', 'owner-a', 305, '{kiwi:validator-test}:decision:nonce-race')[0]);
        $decisionRedis->strings['{kiwi:validator-test}:decision:nonce-race'] = (string) json_encode(['decision_id' => 'decision-second']);
        self::assertSame('pending', $store->claim('nonce-race', 'owner-b', 305, '{kiwi:validator-test}:decision:nonce-race')[0], 'the concurrent second claim is busy');
        self::assertSame('decision-first', $store->read('nonce-race')?->decisionId, 'the record keeps the first winner\'s handle');
        $loserMapping = json_decode($decisionRedis->strings['{kiwi:validator-test}:decision:nonce-race'] ?? '', true);
        self::assertIsArray($loserMapping);
        self::assertSame('decision-second', $loserMapping['decision_id'] ?? null, 'the pending-live claim NEVER consumed the mapping — it stays resolvable');

        // A complete record: a replay claim returns 'complete' and never
        // touches the decision key — the mapping inserted after the
        // finalize stays resolvable.
        $decisionRedis->strings['{kiwi:validator-test}:decision:nonce-complete'] = (string) json_encode(['decision_id' => 'decision-final']);
        self::assertSame('claimed', $store->claim('nonce-complete', 'owner-a', 305, '{kiwi:validator-test}:decision:nonce-complete')[0]);
        self::assertTrue($store->finalize('nonce-complete', 'owner-a', new PostSolveDisposition(PostSolveDispositionKind::Pass, 'decision-final')));
        $decisionRedis->strings['{kiwi:validator-test}:decision:nonce-complete'] = (string) json_encode(['decision_id' => 'decision-after-complete']);
        self::assertSame('complete', $store->claim('nonce-complete', 'owner-b', 305, '{kiwi:validator-test}:decision:nonce-complete')[0]);
        $completeMapping = json_decode($decisionRedis->strings['{kiwi:validator-test}:decision:nonce-complete'] ?? '', true);
        self::assertIsArray($completeMapping);
        self::assertSame('decision-after-complete', $completeMapping['decision_id'] ?? null, 'a complete claim NEVER consumes the decision mapping');

        // No decision map wired: the claim with a key behaves as before.
        [$plain] = $this->clockedDispositionStore();
        self::assertSame('claimed', $plain->claim('nonce-plain', 'owner-a', 305, '{kiwi:validator-test}:decision:nonce-plain')[0]);
        self::assertNull($plain->read('nonce-plain')?->decisionId);
    }

    public function testCorruptDispositionRecordWithChainRequiredMissingExpiryFailsClosed(): void
    {
        // A v2 ChainRequired disposition without its chain expiry bound is
        // malformed state — the strict v2 decoder refuses it (fail
        // closed), never a ticket.
        $record = $this->completeDispositionRecord();
        $record['v'] = 2;
        $record['disposition'] = new PostSolveDisposition(PostSolveDispositionKind::ChainRequired, 'decision-1', 'chain-xyz');
        [$code, $store, $nonce] = $this->validateCorruptDisposition($record);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $code, 'a v2 ChainRequired record without its expiry bound must fail closed as temporary_unavailable — never a ticket');
        try {
            $store->read($nonce);
            self::fail('the strict decoder must refuse a v2 ChainRequired record without its expiry bound');
        } catch (MalformedPostSolveDispositionException $e) {
            self::assertStringContainsString('chain expiry', $e->getMessage());
        }
    }

    public function testLegacyV1ChainRequiredRecordSignsFromTheExactChain(): void
    {
        // A legacy v1 ChainRequired record (the shape written by the
        // earlier store generation — a null carried expiry) is NOT
        // corrupt: the reader accepts it and the signing falls back to
        // the exact chain X record's server-held expiresAt — never the
        // current obligation Y.
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(1, 'allow', 'allow', false, null, $resolver);
        [$store] = $this->clockedDispositionStore();

        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = new ChainedChallengeTicketService($chainStore, self::SECRET, 300, 15, $this->bindingAuthority());
        $chainX = $chainService->requireStage2(base64_encode(random_bytes(32)), 'login', 'auth-txn-1', 1, RiskAction::Argon32, time() + 300);

        $challenge = $this->issuer->issue('login', '198.51.100.7', 'auth-txn-1');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $nonce = \KiwiCaptcha\SolutionToken::decode($token)->nonce;
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;

        // Seed the legacy v1 record (no carried expiry).
        $record = $this->completeDispositionRecord();
        $record['v'] = 1;
        $record['decisionId'] = 'decision-legacy';
        $record['disposition'] = new PostSolveDisposition(PostSolveDispositionKind::ChainRequired, 'decision-legacy', $chainX->chainId);
        $this->injectDispositionRecord($store, $nonce, $record);

        // The reader accepts it with a null carried expiry.
        $read = $store->read($nonce);
        self::assertNotNull($read);
        self::assertSame($chainX->chainId, $read->disposition?->chainId);
        self::assertNull($read->disposition?->chainExpiresAt, 'a legacy v1 record carries no expiry bound — not corrupt');

        // The signing takes the expiry from the exact chain X's record
        // (via requirementFor).
        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, resolver: $resolver, bindingAuthority: $this->bindingAuthority(), operationId: 'op-retry');
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode(), 'a legacy v1 ChainRequired record is accepted — never temporary_unavailable');
        $ticket = $violations[0]->getParameters()['{{ chain_ticket }}'] ?? null;
        self::assertIsString($ticket);
        $payload = $chainService->verify($ticket);
        self::assertIsArray($payload);
        self::assertSame($chainX->chainId, (string) $payload['chainId'], 'the legacy record signs the EXACT chain X');
        self::assertSame($chainX->expiresAt, (int) $payload['expiresAt'], 'the legacy record signs X\'s server-held expiry (requirementFor(X))');

        // never consults the current obligation Y: X's stage-2 challenge
        // verifies (the obligation is cleared, the chain record retained)
        // and a fresh chain Y opens for the same transaction — the ticket
        // stays byte-identical (X, X.expiresAt).
        $stage2Nonce = base64_encode(hash('sha256', 'stage2-legacy', true));
        self::assertSame(ChainReservationResult::Available, $chainService->reserveStage2($chainX->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $chainService->markIssued($chainX->chainId, 'owner-a', $stage2Nonce));
        self::assertSame(ChainVerifiedResult::VerifiedNew, $chainService->markVerified($chainX->chainId, $stage2Nonce));
        self::assertNull($chainService->findOpenRequirement('login', 'auth-txn-1', 1), 'X\'s obligation is cleared');
        $chainY = $chainService->requireStage2(base64_encode(random_bytes(32)), 'login', 'auth-txn-1', 1, RiskAction::Argon64, time() + 600);
        self::assertNotSame($chainX->chainId, $chainY->chainId, 'the cleared obligation opens a FRESH chain');
        self::assertSame($chainY->chainId, $chainService->findOpenRequirement('login', 'auth-txn-1', 1)?->chainId, 'Y now owns the transaction obligation');

        [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, resolver: $resolver, bindingAuthority: $this->bindingAuthority(), operationId: 'op-retry');
        $meta2 = $engine2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine2->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $ticket2 = $violations[0]->getParameters()['{{ chain_ticket }}'] ?? null;
        self::assertIsString($ticket2);
        self::assertSame($ticket, $ticket2, 'the legacy-record ticket stays byte-identical with a concurrent chain Y open');
        $payload2 = $chainService->verify($ticket2);
        self::assertIsArray($payload2);
        self::assertSame($chainX->chainId, (string) $payload2['chainId'], 'the signing stays bound to the disposition\'s exact chain — never Y');
        self::assertSame($chainX->expiresAt, (int) $payload2['expiresAt'], 'the signed expiry is X\'s server-held bound — never Y\'s');
        self::assertNotSame($chainY->expiresAt, (int) $payload2['expiresAt'], 'Y\'s expiry must never leak into X\'s ticket');
    }

    public function testChainRequiredSigningWithMismatchedCarriedExpiryFailsClosed(): void
    {
        // A shape-valid chain_expires_at that differs from the exact
        // chain record's server-held expiresAt is corrupt state — the
        // signing fails closed temporary_unavailable, never a ticket that
        // outlives (or expires early vs) its chain. The matching value
        // signs normally.
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(1, 'allow', 'allow', false, null, $resolver);
        [$store] = $this->clockedDispositionStore();

        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = new ChainedChallengeTicketService($chainStore, self::SECRET, 300, 15, $this->bindingAuthority());
        $chainX = $chainService->requireStage2(base64_encode(random_bytes(32)), 'login', 'auth-txn-1', 1, RiskAction::Argon32, time() + 300);

        $challenge = $this->issuer->issue('login', '198.51.100.7', 'auth-txn-1');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $nonce = \KiwiCaptcha\SolutionToken::decode($token)->nonce;
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;

        $record = $this->completeDispositionRecord();
        $record['v'] = 2;
        $record['decisionId'] = 'decision-1';
        $record['disposition'] = new PostSolveDisposition(PostSolveDispositionKind::ChainRequired, 'decision-1', $chainX->chainId, $chainX->expiresAt + 1000);
        $this->injectDispositionRecord($store, $nonce, $record);

        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, resolver: $resolver, bindingAuthority: $this->bindingAuthority(), operationId: 'op-retry');
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'a mismatched carried expiry must fail closed — never a ticket');
        self::assertArrayNotHasKey('{{ chain_ticket }}', $violations[0]->getParameters(), 'no ticket is produced for the mismatched bound');

        // The matching value signs normally with the exact chain's bound.
        $record['disposition'] = new PostSolveDisposition(PostSolveDispositionKind::ChainRequired, 'decision-1', $chainX->chainId, $chainX->expiresAt);
        $this->injectDispositionRecord($store, $nonce, $record);
        [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, resolver: $resolver, bindingAuthority: $this->bindingAuthority(), operationId: 'op-retry');
        $meta2 = $engine2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine2->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode(), 'the matching carried expiry signs normally');
        $ticket = $violations[0]->getParameters()['{{ chain_ticket }}'] ?? null;
        self::assertIsString($ticket);
        $payload = $chainService->verify($ticket);
        self::assertIsArray($payload);
        self::assertSame($chainX->chainId, (string) $payload['chainId']);
        self::assertSame($chainX->expiresAt, (int) $payload['expiresAt'], 'the ticket signs the exact chain record\'s bound');
    }

    public function testChainRequiredDispositionSurvivesTokenExpiryForTheRetainedMargin(): void
    {
        // short token lifetime (2 s) + the retained margin (5 s): the
        // disposition record (TTL = Config::MAX_TTL_secs + margin = 305 s)
        // must outlive the token AND the retained consumed core result
        // (token lifetime + the same margin = 7 s) — the disposition never
        // dies while the core result could still be replayed.
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 2), $storage);
        $verifier = new Verifier($storage);
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(1, 'allow', 'allow', false, null, $resolver);
        $risk['store']->setVector(SignalVector::fromArray(self::ARGON32_VECTOR));
        [$store, $advance] = $this->clockedDispositionStore();

        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = new ChainedChallengeTicketService($chainStore, self::SECRET, 300, 15, $this->bindingAuthority());

        $challenge = $issuer->issue('login', '198.51.100.7', 'auth-txn-1');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $nonce = \KiwiCaptcha\SolutionToken::decode($token)->nonce;
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;

        [$engine] = $this->dispositionEngine($verifier, $risk['gateway'], $store, ttlMargin: 5, chainTickets: $chainService, resolver: $resolver, bindingAuthority: $this->bindingAuthority(), operationId: 'op-123');
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $chainId = $store->read($nonce)?->disposition?->chainId;
        self::assertIsString($chainId);

        // The token expires (2 s TTL) while the retained consumed result
        // and the disposition stay alive (token lifetime + margin).
        sleep(3);

        // The disposition survives the normal token expiry: the record is
        // still complete with the same chain id.
        $record = $store->read($nonce);
        self::assertNotNull($record, 'the disposition must survive the token expiry');
        self::assertSame('complete', $record->state);
        self::assertSame($chainId, $record->disposition?->chainId, 'the survived disposition keeps the SAME chain id');

        // The expired token replayed by the exact same logical operation
        // (the validator derives the operation identity from the scope,
        // the authoritative transaction binding and the explicit
        // kiwi_operation_id, so the retry carries the same identity as the
        // original solve) reproduces the retained deterministic outcome:
        // the core's committed result is expiry-exempt — it was durably
        // recorded only after the original final expiry check passed —
        // and the disposition replay contract returns the same
        // chain_required. The protected action is refused (never a pass,
        // never a fresh assessment), and the persisted disposition is
        // untouched.
        [$engine2] = $this->dispositionEngine($verifier, $risk['gateway'], $store, ttlMargin: 5, chainTickets: $chainService, resolver: $resolver, bindingAuthority: $this->bindingAuthority(), operationId: 'op-123');
        $meta2 = $engine2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine2->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode(), 'the identity-proven expired replay reproduces the retained chain_required disposition — never a pass');
        self::assertSame(1, \count($risk['store']->observations), 'the stored-result replay must not reassess');
        self::assertSame($chainId, $store->read($nonce)?->disposition?->chainId, 'the replayed disposition keeps the SAME chain id');

        // The disposition outlives the retained core-result window (token
        // lifetime + margin = 7 s): still complete past it, expiring only
        // with its own TTL (MAX_TTL_secs + margin = 305 s).
        $advance(8);
        self::assertSame('complete', $store->read($nonce)?->state, 'the disposition survives the retained core-result window');
        $advance(305);
        self::assertNull($store->read($nonce), 'the disposition expires only with its own record TTL (MAX_TTL_SECS + margin)');
    }

    // ── Stage-2 final disposition -> terminal chain transition ─────────

    /**
     * A full stage-2 chain for the validator-level disposition tests: the
     * stage-1 chain_required solve opens the chain, then the chain is
     * issued directly (reserve + markIssued) with the nonce of a real
     * issued challenge.
     *
     * @return array{chainService: ChainedChallengeTicketService, chainId: string, stage2: \KiwiCaptcha\Challenge, token1: string}
     */
    private function stage2Chain(RiskGateway $gateway, \BelConsulting\KiwiCaptchaBundle\Risk\ArrayPostSolveDispositionStore $store, \BelConsulting\KiwiCaptchaBundle\Risk\ArrayChainedChallengeStateStore $chainStore): array
    {
        $chainService = new ChainedChallengeTicketService($chainStore, self::SECRET, 300, 15, $this->bindingAuthority());

        // Stage 1: the reassessment (Argon32) opens the chain.
        $challenge1 = $this->issuer->issue('login', '198.51.100.7', 'auth-txn-1');
        usleep(($challenge1->minDurationMs + 10) * 1000);
        $token1 = $this->solveToken($challenge1->prefix, $challenge1->salt, $challenge1->targetBits, $challenge1->nonce);
        $dto1 = new class {
            public ?string $captcha = null;
        };
        $dto1->captcha = $token1;
        [$engine1] = $this->dispositionEngine($this->verifier, $gateway, $store, chainTickets: $chainService, bindingAuthority: $this->bindingAuthority());
        $meta1 = $engine1->getMetadataFor($dto1::class);
        $meta1->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine1->validate($dto1);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $chainId = (string) $chainService->verify((string) $violations[0]->getParameters()['{{ chain_ticket }}'])['chainId'];

        // Stage 2: the chain issues a real challenge (its nonce becomes
        // the chain's stage2Nonce).
        $stage2 = $this->issuer->issue('login', '198.51.100.7', 'auth-txn-1');
        self::assertSame(ChainReservationResult::Available, $chainService->reserveStage2($chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $chainService->markIssued($chainId, 'owner-a', $stage2->nonce));

        return ['chainService' => $chainService, 'chainId' => $chainId, 'stage2' => $stage2, 'token1' => $token1];
    }

    public function testStage2StepUpDispositionMarksStepUpRequiredAndTheObligationSurvives(): void
    {
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(1, 'allow', 'allow', false, null, $resolver);
        $risk['store']->setVector(SignalVector::fromArray(self::ARGON32_VECTOR));
        [$store] = $this->clockedDispositionStore();
        $chainStore = new ArrayChainedChallengeStateStore();
        $stage2 = $this->stage2Chain($risk['gateway'], $store, $chainStore);

        // The stage-2 solve with a step-up post-solve decision: the final
        // disposition is step-up — the chain transitions to the terminal
        // step_up_required (the obligation is kept) and the application
        // sees the terminal step-up violation.
        $risk['store']->setVector(SignalVector::fromArray(self::STEP_UP_VECTOR));
        usleep(($stage2['stage2']->minDurationMs + 10) * 1000);
        $token2 = $this->solveToken($stage2['stage2']->prefix, $stage2['stage2']->salt, $stage2['stage2']->targetBits, $stage2['stage2']->nonce);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token2;
        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $stage2['chainService'], bindingAuthority: $this->bindingAuthority());
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine->validate($dto);

        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations[0]->getCode(), 'a stage-2 solve with a StepUp post-solve decision is terminal step-up');
        self::assertSame(PostSolveDispositionKind::StepUp, $store->read($stage2['stage2']->nonce)?->disposition?->kind, 'the StepUp disposition is durably finalized BEFORE the chain transition');
        $state = $stage2['chainService']->requirementFor($stage2['chainId']);
        self::assertSame('step_up_required', $state?->state, 'the chain is TERMINAL step_up_required');
        self::assertSame($stage2['stage2']->nonce, $state?->stage2Nonce);
        self::assertNotNull($stage2['chainService']->findOpenRequirement('login', 'auth-txn-1', 1), 'the step-up transition KEEPS the obligation — the transaction stays bound');
    }

    public function testStage2DenyDispositionMarksDeniedAndTheObligationSurvives(): void
    {
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(1, 'allow', 'allow', false, null, $resolver);
        $risk['store']->setVector(SignalVector::fromArray(self::ARGON32_VECTOR));
        [$store] = $this->clockedDispositionStore();
        $chainStore = new ArrayChainedChallengeStateStore();
        $stage2 = $this->stage2Chain($risk['gateway'], $store, $chainStore);

        // The stage-2 solve with a deny post-solve decision: the final
        // disposition is deny — the chain transitions to the terminal
        // denied (the obligation is kept) and the application sees the
        // post-solve rejection.
        $risk['store']->setVector(SignalVector::fromArray(['network_risk' => 900]));
        usleep(($stage2['stage2']->minDurationMs + 10) * 1000);
        $token2 = $this->solveToken($stage2['stage2']->prefix, $stage2['stage2']->salt, $stage2['stage2']->targetBits, $stage2['stage2']->nonce);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token2;
        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $stage2['chainService'], bindingAuthority: $this->bindingAuthority());
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine->validate($dto);

        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violations[0]->getCode(), 'a stage-2 solve with a Deny post-solve decision is rejected');
        self::assertSame(PostSolveDispositionKind::Deny, $store->read($stage2['stage2']->nonce)?->disposition?->kind, 'the Deny disposition is durably finalized BEFORE the chain transition');
        $state = $stage2['chainService']->requirementFor($stage2['chainId']);
        self::assertSame('denied', $state?->state, 'the chain is TERMINAL denied');
        self::assertSame($stage2['stage2']->nonce, $state?->stage2Nonce);
        self::assertNotNull($stage2['chainService']->findOpenRequirement('login', 'auth-txn-1', 1), 'the denied transition KEEPS the obligation — the transaction stays bound');
    }

    public function testStage2PassDispositionMarksVerifiedAndDeletesTheObligation(): void
    {
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(1, 'allow', 'allow', false, null, $resolver);
        $risk['store']->setVector(SignalVector::fromArray(self::ARGON32_VECTOR));
        [$store] = $this->clockedDispositionStore();
        $chainStore = new ArrayChainedChallengeStateStore();
        $stage2 = $this->stage2Chain($risk['gateway'], $store, $chainStore);

        // The stage-2 solve with a neutral post-solve decision (a fresh
        // risk stack — a fresh scope-action hysteresis — so the neutral
        // assessment is actually neutral): the final disposition is pass —
        // the chain verifies (the obligation is deleted) and the solve
        // passes.
        $neutral = $this->riskStack(1, 'allow', 'allow', false, null, $resolver);
        usleep(($stage2['stage2']->minDurationMs + 10) * 1000);
        $token2 = $this->solveToken($stage2['stage2']->prefix, $stage2['stage2']->salt, $stage2['stage2']->targetBits, $stage2['stage2']->nonce);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token2;
        [$engine] = $this->dispositionEngine($this->verifier, $neutral['gateway'], $store, chainTickets: $stage2['chainService'], bindingAuthority: $this->bindingAuthority());
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine->validate($dto);

        self::assertCount(0, $violations, 'a stage-2 solve with a Pass disposition passes');
        self::assertSame(PostSolveDispositionKind::Pass, $store->read($stage2['stage2']->nonce)?->disposition?->kind, 'the Pass disposition is durably finalized BEFORE the chain transition');
        $state = $stage2['chainService']->requirementFor($stage2['chainId']);
        self::assertSame('verified', $state?->state, 'the chain is TERMINAL verified');
        self::assertSame($stage2['stage2']->nonce, $state?->stage2Nonce);
        self::assertNull($stage2['chainService']->findOpenRequirement('login', 'auth-txn-1', 1), 'the verified transition DELETED the obligation — the transaction is complete');
    }

    public function testStage2NoReassessmentPassStillEndsTheChain(): void
    {
        // The asymmetric path: a stage-2 challenge verified with
        // post_solve_check=false AND no honeypot AND no chain-eligible
        // scope (the metadata chainId marker forbids a third stage) — the
        // Pass disposition is produced without any reassessment, yet the
        // recognized stage-2 nonce still performs the stage-2 transition
        // (markVerified — the chain ends, the obligation is deleted).
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(1, 'allow', 'allow', false, null, $resolver);
        $risk['store']->setVector(SignalVector::fromArray(self::ARGON32_VECTOR));
        [$store] = $this->clockedDispositionStore();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = new ChainedChallengeTicketService($chainStore, self::SECRET, 300, 15, $this->bindingAuthority());
        $metaStore = new \BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyMetadataStore();

        // Stage 1: the reassessment (Argon32) opens the chain.
        $challenge1 = $this->issuer->issue('login', '198.51.100.7', 'auth-txn-1');
        usleep(($challenge1->minDurationMs + 10) * 1000);
        $token1 = $this->solveToken($challenge1->prefix, $challenge1->salt, $challenge1->targetBits, $challenge1->nonce);
        $dto1 = new class {
            public ?string $captcha = null;
        };
        $dto1->captcha = $token1;
        [$engine1] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, bindingAuthority: $this->bindingAuthority());
        $meta1 = $engine1->getMetadataFor($dto1::class);
        $meta1->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine1->validate($dto1);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $chainId = (string) $chainService->verify((string) $violations[0]->getParameters()['{{ chain_ticket }}'])['chainId'];

        // Stage 2: the chain issues a real challenge (its nonce becomes
        // the chain's stage2Nonce), and the chain identity is stamped into
        // the metadata sidecar exactly as the controller does — the
        // marker ends the chain at stage 2 (no third-stage eligibility).
        $stage2 = $this->issuer->issue('login', '198.51.100.7', 'auth-txn-1');
        self::assertSame(ChainReservationResult::Available, $chainService->reserveStage2($chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $chainService->markIssued($chainId, 'owner-a', $stage2->nonce));
        $metaStore->store($stage2->nonce, new \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadata(null, null, 'login', $chainId, 2), 300);

        // The stage-2 solve: NO reassessment runs (post_solve_check=false,
        // no honeypot, no chain-eligible scope — the marker) — the final
        // disposition is the plain Pass, and the recognized stage-2 nonce
        // still ends the chain (markVerified, obligation deleted).
        usleep(($stage2->minDurationMs + 10) * 1000);
        $token2 = $this->solveToken($stage2->prefix, $stage2->salt, $stage2->targetBits, $stage2->nonce);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token2;
        [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, bindingAuthority: $this->bindingAuthority(), metadataStore: $metaStore);
        $meta2 = $engine2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations2 = $engine2->validate($dto);

        self::assertCount(0, $violations2, 'the no-reassessment stage-2 solve passes');
        self::assertSame(PostSolveDispositionKind::Pass, $store->read($stage2->nonce)?->disposition?->kind, 'the Pass disposition is durably finalized');
        $state = $chainService->requirementFor($chainId);
        self::assertSame('verified', $state?->state, 'the no-reassessment PASS still performs the stage-2 transition — the chain ends');
        self::assertSame($stage2->nonce, $state?->stage2Nonce);
        self::assertNull($chainService->findOpenRequirement('login', 'auth-txn-1', 1), 'the verified transition deleted the obligation — the transaction is complete');
    }

    public function testStage2TransitionFailureIsTemporaryUnavailableNeverPass(): void
    {
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(1, 'allow', 'allow', false, null, $resolver);
        $risk['store']->setVector(SignalVector::fromArray(self::ARGON32_VECTOR));
        [$store] = $this->clockedDispositionStore();
        $inner = new ArrayChainedChallengeStateStore();
        $stage2 = $this->stage2Chain($risk['gateway'], $store, $inner);

        // The terminal transition fails (a store outage on the step-up
        // transition): the disposition is durably finalized, but the chain
        // cannot transition — fail-closed temporary_unavailable, never a
        // silent pass while the obligation may be uncleared.
        $failing = new FailingTerminalChainStore($inner);
        $failing->failStepUpRequired = true;
        $failingService = new ChainedChallengeTicketService($failing, self::SECRET, 300, 15, $this->bindingAuthority());
        $risk['store']->setVector(SignalVector::fromArray(self::STEP_UP_VECTOR));
        usleep(($stage2['stage2']->minDurationMs + 10) * 1000);
        $token2 = $this->solveToken($stage2['stage2']->prefix, $stage2['stage2']->salt, $stage2['stage2']->targetBits, $stage2['stage2']->nonce);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token2;
        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $failingService, bindingAuthority: $this->bindingAuthority(), operationId: 'op-retry');
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine->validate($dto);

        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'a failed stage-2 chain transition is fail-closed temporary_unavailable');
        self::assertSame(PostSolveDispositionKind::StepUp, $store->read($stage2['stage2']->nonce)?->disposition?->kind, 'the disposition stays durably finalized');
        self::assertSame('issued', $inner->read($stage2['chainId'])['state'], 'the chain stays issued — the obligation is never cleared without the transition');

        // The transition recovers: the retry completes the terminal
        // step-up.
        $failing->failStepUpRequired = false;
        [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $failingService, bindingAuthority: $this->bindingAuthority(), operationId: 'op-retry');
        $meta2 = $engine2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations2 = $engine2->validate($dto);
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations2[0]->getCode(), 'after the store recovers the retry completes the terminal step-up');
        self::assertSame('step_up_required', $inner->read($stage2['chainId'])['state']);
    }

    public function testFreshDenyOnAnOpenObligationTerminalizesTheChain(): void
    {
        // The durability invariant at the validator level: token A opens
        // the chain (Argon32); token B — a different stage-1 token of the
        // same transaction — gets a fresh deny: the solve is denied AND
        // the open obligation is terminalized (the chain becomes
        // terminal denied with NO stage-2 nonce, the obligation mapping
        // kept — the denial is durable, keyed by the chain identity); a
        // later neutral token of the same transaction still receives the
        // terminal denial — never chain_required, never Pass.
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(1, 'allow', 'allow', false, null, $resolver);
        [$store] = $this->clockedDispositionStore();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = new ChainedChallengeTicketService($chainStore, self::SECRET, 300, 15, $this->bindingAuthority());

        // Token A: the reassessment (Argon32) opens the chain.
        $risk['store']->setVector(SignalVector::fromArray(self::ARGON32_VECTOR));
        $challengeA = $this->issuer->issue('login', '198.51.100.7', 'auth-txn-1');
        usleep(($challengeA->minDurationMs + 10) * 1000);
        $tokenA = $this->solveToken($challengeA->prefix, $challengeA->salt, $challengeA->targetBits, $challengeA->nonce);
        $dtoA = new class {
            public ?string $captcha = null;
        };
        $dtoA->captcha = $tokenA;
        [$engineA] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, bindingAuthority: $this->bindingAuthority());
        $metaA = $engineA->getMetadataFor($dtoA::class);
        $metaA->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violationsA = $engineA->validate($dtoA);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violationsA[0]->getCode());
        $chainId = (string) $chainService->verify((string) $violationsA[0]->getParameters()['{{ chain_ticket }}'])['chainId'];

        // Token B: a fresh deny — the terminal rejection AND the durable
        // terminalization of the open obligation (the disposition is
        // durably finalized first).
        $risk['store']->setVector(SignalVector::fromArray(['network_risk' => 900]));
        $challengeB = $this->issuer->issue('login', '198.51.100.7', 'auth-txn-1');
        usleep(($challengeB->minDurationMs + 10) * 1000);
        $tokenB = $this->solveToken($challengeB->prefix, $challengeB->salt, $challengeB->targetBits, $challengeB->nonce);
        $dtoB = new class {
            public ?string $captcha = null;
        };
        $dtoB->captcha = $tokenB;
        [$engineB] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, bindingAuthority: $this->bindingAuthority());
        $metaB = $engineB->getMetadataFor($dtoB::class);
        $metaB->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violationsB = $engineB->validate($dtoB);
        self::assertCount(1, $violationsB);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violationsB[0]->getCode(), 'B\'s fresh Deny over the open obligation is the terminal rejection');
        self::assertSame(PostSolveDispositionKind::Deny, $store->read($challengeB->nonce)?->disposition?->kind, 'the Deny disposition is durably finalized');
        $state = $chainService->requirementFor($chainId);
        self::assertSame('denied', $state?->state, 'the fresh Deny TERMINALIZES the open obligation');
        self::assertNull($state?->stage2Nonce, 'no stage-2 nonce exists — the terminality is keyed by the chain identity alone');
        self::assertNotNull($chainService->findOpenRequirement('login', 'auth-txn-1', 1), 'the denied transition KEEPS the obligation — the transaction stays bound');

        // Token C: a neutral assessment — still the terminal denial
        // (never chain_required, never Pass); the chain stays denied.
        $neutral = $this->riskStack(1, 'allow', 'allow', false, null, $resolver);
        $challengeC = $this->issuer->issue('login', '198.51.100.7', 'auth-txn-1');
        usleep(($challengeC->minDurationMs + 10) * 1000);
        $tokenC = $this->solveToken($challengeC->prefix, $challengeC->salt, $challengeC->targetBits, $challengeC->nonce);
        $dtoC = new class {
            public ?string $captcha = null;
        };
        $dtoC->captcha = $tokenC;
        [$engineC] = $this->dispositionEngine($this->verifier, $neutral['gateway'], $store, chainTickets: $chainService, bindingAuthority: $this->bindingAuthority());
        $metaC = $engineC->getMetadataFor($dtoC::class);
        $metaC->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violationsC = $engineC->validate($dtoC);
        self::assertCount(1, $violationsC, 'a later token of the denied transaction must never pass');
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violationsC[0]->getCode(), 'the durable terminal denial wins — never CHAIN_REQUIRED, never Pass');
        self::assertArrayNotHasKey('{{ chain_ticket }}', $violationsC[0]->getParameters());
        self::assertSame('denied', $chainService->requirementFor($chainId)?->state, 'the chain stays denied');
    }

    public function testFreshStepUpOnAnOpenObligationTerminalizesTheChain(): void
    {
        // The StepUp mirror: token A opens the chain; token B — a
        // different stage-1 token — gets a fresh step-up: the terminal
        // step-up violation AND the durable terminalization of the open
        // obligation (step_up_required, obligation mapping kept); a
        // later neutral token still receives the terminal step-up.
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(1, 'allow', 'allow', false, null, $resolver);
        [$store] = $this->clockedDispositionStore();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = new ChainedChallengeTicketService($chainStore, self::SECRET, 300, 15, $this->bindingAuthority());

        // Token A: the reassessment (Argon32) opens the chain.
        $risk['store']->setVector(SignalVector::fromArray(self::ARGON32_VECTOR));
        $challengeA = $this->issuer->issue('login', '198.51.100.7', 'auth-txn-1');
        usleep(($challengeA->minDurationMs + 10) * 1000);
        $tokenA = $this->solveToken($challengeA->prefix, $challengeA->salt, $challengeA->targetBits, $challengeA->nonce);
        $dtoA = new class {
            public ?string $captcha = null;
        };
        $dtoA->captcha = $tokenA;
        [$engineA] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, bindingAuthority: $this->bindingAuthority());
        $metaA = $engineA->getMetadataFor($dtoA::class);
        $metaA->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violationsA = $engineA->validate($dtoA);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violationsA[0]->getCode());
        $chainId = (string) $chainService->verify((string) $violationsA[0]->getParameters()['{{ chain_ticket }}'])['chainId'];

        // Token B: a fresh step-up — the terminal step-up AND the durable
        // terminalization of the open obligation.
        $risk['store']->setVector(SignalVector::fromArray(self::STEP_UP_VECTOR));
        $challengeB = $this->issuer->issue('login', '198.51.100.7', 'auth-txn-1');
        usleep(($challengeB->minDurationMs + 10) * 1000);
        $tokenB = $this->solveToken($challengeB->prefix, $challengeB->salt, $challengeB->targetBits, $challengeB->nonce);
        $dtoB = new class {
            public ?string $captcha = null;
        };
        $dtoB->captcha = $tokenB;
        [$engineB] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, bindingAuthority: $this->bindingAuthority());
        $metaB = $engineB->getMetadataFor($dtoB::class);
        $metaB->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violationsB = $engineB->validate($dtoB);
        self::assertCount(1, $violationsB);
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violationsB[0]->getCode(), 'B\'s fresh StepUp over the open obligation is the terminal step-up');
        self::assertSame(PostSolveDispositionKind::StepUp, $store->read($challengeB->nonce)?->disposition?->kind, 'the StepUp disposition is durably finalized');
        $state = $chainService->requirementFor($chainId);
        self::assertSame('step_up_required', $state?->state, 'the fresh StepUp TERMINALIZES the open obligation');
        self::assertNull($state?->stage2Nonce, 'no stage-2 nonce exists — the terminality is keyed by the chain identity alone');
        self::assertNotNull($chainService->findOpenRequirement('login', 'auth-txn-1', 1), 'the step-up transition KEEPS the obligation — the transaction stays bound');

        // Token C: a neutral assessment — still the terminal step-up
        // (never chain_required, never Pass); the chain stays
        // step_up_required.
        $neutral = $this->riskStack(1, 'allow', 'allow', false, null, $resolver);
        $challengeC = $this->issuer->issue('login', '198.51.100.7', 'auth-txn-1');
        usleep(($challengeC->minDurationMs + 10) * 1000);
        $tokenC = $this->solveToken($challengeC->prefix, $challengeC->salt, $challengeC->targetBits, $challengeC->nonce);
        $dtoC = new class {
            public ?string $captcha = null;
        };
        $dtoC->captcha = $tokenC;
        [$engineC] = $this->dispositionEngine($this->verifier, $neutral['gateway'], $store, chainTickets: $chainService, bindingAuthority: $this->bindingAuthority());
        $metaC = $engineC->getMetadataFor($dtoC::class);
        $metaC->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violationsC = $engineC->validate($dtoC);
        self::assertCount(1, $violationsC, 'a later token of the step-up transaction must never pass');
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violationsC[0]->getCode(), 'the durable terminal step-up wins — never CHAIN_REQUIRED, never Pass');
        self::assertArrayNotHasKey('{{ chain_ticket }}', $violationsC[0]->getParameters());
        self::assertSame('step_up_required', $chainService->requirementFor($chainId)?->state, 'the chain stays step_up_required');
    }

    public function testFreshDenyTerminalizationFailureIsTemporaryUnavailable(): void
    {
        // The terminalization of the open obligation fails (a store
        // outage): the solve must NOT get the bare denial — fail closed
        // with the temporary_unavailable violation (never a Deny without
        // the durable transaction terminality), the disposition is never
        // finalized, and the chain stays available. After the store
        // recovers the retry completes the terminalization and the
        // denial.
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(1, 'allow', 'allow', false, null, $resolver);
        [$store, $advance] = $this->clockedDispositionStore();
        $inner = new ArrayChainedChallengeStateStore();
        $failing = new FailingTerminalChainStore($inner);
        $chainService = new ChainedChallengeTicketService($failing, self::SECRET, 300, 15, $this->bindingAuthority());

        // Token A opens the chain (the create path delegates cleanly).
        $risk['store']->setVector(SignalVector::fromArray(self::ARGON32_VECTOR));
        $challengeA = $this->issuer->issue('login', '198.51.100.7', 'auth-txn-1');
        usleep(($challengeA->minDurationMs + 10) * 1000);
        $tokenA = $this->solveToken($challengeA->prefix, $challengeA->salt, $challengeA->targetBits, $challengeA->nonce);
        $dtoA = new class {
            public ?string $captcha = null;
        };
        $dtoA->captcha = $tokenA;
        [$engineA] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, bindingAuthority: $this->bindingAuthority(), operationId: 'op-retry');
        $metaA = $engineA->getMetadataFor($dtoA::class);
        $metaA->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violationsA = $engineA->validate($dtoA);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violationsA[0]->getCode());
        $chainId = (string) $chainService->verify((string) $violationsA[0]->getParameters()['{{ chain_ticket }}'])['chainId'];

        // Token B: a fresh deny whose terminalization fails — fail
        // closed temporary_unavailable; the chain stays available and
        // the disposition is never finalized.
        $risk['store']->setVector(SignalVector::fromArray(['network_risk' => 900]));
        $challengeB = $this->issuer->issue('login', '198.51.100.7', 'auth-txn-1');
        usleep(($challengeB->minDurationMs + 10) * 1000);
        $tokenB = $this->solveToken($challengeB->prefix, $challengeB->salt, $challengeB->targetBits, $challengeB->nonce);
        $dtoB = new class {
            public ?string $captcha = null;
        };
        $dtoB->captcha = $tokenB;
        $failing->failTransactionDenied = true;
        [$engineB] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, bindingAuthority: $this->bindingAuthority(), operationId: 'op-retry');
        $metaB = $engineB->getMetadataFor($dtoB::class);
        $metaB->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violationsB = $engineB->validate($dtoB);
        self::assertCount(1, $violationsB);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violationsB[0]->getCode(), 'a failed chain terminalization is fail-closed temporary_unavailable');
        self::assertSame('available', $inner->read($chainId)['state'], 'the chain is untouched by the failed terminalization');
        self::assertNull($store->read($challengeB->nonce)?->disposition, 'the Deny disposition is never finalized — no bare denial without durable terminality');

        // The store recovers (and the failed claim lease expired): the
        // retry completes the terminalization and the denial.
        $advance(16);
        $failing->failTransactionDenied = false;
        [$engineB2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, bindingAuthority: $this->bindingAuthority(), operationId: 'op-retry');
        $metaB2 = $engineB2->getMetadataFor($dtoB::class);
        $metaB2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violationsB2 = $engineB2->validate($dtoB);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violationsB2[0]->getCode(), 'after the store recovers the retry completes the terminalization and the denial');
        self::assertSame('denied', $inner->read($chainId)['state'], 'the chain is TERMINAL denied after the recovery');
    }

    // ── Terminal transaction state dominates the exact stage-2 nonce ────

    public function testTerminalTransactionStateDominatesTheExactStage2NonceAcrossEveryAssessment(): void
    {
        // THE regression matrix: a chain issued(S) whose transaction is
        // already terminal (denied / step_up_required — a different token
        // of the same transaction terminalized it, the exact stage-2
        // nonce preserved) dominates the submission of the exact stage-2
        // nonce S under every assessment: no reassessment
        // (post_solve_check=false + the chain marker), Allow, weaker PoW,
        // stronger PoW and the opposite terminal assessment (a fresh
        // StepUp on a denied chain / a fresh Deny on a step_up_required
        // chain). The terminal disposition wins — never Pass, never the
        // stage-2 transition conflict (503) — and S's nonce disposition
        // is persisted AS THE terminal kind, so the replay of S
        // reproduces the same terminal result (never Pass, never 503).
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $rows = [
            'denied + no reassessment' => ['denied', 'none'],
            'denied + Allow' => ['denied', 'allow'],
            'denied + weaker PoW' => ['denied', 'weaker'],
            'denied + fresh StepUp' => ['denied', 'stepup'],
            'step_up_required + no reassessment' => ['step_up_required', 'none'],
            'step_up_required + Allow' => ['step_up_required', 'allow'],
            'step_up_required + weaker PoW' => ['step_up_required', 'weaker'],
            'step_up_required + stronger PoW' => ['step_up_required', 'stronger'],
        ];
        $vectors = [
            'allow' => null,
            'weaker' => ['replay' => 400],
            'stronger' => self::ARGON32_VECTOR,
            'stepup' => self::STEP_UP_VECTOR,
        ];
        foreach ($rows as $label => [$terminal, $assessment]) {
            $risk = $this->riskStack(1, 'allow', 'allow', $assessment !== 'none', null, $resolver);
            $risk['store']->setVector(SignalVector::fromArray(self::ARGON32_VECTOR));
            [$store] = $this->clockedDispositionStore();
            $chainStore = new ArrayChainedChallengeStateStore();
            $stage2 = $this->stage2Chain($risk['gateway'], $store, $chainStore);
            $chainService = $stage2['chainService'];
            $chainId = $stage2['chainId'];
            $nonceS = $stage2['stage2']->nonce;
            $expectedCode = $terminal === 'denied' ? KiwiCaptcha::POST_SOLVE_REJECTED_ERROR : KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED;
            $expectedKind = $terminal === 'denied' ? PostSolveDispositionKind::Deny : PostSolveDispositionKind::StepUp;

            // The transaction is already terminal (a different token of
            // the same transaction terminalized the issued chain — the
            // exact stage-2 nonce preserved).
            $obligationId = $chainService->obligationIdFor('login', 'auth-txn-1', 1);
            $result = $terminal === 'denied'
                ? $chainService->markTransactionDenied($chainId, $obligationId)
                : $chainService->markTransactionStepUpRequired($chainId, $obligationId);
            self::assertNotSame(ChainVerifiedResult::Conflict, $result, $label);
            $requirement = $chainService->requirementFor($chainId);
            self::assertSame($terminal, $requirement?->state, 'the chain is TERMINAL: '.$label);
            self::assertSame($nonceS, $requirement?->stage2Nonce, 'the exact stage-2 nonce is preserved: '.$label);

            // The browser submits the exact stage-2 nonce S.
            usleep(($stage2['stage2']->minDurationMs + 10) * 1000);
            $tokenS = $this->solveToken($stage2['stage2']->prefix, $stage2['stage2']->salt, $stage2['stage2']->targetBits, $stage2['stage2']->nonce);
            $dto = new class {
                public ?string $captcha = null;
            };
            $dto->captcha = $tokenS;

            $metaStore = null;
            if ($assessment === 'none') {
                // post_solve_check=false AND the chain marker: NO
                // reassessment would run at all (the defect's case a).
                $metaStore = new \BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyMetadataStore();
                $metaStore->store($nonceS, new \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadata(null, null, 'login', $chainId, 2), 300);
            }
            if (($vectors[$assessment] ?? null) !== null) {
                $risk['store']->setVector(SignalVector::fromArray($vectors[$assessment]));
            }

            [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, resolver: $resolver, bindingAuthority: $this->bindingAuthority(), metadataStore: $metaStore, operationId: 'op-retry');
            $meta = $engine->getMetadataFor($dto::class);
            $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
            $violations = $engine->validate($dto);

            self::assertCount(1, $violations, 'the terminal state dominates the exact stage-2 nonce: '.$label);
            self::assertSame($expectedCode, $violations[0]->getCode(), 'the terminal disposition wins — never Pass, never 503: '.$label);
            self::assertArrayNotHasKey('{{ chain_ticket }}', $violations[0]->getParameters(), 'a terminal disposition never becomes a chain ticket: '.$label);
            self::assertSame($expectedKind, $store->read($nonceS)?->disposition?->kind, 'S\'s nonce disposition is persisted AS THE TERMINAL KIND: '.$label);
            self::assertSame($terminal, $chainService->requirementFor($chainId)?->state, 'the terminal state survives: '.$label);

            // replay of S (the stored-result retry): the same terminal
            // result — never Pass, never 503 (the replay path is
            // consistent).
            [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, resolver: $resolver, bindingAuthority: $this->bindingAuthority(), metadataStore: $metaStore, operationId: 'op-retry');
            $meta2 = $engine2->getMetadataFor($dto::class);
            $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
            $violations2 = $engine2->validate($dto);

            self::assertCount(1, $violations2, 'the replay of S must never pass: '.$label);
            self::assertSame($expectedCode, $violations2[0]->getCode(), 'the replay reproduces the SAME terminal disposition — never Pass, never 503: '.$label);
            self::assertSame($expectedKind, $store->read($nonceS)?->disposition?->kind, 'the replay keeps the terminal kind: '.$label);
        }
    }

    public function testStage2TokenInheritsATerminalDenyFromAnotherTokenOfTheSameTransaction(): void
    {
        // THE critical scenario: the chain is issued(S); a different
        // stage-1 token B of the same transaction gets a fresh Deny — the
        // chain becomes terminal denied preserving the exact stage-2
        // nonce S; the browser then submits S with NO post-solve
        // reassessment (post_solve_check=false + the chain marker): the
        // terminal deny — never Pass, never the stage-2 transition
        // conflict (503) — and S's nonce disposition is persisted AS THE
        // terminal kind, so the replay of S reproduces the same terminal
        // denial.
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(1, 'allow', 'allow', false, null, $resolver);
        $risk['store']->setVector(SignalVector::fromArray(self::ARGON32_VECTOR));
        [$store] = $this->clockedDispositionStore();
        $chainStore = new ArrayChainedChallengeStateStore();
        $stage2 = $this->stage2Chain($risk['gateway'], $store, $chainStore);
        $chainService = $stage2['chainService'];
        $chainId = $stage2['chainId'];
        $nonceS = $stage2['stage2']->nonce;

        // Token B — a different stage-1 token of the same transaction —
        // gets a fresh deny: the terminal rejection AND the durable
        // terminalization of the open (issued) chain — the exact stage-2
        // nonce preserved.
        $risk['store']->setVector(SignalVector::fromArray(['network_risk' => 900]));
        $challengeB = $this->issuer->issue('login', '198.51.100.7', 'auth-txn-1');
        usleep(($challengeB->minDurationMs + 10) * 1000);
        $tokenB = $this->solveToken($challengeB->prefix, $challengeB->salt, $challengeB->targetBits, $challengeB->nonce);
        $dtoB = new class {
            public ?string $captcha = null;
        };
        $dtoB->captcha = $tokenB;
        [$engineB] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, bindingAuthority: $this->bindingAuthority(), operationId: 'op-retry');
        $metaB = $engineB->getMetadataFor($dtoB::class);
        $metaB->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violationsB = $engineB->validate($dtoB);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violationsB[0]->getCode(), 'B\'s fresh Deny is the terminal rejection');
        $state = $chainService->requirementFor($chainId);
        self::assertSame('denied', $state?->state, 'the fresh Deny TERMINALIZES the issued chain');
        self::assertSame($nonceS, $state?->stage2Nonce, 'the exact stage-2 nonce S is PRESERVED');
        self::assertNotNull($chainService->findOpenRequirement('login', 'auth-txn-1', 1), 'the obligation mapping is KEPT');

        // The browser submits S with NO reassessment (post_solve_check=
        // false + the chain marker): the terminal deny — never Pass,
        // never 503.
        $metaStore = new \BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyMetadataStore();
        $metaStore->store($nonceS, new \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadata(null, null, 'login', $chainId, 2), 300);
        usleep(($stage2['stage2']->minDurationMs + 10) * 1000);
        $tokenS = $this->solveToken($stage2['stage2']->prefix, $stage2['stage2']->salt, $stage2['stage2']->targetBits, $stage2['stage2']->nonce);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $tokenS;
        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, resolver: $resolver, bindingAuthority: $this->bindingAuthority(), metadataStore: $metaStore, operationId: 'op-retry');
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine->validate($dto);

        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violations[0]->getCode(), 'the terminal Deny wins for the EXACT stage-2 nonce — never Pass, never 503');
        self::assertArrayNotHasKey('{{ chain_ticket }}', $violations[0]->getParameters(), 'a terminal denial never becomes a chain ticket');
        self::assertSame(PostSolveDispositionKind::Deny, $store->read($nonceS)?->disposition?->kind, 'S\'s nonce disposition is persisted AS THE TERMINAL KIND');
        self::assertSame('denied', $chainService->requirementFor($chainId)?->state, 'the chain stays terminal denied');

        // replay of S: the same terminal denial — never Pass, never 503.
        [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, resolver: $resolver, bindingAuthority: $this->bindingAuthority(), metadataStore: $metaStore, operationId: 'op-retry');
        $meta2 = $engine2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations2 = $engine2->validate($dto);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violations2[0]->getCode(), 'the replay of S reproduces the terminal Deny — never a stored Pass, never 503');
        self::assertSame(PostSolveDispositionKind::Deny, $store->read($nonceS)?->disposition?->kind, 'the replay keeps the terminal kind');
    }

    public function testStage2TokenInheritsATerminalStepUpFromAnotherTokenOfTheSameTransaction(): void
    {
        // The StepUp mirror of the critical scenario: a different stage-1
        // token B gets a fresh step-up — the issued chain becomes terminal
        // step_up_required preserving the exact stage-2 nonce S; the
        // submission of S (with a fresh deny assessment — the opposite
        // terminal) still answers the terminal step-up — never the
        // conflicting stage-2 transition (503), never Pass.
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(1, 'allow', 'allow', false, null, $resolver);
        $risk['store']->setVector(SignalVector::fromArray(self::ARGON32_VECTOR));
        [$store] = $this->clockedDispositionStore();
        $chainStore = new ArrayChainedChallengeStateStore();
        $stage2 = $this->stage2Chain($risk['gateway'], $store, $chainStore);
        $chainService = $stage2['chainService'];
        $chainId = $stage2['chainId'];
        $nonceS = $stage2['stage2']->nonce;

        // Token B — a different stage-1 token — gets a fresh step-up: the
        // terminal step-up AND the durable terminalization of the open
        // (issued) chain — the exact stage-2 nonce preserved.
        $risk['store']->setVector(SignalVector::fromArray(self::STEP_UP_VECTOR));
        $challengeB = $this->issuer->issue('login', '198.51.100.7', 'auth-txn-1');
        usleep(($challengeB->minDurationMs + 10) * 1000);
        $tokenB = $this->solveToken($challengeB->prefix, $challengeB->salt, $challengeB->targetBits, $challengeB->nonce);
        $dtoB = new class {
            public ?string $captcha = null;
        };
        $dtoB->captcha = $tokenB;
        [$engineB] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, bindingAuthority: $this->bindingAuthority(), operationId: 'op-retry');
        $metaB = $engineB->getMetadataFor($dtoB::class);
        $metaB->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violationsB = $engineB->validate($dtoB);
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violationsB[0]->getCode(), 'B\'s fresh StepUp is the terminal step-up');
        $state = $chainService->requirementFor($chainId);
        self::assertSame('step_up_required', $state?->state, 'the fresh StepUp TERMINALIZES the issued chain');
        self::assertSame($nonceS, $state?->stage2Nonce, 'the exact stage-2 nonce S is PRESERVED');
        self::assertNotNull($chainService->findOpenRequirement('login', 'auth-txn-1', 1), 'the obligation mapping is KEPT');

        // The browser submits S under a fresh deny assessment (the
        // opposite terminal): the terminal step-up wins permanently —
        // never the conflicting transition (503), never Pass.
        $risk['store']->setVector(SignalVector::fromArray(['network_risk' => 900]));
        usleep(($stage2['stage2']->minDurationMs + 10) * 1000);
        $tokenS = $this->solveToken($stage2['stage2']->prefix, $stage2['stage2']->salt, $stage2['stage2']->targetBits, $stage2['stage2']->nonce);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $tokenS;
        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, resolver: $resolver, bindingAuthority: $this->bindingAuthority(), operationId: 'op-retry');
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine->validate($dto);

        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations[0]->getCode(), 'the terminal StepUp wins for the EXACT stage-2 nonce — never the conflicting transition, never 503');
        self::assertArrayNotHasKey('{{ chain_ticket }}', $violations[0]->getParameters(), 'a terminal step-up never becomes a chain ticket');
        self::assertSame(PostSolveDispositionKind::StepUp, $store->read($nonceS)?->disposition?->kind, 'S\'s nonce disposition is persisted AS THE TERMINAL KIND');
        self::assertSame('step_up_required', $chainService->requirementFor($chainId)?->state, 'the chain stays terminal step_up_required');

        // replay of S: the same terminal step-up — never Pass, never 503.
        [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, resolver: $resolver, bindingAuthority: $this->bindingAuthority(), operationId: 'op-retry');
        $meta2 = $engine2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations2 = $engine2->validate($dto);
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations2[0]->getCode(), 'the replay of S reproduces the terminal StepUp — never 503');
        self::assertSame(PostSolveDispositionKind::StepUp, $store->read($nonceS)?->disposition?->kind, 'the replay keeps the terminal kind');
    }

    public function testReplayOfTheStage2NonceNeverReproducesAStalePassOverATerminalTransaction(): void
    {
        // A stale pass persisted for S (e.g. by a racing/buggy path
        // before the transaction terminalized — the record that used to
        // trap the stage-2 nonce in the persistent 503 loop) is
        // superseded by the requirement's terminal state on every replay:
        // the terminal Deny answers — never the stored Pass, never the
        // stage-2 transition conflict.
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(1, 'allow', 'allow', false, null, $resolver);
        $risk['store']->setVector(SignalVector::fromArray(self::ARGON32_VECTOR));
        [$store] = $this->clockedDispositionStore();
        $chainStore = new ArrayChainedChallengeStateStore();
        $stage2 = $this->stage2Chain($risk['gateway'], $store, $chainStore);
        $chainService = $stage2['chainService'];
        $chainId = $stage2['chainId'];
        $nonceS = $stage2['stage2']->nonce;

        // The transaction is terminal denied — the exact stage-2 nonce
        // preserved.
        $obligationId = $chainService->obligationIdFor('login', 'auth-txn-1', 1);
        self::assertSame(ChainVerifiedResult::DeniedNew, $chainService->markTransactionDenied($chainId, $obligationId));
        self::assertSame($nonceS, $chainService->requirementFor($chainId)?->stage2Nonce, 'the exact stage-2 nonce is preserved');

        // A stale pass is S's persisted nonce disposition (injected
        // directly — the record the pre-fix path could leave behind).
        $this->injectDispositionRecord($store, $nonceS, $this->completeDispositionRecord());

        // The submission (and replay) of S answers the terminal Deny —
        // never the stored Pass, never 503.
        usleep(($stage2['stage2']->minDurationMs + 10) * 1000);
        $tokenS = $this->solveToken($stage2['stage2']->prefix, $stage2['stage2']->salt, $stage2['stage2']->targetBits, $stage2['stage2']->nonce);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $tokenS;
        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, resolver: $resolver, bindingAuthority: $this->bindingAuthority());
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine->validate($dto);

        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violations[0]->getCode(), 'the terminal Deny supersedes a stale persisted Pass — never Pass, never 503');
        self::assertSame('denied', $chainService->requirementFor($chainId)?->state, 'the terminal state survives');
    }

    public function testTerminalizationBeforeFinalizeFailureRetryReconstructsTheTerminalDisposition(): void
    {
        // THE crash test (terminalization-first): token B's fresh Deny
        // terminalizes the open obligation (the chain transition is
        // applied before the nonce-disposition finalize), the finalize
        // fails (decorator) -> the request answers temporary_unavailable;
        // a retry (finalize healthy, after the claim lease) rediscovers
        // the terminal transaction (the dominance rule) and reconstructs
        // the terminal disposition — Deny — persisted as B's nonce
        // disposition kind. No authorization weakness: the durable
        // terminality was established by the successful transition, the
        // failure only delayed the nonce disposition.
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $risk = $this->riskStack(1, 'allow', 'allow', false, null, $resolver);
        [$store, $advance] = $this->clockedDispositionStore();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = new ChainedChallengeTicketService($chainStore, self::SECRET, 300, 15, $this->bindingAuthority());

        // Token A opens the chain (Argon32).
        $risk['store']->setVector(SignalVector::fromArray(self::ARGON32_VECTOR));
        $challengeA = $this->issuer->issue('login', '198.51.100.7', 'auth-txn-1');
        usleep(($challengeA->minDurationMs + 10) * 1000);
        $tokenA = $this->solveToken($challengeA->prefix, $challengeA->salt, $challengeA->targetBits, $challengeA->nonce);
        $dtoA = new class {
            public ?string $captcha = null;
        };
        $dtoA->captcha = $tokenA;
        [$engineA] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, bindingAuthority: $this->bindingAuthority(), operationId: 'op-retry');
        $metaA = $engineA->getMetadataFor($dtoA::class);
        $metaA->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violationsA = $engineA->validate($dtoA);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violationsA[0]->getCode());
        $chainId = (string) $chainService->verify((string) $violationsA[0]->getParameters()['{{ chain_ticket }}'])['chainId'];

        // Token B: a fresh deny whose terminalization succeeds (the chain
        // becomes terminal denied) but whose nonce-disposition finalize
        // fails: the request answers temporary_unavailable — the durable
        // terminality is already established, no bare Deny escapes
        // without its nonce disposition.
        $risk['store']->setVector(SignalVector::fromArray(['network_risk' => 900]));
        $challengeB = $this->issuer->issue('login', '198.51.100.7', 'auth-txn-1');
        usleep(($challengeB->minDurationMs + 10) * 1000);
        $tokenB = $this->solveToken($challengeB->prefix, $challengeB->salt, $challengeB->targetBits, $challengeB->nonce);
        $dtoB = new class {
            public ?string $captcha = null;
        };
        $dtoB->captcha = $tokenB;
        $faulted = $this->faultedStore($store, failFinalize: true);
        [$engineB] = $this->dispositionEngine($this->verifier, $risk['gateway'], $faulted, chainTickets: $chainService, bindingAuthority: $this->bindingAuthority(), operationId: 'op-retry');
        $metaB = $engineB->getMetadataFor($dtoB::class);
        $metaB->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violationsB = $engineB->validate($dtoB);
        self::assertCount(1, $violationsB);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violationsB[0]->getCode(), 'a finalize failure after a successful terminalization is temporary_unavailable');
        self::assertSame('denied', $chainService->requirementFor($chainId)?->state, 'the chain transition ran BEFORE the finalize — the terminality is durable');
        self::assertSame('pending', $store->read($challengeB->nonce)?->state, 'the claim is left pending — the nonce disposition was never finalized');

        // The retry (finalize healthy, after the claim lease): the
        // dominance rule rediscovers the terminal transaction and
        // reconstructs the terminal disposition — persisted AS Deny.
        $advance(16);
        [$engineB2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, bindingAuthority: $this->bindingAuthority(), operationId: 'op-retry');
        $metaB2 = $engineB2->getMetadataFor($dtoB::class);
        $metaB2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violationsB2 = $engineB2->validate($dtoB);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violationsB2[0]->getCode(), 'the retry reconstructs the terminal Deny');
        self::assertSame(PostSolveDispositionKind::Deny, $store->read($challengeB->nonce)?->disposition?->kind, 'the retry persists the terminal kind as the nonce disposition');
        self::assertSame('denied', $chainService->requirementFor($chainId)?->state, 'the chain stays terminal denied');
    }
}

/**
 * The authoritative transaction-binding fixture of the binding-authority
 * tests: maps the presented client hint 'client-hint' to the canonical
 * 'server-transaction' binding (the value the challenge controller signs)
 * and counts every resolution — the authority must be consulted exactly
 * once per validation.
 */
final class MappingBindingAuthority implements RequestBindingAuthorityInterface
{
    public int $calls = 0;

    public function resolve(Request $request, string $scope, ?string $presentedBinding): ?string
    {
        ++$this->calls;
        if ($presentedBinding !== null && $presentedBinding !== '' && $presentedBinding !== 'client-hint') {
            throw new \InvalidArgumentException('presented binding does not match the authoritative transaction binding');
        }

        return 'server-transaction';
    }
}

/**
 * The authority fixture whose backend is down: every resolution throws.
 * The validator must fail closed with temporary_unavailable — never a
 * silent pass, never a raw exception.
 */
final class ThrowingBindingAuthority implements RequestBindingAuthorityInterface
{
    public int $calls = 0;

    public function resolve(Request $request, string $scope, ?string $presentedBinding): ?string
    {
        ++$this->calls;
        throw new \RuntimeException('the authoritative binding backend is unavailable');
    }
}

/**
 * The authority fixture that declines the transaction: the transaction is
 * invalid/unknown (null) — the normal invalid-binding outcome applies.
 */
final class NullBindingAuthority implements RequestBindingAuthorityInterface
{
    public int $calls = 0;

    public function resolve(Request $request, string $scope, ?string $presentedBinding): ?string
    {
        ++$this->calls;

        return null;
    }
}

/**
 * A transactional chain-state decorator with a test seam: the terminal
 * transitions can fail on demand (a simulated store outage), so the
 * validator's fail-closed stage-2 transition path is exercisable. All
 * other operations delegate to the wrapped store.
 */
final class FailingTerminalChainStore implements TransactionalChainedChallengeStateStore
{
    public bool $failStepUpRequired = false;

    public bool $failDenied = false;

    public bool $failVerified = false;

    public bool $failTransactionDenied = false;

    public bool $failTransactionStepUpRequired = false;

    /** When true, the obligation read throws — the validator's chain-state read seam. */
    public bool $failObligationChainId = false;

    public function __construct(private readonly ArrayChainedChallengeStateStore $inner)
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
        if ($this->failObligationChainId) {
            throw new \RuntimeException('simulated chain-state read outage');
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
        if ($this->failVerified) {
            throw new \RuntimeException('simulated terminal transition outage');
        }

        return $this->inner->markVerified($chainId, $stage2Nonce);
    }

    public function markStepUpRequired(string $chainId, string $stage2Nonce): string
    {
        if ($this->failStepUpRequired) {
            throw new \RuntimeException('simulated terminal transition outage');
        }

        return $this->inner->markStepUpRequired($chainId, $stage2Nonce);
    }

    public function markDenied(string $chainId, string $stage2Nonce): string
    {
        if ($this->failDenied) {
            throw new \RuntimeException('simulated terminal transition outage');
        }

        return $this->inner->markDenied($chainId, $stage2Nonce);
    }

    public function markTransactionDenied(string $chainId, string $obligationId): string
    {
        if ($this->failTransactionDenied) {
            throw new \RuntimeException('simulated terminal transition outage');
        }

        return $this->inner->markTransactionDenied($chainId, $obligationId);
    }

    public function markTransactionStepUpRequired(string $chainId, string $obligationId): string
    {
        if ($this->failTransactionStepUpRequired) {
            throw new \RuntimeException('simulated terminal transition outage');
        }

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
