<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use BelConsulting\KiwiCaptchaBundle\Risk\ArrayChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ArrayPostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDisposition;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionRecord;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\Risk\RequestBindingAuthorityInterface;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
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
 * locally (never via an external HTTP call). Tested through the full
 * Symfony validation pipeline, exactly as a form submission would be.
 */
final class ValidatorTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    /** The post-solve vector that demands Argon32 (score 813). */
    private const ARGON32_VECTOR = ['source_fast' => 900, 'subnet_fast' => 1000, 'issue_debt' => 1000, 'replay' => 699, 'network_risk' => 890];

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
     * A full risk stack (engine + gateway with a wired policy) over a fake
     * state store for ONE 'login' scope.
     *
     * @return array{gateway: RiskGateway, store: FakeRiskStateStore}
     */
    private function riskStack(int $scopeId, string $minimum, string $degraded, bool $postSolveCheck, ?RiskV2Weights $v2Weights = null, ?RiskProfileResolver $resolver = null): array
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
        $gateway = new RiskGateway($engine, $classifier, $resolver ?? new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => $scopeId], null, null, ['login' => $postSolveCheck], 'reject', null, null, null, null, '{kiwi:validator-test}:decision:', 300, $policy, null, null, $v2Weights);

        return ['gateway' => $gateway, 'store' => $store];
    }

    /**
     * Solve a challenge issued with BindingMode::None and validate it
     * against a request carrying NO usable client IP (bogus/missing), so the
     * post-solve assessment throws InvalidArgumentException and the
     * validator must fall back to the scope's DEGRADED decision.
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
        // Request::create defaults REMOTE_ADDR to 127.0.0.1 — null it
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
     * MISSING client IP — e.g. BindingMode::None deployments) must NOT
     * silently skip the adaptive re-check. The scope's DEGRADED decision
     * applies exactly like on the pre-issue path: degraded=deny fails the
     * valid solve with POST_SOLVE_REJECTED_ERROR instead of passing with
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
     * action the solved SHA-8 challenge does NOT satisfy under the
     * configured ladders: a STRONGER PoW requirement must never silently
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
            // Capacity exhaustion keeps its DISTINCT public code
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

    public function testValidSolveDecrementsTheOutstandingCounter(): void
    {
        $client = new FakePredisClient();
        $outstanding = new OutstandingChallenges($client, '{kiwi:validator-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 3, 100, 0);

        // Two outstanding challenges for the source (the 3rd would hit the cap).
        self::assertSame(1, $outstanding->issue('198.51.100.7', 120));
        self::assertSame(1, $outstanding->issue('198.51.100.7', 120));
        $sourceKey = $outstanding->sourceKey('198.51.100.7');
        self::assertSame(2, $client->counters[$sourceKey]);

        // A VALID solve decrements the per-source counter (best-effort).
        $challenge = $this->issuer->issue('login', '198.51.100.7');
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

        // A FAILED solve must NOT decrement (the challenge stays outstanding).
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
    private function buildBindingEngine(?Verifier $verifier = null, string $requestBinding = 'txn-123', bool $asAttribute = true): array
    {
        $stack = new RequestStack();
        $request = Request::create('/', 'POST', ['kiwi_request_binding' => $requestBinding], [], [], ['REMOTE_ADDR' => '198.51.100.7']);
        if ($asAttribute) {
            // The application controller copies the POSTed field into the
            // request attribute before validation (the documented contract).
            $request->attributes->set(KiwiCaptchaValidator::REQUEST_BINDING_ATTRIBUTE, $requestBinding);
        }
        $stack->push($request);

        $validator = new KiwiCaptchaValidator($verifier ?? $this->verifier, $stack, self::SECRET);
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

    public function testUnboundChallengeIgnoresTheRequestBinding(): void
    {
        // The record has NO binding (issue without requestBinding): the
        // request may carry a binding (or not) — no check applies.
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

        self::assertCount(0, $engine->validate($dto), 'an unbound record must pass regardless of the request binding');
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
        // invalid_or_expired — the client gets no oracle for WHICH check
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
    private function buildRetryEngine(Verifier $verifier, ?StorageInterface $storage, string $ip = '198.51.100.7', ?string $binding = null): array
    {
        $stack = new RequestStack();
        $request = Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => $ip]);
        if ($binding !== null) {
            $request->attributes->set(KiwiCaptchaValidator::REQUEST_BINDING_ATTRIBUTE, $binding);
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
     * Whether the vendored core already carries the consumed-state
     * fields (ChallengeRecord::$consumed / $consumedResult / $consumedBinding
     * and the WIRE_KEYS entries). The parallel core work adds them; until
     * then the full stored-result scenarios cannot be constructed.
     */
    private function coreSupportsConsumedState(): bool
    {
        try {
            $sample = ChallengeRecord::fromArray([
                'nonce' => base64_encode(str_repeat('a', 32)),
                'scope' => 'login',
                'binding_tag' => '',
                'issued_at' => 1_800_000_000,
                'expires_at' => 1_800_000_120,
                'algorithm' => 'sha256',
                'm_kib' => 0,
                't' => 1,
                'p' => 1,
                'target_bits' => 8,
                'salt' => base64_encode('1234567890abcdef'),
                'prefix' => 'prefix',
                'challenge' => 'challenge',
                'min_duration_ms' => 0,
            ])->toArray();
            ChallengeRecord::fromArray($sample + ['consumed' => true, 'consumed_result' => null, 'consumed_binding' => null]);

            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Retryable contract (runs on the CURRENT core): a
     * ConsumeIndeterminate (lost consume response) NEVER burns the token and
     * NEVER re-derives — the first attempt surfaces as temporary_unavailable
     * (the record is still pending), and a retry consumes + derives exactly
     * ONCE.
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
     * (a) the FULL stored-result retry — first verification
     * succeeds (consume transition + derive + committed result); a lost
     * response makes the client re-submit the SAME token with the SAME
     * binding: the retry resolves from the STORED RESULT — the SAME success
     * (jti + binding exposed) with NO second consume, NO second derive.
     *
     * Requires the current core (consumed-state record fields + the
     * stored-result re-verify path); skipped until it is vendored.
     */
    public function testStoredResultRetryWithSameBindingSucceedsWithoutSecondDerive(): void
    {
        if (!$this->coreSupportsConsumedState()) {
            self::markTestSkipped('the consumed-state record + stored-result re-verify path is not vendored yet');
        }

        $storage = new ConsumedStateStorage();
        $verifier = new Verifier($storage);
        $challenge = $this->issueBoundChallenge('txn-123', $storage);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        // FIRST verification: real derive — consume transition + committed
        // result (the verifier commits after deriving).
        [$engine, $stack, $validator] = $this->buildRetryEngine($verifier, $storage, binding: 'txn-123');
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

        // LOST RESPONSE: the client never saw the reply and re-submits the
        // same token with the same binding.
        [$engine2, $stack2, $validator2] = $this->buildRetryEngine($verifier, $storage, binding: 'txn-123');
        $dto2 = new class {
            public ?string $captcha = null;
        };
        $dto2->captcha = $token;
        $meta2 = $engine2->getMetadataFor($dto2::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        self::assertCount(0, $engine2->validate($dto2), 'a retry with the SAME binding must produce the SAME success');
        self::assertSame($challenge->nonce, $stack2->getMainRequest()?->attributes->get(KiwiCaptchaValidator::VERIFIED_JTI_ATTRIBUTE), 'the retry must expose the SAME canonical jti');
        self::assertSame('txn-123', $validator2->verifiedRequestBinding(), 'the retry must expose the stored signed binding');
        self::assertSame(1, $storage->consumes, 'the retry must NOT consume again — the outcome came from the STORED RESULT, no second derive');
        self::assertSame(1, $storage->commits, 'the retry must NOT commit again');
        self::assertSame(0, $storage->deletes);
    }

    /**
     * (b) the retry with a DIFFERENT request binding is refused
     * with invalid_or_expired — a challenge bound to one transaction is
     * never redeemable for another, retries included.
     */
    public function testStoredResultRetryWithDifferentBindingFailsInvalidOrExpired(): void
    {
        if (!$this->coreSupportsConsumedState()) {
            self::markTestSkipped('the consumed-state record + stored-result re-verify path is not vendored yet');
        }

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

        // Retry with a DIFFERENT binding: the stored-result outcome carries
        // the stored binding, the binding check rejects the mismatch.
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
     * A consumed record whose committed result is INVALID (the original
     * derivation failed, response lost) resolves the retry to
     * invalid_or_expired — the failed outcome is authoritative.
     */
    public function testStoredResultRetryOfAFailedDeriveFailsInvalidOrExpired(): void
    {
        if (!$this->coreSupportsConsumedState()) {
            self::markTestSkipped('the consumed-state record + stored-result re-verify path is not vendored yet');
        }

        $storage = new ConsumedStateStorage();
        $verifier = new Verifier($storage);
        $challenge = $this->issueBoundChallenge('txn-123', $storage);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        // Simulate the original attempt: consumed, derivation FAILED,
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
        self::assertSame(0, $storage->consumes, 'the retry must not re-derive a record with a committed result');
    }

    /**
     * A consumed record WITHOUT a committed result (the original attempt
     * died mid-proof) stays genuinely indeterminate — the retry collapses
     * to temporary_unavailable, never to a guessed success.
     */
    public function testConsumedWithoutCommittedResultStaysTemporaryUnavailable(): void
    {
        if (!$this->coreSupportsConsumedState()) {
            self::markTestSkipped('the consumed-state record + stored-result re-verify path is not vendored yet');
        }

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

// ── QUIC IP-migration policy ───────────────────────────────────────────────

    /**
     * Documentation test: the STRICT binding stays — a challenge
     * bound to IP A verified from IP B fails closed with IpMismatch at the
     * core level (the collapsed invalid_or_expired through the validator).
     * The documented migration policy (README): exact IP -> normal; same
     * network -> acceptable with a risk penalty (the engine's subnet
     * dimension); different network -> fresh challenge or stronger
     * request_binding/session check; mobile clients prefer request_binding
     * over IP. The IP binding itself is a nonce-bound HMAC tag, never a
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
        // A different network: the nonce-bound tag cannot match -> IpMismatch
        // (fail closed, one-shot — the challenge is burned by the attempt).
        $outcome = $verifier->verify($token, self::SECRET, 'login', '203.0.113.9');
        self::assertFalse($outcome->isOk());
        self::assertSame(\KiwiCaptcha\VerifyError::IpMismatch, $outcome->error, 'the strict IP binding must fail closed on a different source');

        // Through the validator: the same mismatch collapses to
        // invalid_or_expired — the client never learns WHICH
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
     * captures the variable BY REFERENCE, so tests advance the store's time
     * to exercise lease expiry.
     *
     * @return array{0: ArrayPostSolveDispositionStore, 1: \Closure}
     */
    private function clockedDispositionStore(): array
    {
        $clock = 1_800_000_000;
        $store = new ArrayPostSolveDispositionStore(static function () use (&$clock): int {
            return $clock;
        });
        $advance = static function (int $seconds) use (&$clock): void {
            $clock += $seconds;
        };

        return [$store, $advance];
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

            public function claim(string $nonce, string $owner, int $ttlSeconds): string
            {
                if ($this->failClaim) {
                    throw new \RuntimeException('simulated claim outage');
                }

                return $this->inner->claim($nonce, $owner, $ttlSeconds);
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
        };
    }

    /**
     * A validator wired with the risk gateway + a durable disposition store
     * over the shared challenge storage, driving the full Symfony
     * validation pipeline for one token.
     *
     * @param array<string, string> $post the POST body (decoy fields, ...)
     *
     * @return array{0: \Symfony\Component\Validator\Validator\ValidatorInterface, 1: RequestStack, 2: KiwiCaptchaValidator}
     */
    private function dispositionEngine(Verifier $verifier, RiskGateway $gateway, PostSolveDispositionStore $store, array $post = [], int $ttlMargin = 0, ?ChainedChallengeTicketService $chainTickets = null, ?RiskProfileResolver $resolver = null, ?RequestBindingAuthorityInterface $bindingAuthority = null, int $chainTtlSecs = 300): array
    {
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', $post, [], [], ['REMOTE_ADDR' => '198.51.100.7']));
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
     * key (HMAC-SHA256 of the domain-separated message, keyed by the
     * master-derived event key) — the dedupe identity a crash-taken-over
     * re-assessment MUST reproduce.
     */
    private function expectedEventId(RiskEventKind $event, int $scope, string $key): string
    {
        return hash_hmac('sha256', pack('N', $scope).chr($event->value).$key, RiskKeys::fromMaster(self::SECRET)->event);
    }

    public function testPostSolveDispositionStoreClaimMachine(): void
    {
        [$store, $advance] = $this->clockedDispositionStore();

        // Missing -> pending(me, 15s lease): claimed.
        self::assertSame('claimed', $store->claim('nonce-a', 'owner-1', 300));
        // pending+me -> 'pending' (the same owner re-enters).
        self::assertSame('pending', $store->claim('nonce-a', 'owner-1', 300));
        // pending+other+live -> 'pending' (busy).
        self::assertSame('pending', $store->claim('nonce-a', 'owner-2', 300));
        $record = $store->read('nonce-a');
        self::assertNotNull($record);
        self::assertSame('pending', $record->state);
        self::assertSame('owner-1', $record->owner);
        self::assertNull($record->disposition);

        // pending+other+expired -> takeover -> 'taken_over'.
        $advance(16);
        self::assertSame('taken_over', $store->claim('nonce-a', 'owner-2', 300));
        self::assertSame('owner-2', $store->read('nonce-a')?->owner, 'the takeover must move the claim to the new owner');

        // pending(me) -> complete(disposition), then 'complete' forever.
        self::assertTrue($store->finalize('nonce-a', 'owner-2', new PostSolveDisposition(PostSolveDispositionKind::Deny, 'decision-1')));
        self::assertSame('complete', $store->claim('nonce-a', 'owner-3', 300), 'a completed disposition replays as complete');
        $record = $store->read('nonce-a');
        self::assertSame('complete', $record->state);
        self::assertNull($record->owner);
        self::assertNull($record->leaseUntil);
        self::assertNotNull($record->disposition);
        self::assertSame(PostSolveDispositionKind::Deny, $record->disposition->kind);
        self::assertSame('decision-1', $record->disposition->decisionId);

        // finalize on a COMPLETE record is refused (never overwritten).
        self::assertFalse($store->finalize('nonce-a', 'owner-3', new PostSolveDisposition(PostSolveDispositionKind::Pass)));
        self::assertSame(PostSolveDispositionKind::Deny, $store->read('nonce-a')?->disposition?->kind, 'a completed disposition is terminal');
    }

    public function testPostSolveDispositionStoreFinalizeIsOwnerGated(): void
    {
        [$store] = $this->clockedDispositionStore();

        self::assertSame('claimed', $store->claim('nonce-b', 'owner-1', 300));
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

        self::assertSame('claimed', $store->claim('nonce-c', 'owner-1', 300));
        $advance(20);
        // The lease (15 s) expired -> takeover, while the RECORD TTL (300 s) is still live.
        self::assertSame('taken_over', $store->claim('nonce-c', 'owner-2', 300));
        self::assertTrue($store->finalize('nonce-c', 'owner-2', new PostSolveDisposition(PostSolveDispositionKind::Pass)));

        // The record TTL is INDEPENDENT of the lease: it expires with its
        // own configured lifetime (Config::MAX_TTL_SECS + margin via the
        // validator's claim TTL), never with the 15 s lease.
        $advance(301);
        self::assertNull($store->read('nonce-c'), 'the record expires with its own TTL, not with the lease');
        self::assertSame('claimed', $store->claim('nonce-c', 'owner-3', 300), 'an expired record is claimable fresh');
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
        self::assertSame('claimed', $store->claim('nonce-d', 'owner-1', 9999));
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

        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        // FRESH: the post-solve assessment denies the valid solve.
        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violations[0]->getCode());
        $record = $store->read($challenge->nonce);
        self::assertNotNull($record);
        self::assertSame(PostSolveDispositionKind::Deny, $record->disposition?->kind, 'the denied disposition must be persisted per nonce');
        $firstDecision = $record->disposition?->decisionId;
        self::assertNotNull($firstDecision);

        // REPLAY (the SAME token — the core replays its stored result): the
        // persisted disposition reproduces the SAME deny — never a pass.
        [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store);
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

        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store);
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

        [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store);
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

        [$engine, $stack] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        self::assertCount(0, $engine->validate($dto));
        self::assertSame($challenge->nonce, $stack->getMainRequest()?->attributes->get(KiwiCaptchaValidator::VERIFIED_JTI_ATTRIBUTE), 'a fresh pass exposes the canonical jti');
        self::assertSame(PostSolveDispositionKind::Pass, $store->read($challenge->nonce)?->disposition?->kind, 'the pass disposition must be persisted per nonce');

        [$engine2, $stack2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store);
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

        // REQUEST 1: the core commits the VALID result, then the process
        // dies BEFORE the post-solve claim (the store is unreachable) — the
        // client sees temporary_unavailable, the token is NOT burned.
        $failing = $this->faultedStore($inner, failClaim: true);
        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $failing);
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

        // REQUEST 2 (retry, store recovered): the retry CLAIMS the nonce
        // fresh, computes the disposition (deny) and persists it — the
        // post-solve policy runs exactly once.
        [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $inner);
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

        // REQUEST 1: the claim is won, the post-solve assessment RUNS, then
        // the process dies BEFORE the finalize — temporary_unavailable.
        $crashed = $this->faultedStore($inner, failFinalize: true);
        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $crashed);
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine->validate($dto);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'a crash before the finalize is retryable temporary_unavailable');
        self::assertSame(1, \count($risk['store']->observations));
        self::assertSame('pending', $inner->read($challenge->nonce)?->state, 'the claim is left pending with its lease');

        // REQUEST 2 (retry AFTER the 15 s lease expires): the retry TAKES
        // OVER the claim and re-runs the assessment — with the SAME
        // nonce-derived idempotency key, so the risk signal is NOT doubled
        // (the dedupe identity is identical; a deduping backend applies it
        // exactly once).
        $advance(16);
        [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $inner);
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

        // REQUEST 1 wins the claim, runs the assessment, dies before the
        // finalize (lease left live).
        $crashed = $this->faultedStore($inner, failFinalize: true);
        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $crashed);
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $engine->validate($dto)[0]->getCode());
        self::assertSame(1, \count($risk['store']->observations));

        // REQUEST 2 (CONCURRENT, same token, claim still live): the busy
        // claim is temporary_unavailable — NEVER a second assessment, never
        // a silent pass.
        [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $inner);
        $meta2 = $engine2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine2->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'a concurrent same-token request must never pass while the claim is live');
        self::assertSame(1, \count($risk['store']->observations), 'exactly ONE owner computes — the concurrent request never assessed');

        // The OWNER still completes after its lease expires: exactly one
        // more assessment, then the final disposition.
        $advance(16);
        [$engine3] = $this->dispositionEngine($this->verifier, $risk['gateway'], $inner);
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

        // The store is unavailable for EVERY operation: the valid solve
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
        // post_solve_check=false AND chaining disabled: only a filled EXACT
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

        // FILLED EXACT DECOY: reassesses through the risk-v2 path; the
        // stronger-PoW demand with chaining disabled is terminal StepUp.
        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, [$decoy => 'filled']);
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations[0]->getCode(), 'a filled exact decoy must reassess — a stronger-PoW demand is terminal StepUp, never a silent pass');
        self::assertSame(PostSolveDispositionKind::StepUp, $store->read($nonce)?->disposition?->kind);

        // The honeypot evidence carries the NONCE-DERIVED
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

        // REPLAY of the same token: the persisted StepUp disposition
        // reproduces — the honeypot is never re-scored.
        [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, [$decoy => 'filled']);
        $meta2 = $engine2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine2->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations[0]->getCode(), 'a replay of the honeypot-hit token is StepUp again — never a pass');
        self::assertSame(2, \count($risk['store']->observations), 'the replay must not re-record evidence or reassess');

        // MISMATCHED decoy name: NOT this challenge's decoy — ignored, no
        // reassessment, plain pass.
        $other = $this->issuer->issue('login', '198.51.100.7');
        usleep(($other->minDurationMs + 10) * 1000);
        $otherToken = $this->solveToken($other->prefix, $other->salt, $other->targetBits, $other->nonce);
        $dto2 = new class {
            public ?string $captcha = null;
        };
        $dto2->captcha = $otherToken;
        [$engine3] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, ['decoy_00000000' => 'filled']);
        $meta3 = $engine3->getMetadataFor($dto2::class);
        $meta3->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        self::assertCount(0, $engine3->validate($dto2), 'a mismatched decoy name is not this challenge\'s decoy — no reassessment');
        self::assertSame(PostSolveDispositionKind::Pass, $store->read($other->nonce)?->disposition?->kind);

        // EMPTY exact decoy: no evidence, no reassessment, plain pass.
        $third = $this->issuer->issue('login', '198.51.100.7');
        usleep(($third->minDurationMs + 10) * 1000);
        $thirdToken = $this->solveToken($third->prefix, $third->salt, $third->targetBits, $third->nonce);
        $thirdDecoy = 'decoy_'.substr(hash('sha256', $third->nonce), 0, 8);
        $dto3 = new class {
            public ?string $captcha = null;
        };
        $dto3->captcha = $thirdToken;
        [$engine4] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, [$thirdDecoy => '']);
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

        $challenge = $this->issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $nonce = \KiwiCaptcha\SolutionToken::decode($token)->nonce;
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;

        // FRESH: the reassessment demands Argon32 — the solved SHA-8 does
        // not satisfy it, the authoritative binding resolves, the chain
        // opens: CHAIN_REQUIRED with the PERSISTED chain id.
        [$engine] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, resolver: $resolver, bindingAuthority: $this->bindingAuthority());
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

        // REPLAY (the SAME token — the core replays its stored result): the
        // persisted disposition reproduces CHAIN_REQUIRED with the SAME
        // chain id — NEVER a pass, never a second chain.
        [$engine2] = $this->dispositionEngine($this->verifier, $risk['gateway'], $store, chainTickets: $chainService, resolver: $resolver, bindingAuthority: $this->bindingAuthority());
        $meta2 = $engine2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine2->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode(), 'a replay of a CHAIN_REQUIRED token must be CHAIN_REQUIRED again — never a pass');
        $ticket2 = $violations[0]->getParameters()['{{ chain_ticket }}'] ?? null;
        self::assertIsString($ticket2);
        self::assertNotEmpty($ticket2);
        self::assertSame($chainId, $store->read($nonce)?->disposition?->chainId, 'the replay reproduces the SAME chain id');
        self::assertSame(1, \count($risk['store']->observations), 'the replay must not re-run the reassessment');
    }

    public function testChainRequiredDispositionSurvivesTokenExpiryForTheRetainedMargin(): void
    {
        // SHORT token lifetime (2 s) + the retained margin (5 s): the
        // disposition record (TTL = Config::MAX_TTL_SECS + margin = 305 s)
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

        $challenge = $issuer->issue('login', '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);
        $nonce = \KiwiCaptcha\SolutionToken::decode($token)->nonce;
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;

        [$engine] = $this->dispositionEngine($verifier, $risk['gateway'], $store, ttlMargin: 5, chainTickets: $chainService, resolver: $resolver, bindingAuthority: $this->bindingAuthority());
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $chainId = $store->read($nonce)?->disposition?->chainId;
        self::assertIsString($chainId);

        // The token EXPIRES (2 s TTL) while the retained consumed result
        // and the disposition stay alive (token lifetime + margin).
        sleep(3);

        // The DISPOSITION survives the normal token expiry: the record is
        // still complete with the SAME chain id.
        $record = $store->read($nonce);
        self::assertNotNull($record, 'the disposition must survive the token expiry');
        self::assertSame('complete', $record->state);
        self::assertSame($chainId, $record->disposition?->chainId, 'the survived disposition keeps the SAME chain id');

        // The expired token itself is refused by the CORE (the stored
        // result's retryable window is the token validity) — never a pass,
        // never a fresh assessment, and the disposition is untouched.
        [$engine2] = $this->dispositionEngine($verifier, $risk['gateway'], $store, ttlMargin: 5, chainTickets: $chainService, resolver: $resolver, bindingAuthority: $this->bindingAuthority());
        $meta2 = $engine2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));
        $violations = $engine2->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode(), 'the expired token is refused by the core — never a pass');
        self::assertSame(1, \count($risk['store']->observations), 'the expired-token attempt must not reassess');
        self::assertSame($chainId, $store->read($nonce)?->disposition?->chainId, 'the refused replay must not disturb the persisted disposition');

        // The disposition outlives the retained core-result window (token
        // lifetime + margin = 7 s): still complete past it, expiring only
        // with its own TTL (MAX_TTL_SECS + margin = 305 s).
        $advance(8);
        self::assertSame('complete', $store->read($nonce)?->state, 'the disposition survives the retained core-result window');
        $advance(305);
        self::assertNull($store->read($nonce), 'the disposition expires only with its own record TTL (MAX_TTL_SECS + margin)');
    }
}
