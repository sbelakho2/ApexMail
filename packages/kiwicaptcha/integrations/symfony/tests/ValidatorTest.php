<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Security\OutstandingChallenges;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore;
use KiwiCaptcha\BindingMode;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Storage\ArrayStorage;
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
    private function riskStack(int $scopeId, string $minimum, string $degraded, bool $postSolveCheck): array
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
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => $scopeId], null, null, ['login' => $postSolveCheck], 'reject', null, null, null, null, '{kiwi:validator-test}:decision:', 300, $policy);

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
     * P1: a post-solve assessment with no usable risk signal (bogus or
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
     * P1: with a degraded=sha20 scope the degraded fallback applies the
     * minimum friction (the PoW challenge itself) — the valid solve passes
     * (no Deny/StepUp in the degraded decision), exactly like a normal
     * post-solve decision, instead of crashing or silently skipping.
     */
    public function testPostSolveNoIpEnforcesDegradedMinimumFriction(): void
    {
        $violations = $this->validateUnboundSolveWithoutIp(1, 'allow', 'sha20', 'not-an-ip', new KiwiCaptcha(['scope' => 'login']));
        self::assertCount(0, $violations, 'a degraded=sha20 decision is neither Deny nor StepUp — the valid solve passes with the minimum friction');

        $violations = $this->validateUnboundSolveWithoutIp(1, 'allow', 'sha20', null, new KiwiCaptcha(['scope' => 'login']));
        self::assertCount(0, $violations, 'missing IP: same minimum-friction contract');
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
            // Audit #57: capacity exhaustion keeps its DISTINCT public code
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

    // ── Round 9: transaction binding (audit #41) ──────────────────────────

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
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode(), 'a binding mismatch must collapse to the SAME invalid_or_expired code (audit #57)');
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
        self::assertSame('txn-123', $validator->verifiedRequestBinding(), 'the record\'s SIGNED request binding must be exposed after a valid solve (audit #41)');
    }

    // ── Round 9: security-policy epoch (audit #42) ─────────────────────────

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
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode(), 'WrongPolicyVersion must collapse to invalid_or_expired (audit #57)');
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

    // ── Round 9: public code collapsing (audit #57) ────────────────────────

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
}
