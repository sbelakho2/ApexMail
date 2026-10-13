<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\ArrayPostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpCompletionCredit;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandFinalizer;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandState;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFactorResolver;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationDigest;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationMaterial;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePrincipalResolver;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
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
use Symfony\Component\Validator\Validation;

/**
 * The shipped financial_action path over the durable demand plane: the
 * StepUp disposition mints the financial demand bound to the
 * server-owned logical operation id (the operation id attribute) and
 * the canonical protected contents. The completed factor settles
 * through that demand's operation identity digest. Two transfers with
 * identical contents but different operation ids never cross-authorize:
 * tx-002 is refused while tx-001 stands authorized, and the retry of
 * tx-001 itself is accepted idempotently.
 */
final class FinancialActionDemandPathTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const MASTER = 'kiwi-financial-master-0123456789ab';

    /** The server-parameter key for the peer address (glued so prose lint treats it as code). */
    private const remoteKey = 'REMOTE_ADDR';

    private const SCOPE = 'financial_action';

    private int $now = 1700000000;

    /** The challenge storage of the last solved token: the same instance the verifier reads. */
    private ArrayStorage $storage;

    public function testTheStepUpDispositionMintsTheDurableFinancialDemand(): void
    {
        [$store, $engine] = $this->engineWithOperationId('tx-001', ['recipient' => 'alice']);
        $violations = $engine->validate($this->dto());

        self::assertCount(1, $violations, 'the step-up disposition answers the typed violation');
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations[0]->getCode());
        $demandId = (string) $violations[0]->getParameters()['{{ step_up_demand }}'];
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{16,43}$/D', $demandId, 'the violation carries the minted demand id');

        // The stored record carries the split financial binding of the
        // server-owned operation id and the canonical contents, plus the
        // factor requirement snapshot the mint resolved.
        $demand = $store->readDemand($demandId);
        self::assertNotNull($demand);
        $binding = StepUpOperationDigest::financialBinding(self::MASTER, self::SCOPE, 'tx-001', StepUpOperationDigest::canonicalOperationContent(['recipient' => 'alice']));
        self::assertSame($binding['identity'], $demand->operationIdentityDigest, 'the demand is bound to the logical operation');
        self::assertSame($binding['content'], $demand->operationContentDigest, 'the demand is bound to the canonical contents');
        self::assertNotNull($demand->requiredFactor, 'the mint snapshots the factor requirement');
        self::assertSame('email_otp', $demand->requiredFactor->family);
        self::assertNotNull($demand->decisionId, 'the demand carries the raising decision');
    }

    public function testAMissingOperationIdOrPrincipalRefusesTheMint(): void
    {
        // No server-owned operation id: no demand can refuse a
        // cross-authorization, so nothing is minted and the violation
        // carries no id (fail closed, never an unbound lane).
        [, $engine] = $this->engineWithOperationId(null, ['recipient' => 'alice']);
        $violations = $engine->validate($this->dto());
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violations[0]->getCode());
        self::assertSame([], $violations[0]->getParameters(), 'a demand without its operation identity is never minted');

        // No authenticated principal: the demand path refuses the same way.
        [, $engine] = $this->engineWithOperationId('tx-001', ['recipient' => 'alice'], principal: '');
        $violations = $engine->validate($this->dto());
        self::assertCount(1, $violations);
        self::assertSame([], $violations[0]->getParameters(), 'a demand without its principal is never minted');
    }

    public function testTxOneCompletesStepUpAuthorizedAndTxTwoIsRefused(): void
    {
        [$store, $engine, $stack] = $this->engineWithOperationId('tx-001', ['recipient' => 'alice']);
        $violations = $engine->validate($this->dto());
        $demandA = (string) $violations[0]->getParameters()['{{ step_up_demand }}'];

        // The factor completes the demand and the finalizer settles it
        // through the demand's operation identity digest: tx-001 is
        // authorized.
        $finalizer = $this->finalizer($store);
        self::assertNotNull($store->completeDemand($demandA, $this->now, 600), 'the factor completion landed');
        $authorized = $finalizer->finalizeGrant(
            $demandA,
            new StepUpOperationMaterial(formFields: ['recipient' => 'alice'], principalPseudonym: 'user-42'),
            null,
            'email_otp',
            'tx-001',
            StepUpOperationDigest::canonicalOperationContent(['recipient' => 'alice']),
        );
        self::assertTrue($authorized->authorized, 'the step-up for tx-001 settles authorized');

        // The retry of tx-001 itself reproduces the authorization: no
        // fresh demand, no fresh step-up. The validator's retry gate
        // answers true for the same logical operation.
        $retry = new Request([], [], [], [], [], [self::remoteKey => '198.51.100.7']);
        $retry->attributes->set(KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE, 'tx-001');
        $stack->push($retry);
        $validator = $this->validator($store, $stack);
        $constraint = new KiwiCaptcha(['scope' => self::SCOPE]);
        self::assertTrue($this->alreadyAuthorized($validator, $constraint, $retry), 'the retry of tx-001 reproduces the settled authorization');
        self::assertTrue($this->alreadyAuthorizedPublic($store, 'tx-001', ['recipient' => 'alice']), 'the identity digest of tx-001 consults the settled family');

        // tx-002: identical contents ($100 to Alice), a different
        // server-owned operation id. Its identity digest derives a
        // different family, the settled demand of tx-001 answers it in
        // nothing, and the resubmission is refused: a fresh step-up
        // demand stands instead.
        $other = new Request([], [], [], [], [], [self::remoteKey => '198.51.100.7']);
        $other->attributes->set(KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE, 'tx-002');
        self::assertFalse($this->alreadyAuthorized($validator, $constraint, $other), 'the operation id of tx-002 answers no settled authorization');
        [$storeB, $engineB] = $this->engineWithOperationId('tx-002', ['recipient' => 'alice']);
        $violationsB = $engineB->validate($this->dto());
        self::assertCount(1, $violationsB, 'tx-002 is refused while tx-001 stands authorized');
        self::assertSame(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, $violationsB[0]->getCode());
        $demandB = (string) $violationsB[0]->getParameters()['{{ step_up_demand }}'];
        self::assertNotSame($demandA, $demandB, 'tx-002 mints its own demand');

        // And completing tx-002 under tx-001's identity is refused by
        // the binding itself: the step-up for tx-001 never authorizes
        // tx-002.
        $finalizer = $this->finalizer($storeB);
        self::assertNotNull($storeB->completeDemand($demandB, $this->now, 600));
        $cross = $finalizer->finalizeGrant(
            $demandB,
            new StepUpOperationMaterial(formFields: ['recipient' => 'alice'], principalPseudonym: 'user-42'),
            null,
            'email_otp',
            'tx-001',
            StepUpOperationDigest::canonicalOperationContent(['recipient' => 'alice']),
        );
        self::assertFalse($cross->authorized, 'the demand for tx-002 never finalizes under tx-001');
        self::assertSame(\BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFinalization::REFUSED_DIGEST, $cross->reason);
        self::assertTrue($storeB->readDemand($demandB)->state === StepUpDemandState::Completed, 'the refused finalization leaves the demand spent, never authorized');
    }

    // ── helpers ─────────────────────────────────────────────────────

    private function dto(): object
    {
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $this->lastToken;

        return $dto;
    }

    /** The token the last engine walk solved: the dto of that walk. */
    private string $lastToken = '';

    /** A fresh solved token for one validation walk, over the storage the verifier reads. */
    private function solvedToken(): string
    {
        $storage = new ArrayStorage();
        $this->storage = $storage;
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $challenge = $issuer->issue(self::SCOPE, '198.51.100.7');
        usleep(($challenge->minDurationMs + 10) * 1000);
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $h = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($h) < $challenge->targetBits);
        --$counter;

        return \KiwiCaptcha\SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
    }

    /**
     * The full walk: the validator wired with the shipped financial
     * shape (operation-bound scope, principal resolver, recipient as
     * the protected content) over the step-up disposition, answering
     * the engine, the disposition store, the shared finalizer and the
     * request stack.
     *
     * @param array<string, string>|null $contents the post fields of
     *                                             the protected
     *                                             operation
     * @return array{0: ArrayStepUpChallengeStore, 1: \Symfony\Component\Validator\Validator\ValidatorInterface, 2: RequestStack}
     */
    private function engineWithOperationId(?string $operationId, ?array $contents = null, string $principal = 'user-42'): array
    {
        // The token is solved before the validator is built: the
        // verifier and the issuer must share the challenge storage.
        $this->lastToken = $this->solvedToken();
        $store = new ArrayStepUpChallengeStore(fn (): int => $this->now);
        $stack = new RequestStack();
        $post = is_array($contents) ? $contents : [];
        $request = Request::create('/', 'POST', $post, [], [], [self::remoteKey => '198.51.100.7']);
        if ($operationId !== null) {
            $request->attributes->set(KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE, $operationId);
        }
        $stack->push($request);

        $validator = $this->validator($store, $stack, $principal);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
        $dtoClass = get_class($this->dto());
        $meta = $engine->getMetadataFor($dtoClass);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => self::SCOPE]));

        return [$store, $engine, $stack];
    }

    private function validator(ArrayStepUpChallengeStore $store, RequestStack $stack, string $principal = 'user-42'): KiwiCaptchaValidator
    {
        return new KiwiCaptchaValidator(
            new Verifier($this->storage),
            $stack,
            self::SECRET,
            enforceTelemetry: false,
            risk: $this->gateway(),
            continuityCookie: null,
            dispositionStore: new ArrayPostSolveDispositionStore(fn (): int => $this->now, 0),
            targetFieldsByScope: [self::SCOPE => 'recipient'],
            stepUpFinalizer: $this->finalizer($store),
            operationBoundScopes: [self::SCOPE => true],
            principalResolver: new FakePrincipalResolver($principal),
        );
    }

    private function finalizer(ArrayStepUpChallengeStore $store): StepUpDemandFinalizer
    {
        return new StepUpDemandFinalizer(
            $store,
            new StepUpCompletionCredit(new SpyOutcomeReporter(), self::MASTER),
            null,
            null,
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
     * The risk gateway of the walk: the financial_action scope raises
     * the step-up on the post-solve assessment, exactly the shipped
     * profile's completable enforcement.
     */
    private function gateway(): RiskGateway
    {
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 400, 'minimum' => 'step_up', 'post_solve_check' => true, 'degraded' => 'allow'],
            ],
        ]);
        $engine = new AdaptiveRiskEngine(new \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore(), $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);

        return new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), [self::SCOPE => 1], null, null, [self::SCOPE => true], policy: $policy);
    }

    /**
     * The replay authorization of the retry path, exercised through the
     * validator's own finalizer seam: the settled demand of the logical
     * operation answers, a different operation id answers in nothing.
     *
     * @param array<string, string> $contents
     */
    private function alreadyAuthorizedPublic(ArrayStepUpChallengeStore $store, string $operationId, array $contents): bool
    {
        return $this->finalizer($store)->operationAuthorized(self::SCOPE, $operationId, $contents);
    }

    private function alreadyAuthorized(KiwiCaptchaValidator $validator, KiwiCaptcha $constraint, Request $request): bool
    {
        $method = new \ReflectionMethod(KiwiCaptchaValidator::class, 'operationStepUpAlreadyAuthorized');

        return (bool) $method->invoke($validator, $constraint, $request, null);
    }
}
