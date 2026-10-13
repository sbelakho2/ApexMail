<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Command\KiwiCaptchaDoctorCommand;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\Configuration;
use BelConsulting\KiwiCaptchaBundle\Risk\ArrayPostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDisposition;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ConfiguredStepUpOperationResolver;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpCompletionCredit;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandFinalizer;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandState;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFactorResolver;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFinalization;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperation;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationDigest;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationMaterial;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationResolverInterface;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePrincipalResolver;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyStepUpOperationResolver;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use KiwiCaptcha\Config;
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
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\TestKernel;
use Symfony\Component\Validator\ConstraintValidatorFactory;
use Symfony\Component\Validator\Validation;

/**
 * The protected-operation resolver of the operation-bound demand path.
 * Covered: the shipped default resolver reads the server-owned logical
 * operation id from its request attribute, the protected contents from
 * the explicit per-scope recipe, and the principal from the wired
 * resolver. A missing id, a scope without a recipe and a configured
 * field with no submitted value throw. The mint feeds the resolved
 * contents into the split content digest, so the demand is bound to the
 * actual business operation (amount, currency, beneficiary) and a
 * changed amount no longer rides the settled authorization. A high
 * or critical value_class scope with an operation identity source but
 * no recipe refuses the container build, and the doctor fails it. The
 * compiled container registers the shipped resolver behind the
 * interface alias, the replacement test re-points that alias, and the
 * server-authoritative walk refuses a business object the settled
 * content digest no longer reproduces.
 */
final class StepUpOperationResolverTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const MASTER = 'kiwi-resolver-master-0123456789ab';

    /** The server-parameter key for the peer address (glued so prose lint treats it as code). */
    private const remoteKey = 'REMOTE_ADDR';

    private const SCOPE = 'financial_action';

    private int $now = 1700000000;

    // ── the default resolver ─────────────────────────────────────────

    public function testTheResolverBindsTheServerOwnedIdAndTheConfiguredContentFields(): void
    {
        $request = Request::create('/', 'POST', ['transfer' => ['amount_minor' => '10000', 'currency' => 'EUR', 'beneficiary_id' => 'alice']]);
        $request->attributes->set(KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE, 'tx-001');
        $resolver = new ConfiguredStepUpOperationResolver(
            [self::SCOPE => ['amount_minor', 'currency', 'beneficiary_id']],
            new FakePrincipalResolver('user-42'),
        );

        $operation = $resolver->resolve($request, self::SCOPE);

        self::assertSame('tx-001', $operation->logicalOperationId, 'the logical operation id is the server-owned attribute');
        self::assertSame(
            StepUpOperationDigest::canonicalOperationContent(['amount_minor' => '10000', 'currency' => 'EUR', 'beneficiary_id' => 'alice']),
            $operation->canonicalProtectedContents,
            'the protected contents are the canonical string over the configured recipe',
        );
        self::assertSame('user-42', $operation->principal, 'the principal rides the operation');
        // Order independence: the canonicalization sorts the recipe.
        $shuffled = new ConfiguredStepUpOperationResolver(
            [self::SCOPE => ['beneficiary_id', 'currency', 'amount_minor']],
            new FakePrincipalResolver('user-42'),
        );
        self::assertSame(
            $operation->canonicalProtectedContents,
            $shuffled->resolve($request, self::SCOPE)->canonicalProtectedContents,
            'the recipe order never changes the canonical bytes',
        );
    }

    public function testAResolutionWithoutIdOrRecipeOrFieldValueThrows(): void
    {
        $refusals = 0;
        // No server-owned operation id under the attribute.
        $request = Request::create('/', 'POST', ['amount_minor' => '10000']);
        $resolver = new ConfiguredStepUpOperationResolver([self::SCOPE => ['amount_minor', 'currency']]);
        try {
            $resolver->resolve($request, self::SCOPE);
        } catch (\InvalidArgumentException) {
            $refusals++;
        }

        // A scope that names no recipe.
        $request->attributes->set(KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE, 'tx-001');
        try {
            $resolver->resolve($request, 'unconfigured_scope');
        } catch (\InvalidArgumentException) {
            $refusals++;
        }

        // A configured field with no submitted value.
        try {
            $resolver->resolve($request, self::SCOPE);
        } catch (\InvalidArgumentException) {
            $refusals++;
        }

        self::assertSame(3, $refusals, 'the missing id, the missing recipe and the empty field each refuse the resolution');
    }

    // ── the mint feeds the digest over the resolved operation ────────

    public function testTheMintBindsTheDemandToTheResolvedBusinessContents(): void
    {
        $store = new ArrayStepUpChallengeStore(fn (): int => $this->now);
        $stack = new RequestStack();
        $request = Request::create('/', 'POST', [
            'transfer' => ['amount_minor' => '10000', 'currency' => 'EUR', 'beneficiary_id' => 'alice'],
        ], [], [], [self::remoteKey => '198.51.100.7']);
        $request->attributes->set(KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE, 'tx-001');
        $stack->push($request);

        $resolver = new ConfiguredStepUpOperationResolver(
            [self::SCOPE => ['amount_minor', 'currency', 'beneficiary_id']],
            new FakePrincipalResolver('user-42'),
        );
        $validator = new KiwiCaptchaValidator(
            new Verifier(new ArrayStorage()),
            $stack,
            self::SECRET,
            enforceTelemetry: false,
            risk: $this->gateway(),
            dispositionStore: new ArrayPostSolveDispositionStore(fn (): int => $this->now, 0),
            stepUpFinalizer: $this->finalizer($store),
            operationBoundScopes: [self::SCOPE => true],
            principalResolver: new FakePrincipalResolver('user-42'),
            operationResolver: $resolver,
        );
        $constraint = new KiwiCaptcha(['scope' => self::SCOPE]);
        $disposition = new PostSolveDisposition(PostSolveDispositionKind::StepUp, 'decision-1');
        $method = new \ReflectionMethod(KiwiCaptchaValidator::class, 'mintOperationBoundDemand');
        $demandId = $method->invoke($validator, $disposition, $constraint, $request, null);

        self::assertNotNull($demandId, 'the resolver-fed mint recorded the demand');
        $demand = $store->readDemand((string) $demandId);
        self::assertNotNull($demand);
        $contents = ['amount_minor' => '10000', 'currency' => 'EUR', 'beneficiary_id' => 'alice'];
        $binding = StepUpOperationDigest::financialBinding(self::MASTER, self::SCOPE, 'tx-001', StepUpOperationDigest::canonicalOperationContent($contents));
        self::assertSame($binding['identity'], $demand->operationIdentityDigest, 'the demand is bound to the server-owned logical operation');
        self::assertSame($binding['content'], $demand->operationContentDigest, 'the content digest runs over the actual business contents');

        // The finalization rerun answers the same operation with the
        // same contents, and refuses the same operation whose amount
        // changed: the wire-level swap of one transfer for another is
        // dead on arrival.
        self::assertNotNull($store->completeDemand((string) $demandId, $this->now, 600));
        $settled = $this->finalizer($store)->finalizeGrant(
            (string) $demandId,
            new StepUpOperationMaterial(principalPseudonym: 'user-42'),
            null,
            'email_otp',
            'tx-001',
            StepUpOperationDigest::canonicalOperationContent($contents),
        );
        self::assertTrue($settled->authorized, 'the same operation with the same contents settles authorized');
        self::assertFalse(
            $this->finalizer($store)->operationAuthorizedContents(self::SCOPE, 'tx-001', StepUpOperationDigest::canonicalOperationContent([
                'amount_minor' => '50000000',
                'currency' => 'EUR',
                'beneficiary_id' => 'bob',
            ])),
            'the replay gate refuses the same operation with swapped contents',
        );
        self::assertTrue(
            $this->finalizer($store)->operationAuthorizedContents(self::SCOPE, 'tx-001', StepUpOperationDigest::canonicalOperationContent($contents)),
            'the replay gate answers the identical contents',
        );
        self::assertSame(StepUpDemandState::Authorized, $store->readDemand((string) $demandId)?->state);
    }

    // ── the compiled seam ────────────────────────────────────────────

    /**
     * The compiled seam: the extension registers the shipped resolver
     * behind the StepUpOperationResolverInterface alias and every
     * consumer references the interface id. The kernel below re-points
     * the alias at the spy implementation at compile time. The compiled
     * container injects the replacement into the validator, the
     * settlement minted through the container's own finalizer
     * reproduces under the replacement's canonical bytes, and the
     * validator's replay gate drives exactly the replacement.
     */
    public function testTheCompiledContainerInjectsTheReplacementBehindTheInterfaceAlias(): void
    {
        SpyStepUpOperationResolver::$resolved = [];
        SpyStepUpOperationResolver::$operation = new StepUpOperation(
            'tx-spy-001',
            StepUpOperationDigest::canonicalOperationContent(['amount_minor' => '25000', 'currency' => 'EUR', 'beneficiary_id' => 'carol']),
            'user-42',
        );
        $kernel = new class ('test', true) extends TestKernel {
            protected function build(ContainerBuilder $container): void
            {
                parent::build($container);
                $container->register('resolver.seam.fake.redis', FakePredisClient::class)
                    ->setPublic(true);
                $container->register('resolver.seam.domain', SpyStepUpOperationResolver::class)
                    ->setPublic(true);
                // The deployment's replacement pass: it re-points the
                // interface alias at the domain implementation after
                // the extension registered the shipped default behind
                // it.
                $container->addCompilerPass(new class implements CompilerPassInterface {
                    public function process(ContainerBuilder $container): void
                    {
                        $container->setAlias(StepUpOperationResolverInterface::class, 'resolver.seam.domain')
                            ->setPublic(true);
                    }
                });
                $container->addCompilerPass(new class implements CompilerPassInterface {
                    public function process(ContainerBuilder $container): void
                    {
                        $id = KiwiCaptchaValidator::class;
                        if ($container->hasDefinition($id)) {
                            $container->getDefinition($id)->setPublic(true);
                        }
                    }
                });
            }

            public function registerContainerConfiguration(LoaderInterface $loader): void
            {
                $loader->load(function (ContainerBuilder $container): void {
                    $container->loadFromExtension('framework', [
                        'secret' => 'test-secret',
                        'test' => true,
                    ]);
                    $container->loadFromExtension('kiwi_captcha', [
                        'secret_key' => '0123456789abcdef0123456789abcdef',
                        'redis_service' => 'resolver.seam.fake.redis',
                        'risk' => [
                            'enabled' => true,
                            'redis_service' => 'resolver.seam.fake.redis',
                            'scopes' => [
                                'wire_transfer' => [
                                    'value_class' => 'high',
                                    'operation_identity_source' => 'request_attribute',
                                    'operation_content_fields' => ['amount_minor', 'currency', 'beneficiary_id'],
                                ],
                                'login' => ['id' => 20],
                            ],
                            'step_up' => [
                                'enabled' => true,
                                'handlers' => ['email_otp' => ['enabled' => true]],
                            ],
                        ],
                    ]);
                });
            }
        };
        try {
            $kernel->boot();
            $container = $kernel->getContainer()->get('test.service_container');
            $validator = $container->get(KiwiCaptchaValidator::class);
            $injected = $this->injectedOperationResolver($validator);
            self::assertInstanceOf(SpyStepUpOperationResolver::class, $injected, 'the validator received the alias replacement, never the shipped default');
            self::assertSame($container->get('resolver.seam.domain'), $injected, 'the injected instance is the replacement service itself');

            // The seam feeds the whole demand path: the demand minted
            // through the container's own finalizer under the
            // replacement's canonical bytes settles authorized, and
            // the validator's replay gate answers it through the
            // replacement.
            $scope = 'wire_transfer';
            $canonical = SpyStepUpOperationResolver::$operation->canonicalProtectedContents;
            $finalizer = $container->get(StepUpDemandFinalizer::class);
            $demandId = $finalizer->mintBoundDemand($scope, 'tx-spy-001', $canonical);
            self::assertNotNull($demandId, 'the replacement-fed mint recorded the demand');
            $store = $container->get('kiwi_captcha.step_up.store');
            self::assertNotNull($store->completeDemand((string) $demandId, time(), 300), 'the factor completion landed on the container store');
            $settled = $finalizer->finalizeGrant((string) $demandId, new StepUpOperationMaterial(), null, 'email_otp', 'tx-spy-001', $canonical);
            self::assertTrue($settled->authorized, 'the replacement-bound demand settles authorized');

            $request = Request::create('/', 'POST', ['amount_minor' => '1']);
            $request->attributes->set(KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE, 'tx-spy-001');
            $gate = new \ReflectionMethod(KiwiCaptchaValidator::class, 'operationStepUpAlreadyAuthorized');
            self::assertTrue($gate->invoke($validator, new KiwiCaptcha(['scope' => $scope]), $request, null), 'the replay gate authorizes through the replacement');
            self::assertSame([['scope' => $scope, 'operationId' => 'tx-spy-001']], SpyStepUpOperationResolver::$resolved, 'the resolution ran on the replacement exactly once');
        } finally {
            SpyStepUpOperationResolver::$operation = null;
            SpyStepUpOperationResolver::$resolved = [];
            $kernel->shutdown();
        }
    }

    // ── the server-authoritative walk ────────────────────────────────

    /**
     * The server-authoritative TOCTOU walk: the browser submits tx-123
     * with 100 EUR to Alice, the demand is minted on the business
     * object's executable fields, and the settlement authorizes. The
     * application then changes the business object to 50000 EUR to
     * Bob: the replay gate reads the executable fields through the
     * domain resolver and refuses, the changed contents never
     * re-authorize, and the settled terminal stands untouched. The
     * unchanged object reproduces the authorization idempotently, over
     * the same canonical bytes.
     */
    public function testAChangedBusinessObjectRefusesTheSettlementAndTheUnchangedObjectRetriesIdempotently(): void
    {
        $store = new ArrayStepUpChallengeStore(fn (): int => $this->now);
        $stack = new RequestStack();
        $request = Request::create('/', 'POST', ['amount' => '100'], [], [], [self::remoteKey => '198.51.100.7']);
        $request->attributes->set(KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE, 'tx-123');
        $stack->push($request);

        // The application's domain-backed resolver: the canonical bytes
        // run over the business object's actual executable fields, read
        // from the domain layer at every resolution.
        $ledger = new class implements StepUpOperationResolverInterface {
            /** @var array<string, array<string, string>> */
            public array $objects = [];

            public function resolve(Request $request, string $scope): StepUpOperation
            {
                $id = (string) $request->attributes->get(KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE);
                $object = $this->objects[$id] ?? null;
                if ($object === null) {
                    throw new \InvalidArgumentException('the business object of the operation id is absent');
                }

                return new StepUpOperation($id, StepUpOperationDigest::canonicalOperationContent($object), 'user-42');
            }
        };
        $ledger->objects['tx-123'] = ['amount' => '100', 'currency' => 'EUR', 'beneficiary' => 'Alice'];

        $validator = new KiwiCaptchaValidator(
            new Verifier(new ArrayStorage()),
            $stack,
            self::SECRET,
            enforceTelemetry: false,
            risk: $this->gateway(),
            dispositionStore: new ArrayPostSolveDispositionStore(fn (): int => $this->now, 0),
            stepUpFinalizer: $this->finalizer($store),
            operationBoundScopes: [self::SCOPE => true],
            principalResolver: new FakePrincipalResolver('user-42'),
            operationResolver: $ledger,
        );
        $constraint = new KiwiCaptcha(['scope' => self::SCOPE]);
        $disposition = new PostSolveDisposition(PostSolveDispositionKind::StepUp, 'decision-1');
        $mint = new \ReflectionMethod(KiwiCaptchaValidator::class, 'mintOperationBoundDemand');
        $demandId = $mint->invoke($validator, $disposition, $constraint, $request, null);
        self::assertNotNull($demandId, 'the domain-backed mint recorded the demand');
        $canonicalSubmitted = StepUpOperationDigest::canonicalOperationContent(['amount' => '100', 'currency' => 'EUR', 'beneficiary' => 'Alice']);
        $binding = StepUpOperationDigest::financialBinding(self::MASTER, self::SCOPE, 'tx-123', $canonicalSubmitted);
        $demand = $store->readDemand((string) $demandId);
        self::assertNotNull($demand);
        self::assertSame($binding['identity'], $demand->operationIdentityDigest, 'the demand is bound to the server-owned operation');
        self::assertSame($binding['content'], $demand->operationContentDigest, 'the content digest runs over the executable fields');

        // The factor completes and the settlement authorizes on the
        // executable representation.
        self::assertNotNull($store->completeDemand((string) $demandId, $this->now, 600));
        $settled = $this->finalizer($store)->finalizeGrant(
            (string) $demandId,
            new StepUpOperationMaterial(principalPseudonym: 'user-42'),
            null,
            'email_otp',
            'tx-123',
            $canonicalSubmitted,
        );
        self::assertTrue($settled->authorized, 'the precondition: tx-123 settled authorized on the executable fields');

        // The business object changes under the settled authorization:
        // tx-123 is now 50000 EUR to Bob. The replay gate resolves the
        // actual executable fields and refuses: the stored content
        // digest reproduces only the operation it was minted for.
        $ledger->objects['tx-123'] = ['amount' => '50000', 'currency' => 'EUR', 'beneficiary' => 'Bob'];
        self::assertFalse(
            $this->alreadyAuthorized($validator, $constraint, $request),
            'the changed business object must not replay the settled authorization',
        );
        $cross = $this->finalizer($store)->finalizeGrant(
            (string) $demandId,
            new StepUpOperationMaterial(principalPseudonym: 'user-42'),
            null,
            'email_otp',
            'tx-123',
            StepUpOperationDigest::canonicalOperationContent($ledger->objects['tx-123']),
        );
        self::assertFalse($cross->authorized, 'a finalization over the changed executable contents is refused');
        self::assertSame(StepUpFinalization::REFUSED_DIGEST, $cross->reason);
        self::assertSame(StepUpDemandState::Authorized, $store->readDemand((string) $demandId)?->state, 'the refused rerun never touches the settled terminal');

        // The unchanged object: the retry reproduces the authorization
        // idempotently, over the same canonical bytes both times.
        $ledger->objects['tx-123'] = ['amount' => '100', 'currency' => 'EUR', 'beneficiary' => 'Alice'];
        self::assertTrue($this->alreadyAuthorized($validator, $constraint, $request), 'the unchanged object replays the settled authorization');
        $replay = $this->finalizer($store)->finalizeGrant(
            (string) $demandId,
            new StepUpOperationMaterial(principalPseudonym: 'user-42'),
            null,
            'email_otp',
            'tx-123',
            $canonicalSubmitted,
        );
        self::assertTrue($replay->authorized, 'the retry of the unchanged object is authorized');
        self::assertTrue($this->alreadyAuthorized($validator, $constraint, $request), 'the replay stays idempotent');
    }

    /**
     * The object-version binding: an application that names a revision
     * (or any other domain version field) in its executable-field
     * recipe invalidates the settled authorization the moment the
     * object moves, even when every user-visible field is unchanged. A
     * beneficiary re-verification, a sanctions-status change, an
     * approval-chain edit or a fee change can all ride a
     * revision-only bump. Applications that deliberately want
     * semantic-content equality simply leave the version field out of
     * the recipe; both shapes ride the same canonical bytes.
     */
    public function testARevisionOnlyBumpInvalidatesTheSettledAuthorization(): void
    {
        $store = new ArrayStepUpChallengeStore(fn (): int => $this->now);
        $stack = new RequestStack();
        $request = Request::create('/', 'POST', ['amount' => '100'], [], [], [self::remoteKey => '198.51.100.7']);
        $request->attributes->set(KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE, 'tx-123');
        $stack->push($request);

        $ledger = new class implements StepUpOperationResolverInterface {
            /** @var array<string, array<string, string>> */
            public array $objects = [];

            public function resolve(Request $request, string $scope): StepUpOperation
            {
                $id = (string) $request->attributes->get(KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE);
                $object = $this->objects[$id] ?? null;
                if ($object === null) {
                    throw new \InvalidArgumentException('the business object of the operation id is absent');
                }

                return new StepUpOperation($id, StepUpOperationDigest::canonicalOperationContent($object), 'user-42');
            }
        };
        // revision_8 rides the recipe next to the executable fields.
        $ledger->objects['tx-123'] = ['amount' => '100', 'currency' => 'EUR', 'beneficiary' => 'Alice', 'revision' => '8'];

        $validator = new KiwiCaptchaValidator(
            new Verifier(new ArrayStorage()),
            $stack,
            self::SECRET,
            enforceTelemetry: false,
            risk: $this->gateway(),
            dispositionStore: new ArrayPostSolveDispositionStore(fn (): int => $this->now, 0),
            stepUpFinalizer: $this->finalizer($store),
            operationBoundScopes: [self::SCOPE => true],
            principalResolver: new FakePrincipalResolver('user-42'),
            operationResolver: $ledger,
        );
        $constraint = new KiwiCaptcha(['scope' => self::SCOPE]);
        $disposition = new PostSolveDisposition(PostSolveDispositionKind::StepUp, 'decision-1');
        $mint = new \ReflectionMethod(KiwiCaptchaValidator::class, 'mintOperationBoundDemand');
        $demandId = $mint->invoke($validator, $disposition, $constraint, $request, null);
        self::assertNotNull($demandId, 'the revision-bound mint recorded the demand');
        $canonicalRevision8 = StepUpOperationDigest::canonicalOperationContent($ledger->objects['tx-123']);
        self::assertNotNull($store->completeDemand((string) $demandId, $this->now, 600));
        $settled = $this->finalizer($store)->finalizeGrant(
            (string) $demandId,
            new StepUpOperationMaterial(principalPseudonym: 'user-42'),
            null,
            'email_otp',
            'tx-123',
            $canonicalRevision8,
        );
        self::assertTrue($settled->authorized, 'the precondition: revision 8 settled authorized');
        self::assertTrue($this->alreadyAuthorized($validator, $constraint, $request), 'revision 8 replays idempotently');

        // The object moves to revision 9 with every visible field
        // unchanged: the settled authorization is invalidated by the
        // version bump alone, because the canonical bytes changed.
        $ledger->objects['tx-123'] = ['amount' => '100', 'currency' => 'EUR', 'beneficiary' => 'Alice', 'revision' => '9'];
        self::assertFalse(
            $this->alreadyAuthorized($validator, $constraint, $request),
            'a revision-only bump invalidates the settled authorization',
        );
        $cross = $this->finalizer($store)->finalizeGrant(
            (string) $demandId,
            new StepUpOperationMaterial(principalPseudonym: 'user-42'),
            null,
            'email_otp',
            'tx-123',
            StepUpOperationDigest::canonicalOperationContent($ledger->objects['tx-123']),
        );
        self::assertFalse($cross->authorized, 'a finalization over revision 9 against the revision-8 demand is refused');
        self::assertSame(StepUpFinalization::REFUSED_DIGEST, $cross->reason);
        self::assertSame(StepUpDemandState::Authorized, $store->readDemand((string) $demandId)?->state, 'the refused rerun never touches the settled terminal');
    }

    // ── the build gate ───────────────────────────────────────────────

    public function testAHighValueOperationBoundScopeWithoutARecipeRefusesTheBuild(): void
    {
        $kernel = new class ('test', true) extends TestKernel {
            protected function build(ContainerBuilder $container): void
            {
                $container->register('resolver.gate.fake.redis', FakePredisClient::class)
                    ->setPublic(true);
            }

            public function registerContainerConfiguration(LoaderInterface $loader): void
            {
                $loader->load(function (ContainerBuilder $container): void {
                    $container->loadFromExtension('framework', [
                        'secret' => 'test-secret',
                        'test' => true,
                    ]);
                    $container->loadFromExtension('kiwi_captcha', [
                        'secret_key' => '0123456789abcdef0123456789abcdef',
                        'redis_service' => 'resolver.gate.fake.redis',
                        'risk' => [
                            'enabled' => true,
                            'redis_service' => 'resolver.gate.fake.redis',
                            'scopes' => [
                                'wire_transfer' => [
                                    'value_class' => 'high',
                                    'operation_identity_source' => 'request_attribute',
                                ],
                            ],
                        ],
                    ]);
                });
            }
        };
        try {
            $kernel->boot();
            $kernel->shutdown();
            self::fail('a high-value operation-bound scope without a content recipe must refuse the build');
        } catch (InvalidConfigurationException $e) {
            self::assertStringContainsString('operation_content_fields', $e->getMessage(), 'the refusal names the knob: '.$e->getMessage());
        }
    }

    public function testAHighValueOperationBoundScopeWithARecipeBuilds(): void
    {
        $kernel = new class ('test', true) extends TestKernel {
            protected function build(ContainerBuilder $container): void
            {
                $container->register('resolver.gate.fake.redis', FakePredisClient::class)
                    ->setPublic(true);
            }

            public function registerContainerConfiguration(LoaderInterface $loader): void
            {
                $loader->load(function (ContainerBuilder $container): void {
                    $container->loadFromExtension('framework', [
                        'secret' => 'test-secret',
                        'test' => true,
                    ]);
                    $container->loadFromExtension('kiwi_captcha', [
                        'secret_key' => '0123456789abcdef0123456789abcdef',
                        'redis_service' => 'resolver.gate.fake.redis',
                        'risk' => [
                            'enabled' => true,
                            'redis_service' => 'resolver.gate.fake.redis',
                            'scopes' => [
                                'wire_transfer' => [
                                    'value_class' => 'high',
                                    'operation_identity_source' => 'request_attribute',
                                    'operation_content_fields' => ['amount_minor', 'currency', 'beneficiary_id'],
                                ],
                                'login' => ['id' => 20],
                            ],
                            'step_up' => [
                                'enabled' => true,
                                'handlers' => ['email_otp' => ['enabled' => true]],
                            ],
                        ],
                    ]);
                });
            }
        };
        try {
            $kernel->boot();
            $container = $kernel->getContainer()->get('test.service_container');
            self::assertTrue($container->has(ConfiguredStepUpOperationResolver::class), 'the named recipe registers the resolver');
        } finally {
            $kernel->shutdown();
        }
    }

    public function testTheShippedFinancialActionScopeCarriesItsRecipe(): void
    {
        $processed = (new \Symfony\Component\Config\Definition\Processor())->processConfiguration(new Configuration(), [
            ['secret_key' => self::SECRET],
        ]);
        $recipe = $processed['risk']['scopes']['financial_action']['operation_content_fields'] ?? null;
        self::assertSame(['amount_minor', 'currency', 'beneficiary_id'], $recipe, 'the shipped financial_action scope names the transfer contents');
    }

    // ── the doctor gate ──────────────────────────────────────────────

    public function testTheDoctorFailsAHighValueScopeWithoutAContentRecipe(): void
    {
        [$fail, $failMessage] = $this->doctorVerdict([
            'financial_action' => ['value_class' => 'high', 'operation_identity_source' => 'request_attribute'],
        ]);
        self::assertSame('FAIL', $fail, 'the doctor fails the empty recipe');
        self::assertStringContainsString('operation_content_fields', $failMessage);

        [$pass, $passMessage] = $this->doctorVerdict([
            'financial_action' => [
                'value_class' => 'high',
                'operation_identity_source' => 'request_attribute',
                'operation_content_fields' => ['amount_minor', 'currency', 'beneficiary_id'],
            ],
        ]);
        self::assertSame('PASS', $pass, 'the recipe clears the doctor');
        self::assertStringContainsString('recipe', $passMessage);
        self::assertStringContainsString('request representation', $passMessage, 'the doctor states what the shipped recipe binds');
        self::assertStringContainsString('StepUpOperationResolverInterface', $passMessage, 'the doctor names the domain-backed resolver seam');
    }

    /**
     * The verdict of the doctor's operation-identity check over one
     * scope map, exercised through the command instance.
     *
     * @param array<string, mixed> $scopes
     * @return array{0: string, 1: string}
     */
    private function doctorVerdict(array $scopes): array
    {
        $command = new KiwiCaptchaDoctorCommand(
            'test',
            ['risk' => ['enabled' => true, 'scopes' => $scopes]],
            new ArrayStorage(),
            new Config(secretKey: self::SECRET),
            new \BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor(new Verifier(new ArrayStorage()), null, 'kiwi:test', 1),
            null,
            null,
            null,
            null,
        );
        $method = new \ReflectionMethod(KiwiCaptchaDoctorCommand::class, 'checkOperationIdentity');
        $verdict = $method->invoke($command);
        \assert(\is_array($verdict) && \is_string($verdict[0]) && \is_string($verdict[1]));

        return $verdict;
    }

    // ── helpers ──────────────────────────────────────────────────────

    /**
     * The operation resolver instance the compiled container injected
     * into the validator.
     */
    private function injectedOperationResolver(KiwiCaptchaValidator $validator): ?StepUpOperationResolverInterface
    {
        $property = new \ReflectionProperty(KiwiCaptchaValidator::class, 'operationResolver');
        $resolver = $property->getValue($validator);
        \assert($resolver instanceof StepUpOperationResolverInterface || $resolver === null);

        return $resolver;
    }

    /**
     * The validator's replay authorization gate: the settled demand of
     * the resolved operation answers, anything else refuses.
     */
    private function alreadyAuthorized(KiwiCaptchaValidator $validator, KiwiCaptcha $constraint, Request $request): bool
    {
        $method = new \ReflectionMethod(KiwiCaptchaValidator::class, 'operationStepUpAlreadyAuthorized');

        return (bool) $method->invoke($validator, $constraint, $request, null);
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
}
