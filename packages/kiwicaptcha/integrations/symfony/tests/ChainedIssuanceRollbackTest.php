<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Risk\ArrayChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\TransactionalChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Security\OutstandingChallenges;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest;
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
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The proven-not-handed-off rollback symmetry: once the outstanding
 * admission succeeds, every exit that positively established the
 * challenge was never handed off must return the admitted slot and
 * release the chain reservation (rollbackIssuanceAttempt). The resource
 * accounting must never depend on which exception type fires — the
 * InvalidArgumentException path returned the reservation but leaked the
 * admitted slot. The successful handoff keeps the slot, and the
 * indeterminate case (the chain state cannot be read after a thrown
 * issuance transition) keeps its existing no-rollback behavior.
 */
final class ChainedIssuanceRollbackTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    /** The post-solve vector that demands Argon32 (score 813). */
    private const ARGON32_VECTOR = ['source_fast' => 900, 'subnet_fast' => 1000, 'issue_debt' => 1000, 'replay' => 699, 'network_risk' => 890];

    private function issuer(StorageInterface $storage): Issuer
    {
        return new Issuer(new Config(
            secretKey: self::SECRET,
            algorithm: PoWAlgorithm::Sha256,
            targetBits: 8,
            ttlSecs: 120,
        ), $storage);
    }

    /** A Kiwi-shaped challenge nonce (base64 of 32 random bytes). */
    private function nonce(): string
    {
        return base64_encode(random_bytes(32));
    }

    private function riskStack(): RiskGateway
    {
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new \KiwiCaptcha\Risk\Network\CidrNetworkClassifier([]);
        $policyConfig = [
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow']],
        ];
        $policy = RiskPolicy::fromConfig($policyConfig);
        $store = new \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore(SignalVector::fromArray(self::ARGON32_VECTOR));
        $engine = new \KiwiCaptcha\Risk\AdaptiveRiskEngine($store, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);

        return new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], policy: $policy);
    }

    private function chainService(TransactionalChainedChallengeStateStore $store): ChainedChallengeTicketService
    {
        return new ChainedChallengeTicketService(
            $store,
            self::SECRET,
            300,
            15,
        );
    }

    private function chainController(StorageInterface $storage, ChainedChallengeTicketService $service, RiskGateway $gateway, ?OutstandingChallenges $outstanding = null, ?\KiwiCaptcha\Issuer $issuer = null): ChallengeController
    {
        return new ChallengeController(
            $issuer ?? $this->issuer($storage),
            null,
            true,
            $gateway,
            new ContinuityCookie(),
            outstanding: $outstanding,
            storage: $storage,
            challengeTtlSecs: 120,
            chainTickets: $service,
            policyVersion: 1,
        );
    }

    private function challengeRequest(string $body): Request
    {
        return JsonRequest::create(
            '/kiwi-captcha/challenge',
            'POST',
            [],
            [],
            [],
            ['REMOTE_ADDR' => '198.51.100.7'],
            $body,
        );
    }

    /** The per-source counter key of the fixture client IP. */
    private function sourceKey(): string
    {
        return '{kiwi:rollback-test}:outstanding:'.hash_hmac('sha256', Issuer::canonicalIpFamily('198.51.100.7'), RiskKeys::fromMaster(self::SECRET)->event);
    }

    /**
     * An open stage-2 chain + its ticket (the txn-alpha transaction).
     *
     * @return array{chainId: string, ticket: string}
     */
    private function openChain(ChainedChallengeTicketService $service): array
    {
        $requirement = $service->requireStage2($this->nonce(), 'login', 'txn-alpha', 1, RiskAction::Argon32, time() + 300);
        $ticket = $service->ticketFor($requirement->chainId, time() + 300);

        return ['chainId' => $requirement->chainId, 'ticket' => $ticket];
    }

    public function testInvalidArgumentExceptionAfterAdmissionRollsBackTheSlotAndTheReservation(): void
    {
        $storage = new ArrayStorage();
        $mint = new ThrowingMintStorage($storage);
        $client = new RollbackFakeRedis();
        $outstanding = new OutstandingChallenges($client, '{kiwi:rollback-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $chainService = $this->chainService(new ArrayChainedChallengeStateStore());
        ['chainId' => $chainId, 'ticket' => $ticket] = $this->openChain($chainService);

        // The mint (after the outstanding admission succeeded) fails with
        // \InvalidArgumentException — the exception type the controller
        // maps to the 422 invalid_scope response.
        $mint->mintError = new \InvalidArgumentException('simulated invalid-argument mint failure');
        $risk = $this->riskStack();
        $controller = $this->chainController($mint, $chainService, $risk, outstanding: $outstanding);

        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode(), sprintf('an InvalidArgumentException mint failure is the 422 INVALID_SCOPE response: %s', (string) $response->getContent()));
        self::assertStringContainsString('INVALID_SCOPE', (string) $response->getContent());

        // both halves of the proven-not-handed-off accounting returned to
        // their state: the admitted slot is returned (the per-source
        // counter is back at 0) and the chain reservation is released (the
        // chain is available/reserved-free again — the ticket stays
        // reusable). The mint failed before the post-mint admission ran,
        // so no nonce ever joined the global LIVE-outstanding membership.
        self::assertSame(0, $client->counters[$this->sourceKey()] ?? 0, 'the admitted outstanding slot is returned — the per-source counter is back to its prior state');
        self::assertSame([], $client->zsets['{kiwi:rollback-test}:outstanding:global:live'] ?? [], 'no minted nonce may join the global LIVE-outstanding membership when the mint never handed out');
        $requirement = $chainService->requirementFor($chainId);
        self::assertNotNull($requirement);
        self::assertSame('available', $requirement->state, 'the chain reservation is released — the chain is back to available');
        self::assertNull($requirement->owner, 'the released chain is reserved-free');
        self::assertSame(0, \count((new \ReflectionObject($storage))->getProperty('records')->getValue($storage)), 'no challenge record may exist for a mint that failed');

        // The same ticket still works end-to-end once the mint recovers —
        // the failure never burned the chain.
        $mint->mintError = null;
        $retry = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $retry->getStatusCode(), sprintf('after the mint recovers the same ticket issues: %s', (string) $retry->getContent()));
        self::assertSame(1, $client->counters[$this->sourceKey()] ?? 0, 'the recovered issuance holds its admitted slot');
        self::assertSame('issued', $chainService->requirementFor($chainId)?->state);
    }

    public function testReplicaWaitFailureAfterAdmissionRollsBackTheSlotAndTheReservation(): void
    {
        $storage = new ArrayStorage();
        $mint = new ThrowingMintStorage($storage);
        $client = new RollbackFakeRedis();
        $outstanding = new OutstandingChallenges($client, '{kiwi:rollback-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $chainService = $this->chainService(new ArrayChainedChallengeStateStore());
        ['chainId' => $chainId, 'ticket' => $ticket] = $this->openChain($chainService);

        $mint->mintError = new ReplicaWaitException('simulated replica-wait barrier failure');
        $risk = $this->riskStack();
        $controller = $this->chainController($mint, $chainService, $risk, outstanding: $outstanding);

        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
        self::assertSame(503, $response->getStatusCode(), sprintf('a replica-wait barrier failure is the retryable 503: %s', (string) $response->getContent()));

        self::assertSame(0, $client->counters[$this->sourceKey()] ?? 0, 'the admitted outstanding slot is returned on the replica-wait failure');
        $requirement = $chainService->requirementFor($chainId);
        self::assertNotNull($requirement);
        self::assertSame('available', $requirement->state, 'the chain reservation is released on the replica-wait failure');
        self::assertNull($requirement->owner);
    }

    public function testSuccessfulHandoffKeepsTheSlot(): void
    {
        $storage = new ArrayStorage();
        $client = new RollbackFakeRedis();
        $outstanding = new OutstandingChallenges($client, '{kiwi:rollback-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $chainService = $this->chainService(new ArrayChainedChallengeStateStore());
        ['chainId' => $chainId, 'ticket' => $ticket] = $this->openChain($chainService);

        $risk = $this->riskStack();
        $controller = $this->chainController($storage, $chainService, $risk, outstanding: $outstanding);

        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $response->getStatusCode(), sprintf('the stage-2 issuance must succeed: %s', (string) $response->getContent()));

        // The challenge was durably handed out: the outstanding slot is
        // NOT rolled back and the chain is durably issued.
        self::assertSame(1, $client->counters[$this->sourceKey()] ?? 0, 'a handed-out challenge keeps its outstanding slot');
        $requirement = $chainService->requirementFor($chainId);
        self::assertSame('issued', $requirement?->state);
        self::assertNotNull($requirement?->stage2Nonce);
    }

    public function testGenericMintFailureBeforeChallengeAssignmentIsAStructured503(): void
    {
        // R68-03: the issuer factory or the early issue() can throw before
        // the $challenge variable is ever assigned — the generic catch's
        // rollback must tolerate the unassigned state (never faulting the
        // error-handling path itself) and answer the private structured
        // 503 with the reservation released.
        $storage = new ArrayStorage();
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        $requirement = $chainService->requireStage2($this->nonce(), 'login', 'txn-alpha', 1, RiskAction::Argon32, time() + 300);
        $ticket = $chainService->ticketFor($requirement->chainId, time() + 300);

        $mintStore = new ThrowingMintStorage($storage);
        $mintStore->mintError = new \RuntimeException('simulated generic issuance backend failure');
        $throwingIssuer = $this->issuer($mintStore);
        $controller = $this->chainController($storage, $chainService, $this->riskStack(), issuer: $throwingIssuer);
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
        self::assertSame(503, $response->getStatusCode(), 'the generic mint failure answers the private structured 503');
        self::assertSame('SERVICE_UNAVAILABLE', json_decode((string) $response->getContent(), true)['error']['code']);
        self::assertSame('available', $chainService->requirementFor($requirement->chainId)?->state, 'the chain reservation is released');
    }

    public function testPostStage2CommitFailureNeverRollsBackTheIssuedState(): void
    {
        // Once markStage2Issued() confirms issued(N), NO later failure
        // (here the risk feedback) may roll back the challenge record, the
        // outstanding memberships or the chain — a rolled-back membership
        // would resurrect a valid-but-unaccounted challenge.
        $storage = new ArrayStorage();
        $client = new RollbackFakeRedis();
        $outstanding = new OutstandingChallenges($client, '{kiwi:rollback-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $chainStore = new ArrayChainedChallengeStateStore();
        $chainService = $this->chainService($chainStore);
        ['chainId' => $chainId, 'ticket' => $ticket] = $this->openChain($chainService);

        // The risk store's feedback write throws after the durable
        // stage-2 commit (the challengeIssued risk feedback fails).
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new \KiwiCaptcha\Risk\Network\CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow']],
        ]);
        $store = new ThrowingFeedbackRiskStore(SignalVector::fromArray(self::ARGON32_VECTOR));
        $risk = new RiskGateway(
            new \KiwiCaptcha\Risk\AdaptiveRiskEngine($store, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys),
            $classifier,
            new RiskProfileResolver(PoWAlgorithm::Sha256, 8),
            ['login' => 1],
            policy: $policy,
        );
        $controller = $this->chainController($storage, $chainService, $risk, outstanding: $outstanding);

        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
        self::assertSame(503, $response->getStatusCode(), 'the post-commit feedback failure answers the private structured 503');
        self::assertSame('SERVICE_UNAVAILABLE', json_decode((string) $response->getContent(), true)['error']['code']);

        // Nothing was rolled back: the chain stays issued(N), the record
        // exists, the outstanding memberships still hold N.
        $requirement = $chainService->requirementFor($chainId);
        self::assertSame('issued', $requirement?->state, 'the chain stays durably issued');
        self::assertIsString($requirement?->stage2Nonce);
        $nonce = (string) $requirement?->stage2Nonce;
        self::assertNotNull($storage->find($nonce), 'the challenge record N still exists');
        self::assertSame(1, $client->counters[$this->sourceKey()] ?? 0, 'the original-source outstanding membership still holds N');
        self::assertArrayHasKey($nonce, $client->zsets['{kiwi:rollback-test}:outstanding:global:live'] ?? [], 'the global live membership still holds N');

        // The same chain retries: it recovers the same issued challenge —
        // no re-mint, no re-admission.
        $retry = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $retry->getStatusCode());
        $retryNonce = json_decode((string) $retry->getContent(), true)['nonce'];
        self::assertSame($nonce, $retryNonce, 'the retry recovers the identical issued challenge');
        self::assertSame(1, $client->counters[$this->sourceKey()] ?? 0, 'the retry performs NO re-admission');
        self::assertCount(1, $client->zsets['{kiwi:rollback-test}:outstanding:global:live'] ?? [], 'the retry performs NO re-mint');
    }

    public function testIndeterminateChainIssuanceDoesNotRollBack(): void
    {
        $storage = new ArrayStorage();
        $client = new RollbackFakeRedis();
        $outstanding = new OutstandingChallenges($client, '{kiwi:rollback-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $innerStore = new ArrayChainedChallengeStateStore();
        $indeterminate = new RollbackLostReplyChainStore($innerStore, throwAfterIssued: true);
        $chainService = $this->chainService($indeterminate);
        ['chainId' => $chainId, 'ticket' => $ticket] = $this->openChain($chainService);
        // From here on the chain state is unreadable: the issuance
        // transition throws AND the recovery read fails — indeterminate.
        $indeterminate->readThrows = true;

        $risk = $this->riskStack();
        $controller = $this->chainController($storage, $chainService, $risk, outstanding: $outstanding);

        // markIssued throws and the state cannot be read: indeterminate —
        // the challenge may be the authoritative issued stage-2. The
        // minted challenge is retained, the slot is NOT rolled back and
        // the reservation is NOT released.
        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
        self::assertSame(503, $response->getStatusCode(), 'an indeterminate chain issuance is the retryable 503');
        self::assertSame(1, $client->counters[$this->sourceKey()] ?? 0, 'an INDETERMINATE chain issuance must NOT prematurely roll back the slot');
        self::assertCount(1, (new \ReflectionObject($storage))->getProperty('records')->getValue($storage), 'the minted challenge is retained (never delete state that may be authoritative)');

        // The transition DID run inside the throwing call — the chain is
        // the authoritative issued stage-2 (read through the inner store,
        // because the decorator's recovery read fails on issued records).
        $records = (new \ReflectionObject($innerStore))->getProperty('records')->getValue($innerStore);
        self::assertSame('issued', $records[$chainId]['state'], 'the chain is durably issued — exactly why the rollback must NOT run');
    }
}

/**
 * A storage whose mint step throws the configured exception on demand
 * — the store() call itself — the failure-injection seam for the
 * post-admission issuance failure paths. The exception type is
 * caller-controlled, so a single fixture exercises the
 * InvalidArgumentException and the ReplicaWait paths. Every other
 * operation delegates to the wrapped storage.
 */
final class ThrowingMintStorage implements StorageInterface
{
    public ?\Throwable $mintError = null;

    public function __construct(private readonly StorageInterface $inner)
    {
    }

    public function store(\KiwiCaptcha\ChallengeRecord $record): void
    {
        if ($this->mintError !== null) {
            throw $this->mintError;
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
 * A transactional chain-state decorator that runs the real issuance
 * transition and then throws (a lost reply), and can additionally make
 * the recovery read fail (the indeterminate outcome).
 */
final class RollbackLostReplyChainStore implements TransactionalChainedChallengeStateStore
{
    /** Whether the recovery read throws (the indeterminate outcome). */
    public bool $readThrows = false;

    public function __construct(
        private readonly TransactionalChainedChallengeStateStore $inner,
        private readonly bool $throwAfterIssued = false,
    ) {
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
        // The indeterminate seam: after the issuance transition the record
        // is issued — the recovery read of such a record fails.
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
 * A minimal in-memory stand-in for Predis\Client covering exactly the
 * outstanding-challenge scripts this test exercises: the atomic issue
 * (per-source cap + live-membership cap -> INCR + EXPIRE the source
 * counter and `ZADD` the nonce at its absolute expiry). Also covered:
 * the best-effort solve and the aborted-before-handoff rollback (decr
 * floored at 0 plus a ZREM of the nonce). The counters and the live
 * membership are observable for the slot assertions.
 */
/**
 * A risk state store whose feedback observation write throws — the
 * post-stage-2-commit risk feedback failure injection.
 */
/**
 * A storage whose store() write throws a generic backend failure — the
 * mint can fail before the controller's $challenge variable is assigned.
 */


final class ThrowingFeedbackRiskStore implements \KiwiCaptcha\Risk\Storage\RiskStateStoreInterface
{
    private readonly \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore $inner;

    public function __construct(\KiwiCaptcha\Risk\SignalVector $vector)
    {
        $this->inner = new \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore($vector);
    }

    public function observe(\KiwiCaptcha\Risk\RiskObservation $observation): \KiwiCaptcha\Risk\SignalVector
    {
        // Only the post-commit ChallengeIssued feedback write throws; the
        // pre-mint assessment observe passes through untouched.
        if ($observation->event === \KiwiCaptcha\Risk\RiskEventKind::ChallengeIssued) {
            throw new \RuntimeException('simulated risk feedback failure');
        }

        return $this->inner->observe($observation);
    }

    public function registerOutcome(string $decisionId, int $scope, int $decisionHour, int $score): bool
    {
        return false;
    }

    public function confirmOutcome(string $decisionId, bool $legitimate): int
    {
        return 0;
    }

    public function correctOutcome(string $decisionId, bool $legitimate): bool
    {
        return false;
    }
}

final class RollbackFakeRedis extends \Predis\Client
{
    /** @var array<string, int> plain incr counters */
    public array $counters = [];

    /** @var array<string, array<string, float>> live-outstanding membership: key => nonce => score */
    public array $zsets = [];

    /** @var array<string, string> plain strings (the nonce sidecars) */
    public array $strings = [];

    public function __construct()
    {
        // Deliberately skip the parent constructor: no connection setup.
    }

    private function timeMs(): float
    {
        return (float) (time() * 1000);
    }

    public function __call($commandID, $arguments)
    {
        if (strtoupper((string) $commandID) === 'GET') {
            return $this->strings[(string) $arguments[0]] ?? null;
        }
        if (strtoupper((string) $commandID) !== 'EVAL') {
            throw new \LogicException('unexpected command '.$commandID);
        }
        $script = (string) $arguments[0];
        $numKeys = (int) $arguments[1];
        $keys = \array_slice($arguments, 2, $numKeys);
        $rest = \array_slice($arguments, 2 + $numKeys);

        if (str_contains($script, 'Outstanding challenge issuance')) {
            // OutstandingChallenges::issue: keys[1] the per-source
            // membership ZSET (member = <source>:<nonce>, score = absolute
            // expiry), keys[2] the global LIVE-outstanding ZSET, keys[3]
            // the nonce sidecar; argv[1] source cap, argv[2] global cap,
            // argv[3] TTL seconds, argv[4] absolute expiry (the score),
            // argv[5] the minted nonce, argv[6] the source pseudonym.
            $sourceZset = (string) $keys[0];
            $global = (string) $keys[1];
            $sidecar = (string) $keys[2];
            $pseudonym = (string) $rest[5];
            $liveUntil = (int) floor($this->timeMs() / 1000) + (int) $rest[3];
            if ($this->sourceCount($sourceZset) >= (int) $rest[0]) {
                return 0;
            }
            if (\count($this->zsets[$global] ?? []) >= (int) $rest[1]) {
                return -1;
            }
            $this->zsets[$sourceZset][(string) $rest[4]] = (float) $liveUntil;
            $this->zsets[$global][(string) $rest[4]] = (float) $liveUntil;
            $this->strings[$sidecar] = $pseudonym;
            $this->mirrorSourceCount($sourceZset);

            return 1;
        }

        if (str_contains($script, 'Outstanding challenge release')) {
            // OutstandingChallenges::solved / ::abortedBeforeHandoff:
            // keys[1] the global live ZSET, keys[2] the nonce sidecar,
            // keys[3] the original source's membership ZSET; argv[1] the
            // released nonce, argv[2] the caller-resolved source. One-shot,
            // nonce-authoritative.
            $global = (string) $keys[0];
            $sidecar = (string) $keys[1];
            $sourceZset = (string) $keys[2];
            $nonce = (string) $rest[0];
            $expectedSource = (string) $rest[1];
            $removed = 0;
            if (isset($this->zsets[$global][$nonce])) {
                unset($this->zsets[$global][$nonce]);
                $removed = 1;
                if (isset($this->strings[$sidecar]) && (string) $this->strings[$sidecar] === $expectedSource) {
                    unset($this->zsets[$sourceZset][$nonce]);
                    unset($this->strings[$sidecar]);
                    $this->mirrorSourceCount($sourceZset);
                }
            }

            return $removed;
        }

        throw new \LogicException('unexpected script');
    }

    private function sourceCount(string $sourceZset): int
    {
        return \count($this->zsets[$sourceZset] ?? []);
    }

    private function mirrorSourceCount(string $sourceZset): void
    {
        $this->counters[$sourceZset] = $this->sourceCount($sourceZset);
    }
}
