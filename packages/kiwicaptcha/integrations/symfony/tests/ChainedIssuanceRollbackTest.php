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
 * The PROVEN-NOT-HANDED-OFF rollback symmetry: once the outstanding
 * admission succeeds, EVERY exit that positively established the
 * challenge was never handed off must return the admitted slot AND
 * release the chain reservation through the controller's SINGLE cleanup
 * primitive (rollbackIssuanceAttempt) — the resource accounting must
 * never depend on which exception type fires (the InvalidArgumentException
 * path returned the reservation but leaked the admitted slot). The
 * successful handoff keeps the slot, and the INDETERMINATE
 * case (the chain state cannot be read after a thrown issuance
 * transition — the challenge may be the authoritative issued stage-2)
 * keeps its existing no-rollback behavior.
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

    private function chainController(StorageInterface $storage, ChainedChallengeTicketService $service, RiskGateway $gateway, ?OutstandingChallenges $outstanding = null): ChallengeController
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

        // The mint (AFTER the outstanding admission succeeded) fails with
        // \InvalidArgumentException — the exception type the controller
        // maps to the 422 INVALID_SCOPE response.
        $mint->mintError = new \InvalidArgumentException('simulated invalid-argument mint failure');
        $risk = $this->riskStack();
        $controller = $this->chainController($mint, $chainService, $risk, outstanding: $outstanding);

        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket, 'request_binding' => 'txn-alpha'], JSON_THROW_ON_ERROR)));
        self::assertSame(422, $response->getStatusCode(), sprintf('an InvalidArgumentException mint failure is the 422 INVALID_SCOPE response: %s', (string) $response->getContent()));
        self::assertStringContainsString('INVALID_SCOPE', (string) $response->getContent());

        // BOTH halves of the proven-not-handed-off accounting returned to
        // their state: the admitted slot is returned (the per-source
        // counter is back at 0 — the GLOBAL counter is never decremented,
        // it decays by EXPIRE) and the chain reservation is released (the
        // chain is available/reserved-free again — the ticket stays
        // reusable).
        self::assertSame(0, $client->counters[$this->sourceKey()] ?? 0, 'the admitted outstanding slot is returned — the per-source counter is back to its prior state');
        self::assertSame(1, $client->counters['{kiwi:rollback-test}:outstanding:global'] ?? 0, 'the GLOBAL counter is never decremented — deployment-wide pressure decays by EXPIRE');
        $requirement = $chainService->requirementFor($chainId);
        self::assertNotNull($requirement);
        self::assertSame('available', $requirement->state, 'the chain reservation is released — the chain is back to available');
        self::assertNull($requirement->owner, 'the released chain is reserved-free');
        self::assertSame(0, \count((new \ReflectionObject($storage))->getProperty('records')->getValue($storage)), 'no challenge record may exist for a mint that failed');

        // The SAME ticket still works end-to-end once the mint recovers —
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

    public function testIndeterminateChainIssuanceDoesNotRollBack(): void
    {
        $storage = new ArrayStorage();
        $client = new RollbackFakeRedis();
        $outstanding = new OutstandingChallenges($client, '{kiwi:rollback-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $innerStore = new ArrayChainedChallengeStateStore();
        $indeterminate = new RollbackLostReplyChainStore($innerStore, throwAfterIssued: true);
        $chainService = $this->chainService($indeterminate);
        ['chainId' => $chainId, 'ticket' => $ticket] = $this->openChain($chainService);
        // From here on the chain state is UNREADABLE: the issuance
        // transition throws AND the recovery read fails — INDETERMINATE.
        $indeterminate->readThrows = true;

        $risk = $this->riskStack();
        $controller = $this->chainController($storage, $chainService, $risk, outstanding: $outstanding);

        // markIssued THROWS and the state CANNOT be read: INDETERMINATE —
        // the challenge may be the authoritative issued stage-2. The
        // minted challenge is RETAINED, the slot is NOT rolled back and
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
 * A storage whose MINT (store()) throws the configured exception on
 * demand — the failure-injection seam for the post-admission issuance
 * failure paths (the exception type is caller-controlled, so a single
 * fixture exercises the InvalidArgumentException and the ReplicaWait
 * paths). Every other operation delegates to the wrapped storage.
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
 * A transactional chain-state decorator that runs the REAL issuance
 * transition and THEN throws (a lost reply), and can additionally make
 * the recovery read fail (the INDETERMINATE outcome).
 */
final class RollbackLostReplyChainStore implements TransactionalChainedChallengeStateStore
{
    /** Whether the recovery read throws (the INDETERMINATE outcome). */
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
        // The INDETERMINATE seam: after the issuance transition the record
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

    public function markTransactionDenied(string $chainId): string
    {
        return $this->inner->markTransactionDenied($chainId);
    }

    public function markTransactionStepUpRequired(string $chainId): string
    {
        return $this->inner->markTransactionStepUpRequired($chainId);
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
 * outstanding-challenge scripts this test exercises: the atomic ISSUE
 * (both caps -> INCR both + EXPIRE), the best-effort SOLVE and the
 * ABORTED-BEFORE-HANDOFF rollback (DECR floored at 0). The counters are
 * observable for the slot assertions.
 */
final class RollbackFakeRedis extends \Predis\Client
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
