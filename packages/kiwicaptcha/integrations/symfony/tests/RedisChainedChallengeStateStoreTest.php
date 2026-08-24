<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\ArrayChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\MalformedChainedChallengeStateException;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Storage\ReplicaWaitException;
use PHPUnit\Framework\TestCase;

/**
 * The Redis-backed chain state store's Lua state machine, exercised
 * against an in-memory Redis fake emulating the store's command surface
 * (GET / SET with the EX options array / TTL / time / eval with the
 * chain scripts interpreted by marker). Covers the transaction-obligation
 * create-or-get, the owner-scoped short reservation lease (redis time +
 * min(lease, remaining TTL)), the idempotent issued transition, the
 * terminal verified transition with the atomic obligation deletion, the
 * nonce-pinned rearm and the owner-gated release. This is the production
 * concurrency path of the chained-challenge state machine.
 */
final class RedisChainedChallengeStateStoreTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private ?ChainRedisFake $fake = null;

    private function store(): RedisChainedChallengeStateStore
    {
        $this->fake = new ChainRedisFake();

        return new RedisChainedChallengeStateStore($this->fake, 'kiwi-test');
    }

    private function waitingStore(int $waitReplicas = 1, int $waitTimeoutMs = 100): RedisChainedChallengeStateStore
    {
        $this->fake = new ChainRedisFake();

        return new RedisChainedChallengeStateStore($this->fake, 'kiwi-test', $waitReplicas, $waitTimeoutMs);
    }

    private function makeNonce(): string
    {
        return base64_encode(random_bytes(32));
    }

    /** @return array{0: ChainedChallengeTicketService, 1: \BelConsulting\KiwiCaptchaBundle\Risk\ChainRequirement} */
    private function issueRequirement(RedisChainedChallengeStateStore $store, string $binding = 'tx-binding'): array
    {
        $service = new ChainedChallengeTicketService($store, self::SECRET, 300, 15, null, fn (): int => $this->fake->clockSecs());
        $requirement = $service->requireStage2($this->makeNonce(), 'login', $binding, 1, RiskAction::Argon32, 1300);

        return [$service, $requirement];
    }

    public function testCreateReadAndOwnerScopedShortLease(): void
    {
        $store = $this->store();
        [$service, $requirement] = $this->issueRequirement($store);
        $chainId = $requirement->chainId;

        // The obligation index is created for the exact transaction anchor.
        self::assertSame($chainId, $store->obligationChainId($service->obligationIdFor('login', 'tx-binding', 1)));

        // The plain read sees the full server-held v2 record in the
        // available state.
        $state = $store->read($chainId);
        self::assertIsArray($state);
        self::assertSame('available', $state['state']);
        self::assertSame('argon32', $state['requiredAction']);
        self::assertSame(2, $state['chainDepth']);
        self::assertSame(1, $state['policyVersion']);
        self::assertSame('tx-binding', $state['requestBinding']);
        self::assertSame(64, \strlen((string) $state['obligationId']));
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/D', (string) $state['obligationId']);
        self::assertNull($state['owner']);
        self::assertNull($state['leaseUntil']);
        self::assertNull($state['stage2Nonce']);

        // Owner-scoped reservation with the short fixed lease: available ->
        // reserved with a lease of now + min(15, remaining TTL).
        self::assertSame('available', $store->reserve($chainId, 'owner-a', 15));
        self::assertSame('retry', $store->reserve($chainId, 'owner-a', 15), 'reserve by the SAME owner is a retry');
        self::assertSame('busy', $store->reserve($chainId, 'owner-b', 15), 'reserve by another owner with a live lease is busy');
        $reserved = $store->read($chainId);
        self::assertSame('reserved', $reserved['state']);
        self::assertSame('owner-a', $reserved['owner']);
        self::assertSame(1015, (int) $reserved['leaseUntil'], 'the lease is now (1000) + the SHORT lease (15), never the record TTL');
    }

    public function testExpiredLeaseIsTakenOverBeforeTheTicketExpiry(): void
    {
        $store = $this->store();
        [, $requirement] = $this->issueRequirement($store);
        $chainId = $requirement->chainId;

        self::assertSame('available', $store->reserve($chainId, 'owner-a', 15));
        $this->fake->setTimeMs(1_016_000.0);
        self::assertSame('taken_over', $store->reserve($chainId, 'owner-b', 15), 'an expired reservation is taken over by the next owner');
        $state = $store->read($chainId);
        self::assertSame('owner-b', $state['owner']);
        self::assertSame(1031, (int) $state['leaseUntil']);
    }

    public function testOwnerGatedReleaseAndNonOwnerReleaseNoOp(): void
    {
        $store = $this->store();
        [, $requirement] = $this->issueRequirement($store);
        $chainId = $requirement->chainId;

        self::assertSame('available', $store->reserve($chainId, 'owner-a', 15));
        $store->release($chainId, 'owner-b');
        self::assertSame('busy', $store->reserve($chainId, 'owner-c', 15), 'a non-owner release is an atomic no-op — the reservation stays live');

        $store->release($chainId, 'owner-a');
        $state = $store->read($chainId);
        self::assertSame('available', $state['state'], 'the owner\'s release returns the chain to available');
        self::assertNull($state['owner']);
        self::assertNull($state['leaseUntil']);
        self::assertSame('available', $store->reserve($chainId, 'owner-b', 15), 'the released chain is reservable again');
    }

    public function testMarkIssuedIsIdempotentAndOwnerGated(): void
    {
        $store = $this->store();
        [, $requirement] = $this->issueRequirement($store);
        $chainId = $requirement->chainId;
        $nonce = $this->makeNonce();

        self::assertSame('not_owner', $store->markIssued($chainId, 'owner-other', $nonce), 'an unreserved chain cannot be issued by a stranger');
        self::assertSame('available', $store->reserve($chainId, 'owner-a', 15));
        self::assertSame('issued_new', $store->markIssued($chainId, 'owner-a', $nonce));
        self::assertSame('issued_same', $store->markIssued($chainId, 'owner-a', $nonce), 'same-nonce retry is idempotent (a lost reply is recoverable)');
        self::assertSame('conflict', $store->markIssued($chainId, 'owner-a', $this->makeNonce()), 'a different nonce on an issued chain is a conflict');
        $state = $store->read($chainId);
        self::assertSame('issued', $state['state']);
        self::assertSame($nonce, $state['stage2Nonce']);
        self::assertNull($state['owner']);
        self::assertNull($state['leaseUntil']);
        self::assertSame('issued', $store->reserve($chainId, 'owner-b', 15), 'an issued chain is never re-reservable (no second mint)');
    }

    public function testMarkVerifiedIsTerminalAndDeletesTheObligation(): void
    {
        $store = $this->store();
        [$service, $requirement] = $this->issueRequirement($store);
        $chainId = $requirement->chainId;
        $nonce = $this->makeNonce();
        $obligationId = $service->obligationIdFor('login', 'tx-binding', 1);

        self::assertSame('available', $store->reserve($chainId, 'owner-a', 15));
        self::assertSame('issued_new', $store->markIssued($chainId, 'owner-a', $nonce));
        self::assertSame('verified_new', $store->markVerified($chainId, $nonce));
        self::assertSame('verified_same', $store->markVerified($chainId, $nonce), 'markVerified is idempotent (a lost reply is confirmable)');
        self::assertSame('conflict', $store->markVerified($chainId, $this->makeNonce()));
        self::assertNull($store->obligationChainId($obligationId), 'the terminal transition deletes the obligation mapping');
        $state = $store->read($chainId);
        self::assertSame('verified', $state['state'], 'the terminal verified record is kept until its TTL');
        self::assertSame($nonce, $state['stage2Nonce']);
        self::assertSame('verified', $store->reserve($chainId, 'owner-b', 15), 'a verified chain is terminal');
    }

    public function testRearmIssuedIsPinnedToTheExpectedNonce(): void
    {
        $store = $this->store();
        [, $requirement] = $this->issueRequirement($store);
        $chainId = $requirement->chainId;
        $nonce = $this->makeNonce();

        self::assertSame('available', $store->reserve($chainId, 'owner-a', 15));
        self::assertSame('issued_new', $store->markIssued($chainId, 'owner-a', $nonce));
        self::assertFalse($store->rearmIssued($chainId, $this->makeNonce()), 'rearm with a different nonce is an atomic no-op');
        self::assertTrue($store->rearmIssued($chainId, $nonce), 'rearm with the exact expected nonce returns the chain to available');
        $state = $store->read($chainId);
        self::assertSame('available', $state['state']);
        self::assertNull($state['stage2Nonce']);
    }

    public function testMissingChainAnswersMissing(): void
    {
        $store = $this->store();
        self::assertSame('missing', $store->reserve('no-such-chain', 'owner-a', 15));
        self::assertNull($store->read('no-such-chain'));
        self::assertNull($store->obligationChainId(str_repeat('a', 64)));
    }

    public function testCorruptServerRecordFailsClosed(): void
    {
        $store = $this->store();
        [, $requirement] = $this->issueRequirement($store);
        $chainId = $requirement->chainId;
        $record = $this->fake->strings['{kiwi:kiwi-test}:chain:'.$chainId];
        $corrupt = json_decode($record, true, 8, JSON_THROW_ON_ERROR);
        unset($corrupt['requiredAction']);
        $this->fake->strings['{kiwi:kiwi-test}:chain:'.$chainId] = (string) json_encode($corrupt, JSON_THROW_ON_ERROR);

        $this->expectException(MalformedChainedChallengeStateException::class);
        $store->read($chainId);
    }

    public function testTerminalTransitionsWaitOnTheFreshMutationOnly(): void
    {
        // THE verified-WAIT gating of the chain terminal transitions: the
        // fresh issued -> verified / step_up_required / denied writes (and
        // the issued transition) WAIT for the configured replica count;
        // the idempotent same-state replays and the refusals perform no
        // write and never WAIT.
        $store = $this->waitingStore();
        [, $requirement] = $this->issueRequirement($store);
        self::assertCount(1, $this->fake->waits(), 'the obligation create-or-get (fresh chain creation) WAITs');
        $chainId = $requirement->chainId;
        $nonce = $this->makeNonce();
        $this->fake->calls = [];

        // A reservation is a short-lease transient claim, never a
        // terminal write: no WAIT.
        self::assertSame('available', $store->reserve($chainId, 'owner-a', 15));
        self::assertCount(0, $this->fake->waits(), 'a reservation never WAITs');

        self::assertSame('issued_new', $store->markIssued($chainId, 'owner-a', $nonce));
        self::assertCount(1, $this->fake->waits(), 'the fresh issued transition WAITs');
        $this->fake->calls = [];
        self::assertSame('issued_same', $store->markIssued($chainId, 'owner-a', $nonce));
        self::assertCount(0, $this->fake->waits(), 'an idempotent same-state replay never WAITs');

        self::assertSame('verified_new', $store->markVerified($chainId, $nonce));
        self::assertCount(1, $this->fake->waits(), 'the fresh terminal verified transition WAITs');
        $this->fake->calls = [];
        self::assertSame('verified_same', $store->markVerified($chainId, $nonce));
        self::assertCount(0, $this->fake->waits(), 'the verified same-state replay never WAITs');
        self::assertSame('conflict', $store->markVerified($chainId, $this->makeNonce()));
        self::assertCount(0, $this->fake->waits(), 'a conflict refusal never WAITs');
    }

    public function testStepUpDeniedAndTransactionTerminalizationsWaitOnTheFreshMutation(): void
    {
        $store = $this->waitingStore();
        $nonce = $this->makeNonce();

        // step-up: the fresh terminal write WAITs, the same-state replay
        // and the conflict refusal never do.
        [$stepUpService, $stepUpRequirement] = $this->issueRequirement($store, 'tx-stepup');
        $stepUpChainId = $stepUpRequirement->chainId;
        $this->fake->calls = [];
        self::assertSame('available', $store->reserve($stepUpChainId, 'owner-a', 15));
        self::assertSame('issued_new', $store->markIssued($stepUpChainId, 'owner-a', $nonce));
        $this->fake->calls = [];
        self::assertSame('step_up_required_new', $store->markStepUpRequired($stepUpChainId, $nonce));
        self::assertCount(1, $this->fake->waits(), 'the fresh terminal step-up transition WAITs');
        $this->fake->calls = [];
        self::assertSame('step_up_required_same', $store->markStepUpRequired($stepUpChainId, $nonce));
        self::assertCount(0, $this->fake->waits(), 'the step-up same-state replay never WAITs');
        self::assertSame('conflict', $store->markStepUpRequired($stepUpChainId, $this->makeNonce()));
        self::assertCount(0, $this->fake->waits(), 'a step-up conflict refusal never WAITs');

        // denied: fresh chain (available -> issued -> denied).
        [$denyService, $denyRequirement] = $this->issueRequirement($store, 'tx-deny');
        $denyChainId = $denyRequirement->chainId;
        $this->fake->calls = [];
        self::assertSame('available', $store->reserve($denyChainId, 'owner-a', 15));
        self::assertSame('issued_new', $store->markIssued($denyChainId, 'owner-a', $nonce));
        $this->fake->calls = [];
        self::assertSame('denied_new', $store->markDenied($denyChainId, $nonce));
        self::assertCount(1, $this->fake->waits(), 'the fresh terminal denied transition WAITs');
        $this->fake->calls = [];
        self::assertSame('denied_same', $store->markDenied($denyChainId, $nonce));
        self::assertCount(0, $this->fake->waits(), 'the denied same-state replay never WAITs');

        // obligation-bound transaction terminalizations: fresh write
        // WAITs, idempotent replay and refusals never do.
        [$txDenyService, $txDenyRequirement] = $this->issueRequirement($store, 'tx-tdeny');
        $txDenyObligationId = $txDenyService->obligationIdFor('login', 'tx-tdeny', 1);
        $this->fake->calls = [];
        self::assertSame('denied_new', $store->markTransactionDenied($txDenyRequirement->chainId, $txDenyObligationId));
        self::assertCount(1, $this->fake->waits(), 'the fresh transaction denial terminalization WAITs');
        $this->fake->calls = [];
        self::assertSame('denied_same', $store->markTransactionDenied($txDenyRequirement->chainId, $txDenyObligationId));
        self::assertCount(0, $this->fake->waits(), 'the repeated transaction denial never WAITs');

        [$txStepService, $txStepRequirement] = $this->issueRequirement($store, 'tx-tstepup');
        $txStepObligationId = $txStepService->obligationIdFor('login', 'tx-tstepup', 1);
        $this->fake->calls = [];
        self::assertSame('step_up_required_new', $store->markTransactionStepUpRequired($txStepRequirement->chainId, $txStepObligationId));
        self::assertCount(1, $this->fake->waits(), 'the fresh transaction step-up terminalization WAITs');
        $this->fake->calls = [];
        self::assertSame('step_up_required_same', $store->markTransactionStepUpRequired($txStepRequirement->chainId, $txStepObligationId));
        self::assertCount(0, $this->fake->waits(), 'the repeated transaction step-up never WAITs');
        self::assertSame('conflict', $store->markTransactionStepUpRequired($txDenyRequirement->chainId, $txDenyObligationId));
        self::assertCount(0, $this->fake->waits(), 'a terminal-conflict refusal never WAITs');
        self::assertNotSame($stepUpChainId, $denyChainId, 'each terminalization drives its own chain');
    }

    public function testRearmAndObligationDeletionWaitOnTheFreshMutation(): void
    {
        $store = $this->waitingStore();
        [, $requirement] = $this->issueRequirement($store);
        $chainId = $requirement->chainId;
        $nonce = $this->makeNonce();
        $this->fake->calls = [];

        self::assertSame('available', $store->reserve($chainId, 'owner-a', 15));
        self::assertSame('issued_new', $store->markIssued($chainId, 'owner-a', $nonce));
        $this->fake->calls = [];
        self::assertFalse($store->rearmIssued($chainId, $this->makeNonce()), 'a rearm with a different nonce is an atomic no-op');
        self::assertCount(0, $this->fake->waits(), 'a refused rearm never WAITs');
        self::assertTrue($store->rearmIssued($chainId, $nonce));
        self::assertCount(1, $this->fake->waits(), 'the fresh rearm WAITs');
        $this->fake->calls = [];

        // The obligation deletion: only the fresh compare-delete that
        // actually deleted WAITs; the no-op second delete never does.
        $obligationId = (string) $store->read($chainId)['obligationId'];
        $store->deleteObligation($chainId, $obligationId);
        self::assertCount(1, $this->fake->waits(), 'the fresh obligation deletion WAITs');
        $this->fake->calls = [];
        $store->deleteObligation($chainId, $obligationId);
        self::assertCount(0, $this->fake->waits(), 'a compare-delete that deleted nothing never WAITs');
    }

    public function testNonMutatingPathsNeverWait(): void
    {
        $store = $this->waitingStore();
        [$service, $requirement] = $this->issueRequirement($store);
        $chainId = $requirement->chainId;
        $this->fake->calls = [];

        // reads
        self::assertIsArray($store->read($chainId));
        self::assertSame($chainId, $store->obligationChainId($service->obligationIdFor('login', 'tx-binding', 1)));
        self::assertCount(0, $this->fake->waits(), 'reads never WAIT');

        // reservation arms: available / retry / busy / taken_over
        self::assertSame('available', $store->reserve($chainId, 'owner-a', 15));
        self::assertSame('retry', $store->reserve($chainId, 'owner-a', 15));
        self::assertSame('busy', $store->reserve($chainId, 'owner-b', 15));
        self::assertCount(0, $this->fake->waits(), 'the reservation arms never WAIT');
        $this->fake->setTimeMs(1_016_000.0);
        self::assertSame('taken_over', $store->reserve($chainId, 'owner-b', 15));
        self::assertCount(0, $this->fake->waits(), 'an expired-lease takeover never WAITs');
        $store->release($chainId, 'owner-b');
        self::assertCount(0, $this->fake->waits(), 'a release never WAITs');

        // refusals: not_owner / conflict / missing
        self::assertSame('not_owner', $store->markIssued($chainId, 'owner-x', $this->makeNonce()));
        self::assertSame('conflict', $store->markDenied($chainId, $this->makeNonce()));
        self::assertSame('missing', $store->markDenied('no-such-chain', $this->makeNonce()));
        self::assertSame('missing', $store->reserve('no-such-chain', 'owner-a', 15));
        self::assertCount(0, $this->fake->waits(), 'the refusals never WAIT');
    }

    public function testViolatedAckFailsClosedAfterTheFreshMutation(): void
    {
        // A returned Deny must never be reported without replication: the
        // replica set never acknowledges, so the fresh denied transition
        // raises ReplicaWaitException after exactly one WAIT — the caller
        // cannot treat the chain as terminal.
        $store = $this->waitingStore();
        [, $requirement] = $this->issueRequirement($store);
        $chainId = $requirement->chainId;
        $nonce = $this->makeNonce();
        self::assertSame('available', $store->reserve($chainId, 'owner-a', 15));
        self::assertSame('issued_new', $store->markIssued($chainId, 'owner-a', $nonce));
        $this->fake->calls = [];
        $this->fake->waitAck = 0;

        try {
            $store->markDenied($chainId, $nonce);
            self::fail('a terminal transition whose write was not replicated must fail closed');
        } catch (ReplicaWaitException $e) {
            self::assertStringContainsString('acknowledged 0 of 1 requested replicas after the denied transition', $e->getMessage());
        }
        self::assertCount(1, $this->fake->waits(), 'the failed terminal transition issued exactly one WAIT');

        // The create-or-get fresh creation fails closed the same way.
        $this->fake->calls = [];
        try {
            $store->createOrGetObligation(str_repeat('a', 64), 'chain-wait-b', $this->makeNonce(), 'login', '', 'sha18', 1, 1, 1300, 300);
            self::fail('an obligation creation whose write was not replicated must fail closed');
        } catch (ReplicaWaitException $e) {
            self::assertStringContainsString('after the obligation create-or-get', $e->getMessage());
        }
        self::assertCount(1, $this->fake->waits(), 'the failed create-or-get issued exactly one WAIT');
    }

    public function testCreateOrGetObligationWaitsOnlyWhenItMutates(): void
    {
        $store = $this->waitingStore();
        [$service, $requirement] = $this->issueRequirement($store);
        self::assertCount(1, $this->fake->waits(), 'the fresh obligation create-or-get WAITs');
        $this->fake->calls = [];

        // Same-floor recovery of the existing chain: no write -> no WAIT.
        $recovered = $service->requireStage2($this->makeNonce(), 'login', 'tx-binding', 1, RiskAction::Argon32, 1300);
        self::assertSame($requirement->chainId, $recovered->chainId);
        self::assertCount(0, $this->fake->waits(), 'a non-mutating create-or-get recovery never WAITs');

        // A stronger reassessment raises the floor: a fresh write -> WAIT.
        $raised = $service->requireStage2($this->makeNonce(), 'login', 'tx-binding', 1, RiskAction::Argon64, 1300);
        self::assertSame($requirement->chainId, $raised->chainId);
        self::assertCount(1, $this->fake->waits(), 'the rank-raising create-or-get mutation WAITs');
    }

    public function testCreateOrGetObligationMovedMappingConverges(): void
    {
        // The pointed-at chain is a DECLARED key resolved from a plain
        // read and re-verified inside the script: when a concurrent
        // create-or-get moves the mapping between the read and the
        // script, the script answers 'moved' and the caller re-reads and
        // retries — the resolution converges on the moved chain instead
        // of silently creating a second chain.
        $store = $this->store();
        $chainId = 'chain-'.base64_encode(random_bytes(32));
        $obligationId = hash('sha256', 'txn-moved');
        $movedChainId = 'chain-'.base64_encode(random_bytes(32));
        $nonce = $this->makeNonce();
        $ttl = 300;
        $expires = (int) $this->fake->clockSecs() + $ttl;

        // Pre-create the moved chain + move the obligation mapping exactly
        // once (simulating a concurrent request that created its chain and
        // won the mapping).
        $movedKey = '{kiwi:kiwi-test}:chain:'.$movedChainId;
        $obligationKey = '{kiwi:kiwi-test}:chain-obligation:'.$obligationId;
        $movedRec = [
            'v' => 2, 'stage1Nonce' => $nonce, 'scope' => 'login',
            'obligationId' => $obligationId, 'requiredAction' => 'sha16',
            'requiredRank' => RiskAction::from('sha16')->rank(), 'policyVersion' => 1,
            'chainDepth' => 2, 'state' => 'available', 'owner' => null,
            'leaseUntil' => null, 'stage2Nonce' => null,
            'requestBinding' => null, 'expiresAt' => $expires,
        ];
        $this->fake->strings[$movedKey] = (string) json_encode($movedRec, JSON_THROW_ON_ERROR);
        $this->fake->onCreateOrGet = function () use ($obligationKey, $movedChainId): void {
            $this->fake->onCreateOrGet = null;
            $this->fake->strings[$obligationKey] = $movedChainId;
            $this->fake->expirations[$obligationKey] = (int) ($this->fake->clockSecs() * 1000 + 300 * 1000);
        };

        $resolved = $store->createOrGetObligation($obligationId, $chainId, $nonce, 'login', '', 'sha16', RiskAction::from('sha16')->rank(), 1, $expires, $ttl);
        self::assertSame($movedChainId, $resolved, 'the retry converges on the chain the mapping moved to');
        self::assertSame($movedChainId, $store->obligationChainId($obligationId), 'the mapping still points at the moved chain');
    }

    public function testArrayStoreObservesTheSameMachineWithoutTheReplicaBarrier(): void
    {
        // The in-memory store has no replicas: the identical terminal
        // sequence produces the identical outcomes and there is no WAIT
        // concept to invoke (single-process semantics).
        $array = new ArrayChainedChallengeStateStore(now: static fn (): float => 1000.0);
        $service = new ChainedChallengeTicketService($array, self::SECRET, 300, 15, null, static fn (): int => 1000);
        $requirement = $service->requireStage2($this->makeNonce(), 'login', 'tx-array', 1, RiskAction::Argon32, 1300);
        $obligationId = $service->obligationIdFor('login', 'tx-array', 1);
        $nonce = $this->makeNonce();

        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', $nonce));
        self::assertSame(ChainVerifiedResult::DeniedNew, $service->markDenied($requirement->chainId, $nonce));
        self::assertSame(ChainVerifiedResult::DeniedSame, $service->markDenied($requirement->chainId, $nonce), 'idempotent, exactly like the Redis machine');
        self::assertSame('denied', $service->requirementFor($requirement->chainId)?->state, 'the terminal record is kept');
        self::assertSame($requirement->chainId, $service->findOpenRequirement('login', 'tx-array', 1)?->chainId, 'the obligation mapping is KEPT');
        self::assertSame(ChainReservationResult::Denied, $service->reserveStage2($requirement->chainId, 'owner-b'));
        self::assertSame(ChainVerifiedResult::DeniedSame, $service->markTransactionDenied($requirement->chainId, $obligationId), 'a repeated same-kind terminalization is idempotent');
        self::assertSame(ChainVerifiedResult::Conflict, $service->markTransactionStepUpRequired($requirement->chainId, $obligationId), 'the OTHER terminal disposition can never flip a terminal chain');
    }

    public function testVerifiedWaitRefusesUnsupportedPredisTopologiesAtConstruction(): void
    {
        // The same fail-closed construction matrix as the core
        // RedisStorage: the verified barrier is connection-relative, so a
        // Predis replication aggregate is refused before any write can
        // run.
        $aggregate = new \Predis\Connection\Replication\MasterSlaveReplication();
        $client = new class($aggregate) extends \Predis\Client {
            public function __construct(private readonly \Predis\Connection\Replication\ReplicationInterface $connection)
            {
            }

            public function getConnection()
            {
                return $this->connection;
            }
        };

        try {
            new RedisChainedChallengeStateStore($client, 'kiwi-test', 1, 100);
            self::fail('a Predis replication aggregate with waitReplicas > 0 must be refused at construction');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('replication aggregate', $e->getMessage());
        }
        // waitReplicas = 0 stays supported on any client.
        self::assertInstanceOf(RedisChainedChallengeStateStore::class, new RedisChainedChallengeStateStore($client, 'kiwi-test'));
    }
}

/**
 * In-memory stand-in for Predis\Client with exactly the command surface
 * the Redis chain state store uses: GET / SET (with the EX options-array
 * form) / TTL / time / eval. The eval interpreter runs the store's chain
 * scripts by their marker comments: obligation create-or-get with rank
 * raising and stale-mapping repair, the owner-scoped short lease from
 * time + min(lease, remaining TTL) with keepttl, and the idempotent
 * issued transition. The terminal verified transition deletes the
 * obligation atomically; the nonce-pinned rearm and the owner-gated
 * release complete the surface. The clock advances through
 * {@see self::setTimeMs()} so the lease expiry is enforceable.
 */
final class ChainRedisFake extends \Predis\Client
{
    /** @var array<string, string> plain strings (the chain/obligation records) */
    public array $strings = [];

    /** @var array<string, int> expire deadlines in ms */
    public array $expirations = [];

    /** @var list<array{0: string, 1: list<mixed>}> every command issued, WAIT included */
    public array $calls = [];

    /** The WAIT acknowledgement count to answer (violated when < waitReplicas). */
    public int $waitAck = 1;

    private float $clockMs = 1_000_000.0;

    public function clockSecs(): int
    {
        return (int) floor($this->clockMs / 1000);
    }

    public function __construct()
    {
        // Deliberately skip the parent constructor: no connection setup.
    }

    /** @internal test hook: advance the fake Redis server clock (ms). */
    public function setTimeMs(float $ms): void
    {
        $this->clockMs = $ms;
    }

    /** @return list<array{0: string, 1: list<mixed>}> the WAIT commands issued */
    public function waits(): array
    {
        return array_values(array_filter($this->calls, static fn (array $c): bool => $c[0] === 'WAIT'));
    }

    public function __call($commandID, $arguments)
    {
        $this->calls[] = [strtoupper((string) $commandID), $arguments];

        return match (strtoupper((string) $commandID)) {
            'GET' => $this->strings[(string) $arguments[0]] ?? null,
            'SET' => $this->fakeSet($arguments),
            'TTL' => $this->fakeTtl((string) $arguments[0]),
            'TIME' => $this->fakeTime(),
            'EVAL' => $this->fakeEval($arguments),
            default => throw new \LogicException('unexpected command '.$commandID),
        };
    }

    /** The raw-command escape hatch the store's verified WAIT uses. */
    public function executeRaw(array $arguments, &$error = null): mixed
    {
        $this->calls[] = [strtoupper((string) ($arguments[0] ?? '')), \array_slice($arguments, 1)];

        return $this->waitAck;
    }

    private function fakeSet(array $arguments): ?string
    {
        $key = (string) $arguments[0];
        $value = (string) $arguments[1];
        $ttl = null;
        if (isset($arguments[2]) && \is_array($arguments[2]) && isset($arguments[2]['EX'])) {
            $ttl = (int) $arguments[2]['EX'];
        }
        $this->strings[$key] = $value;
        if ($ttl !== null) {
            $this->expirations[$key] = (int) ($this->clockMs + $ttl * 1000);
        }

        return 'OK';
    }

    private function fakeTtl(string $key): int
    {
        if (!isset($this->strings[$key])) {
            return -2;
        }
        if (!isset($this->expirations[$key])) {
            return -1;
        }
        $remainingMs = $this->expirations[$key] - $this->clockMs;

        return (int) max(1, floor($remainingMs / 1000));
    }

    /** @return array{0: int, 1: int} [seconds, microseconds] */
    private function fakeTime(): array
    {
        $sec = (int) floor($this->clockMs / 1000);

        return [$sec, (int) round(($this->clockMs - $sec * 1000) * 1000)];
    }

    private function fakeEval(array $arguments): mixed
    {
        $script = (string) $arguments[0];
        $numKeys = (int) $arguments[1];
        $keysAndArgs = \array_slice($arguments, 2);
        $keys = \array_slice($keysAndArgs, 0, $numKeys);
        $args = \array_slice($keysAndArgs, $numKeys);

        if (str_contains($script, 'Chain obligation create-or-get')) {
            return $this->luaCreateOrGet($keys, $args);
        }
        if (str_contains($script, 'Chain reservation')) {
            return $this->luaReserve($keys[0], $args);
        }
        if (str_contains($script, 'Chain issuance')) {
            return $this->luaMarkIssued($keys[0], $args);
        }
        if (str_contains($script, 'Chain verification')) {
            return $this->luaMarkVerified($keys, $args);
        }
        if (str_contains($script, 'Chain step-up')) {
            return $this->luaMarkStepUpRequired($keys[0], $args);
        }
        if (str_contains($script, 'Chain denial')) {
            return $this->luaMarkDenied($keys[0], $args);
        }
        if (str_contains($script, 'Transaction denial')) {
            return $this->luaTransactionDenied($keys, $args);
        }
        if (str_contains($script, 'Transaction step-up')) {
            return $this->luaTransactionStepUpRequired($keys, $args);
        }
        if (str_contains($script, 'Chain rearm')) {
            return $this->luaRearm($keys[0], $args);
        }
        if (str_contains($script, 'Chain release')) {
            return $this->luaRelease($keys[0], $args);
        }
        if (str_contains($script, 'Chain completion')) {
            return $this->luaComplete($keys[0], $args);
        }
        if (str_contains($script, 'Chain obligation compare-delete')) {
            return $this->luaDeleteObligation($keys[0], $args);
        }

        throw new \LogicException('unexpected script');
    }

    /** @var null|\Closure test hook: fires at the top of the create-or-get emulation (mapping-move races). */
    public ?\Closure $onCreateOrGet = null;

    private function luaCreateOrGet(array $keys, array $args): array
    {
        if ($this->onCreateOrGet !== null) {
            ($this->onCreateOrGet)();
        }
        $chainKey = $keys[0];
        $obligationKey = $keys[1];
        $pointedKey = $keys[2];
        $pointedChainId = (string) $args[10];
        $existing = $this->strings[$obligationKey] ?? null;
        if ($existing !== null) {
            if ($existing !== $pointedChainId) {
                return [$pointedChainId, 0, 'moved'];
            }
            $chained = $this->strings[$pointedKey] ?? null;
            if ($chained !== null) {
                $rec = json_decode($chained, true, 8, JSON_THROW_ON_ERROR);
                if (isset($rec['requiredRank']) && \is_int($rec['requiredRank'])) {
                    $newRank = (int) $args[5];
                    if ($newRank > $rec['requiredRank']) {
                        $rec['requiredRank'] = $newRank;
                        $rec['requiredAction'] = (string) $args[4];
                        $this->strings[$pointedKey] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

                        return [$pointedChainId, 1, ''];
                    }

                    return [$pointedChainId, 0, ''];
                }
            }
            if (($this->strings[$obligationKey] ?? null) === $pointedChainId) {
                unset($this->strings[$obligationKey], $this->expirations[$obligationKey]);
            }
        }
        $rec = [
            'v' => 2,
            'stage1Nonce' => (string) $args[2],
            'scope' => (string) $args[3],
            'obligationId' => (string) $args[0],
            'requiredAction' => (string) $args[4],
            'requiredRank' => (int) $args[5],
            'policyVersion' => (int) $args[6],
            'chainDepth' => 2,
            'state' => 'available',
            'owner' => null,
            'leaseUntil' => null,
            'stage2Nonce' => null,
            'requestBinding' => (string) $args[7] !== '' ? (string) $args[7] : null,
            'expiresAt' => (int) $args[8],
        ];
        $ttl = (int) $args[9];
        $this->strings[$chainKey] = (string) json_encode($rec, JSON_THROW_ON_ERROR);
        $this->expirations[$chainKey] = (int) ($this->clockMs + $ttl * 1000);
        $this->strings[$obligationKey] = (string) $args[1];
        $this->expirations[$obligationKey] = (int) ($this->clockMs + $ttl * 1000);

        return [(string) $args[1], 1, ''];
    }

    private function luaReserve(string $key, array $args): string
    {
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return 'missing';
        }
        $ttl = $this->fakeTtl($key);
        if ($ttl <= 0) {
            return 'missing';
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if ($rec['state'] === 'issued') {
            return 'issued';
        }
        if ($rec['state'] === 'verified') {
            return 'verified';
        }
        if ($rec['state'] === 'completed') {
            return 'completed';
        }
        $nowSecs = (int) floor($this->clockMs / 1000);
        if ($rec['state'] === 'reserved') {
            if ($rec['owner'] === $args[0]) {
                return 'retry';
            }
            if ((int) $rec['leaseUntil'] > $nowSecs) {
                return 'busy';
            }
            $lease = min((int) $args[1], $ttl);
            $rec['state'] = 'reserved';
            $rec['owner'] = (string) $args[0];
            $rec['leaseUntil'] = $nowSecs + $lease;
            $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

            return 'taken_over';
        }
        $lease = min((int) $args[1], $ttl);
        $rec['state'] = 'reserved';
        $rec['owner'] = (string) $args[0];
        $rec['leaseUntil'] = $nowSecs + $lease;
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

        return 'available';
    }

    private function luaMarkIssued(string $key, array $args): string
    {
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return 'missing';
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if ($rec['state'] === 'reserved') {
            if ($rec['owner'] !== $args[0]) {
                return 'not_owner';
            }
            $rec['state'] = 'issued';
            $rec['stage2Nonce'] = (string) $args[1];
            $rec['owner'] = null;
            $rec['leaseUntil'] = null;
            $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

            return 'issued_new';
        }
        if ($rec['state'] === 'issued' || $rec['state'] === 'completed') {
            return $rec['stage2Nonce'] === $args[1] ? 'issued_same' : 'conflict';
        }
        if ($rec['state'] === 'verified') {
            return $rec['stage2Nonce'] === $args[1] ? 'verified_same' : 'conflict';
        }

        return 'not_owner';
    }

    private function luaMarkVerified(array $keys, array $args): string
    {
        $key = $keys[0];
        $obligationKey = $keys[1];
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return 'missing';
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if ($rec['state'] === 'verified') {
            return $rec['stage2Nonce'] === $args[0] ? 'verified_same' : 'conflict';
        }
        if (($rec['state'] !== 'issued' && $rec['state'] !== 'completed') || $rec['stage2Nonce'] !== $args[0]) {
            return 'conflict';
        }
        $rec['state'] = 'verified';
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);
        if (($this->strings[$obligationKey] ?? null) === $args[1]) {
            unset($this->strings[$obligationKey], $this->expirations[$obligationKey]);
        }

        return 'verified_new';
    }

    private function luaMarkStepUpRequired(string $key, array $args): string
    {
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return 'missing';
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if ($rec['state'] === 'step_up_required') {
            return $rec['stage2Nonce'] === $args[0] ? 'step_up_required_same' : 'conflict';
        }
        if (($rec['state'] !== 'issued' && $rec['state'] !== 'completed') || $rec['stage2Nonce'] !== $args[0]) {
            return 'conflict';
        }
        $rec['state'] = 'step_up_required';
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

        return 'step_up_required_new';
    }

    private function luaMarkDenied(string $key, array $args): string
    {
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return 'missing';
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if ($rec['state'] === 'denied') {
            return $rec['stage2Nonce'] === $args[0] ? 'denied_same' : 'conflict';
        }
        if (($rec['state'] !== 'issued' && $rec['state'] !== 'completed') || $rec['stage2Nonce'] !== $args[0]) {
            return 'conflict';
        }
        $rec['state'] = 'denied';
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

        return 'denied_new';
    }

    private function luaTransactionDenied(array $keys, array $args): string
    {
        $key = $keys[0];
        $obligationKey = $keys[1];
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return 'missing';
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if (($rec['obligationId'] ?? null) !== $args[1]) {
            return 'obligation_moved';
        }
        $mapped = $this->strings[$obligationKey] ?? null;
        if ($mapped === null) {
            return 'already_completed';
        }
        if ($mapped !== $args[0]) {
            return 'obligation_moved';
        }
        if ($rec['state'] === 'denied') {
            return 'denied_same';
        }
        if ($rec['state'] === 'step_up_required') {
            return 'conflict';
        }
        if ($rec['state'] === 'verified') {
            return 'already_verified';
        }
        if (!\in_array($rec['state'], ['available', 'reserved', 'issued', 'completed'], true)) {
            return 'conflict';
        }
        $rec['state'] = 'denied';
        $rec['owner'] = null;
        $rec['leaseUntil'] = null;
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

        return 'denied_new';
    }

    private function luaTransactionStepUpRequired(array $keys, array $args): string
    {
        $key = $keys[0];
        $obligationKey = $keys[1];
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return 'missing';
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if (($rec['obligationId'] ?? null) !== $args[1]) {
            return 'obligation_moved';
        }
        $mapped = $this->strings[$obligationKey] ?? null;
        if ($mapped === null) {
            return 'already_completed';
        }
        if ($mapped !== $args[0]) {
            return 'obligation_moved';
        }
        if ($rec['state'] === 'step_up_required') {
            return 'step_up_required_same';
        }
        if ($rec['state'] === 'denied') {
            return 'conflict';
        }
        if ($rec['state'] === 'verified') {
            return 'already_verified';
        }
        if (!\in_array($rec['state'], ['available', 'reserved', 'issued', 'completed'], true)) {
            return 'conflict';
        }
        $rec['state'] = 'step_up_required';
        $rec['owner'] = null;
        $rec['leaseUntil'] = null;
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

        return 'step_up_required_new';
    }

    private function luaRearm(string $key, array $args): bool
    {
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return false;
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if ($rec['state'] !== 'issued' || $rec['stage2Nonce'] !== $args[0]) {
            return false;
        }
        $rec['state'] = 'available';
        $rec['stage2Nonce'] = null;
        $rec['owner'] = null;
        $rec['leaseUntil'] = null;
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

        return true;
    }

    private function luaRelease(string $key, array $args): mixed
    {
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return false;
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if ($rec['state'] !== 'reserved' || $rec['owner'] !== $args[0]) {
            return false;
        }
        $rec['state'] = 'available';
        $rec['owner'] = null;
        $rec['leaseUntil'] = null;
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

        return true;
    }

    private function luaComplete(string $key, array $args): mixed
    {
        $existing = $this->strings[$key] ?? null;
        if ($existing === null) {
            return false;
        }
        $rec = json_decode($existing, true, 8, JSON_THROW_ON_ERROR);
        if ($rec['state'] !== 'reserved' || $rec['owner'] !== $args[0]) {
            return false;
        }
        $rec['state'] = 'completed';
        $rec['stage2Nonce'] = (string) $args[1];
        $this->strings[$key] = (string) json_encode($rec, JSON_THROW_ON_ERROR);

        return (string) json_encode($rec, JSON_THROW_ON_ERROR);
    }

    private function luaDeleteObligation(string $key, array $args): mixed
    {
        if (($this->strings[$key] ?? null) === $args[0]) {
            unset($this->strings[$key], $this->expirations[$key]);

            return 1;
        }

        return 0;
    }
}
