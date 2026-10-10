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
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\ChainRedisFake;
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
 * nonce-pinned rearm and the owner-gated release. The fake mirrors the
 * key-lifetime and signed-expiry guards of the Lua scripts and the live
 * read, so the fail-closed corners hold at the unit level too. This is
 * the production concurrency path of the chained-challenge state machine.
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

    public function testObligationChainIdFailsClosedOnACorruptPointedChainOnBothStores(): void
    {
        // The lockstep obligation-read contract, pinned on both stores:
        // a corrupt pointed-at chain record must never silently pass —
        // obligationChainId() follows the mapping only to a
        // strictly-decodable live chain and throws the strict decode
        // exception otherwise, and the mapping itself is never dropped.
        $store = $this->store();
        [$service, $requirement] = $this->issueRequirement($store, 'tx-corrupt');
        $obligationId = $service->obligationIdFor('login', 'tx-corrupt', 1);
        $chainKey = '{kiwi:kiwi-test}:chain:'.$requirement->chainId;
        $corrupt = json_decode($this->fake->strings[$chainKey], true, 8, JSON_THROW_ON_ERROR);
        unset($corrupt['requiredAction']);
        $this->fake->strings[$chainKey] = (string) json_encode($corrupt, JSON_THROW_ON_ERROR);

        try {
            $store->obligationChainId($obligationId);
            self::fail('the Redis obligation read must fail closed on the corrupt pointed-at chain');
        } catch (MalformedChainedChallengeStateException) {
            // expected: the mapping is never silently followed to corrupt state
        }
        self::assertSame($requirement->chainId, $this->fake->strings['{kiwi:kiwi-test}:chain-obligation:'.$obligationId] ?? null, 'the Redis mapping is preserved by the fail-closed read');

        // The Array mirror throws identically and keeps its mapping.
        $array = new ArrayChainedChallengeStateStore();
        $arrayService = new ChainedChallengeTicketService($array, self::SECRET, 300, 15);
        $arrayRequirement = $arrayService->requireStage2($this->makeNonce(), 'login', 'tx-corrupt', 1, RiskAction::Argon32, time() + 300);
        $arrayObligationId = $arrayService->obligationIdFor('login', 'tx-corrupt', 1);
        $records = (new \ReflectionObject($array))->getProperty('records')->getValue($array);
        unset($records[$arrayRequirement->chainId]['requiredAction']);
        (new \ReflectionObject($array))->getProperty('records')->setValue($array, $records);
        try {
            $array->obligationChainId($arrayObligationId);
            self::fail('the Array obligation read must fail closed on the corrupt pointed-at chain');
        } catch (MalformedChainedChallengeStateException) {
            // expected: the corrupt state is never silently dropped
        }
        $obligations = (new \ReflectionObject($array))->getProperty('obligations')->getValue($array);
        self::assertSame($arrayRequirement->chainId, $obligations[$arrayObligationId] ?? null, 'the Array mapping is preserved by the fail-closed read');
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
        // The pointed-at chain is a declared key resolved from a plain
        // read and re-verified inside the script: when a concurrent
        // create-or-get moves the mapping between the read and the
        // script, the script answers 'moved' and the caller re-reads and
        // retries — the resolution converges on the moved chain instead
        // of silently creating a second chain.
        $store = $this->store();
        $chainId = rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');
        $obligationId = hash('sha256', 'txn-moved');
        $movedChainId = rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');
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
            'requirementGeneration' => 1, 'reservedRequirementGeneration' => null,
        ];
        $this->fake->strings[$movedKey] = (string) json_encode($movedRec, JSON_THROW_ON_ERROR);
        // The pointed chain carries a key lifetime, the same authority
        // the read authority enforces; a TTL-less key is corrupt state.
        $this->fake->expirations[$movedKey] = (int) ($expires * 1000);
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
