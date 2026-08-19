<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\ArrayChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\TransactionalChainedChallengeStateStore;
use KiwiCaptcha\Risk\RiskAction;
use PHPUnit\Framework\TestCase;

/**
 * REAL-REDIS integration tests of the transactional chained-challenge
 * state machine (CI service container: redis on 127.0.0.1:6399).
 *
 * Skipped unless a Redis answers at tcp://127.0.0.1:6399. Exercises the
 * atomicity the fakes cannot prove:
 *  - the obligation create-or-get (ONE Lua over the chain + obligation
 *    keys — a repeated stage-1 token returns the SAME chain, a stale
 *    mapping is compare-deleted and repaired),
 *  - the SHORT owner-scoped reservation lease (busy vs expired-lease
 *    takeover),
 *  - the markIssued LOST-REPLY: the real Lua runs, the reply is thrown
 *    away, a RECONNECTED reader confirms the durable issued state,
 *  - markVerified + the atomic obligation deletion,
 *  - rearm (issued -> available, nonce-pinned),
 *  - the auto-resume read (findOpenRequirement without a ticket).
 */
final class RealRedisChainedChallengeTest extends TestCase
{
    private const REDIS_URL = 'tcp://127.0.0.1:6399';

    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const NAMESPACE = 'ci-chain';

    private \Predis\Client $client;

    protected function setUp(): void
    {
        if (!class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis not installed');
        }
        $this->client = new \Predis\Client(self::REDIS_URL);
        try {
            $this->client->ping();
        } catch (\Throwable $e) {
            self::markTestSkipped('Redis unreachable at '.self::REDIS_URL.': '.$e->getMessage());
        }
        $this->client->flushdb();
    }

    private function store(?\Predis\Client $client = null): RedisChainedChallengeStateStore
    {
        return new RedisChainedChallengeStateStore($client ?? $this->client, self::NAMESPACE);
    }

    private function service(?RedisChainedChallengeStateStore $store = null): ChainedChallengeTicketService
    {
        return new ChainedChallengeTicketService($store ?? $this->store(), self::SECRET, 300, 15);
    }

    private function nonce(): string
    {
        return base64_encode(random_bytes(32));
    }

    public function testObligationCreateOrGetReturnsTheSameChainAndRaisesTheRank(): void
    {
        $service = $this->service();
        $expiry = time() + 300;

        $first = $service->requireStage2($this->nonce(), 'login', 'txn-alpha', 1, RiskAction::Argon32, $expiry);
        $second = $service->requireStage2($this->nonce(), 'login', 'txn-alpha', 1, RiskAction::Argon32, $expiry);
        self::assertSame($first->chainId, $second->chainId, 'the create-or-get is atomic over the two keys — the SAME chain returns');

        // The obligation key holds the chain id (never a raw binding).
        $obligationId = $service->obligationIdFor('login', 'txn-alpha', 1);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/D', $obligationId, 'the obligation id is the bounded pseudonymous HMAC');
        self::assertSame($first->chainId, (string) $this->client->get(sprintf('{kiwi:%s}:chain-obligation:%s', self::NAMESPACE, $obligationId)));

        // A STRONGER reassessment raises the floor (never lowers).
        $raised = $service->requireStage2($this->nonce(), 'login', 'txn-alpha', 1, RiskAction::Argon64, $expiry);
        self::assertSame($first->chainId, $raised->chainId);
        self::assertSame(RiskAction::Argon64, $raised->requiredAction);
        $decayed = $service->requireStage2($this->nonce(), 'login', 'txn-alpha', 1, RiskAction::Sha16, $expiry);
        self::assertSame(RiskAction::Argon64, $decayed->requiredAction, 'the floor can never decay');
    }

    public function testStaleObligationPointingAtMissingChainIsRepaired(): void
    {
        $store = $this->store();
        $service = $this->service($store);
        $expiry = time() + 300;

        $requirement = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, $expiry);
        // The chain record vanishes while the obligation stays: the next
        // create-or-get compare-deletes the stale mapping and creates a
        // fresh chain (never a silent stage-1).
        $this->client->del(sprintf('{kiwi:%s}:chain:%s', self::NAMESPACE, $requirement->chainId));
        $fresh = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, $expiry);
        self::assertNotSame($requirement->chainId, $fresh->chainId);
        self::assertSame($fresh->chainId, $service->findOpenRequirement('login', '', 1)?->chainId);
    }

    public function testReservationLeaseBusyAndExpiredLeaseTakeover(): void
    {
        $store = $this->store();
        $service = $this->service($store);
        $requirement = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, time() + 300);

        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
        self::assertSame(ChainReservationResult::Retry, $service->reserveStage2($requirement->chainId, 'owner-a'));
        self::assertSame(ChainReservationResult::Busy, $service->reserveStage2($requirement->chainId, 'owner-b'), 'the live SHORT lease refuses another owner');

        // The record has an expiry (the ticket bound); the lease is
        // now + min(15, remaining TTL).
        $state = $service->requirementFor($requirement->chainId);
        self::assertNotNull($state);
        self::assertGreaterThan(time(), (int) $state->leaseUntil, 'the lease is in the future');
        self::assertLessThanOrEqual(time() + 15, (int) $state->leaseUntil, 'the lease is bounded by the SHORT reservation lease');

        // Expire the lease directly (the record TTL stays): the next
        // reserving owner TAKES OVER.
        $recordKey = sprintf('{kiwi:%s}:chain:%s', self::NAMESPACE, $requirement->chainId);
        $record = json_decode((string) $this->client->get($recordKey), true, 8, JSON_THROW_ON_ERROR);
        $record['leaseUntil'] = time() - 10;
        $this->client->set($recordKey, (string) json_encode($record, JSON_THROW_ON_ERROR), 'EX', max(1, (int) $this->client->ttl($recordKey)));
        self::assertSame(ChainReservationResult::TakenOver, $service->reserveStage2($requirement->chainId, 'owner-b'), 'an expired lease is taken over');

        // A chain record WITHOUT an expiry is corrupted state: fail
        // closed ('missing'), never manufacture a lifetime.
        $recordKey = sprintf('{kiwi:%s}:chain:%s', self::NAMESPACE, $requirement->chainId);
        $this->client->persist($recordKey);
        self::assertSame(ChainReservationResult::Missing, $service->reserveStage2($requirement->chainId, 'owner-c'), 'a record without an expiry fails closed');
    }

    public function testMarkIssuedLostReplyIsDurableAcrossAReconnect(): void
    {
        $store = $this->store();
        $service = $this->service($store);
        $requirement = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, time() + 300);

        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
        // The real Lua runs and the reply is LOST (thrown away): the
        // durable state must be readable by a RECONNECTED client.
        $result = $store->markIssued($requirement->chainId, 'owner-a', 'stage2-nonce');
        self::assertSame('issued_new', $result);

        $reconnected = $this->store(new \Predis\Client(self::REDIS_URL));
        $state = $reconnected->read($requirement->chainId);
        self::assertIsArray($state);
        self::assertSame('issued', $state['state'], 'the issued transition is durable');
        self::assertSame('stage2-nonce', $state['stage2Nonce']);
        self::assertNull($state['owner'], 'the reservation fields are cleared in the issued state');
        self::assertNull($state['leaseUntil']);

        // The idempotent same-nonce retry confirms, never a second mint.
        self::assertSame(ChainIssuedResult::IssuedSame, $service->markIssued($requirement->chainId, 'owner-a', 'stage2-nonce'));
        self::assertSame(ChainIssuedResult::Conflict, $service->markIssued($requirement->chainId, 'owner-a', 'other-nonce'));
    }

    public function testMarkVerifiedDeletesTheObligationAtomically(): void
    {
        $store = $this->store();
        $service = $this->service($store);
        $expiry = time() + 300;
        $requirement = $service->requireStage2($this->nonce(), 'login', 'txn-verified', 1, RiskAction::Argon32, $expiry);
        $obligationId = $service->obligationIdFor('login', 'txn-verified', 1);
        $obligationKey = sprintf('{kiwi:%s}:chain-obligation:%s', self::NAMESPACE, $obligationId);

        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', 'stage2-nonce'));
        self::assertSame((string) $this->client->get($obligationKey), $requirement->chainId, 'the obligation is live before verification');

        self::assertSame(ChainVerifiedResult::VerifiedNew, $service->markVerified($requirement->chainId, 'stage2-nonce'));
        self::assertSame(ChainVerifiedResult::VerifiedSame, $service->markVerified($requirement->chainId, 'stage2-nonce'), 'idempotent');
        self::assertNull($this->client->get($obligationKey), 'the verified transition ATOMICALLY deleted the obligation');
        self::assertSame('verified', $service->requirementFor($requirement->chainId)?->state, 'the terminal record is kept until its TTL');
        self::assertNull($service->findOpenRequirement('login', 'txn-verified', 1), 'no open obligation remains');

        // The compare-delete guard: an obligation repointed at ANOTHER
        // chain must never be unlinked by a stale verified transition.
        $other = $service->requireStage2($this->nonce(), 'login', 'txn-other', 1, RiskAction::Argon32, $expiry);
        $this->client->set($obligationKey, $other->chainId);
        self::assertSame(ChainVerifiedResult::VerifiedSame, $service->markVerified($requirement->chainId, 'stage2-nonce'));
        self::assertSame($other->chainId, (string) $this->client->get($obligationKey), 'a stale delete must never unlink a live mapping');
    }

    public function testRearmPinsTheExpectedNonceAndAutoResumeReadsWithoutATicket(): void
    {
        $store = $this->store();
        $service = $this->service($store);
        $requirement = $service->requireStage2($this->nonce(), 'login', 'txn-rearm', 1, RiskAction::Argon32, time() + 300);

        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', 'stage2-nonce'));

        // A DIFFERENT expected nonce is an atomic no-op.
        self::assertFalse($service->rearmIssued($requirement->chainId, 'other-nonce'));
        self::assertSame('issued', $service->requirementFor($requirement->chainId)?->state);

        // The EXACT nonce rearms to available for a fresh stage-2 mint.
        self::assertTrue($service->rearmIssued($requirement->chainId, 'stage2-nonce'));
        $state = $service->requirementFor($requirement->chainId);
        self::assertSame('available', $state?->state);
        self::assertNull($state?->stage2Nonce);

        // AUTO-RESUME read: findOpenRequirement without any ticket finds
        // the open chain of the transaction.
        $auto = $service->findOpenRequirement('login', 'txn-rearm', 1);
        self::assertNotNull($auto);
        self::assertSame($requirement->chainId, $auto->chainId);
        self::assertSame('available', $auto->state);
    }

    public function testArrayAndRedisObserveOneMachine(): void
    {
        // The same transition sequence on BOTH stores produces the SAME
        // typed results (the in-memory store mirrors the Redis Lua).
        $redisStore = $this->store();
        $arrayStore = new ArrayChainedChallengeStateStore();
        $expiry = time() + 300;

        foreach ([$redisStore, $arrayStore] as $store) {
            $service = new ChainedChallengeTicketService($store, self::SECRET, 300, 15);
            $requirement = $service->requireStage2($this->nonce(), 'login', 'txn-parity', 1, RiskAction::Argon32, $expiry);
            self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
            self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', 'stage2-nonce'));
            self::assertSame(ChainReservationResult::Issued, $service->reserveStage2($requirement->chainId, 'owner-b'));
            self::assertSame(ChainVerifiedResult::VerifiedNew, $service->markVerified($requirement->chainId, 'stage2-nonce'));
            self::assertSame('verified', $service->requirementFor($requirement->chainId)?->state);
            self::assertNull($service->findOpenRequirement('login', 'txn-parity', 1));
        }
    }
}
