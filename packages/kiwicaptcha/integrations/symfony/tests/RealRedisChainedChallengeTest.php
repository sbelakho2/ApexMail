<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Risk\ArrayChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\TransactionalChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\StorageInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * real-redis integration tests of the transactional chained-challenge
 * state machine (CI service container: redis on 127.0.0.1:6399).
 *
 * Skipped unless a Redis answers at tcp://127.0.0.1:6399. Exercises the
 * atomicity the fakes cannot prove:
 *  - the obligation create-or-get (one Lua over the chain + obligation
 *    keys — a repeated stage-1 token returns the same chain, a stale
 *    mapping is compare-deleted and repaired).
 *  - the short owner-scoped reservation lease (busy vs expired-lease
 *    takeover).
 *  - the markIssued lost-reply (the real Lua runs, the reply is thrown
 *    away, a reconnected reader confirms the durable issued state).
 *  - markVerified with the atomic obligation deletion.
 *  - rearm (issued -> available, nonce-pinned).
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

    /**
     * A no-op risk gateway for the controller (the terminal-response
     * paths answer before any engine call).
     */
    private function gateway(): RiskGateway
    {
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $engine = new AdaptiveRiskEngine(new FakeRiskStateStore(), $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);

        return new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], policy: $policy);
    }

    private function controller(RedisChainedChallengeStateStore $store, StorageInterface $storage, ?\BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionStore $dispositions = null): ChallengeController
    {
        return new ChallengeController(
            new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage),
            null,
            true,
            $this->gateway(),
            new ContinuityCookie(),
            storage: $storage,
            challengeTtlSecs: 120,
            chainTickets: $this->service($store),
            policyVersion: 1,
            postSolveDispositionStore: $dispositions,
        );
    }

    private function challengeRequest(string $body): Request
    {
        return \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest::create(
            '/kiwi-captcha/challenge',
            'POST',
            [],
            [],
            [],
            ['REMOTE_ADDR' => '198.51.100.7'],
            $body,
        );
    }

    private function nonce(): string
    {
        return base64_encode(random_bytes(32));
    }

    /**
     * A deterministic Kiwi-shaped stage-2 nonce for a literal seed (the
     * strict v2 decode requires the Kiwi base64 nonce shape for
     * stage2Nonce, so the tests never use arbitrary strings).
     */
    private function stageNonce(string $seed): string
    {
        return base64_encode(hash('sha256', 'stage2:'.$seed, true));
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

        // A stronger reassessment raises the floor (never lowers).
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
        // reserving owner takes over.
        $recordKey = sprintf('{kiwi:%s}:chain:%s', self::NAMESPACE, $requirement->chainId);
        $record = json_decode((string) $this->client->get($recordKey), true, 8, JSON_THROW_ON_ERROR);
        $record['leaseUntil'] = time() - 10;
        $this->client->set($recordKey, (string) json_encode($record, JSON_THROW_ON_ERROR), 'EX', max(1, (int) $this->client->ttl($recordKey)));
        self::assertSame(ChainReservationResult::TakenOver, $service->reserveStage2($requirement->chainId, 'owner-b'), 'an expired lease is taken over');

        // A chain record without an expiry is corrupted state: fail
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
        // The real Lua runs and the reply is lost (thrown away): the
        // durable state must be readable by a reconnected client.
        $result = $store->markIssued($requirement->chainId, 'owner-a', $this->stageNonce('stage2-nonce'));
        self::assertSame('issued_new', $result);

        $reconnected = $this->store(new \Predis\Client(self::REDIS_URL));
        $state = $reconnected->read($requirement->chainId);
        self::assertIsArray($state);
        self::assertSame('issued', $state['state'], 'the issued transition is durable');
        self::assertSame($this->stageNonce('stage2-nonce'), $state['stage2Nonce']);
        self::assertNull($state['owner'], 'the reservation fields are cleared in the issued state');
        self::assertNull($state['leaseUntil']);

        // The idempotent same-nonce retry confirms, never a second mint.
        self::assertSame(ChainIssuedResult::IssuedSame, $service->markIssued($requirement->chainId, 'owner-a', $this->stageNonce('stage2-nonce')));
        self::assertSame(ChainIssuedResult::Conflict, $service->markIssued($requirement->chainId, 'owner-a', $this->stageNonce('other-nonce')));
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
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', $this->stageNonce('stage2-nonce')));
        self::assertSame((string) $this->client->get($obligationKey), $requirement->chainId, 'the obligation is live before verification');

        self::assertSame(ChainVerifiedResult::VerifiedNew, $service->markVerified($requirement->chainId, $this->stageNonce('stage2-nonce')));
        self::assertSame(ChainVerifiedResult::VerifiedSame, $service->markVerified($requirement->chainId, $this->stageNonce('stage2-nonce')), 'idempotent');
        self::assertNull($this->client->get($obligationKey), 'the verified transition ATOMICALLY deleted the obligation');
        self::assertSame('verified', $service->requirementFor($requirement->chainId)?->state, 'the terminal record is kept until its TTL');
        self::assertNull($service->findOpenRequirement('login', 'txn-verified', 1), 'no open obligation remains');

        // The compare-delete guard: an obligation repointed at another
        // chain must never be unlinked by a stale verified transition.
        $other = $service->requireStage2($this->nonce(), 'login', 'txn-other', 1, RiskAction::Argon32, $expiry);
        $this->client->set($obligationKey, $other->chainId);
        self::assertSame(ChainVerifiedResult::VerifiedSame, $service->markVerified($requirement->chainId, $this->stageNonce('stage2-nonce')));
        self::assertSame($other->chainId, (string) $this->client->get($obligationKey), 'a stale delete must never unlink a live mapping');
    }

    public function testMarkStepUpRequiredKeepsTheObligationAndIsTerminal(): void
    {
        $store = $this->store();
        $service = $this->service($store);
        $expiry = time() + 300;
        $requirement = $service->requireStage2($this->nonce(), 'login', 'txn-stepup', 1, RiskAction::Argon32, $expiry);
        $obligationId = $service->obligationIdFor('login', 'txn-stepup', 1);
        $obligationKey = sprintf('{kiwi:%s}:chain-obligation:%s', self::NAMESPACE, $obligationId);
        $nonce = $this->stageNonce('stage2-nonce');

        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', $nonce));
        self::assertSame(ChainVerifiedResult::StepUpRequiredNew, $service->markStepUpRequired($requirement->chainId, $nonce));
        self::assertSame(ChainVerifiedResult::StepUpRequiredSame, $service->markStepUpRequired($requirement->chainId, $nonce), 'idempotent');
        self::assertSame(ChainVerifiedResult::Conflict, $service->markStepUpRequired($requirement->chainId, $this->stageNonce('other-nonce')), 'a different nonce on a TERMINAL state is a conflict');
        self::assertSame(ChainVerifiedResult::Conflict, $service->markVerified($requirement->chainId, $nonce), 'a terminal step-up chain can never verify');
        self::assertSame('step_up_required', $service->requirementFor($requirement->chainId)?->state, 'the terminal record is kept until its TTL');
        self::assertSame($nonce, $service->requirementFor($requirement->chainId)?->stage2Nonce);
        self::assertSame($requirement->chainId, (string) $this->client->get($obligationKey), 'the step-up transition KEEPS the obligation');
        self::assertSame($requirement->chainId, $service->findOpenRequirement('login', 'txn-stepup', 1)?->chainId, 'the transaction stays bound to the open chain');
        self::assertSame(ChainReservationResult::StepUpRequired, $service->reserveStage2($requirement->chainId, 'owner-b'), 'the reserve answers the TERMINAL step_up_required state');
    }

    public function testMarkDeniedKeepsTheObligationAndIsTerminal(): void
    {
        $store = $this->store();
        $service = $this->service($store);
        $expiry = time() + 300;
        $requirement = $service->requireStage2($this->nonce(), 'login', 'txn-denied', 1, RiskAction::Argon32, $expiry);
        $obligationId = $service->obligationIdFor('login', 'txn-denied', 1);
        $obligationKey = sprintf('{kiwi:%s}:chain-obligation:%s', self::NAMESPACE, $obligationId);
        $nonce = $this->stageNonce('stage2-nonce');

        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', $nonce));
        self::assertSame(ChainVerifiedResult::DeniedNew, $service->markDenied($requirement->chainId, $nonce));
        self::assertSame(ChainVerifiedResult::DeniedSame, $service->markDenied($requirement->chainId, $nonce), 'idempotent');
        self::assertSame(ChainVerifiedResult::Conflict, $service->markDenied($requirement->chainId, $this->stageNonce('other-nonce')), 'a different nonce on a TERMINAL state is a conflict');
        self::assertSame(ChainVerifiedResult::Conflict, $service->markVerified($requirement->chainId, $nonce), 'a terminal denied chain can never verify');
        self::assertSame(ChainIssuedResult::Conflict, $service->markIssued($requirement->chainId, 'owner-b', $nonce), 'a terminal chain can never be issued again');
        self::assertSame('denied', $service->requirementFor($requirement->chainId)?->state, 'the terminal record is kept until its TTL');
        self::assertSame($nonce, $service->requirementFor($requirement->chainId)?->stage2Nonce);
        self::assertSame($requirement->chainId, (string) $this->client->get($obligationKey), 'the denied transition KEEPS the obligation');
        self::assertSame($requirement->chainId, $service->findOpenRequirement('login', 'txn-denied', 1)?->chainId, 'the transaction stays bound to the open chain');
        self::assertSame(ChainReservationResult::Denied, $service->reserveStage2($requirement->chainId, 'owner-b'), 'the reserve answers the TERMINAL denied state');
    }

    public function testControllerAnswersTheTerminalResponsesForStepUpAndDeniedChains(): void
    {
        $storage = new ArrayStorage();
        $store = $this->store();
        $service = $this->service($store);
        $expiry = time() + 300;
        $controller = $this->controller($store, $storage);

        // A terminal step_up_required chain: the challenge request for the
        // same transaction answers the terminal step_UP_required — never a
        // new stage-1, never a stage-2 challenge.
        $stepUp = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, $expiry);
        $stepUpTicket = $service->ticketFor($stepUp->chainId, $expiry);
        $stepUpNonce = $this->stageNonce('stage2-nonce');
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($stepUp->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($stepUp->chainId, 'owner-a', $stepUpNonce));
        self::assertSame(ChainVerifiedResult::StepUpRequiredNew, $service->markStepUpRequired($stepUp->chainId, $stepUpNonce));

        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $stepUpTicket], JSON_THROW_ON_ERROR)));
        self::assertSame(403, $response->getStatusCode(), 'a step_up_required chain answers the terminal STEP_UP_REQUIRED');
        self::assertStringContainsString('STEP_UP_REQUIRED', (string) $response->getContent());
        self::assertSame('step_up_required', $service->requirementFor($stepUp->chainId)?->state, 'the terminal state survives the request');
        self::assertSame($stepUp->chainId, $service->findOpenRequirement('login', '', 1)?->chainId, 'the obligation survives the request');

        // A terminal denied chain: the challenge request for the same
        // transaction answers the terminal risk-denied response.
        $denied = $service->requireStage2($this->nonce(), 'login', 'txn-denied-c', 1, RiskAction::Argon32, $expiry);
        $deniedTicket = $service->ticketFor($denied->chainId, $expiry);
        $deniedNonce = $this->stageNonce('denied-nonce');
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($denied->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($denied->chainId, 'owner-a', $deniedNonce));
        self::assertSame(ChainVerifiedResult::DeniedNew, $service->markDenied($denied->chainId, $deniedNonce));

        $response = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $deniedTicket, 'request_binding' => 'txn-denied-c'], JSON_THROW_ON_ERROR)));
        self::assertSame(429, $response->getStatusCode(), 'a denied chain answers the terminal risk-denied response');
        self::assertStringContainsString('RISK_DENIED', (string) $response->getContent());
        self::assertSame('denied', $service->requirementFor($denied->chainId)?->state, 'the terminal state survives the request');
        self::assertSame($denied->chainId, $service->findOpenRequirement('login', 'txn-denied-c', 1)?->chainId, 'the obligation survives the request');
    }

    public function testControllerConsumedValidStage2WithDispositionTransitionsTheChain(): void
    {
        $storage = new ArrayStorage();
        $store = $this->store();
        $service = $this->service($store);
        $dispositions = new \BelConsulting\KiwiCaptchaBundle\Risk\ArrayPostSolveDispositionStore();
        $controller = $this->controller($store, $storage, $dispositions);
        $expiry = time() + 300;
        $requirement = $service->requireStage2($this->nonce(), 'login', '', 1, RiskAction::Argon32, $expiry);
        $ticket = $service->ticketFor($requirement->chainId, $expiry);

        // Issue the stage-2 challenge through the controller (real Redis
        // chain state).
        $first = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $first->getStatusCode(), sprintf('the stage-2 issuance must succeed: %s', (string) $first->getContent()));
        $nonce = json_decode((string) $first->getContent(), true)['nonce'];

        // Consumed+valid without a committed disposition: the retryable
        // 503 — the core's consumed result alone never clears the
        // obligation.
        $storage->consume($nonce);
        $storage->commitResult($nonce, true, null);
        $second = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(503, $second->getStatusCode(), 'a consumed-valid stage-2 without a committed disposition is the retryable 503');
        self::assertSame('issued', $service->requirementFor($requirement->chainId)?->state, 'the chain stays issued');
        self::assertNotNull($service->findOpenRequirement('login', '', 1), 'the obligation survives the crash window');

        // The pass disposition is committed: the retry verifies the chain
        // and the obligation is deleted.
        $dispositions->claim($nonce, 'disposition-owner', 300);
        $dispositions->finalize($nonce, 'disposition-owner', new \BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDisposition(\BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind::Pass));
        $third = $controller->challenge($this->challengeRequest(json_encode(['scope' => 'login', 'chain_ticket' => $ticket], JSON_THROW_ON_ERROR)));
        self::assertSame(200, $third->getStatusCode(), sprintf('after the PASS disposition is committed the retry verifies: %s', (string) $third->getContent()));
        self::assertSame('verified', $service->requirementFor($requirement->chainId)?->state);
        self::assertNull($service->findOpenRequirement('login', '', 1), 'the PASS disposition cleared the obligation');
    }

    public function testRearmPinsTheExpectedNonceAndAutoResumeReadsWithoutATicket(): void
    {
        $store = $this->store();
        $service = $this->service($store);
        $requirement = $service->requireStage2($this->nonce(), 'login', 'txn-rearm', 1, RiskAction::Argon32, time() + 300);

        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', $this->stageNonce('stage2-nonce')));

        // A different expected nonce is an atomic no-op.
        self::assertFalse($service->rearmIssued($requirement->chainId, $this->stageNonce('other-nonce')));
        self::assertSame('issued', $service->requirementFor($requirement->chainId)?->state);

        // The exact nonce rearms to available for a fresh stage-2 mint.
        self::assertTrue($service->rearmIssued($requirement->chainId, $this->stageNonce('stage2-nonce')));
        $state = $service->requirementFor($requirement->chainId);
        self::assertSame('available', $state?->state);
        self::assertNull($state?->stage2Nonce);

        // auto-resume read: findOpenRequirement without any ticket finds
        // the open chain of the transaction.
        $auto = $service->findOpenRequirement('login', 'txn-rearm', 1);
        self::assertNotNull($auto);
        self::assertSame($requirement->chainId, $auto->chainId);
        self::assertSame('available', $auto->state);
    }

    public function testArrayAndRedisObserveOneMachine(): void
    {
        // The same transition sequence on both stores produces the same
        // typed results (the in-memory store mirrors the Redis Lua).
        $redisStore = $this->store();
        $arrayStore = new ArrayChainedChallengeStateStore();
        $expiry = time() + 300;

        foreach ([$redisStore, $arrayStore] as $store) {
            $service = new ChainedChallengeTicketService($store, self::SECRET, 300, 15);
            $requirement = $service->requireStage2($this->nonce(), 'login', 'txn-parity', 1, RiskAction::Argon32, $expiry);
            self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
            self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', $this->stageNonce('stage2-nonce')));
            self::assertSame(ChainReservationResult::Issued, $service->reserveStage2($requirement->chainId, 'owner-b'));
            self::assertSame(ChainVerifiedResult::VerifiedNew, $service->markVerified($requirement->chainId, $this->stageNonce('stage2-nonce')));
            self::assertSame('verified', $service->requirementFor($requirement->chainId)?->state);
            self::assertNull($service->findOpenRequirement('login', 'txn-parity', 1));
        }
    }

    public function testTransactionTerminalizationDenyAndStepUpAreDurable(): void
    {
        // The nonce-agnostic transaction terminalizations over real
        // Redis: the Lua transitions an open obligation (available) ->
        // denied/step_up_required without any stage-2 nonce — the
        // obligation mapping kept, the chainId + original expiry
        // preserved, the terminal record durable across a reconnected
        // reader (the strict decode accepts the terminal state with a
        // null stage-2 nonce).
        $store = $this->store();
        $service = $this->service($store);
        $expiry = time() + 300;

        // deny: available -> denied.
        $denied = $service->requireStage2($this->nonce(), 'login', 'txn-tdeny', 1, RiskAction::Sha18, $expiry);
        $deniedObligationId = $service->obligationIdFor('login', 'txn-tdeny', 1);
        self::assertSame(ChainVerifiedResult::DeniedNew, $service->markTransactionDenied($denied->chainId, $deniedObligationId));
        $reconnected = $this->store(new \Predis\Client(self::REDIS_URL));
        $state = $reconnected->read($denied->chainId);
        self::assertIsArray($state, 'the terminalized record strictly decodes over real Redis');
        self::assertSame('denied', $state['state']);
        self::assertNull($state['stage2Nonce'], 'the terminal state carries a NULL stage-2 nonce');
        self::assertNull($state['owner']);
        self::assertNull($state['leaseUntil']);
        self::assertSame($expiry, $state['expiresAt'], 'the original expiry is preserved');
        self::assertSame($denied->chainId, $reconnected->obligationChainId($service->obligationIdFor('login', 'txn-tdeny', 1)), 'the obligation mapping is KEPT');
        self::assertSame(ChainVerifiedResult::DeniedSame, $service->markTransactionDenied($denied->chainId, $deniedObligationId), 'a repeated terminalization is idempotent');
        self::assertSame(ChainVerifiedResult::Conflict, $service->markTransactionStepUpRequired($denied->chainId, $deniedObligationId), 'the OTHER terminal disposition can never flip a terminal state');
        self::assertSame(ChainReservationResult::Denied, $service->reserveStage2($denied->chainId, 'owner-b'), 'the reserve answers the TERMINAL denied state');
        self::assertSame(ChainIssuedResult::Conflict, $service->markIssued($denied->chainId, 'owner-b', $this->stageNonce('stage2-nonce')), 'markIssued on a terminal state is a conflict');
        self::assertSame('denied', $service->requirementFor($denied->chainId)?->state, 'the terminal state survives');

        // step-up: available -> step_up_required.
        $stepUp = $service->requireStage2($this->nonce(), 'login', 'txn-tstepup', 1, RiskAction::Sha18, $expiry);
        $stepUpObligationId = $service->obligationIdFor('login', 'txn-tstepup', 1);
        self::assertSame(ChainVerifiedResult::StepUpRequiredNew, $service->markTransactionStepUpRequired($stepUp->chainId, $stepUpObligationId));
        $state = $reconnected->read($stepUp->chainId);
        self::assertIsArray($state);
        self::assertSame('step_up_required', $state['state']);
        self::assertNull($state['stage2Nonce']);
        self::assertSame($stepUp->chainId, $reconnected->obligationChainId($service->obligationIdFor('login', 'txn-tstepup', 1)), 'the obligation mapping is KEPT');
        self::assertSame(ChainVerifiedResult::StepUpRequiredSame, $service->markTransactionStepUpRequired($stepUp->chainId, $stepUpObligationId), 'a repeated terminalization is idempotent');
        self::assertSame(ChainVerifiedResult::Conflict, $service->markTransactionDenied($stepUp->chainId, $stepUpObligationId), 'the OTHER terminal disposition can never flip a terminal state');
        self::assertSame(ChainReservationResult::StepUpRequired, $service->reserveStage2($stepUp->chainId, 'owner-b'), 'the reserve answers the TERMINAL step_up_required state');
        self::assertSame('step_up_required', $service->requirementFor($stepUp->chainId)?->state);
    }

    public function testTransactionTerminalizationPreservesAnIssuedNonceAndAnswersAlreadyVerified(): void
    {
        // The terminalization preserves the exact stage-2 nonce of an
        // issued chain (the terminal state carries an optional nonce — a
        // valid Kiwi nonce when one exists), and a verified chain
        // answers 'already_verified' (the transaction already ended via
        // Pass — its obligation is gone).
        $store = $this->store();
        $service = $this->service($store);
        $expiry = time() + 300;
        $nonce = $this->stageNonce('stage2-nonce');

        // issued -> denied: the exact nonce is preserved.
        $issued = $service->requireStage2($this->nonce(), 'login', 'txn-tnonce', 1, RiskAction::Sha18, $expiry);
        $issuedObligationId = $service->obligationIdFor('login', 'txn-tnonce', 1);
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($issued->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($issued->chainId, 'owner-a', $nonce));
        self::assertSame(ChainVerifiedResult::DeniedNew, $service->markTransactionDenied($issued->chainId, $issuedObligationId));
        self::assertSame($nonce, $service->requirementFor($issued->chainId)?->stage2Nonce, 'the exact stage-2 nonce is PRESERVED by the nonce-agnostic terminalization');
        self::assertSame('denied', $service->requirementFor($issued->chainId)?->state);

        // verified -> already_verified (the obligation was cleared by the
        // Pass — there is no chain left to terminalize).
        $verified = $service->requireStage2($this->nonce(), 'login', 'txn-tverified', 1, RiskAction::Sha18, $expiry);
        $verifiedObligationId = $service->obligationIdFor('login', 'txn-tverified', 1);
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($verified->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($verified->chainId, 'owner-a', $nonce));
        self::assertSame(ChainVerifiedResult::VerifiedNew, $service->markVerified($verified->chainId, $nonce));
        self::assertSame(ChainVerifiedResult::AlreadyVerified, $service->markTransactionDenied($verified->chainId, $verifiedObligationId), 'the post-Pass terminalization answers already_verified');
        self::assertSame(ChainVerifiedResult::AlreadyVerified, $service->markTransactionStepUpRequired($verified->chainId, $verifiedObligationId));
        self::assertSame('verified', $service->requirementFor($verified->chainId)?->state, 'the verified terminal record is untouched');
    }

    public function testTransactionTerminalizationRacesReservationAndMarkVerified(): void
    {
        // The atomic races over real Redis, both orders of each pair:
        // terminalization vs reservation (reserved-then-terminalized ->
        // terminal; terminalized-then-reserve -> the terminal result) and
        // terminalization vs markVerified (verified-then-terminalized ->
        // already_verified; terminalized-then-markVerified -> conflict).
        // Whichever writer lands first, the final state is consistent.
        $store = $this->store();
        $service = $this->service($store);
        $expiry = time() + 300;
        $nonce = $this->stageNonce('stage2-nonce');

        // Reservation first, terminalization second: the terminalization
        // wins against the in-flight reservation.
        $a = $service->requireStage2($this->nonce(), 'login', 'txn-race-a', 1, RiskAction::Sha18, $expiry);
        $aObligationId = $service->obligationIdFor('login', 'txn-race-a', 1);
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($a->chainId, 'owner-a'));
        self::assertSame(ChainVerifiedResult::DeniedNew, $service->markTransactionDenied($a->chainId, $aObligationId));
        self::assertSame('denied', $service->requirementFor($a->chainId)?->state);
        self::assertNull($service->requirementFor($a->chainId)?->owner, 'the reservation fields are cleared');
        self::assertSame(ChainReservationResult::Denied, $service->reserveStage2($a->chainId, 'owner-b'), 'the reserve on the terminalized chain answers the terminal result');

        // Terminalization first, reservation second: the reserve answers
        // the terminal result (never available).
        $b = $service->requireStage2($this->nonce(), 'login', 'txn-race-b', 1, RiskAction::Sha18, $expiry);
        $bObligationId = $service->obligationIdFor('login', 'txn-race-b', 1);
        self::assertSame(ChainVerifiedResult::StepUpRequiredNew, $service->markTransactionStepUpRequired($b->chainId, $bObligationId));
        self::assertSame(ChainReservationResult::StepUpRequired, $service->reserveStage2($b->chainId, 'owner-a'), 'a reserve on the terminalized chain returns the terminal result');

        // markVerified first, terminalization second: already_verified.
        $c = $service->requireStage2($this->nonce(), 'login', 'txn-race-c', 1, RiskAction::Sha18, $expiry);
        $cObligationId = $service->obligationIdFor('login', 'txn-race-c', 1);
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($c->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($c->chainId, 'owner-a', $nonce));
        self::assertSame(ChainVerifiedResult::VerifiedNew, $service->markVerified($c->chainId, $nonce));
        self::assertSame(ChainVerifiedResult::AlreadyVerified, $service->markTransactionDenied($c->chainId, $cObligationId), 'the terminalization on a verified chain answers already_verified');

        // Terminalization first, markVerified second: conflict.
        $d = $service->requireStage2($this->nonce(), 'login', 'txn-race-d', 1, RiskAction::Sha18, $expiry);
        $dObligationId = $service->obligationIdFor('login', 'txn-race-d', 1);
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($d->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($d->chainId, 'owner-a', $nonce));
        self::assertSame(ChainVerifiedResult::DeniedNew, $service->markTransactionDenied($d->chainId, $dObligationId));
        self::assertSame(ChainVerifiedResult::Conflict, $service->markVerified($d->chainId, $nonce), 'a markVerified on the terminalized chain is a conflict');
        self::assertSame('denied', $service->requirementFor($d->chainId)?->state);
    }

    public function testTransactionTerminalizationParityArrayAndRedis(): void
    {
        // The nonce-agnostic terminalizations observe ONE machine: the
        // same sequence on the Redis Lua and the in-memory mirror
        // produces the same typed results and the same final records.
        $redisStore = $this->store();
        $arrayStore = new ArrayChainedChallengeStateStore();
        $expiry = time() + 300;

        foreach ([$redisStore, $arrayStore] as $store) {
            $service = new ChainedChallengeTicketService($store, self::SECRET, 300, 15);
            $requirement = $service->requireStage2($this->nonce(), 'login', 'txn-parity2', 1, RiskAction::Sha18, $expiry);
            $obligationId = $service->obligationIdFor('login', 'txn-parity2', 1);
            self::assertSame(ChainVerifiedResult::DeniedNew, $service->markTransactionDenied($requirement->chainId, $obligationId));
            self::assertSame(ChainVerifiedResult::DeniedSame, $service->markTransactionDenied($requirement->chainId, $obligationId));
            self::assertSame(ChainVerifiedResult::Conflict, $service->markTransactionStepUpRequired($requirement->chainId, $obligationId));
            self::assertSame(ChainReservationResult::Denied, $service->reserveStage2($requirement->chainId, 'owner-b'));
            $state = $service->requirementFor($requirement->chainId);
            self::assertSame('denied', $state?->state);
            self::assertNull($state?->stage2Nonce);
            self::assertSame($expiry, $state?->expiresAt, 'the original expiry is preserved on both stores');
            self::assertNotNull($service->findOpenRequirement('login', 'txn-parity2', 1), 'the obligation mapping is KEPT on both stores');
        }
    }

    public function testIssuedStage2NonceStaysTerminalAfterAnotherTokensTransactionTerminalization(): void
    {
        // THE critical scenario over real Redis: the chain is issued(S);
        // the obligation-bound transaction terminalization (a fresh
        // Deny/StepUp of a different token of the same transaction) makes
        // it terminal preserving the exact stage-2 nonce S; the stage-2
        // pass transition for the exact nonce S is then refused
        // (conflict — a terminal denial can never be flipped by a Pass,
        // the stage-2 503 loop is impossible), the terminal transition
        // for the exact nonce is idempotent (denied_same — never a
        // conflict) and the reserve answers the terminal result.
        $store = $this->store();
        $service = $this->service($store);
        $expiry = time() + 300;
        $nonce = $this->stageNonce('stage2-nonce');

        // deny: issued(S) -> denied(S) by the transaction terminalization.
        $denied = $service->requireStage2($this->nonce(), 'login', 'txn-critical-deny', 1, RiskAction::Sha18, $expiry);
        $deniedObligationId = $service->obligationIdFor('login', 'txn-critical-deny', 1);
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($denied->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($denied->chainId, 'owner-a', $nonce));
        self::assertSame(ChainVerifiedResult::DeniedNew, $service->markTransactionDenied($denied->chainId, $deniedObligationId));
        self::assertSame('denied', $service->requirementFor($denied->chainId)?->state);
        self::assertSame($nonce, $service->requirementFor($denied->chainId)?->stage2Nonce, 'the exact stage-2 nonce is PRESERVED');
        self::assertSame(ChainVerifiedResult::Conflict, $service->markVerified($denied->chainId, $nonce), 'the stage-2 PASS transition on the terminal chain is refused — the 503 loop is impossible');
        self::assertSame(ChainVerifiedResult::DeniedSame, $service->markDenied($denied->chainId, $nonce), 'the terminal Deny is idempotent for the EXACT nonce');
        self::assertSame(ChainReservationResult::Denied, $service->reserveStage2($denied->chainId, 'owner-b'), 'the reserve answers the TERMINAL denied state');

        // step-up mirror: issued(S) -> step_up_required(S).
        $stepUp = $service->requireStage2($this->nonce(), 'login', 'txn-critical-stepup', 1, RiskAction::Sha18, $expiry);
        $stepUpObligationId = $service->obligationIdFor('login', 'txn-critical-stepup', 1);
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($stepUp->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($stepUp->chainId, 'owner-a', $nonce));
        self::assertSame(ChainVerifiedResult::StepUpRequiredNew, $service->markTransactionStepUpRequired($stepUp->chainId, $stepUpObligationId));
        self::assertSame($nonce, $service->requirementFor($stepUp->chainId)?->stage2Nonce, 'the exact stage-2 nonce is PRESERVED');
        self::assertSame(ChainVerifiedResult::Conflict, $service->markVerified($stepUp->chainId, $nonce), 'the stage-2 PASS transition is refused on the terminal step-up chain');
        self::assertSame(ChainVerifiedResult::StepUpRequiredSame, $service->markStepUpRequired($stepUp->chainId, $nonce), 'the terminal StepUp is idempotent for the EXACT nonce');
        self::assertSame(ChainReservationResult::StepUpRequired, $service->reserveStage2($stepUp->chainId, 'owner-b'), 'the reserve answers the TERMINAL step_up_required state');
    }

    public function testObligationBoundTerminalizationRefusesAStaleChainIdOverRedis(): void
    {
        // The obligation-bound terminalization over real Redis: the Lua
        // verifies over both keys — the obligation mapping still points
        // at the chain AND the chain record still agrees on the
        // obligation id. A stale chainId (the obligation moved to a
        // different chain) answers 'obligation_moved' (Conflict at the
        // service) and nothing is transitioned; the happy path (the
        // mapping intact) transitions.
        $store = $this->store();
        $service = $this->service($store);
        $expiry = time() + 300;

        // The transaction's chain + its obligation mapping agree.
        $requirement = $service->requireStage2($this->nonce(), 'login', 'txn-stale', 1, RiskAction::Sha18, $expiry);
        $obligationId = $service->obligationIdFor('login', 'txn-stale', 1);
        self::assertSame($requirement->chainId, (string) $this->client->get(sprintf('{kiwi:%s}:chain-obligation:%s', self::NAMESPACE, $obligationId)), 'the obligation maps the chain');

        // The obligation moves to a fresh chain (a re-created chain of
        // the same transaction) while the stale chain record survives.
        $fresh = $service->requireStage2($this->nonce(), 'login', 'txn-stale-2', 1, RiskAction::Sha18, $expiry);
        $store->createWithObligation($fresh->chainId, $obligationId, $this->nonce(), 'login', 'txn-stale', 'sha18', 1, 300);

        // The stale-chainId terminalization is refused atomically:
        // nothing transitioned, the mapping untouched.
        self::assertSame('obligation_moved', $store->markTransactionDenied($requirement->chainId, $obligationId), 'a stale chainId (the obligation moved) is refused at the store');
        self::assertSame('available', $service->requirementFor($requirement->chainId)?->state, 'the stale chain is untouched');
        self::assertSame($fresh->chainId, (string) $this->client->get(sprintf('{kiwi:%s}:chain-obligation:%s', self::NAMESPACE, $obligationId)), 'the obligation mapping is untouched');
        self::assertSame(ChainVerifiedResult::Conflict, $service->markTransactionDenied($requirement->chainId, $obligationId), 'the service surfaces the refused terminalization as Conflict');

        // The happy path (the mapping intact) transitions.
        self::assertSame(ChainVerifiedResult::DeniedNew, $service->markTransactionDenied($fresh->chainId, $obligationId), 'the happy path transitions');
        self::assertSame('denied', $service->requirementFor($fresh->chainId)?->state);

        // The record-agrees guard: an obligation id the chain record does
        // NOT carry is refused too.
        $other = $service->requireStage2($this->nonce(), 'login', 'txn-stale-3', 1, RiskAction::Sha18, $expiry);
        $otherObligationId = $service->obligationIdFor('login', 'txn-stale-3', 1);
        self::assertSame($otherObligationId, $store->read($other->chainId)['obligationId'], 'the record carries its own obligation id');
        self::assertSame('obligation_moved', $store->markTransactionDenied($other->chainId, $obligationId), 'a mismatched obligation id is refused — the record does not agree');
        self::assertSame('available', $service->requirementFor($other->chainId)?->state, 'the record is untouched');
    }
}
