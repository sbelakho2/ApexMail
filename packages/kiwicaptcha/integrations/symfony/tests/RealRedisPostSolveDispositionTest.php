<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\MalformedPostSolveDispositionException;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDisposition;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisPostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use KiwiCaptcha\Challenge;
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
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Validator\ConstraintValidatorFactory;
use Symfony\Component\Validator\ConstraintViolationListInterface;
use Symfony\Component\Validator\Validation;

/**
 * real-redis post-solve disposition tests (127.0.0.1:6399 — skipped when
 * unreachable).
 *
 * Exercises the store's single-Lua state machine (claim / takeover /
 * finalize / replay) and the full end-to-end replay guarantee that fakes
 * cannot prove: a valid token whose post-solve assessment denies replays
 * as deny from the persisted nonce-keyed disposition, and the replay
 * never re-runs the assessment (exactly one risk observation).
 */
final class RealRedisPostSolveDispositionTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private \Predis\Client $client;

    protected function setUp(): void
    {
        if (!class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis not installed');
        }
        $this->client = new \Predis\Client('tcp://127.0.0.1:6399');
        try {
            $this->client->ping();
        } catch (\Throwable $e) {
            self::markTestSkipped('Redis at 127.0.0.1:6399 unreachable: '.$e->getMessage());
        }
        $this->client->flushdb();
    }

    private function store(int $ttlSecs = 0): RedisPostSolveDispositionStore
    {
        return new RedisPostSolveDispositionStore($this->client, 'ci-postsolve', $ttlSecs);
    }

    private function key(string $nonce): string
    {
        return '{kiwi:ci-postsolve}:postsolve:'.$nonce;
    }

    private function decisionKey(string $nonce): string
    {
        return '{kiwi:ci-postsolve}:decision:'.$nonce;
    }

    /** Seed the nonce -> decision mapping (the gateway's json shape). */
    private function attachDecision(string $nonce, string $decisionId): void
    {
        $this->client->set($this->decisionKey($nonce), (string) json_encode(['decision_id' => $decisionId], JSON_UNESCAPED_SLASHES), 'EX', 300);
    }

    /** Solve a real sha256 challenge (the same derivation as the core). */
    private function solve(Challenge $challenge): string
    {
        $counter = 0;
        do {
            $h = hash('sha256', $challenge->prefix.$counter.base64_decode($challenge->salt, true), true);
            $counter++;
        } while (Verifier::leadingZeroBits($h) < $challenge->targetBits);
        --$counter;
        usleep(((int) $challenge->minDurationMs + 10) * 1000);

        return SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
    }

    /** Drive one token through the full Symfony validation pipeline. */
    private function validateToken(KiwiCaptchaValidator $validator, string $token): ConstraintViolationListInterface
    {
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        return $engine->validate($dto);
    }

    /**
     * The chained-stage validator fixture: real challenge storage + Redis
     * chain state + the risk gateway (post_solve_check on) over the
     * 'login' scope, bound to the 'txn-alpha' transaction.
     */
    private function chainedStageValidator(Verifier $verifier, RedisStorage $storage, ChainedChallengeTicketService $chainService, RiskProfileResolver $resolver, RiskGateway $gateway, RedisPostSolveDispositionStore $dispositions): KiwiCaptchaValidator
    {
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));

        return new KiwiCaptchaValidator(
            $verifier,
            $stack,
            self::SECRET,
            enforceTelemetry: false,
            risk: $gateway,
            continuityCookie: new ContinuityCookie(),
            storage: $storage,
            chainTickets: $chainService,
            riskResolver: $resolver,
            dispositionStore: $dispositions,
            bindingAuthority: new FixtureBindingAuthority('txn-alpha'),
        );
    }

    /**
     * The post-solve risk gateway over the 'login' scope
     * (post_solve_check on, decision prefix matching the disposition
     * store's namespace).
     */
    private function chainedStageGateway(RiskProfileResolver $resolver): RiskGateway
    {
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'allow'],
            ],
        ]);
        $riskStore = new FakeRiskStateStore(SignalVector::fromArray(['source_fast' => 900, 'subnet_fast' => 1000, 'issue_debt' => 1000, 'replay' => 699, 'network_risk' => 890]));
        $engine = new AdaptiveRiskEngine($riskStore, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);

        return new RiskGateway($engine, $classifier, $resolver, ['login' => 1], null, null, ['login' => true], 'reject', null, null, null, null, '{kiwi:ci-postsolve}:decision:', 300, $policy);
    }

    public function testClaimTakeoverFinalizeReplayAgainstRealRedis(): void
    {
        $store = $this->store();
        $nonce = bin2hex(random_bytes(16));

        // Missing -> pending(me, lease) -> claimed.
        self::assertSame('claimed', $store->claim($nonce, 'owner-a', 305));
        $record = $store->read($nonce);
        self::assertNotNull($record);
        self::assertSame('pending', $record->state);
        self::assertSame('owner-a', $record->owner);
        self::assertNull($record->disposition);
        $ttl = $this->client->ttl($this->key($nonce));
        self::assertGreaterThanOrEqual(304, $ttl, 'the record TTL = the claim TTL (Config::MAX_TTL_SECS + margin)');
        self::assertLessThanOrEqual(305, $ttl);

        // pending+other+live -> 'pending' (busy).
        self::assertSame('pending', $store->claim($nonce, 'owner-b', 305));

        // finalize by a NON-owner is refused; by the owner it completes.
        self::assertFalse($store->finalize($nonce, 'owner-b', new PostSolveDisposition(PostSolveDispositionKind::Deny)));
        self::assertTrue($store->finalize($nonce, 'owner-a', new PostSolveDisposition(PostSolveDispositionKind::Deny, 'decision-1')));
        $record = $store->read($nonce);
        self::assertSame('complete', $record->state);
        self::assertNull($record->owner);
        self::assertNull($record->leaseUntil);
        self::assertNotNull($record->disposition);
        self::assertSame(PostSolveDispositionKind::Deny, $record->disposition->kind);
        self::assertSame('decision-1', $record->disposition->decisionId);
        self::assertNull($record->disposition->chainId);

        // complete -> 'complete' forever (a replay never re-computes).
        self::assertSame('complete', $store->claim($nonce, 'owner-c', 305));
        self::assertFalse($store->finalize($nonce, 'owner-c', new PostSolveDisposition(PostSolveDispositionKind::Pass)), 'a completed disposition is terminal');
        $record = $store->read($nonce);
        self::assertSame(PostSolveDispositionKind::Deny, $record?->disposition?->kind, 'the completed disposition is never overwritten');

        // Expired-lease takeover: a separate pending claim whose
        // lease_until is rewound behind now (simulating the fixed 15 s
        // computation lease passing) is taken over by another owner.
        $takeoverNonce = bin2hex(random_bytes(16));
        self::assertSame('claimed', $store->claim($takeoverNonce, 'owner-a', 305));
        self::assertSame('pending', $store->claim($takeoverNonce, 'owner-b', 305), 'a live lease is busy');
        $rec = json_decode((string) $this->client->get($this->key($takeoverNonce)), true);
        self::assertIsArray($rec);
        $rec['lease_until'] = time() - 1;
        $this->client->set($this->key($takeoverNonce), (string) json_encode($rec), 'KEEPTTL');
        self::assertSame('taken_over', $store->claim($takeoverNonce, 'owner-d', 305));
        self::assertSame('owner-d', $store->read($takeoverNonce)?->owner, 'the takeover moves the claim to the new owner');
    }

    public function testChainRequiredDispositionWireShapeAgainstRealRedis(): void
    {
        $store = $this->store();
        $nonce = bin2hex(random_bytes(16));
        $expiry = time() + 300;

        self::assertSame('claimed', $store->claim($nonce, 'owner-a', 300));
        self::assertTrue($store->finalize($nonce, 'owner-a', new PostSolveDisposition(PostSolveDispositionKind::ChainRequired, 'decision-2', 'chain-xyz', $expiry)));

        $raw = json_decode((string) $this->client->get($this->key($nonce)), true);
        self::assertIsArray($raw);
        self::assertSame(1, $raw['v'], 'new writes are v1 (the compatibility release writes the schema an earlier release reads, with chain_required carrying chain_expires_at)');
        self::assertSame('complete', $raw['state']);
        self::assertNull($raw['owner']);
        self::assertNull($raw['lease_until']);
        self::assertSame('chain_required', $raw['disposition']['kind']);
        self::assertSame('decision-2', $raw['disposition']['decision_id']);
        self::assertSame('chain-xyz', $raw['disposition']['chain_id']);
        self::assertSame($expiry, $raw['disposition']['chain_expires_at'], 'the ChainRequired record carries its chain\'s ORIGINAL expiry bound');
        self::assertArrayNotHasKey('vector', $raw['disposition']);
        self::assertArrayNotHasKey('fingerprint', $raw['disposition']);
        self::assertArrayNotHasKey('descriptor', $raw['disposition']);

        $record = $store->read($nonce);
        self::assertSame(PostSolveDispositionKind::ChainRequired, $record?->disposition?->kind);
        self::assertSame('chain-xyz', $record?->disposition?->chainId);
        self::assertSame($expiry, $record?->disposition?->chainExpiresAt, 'the read-back reproduces the disposition-carried expiry bound');
    }

    public function testChainRequiredRecordWithoutExpiryBoundIsMalformedFailsClosed(): void
    {
        // A v2 ChainRequired record without its chain_expires_at bound is
        // malformed state — the strict v2 decoder refuses it (fail
        // closed), never a ticket.
        $store = $this->store();
        $nonce = bin2hex(random_bytes(16));
        $raw = ['v' => 2, 'state' => 'complete', 'owner' => null, 'lease_until' => null, 'disposition' => ['kind' => 'chain_required', 'decision_id' => 'decision-1', 'chain_id' => 'chain-xyz']];
        $this->client->set($this->key($nonce), (string) json_encode($raw), 'EX', 300);

        try {
            $store->read($nonce);
            self::fail('the strict decoder must refuse a v2 ChainRequired record without its expiry bound');
        } catch (MalformedPostSolveDispositionException $e) {
            self::assertStringContainsString('chain_expires_at', $e->getMessage());
        }
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $this->corruptRecordOutcome($raw), 'a v2 ChainRequired record without its expiry bound must fail closed as temporary_unavailable — never a ticket');
    }

// ── the decision handle in the disposition records ─────────────────────────

    public function testDecisionHandleSurvivesInThePendingAndCompleteRecords(): void
    {
        $store = $this->store();
        $nonce = bin2hex(random_bytes(16));
        $this->attachDecision($nonce, 'decision-original');

        // The claim atomically consumes the nonce -> decision mapping
        // (getdel inside the claim Lua) and persists the paired handle in
        // the pending record.
        self::assertSame('claimed', $store->claim($nonce, 'owner-a', 305, $this->decisionKey($nonce)));
        $record = $store->read($nonce);
        self::assertSame('pending', $record?->state);
        self::assertSame('decision-original', $record?->decisionId, 'the pending record carries the decision handle');
        self::assertNull($record?->disposition);
        self::assertNull($this->client->get($this->decisionKey($nonce)), 'the mapping is consumed in the SAME atomic operation as the claim');

        // The complete record keeps the handle (the finalize never clears it).
        self::assertTrue($store->finalize($nonce, 'owner-a', new PostSolveDisposition(PostSolveDispositionKind::Pass, 'decision-original')));
        $record = $store->read($nonce);
        self::assertSame('complete', $record?->state);
        self::assertSame('decision-original', $record?->decisionId, 'the complete record keeps the decision handle');
        self::assertSame('decision-original', $record?->disposition?->decisionId);
        $raw = json_decode((string) $this->client->get($this->key($nonce)), true);
        self::assertIsArray($raw);
        self::assertSame('decision-original', $raw['decision_id'] ?? null, 'the wire record carries the decision_id field');
    }

    public function testTakeoverPreservesTheOriginalDecisionHandle(): void
    {
        $store = $this->store();
        $nonce = bin2hex(random_bytes(16));
        $this->attachDecision($nonce, 'decision-original');

        self::assertSame('claimed', $store->claim($nonce, 'owner-a', 305, $this->decisionKey($nonce)));
        // The lease expires; a NEW owner takes over with a different
        // mapping — the original handle survives (a takeover never
        // touches the decision key: the fresh mapping belongs to the
        // caller who will win the next claim).
        $rec = json_decode((string) $this->client->get($this->key($nonce)), true);
        self::assertIsArray($rec);
        $rec['lease_until'] = time() - 1;
        $this->client->set($this->key($nonce), (string) json_encode($rec), 'KEEPTTL');
        $this->attachDecision($nonce, 'decision-new');
        self::assertSame('taken_over', $store->claim($nonce, 'owner-b', 305, $this->decisionKey($nonce)));
        self::assertSame('decision-original', $store->read($nonce)?->decisionId, 'the takeover keeps the ORIGINAL decision handle — never the new owner\'s');
        $mapping = json_decode((string) $this->client->get($this->decisionKey($nonce)), true);
        self::assertIsArray($mapping);
        self::assertSame('decision-new', $mapping['decision_id'] ?? null, 'the takeover NEVER consumes the decision mapping — it stays resolvable for the next claimant');
        self::assertTrue($store->finalize($nonce, 'owner-b', new PostSolveDisposition(PostSolveDispositionKind::Pass, 'decision-new')));
        $record = $store->read($nonce);
        self::assertSame('decision-original', $record?->decisionId, 'the completed disposition keeps the ORIGINAL handle');
    }

    public function testClaimWithoutDecisionHandleBehavesAsBefore(): void
    {
        $store = $this->store();
        $nonce = bin2hex(random_bytes(16));

        self::assertSame('claimed', $store->claim($nonce, 'owner-a', 305));
        self::assertNull($store->read($nonce)?->decisionId, 'no decision mapping key -> the records carry null');
        self::assertTrue($store->finalize($nonce, 'owner-a', new PostSolveDisposition(PostSolveDispositionKind::Pass)));
        $record = $store->read($nonce);
        self::assertNull($record?->decisionId);
        self::assertSame(PostSolveDispositionKind::Pass, $record?->disposition?->kind);
    }

    public function testClaimConsumesTheDecisionMappingAtomicallyAgainstRealRedis(): void
    {
        // The atomic transfer: the claim-with-decision GETDELs the mapping
        // AND writes the pending record in ONE operation — the mapping is
        // gone and the pending record carries the paired decision id. Two
        // concurrent claims (the same nonce, the same mapping): exactly
        // one wins the getdel.
        $store = $this->store();
        $nonce = bin2hex(random_bytes(16));
        $this->attachDecision($nonce, 'decision-atomic');

        self::assertSame('claimed', $store->claim($nonce, 'owner-a', 305, $this->decisionKey($nonce)));
        self::assertNull($this->client->get($this->decisionKey($nonce)), 'the mapping is consumed by the winning claim');
        $record = $store->read($nonce);
        self::assertSame('decision-atomic', $record?->decisionId, 'the pending record carries the decision id from the SAME atomic transition');

        // A second mapping seeded for the concurrent loser: the loser's
        // claim sees the record pending+other+live ('pending') and never
        // touches the decision key — the mapping inserted after the
        // winner's claim remains resolvable (it belongs to the caller who
        // will win the next claim).
        $nonce2 = bin2hex(random_bytes(16));
        $this->attachDecision($nonce2, 'decision-first');
        self::assertSame('claimed', $store->claim($nonce2, 'owner-a', 305, $this->decisionKey($nonce2)));
        $this->attachDecision($nonce2, 'decision-second');
        self::assertSame('pending', $store->claim($nonce2, 'owner-b', 305, $this->decisionKey($nonce2)), 'the concurrent second claim is busy');
        self::assertSame('decision-first', $store->read($nonce2)?->decisionId, 'the record keeps the first winner\'s handle');
        $mapping = json_decode((string) $this->client->get($this->decisionKey($nonce2)), true);
        self::assertIsArray($mapping);
        self::assertSame('decision-second', $mapping['decision_id'] ?? null, 'the pending-live claim NEVER consumed the mapping — it stays resolvable');
    }

    public function testCompleteClaimNeverConsumesTheDecisionMapping(): void
    {
        // A replay claim against a complete record returns 'complete'
        // without touching the decision key: the mapping inserted after
        // the finalize remains resolvable.
        $store = $this->store();
        $nonce = bin2hex(random_bytes(16));
        $this->attachDecision($nonce, 'decision-original');
        self::assertSame('claimed', $store->claim($nonce, 'owner-a', 305, $this->decisionKey($nonce)));
        self::assertTrue($store->finalize($nonce, 'owner-a', new PostSolveDisposition(PostSolveDispositionKind::Pass, 'decision-original')));
        $this->attachDecision($nonce, 'decision-after-complete');
        self::assertSame('complete', $store->claim($nonce, 'owner-b', 305, $this->decisionKey($nonce)));
        $mapping = json_decode((string) $this->client->get($this->decisionKey($nonce)), true);
        self::assertIsArray($mapping);
        self::assertSame('decision-after-complete', $mapping['decision_id'] ?? null, 'a complete claim NEVER consumes the decision mapping');
        self::assertSame('decision-original', $store->read($nonce)?->decisionId, 'the completed record keeps its original handle');
    }

// ── strict post-solve disposition decoding (all-or-nothing) ────────────────

    /**
     * The end-to-end violation code of a fresh valid token whose nonce's
     * disposition record is corrupt: the strict decoder must fail closed
     * as temporary_unavailable — never a pass, never a 422.
     *
     * @param array<string, mixed> $raw the corrupt wire record
     */
    private function corruptRecordOutcome(array $raw): string
    {
        $storage = new RedisStorage($this->client, 'ci-postsolve-corrupt:');
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        $counter = 0;
        do {
            $h = hash('sha256', $challenge->prefix.$counter.base64_decode($challenge->salt, true), true);
            $counter++;
        } while (Verifier::leadingZeroBits($h) < $challenge->targetBits);
        --$counter;
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
        usleep(((int) $challenge->minDurationMs + 10) * 1000);

        $this->client->set($this->key($challenge->nonce), (string) json_encode($raw), 'EX', 300);

        $verifier = new Verifier($storage);
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $validator = new KiwiCaptchaValidator(
            $verifier,
            $stack,
            self::SECRET,
            enforceTelemetry: false,
            dispositionStore: $this->store(),
        );
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

        return $violations[0]->getCode();
    }

    public function testCorruptWireRecordWithUnknownSchemaVersionFailsClosed(): void
    {
        $store = $this->store();
        $nonce = bin2hex(random_bytes(16));
        $raw = ['v' => 3, 'state' => 'pending', 'owner' => 'owner-a', 'lease_until' => time() - 1, 'disposition' => null];
        $this->client->set($this->key($nonce), (string) json_encode($raw), 'EX', 300);

        try {
            $store->read($nonce);
            self::fail('the strict decoder must refuse an unknown schema version');
        } catch (MalformedPostSolveDispositionException $e) {
            self::assertStringContainsString('schema version', $e->getMessage());
        }
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $this->corruptRecordOutcome($raw), 'an unknown disposition schema version must fail closed as temporary_unavailable — never a pass, never a 422');
    }

    public function testCorruptWireRecordWithUnknownStateFailsClosed(): void
    {
        $store = $this->store();
        $nonce = bin2hex(random_bytes(16));
        $raw = ['v' => 1, 'state' => 'weird', 'owner' => 'owner-a', 'lease_until' => time() - 1, 'disposition' => null];
        $this->client->set($this->key($nonce), (string) json_encode($raw), 'EX', 300);

        try {
            $store->read($nonce);
            self::fail('the strict decoder must refuse an unknown state');
        } catch (MalformedPostSolveDispositionException $e) {
            self::assertStringContainsString('state', $e->getMessage());
        }
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $this->corruptRecordOutcome($raw), 'an unknown disposition state must fail closed as temporary_unavailable — never a defaulted record');
    }

    public function testCorruptWireRecordWithMissingPendingOwnerFailsClosed(): void
    {
        $store = $this->store();
        $nonce = bin2hex(random_bytes(16));
        $raw = ['v' => 1, 'state' => 'pending', 'lease_until' => time() - 1, 'disposition' => null];
        $this->client->set($this->key($nonce), (string) json_encode($raw), 'EX', 300);

        try {
            $store->read($nonce);
            self::fail('the strict decoder must refuse a pending record without an owner');
        } catch (MalformedPostSolveDispositionException $e) {
            self::assertStringContainsString('owner', $e->getMessage());
        }
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $this->corruptRecordOutcome($raw), 'a pending record without an owner must fail closed as temporary_unavailable — the claim never heals it');
    }

    public function testCorruptWireRecordWithMissingCompleteDispositionFailsClosed(): void
    {
        $store = $this->store();
        $nonce = bin2hex(random_bytes(16));
        $raw = ['v' => 1, 'state' => 'complete', 'owner' => null, 'lease_until' => null, 'disposition' => null];
        $this->client->set($this->key($nonce), (string) json_encode($raw), 'EX', 300);

        try {
            $store->read($nonce);
            self::fail('the strict decoder must refuse a complete record without a disposition');
        } catch (MalformedPostSolveDispositionException $e) {
            self::assertStringContainsString('disposition', $e->getMessage());
        }
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $this->corruptRecordOutcome($raw), 'a complete record without a disposition must fail closed as temporary_unavailable — never a silent pass');
    }

    public function testCorruptWireRecordWithBadKindFailsClosed(): void
    {
        $store = $this->store();
        $nonce = bin2hex(random_bytes(16));
        $raw = ['v' => 1, 'state' => 'complete', 'owner' => null, 'lease_until' => null, 'disposition' => ['kind' => 'garbage', 'decision_id' => 'decision-1', 'chain_id' => null]];
        $this->client->set($this->key($nonce), (string) json_encode($raw), 'EX', 300);

        try {
            $store->read($nonce);
            self::fail('the strict decoder must refuse an invalid disposition kind');
        } catch (MalformedPostSolveDispositionException $e) {
            self::assertStringContainsString('kind', $e->getMessage());
        }
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $this->corruptRecordOutcome($raw), 'a corrupt disposition kind must fail closed as temporary_unavailable — never a Pass');
    }

    public function testCorruptWireRecordWithBadChainIdShapeFailsClosed(): void
    {
        $store = $this->store();
        $nonce = bin2hex(random_bytes(16));
        $raw = ['v' => 1, 'state' => 'complete', 'owner' => null, 'lease_until' => null, 'disposition' => ['kind' => 'chain_required', 'decision_id' => 'decision-1', 'chain_id' => 'bad id!']];
        $this->client->set($this->key($nonce), (string) json_encode($raw), 'EX', 300);

        try {
            $store->read($nonce);
            self::fail('the strict decoder must refuse a malformed chain id');
        } catch (MalformedPostSolveDispositionException $e) {
            self::assertStringContainsString('chain_id', $e->getMessage());
        }
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $this->corruptRecordOutcome($raw), 'a malformed chain id in a ChainRequired disposition must fail closed as temporary_unavailable');
    }

    public function testEndToEndDenyReplaysAsDenyAgainstRealRedis(): void
    {
        // A full valid solve through the real storage + the real
        // disposition store: the post-solve assessment denies, the denial
        // is persisted per nonce, and the replay of the same token
        // reproduces the denial from the disposition — the replay never
        // re-runs the assessment (exactly one risk observation).
        $storage = new RedisStorage($this->client, 'ci-postsolve-e2e:');
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7');

        $counter = 0;
        do {
            $h = hash('sha256', $challenge->prefix.$counter.base64_decode($challenge->salt, true), true);
            $counter++;
        } while (Verifier::leadingZeroBits($h) < $challenge->targetBits);
        --$counter;
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
        usleep(((int) $challenge->minDurationMs + 10) * 1000);

        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'allow'],
            ],
        ]);
        $riskStore = new FakeRiskStateStore(SignalVector::fromArray(['network_risk' => 900]));
        $engine = new AdaptiveRiskEngine($riskStore, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);
        $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], null, null, ['login' => true], 'reject', null, null, null, null, '{kiwi:ci-postsolve}:decision:', 300, $policy);
        $disposition = $this->store();

        $verifier = new Verifier($storage);
        $nowNs = (int) (microtime(true) * 1_000_000) + 1_000_000;
        self::assertTrue($verifier->verify($token, self::SECRET, 'login', '198.51.100.7', $nowNs)->isOk());

        // fresh validation: the post-solve assessment denies the valid solve.
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $validator = new KiwiCaptchaValidator(
            $verifier,
            $stack,
            self::SECRET,
            enforceTelemetry: false,
            risk: $gateway,
            dispositionStore: $disposition,
        );
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engineValidator = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engineValidator->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engineValidator->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violations[0]->getCode(), 'the fresh valid solve is denied by the post-solve assessment');
        self::assertSame(1, \count($riskStore->observations), 'the fresh validation assessed exactly once');
        $record = $disposition->read($challenge->nonce);
        self::assertNotNull($record);
        self::assertSame(PostSolveDispositionKind::Deny, $record->disposition?->kind, 'the denial is persisted per nonce');

        // replay: the same token — the core replays its stored result, the
        // persisted disposition reproduces the same deny, and the
        // assessment never runs again.
        $stack2 = new RequestStack();
        $stack2->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $validator2 = new KiwiCaptchaValidator(
            $verifier,
            $stack2,
            self::SECRET,
            enforceTelemetry: false,
            risk: $gateway,
            dispositionStore: $disposition,
        );
        $factory2 = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator2]);
        $engineValidator2 = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory2)->getValidator();
        $meta2 = $engineValidator2->getMetadataFor($dto::class);
        $meta2->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engineValidator2->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR, $violations[0]->getCode(), 'a replay of a denied token is denied again — never a silent pass');
        self::assertSame(1, \count($riskStore->observations), 'the replay must NEVER re-run the assessment — the persisted disposition answers');
        $record = $disposition->read($challenge->nonce);
        self::assertSame($record?->disposition?->decisionId, $record?->disposition?->decisionId);
    }

    public function testChainRequiredSigningIsBoundToTheDispositionsExactChainAgainstRealRedis(): void
    {
        // THE concurrency scenario against real Redis (chain state +
        // dispositions + challenge storage): a stage-1 token B durably
        // finalizes a chain_required(X) disposition carrying X's original
        // expiry; X's stage-2 challenge then verifies (the obligation is
        // cleared, the chain record retained) and a fresh chain Y opens
        // for the same transaction — B's replay must re-sign (X,
        // X.expiresAt), never Y's expiry, and without any
        // current-obligation lookup. A deleted chain record (expired) is
        // fail-closed temporary_unavailable.
        $storage = new RedisStorage($this->client, 'ci-psd-e2e:');
        $chainStore = new RedisChainedChallengeStateStore($this->client, 'ci-psd-chain');
        $chainService = new ChainedChallengeTicketService($chainStore, self::SECRET, 300, 15);
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'allow'],
            ],
        ]);
        $riskStore = new FakeRiskStateStore(SignalVector::fromArray(['source_fast' => 900, 'subnet_fast' => 1000, 'issue_debt' => 1000, 'replay' => 699, 'network_risk' => 890]));
        $engine = new AdaptiveRiskEngine($riskStore, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);
        $gateway = new RiskGateway($engine, $classifier, $resolver, ['login' => 1], null, null, ['login' => true], 'reject', null, null, null, null, '{kiwi:ci-postsolve}:decision:', 300, $policy);
        $dispositions = $this->store();

        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage);
        $stage1 = $issuer->issue('login', '198.51.100.7');
        $tokenB = $this->solve($stage1);

        $verifier = new Verifier($storage);
        $nowNs = (int) (microtime(true) * 1_000_000) + 1_000_000;
        self::assertTrue($verifier->verify($tokenB, self::SECRET, 'login', '198.51.100.7', $nowNs)->isOk());

        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $validator = new KiwiCaptchaValidator(
            $verifier,
            $stack,
            self::SECRET,
            enforceTelemetry: false,
            risk: $gateway,
            continuityCookie: new ContinuityCookie(),
            storage: $storage,
            chainTickets: $chainService,
            riskResolver: $resolver,
            dispositionStore: $dispositions,
            bindingAuthority: new FixtureBindingAuthority('txn-alpha'),
        );

        // fresh: the reassessment (Argon32) opens chain X and the
        // chain_required disposition is durably finalized with X's expiry.
        $violations = $this->validateToken($validator, $tokenB);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $ticket = $violations[0]->getParameters()['{{ chain_ticket }}'];
        self::assertIsString($ticket);
        $payloadX = $chainService->verify($ticket);
        self::assertIsArray($payloadX);
        $chainX = (string) $payloadX['chainId'];
        $expiryX = (int) $payloadX['expiresAt'];
        $record = $dispositions->read(SolutionToken::decode($tokenB)->nonce);
        self::assertNotNull($record);
        self::assertSame($chainX, $record->disposition?->chainId);
        self::assertSame($expiryX, $record->disposition?->chainExpiresAt, 'the disposition carries the chain\'s ORIGINAL expiry bound');

        // X's stage-2 challenge verifies: the obligation is cleared, the
        // chain record is retained and NO new chain exists — the replay of
        // B must still re-sign the byte-identical ticket from the
        // disposition-carried bound (no obligation lookup needed).
        $stage2Nonce = base64_encode(random_bytes(32));
        self::assertSame(ChainReservationResult::Available, $chainService->reserveStage2($chainX, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $chainService->markIssued($chainX, 'owner-a', $stage2Nonce));
        self::assertSame(ChainVerifiedResult::VerifiedNew, $chainService->markVerified($chainX, $stage2Nonce));
        self::assertNull($chainService->findOpenRequirement('login', 'txn-alpha', 1), 'X\'s obligation is cleared');
        self::assertNotNull($chainService->requirementFor($chainX), 'X\'s chain record is retained');

        $violations = $this->validateToken($validator, $tokenB);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode(), 'the completed-chain replay is still CHAIN_REQUIRED — never temporary_unavailable');
        $ticket2 = $violations[0]->getParameters()['{{ chain_ticket }}'];
        self::assertSame($ticket, $ticket2, 'the completed-chain replay re-signs the byte-identical ticket from the disposition-carried bound');
        $payload2 = $chainService->verify($ticket2);
        self::assertIsArray($payload2);
        self::assertSame($chainX, (string) $payload2['chainId']);
        self::assertSame($expiryX, (int) $payload2['expiresAt']);

        // A fresh chain Y opens for the same transaction identity: B's
        // signing must still produce (X, X.expiresAt) — never Y's expiry.
        $chainY = $chainService->requireStage2(base64_encode(random_bytes(32)), 'login', 'txn-alpha', 1, RiskAction::Argon64, time() + 600);
        self::assertNotSame($chainX, $chainY->chainId, 'the cleared obligation opens a FRESH chain');
        self::assertSame($chainY->chainId, $chainService->findOpenRequirement('login', 'txn-alpha', 1)?->chainId, 'Y now owns the transaction obligation');

        $violations = $this->validateToken($validator, $tokenB);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $ticket3 = $violations[0]->getParameters()['{{ chain_ticket }}'];
        self::assertSame($ticket, $ticket3, 'the ticket stays byte-identical with a concurrent chain Y open');
        $payload3 = $chainService->verify($ticket3);
        self::assertIsArray($payload3);
        self::assertSame($chainX, (string) $payload3['chainId'], 'the signing stays bound to the disposition\'s exact chain — never Y');
        self::assertSame($expiryX, (int) $payload3['expiresAt'], 'the signed expiry is X\'s ORIGINAL bound — never Y\'s');
        self::assertNotSame($chainY->expiresAt, (int) $payload3['expiresAt'], 'Y\'s expiry must never leak into X\'s ticket');

        // The record-gone case: X's chain record is gone (expired) — the
        // replay must fail closed temporary_unavailable, never a ticket
        // that outlives its chain state.
        $this->client->del('{kiwi:ci-psd-chain}:chain:'.$chainX);
        $violations = $this->validateToken($validator, $tokenB);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'a disposition whose chain record is gone is temporary_unavailable — never a ticket');
        self::assertSame(PostSolveDispositionKind::ChainRequired, $dispositions->read(SolutionToken::decode($tokenB)->nonce)?->disposition?->kind, 'the persisted disposition is untouched');
    }

    public function testLegacyV1ChainRequiredRecordSignsFromTheExactChainAgainstRealRedis(): void
    {
        // The exact legacy v1 wire
        // ({"v":1,"state":"complete","disposition":{"kind":"chain_required","chain_id":"X","decision_id":"D"}}
        // — no chain_expires_at) is accepted, never corrupt: the signing
        // takes the expiry from the exact chain X's record
        // (requirementFor(X)), never the current obligation Y, and the
        // record is never rewritten (pure compat-read).
        $storage = new RedisStorage($this->client, 'ci-psd-legacy:');
        $chainStore = new RedisChainedChallengeStateStore($this->client, 'ci-psd-chain');
        $chainService = new ChainedChallengeTicketService($chainStore, self::SECRET, 300, 15);
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $gateway = $this->chainedStageGateway($resolver);
        $dispositions = $this->store();

        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage);
        $stage1 = $issuer->issue('login', '198.51.100.7');
        $tokenB = $this->solve($stage1);
        $nonceB = SolutionToken::decode($tokenB)->nonce;

        $verifier = new Verifier($storage);
        $nowNs = (int) (microtime(true) * 1_000_000) + 1_000_000;
        self::assertTrue($verifier->verify($tokenB, self::SECRET, 'login', '198.51.100.7', $nowNs)->isOk());

        // Chain X opens for the transaction; the exact legacy v1 wire is
        // seeded for B's nonce.
        $chainX = $chainService->requireStage2(base64_encode(random_bytes(32)), 'login', 'txn-alpha', 1, RiskAction::Argon32, time() + 300);
        $legacy = [
            'v' => 1,
            'state' => 'complete',
            'owner' => null,
            'lease_until' => null,
            'disposition' => ['kind' => 'chain_required', 'chain_id' => $chainX->chainId, 'decision_id' => 'decision-D'],
            'decision_id' => 'decision-D',
        ];
        $this->client->set($this->key($nonceB), (string) json_encode($legacy), 'EX', 300);

        $validator = $this->chainedStageValidator($verifier, $storage, $chainService, $resolver, $gateway, $dispositions);

        // The reader accepts the legacy record: the carried expiry is
        // null — and the signing takes the expiry from the exact chain
        // X's record (requirementFor(X)).
        $record = $dispositions->read($nonceB);
        self::assertNotNull($record);
        self::assertSame($chainX->chainId, $record->disposition?->chainId);
        self::assertNull($record->disposition?->chainExpiresAt, 'a legacy v1 record carries no expiry bound — not corrupt');

        $violations = $this->validateToken($validator, $tokenB);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode(), 'a legacy v1 ChainRequired record is accepted — never temporary_unavailable');
        $ticket = $violations[0]->getParameters()['{{ chain_ticket }}'];
        self::assertIsString($ticket);
        $payload = $chainService->verify($ticket);
        self::assertIsArray($payload);
        self::assertSame($chainX->chainId, (string) $payload['chainId'], 'the legacy record signs the EXACT chain X');
        self::assertSame($chainX->expiresAt, (int) $payload['expiresAt'], 'the legacy record signs X\'s server-held expiry (requirementFor(X))');

        // The read path never migrates the record (pure compat-read).
        $raw = json_decode((string) $this->client->get($this->key($nonceB)), true);
        self::assertIsArray($raw);
        self::assertSame(1, $raw['v'] ?? null, 'the read path never rewrites a legacy v1 record');
        self::assertArrayNotHasKey('chain_expires_at', $raw['disposition'] ?? []);

        // X's stage-2 challenge verifies (the obligation is cleared, the
        // chain record retained) and a fresh chain Y opens for the same
        // transaction: the signing never consults the current obligation —
        // the ticket stays byte-identical (X, X.expiresAt).
        $stage2Nonce = base64_encode(random_bytes(32));
        self::assertSame(ChainReservationResult::Available, $chainService->reserveStage2($chainX->chainId, 'owner-a'));
        self::assertSame(ChainIssuedResult::IssuedNew, $chainService->markIssued($chainX->chainId, 'owner-a', $stage2Nonce));
        self::assertSame(ChainVerifiedResult::VerifiedNew, $chainService->markVerified($chainX->chainId, $stage2Nonce));
        self::assertNull($chainService->findOpenRequirement('login', 'txn-alpha', 1), 'X\'s obligation is cleared');
        $chainY = $chainService->requireStage2(base64_encode(random_bytes(32)), 'login', 'txn-alpha', 1, RiskAction::Argon64, time() + 600);
        self::assertNotSame($chainX->chainId, $chainY->chainId, 'the cleared obligation opens a FRESH chain');
        self::assertSame($chainY->chainId, $chainService->findOpenRequirement('login', 'txn-alpha', 1)?->chainId, 'Y owns the current obligation');

        $violations = $this->validateToken($validator, $tokenB);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode());
        $ticket2 = $violations[0]->getParameters()['{{ chain_ticket }}'];
        self::assertIsString($ticket2);
        self::assertSame($ticket, $ticket2, 'the legacy-record ticket stays byte-identical with a concurrent chain Y open');
        $payload2 = $chainService->verify($ticket2);
        self::assertIsArray($payload2);
        self::assertSame($chainX->chainId, (string) $payload2['chainId'], 'the signing stays bound to the disposition\'s exact chain — never Y');
        self::assertSame($chainX->expiresAt, (int) $payload2['expiresAt'], 'the signed expiry is X\'s server-held bound — never Y\'s');
        self::assertNotSame($chainY->expiresAt, (int) $payload2['expiresAt'], 'Y\'s expiry must never leak into X\'s ticket');

        // The legacy fallback still requires the exact chain record: X is
        // gone -> fail closed temporary_unavailable, never a ticket.
        $this->client->del('{kiwi:ci-psd-chain}:chain:'.$chainX->chainId);
        $violations = $this->validateToken($validator, $tokenB);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'a legacy disposition whose chain record is gone is temporary_unavailable — never a ticket');
    }

    public function testLegacyV1ChainRequiredWithoutChainIdIsMalformed(): void
    {
        // The v1 compat window exempts only the absent chain_expires_at:
        // every other rule stays strict — a v1 chain_required record
        // without its chain id is still corrupt.
        $store = $this->store();
        $nonce = bin2hex(random_bytes(16));
        $raw = ['v' => 1, 'state' => 'complete', 'owner' => null, 'lease_until' => null, 'disposition' => ['kind' => 'chain_required', 'decision_id' => 'decision-1']];
        $this->client->set($this->key($nonce), (string) json_encode($raw), 'EX', 300);

        try {
            $store->read($nonce);
            self::fail('the strict decoder must refuse a v1 ChainRequired record without a chain id');
        } catch (MalformedPostSolveDispositionException $e) {
            self::assertStringContainsString('chain id', $e->getMessage());
        }
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $this->corruptRecordOutcome($raw), 'a v1 ChainRequired record without a chain id must fail closed as temporary_unavailable');
    }

    public function testChainRequiredSigningWithMismatchedCarriedExpiryFailsClosedAgainstRealRedis(): void
    {
        // A shape-valid chain_expires_at that differs from the exact
        // chain record's server-held expiresAt is corrupt state — the
        // signing fails closed temporary_unavailable, never a ticket that
        // outlives (or expires early vs) its chain. The matching value
        // signs normally.
        $storage = new RedisStorage($this->client, 'ci-psd-mismatch:');
        $chainStore = new RedisChainedChallengeStateStore($this->client, 'ci-psd-chain');
        $chainService = new ChainedChallengeTicketService($chainStore, self::SECRET, 300, 15);
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $gateway = $this->chainedStageGateway($resolver);
        $dispositions = $this->store();

        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage);
        $stage1 = $issuer->issue('login', '198.51.100.7');
        $tokenB = $this->solve($stage1);
        $nonceB = SolutionToken::decode($tokenB)->nonce;

        $verifier = new Verifier($storage);
        $nowNs = (int) (microtime(true) * 1_000_000) + 1_000_000;
        self::assertTrue($verifier->verify($tokenB, self::SECRET, 'login', '198.51.100.7', $nowNs)->isOk());

        $chainX = $chainService->requireStage2(base64_encode(random_bytes(32)), 'login', 'txn-alpha', 1, RiskAction::Argon32, time() + 300);

        // A shape-valid v2 record whose carried bound is X.expiry + 1000:
        // the exact-bound comparison refuses it.
        $wrong = [
            'v' => 2,
            'state' => 'complete',
            'owner' => null,
            'lease_until' => null,
            'disposition' => ['kind' => 'chain_required', 'chain_id' => $chainX->chainId, 'decision_id' => 'decision-D', 'chain_expires_at' => $chainX->expiresAt + 1000],
            'decision_id' => 'decision-D',
        ];
        $this->client->set($this->key($nonceB), (string) json_encode($wrong), 'EX', 300);

        $validator = $this->chainedStageValidator($verifier, $storage, $chainService, $resolver, $gateway, $dispositions);
        $violations = $this->validateToken($validator, $tokenB);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR, $violations[0]->getCode(), 'a mismatched carried expiry must fail closed — never a ticket');
        self::assertArrayNotHasKey('{{ chain_ticket }}', $violations[0]->getParameters(), 'no ticket is produced for the mismatched bound');

        // The matching value signs normally with the exact chain's bound.
        $right = [
            'v' => 2,
            'state' => 'complete',
            'owner' => null,
            'lease_until' => null,
            'disposition' => ['kind' => 'chain_required', 'chain_id' => $chainX->chainId, 'decision_id' => 'decision-D', 'chain_expires_at' => $chainX->expiresAt],
            'decision_id' => 'decision-D',
        ];
        $this->client->set($this->key($nonceB), (string) json_encode($right), 'EX', 300);
        $violations = $this->validateToken($validator, $tokenB);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptchaValidator::CHAIN_REQUIRED_ERROR, $violations[0]->getCode(), 'the matching carried expiry signs normally');
        $ticket = $violations[0]->getParameters()['{{ chain_ticket }}'];
        self::assertIsString($ticket);
        $payload = $chainService->verify($ticket);
        self::assertIsArray($payload);
        self::assertSame($chainX->chainId, (string) $payload['chainId']);
        self::assertSame($chainX->expiresAt, (int) $payload['expiresAt'], 'the ticket signs the exact chain record\'s bound');
    }

// ── the two-phase wire migration (compatibility direction) ──────────────────

    public function testCompatibilityWriterRecordReadsUnderTheEarlierReleaseDecoder(): void
    {
        // THE missing mixed-version direction: a record written by this
        // release (v1 + chain_expires_at for chain_required) must parse
        // under the earlier release's strict decoder — the wire a rolling
        // upgrade leaves behind for older nodes is never malformed.
        $store = $this->store();
        $nonce = bin2hex(random_bytes(16));
        $expiry = time() + 300;

        self::assertSame('claimed', $store->claim($nonce, 'owner-a', 300));
        $pendingRaw = json_decode((string) $this->client->get($this->key($nonce)), true);
        self::assertIsArray($pendingRaw);
        self::assertSame(1, $pendingRaw['v'] ?? null, 'the claim Lua writes schema v1');
        self::assertTrue($store->finalize($nonce, 'owner-a', new PostSolveDisposition(PostSolveDispositionKind::ChainRequired, 'decision-2', 'chain-xyz', $expiry)));

        $rec = self::legacyV1Decode((string) $this->client->get($this->key($nonce)));
        self::assertSame('chain_required', $rec['disposition']['kind']);
        self::assertSame('decision-2', $rec['disposition']['decision_id']);
        self::assertSame('chain-xyz', $rec['disposition']['chain_id']);
        self::assertSame($expiry, $rec['disposition']['chain_expires_at'], 'the carried expiry reads back intact under the earlier decoder');

        // The fixture is the exact earlier semantics: a v2 record is refused.
        $v2 = json_decode((string) $this->client->get($this->key($nonce)), true);
        $v2['v'] = 2;
        try {
            self::legacyV1Decode((string) json_encode($v2));
            self::fail('the earlier release decoder must refuse schema version 2');
        } catch (MalformedPostSolveDispositionException $e) {
            self::assertStringContainsString('schema version', $e->getMessage());
        }
    }

    /**
     * The earlier release's strict decoder, frozen as a fixture: the
     * schema version must be 1 (anything else throws
     * MalformedPostSolveDispositionException), chain_required accepts the
     * carried chain_expires_at, and every other shape rule stays strict.
     *
     * @return array<string, mixed> the decoded record
     *
     * @throws MalformedPostSolveDispositionException
     */
    private static function legacyV1Decode(string $raw): array
    {
        $rec = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        if (!\is_array($rec)) {
            throw new MalformedPostSolveDispositionException('post-solve disposition record must be a JSON object');
        }
        if (($rec['v'] ?? null) !== 1) {
            throw new MalformedPostSolveDispositionException('post-solve disposition record schema version must be 1');
        }
        $state = $rec['state'] ?? null;
        if (!\is_string($state) || !\in_array($state, ['pending', 'complete'], true)) {
            throw new MalformedPostSolveDispositionException('post-solve disposition record state must be pending|complete');
        }
        $owner = $rec['owner'] ?? null;
        $leaseUntil = $rec['lease_until'] ?? null;
        $disposition = $rec['disposition'] ?? null;
        if ($state === 'pending') {
            if (!\is_string($owner) || $owner === '') {
                throw new MalformedPostSolveDispositionException('post-solve disposition record owner is required in the pending state');
            }
            if (!\is_int($leaseUntil)) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record lease_until must be an integer in the pending state');
            }
            if ($disposition !== null) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record disposition must be null in the pending state');
            }
        } else {
            if ($owner !== null || $leaseUntil !== null) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record owner/lease_until must be null in the complete state');
            }
            if (!\is_array($disposition)) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record disposition is required in the complete state');
            }
            $kind = $disposition['kind'] ?? null;
            if (!\is_string($kind) || PostSolveDispositionKind::tryFrom($kind) === null) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record kind must be a valid disposition kind');
            }
            $decisionId = $disposition['decision_id'] ?? null;
            if ($decisionId !== null && (!\is_string($decisionId) || $decisionId === '')) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record decision_id must be a non-empty string or null');
            }
            $chainId = $disposition['chain_id'] ?? null;
            if ($chainId !== null && (!\is_string($chainId) || preg_match('/^[A-Za-z0-9_-]{1,64}$/D', $chainId) !== 1)) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record chain_id must match the chain id shape or be null');
            }
            if ($kind === PostSolveDispositionKind::ChainRequired->value && ($chainId === null || $chainId === '')) {
                throw new MalformedPostSolveDispositionException('a ChainRequired disposition must carry a chain id');
            }
            if ($kind !== PostSolveDispositionKind::ChainRequired->value && $chainId !== null) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record chain_id must be null outside the ChainRequired kind');
            }
            $chainExpiresAt = $disposition['chain_expires_at'] ?? null;
            if ($kind === PostSolveDispositionKind::ChainRequired->value) {
                if ($chainExpiresAt !== null && (!\is_int($chainExpiresAt) || $chainExpiresAt <= 0)) {
                    throw new MalformedPostSolveDispositionException('a ChainRequired disposition record must carry a positive integer chain_expires_at');
                }
            } elseif ($chainExpiresAt !== null) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record chain_expires_at must be null outside the ChainRequired kind');
            }
        }
        $recordDecisionId = $rec['decision_id'] ?? null;
        if ($recordDecisionId !== null && (!\is_string($recordDecisionId) || $recordDecisionId === '')) {
            throw new MalformedPostSolveDispositionException('post-solve disposition record decision_id must be a non-empty string or null');
        }

        return $rec;
    }
}
