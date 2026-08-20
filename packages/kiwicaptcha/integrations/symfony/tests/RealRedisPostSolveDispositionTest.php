<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\MalformedPostSolveDispositionException;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDisposition;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisPostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore;
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
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Validator\ConstraintValidatorFactory;
use Symfony\Component\Validator\Validation;

/**
 * REAL-REDIS post-solve disposition tests (127.0.0.1:6399 — skipped when
 * unreachable).
 *
 * Exercises the store's single-Lua state machine (claim / takeover /
 * finalize / replay) and the full end-to-end replay guarantee that fakes
 * cannot prove: a valid token whose post-solve assessment DENIES replays
 * as DENY from the persisted nonce-keyed disposition, and the replay
 * NEVER re-runs the assessment (exactly one risk observation).
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

        // finalize by a NON-owner is refused; by the OWNER it completes.
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

        // Expired-lease takeover: a SEPARATE pending claim whose
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

        self::assertSame('claimed', $store->claim($nonce, 'owner-a', 300));
        self::assertTrue($store->finalize($nonce, 'owner-a', new PostSolveDisposition(PostSolveDispositionKind::ChainRequired, 'decision-2', 'chain-xyz')));

        $raw = json_decode((string) $this->client->get($this->key($nonce)), true);
        self::assertIsArray($raw);
        self::assertSame(1, $raw['v']);
        self::assertSame('complete', $raw['state']);
        self::assertNull($raw['owner']);
        self::assertNull($raw['lease_until']);
        self::assertSame('chain_required', $raw['disposition']['kind']);
        self::assertSame('decision-2', $raw['disposition']['decision_id']);
        self::assertSame('chain-xyz', $raw['disposition']['chain_id']);
        self::assertArrayNotHasKey('vector', $raw['disposition']);
        self::assertArrayNotHasKey('fingerprint', $raw['disposition']);
        self::assertArrayNotHasKey('descriptor', $raw['disposition']);

        $record = $store->read($nonce);
        self::assertSame(PostSolveDispositionKind::ChainRequired, $record?->disposition?->kind);
        self::assertSame('chain-xyz', $record?->disposition?->chainId);
    }

// ── the decision handle in the disposition records ─────────────────────────

    public function testDecisionHandleSurvivesInThePendingAndCompleteRecords(): void
    {
        $store = $this->store();
        $nonce = bin2hex(random_bytes(16));

        self::assertSame('claimed', $store->claim($nonce, 'owner-a', 305, 'decision-original'));
        $record = $store->read($nonce);
        self::assertSame('pending', $record?->state);
        self::assertSame('decision-original', $record?->decisionId, 'the pending record carries the decision handle');
        self::assertNull($record?->disposition);

        // The COMPLETE record keeps the handle (the finalize never clears it).
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

        self::assertSame('claimed', $store->claim($nonce, 'owner-a', 305, 'decision-original'));
        // The lease expires; a NEW owner takes over with a DIFFERENT
        // handle — the ORIGINAL handle survives (the new owner's GETDEL is
        // empty after the first owner consumed the mapping).
        $rec = json_decode((string) $this->client->get($this->key($nonce)), true);
        self::assertIsArray($rec);
        $rec['lease_until'] = time() - 1;
        $this->client->set($this->key($nonce), (string) json_encode($rec), 'KEEPTTL');
        self::assertSame('taken_over', $store->claim($nonce, 'owner-b', 305, 'decision-new'));
        self::assertSame('decision-original', $store->read($nonce)?->decisionId, 'the takeover keeps the ORIGINAL decision handle — never the new owner\'s');
        self::assertTrue($store->finalize($nonce, 'owner-b', new PostSolveDisposition(PostSolveDispositionKind::Pass, 'decision-new')));
        $record = $store->read($nonce);
        self::assertSame('decision-original', $record?->decisionId, 'the completed disposition keeps the ORIGINAL handle');
    }

    public function testClaimWithoutDecisionHandleBehavesAsBefore(): void
    {
        $store = $this->store();
        $nonce = bin2hex(random_bytes(16));

        self::assertSame('claimed', $store->claim($nonce, 'owner-a', 305));
        self::assertNull($store->read($nonce)?->decisionId, 'no decision handle -> the records carry null');
        self::assertTrue($store->finalize($nonce, 'owner-a', new PostSolveDisposition(PostSolveDispositionKind::Pass)));
        $record = $store->read($nonce);
        self::assertNull($record?->decisionId);
        self::assertSame(PostSolveDispositionKind::Pass, $record?->disposition?->kind);
    }

// ── strict post-solve disposition decoding (ALL-OR-NOTHING) ────────────────

    /**
     * The end-to-end violation code of a FRESH valid token whose nonce's
     * disposition record is CORRUPT: the strict decoder must fail closed
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
        $raw = ['v' => 2, 'state' => 'pending', 'owner' => 'owner-a', 'lease_until' => time() - 1, 'disposition' => null];
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
        // A full valid solve through the REAL storage + the REAL
        // disposition store: the post-solve assessment denies, the denial
        // is persisted per nonce, and the replay of the SAME token
        // reproduces the denial from the disposition — the replay NEVER
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

        // FRESH validation: the post-solve assessment denies the valid solve.
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

        // REPLAY: the SAME token — the core replays its stored result, the
        // persisted disposition reproduces the SAME deny, and the
        // assessment NEVER runs again.
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
}
