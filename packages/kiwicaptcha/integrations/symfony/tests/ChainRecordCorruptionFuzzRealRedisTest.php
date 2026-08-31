<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\ArrayChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\MalformedChainedChallengeStateException;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\TransactionalChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\ChainModel;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\ChainStateWalk;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use KiwiCaptcha\Risk\RiskAction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The deterministic chain-record corruption fuzz, the systematic
 * extension of the adversarial fault-injection discipline to the chain
 * stores. Every stored chain record field is tampered one at a time
 * (plus fixed-seed random byte flips) across the available, reserved,
 * issued and denied states, and every corruption must fail closed.
 *
 * Every store boundary resolves the strict decode exception or the
 * documented refusal vocabulary, deterministically, twice. A corrupt
 * record is never mutated. The obligation mapping stays untouched,
 * and the create-or-get heals the corrupt mapping with a fresh chain
 * on both stores. A flipped record that still strictly decodes stays
 * schema-coherent (the ChainModel schema invariants hold), and the
 * machine continues on the record's own fields without an exception.
 *
 * The shape-valid forgeries (a foreign scope or request binding, a
 * consistent rank swap, a future expiry on an expired chain) are
 * pinned. Chain record fields are unauthenticated state (the ticket
 * HMAC covers the chain id and the expiry only), so the strict decode
 * accepts them and the machine serves them coherently.
 *
 * Runs in the dedicated "Real-Redis concurrency" CI lane; skips
 * without the published Redis env, fails instead of skipping when
 * KIWI_REQUIRE_REAL_REDIS_TESTS is set and the env is missing.
 */
final class ChainRecordCorruptionFuzzRealRedisTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const NAMESPACE = 'ci-chain-corruption-fuzz';

    private \Predis\Client $client;

    protected function setUp(): void
    {
        $url = RedisTestUrl::resolve();
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis suites run in the dedicated Redis-service lane');
        }
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis not installed');
        }
        $this->client = new \Predis\Client($url, ['timeout' => 10.0, 'read_write_timeout' => 10.0]);
        try {
            $this->client->ping();
        } catch (\Throwable $e) {
            $this->failIfRealRedisRequired('no Redis is reachable at the configured KC_REDIS_URL/TEST_REDIS_URL ('.$e->getMessage().')');
            self::markTestSkipped('no Redis at the configured KC_REDIS_URL/TEST_REDIS_URL');
        }
        $this->client->flushdb();
    }

    private function failIfRealRedisRequired(string $why): void
    {
        $flag = getenv('KIWI_REQUIRE_REAL_REDIS_TESTS');
        if (\is_string($flag) && $flag !== '' && $flag !== '0') {
            self::fail($why.' — the chain-record corruption fuzz must run in the real-Redis CI lane');
        }
    }

    // ── helpers ─────────────────────────────────────────────────────────

    private function store(): RedisChainedChallengeStateStore
    {
        return new RedisChainedChallengeStateStore($this->client, self::NAMESPACE);
    }

    private function service(): ChainedChallengeTicketService
    {
        return new ChainedChallengeTicketService($this->store(), self::SECRET, 300, 15);
    }

    private function chainKey(string $chainId): string
    {
        return sprintf('{kiwi:%s}:chain:%s', self::NAMESPACE, $chainId);
    }

    private function obligationKey(string $obligationId): string
    {
        return sprintf('{kiwi:%s}:chain-obligation:%s', self::NAMESPACE, $obligationId);
    }

    /** Prepare a chain record to one of the four fuzz states. */
    private function prepareState(TransactionalChainedChallengeStateStore $store, string $chainId, string $state): void
    {
        if ($state === 'available') {
            return;
        }
        self::assertSame('available', $store->reserve($chainId, ChainStateWalk::OWNERS[0], 15), 'the prepare reservation must land');
        if ($state === 'reserved') {
            return;
        }
        self::assertSame('issued_new', $store->markIssued($chainId, ChainStateWalk::OWNERS[0], ChainStateWalk::NONCES[0]), 'the prepare mint must land');
        if ($state === 'issued') {
            return;
        }
        self::assertSame('denied_new', $store->markDenied($chainId, ChainStateWalk::NONCES[0]), 'the prepare denial must land');
    }

    /**
     * The refusal matrix: every mutating boundary throws the strict
     * decode exception on a corrupt record, deterministically, twice.
     */
    private function assertEveryBoundaryFailsClosed(TransactionalChainedChallengeStateStore $store, string $chainId, string $obligationId, string $context): void
    {
        $boundaries = [
            'read' => static fn () => $store->read($chainId),
            'reserve' => static fn () => $store->reserve($chainId, ChainStateWalk::OWNERS[0], 15),
            'markIssued' => static fn () => $store->markIssued($chainId, ChainStateWalk::OWNERS[0], ChainStateWalk::NONCES[0]),
            'markVerified' => static fn () => $store->markVerified($chainId, ChainStateWalk::NONCES[0]),
            'markStepUpRequired' => static fn () => $store->markStepUpRequired($chainId, ChainStateWalk::NONCES[0]),
            'markDenied' => static fn () => $store->markDenied($chainId, ChainStateWalk::NONCES[0]),
            'markTransactionDenied' => static fn () => $store->markTransactionDenied($chainId, $obligationId),
            'markTransactionStepUpRequired' => static fn () => $store->markTransactionStepUpRequired($chainId, $obligationId),
            'rearmIssued' => static fn () => $store->rearmIssued($chainId, ChainStateWalk::NONCES[0]),
            'complete' => static fn () => $store->complete($chainId, ChainStateWalk::OWNERS[0], ChainStateWalk::NONCES[0]),
            'release' => static fn () => $store->release($chainId, ChainStateWalk::OWNERS[0]),
        ];
        foreach ($boundaries as $name => $call) {
            for ($attempt = 0; $attempt < 2; ++$attempt) {
                try {
                    $call();
                    self::fail(sprintf('%s: %s must fail closed on the corrupt record', $context, $name));
                } catch (MalformedChainedChallengeStateException $e) {
                    self::assertStringContainsString('chain record', $e->getMessage(), $context.': '.$name);
                }
            }
        }
    }

    /**
     * The heal assertion: the create-or-get repairs the corrupt mapping
     * with a fresh chain, strictly decodable and schema-coherent.
     */
    private function assertMappingHeals(TransactionalChainedChallengeStateStore $store, string $obligationId, string $freshChainId, string $context): void
    {
        $repaired = $store->createOrGetObligation(
            $obligationId,
            $freshChainId,
            ChainStateWalk::S1_NONCE,
            'login',
            'txn-alpha',
            'sha16',
            1,
            1,
            time() + 300,
            300,
        );
        self::assertSame($freshChainId, $repaired, $context.': the create-or-get heals the corrupt mapping with a fresh chain');
        self::assertSame($freshChainId, $store->obligationChainId($obligationId), $context.': the obligation now points at the fresh chain');
        $fresh = $store->read($freshChainId);
        self::assertIsArray($fresh, $context.': the healed chain strictly decodes');
        self::assertSame('available', $fresh['state'], $context.': the healed chain is available');
        ChainModel::assertSchemaInvariants($this->modelForRecord($fresh), $context.' healed');
    }

    /** @param array<string, mixed> $record */
    private function modelForRecord(array $record): ChainModel
    {
        $model = ChainModel::fresh((string) $record['obligationId']);
        $model->state = $record['state'] === 'completed' ? ChainModel::ISSUED : $record['state'];
        $model->owner = $record['owner'];
        $model->nonce = $record['stage2Nonce'];
        $model->rank = (int) $record['requiredRank'];
        $model->obligationPresent = true;
        $model->alive = true;

        return $model;
    }

    // ── 1. the field-by-field corruption matrix ─────────────────────────

    /**
     * The per-field tamper corpus: every chain record field, one at a
     * time, with values that break the strict v2 decode, plus the
     * drop-key shapes.
     *
     * @return array<string, \Closure>
     */
    private static function fieldTampers(): array
    {
        return [
            'schema version' => static fn (array &$r): array => ['v' => 3] + $r,
            'schema version dropped' => static function (array &$r): array {
                unset($r['v']);

                return $r;
            },
            'stage1Nonce foreign' => static fn (array &$r): array => ['stage1Nonce' => 'not-a-kiwi-nonce'] + $r,
            'scope with a space' => static fn (array &$r): array => ['scope' => 'bad scope'] + $r,
            'obligationId non-hex' => static fn (array &$r): array => ['obligationId' => 'zzzz'] + $r,
            'requiredAction foreign' => static fn (array &$r): array => ['requiredAction' => 'sha8'] + $r,
            'requiredRank mismatch' => static fn (array &$r): array => ['requiredRank' => 6] + $r,
            'requiredRank dropped' => static function (array &$r): array {
                unset($r['requiredRank']);

                return $r;
            },
            'policyVersion zeroed' => static fn (array &$r): array => ['policyVersion' => 0] + $r,
            'chainDepth one' => static fn (array &$r): array => ['chainDepth' => 1] + $r,
            'state foreign' => static fn (array &$r): array => ['state' => 'bogus'] + $r,
            'state dropped' => static function (array &$r): array {
                unset($r['state']);

                return $r;
            },
            'owner non-string on a reserved record' => static fn (array &$r): array => ['owner' => 7] + $r,
            'leaseUntil string on a reserved record' => static fn (array &$r): array => ['leaseUntil' => 'soon'] + $r,
            'stage2Nonce foreign' => static fn (array &$r): array => ['stage2Nonce' => 'not-a-kiwi-nonce'] + $r,
            'requestBinding with a space' => static fn (array &$r): array => ['requestBinding' => 'bad binding'] + $r,
            'expiresAt string' => static fn (array &$r): array => ['expiresAt' => 'soon'] + $r,
            'expiresAt dropped' => static function (array &$r): array {
                unset($r['expiresAt']);

                return $r;
            },
        ];
    }

    /**
     * @return iterable<string, array{0: string, 1: string, 2: \Closure}>
     */
    public static function fieldTamperProvider(): iterable
    {
        foreach (['available', 'reserved', 'issued', 'denied'] as $state) {
            foreach (self::fieldTampers() as $label => $tamper) {
                yield $state.': '.$label => [$state, $label, $tamper];
            }
        }
    }

    /**
     * @param string   $state
     * @param string   $label
     * @param \Closure $tamper
     */
    #[DataProvider('fieldTamperProvider')]
    public function testEveryChainFieldTamperFailsClosedAndTheMappingHeals(string $state, string $label, \Closure $tamper): void
    {
        $store = $this->store();
        $service = $this->service();
        $obligationId = $service->obligationIdFor('login', 'txn-alpha', 1);
        $requirement = $service->requireStage2(ChainStateWalk::S1_NONCE, 'login', 'txn-alpha', 1, RiskAction::Sha16, time() + 300);
        $this->prepareState($store, $requirement->chainId, $state);

        $raw = $this->client->get($this->chainKey($requirement->chainId));
        self::assertIsString($raw);
        $record = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        $tampered = $tamper($record);
        $this->client->set($this->chainKey($requirement->chainId), (string) json_encode($tampered, JSON_THROW_ON_ERROR), 'EX', 300);

        $this->assertEveryBoundaryFailsClosed($store, $requirement->chainId, $obligationId, 'redis '.$state.' '.$label);
        self::assertSame($requirement->chainId, $store->obligationChainId($obligationId), 'the refusals leave the mapping alone');
        $this->assertMappingHeals($store, $obligationId, 'chain-healed-'.$state.'-'.$label, 'redis');

        // The Array mirror observes the identical machine: same throws,
        // same heal.
        $array = new ArrayChainedChallengeStateStore();
        $arrayService = new ChainedChallengeTicketService($array, self::SECRET, 300, 15);
        $arrayRequirement = $arrayService->requireStage2(ChainStateWalk::S1_NONCE, 'login', 'txn-alpha', 1, RiskAction::Sha16, time() + 300);
        $this->prepareState($array, $arrayRequirement->chainId, $state);
        $records = (new \ReflectionObject($array))->getProperty('records')->getValue($array);
        $records[$arrayRequirement->chainId] = $tamper($records[$arrayRequirement->chainId]);
        (new \ReflectionObject($array))->getProperty('records')->setValue($array, $records);

        $this->assertEveryBoundaryFailsClosed($array, $arrayRequirement->chainId, $obligationId, 'array '.$state.' '.$label);
        $this->assertMappingHeals($array, $obligationId, 'array-healed-'.$state.'-'.$label, 'array');
    }

    // ── 2. the fixed-seed random byte flips ─────────────────────────────

    /**
     * Fixed-seed byte flips on the raw chain record: every boundary
     * either throws the strict decode exception or answers the
     * documented vocabulary, never an unexpected exception type, and a
     * flipped record that still strictly decodes stays schema-coherent.
     */
    public function testRandomByteFlipsOnChainRecordsFailClosedOrStayCoherent(): void
    {
        $rng = 0xC0FFEE;
        foreach (['available', 'reserved', 'issued', 'denied'] as $state) {
            for ($case = 0; $case < 10; ++$case) {
                $store = $this->store();
                $service = $this->service();
                // A unique binding per case: the obligation mapping is
                // persistent state, and every case must observe a clean
                // mapping of its own transaction.
                $binding = 'txn-'.$state.'-'.$case;
                $obligationId = $service->obligationIdFor('login', $binding, 1);
                $requirement = $service->requireStage2(ChainStateWalk::S1_NONCE, 'login', $binding, 1, RiskAction::Sha16, time() + 300);
                $this->prepareState($store, $requirement->chainId, $state);
                $raw = (string) $this->client->get($this->chainKey($requirement->chainId));

                $rng = (1103515245 * $rng + 12345) & 0x7fffffff;
                $flips = 1 + $rng % 3;
                for ($i = 0; $i < $flips; ++$i) {
                    $rng = (1103515245 * $rng + 12345) & 0x7fffffff;
                    $pos = $rng % \strlen($raw);
                    $raw[$pos] = $raw[$pos] === 'A' ? 'B' : 'A';
                }
                $this->client->set($this->chainKey($requirement->chainId), $raw, 'EX', 300);

                $this->assertFlipOutcome($store, $requirement->chainId, $obligationId, $state, $case);
            }
        }
    }

    /**
     * The flip outcome contract: every boundary resolves the documented
     * exception or the documented vocabulary, a decodable record keeps
     * the schema invariants, and the mapping resolves to a
     * strict-decodable chain. A flip that renames an optional key is
     * rejected by the strict decode: validateState() and the Lua
     * predicate both deny unknown fields, so the record fails closed
     * and the create-or-get heals the corrupt mapping with a fresh
     * chain. The wire decode can never surface an undefined-key warning,
     * because a record reaching wire() always passed the deny-unknown
     * gate.
     */
    private function assertFlipOutcome(TransactionalChainedChallengeStateStore $store, string $chainId, string $obligationId, string $state, int $case): void
    {
        $context = sprintf('%s flip-%d', $state, $case);
        $read = $this->assertFlipBoundaries($store, $chainId, $obligationId, $context);
        $fresh = 'chain-flip-healed-'.$state.'-'.$case;
        $repaired = $store->createOrGetObligation($obligationId, $fresh, ChainStateWalk::S1_NONCE, 'login', 'txn-alpha', 'sha16', 1, 1, time() + 300, 300);
        $postRead = $repaired === $fresh ? $store->read($fresh) : $store->read($chainId);
        if (\is_array($read)) {
            ChainModel::assertSchemaInvariants($this->modelForRecord($read), $context.' decodable record');
        }
        self::assertSame($repaired, $store->obligationChainId($obligationId), $context.': the obligation resolves to the returned chain');
        self::assertIsArray($postRead, $context.': the resolved chain strictly decodes');
        if ($repaired === $fresh) {
            // The mapping was corrupt or missing: the create-or-get
            // healed it with the fresh chain.
            self::assertSame('available', $postRead['state'], $context.': the healed chain is available');
        } else {
            // The flipped record stayed strictly valid: the create-or-get
            // keeps the live obligation on its existing chain, and the
            // record keeps the schema invariants.
            self::assertSame($chainId, $repaired, $context.': a still-valid flipped record keeps its chain');
            ChainModel::assertSchemaInvariants($this->modelForRecord($postRead), $context.' kept record');
        }
    }

    /**
     * The boundary sweep of the flip contract; returns the read record,
     * or null when the read failed closed.
     *
     * @return array<string, mixed>|null
     */
    private function assertFlipBoundaries(TransactionalChainedChallengeStateStore $store, string $chainId, string $obligationId, string $context): ?array
    {
        $boundaries = [
            'read' => static fn () => $store->read($chainId),
            'reserve' => static fn () => $store->reserve($chainId, ChainStateWalk::OWNERS[0], 15),
            'markIssued' => static fn () => $store->markIssued($chainId, ChainStateWalk::OWNERS[0], ChainStateWalk::NONCES[0]),
            'markVerified' => static fn () => $store->markVerified($chainId, ChainStateWalk::NONCES[0]),
            'markStepUpRequired' => static fn () => $store->markStepUpRequired($chainId, ChainStateWalk::NONCES[0]),
            'markDenied' => static fn () => $store->markDenied($chainId, ChainStateWalk::NONCES[0]),
            'markTransactionDenied' => static fn () => $store->markTransactionDenied($chainId, $obligationId),
            'markTransactionStepUpRequired' => static fn () => $store->markTransactionStepUpRequired($chainId, $obligationId),
            'rearmIssued' => static fn () => $store->rearmIssued($chainId, ChainStateWalk::NONCES[0]),
            'complete' => static fn () => $store->complete($chainId, ChainStateWalk::OWNERS[0], ChainStateWalk::NONCES[0]),
            'release' => static fn () => $store->release($chainId, ChainStateWalk::OWNERS[0]),
        ];
        $read = null;
        foreach ($boundaries as $name => $call) {
            try {
                $out = $call();
                if ($name === 'read') {
                    $read = $out;
                }
                self::assertTrue(
                    $out === null
                    || $out === false
                    || \is_array($out)
                    || \in_array($out, ['available', 'retry', 'busy', 'taken_over', 'issued', 'verified', 'completed', 'step_up_required', 'denied', 'missing', 'issued_new', 'issued_same', 'verified_same', 'conflict', 'not_owner', 'verified_new', 'step_up_required_new', 'step_up_required_same', 'denied_new', 'denied_same', 'already_completed', 'already_verified', 'obligation_moved'], true),
                    $context.': '.$name.' answers the documented vocabulary',
                );
            } catch (MalformedChainedChallengeStateException) {
                // The documented fail-closed decode.
            } catch (\Throwable $e) {
                self::fail(sprintf('%s: %s threw an unexpected %s: %s', $context, $name, $e::class, $e->getMessage()));
            }
        }

        return $read;
    }

    // ── 3. the shape-valid forgery surface (pinned) ─────────────────────

    /**
     * A shape-valid forged record field passes the strict decode: the
     * chain record fields are unauthenticated state (the ticket HMAC
     * covers the chain id and the expiry only, never the record), so
     * the store serves the forged fields coherently. The machine stays
     * on the record's own fields with no exception. The forged scope or
     * binding only rebinds, the consistent rank swap only re-labels
     * the required action, and a future expiry resurrects an expired
     * chain exactly like the state-marker flip on the core envelope.
     * Pinned as the current behavior: hardening would sign the required
     * action/rank into the ticket or the stage-2 challenge.
     */
    public function testShapeValidForgedChainFieldsStayCoherentPinned(): void
    {
        $store = $this->store();
        $service = $this->service();
        $obligationId = $service->obligationIdFor('login', 'txn-alpha', 1);
        $requirement = $service->requireStage2(ChainStateWalk::S1_NONCE, 'login', 'txn-alpha', 1, RiskAction::Sha16, time() + 300);
        $chainId = $requirement->chainId;
        $this->prepareState($store, $chainId, 'available');

        $raw = $this->client->get($this->chainKey($chainId));
        self::assertIsString($raw);
        $record = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);

        // The foreign scope and the foreign transaction binding are
        // well-formed identifiers: the strict decode accepts them.
        $record['scope'] = 'admin';
        $record['requestBinding'] = 'txn-other';
        $this->client->set($this->chainKey($chainId), (string) json_encode($record, JSON_THROW_ON_ERROR), 'EX', 300);
        $served = $store->read($chainId);
        self::assertIsArray($served, 'the shape-valid forgery strictly decodes');
        self::assertSame('admin', $served['scope'], 'the forged scope is served as the record\'s own');
        self::assertSame('txn-other', $served['requestBinding'], 'the forged binding is served as the record\'s own');
        self::assertSame('available', $store->reserve($chainId, ChainStateWalk::OWNERS[0], 15), 'the machine transitions on the forged record coherently');

        // A consistent rank swap (action plus rank) passes the strict
        // decode: nothing authenticates the required work of the chain
        // record itself.
        $record2 = json_decode((string) $this->client->get($this->chainKey($chainId)), true, 8, JSON_THROW_ON_ERROR);
        $record2['state'] = 'available';
        $record2['owner'] = null;
        $record2['leaseUntil'] = null;
        $record2['requiredAction'] = 'argon64';
        $record2['requiredRank'] = 6;
        $this->client->set($this->chainKey($chainId), (string) json_encode($record2, JSON_THROW_ON_ERROR), 'EX', 300);
        $swapped = $store->read($chainId);
        self::assertIsArray($swapped, 'the consistent rank swap strictly decodes');
        self::assertSame('argon64', $swapped['requiredAction'], 'PINNED: the required action on the chain record is unauthenticated state');
        self::assertSame(6, $swapped['requiredRank'], 'PINNED: the required rank on the chain record is unauthenticated state');

        // A foreign reservation owner on a reserved chain passes the
        // strict decode: the reservation is owner-scoped state, and the
        // machine serves the foreign owner's reservation coherently.
        $storeOwner = $this->store();
        $serviceOwner = $this->service();
        $requirementOwner = $serviceOwner->requireStage2(ChainStateWalk::S1_NONCE, 'login', 'txn-owner-swap', 1, RiskAction::Sha16, time() + 300);
        $this->prepareState($storeOwner, $requirementOwner->chainId, 'reserved');
        $rawOwner = $this->client->get($this->chainKey($requirementOwner->chainId));
        self::assertIsString($rawOwner);
        $recordOwner = json_decode($rawOwner, true, 8, JSON_THROW_ON_ERROR);
        $recordOwner['owner'] = ChainStateWalk::OWNERS[1];
        $this->client->set($this->chainKey($requirementOwner->chainId), (string) json_encode($recordOwner, JSON_THROW_ON_ERROR), 'EX', 300);
        $servedOwner = $storeOwner->read($requirementOwner->chainId);
        self::assertIsArray($servedOwner, 'the shape-valid foreign owner strictly decodes');
        self::assertSame(ChainStateWalk::OWNERS[1], $servedOwner['owner'], 'the forged owner is served as the record\'s own');
        self::assertSame('issued_new', $storeOwner->markIssued($requirementOwner->chainId, ChainStateWalk::OWNERS[1], ChainStateWalk::NONCES[0]), 'the machine mints on the forged owner\'s reservation');
        self::assertSame('conflict', $storeOwner->markIssued($requirementOwner->chainId, ChainStateWalk::OWNERS[0], ChainStateWalk::NONCES[1]), 'the displaced owner cannot re-mint a different nonce on the issued chain');

        // A foreign stage-2 nonce of the valid shape passes the strict
        // decode: the chain serves the record's own nonce, and the
        // verification transitions follow it coherently.
        $store3 = $this->store();
        $service3 = $this->service();
        $requirement3 = $service3->requireStage2(ChainStateWalk::S1_NONCE, 'login', 'txn-nonce-swap', 1, RiskAction::Sha16, time() + 300);
        $this->prepareState($store3, $requirement3->chainId, 'issued');
        $raw3 = $this->client->get($this->chainKey($requirement3->chainId));
        self::assertIsString($raw3);
        $record4 = json_decode($raw3, true, 8, JSON_THROW_ON_ERROR);
        $record4['stage2Nonce'] = ChainStateWalk::NONCES[1];
        $this->client->set($this->chainKey($requirement3->chainId), (string) json_encode($record4, JSON_THROW_ON_ERROR), 'EX', 300);
        $served = $store3->read($requirement3->chainId);
        self::assertIsArray($served, 'the shape-valid foreign nonce strictly decodes');
        self::assertSame(ChainStateWalk::NONCES[1], $served['stage2Nonce'], 'the forged nonce is served as the record\'s own');
        self::assertSame('verified_new', $store3->markVerified($requirement3->chainId, ChainStateWalk::NONCES[1]), 'the machine passes on the record\'s own nonce');
        self::assertSame('conflict', $store3->markVerified($requirement3->chainId, ChainStateWalk::NONCES[0]), 'the genuine nonce no longer matches the record');

        // A renamed optional key (requestBinding) is rejected by the
        // chain strict decode: validateState() denies unknown fields
        // (mirroring the core ChallengeRecord::fromArray strictness), so
        // a record whose key was renamed fails closed with the
        // MalformedChainedChallengeStateException instead of being
        // served with the optional field nulled — and the undefined-key
        // warning of the wire decode can never surface.
        $storeRename = $this->store();
        $serviceRename = $this->service();
        $requirementRename = $serviceRename->requireStage2(ChainStateWalk::S1_NONCE, 'login', 'txn-key-rename', 1, RiskAction::Sha16, time() + 300);
        $rawRename = $this->client->get($this->chainKey($requirementRename->chainId));
        self::assertIsString($rawRename);
        $renamed = str_replace('"requestBinding"', '"requestBInding"', $rawRename, $count);
        self::assertSame(1, $count, 'the rename must land');
        $this->client->set($this->chainKey($requirementRename->chainId), $renamed, 'EX', 300);
        try {
            $storeRename->read($requirementRename->chainId);
            self::fail('a renamed optional key must be refused by the chain strict decode');
        } catch (MalformedChainedChallengeStateException $e) {
            // The refusal surfaces either through the Lua read boundary
            // (the predicate's deny-unknown-fields rejects the record
            // first, 'malformed at the read boundary') or through the
            // PHP decoder ('unknown key') when the raw bytes reach
            // validateState directly.
            self::assertTrue(
                str_contains($e->getMessage(), 'unknown key') || str_contains($e->getMessage(), 'malformed at the read boundary'),
                'the refusal names the deny-unknown-fields rule',
            );
        }

        // A future expiry on an expired chain resurrects it: the
        // lifetime guard reads the record's own expiry, exactly like
        // the state-marker flip on the core envelope. The chain is
        // created with a live expiry, its record expiry is then
        // rewritten into the past (the expired-but-live fail-closed
        // corner), and the same rewrite back into the future serves it
        // again.
        $store2 = $this->store();
        $service2 = new ChainedChallengeTicketService($store2, self::SECRET, 300, 15);
        $requirement2 = $service2->requireStage2(ChainStateWalk::S1_NONCE, 'login', 'txn-expired', 1, RiskAction::Sha16, time() + 300);
        $chainId2 = $requirement2->chainId;
        $raw2 = $this->client->get($this->chainKey($chainId2));
        self::assertIsString($raw2);
        $record3 = json_decode($raw2, true, 8, JSON_THROW_ON_ERROR);
        $record3['expiresAt'] = time() - 100;
        $this->client->set($this->chainKey($chainId2), (string) json_encode($record3, JSON_THROW_ON_ERROR), 'EX', 300);
        self::assertNull($store2->read($chainId2), 'the expired-but-live record fails closed');
        $record3['expiresAt'] = time() + 300;
        $this->client->set($this->chainKey($chainId2), (string) json_encode($record3, JSON_THROW_ON_ERROR), 'EX', 300);
        $resurrected = $store2->read($chainId2);
        self::assertIsArray($resurrected, 'PINNED: a future expiry on the record resurrects the expired chain (the record fields are unauthenticated)');
        self::assertSame('available', $store2->reserve($chainId2, ChainStateWalk::OWNERS[0], 15), 'the resurrected chain serves the reservation');
    }
}
