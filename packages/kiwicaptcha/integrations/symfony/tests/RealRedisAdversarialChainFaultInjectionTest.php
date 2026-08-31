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
use BelConsulting\KiwiCaptchaBundle\Risk\TransactionalChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\ChainModel;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\ChainStateWalk;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisChainDriver;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use KiwiCaptcha\Risk\RiskAction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Adversarial fault injection over the real-Redis chained-challenge
 * state machine, the extension of the fault-injection discipline to
 * the corruption and forgery corners.
 *
 *  - corrupt and forged chain records on Redis: every store boundary
 *    fails closed with the strict v2 decode, and the create-or-get
 *    heals the mapping with a fresh chain exactly like the Array
 *    mirror.
 *  - forged chain tickets (tampered signature, payload, version,
 *    expiry, rotated secret): rejected before any store call, the
 *    genuine record and mapping stay byte-identical.
 *  - concurrent adversarial redemptions (malformed tickets, forged
 *    tickets, forged stage-2 nonces and one valid redemption): exactly
 *    one fresh mint, exactly one verified Pass, the obligation cleared.
 *  - foreign owner tokens: reserve, release and issue transitions are
 *    refused without mutation, checked step by step against the
 *    clean-room model.
 *  - expired-but-live records and lifetime-less keys: both stores fail
 *    closed identically at every boundary (the Array mirror's
 *    expiresAt-vs-clock sweep and the Redis key-lifetime + signed-expiry
 *    guards), and the create-or-get heals the stale mapping.
 *  - malformed stage-2 nonces: the write boundaries refuse the shape
 *    deterministically on both stores; a legacy malformed record still
 *    fails closed on read and heals.
 *
 * Runs in the real-Redis CI lane.
 */
final class RealRedisAdversarialChainFaultInjectionTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const NAMESPACE = 'ci-adversarial-chain';

    private \Predis\Client $client;

    protected function setUp(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis not installed');
        }
        $url = RedisTestUrl::resolve();
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis suites run in the CI Redis-service job');
        }
        $this->client = new \Predis\Client($url, ['timeout' => 10.0, 'read_write_timeout' => 10.0]);
        try {
            $this->client->ping();
        } catch (\Throwable $e) {
            self::markTestSkipped('Redis unreachable at '.$url.': '.$e->getMessage());
        }
        $this->client->flushdb();
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

    /** A deterministic Kiwi-shaped stage-2 nonce for a seed. */
    private function stageNonce(string $seed): string
    {
        return base64_encode(hash('sha256', 'adversarial-chain:'.$seed, true));
    }

    /**
     * Every store boundary must throw the strict decode exception on a
     * corrupt record, deterministically (the refusal matrix).
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
     * Prepare the record to the requested state on either store shape.
     */
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
     * The tamper on the Array mirror and the heal assertion, the exact
     * mirror of the Redis side of the corrupt-record test.
     */
    private function assertArrayMirrorHeals(string $label, \Closure $tamper, string $prepare, string $obligationId): void
    {
        $array = new ArrayChainedChallengeStateStore();
        $arrayService = new ChainedChallengeTicketService($array, self::SECRET, 300, 15);
        $requirement = $arrayService->requireStage2(ChainStateWalk::S1_NONCE, 'login', 'txn-adv', 1, RiskAction::Sha16, time() + 300);
        $this->prepareState($array, $requirement->chainId, $prepare);

        $records = (new \ReflectionObject($array))->getProperty('records')->getValue($array);
        $records[$requirement->chainId] = $tamper($records[$requirement->chainId]);
        (new \ReflectionObject($array))->getProperty('records')->setValue($array, $records);

        $this->assertEveryBoundaryFailsClosed($array, $requirement->chainId, $obligationId, 'array-mirror '.$label);

        $fresh = 'array-healed-'.$label;
        $returned = $array->createOrGetObligation($obligationId, $fresh, ChainStateWalk::S1_NONCE, 'login', 'txn-adv', 'sha16', 1, 1, time() + 300, 300);
        self::assertSame($fresh, $returned, 'the Array create-or-get must heal the corrupt mapping with a fresh chain');
        self::assertSame($fresh, $array->obligationChainId($obligationId), 'the Array obligation now points at the fresh chain');
        $freshRecord = $array->read($fresh);
        self::assertIsArray($freshRecord, 'the healed Array chain strictly decodes');
        self::assertSame('available', $freshRecord['state']);
    }

    // ── 1. corrupt and forged chain records on Redis ─────────────────────

    /**
     * @return iterable<string, array{0: string, 1: \Closure, 2: string}>
     */
    public static function corruptProvider(): iterable
    {
        yield 'wrong schema state' => [
            'wrong-schema',
            static fn (array $rec): array => [...$rec, 'state' => 'bogus', 'owner' => 'x', 'leaseUntil' => 1234],
            'available',
        ];
        yield 'forged stage-2 nonce in the issued state' => [
            'forged-nonce-issued',
            static fn (array $rec): array => [...$rec, 'stage2Nonce' => bin2hex(random_bytes(32))],
            'issued',
        ];
        yield 'forged stage-2 nonce in the denied terminal' => [
            'forged-nonce-denied',
            static fn (array $rec): array => [...$rec, 'stage2Nonce' => bin2hex(random_bytes(32))],
            'denied',
        ];
        yield 'missing expiry field' => [
            'missing-expiry',
            static function (array $rec): array {
                unset($rec['expiresAt']);

                return $rec;
            },
            'available',
        ];
        yield 'rank does not match the required action' => [
            'rank-mismatch',
            static fn (array $rec): array => [...$rec, 'requiredRank' => 6],
            'available',
        ];
    }

    #[DataProvider('corruptProvider')]
    public function testCorruptChainRecordEveryBoundaryFailsClosedAndTheMappingHeals(string $label, \Closure $tamper, string $prepare): void
    {
        $store = $this->store();
        $service = $this->service();
        $obligationId = $service->obligationIdFor('login', 'txn-adv', 1);
        $requirement = $service->requireStage2(ChainStateWalk::S1_NONCE, 'login', 'txn-adv', 1, RiskAction::Sha16, time() + 300);
        $this->prepareState($store, $requirement->chainId, $prepare);

        // The tamper lands as a server-side forgery on the stored JSON.
        $raw = $this->client->get($this->chainKey($requirement->chainId));
        self::assertIsString($raw);
        $record = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        $tampered = $tamper($record);
        $this->client->set($this->chainKey($requirement->chainId), (string) json_encode($tampered, JSON_THROW_ON_ERROR), 'EX', 300);

        // The refusal matrix: every boundary throws the strict decode
        // exception, twice, and the obligation mapping stays untouched.
        $this->assertEveryBoundaryFailsClosed($store, $requirement->chainId, $obligationId, 'redis '.$label);
        self::assertSame($requirement->chainId, $store->obligationChainId($obligationId), 'the refusals leave the mapping alone');

        // The create-or-get heals: compare-delete the stale mapping and
        // create the chain fresh in one script.
        $fresh = 'chain-healed-'.$label;
        $repaired = $store->createOrGetObligation($obligationId, $fresh, ChainStateWalk::S1_NONCE, 'login', 'txn-adv', 'sha16', 1, 1, time() + 300, 300);
        self::assertSame($fresh, $repaired, 'the Redis create-or-get must heal the corrupt mapping with a fresh chain');
        self::assertSame($fresh, $store->obligationChainId($obligationId), 'the obligation now points at the fresh chain');
        $freshRecord = $store->read($fresh);
        self::assertIsArray($freshRecord, 'the healed chain strictly decodes');
        self::assertSame('available', $freshRecord['state']);
        ChainModel::assertSchemaInvariants($this->modelForRecord($freshRecord), 'healed '.$label);

        // The orphaned corrupt record still fails closed on Redis (its
        // own TTL sweeps it later).
        try {
            $store->read($requirement->chainId);
            self::fail($label.': the orphaned corrupt record must stay fail-closed on Redis');
        } catch (MalformedChainedChallengeStateException) {
        }

        // The Array mirror observes the identical machine: same throws,
        // same heal.
        $this->assertArrayMirrorHeals($label, $tamper, $prepare, $obligationId);
    }

    public function testMalformedStage2NonceWriteIsRefusedDeterministicallyOnBothStores(): void
    {
        $store = $this->store();
        $service = $this->service();
        $obligationId = $service->obligationIdFor('login', 'txn-adv', 1);
        $requirement = $service->requireStage2(ChainStateWalk::S1_NONCE, 'login', 'txn-adv', 1, RiskAction::Sha16, time() + 300);
        $this->prepareState($store, $requirement->chainId, 'reserved');
        $key = $this->chainKey($requirement->chainId);
        $before = $this->client->get($key);

        // The write boundaries refuse a malformed stage-2 nonce shape
        // deterministically, before any store write: the record stays
        // reserved, byte-identical, fully readable.
        try {
            $store->markIssued($requirement->chainId, ChainStateWalk::OWNERS[0], 'not-a-kiwi-nonce');
            self::fail('a malformed stage-2 nonce must be refused at the issuance write boundary');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('stage2Nonce', $e->getMessage(), 'the refusal names the nonce boundary');
        }
        self::assertSame($before, $this->client->get($key), 'the refused mint left the record byte-identical');
        self::assertSame('reserved', $store->read($requirement->chainId)['state'], 'the record stays reserved and readable');

        try {
            $store->complete($requirement->chainId, ChainStateWalk::OWNERS[0], 'not-a-kiwi-nonce');
            self::fail('a malformed stage-2 nonce must be refused at the completion write boundary');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('stage2Nonce', $e->getMessage(), 'the refusal names the nonce boundary');
        }
        self::assertSame($before, $this->client->get($key), 'the refused completion left the record byte-identical');
        self::assertSame($chainId = $requirement->chainId, $store->obligationChainId($obligationId), 'the obligation mapping stays untouched');

        // The refusals burned nothing: the genuine mint + Pass still
        // serve the full stage-2 flow.
        self::assertSame('issued_new', $store->markIssued($chainId, ChainStateWalk::OWNERS[0], ChainStateWalk::NONCES[0]));
        self::assertSame('verified_new', $store->markVerified($chainId, ChainStateWalk::NONCES[0]));
        self::assertNull($store->obligationChainId($obligationId), 'the genuine flow passes and clears the obligation');

        // A legacy malformed record (a forged nonce written around the
        // boundary, as if from a pre-fix server) still fails closed on
        // read and the mapping heals with a fresh chain.
        $legacyObligationId = $service->obligationIdFor('login', 'txn-legacy', 1);
        $legacy = $service->requireStage2(ChainStateWalk::S1_NONCE, 'login', 'txn-legacy', 1, RiskAction::Sha16, time() + 300);
        $this->prepareState($store, $legacy->chainId, 'reserved');
        $legacyRecord = json_decode((string) $this->client->get($this->chainKey($legacy->chainId)), true, 8, JSON_THROW_ON_ERROR);
        $legacyRecord['stage2Nonce'] = 'not-a-kiwi-nonce';
        $legacyRecord['state'] = 'issued';
        $legacyRecord['owner'] = null;
        $legacyRecord['leaseUntil'] = null;
        $this->client->set($this->chainKey($legacy->chainId), (string) json_encode($legacyRecord, JSON_THROW_ON_ERROR), 'EX', 300);
        $this->assertEveryBoundaryFailsClosed($store, $legacy->chainId, $legacyObligationId, 'legacy-malformed-mint');
        $fresh = 'chain-healed-malformed-mint';
        $repaired = $store->createOrGetObligation($legacyObligationId, $fresh, ChainStateWalk::S1_NONCE, 'login', 'txn-legacy', 'sha16', 1, 1, time() + 300, 300);
        self::assertSame($fresh, $repaired, 'the create-or-get heals the legacy malformed mapping with a fresh chain');
        self::assertSame($fresh, $store->obligationChainId($legacyObligationId));
        self::assertSame('available', $store->read($fresh)['state']);

        // The Array mirror refuses identically at the same boundaries.
        $array = new ArrayChainedChallengeStateStore();
        $arrayService = new ChainedChallengeTicketService($array, self::SECRET, 300, 15);
        $arrayRequirement = $arrayService->requireStage2(ChainStateWalk::S1_NONCE, 'login', 'txn-adv', 1, RiskAction::Sha16, time() + 300);
        $this->prepareState($array, $arrayRequirement->chainId, 'reserved');
        try {
            $array->markIssued($arrayRequirement->chainId, ChainStateWalk::OWNERS[0], 'not-a-kiwi-nonce');
            self::fail('the Array mirror must refuse the malformed stage-2 nonce at the issuance write boundary');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('stage2Nonce', $e->getMessage(), 'the Array refusal names the nonce boundary');
        }
        self::assertSame('reserved', $array->read($arrayRequirement->chainId)['state'], 'the Array record stays reserved and readable');
        try {
            $array->complete($arrayRequirement->chainId, ChainStateWalk::OWNERS[0], 'not-a-kiwi-nonce');
            self::fail('the Array mirror must refuse the malformed stage-2 nonce at the completion write boundary');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('stage2Nonce', $e->getMessage(), 'the Array refusal names the nonce boundary');
        }
        self::assertSame('issued_new', $array->markIssued($arrayRequirement->chainId, ChainStateWalk::OWNERS[0], ChainStateWalk::NONCES[0]), 'the genuine mint passes on the Array mirror');
    }

    // ── 2. forged chain tickets ──────────────────────────────────────────

    public function testForgedChainTicketsAreRejectedWithoutAnyStateMutation(): void
    {
        $store = $this->store();
        $service = $this->service();
        $obligationId = $service->obligationIdFor('login', 'txn-adv', 1);
        $requirement = $service->requireStage2(ChainStateWalk::S1_NONCE, 'login', 'txn-adv', 1, RiskAction::Sha16, time() + 300);
        $chainId = $requirement->chainId;
        $ticket = $service->ticketFor($chainId, $requirement->expiresAt);
        $before = $this->client->get($this->chainKey($chainId));

        // One signature character flipped.
        $sigPos = strrpos($ticket, '.') + 1;
        $flippedSig = substr($ticket, 0, $sigPos).($ticket[$sigPos] === 'A' ? 'B' : 'A').substr($ticket, $sigPos + 1);

        // The payload rewritten to a foreign chain id, the genuine
        // signature kept (the signature no longer covers the body).
        [$payloadB64] = explode('.', $ticket, 2);
        $payload = json_decode(base64_decode(strtr($payloadB64, '-_', '+/'), true), true, 8, JSON_THROW_ON_ERROR);
        $payload[1] = 'attacker-chain-id';
        $foreignBody = rtrim(strtr(base64_encode((string) json_encode($payload, JSON_THROW_ON_ERROR)), '+/', '-_'), '=');
        $foreignPayload = $foreignBody.'.'.substr($ticket, $sigPos);

        // A correctly signed future version (version 2) of the payload.
        $v2Body = rtrim(strtr(base64_encode((string) json_encode([2, $chainId, $requirement->expiresAt], JSON_THROW_ON_ERROR)), '+/', '-_'), '=');
        $v2Ticket = $v2Body.'.'.rtrim(strtr(base64_encode(hash_hmac('sha256', $v2Body, self::SECRET, true)), '+/', '-_'), '=');

        // A correctly signed ticket whose signed expiry is already past.
        $expiredTicket = $service->ticketFor($chainId, time() - 1);

        // The same payload signed by a rotated backend secret.
        $rotated = new ChainedChallengeTicketService($store, str_repeat('f', 32), 300, 15);
        $rotatedTicket = $rotated->ticketFor($chainId, time() + 300);

        // Structurally malformed tickets.
        $malformed = ['', 'no-dot', 'abc.def', $ticket.'.extra', '!!!!.!!!!'];

        $forged = [$flippedSig, $foreignPayload, $v2Ticket, $expiredTicket, $rotatedTicket, ...$malformed];
        foreach ($forged as $index => $badTicket) {
            self::assertNull($service->verify($badTicket), 'the forged ticket must fail verification (case '.$index.')');
            self::assertSame('missing', $service->reserve($badTicket, ChainStateWalk::OWNERS[0]), 'the forged ticket redeems to missing (case '.$index.')');
            self::assertNull($service->read($badTicket), 'the forged ticket reads to nothing (case '.$index.')');
            self::assertSame($before, $this->client->get($this->chainKey($chainId)), 'the forged redemption must not mutate the chain record (case '.$index.')');
            self::assertSame($chainId, $store->obligationChainId($obligationId), 'the obligation mapping stays untouched (case '.$index.')');
        }

        // A genuinely signed ticket for a chain that never existed.
        $ghost = $service->ticketFor('ghost-chain-0001', time() + 300);
        self::assertSame('missing', $service->reserve($ghost, ChainStateWalk::OWNERS[0]));
        self::assertSame($before, $this->client->get($this->chainKey($chainId)));

        // The genuine ticket still works end to end: the refusals burned
        // nothing.
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($chainId, ChainStateWalk::OWNERS[0]));
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($chainId, ChainStateWalk::OWNERS[0], ChainStateWalk::NONCES[0]));
        self::assertSame(ChainVerifiedResult::VerifiedNew, $service->markVerified($chainId, ChainStateWalk::NONCES[0]));
        self::assertNull($store->obligationChainId($obligationId), 'the single Pass clears the obligation');
    }

    // ── 3. concurrent adversarial redemptions ────────────────────────────

    public function testConcurrentAdversarialRedemptionMixExactlyOneSuccessNoObligationLeak(): void
    {
        if (!\function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is not installed; cannot fork adversarial redeemers');
        }
        $probe = $this->client;
        $store = $this->store();
        $service = $this->service();
        $stage1 = ChainStateWalk::S1_NONCE;
        $stage2 = ChainStateWalk::NONCES[0];
        $forgedNonce = ChainStateWalk::NONCES[1];
        $requirement = $service->requireStage2($stage1, 'login', 'txn-race', 1, RiskAction::Sha16, time() + 300);
        $obligationId = $service->obligationIdFor('login', 'txn-race', 1);
        $ticket = $service->ticketFor($requirement->chainId, $requirement->expiresAt);
        $sigPos = strrpos($ticket, '.') + 1;
        $forgedTicket = substr($ticket, 0, $sigPos).($ticket[$sigPos] === 'A' ? 'B' : 'A').substr($ticket, $sigPos + 1);
        $paramsFile = tempnam(sys_get_temp_dir(), 'kiwi-adv-race-');
        file_put_contents($paramsFile, (string) json_encode([
            'chainId' => $requirement->chainId,
            'stage2' => $stage2,
            'forgedNonce' => $forgedNonce,
            'ticket' => $ticket,
            'forgedTicket' => $forgedTicket,
            'foreignObligation' => ChainStateWalk::OTHER_OBLIGATION,
        ], JSON_THROW_ON_ERROR)."\n");
        $probe->disconnect();

        $workers = 7;
        $base = tempnam(sys_get_temp_dir(), 'kiwi-adv-out-');
        $startBarrier = tempnam(sys_get_temp_dir(), 'kiwi-adv-start-');
        $outFiles = [];
        $children = [];
        for ($w = 0; $w < $workers; $w++) {
            $outFiles[$w] = $base.'.'.$w;
            $pid = pcntl_fork();
            if ($pid === -1) {
                self::markTestSkipped('pcntl_fork failed; the concurrency test did not run');
            }
            if ($pid === 0) {
                $fp = @fopen($startBarrier, 'r');
                if ($fp !== false) {
                    flock($fp, LOCK_SH);
                    fread($fp, 1);
                    fclose($fp);
                }
                $params = json_decode(trim((string) file_get_contents($paramsFile)), true, 8, JSON_THROW_ON_ERROR);
                $line = 'error';
                try {
                    $client = new \Predis\Client(self::redisUrl(), ['timeout' => 15.0, 'read_write_timeout' => 15.0]);
                    $raceStore = new RedisChainedChallengeStateStore($client, self::NAMESPACE);
                    $raceService = new ChainedChallengeTicketService($raceStore, self::SECRET, 300, 15);
                    $chainId = $params['chainId'];
                    $owner = 'owner-race-'.$w;
                    $parts = [];
                    if ($w === 0) {
                        // The one valid redemption path.
                        $parts[] = 't='.$raceService->reserve($params['ticket'], $owner);
                        $parts[] = 'i='.$raceStore->markIssued($chainId, $owner, $params['stage2']);
                        $parts[] = 'v='.$raceStore->markVerified($chainId, $params['stage2']);
                    } elseif ($w === 1) {
                        // The forged-signature ticket.
                        $parts[] = 't='.$raceService->reserve($params['forgedTicket'], $owner);
                    } elseif ($w === 2) {
                        // The structurally malformed ticket.
                        $parts[] = 't='.$raceService->reserve('not-a-ticket', $owner);
                    } elseif ($w === 3) {
                        // A genuine ticket racing a forged stage-2 nonce
                        // mint (the store cannot distinguish it from a
                        // legit mint).
                        $parts[] = 'r='.$raceService->reserve($params['ticket'], $owner);
                        $parts[] = 'i='.$raceStore->markIssued($chainId, $owner, $params['forgedNonce']);
                        $parts[] = 'v='.$raceStore->markVerified($chainId, $params['forgedNonce']);
                    } elseif ($w === 4) {
                        // A genuine ticket verifying a nonce that was
                        // never minted.
                        $parts[] = 'r='.$raceService->reserve($params['ticket'], $owner);
                        $parts[] = 'v='.$raceStore->markVerified($chainId, $params['forgedNonce']);
                    } elseif ($w === 5) {
                        // Reservation churn: reserve, release, reserve.
                        $parts[] = 'r1='.$raceService->reserve($params['ticket'], $owner);
                        $raceStore->release($chainId, $owner);
                        $parts[] = 'r2='.$raceService->reserve($params['ticket'], $owner);
                    } else {
                        // Foreign-obligation transaction terminalizations.
                        $parts[] = 'd1='.$raceStore->markTransactionDenied($chainId, $params['foreignObligation']);
                        $parts[] = 'd2='.$raceStore->markTransactionStepUpRequired($chainId, $params['foreignObligation']);
                    }
                    $line = implode('|', $parts);
                    $client->disconnect();
                } catch (\Throwable $e) {
                    fwrite(STDERR, 'ADVCHAINERR: '.$e->getMessage()."\n");
                }
                file_put_contents($base.'.'.$w, $line."\n");
                exit(0);
            }
            $children[] = $pid;
        }
        $barrierFile = fopen($startBarrier, 'w');
        fwrite($barrierFile, 'go');
        fclose($barrierFile);
        $crashed = false;
        foreach ($children as $pid) {
            pcntl_waitpid($pid, $status);
            if (pcntl_wexitstatus($status) !== 0) {
                $crashed = true;
            }
        }
        self::assertFalse($crashed, 'every adversarial redeemer must exit cleanly');
        @unlink($startBarrier);
        @unlink($base);
        @unlink($paramsFile);

        $reserveVocabulary = ['available', 'retry', 'busy', 'taken_over', 'issued', 'verified', 'completed', 'step_up_required', 'denied', 'missing'];
        $issueVocabulary = ['issued_new', 'issued_same', 'verified_same', 'conflict', 'not_owner', 'missing'];
        $verifyVocabulary = ['verified_new', 'verified_same', 'conflict', 'missing'];
        $issuedNew = 0;
        $verifiedNew = 0;
        foreach ($outFiles as $w => $outFile) {
            $line = trim((string) file_get_contents($outFile));
            @unlink($outFile);
            self::assertNotSame('error', $line, 'a redeemer must report its outcomes');
            foreach (explode('|', $line) as $part) {
                [$key, $value] = explode('=', $part, 2);
                if ($w === 1 || $w === 2) {
                    self::assertSame('t', $key, 'the forged-ticket workers report only the ticket outcome');
                    self::assertSame('missing', $value, 'a forged or malformed ticket must redeem to missing');
                } elseif ($key === 't') {
                    self::assertContains($value, $reserveVocabulary, 'the genuine-ticket reservation is from the documented set: '.$line);
                } elseif ($key === 'r' || $key === 'r1' || $key === 'r2') {
                    self::assertContains($value, $reserveVocabulary, 'the reservation outcome is from the documented set: '.$line);
                } elseif ($key === 'i') {
                    self::assertContains($value, $issueVocabulary, 'the issuance outcome is from the documented set: '.$line);
                    if ($value === 'issued_new') {
                        $issuedNew++;
                    }
                } elseif ($key === 'v') {
                    self::assertContains($value, $verifyVocabulary, 'the verification outcome is from the documented set: '.$line);
                    if ($value === 'verified_new') {
                        $verifiedNew++;
                    }
                } elseif ($key === 'd1' || $key === 'd2') {
                    self::assertSame('obligation_moved', $value, 'a foreign obligation id is an atomic no-op: '.$line);
                } else {
                    self::fail('an unknown worker outcome key: '.$key.' in '.$line);
                }
            }
        }
        self::assertSame(1, $issuedNew, 'exactly one fresh mint under the adversarial race');
        self::assertSame(1, $verifiedNew, 'exactly one verified Pass under the adversarial race');

        // The terminal consistency: verified with one of the two raced
        // nonces, the obligation cleared exactly once, no leak.
        $check = new \Predis\Client(self::redisUrl(), ['timeout' => 10.0, 'read_write_timeout' => 10.0]);
        try {
            $checkStore = new RedisChainedChallengeStateStore($check, self::NAMESPACE);
            $state = $checkStore->read($requirement->chainId);
            self::assertIsArray($state, 'the chain record must survive the adversarial race');
            self::assertSame('verified', $state['state'], 'the terminal state after the race is verified');
            self::assertContains($state['stage2Nonce'], [$stage2, $forgedNonce], 'the verified record carries the single raced nonce');
            self::assertNull($checkStore->obligationChainId($obligationId), 'the Pass cleared the obligation exactly once');
            self::assertSame('verified', $checkStore->reserve($requirement->chainId, 'owner-after', 15), 'a later reserve observes the terminal state');
        } finally {
            $check->disconnect();
        }
    }

    // ── 4. lease and ownership abuse ─────────────────────────────────────

    public function testForeignOwnerTokenReserveReleaseIssueAreRefusedWithoutMutation(): void
    {
        $driver = new RedisChainDriver($this->client, self::NAMESPACE);
        $chainId = 'chain-owner-abuse';
        $obligationId = ChainStateWalk::OBLIGATION;
        $model = ChainModel::fresh($obligationId);
        $actual = $driver->createOrGet($chainId, $obligationId, 1, $driver->now() + 300);
        self::assertSame($chainId, $actual);
        $model->apply('createOrGet', ['rank' => 1]);

        $step = function (string $transition, array $args, mixed $expected) use ($driver, &$model, $chainId, $obligationId): void {
            $before = clone $model;
            $modelOutcome = $model->apply($transition, $args);
            $stored = match ($transition) {
                'reserve' => $driver->reserve($chainId, $args['owner']),
                'release' => $driver->release($chainId, $args['owner']),
                'markIssued' => $driver->markIssued($chainId, $args['owner'], $args['nonce']),
                'markVerified' => $driver->markVerified($chainId, $args['nonce']),
                'rearmIssued' => $driver->rearmIssued($chainId, $args['nonce']),
                'complete' => $driver->complete($chainId, $args['owner'], $args['nonce']) !== null,
                'markTransactionDenied' => $driver->markTransactionDenied($chainId, $args['obligationId']),
                'markTransactionStepUpRequired' => $driver->markTransactionStepUpRequired($chainId, $args['obligationId']),
                default => throw new \LogicException(sprintf('unknown abuse step %s', $transition)),
            };
            if ($transition === 'complete') {
                self::assertSame($expected === 'completed', $stored, 'the legacy completion parity under abuse');
            } else {
                self::assertSame($modelOutcome, $stored, sprintf('outcome parity for %s under abuse', $transition));
                self::assertSame($expected, $modelOutcome, sprintf('the expected outcome for %s', $transition));
            }
            ChainModel::assertInvariants($before, $model, $modelOutcome, $transition, $args, 'ownership-abuse');
            ChainStateWalk::assertConcreteMatchesModel('ownership-abuse', $driver, $model, $chainId, $obligationId);
        };

        // Owner A reserves the chain; the foreign owner B is refused at
        // every owner-scoped transition, with the raw record untouched.
        $step('reserve', ['owner' => ChainStateWalk::OWNERS[0]], 'available');
        $rawBefore = $this->client->get($this->chainKey($chainId));
        $step('reserve', ['owner' => ChainStateWalk::OWNERS[1]], 'busy');
        $step('release', ['owner' => ChainStateWalk::OWNERS[1]], null);
        $step('markIssued', ['owner' => ChainStateWalk::OWNERS[1], 'nonce' => ChainStateWalk::NONCES[0]], 'not_owner');
        $step('markVerified', ['nonce' => ChainStateWalk::NONCES[0]], 'conflict');
        $step('complete', ['owner' => ChainStateWalk::OWNERS[1], 'nonce' => ChainStateWalk::NONCES[0]], null);
        $step('rearmIssued', ['nonce' => ChainStateWalk::NONCES[0]], false);
        $step('markTransactionDenied', ['obligationId' => ChainStateWalk::OTHER_OBLIGATION], 'obligation_moved');
        $step('markTransactionStepUpRequired', ['obligationId' => ChainStateWalk::OTHER_OBLIGATION], 'obligation_moved');
        self::assertSame($rawBefore, $this->client->get($this->chainKey($chainId)), 'the foreign attempts left the raw record byte-identical');

        // The owner's own release works; a later foreign owner then
        // reserves freely (the reservation is owner-scoped, the chain is
        // shared).
        $step('release', ['owner' => ChainStateWalk::OWNERS[0]], null);
        $step('reserve', ['owner' => ChainStateWalk::OWNERS[1]], 'available');
        $step('markIssued', ['owner' => ChainStateWalk::OWNERS[1], 'nonce' => ChainStateWalk::NONCES[1]], 'issued_new');
        $step('markVerified', ['nonce' => ChainStateWalk::NONCES[1]], 'verified_new');

        // The displaced owner A cannot release or issue the reservation B
        // holds: the chain is verified-terminal and absorbs every attempt.
        $step('reserve', ['owner' => ChainStateWalk::OWNERS[0]], 'verified');
        $step('release', ['owner' => ChainStateWalk::OWNERS[0]], null);
        $step('markIssued', ['owner' => ChainStateWalk::OWNERS[0], 'nonce' => ChainStateWalk::NONCES[0]], 'conflict');
    }

    // ── 5. expired-but-live records ──────────────────────────────────────

    public function testLifetimeLessRecordFailsClosedAtEveryBoundaryOnBothStores(): void
    {
        $store = $this->store();
        $service = $this->service();
        $obligationId = $service->obligationIdFor('login', 'txn-adv', 1);
        $requirement = $service->requireStage2(ChainStateWalk::S1_NONCE, 'login', 'txn-adv', 1, RiskAction::Sha16, time() + 300);
        $chainId = $requirement->chainId;
        $key = $this->chainKey($chainId);

        // The lifetime is removed from the key while the record survives.
        $this->client->persist($key);
        self::assertSame(-1, (int) $this->client->ttl($key), 'the tampered key carries no lifetime');
        $before = $this->client->get($key);

        // Every mutating transition fails closed like the reservation
        // does: a lifetime can never be manufactured for a TTL-less
        // chain, deterministic, zero mutation.
        self::assertSame('missing', $store->reserve($chainId, ChainStateWalk::OWNERS[0], 15), 'the reservation refuses the lifetime-less key');
        self::assertSame('missing', $store->markIssued($chainId, ChainStateWalk::OWNERS[0], ChainStateWalk::NONCES[0]), 'the issuance refuses the lifetime-less key');
        self::assertSame('missing', $store->markVerified($chainId, ChainStateWalk::NONCES[0]), 'the verification refuses the lifetime-less key');
        self::assertSame('missing', $store->markStepUpRequired($chainId, ChainStateWalk::NONCES[0]), 'the step-up refuses the lifetime-less key');
        self::assertSame('missing', $store->markDenied($chainId, ChainStateWalk::NONCES[0]), 'the denial refuses the lifetime-less key');
        self::assertSame('missing', $store->markTransactionDenied($chainId, $obligationId), 'the transaction denial refuses the lifetime-less key');
        self::assertSame('missing', $store->markTransactionStepUpRequired($chainId, $obligationId), 'the transaction step-up refuses the lifetime-less key');
        self::assertFalse($store->rearmIssued($chainId, ChainStateWalk::NONCES[0]), 'the rearm refuses the lifetime-less key');
        self::assertNull($store->complete($chainId, ChainStateWalk::OWNERS[0], ChainStateWalk::NONCES[0]), 'the completion refuses the lifetime-less key');
        self::assertNull($store->read($chainId), 'the read refuses the lifetime-less record as corrupted state');
        self::assertSame($before, $this->client->get($key), 'the refusals left the lifetime-less record byte-identical');
        self::assertSame($chainId, $store->obligationChainId($obligationId), 'the obligation mapping stays untouched');

        // The Array mirror's lifetime-equivalent corruption (its own
        // expiry swept into the past, the store has no key TTL): the
        // identical fail-closed matrix answers the identical statuses.
        $clock = 1_000;
        $array = new ArrayChainedChallengeStateStore(static function () use (&$clock): float {
            return (float) $clock;
        });
        $arrayService = new ChainedChallengeTicketService($array, self::SECRET, 300, 15, null, static fn (): int => $clock);
        $arrayRequirement = $arrayService->requireStage2(ChainStateWalk::S1_NONCE, 'login', 'txn-adv', 1, RiskAction::Sha16, $clock + 300);
        $arrayRecords = (new \ReflectionObject($array))->getProperty('records')->getValue($array);
        $arrayRecords[$arrayRequirement->chainId]['expiresAt'] = $clock - 100;
        (new \ReflectionObject($array))->getProperty('records')->setValue($array, $arrayRecords);
        self::assertNull($array->read($arrayRequirement->chainId), 'the Array mirror sweeps its lifetime-lapsed record');
        self::assertSame('missing', $array->reserve($arrayRequirement->chainId, ChainStateWalk::OWNERS[0], 15), 'the Array mirror refuses the reservation');
        self::assertSame('missing', $array->markIssued($arrayRequirement->chainId, ChainStateWalk::OWNERS[0], ChainStateWalk::NONCES[0]), 'the Array mirror refuses the issuance');
        self::assertSame('missing', $array->markVerified($arrayRequirement->chainId, ChainStateWalk::NONCES[0]), 'the Array mirror refuses the verification');
        self::assertSame('missing', $array->markTransactionDenied($arrayRequirement->chainId, $obligationId), 'the Array mirror refuses the transaction denial');
        self::assertFalse($array->rearmIssued($arrayRequirement->chainId, ChainStateWalk::NONCES[0]), 'the Array mirror refuses the rearm');
        self::assertNull($array->complete($arrayRequirement->chainId, ChainStateWalk::OWNERS[0], ChainStateWalk::NONCES[0]), 'the Array mirror refuses the completion');
    }

    public function testExpiredButLiveRecordFailsClosedOnBothStoresAndTheMappingHeals(): void
    {
        $store = $this->store();
        $service = $this->service();
        $obligationId = $service->obligationIdFor('login', 'txn-adv', 1);
        $requirement = $service->requireStage2(ChainStateWalk::S1_NONCE, 'login', 'txn-adv', 1, RiskAction::Sha16, time() + 300);
        $chainId = $requirement->chainId;
        $key = $this->chainKey($chainId);

        // The signed expiry is rewritten into the past while the key TTL
        // stays live (a clock-skew or tamper corner).
        $record = json_decode((string) $this->client->get($key), true, 8, JSON_THROW_ON_ERROR);
        $record['expiresAt'] = time() - 100;
        $this->client->set($key, (string) json_encode($record, JSON_THROW_ON_ERROR), 'EX', 300);
        $before = $this->client->get($key);

        // Both stores consult the record's own expiry against their
        // clock: the expired-but-live record is stale and every boundary
        // fails closed identically (the Array mirror sweeps it, Redis
        // answers the same statuses).
        self::assertNull($store->read($chainId), 'the read refuses the expired-but-live record');
        self::assertSame('missing', $store->reserve($chainId, ChainStateWalk::OWNERS[0], 15), 'the reservation refuses the expired-but-live record');
        self::assertSame('missing', $store->markIssued($chainId, ChainStateWalk::OWNERS[0], ChainStateWalk::NONCES[0]), 'the issuance refuses the expired-but-live record');
        self::assertSame('missing', $store->markVerified($chainId, ChainStateWalk::NONCES[0]), 'the verification refuses the expired-but-live record');
        self::assertSame('missing', $store->markStepUpRequired($chainId, ChainStateWalk::NONCES[0]), 'the step-up refuses the expired-but-live record');
        self::assertSame('missing', $store->markDenied($chainId, ChainStateWalk::NONCES[0]), 'the denial refuses the expired-but-live record');
        self::assertSame('missing', $store->markTransactionDenied($chainId, $obligationId), 'the transaction denial refuses the expired-but-live record');
        self::assertSame('missing', $store->markTransactionStepUpRequired($chainId, $obligationId), 'the transaction step-up refuses the expired-but-live record');
        self::assertFalse($store->rearmIssued($chainId, ChainStateWalk::NONCES[0]), 'the rearm refuses the expired-but-live record');
        self::assertNull($store->complete($chainId, ChainStateWalk::OWNERS[0], ChainStateWalk::NONCES[0]), 'the completion refuses the expired-but-live record');
        self::assertSame($before, $this->client->get($key), 'the refusals left the expired-but-live record byte-identical');

        // The create-or-get heals the expired mapping with a fresh chain
        // (never returns the past-expiry chain as the existing one).
        $fresh = 'chain-healed-expiry';
        $repaired = $store->createOrGetObligation($obligationId, $fresh, ChainStateWalk::S1_NONCE, 'login', 'txn-adv', 'sha16', 1, 1, time() + 300, 300);
        self::assertSame($fresh, $repaired, 'the Redis create-or-get heals the expired mapping with a fresh chain');
        self::assertSame($fresh, $store->obligationChainId($obligationId), 'the obligation now points at the fresh chain');
        $freshRecord = $store->read($fresh);
        self::assertIsArray($freshRecord, 'the healed chain strictly decodes');
        self::assertSame('available', $freshRecord['state']);
        ChainModel::assertSchemaInvariants($this->modelForRecord($freshRecord), 'healed-expiry');
        self::assertSame('available', $store->reserve($fresh, ChainStateWalk::OWNERS[1], 15), 'the healed chain serves the reservation');
        self::assertSame('issued_new', $store->markIssued($fresh, ChainStateWalk::OWNERS[1], ChainStateWalk::NONCES[1]), 'the healed chain serves the mint');
        self::assertSame('verified_new', $store->markVerified($fresh, ChainStateWalk::NONCES[1]), 'the healed chain passes');
        self::assertNull($store->obligationChainId($obligationId), 'the healed chain passes and clears the obligation');

        // The Array mirror observes the identical machine: same refusals,
        // same heal.
        $clock = 1_000;
        $array = new ArrayChainedChallengeStateStore(static function () use (&$clock): float {
            return (float) $clock;
        });
        $arrayService = new ChainedChallengeTicketService($array, self::SECRET, 300, 15, null, static fn (): int => $clock);
        $arrayRequirement = $arrayService->requireStage2(ChainStateWalk::S1_NONCE, 'login', 'txn-adv', 1, RiskAction::Sha16, $clock + 300);
        $arrayRecords = (new \ReflectionObject($array))->getProperty('records')->getValue($array);
        $arrayRecords[$arrayRequirement->chainId]['expiresAt'] = $clock - 100;
        (new \ReflectionObject($array))->getProperty('records')->setValue($array, $arrayRecords);
        self::assertNull($array->read($arrayRequirement->chainId), 'the Array mirror sweeps the expired record');
        self::assertSame('missing', $array->reserve($arrayRequirement->chainId, ChainStateWalk::OWNERS[0], 15), 'the Array mirror refuses to reserve the expired record');
        self::assertSame('missing', $array->markIssued($arrayRequirement->chainId, ChainStateWalk::OWNERS[0], ChainStateWalk::NONCES[0]), 'the Array mirror refuses the issuance');
        self::assertSame('missing', $array->markVerified($arrayRequirement->chainId, ChainStateWalk::NONCES[0]), 'the Array mirror refuses the verification');
        self::assertSame('missing', $array->markTransactionDenied($arrayRequirement->chainId, $obligationId), 'the Array mirror refuses the transaction denial');
        self::assertFalse($array->rearmIssued($arrayRequirement->chainId, ChainStateWalk::NONCES[0]), 'the Array mirror refuses the rearm');
        self::assertNull($array->complete($arrayRequirement->chainId, ChainStateWalk::OWNERS[0], ChainStateWalk::NONCES[0]), 'the Array mirror refuses the completion');
        $arrayFresh = 'array-healed-expiry';
        self::assertSame($arrayFresh, $array->createOrGetObligation($obligationId, $arrayFresh, ChainStateWalk::S1_NONCE, 'login', 'txn-adv', 'sha16', 1, 1, $clock + 300, 300), 'the Array create-or-get heals the expired mapping');
        self::assertSame($arrayFresh, $array->obligationChainId($obligationId));
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

    private static function redisUrl(): string
    {
        $url = RedisTestUrl::resolve();
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis suites run in the CI Redis-service job');
        }

        return $url;
    }
}
