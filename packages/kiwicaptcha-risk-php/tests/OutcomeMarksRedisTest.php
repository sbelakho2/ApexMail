<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\Outcomes\KiwiOutcomes;
use KiwiCaptcha\Risk\Outcomes\Outcome;
use KiwiCaptcha\Risk\Outcomes\OutcomeHandle;
use KiwiCaptcha\Risk\Outcomes\OutcomeMap;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use KiwiCaptcha\Risk\Storage\RiskStoreException;
use PHPUnit\Framework\TestCase;

/**
 * The long-memory mark surface against real Redis: the atomic
 * kind/count/first/last write with its refreshed TTL, the erasure path,
 * and the report()/forget() resolution over the real ledger and state
 * scripts. The state-level polarity proof pins the invariant that no
 * mapped outcome event ever lowers attacker-added risk and trust flows
 * only through the server-confirmed channels.
 */
final class OutcomeMarksRedisTest extends TestCase
{
    private const T0 = 1_700_000_000_000;
    private const PRINCIPAL = '9f1c4a7e2b8d63f05a1e9c4d7b2e6f18';
    private const SESSION = 'c7b3e1f9a5d24708b6e0c8a2f4d69123';

    /** @var \Predis\Client */
    private $client;

    protected function setUp(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if (!is_string($url) || $url === '') {
            self::markTestSkipped('RISK_REDIS_URL not set; start redis with: redis-server --port 6421 --save "" --appendonly no --daemonize yes');
        }
        $this->client = RedisRiskStateStore::createClient($url);
        $this->client->ping();
    }

    private function store(?int $markTtlSecs = null): RedisRiskStateStore
    {
        $namespace = 'outcomes-' . bin2hex(random_bytes(4));
        $args = ['namespace' => $namespace];
        if ($markTtlSecs !== null) {
            $args['markTtlSecs'] = $markTtlSecs;
        }

        return new RedisRiskStateStore($this->client, ...$args);
    }

    public function testMarkWriteCarriesCountFirstLastAndTheNinetyDayTtl(): void
    {
        $store = $this->store();
        $key = $store->markKey('principal', self::PRINCIPAL);

        try {
            self::assertSame(1, $store->writeMark('principal', self::PRINCIPAL, 'spamReported', self::T0));
            self::assertSame(2, $store->writeMark('principal', self::PRINCIPAL, 'chargeback', self::T0 + 5_000));

            $mark = $store->readMark('principal', self::PRINCIPAL);
            self::assertSame('chargeback', $mark['kind'], 'the max-severity kind is kept');
            self::assertSame('chargeback', $mark['last_kind']);
            self::assertSame(2, $mark['count']);
            // The mark clock is the server's TIME (marks.lua ignores the
            // caller timestamp), so the stamps are wall-clock, not T0.
            $now = (int) floor(microtime(true) * 1000);
            self::assertGreaterThan($now - 60_000, $mark['first_ms']);
            self::assertLessThanOrEqual($now + 1_000, $mark['first_ms']);
            self::assertGreaterThanOrEqual($mark['first_ms'], $mark['last_ms']);
            self::assertLessThanOrEqual($now + 1_000, $mark['last_ms']);

            $pttl = (int) $this->client->pttl($key);
            self::assertGreaterThan(RedisRiskStateStore::DEFAULT_MARK_TTL_SECS * 1000 - 10_000, $pttl);
            self::assertLessThanOrEqual(RedisRiskStateStore::DEFAULT_MARK_TTL_SECS * 1000, $pttl);
        } finally {
            $this->client->del([$key]);
        }
    }

    public function testMarkSeverityNeverDowngradesAndLatestIsKeptSeparately(): void
    {
        $store = $this->store();
        $key = $store->markKey('principal', self::PRINCIPAL);
        try {
            $store->writeMark('principal', self::PRINCIPAL, 'chargeback', self::T0);
            $store->writeMark('principal', self::PRINCIPAL, 'spamReported', self::T0 + 1_000);
            $mark = $store->readMark('principal', self::PRINCIPAL);
            self::assertSame('chargeback', $mark['kind'], 'a mild report after a chargeback must never downgrade the kind');
            self::assertSame('spamReported', $mark['last_kind'], 'the latest kind is recorded separately');
            self::assertSame(2, $mark['count']);
        } finally {
            $this->client->del([$key]);
        }
    }

    public function testMarkWritesDedupeByEventId(): void
    {
        $store = $this->store();
        $key = $store->markKey('session', self::SESSION);
        $event = hash('sha256', 'retried-report');
        try {
            self::assertSame(1, $store->writeMark('session', self::SESSION, 'accountBanned', self::T0, $event));
            self::assertSame(1, $store->writeMark('session', self::SESSION, 'accountBanned', self::T0 + 5, $event), 'a retried report must not double-count');
            self::assertSame(2, $store->writeMark('session', self::SESSION, 'accountBanned', self::T0 + 5, hash('sha256', 'another-event')));
            $mark = $store->readMark('session', self::SESSION);
            self::assertSame(2, $mark['count']);
        } finally {
            $this->client->del([$key, "mark:{kiwi:{$store->namespace()}}:dd:{$event}"]);
        }
    }

    public function testEveryWriteRefreshesTheWholeKeyTtl(): void
    {
        $store = $this->store(markTtlSecs: 6);
        $key = $store->markKey('session', self::SESSION);

        try {
            $store->writeMark('session', self::SESSION, 'accountBanned', self::T0);
            sleep(2);
            $decayed = (int) $this->client->pttl($key);
            self::assertLessThanOrEqual(4_000, $decayed, 'the mark window must measurably decay first');

            $store->writeMark('session', self::SESSION, 'fraudConfirmed', self::T0);
            $refreshed = (int) $this->client->pttl($key);
            self::assertGreaterThan(
                $decayed + 1_000,
                $refreshed,
                'the second write must re-arm the full mark TTL',
            );
        } finally {
            $this->client->del([$key]);
        }
    }

    public function testMarkSurfaceValidatesItsInputsFailClosed(): void
    {
        $store = $this->store();
        try {
            OutcomeHandle::principal('user@example.com');
            self::fail('a raw principal identifier must never build a handle');
        } catch (\InvalidArgumentException) {
            self::addToAssertionCount(1);
        }
        foreach ([['principal', 'a:b'], ['nope', self::PRINCIPAL]] as [$dimension, $id]) {
            try {
                $store->markKey($dimension, $id);
                self::fail('an invalid dimension or identifier must be refused before Redis');
            } catch (\InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
        try {
            $store->writeMark('asn', '64496', '', self::T0);
            self::fail('an empty kind must be refused');
        } catch (\InvalidArgumentException) {
            self::addToAssertionCount(1);
        }
        try {
            $store->writeMark('asn', '64496', 'fraudConfirmed', -1);
            self::fail('a negative timestamp must be refused');
        } catch (\InvalidArgumentException) {
            self::addToAssertionCount(1);
        }
    }

    public function testCorruptMarkHashFailsClosedOnRead(): void
    {
        $store = $this->store();
        $key = $store->markKey('agent', 'backfill-bot');
        try {
            $this->client->hset($key, 'count', '3');
            try {
                $store->readMark('agent', 'backfill-bot');
                self::fail('a mark hash without its kind must fail closed');
            } catch (RiskStoreException) {
                self::addToAssertionCount(1);
            }
        } finally {
            $this->client->del([$key]);
        }
    }

    public function testForgetRemovesTheExactMarkAndCountsIt(): void
    {
        $store = $this->store();
        $key = $store->markKey('target', '5e2a9b4c1d7f38e6a0b5c9d2e4f6a813');
        try {
            $store->writeMark('target', '5e2a9b4c1d7f38e6a0b5c9d2e4f6a813', 'chargeback', self::T0);
            self::assertSame(1, $store->forgetMarks('target', '5e2a9b4c1d7f38e6a0b5c9d2e4f6a813'));
            self::assertSame(0, (int) $this->client->exists($key));
            self::assertNull($store->readMark('target', '5e2a9b4c1d7f38e6a0b5c9d2e4f6a813'));
            self::assertSame(0, $store->forgetMarks('target', '5e2a9b4c1d7f38e6a0b5c9d2e4f6a813'));
        } finally {
            $this->client->del([$key]);
        }
    }

    public function testReportResolvesTheLedgerMarkAndChannelOverRealSurfaces(): void
    {
        $store = $this->store();
        $engine = $this->engine($store);
        $outcomes = new KiwiOutcomes($engine, $store);
        $decisionId = bin2hex(random_bytes(16));
        $ledgerKey = $store->ledgerKey($decisionId);
        $markKey = $store->markKey('principal', self::PRINCIPAL);

        try {
            self::assertTrue($store->registerOutcome($decisionId, 1, 0, 420));
            $receipt = $outcomes->report(Outcome::Chargeback, OutcomeHandle::decisionId($decisionId));
            self::assertSame(1, $receipt->status);
            self::assertSame(0, $receipt->marksWritten, 'a ledger handle names no mark dimension');
            self::assertStringContainsString('"o":"A"', (string) $this->client->get($ledgerKey));
            self::assertSame(0, $outcomes->report(Outcome::Chargeback, OutcomeHandle::decisionId($decisionId))->status, 'the retry consumes nothing');

            $receipt = $outcomes->report(Outcome::SpamReported, OutcomeHandle::principal(self::PRINCIPAL), 'idem-1', $this->context());
            self::assertSame(1, $receipt->marksWritten);
            self::assertTrue($receipt->channelBooked);
            $mark = $store->readMark('principal', self::PRINCIPAL);
            self::assertSame('spamReported', $mark['kind']);

            // The trust trio never writes an abuse mark.
            $outcomes->report(Outcome::ConfirmedLegitimate, OutcomeHandle::principal(self::PRINCIPAL), null, $this->context());
            self::assertSame('spamReported', $store->readMark('principal', self::PRINCIPAL)['kind'], 'trust outcomes never touch marks');

            self::assertSame(1, $outcomes->forget(OutcomeHandle::principal(self::PRINCIPAL)));
            self::assertNull($store->readMark('principal', self::PRINCIPAL));
        } finally {
            $this->client->del([$ledgerKey, $markKey]);
        }
    }

    /**
     * The state-level polarity proof: after attacker evidence (a bad
     * proof and a replay) is seeded at T0, applying any mapped outcome
     * event at the same timestamp leaves every attacker channel
     * undamaged. Trust credit flows only through the mapped trust
     * channels. Decay is pinned to zero by the shared timestamp, so any
     * decrease would be the event itself subtracting attacker risk.
     */
    public function testNoOutcomeEventEverLowersAttackerAddedRisk(): void
    {
        foreach (OutcomeMap::all() as $row) {
            $store = $this->store();
            try {
                $seeded = null;
                foreach ([RiskEventKind::InvalidProof, RiskEventKind::ReplayAttempt] as $seed) {
                    $reply = $store->observeWithReply($this->observation($store, $seed, 'seed' . $seed->value . bin2hex(random_bytes(4))));
                    $seeded = $reply->vector;
                }
                $after = $store->observeWithReply($this->observation($store, $row->channel, 'outcome' . bin2hex(random_bytes(4))))->vector;

                foreach (['badProof', 'malformed', 'replay', 'actionFailure'] as $slot) {
                    self::assertGreaterThanOrEqual(
                        $seeded->$slot,
                        $after->$slot,
                        sprintf('%s (channel %d) must never lower the attacker channel %s', $row->outcome->value, $row->channel->value, $slot),
                    );
                }
                if ($row->maySubtractRisk) {
                    self::assertGreaterThan(
                        $seeded->trustCredit,
                        $after->trustCredit,
                        sprintf('%s grants trust through its mapped channel', $row->outcome->value),
                    );
                } else {
                    self::assertSame(
                        $seeded->trustCredit,
                        $after->trustCredit,
                        sprintf('%s (channel %d) must never grant source trust', $row->outcome->value, $row->channel->value),
                    );
                }
            } finally {
                $epoch = intdiv(intdiv(self::T0, 1000), 900);
                $this->client->del(RedisRiskStateStore::keysFor(
                    $store->rawNamespace(),
                    $store->namespaceVersion(),
                    $epoch,
                    str_repeat('a', 32),
                    str_repeat('a', 32),
                    str_repeat('a', 32),
                    $epoch,
                    str_repeat('b', 32),
                    str_repeat('b', 32),
                    str_repeat('b', 32),
                    null,
                    null,
                    'cleanup',
                ));
            }
        }
    }

    private function observation(RedisRiskStateStore $store, RiskEventKind $event, string $eventId): RiskObservation
    {
        $epoch = intdiv(intdiv(self::T0, 1000), 900);

        return new RiskObservation(
            event: $event,
            scope: 1,
            sourceEpoch: $epoch,
            sourceIdPrev: str_repeat('a', 32),
            sourceId: str_repeat('a', 32),
            sourceIdNext: str_repeat('a', 32),
            subnetEpoch: $epoch,
            subnetIdPrev: str_repeat('b', 32),
            subnetId: str_repeat('b', 32),
            subnetIdNext: str_repeat('b', 32),
            sessionId: null,
            principalId: null,
            eventId: hash('sha256', $eventId),
            networkRisk: 0,
            nowMs: self::T0,
        );
    }

    private function context(): RiskContext
    {
        return new RiskContext(
            scope: 1,
            sourceIp: '198.51.100.7',
            sessionId: '00112233445566778899aabbccddeeff',
            principalId: 'raw-principal-42',
            event: RiskEventKind::PreIssue,
            networkFlags: (new CidrNetworkClassifier([]))->classify('198.51.100.7'),
            resources: new ResourcePressure(1000, 1000),
        );
    }

    private function engine(RedisRiskStateStore $store): AdaptiveRiskEngine
    {
        $keys = RiskKeys::fromMaster(str_repeat(chr(0x42), 32));

        return new AdaptiveRiskEngine(
            store: $store,
            classifier: new CidrNetworkClassifier([]),
            identityFactory: new RiskIdentityFactory($keys),
            scorer: new RiskScorer(),
            policy: RiskPolicy::fromConfig([
                'version' => 3,
                'weights' => (new \KiwiCaptcha\Risk\RiskWeights())->toArray(),
                'scopes' => [
                    1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20'],
                ],
                'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            ]),
            keys: $keys,
        );
    }
}
