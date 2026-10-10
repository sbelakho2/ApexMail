<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\RiskV2Weights;
use KiwiCaptcha\Risk\Storage\KeyspaceMode;
use KiwiCaptcha\Risk\Storage\OutcomeRegistration;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use KiwiCaptcha\Risk\Storage\RiskStoreException;
use KiwiCaptcha\Risk\Storage\ShardedRedisRiskStateStore;
use PHPUnit\Framework\TestCase;

/**
 * The Plane 7 invariant suite, run against the sharded keyspace: every
 * store invariant the classic suite pins is proven here for the
 * horizontally scalable layout, against a real Redis (skipped unless
 * the RISK_REDIS_URL env carries one, e.g. a server started with
 * redis-server --port 6426 --save "" --appendonly no).
 *
 * Covered: the classic signal contract (single event, duplicate no-op,
 * saturation, global level under the staleness contract), and the
 * keyspace mode marker with its claim, refusal and no-silent-fallback
 * rule.
 *
 * Also covered: the classic parity of the sharded assessment path, the
 * consolidated tags and ledger score, the merged-aggregate window, the
 * scope shard dispersion, the mode-insensitive auxiliary surfaces, and
 * the partial-batch retry idempotency under a dropped reply.
 */
final class ShardedRedisStateStoreTest extends TestCase
{
    private const T0 = 1_700_000_000_000;

    private ?\Predis\Client $client = null;

    protected function setUp(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if (!is_string($url) || $url === '') {
            self::markTestSkipped('RISK_REDIS_URL not set; start redis with: redis-server --port 6426 --save "" --appendonly no --daemonize yes');
        }
        $this->client = RedisRiskStateStore::createClient($url);
    }

    /** @return list<string> */
    private function urls(): array
    {
        return [getenv('RISK_REDIS_URL')];
    }

    private function shardedStore(string $suffix): ShardedRedisRiskStateStore
    {
        // Relaxed timeouts: the production 5 ms/10 ms defaults are
        // fail-fast tuning knobs, and the dropped-reply proxy adds real
        // latency that must never flake the suite.
        return new ShardedRedisRiskStateStore(
            $this->urls(),
            namespace: 'sh' . $suffix . bin2hex(random_bytes(4)),
            connectTimeoutSecs: 2.0,
            commandTimeoutSecs: 2.0,
        );
    }

    private function legacyStore(string $suffix): RedisRiskStateStore
    {
        return new RedisRiskStateStore(
            $this->client,
            namespace: 'lg' . $suffix . bin2hex(random_bytes(4)),
        );
    }

    private function observation(
        string $eventId,
        int $scope = 0,
        int $networkRisk = 0,
        ?string $sessionId = null,
        ?string $principalId = null,
        RiskEventKind $event = RiskEventKind::PreIssue,
    ): RiskObservation {
        return new RiskObservation(
            event: $event,
            scope: $scope,
            sourceEpoch: 12345,
            sourceIdPrev: str_repeat('a', 32),
            sourceId: str_repeat('b', 32),
            sourceIdNext: str_repeat('c', 32),
            subnetEpoch: 12345,
            subnetIdPrev: str_repeat('d', 32),
            subnetId: str_repeat('e', 32),
            subnetIdNext: str_repeat('f', 32),
            sessionId: $sessionId,
            principalId: $principalId,
            eventId: $eventId,
            networkRisk: $networkRisk,
            nowMs: self::T0,
        );
    }

    private function eventId(int $n): string
    {
        return str_pad(dechex($n), 32, '0', STR_PAD_LEFT);
    }

    private function registration(string $decisionId): OutcomeRegistration
    {
        return new OutcomeRegistration(
            decisionId: $decisionId,
            decisionHour: 472222,
            baseRisk: 100,
            globalPressureEnabled: true,
            honeypotHit: false,
            weights: new RiskWeights(),
            v2Weights: new RiskV2Weights(),
        );
    }

    public function testSingleEventMatchesTheClassicContract(): void
    {
        $store = $this->shardedStore('single');
        $reply = $store->observeWithReply($this->observation($this->eventId(1)));
        self::assertSame(125, $reply->vector->sourceFast, '1000*1000/8000');
        self::assertSame(10, $reply->vector->sourceSlow, '1000*1000/100000');
        self::assertSame(125, $reply->vector->subnetFast);
        self::assertSame(0, $reply->vector->issueDebt);
        self::assertSame(28, $reply->vector->globalPressure, 'the merged aggregate sees one event');
        self::assertSame(0, $reply->vector->networkRisk);
        self::assertFalse($reply->isDuplicate);
        self::assertSame(0, $store->lastGlobalLevel());
    }

    public function testDuplicateEventIdIsASingleIncrement(): void
    {
        $store = $this->shardedStore('dup');
        $id = $this->eventId(7);

        $first = $store->observeWithReply($this->observation($id));
        self::assertSame(125, $first->vector->sourceFast);
        self::assertFalse($first->isDuplicate);

        // Same event id again: duplicate no-op, current signals returned;
        // real elapsed decay can floor one unit lower.
        $duplicate = $store->observeWithReply($this->observation($id));
        self::assertTrue($duplicate->isDuplicate);
        self::assertThat(
            $duplicate->vector->sourceFast,
            self::logicalAnd(self::greaterThanOrEqual(100), self::lessThanOrEqual(125)),
            'a duplicate must not increment',
        );

        // A distinct event observes the state from a single increment.
        $third = $store->observeWithReply($this->observation($this->eventId(8)));
        self::assertFalse($third->isDuplicate);
        self::assertThat(
            $third->vector->sourceFast,
            self::logicalAnd(self::greaterThanOrEqual(200), self::lessThanOrEqual(250)),
            'exactly two increments',
        );
    }

    public function testHundredSequentialEventsSaturateAcrossShards(): void
    {
        $store = $this->shardedStore('sat');
        $vector = null;
        for ($i = 0; $i < 100; $i++) {
            $vector = $store->observeWithReply($this->observation($this->eventId($i)))->vector;
        }
        self::assertNotNull($vector);
        self::assertSame(1000, $vector->sourceFast, 'no increments may be lost');
        self::assertSame(1000, $vector->subnetFast);
        // The merged aggregate lags by at most the staleness window; let
        // the window pass and assess once more so the level transition
        // sees the full pressure (minus real-elapsed leak).
        usleep(1_100_000);
        $vector = $store->observeWithReply($this->observation($this->eventId(1000)))->vector;
        self::assertThat(
            $vector->globalPressure,
            self::logicalAnd(self::greaterThanOrEqual(960), self::lessThanOrEqual(1000)),
            'the merged aggregate must saturate after the window',
        );
        self::assertSame(4, $store->lastGlobalLevel(), 'gnorm >= 900 ratchets to level 4');
    }

    public function testKeySpaceModeMarkerIsClaimedAndEnforced(): void
    {
        $ns = 'mode' . bin2hex(random_bytes(4));

        // Construction claims the marker; a second sharded store on the
        // same namespace is accepted.
        $first = new ShardedRedisRiskStateStore($this->urls(), namespace: $ns, connectTimeoutSecs: 2.0, commandTimeoutSecs: 2.0);
        self::assertSame($ns, $first->namespace());
        new ShardedRedisRiskStateStore($this->urls(), namespace: $ns, connectTimeoutSecs: 2.0, commandTimeoutSecs: 2.0);

        // A legacy claim on a sharded-marked namespace is refused.
        try {
            KeyspaceMode::claim($this->client, $ns, KeyspaceMode::Legacy);
            self::fail('the legacy claim must be refused');
        } catch (RiskStoreException $e) {
            self::assertStringContainsString('keyspace mode mismatch', $e->getMessage());
            self::assertStringContainsString('sharded', $e->getMessage());
            self::assertStringContainsString('legacy', $e->getMessage());
        }

        // The mirror direction: a namespace claimed legacy refuses the
        // sharded store at construction (no silent fallback).
        $legacyNs = 'modelflip' . bin2hex(random_bytes(4));
        KeyspaceMode::claim($this->client, $legacyNs, KeyspaceMode::Legacy);
        try {
            new ShardedRedisRiskStateStore($this->urls(), namespace: $legacyNs, connectTimeoutSecs: 2.0, commandTimeoutSecs: 2.0);
            self::fail('the sharded store must refuse a legacy-marked namespace');
        } catch (RiskStoreException $e) {
            self::assertStringContainsString('keyspace mode mismatch', $e->getMessage());
        }
    }

    /**
     * Classic parity: the same observation sequence through the classic
     * single-tag store and the sharded store produces the same signals.
     * The two runs decay by real elapsed time independently, so each
     * channel carries a small tolerance; the merged global pressure
     * additionally honors the one-second staleness window.
     */
    public function testShardedAssessmentMatchesTheClassicPath(): void
    {
        $legacy = $this->legacyStore('parity');
        $sharded = $this->shardedStore('parity');
        $scopes = [0, 1, 2, 1, 0];
        $events = [
            RiskEventKind::PreIssue,
            RiskEventKind::ChallengeIssued,
            RiskEventKind::InvalidProof,
            RiskEventKind::ReplayAttempt,
            RiskEventKind::ProtectedActionSuccess,
        ];
        $session = str_repeat('5a', 16);
        for ($i = 0; $i < 5; $i++) {
            $classicVector = $legacy->observe($this->observation(
                $this->eventId(100 + $i),
                $scopes[$i],
                600,
                $session,
                null,
                $events[$i],
            ));
            $shardedVector = $sharded->observe($this->observation(
                $this->eventId(200 + $i),
                $scopes[$i],
                600,
                $session,
                null,
                $events[$i],
            ));
            foreach ([
                ['sourceFast', $classicVector->sourceFast, $shardedVector->sourceFast],
                ['sourceSlow', $classicVector->sourceSlow, $shardedVector->sourceSlow],
                ['subnetFast', $classicVector->subnetFast, $shardedVector->subnetFast],
                ['issueDebt', $classicVector->issueDebt, $shardedVector->issueDebt],
                ['badProof', $classicVector->badProof, $shardedVector->badProof],
                ['malformed', $classicVector->malformed, $shardedVector->malformed],
                ['replay', $classicVector->replay, $shardedVector->replay],
                ['actionFailure', $classicVector->actionFailure, $shardedVector->actionFailure],
                ['scopeSwitch', $classicVector->scopeSwitch, $shardedVector->scopeSwitch],
                ['trustCredit', $classicVector->trustCredit, $shardedVector->trustCredit],
                ['principalCredit', $classicVector->principalCredit, $shardedVector->principalCredit],
            ] as [$channel, $a, $b]) {
                self::assertLessThanOrEqual(
                    3,
                    abs($a - $b),
                    "$channel diverged: classic $a, sharded $b",
                );
            }
            // The merged pressure honors the staleness window: both sides
            // carry the same raw accumulation within one window of leak.
            self::assertLessThanOrEqual(
                6,
                abs($classicVector->globalPressure - $shardedVector->globalPressure),
                sprintf(
                    'global pressure diverged beyond the staleness band: classic %d, sharded %d',
                    $classicVector->globalPressure,
                    $shardedVector->globalPressure,
                ),
            );
        }
    }

    public function testConsolidatedAssessmentRegistersTagsAndTheLedger(): void
    {
        $legacy = $this->legacyStore('v2');
        $sharded = $this->shardedStore('v2s');
        $session = str_repeat('9c', 16);
        $observation = $this->observation($this->eventId(2), 1, 600, $session);

        // The classic consolidated reply is the reference: the sharded
        // batch must register a byte-identical ledger entry.
        $legacyReply = $legacy->assessV2WithReply(
            $this->observation($this->eventId(1), 1, 600, $session),
            'aa',
            'tls13|http2',
            $this->registration('dec-classic'),
        );
        self::assertTrue($legacyReply->registrationStatus);

        $reply = $sharded->assessV2WithReply(
            $observation,
            'aa',
            'tls13|http2',
            $this->registration('dec-sharded'),
        );
        self::assertTrue($reply->registrationStatus, 'the pending ledger entry must be created');
        self::assertSame('aa', $reply->existingContextTag);
        self::assertSame('tls13|http2', $reply->existingTlsTag);
        self::assertSame(
            $legacyReply->vector->sourceFast,
            $reply->vector->sourceFast,
            'the v1 observation must run identically',
        );

        // The ledger entries mirror each other field by field (the score
        // is computed from the same signals and weights).
        $classicRaw = $this->client->get($legacy->ledgerKey('dec-classic'));
        $shardedRaw = $this->client->get(KeyspaceMode::outcomeLedgerKey($sharded->namespace(), 'dec-sharded'));
        self::assertIsString($classicRaw);
        self::assertIsString($shardedRaw);
        $classicLedger = json_decode($classicRaw, true);
        $shardedLedger = json_decode($shardedRaw, true);
        self::assertSame($classicLedger['o'], $shardedLedger['o']);
        self::assertSame($classicLedger['scope'], $shardedLedger['scope']);
        self::assertSame($classicLedger['hour'], $shardedLedger['hour']);
        self::assertSame($classicLedger['score'], $shardedLedger['score'], 'the client-side score must match the script-computed one exactly');

        // A retried decision id is refused (SET NX), and a changed tag on
        // an established session returns the first tags.
        $retry = $sharded->assessV2WithReply(
            $this->observation($this->eventId(3), 1, 600, $session),
            'bb',
            'aa',
            $this->registration('dec-sharded'),
        );
        self::assertFalse($retry->registrationStatus, 'a duplicate decision id must not overwrite');
        self::assertSame('aa', $retry->existingContextTag, 'the first tag wins');
    }

    public function testMergedAggregateHonorsTheStalenessWindow(): void
    {
        $store = $this->shardedStore('stale');
        // Each assessment writes its own shard's post-apply sum back into
        // the cache, so the merged read reflects every commit immediately
        // (stronger than the one-second contract).
        $store->observe($this->observation($this->eventId(1)));
        self::assertThat(
            $store->mergedGlobalPressure(),
            self::logicalAnd(self::greaterThanOrEqual(1700), self::lessThanOrEqual(2000)),
            'the written shard is current',
        );
        // A second commit inside the window keeps the merge current.
        $store->observe($this->observation($this->eventId(2)));
        self::assertThat(
            $store->mergedGlobalPressure(),
            self::logicalAnd(self::greaterThanOrEqual(3400), self::lessThanOrEqual(4000)),
            'both commits are visible inside the window',
        );
        // Past the window the merge batch re-runs and still carries both
        // events (minus the real-elapsed leak).
        usleep(1_100_000);
        self::assertThat(
            $store->mergedGlobalPressure(),
            self::logicalAnd(self::greaterThanOrEqual(3200), self::lessThanOrEqual(4000)),
            'the refreshed merge still carries both events',
        );
    }

    public function testScopeShardsDisperseAcrossSlots(): void
    {
        $store = $this->shardedStore('disp');
        for ($i = 0; $i < 120; $i++) {
            $store->observe($this->observation($this->eventId($i)));
        }
        $pattern = '{kiwi:' . $store->namespace() . ':s:global:*}:scope:*';
        $keys = $this->client->keys($pattern);
        self::assertGreaterThanOrEqual(
            8,
            \count(array_unique($keys)),
            sprintf('120 events over 16 shards must light up most of them (got %d)', \count(array_unique($keys))),
        );
        foreach ($keys as $key) {
            self::assertSame(1, $this->client->exists($key));
        }
    }

    public function testAuxiliarySurfacesStayModeInsensitive(): void
    {
        $store = $this->shardedStore('aux');
        $hour = intdiv(self::T0, 3_600_000);

        // Ledger lifecycle through the sharded store.
        self::assertTrue($store->registerOutcome('led-1', 7, $hour, 900));
        self::assertFalse($store->registerOutcome('led-1', 7, $hour, 900));
        self::assertSame(1, $store->confirmOutcome('led-1', false));
        self::assertSame(0, $store->confirmOutcome('led-1', false));
        self::assertTrue($store->correctOutcome('led-1', true));
        self::assertFalse($store->correctOutcome('led-1', true));

        // Marks through the sharded store.
        self::assertSame(1, $store->writeMark('principal', 'mark-one', 'ConfirmedAbuse', self::T0));
        $mark = $store->readMark('principal', 'mark-one');
        self::assertNotNull($mark);
        self::assertSame('ConfirmedAbuse', $mark['kind']);
        self::assertSame(1, $store->forgetMarks('principal', 'mark-one'));
        self::assertNull($store->readMark('principal', 'mark-one'));

        // The first-seen session tag surface (same key shape in both modes).
        $session = str_repeat('7e', 16);
        self::assertSame('aa', $store->sessionFirstContextTag($session, 'aa'));
        self::assertSame('aa', $store->sessionFirstContextTag($session, 'bb'), 'the first-seen tag wins');
    }

    /**
     * The invariant core against a real Redis Cluster: gated behind
     * KIWI_SHARDING_CLUSTER=1 with `RISK_REDIS_URL` as the seed (any
     * cluster node). The store resolves the topology at construction,
     * routes every family to its owning primary and serves the sharded
     * assessment batch across the three primaries.
     * The reference deployment is three primaries on ports 6433-6435
     * (redis-cli --cluster create ... --cluster-replicas 0). KEYS is
     * node-local in cluster mode, so every primary is scanned for the
     * shard-dispersion check.
     */
    public function testClusterTopologyServesTheShardedInvariants(): void
    {
        if (getenv('KIWI_SHARDING_CLUSTER') !== '1') {
            self::markTestSkipped('KIWI_SHARDING_CLUSTER != 1');
        }
        $seed = (string) getenv('RISK_REDIS_URL');
        $ns = 'clu' . bin2hex(random_bytes(4));
        $store = new ShardedRedisRiskStateStore(
            [$seed],
            namespace: $ns,
            cluster: true,
            connectTimeoutSecs: 2.0,
            commandTimeoutSecs: 2.0,
        );
        self::assertSame(3, $store->endpointCount(), 'the three primaries must all be routed');

        // The core signal contract across the cluster-routed batch.
        $first = $store->observeWithReply($this->observation($this->eventId(1)));
        self::assertSame(125, $first->vector->sourceFast);
        self::assertSame(10, $first->vector->sourceSlow);
        self::assertSame(125, $first->vector->subnetFast);
        self::assertFalse($first->isDuplicate);

        // Dedupe and the merged aggregate across shards on three nodes.
        $duplicate = $store->observeWithReply($this->observation($this->eventId(1)));
        self::assertTrue($duplicate->isDuplicate);
        $third = $store->observeWithReply($this->observation($this->eventId(2)));
        self::assertFalse($third->isDuplicate);
        self::assertThat(
            $third->vector->sourceFast,
            self::logicalAnd(self::greaterThanOrEqual(200), self::lessThanOrEqual(250)),
            'exactly two increments',
        );

        // Saturation drives the level machine across all three primaries.
        for ($i = 100; $i < 200; $i++) {
            $store->observe($this->observation($this->eventId($i)));
        }
        usleep(1_100_000);
        $vector = $store->observeWithReply($this->observation($this->eventId(500)))->vector;
        self::assertThat(
            $vector->globalPressure,
            self::logicalAnd(self::greaterThanOrEqual(960), self::lessThanOrEqual(1000)),
            'the merged aggregate saturates across the cluster',
        );
        self::assertSame(4, $store->lastGlobalLevel());

        // Scope shards disperse over the cluster (KEYS is node-local).
        $port = (int) (parse_url($seed, PHP_URL_PORT) ?? 6379);
        $pattern = '{kiwi:' . $store->namespace() . ':s:global:*}:scope:*';
        $keys = [];
        foreach ([$port, $port + 1, $port + 2] as $nodePort) {
            $node = RedisRiskStateStore::createClient("tcp://127.0.0.1:$nodePort");
            $keys = array_merge($keys, $node->keys($pattern));
        }
        self::assertGreaterThanOrEqual(
            8,
            \count(array_unique($keys)),
            sprintf('the scope shards must light up across the cluster (got %d)', \count(array_unique($keys))),
        );

        // The auxiliary surfaces ride the node that owns the shared tag.
        $hour = intdiv(self::T0, 3_600_000);
        self::assertTrue($store->registerOutcome('clu-led', 7, $hour, 900));
        self::assertSame(1, $store->confirmOutcome('clu-led', true));
        self::assertSame(1, $store->writeMark('principal', 'clu-p', 'ConfirmedAbuse', self::T0));
        self::assertSame(1, $store->forgetMarks('principal', 'clu-p'));
    }

    /**
     * The partial-batch retry proof: an armed proxy (a forked process)
     * swallows one endpoint's commands mid-batch, so part of the batch
     * commits while the rest is lost. The retried assessment must
     * produce exactly one application, never a double count: the
     * per-dimension dedupe markers turn the committed dimensions into
     * no-ops.
     */
    public function testPartialBatchRetryIsIdempotent(): void
    {
        $url = (string) getenv('RISK_REDIS_URL');
        $parts = parse_url($url);
        $upstreamPort = (int) ($parts['port'] ?? 6379);
        [$listener, $armPipe, $childPid, $fromParentHolder] = self::spawnDroppingProxy($upstreamPort);

        try {
            $proxyPort = self::listenerPort($listener);
            $proxyUrl = "tcp://127.0.0.1:$proxyPort";
            $ns = 'partial' . bin2hex(random_bytes(4));
            // Order the endpoints so the source state key routes to the
            // proxy: the first assessment is guaranteed to lose the
            // batch's proxy-side groups while the real-side groups commit.
            $probe = new ShardedRedisRiskStateStore([$url, $proxyUrl], namespace: 'route' . bin2hex(random_bytes(4)), connectTimeoutSecs: 2.0, commandTimeoutSecs: 2.0);
            $srcCurKey = KeyspaceMode::identityStateKey($probe->namespace(), 'src', 1, str_repeat('b', 32));
            $proxyFirst = $probe->endpointForKey($srcCurKey) === 0;
            $endpoints = $proxyFirst ? [$proxyUrl, $url] : [$url, $proxyUrl];
            $store = new ShardedRedisRiskStateStore($endpoints, namespace: $ns, connectTimeoutSecs: 2.0, commandTimeoutSecs: 2.0);
            $obs = $this->observation($this->eventId(42));

            // Arm the drop only after every construction connection has
            // been served clean, and wait for the child's ack so the
            // next connection is guaranteed the dropped one.
            fwrite($armPipe, '1');
            fflush($armPipe);
            $ackRead = [$armPipe];
            $ackWrite = null;
            $ackExcept = null;
            $ready = stream_select($ackRead, $ackWrite, $ackExcept, 5);
            if ($ready === false || $ready === 0 || fread($armPipe, 1) === false) {
                self::fail('the proxy child never acknowledged the arm');
            }
            // Force fresh connections so the batch's proxy-side commands
            // arrive on a connection the armed child can drop (the same
            // eviction a failed batch forces through the poison rule).
            $store->disconnectAll();

            // Attempt 1: the proxy swallows its connection; the batch fails.
            try {
                $store->observe($obs);
                self::fail('the dropped-reply batch must fail (the source state routes through the proxy)');
            } catch (RiskStoreException $e) {
                self::assertTrue($e->getMessage() !== '', 'the backend failure carries a message');
            }

            // Attempt 2: the retry succeeds and the committed dimensions
            // are skipped by their markers: exactly one application.
            $vector = $store->observe($obs);
            self::assertSame(125, $vector->sourceFast, 'one application (a double count would read 250)');
            self::assertSame(125, $vector->subnetFast);

            // The final aggregate check reads through a direct store on
            // the same namespace, so the proof never depends on the proxy.
            usleep(1_100_000);
            $direct = new ShardedRedisRiskStateStore([$url], namespace: $ns, connectTimeoutSecs: 2.0, commandTimeoutSecs: 2.0);
            $merged = $direct->mergedGlobalPressure();
            self::assertThat(
                $merged,
                self::logicalAnd(self::greaterThanOrEqual(1600), self::lessThanOrEqual(2000)),
                'the merged aggregate must carry exactly one event after the window',
            );
        } finally {
            posix_kill($childPid, SIGTERM);
            pcntl_waitpid($childPid, $status);
            fclose($listener);
            fclose($armPipe);
        }
    }

    private static function listenerPort($listener): int
    {
        $name = stream_socket_get_name($listener, false);

        return (int) substr((string) $name, (int) strrpos((string) $name, ':') + 1);
    }

    /**
     * Forks a TCP proxy: clean forwarding until the arming pipe carries a
     * byte, then the next connection is swallowed with no reply (the
     * dropped-reply injection). Returns the listener, the parent-side
     * end of the arming pipe and the child pid.
     *
     * @return array{0: resource, 1: resource, 2: int}
     */
    private static function spawnDroppingProxy(int $upstreamPort): array
    {
        $listener = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        self::assertNotFalse($listener, "proxy bind failed: $errstr");
        stream_set_blocking($listener, false);
        $sockets = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        if ($sockets === false) {
            self::fail('stream_socket_pair failed');
        }
        [$toChild, $fromParent] = $sockets;
        $pid = pcntl_fork();
        if ($pid === 0) {
            // The child serves the proxy; it never returns to phpunit.
            fclose($fromParent);
            try {
                self::proxyLoop($listener, $toChild, $upstreamPort);
            } catch (\Throwable) {
                // The child exits quietly; the parent owns the verdicts.
            }
            exit(0);
        }
        fclose($toChild);

        return [$listener, $fromParent, $pid, $fromParent];
    }

    /**
     * The child's event loop: one stream_select over the listener, the
     * arming pipe and every forwarded connection pair, so a long-lived
     * connection never starves a new accept.
     */
    private static function proxyLoop($listener, $armPipe, int $upstreamPort): void
    {
        $armed = false;
        $dropped = false;
        $pairs = [];

        while (true) {
            $read = [$listener];
            if (!$armed) {
                $read[] = $armPipe;
            }
            foreach ($pairs as [$clientSide, $upstreamSide]) {
                if (is_resource($clientSide) || $clientSide instanceof \Socket) {
                    $read[] = $clientSide;
                }
                if (is_resource($upstreamSide) || $upstreamSide instanceof \Socket) {
                    $read[] = $upstreamSide;
                }
            }
            $write = null;
            $except = null;
            if (stream_select($read, $write, $except, 5) === false) {
                continue;
            }
            if (!$armed && in_array($armPipe, $read, true)) {
                $armByte = fread($armPipe, 1);
                if ($armByte !== false && $armByte !== '') {
                    $armed = true;
                    // Acknowledge on the same bidirectional pipe, so the
                    // parent only proceeds once the drop is live.
                    fwrite($armPipe, 'a');
                }
            }
            if (in_array($listener, $read, true)) {
                $client = stream_socket_accept($listener, 0);
                if (is_resource($client)) {
                    if ($armed && !$dropped) {
                        // The dropped-reply injection: swallow whatever
                        // the client pipelined, then close with no reply.
                        $dropped = true;
                        stream_set_blocking($client, true);
                        @fread($client, 65536);
                        fclose($client);
                    } else {
                        $upstream = stream_socket_client("tcp://127.0.0.1:$upstreamPort", $errno, $errstr, 5);
                        if (is_resource($upstream)) {
                            stream_set_blocking($client, false);
                            stream_set_blocking($upstream, false);
                            $pairs[] = [$client, $upstream];
                        } else {
                            fclose($client);
                        }
                    }
                }
            }
            foreach ($read as $stream) {
                if ($stream === $listener || $stream === $armPipe) {
                    continue;
                }
                $data = @fread($stream, 65536);
                if ($data === false || $data === '') {
                    self::dropPair($pairs, $stream);
                    continue;
                }
                foreach ($pairs as $index => [$clientSide, $upstreamSide]) {
                    if ($stream === $clientSide) {
                        fwrite($upstreamSide, $data);
                    } elseif ($stream === $upstreamSide) {
                        fwrite($clientSide, $data);
                    }
                }
            }
        }
    }

    /** Closes and removes the pair a stream belongs to (peer EOF or error). */
    private static function dropPair(array &$pairs, $stream): void
    {
        foreach ($pairs as $index => [$clientSide, $upstreamSide]) {
            if ($stream === $clientSide || $stream === $upstreamSide) {
                @fclose($clientSide);
                @fclose($upstreamSide);
                unset($pairs[$index]);

                return;
            }
        }
    }
}
