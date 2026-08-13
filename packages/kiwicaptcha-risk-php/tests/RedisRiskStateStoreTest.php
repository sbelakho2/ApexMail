<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use Predis\Client;
use PHPUnit\Framework\TestCase;

/**
 * Redis-backed store tests. Skipped unless RISK_REDIS_URL is set
 * (e.g. tcp://127.0.0.1:6399 with `docker run -d -p 6399:6379 redis:7-alpine`).
 *
 * The risk-v1 Lua derives `now` from Redis TIME (ARGV[3] now_ms is
 * informational — wire compat only), so expectations that depend on decay
 * are derived from REAL elapsed time (bracketed TIME measurements around
 * the observations) instead of injected timestamps. The Lua executes
 * atomically, so sequential calls in one process are equivalent to
 * concurrent ones for state semantics; the store asserts that all keys
 * share one Redis Cluster slot.
 */
final class RedisRiskStateStoreTest extends TestCase
{
    private const T0 = 1_700_000_000_000; // fixed ms clock: epoch math only (now_ms is informational)

    private ?Client $client = null;

    protected function setUp(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if (!is_string($url) || $url === '') {
            self::markTestSkipped('RISK_REDIS_URL not set; start redis with: docker run -d -p 6399:6379 redis:7-alpine');
        }
        $this->client = RedisRiskStateStore::createClient($url);
    }

    private function store(int $hysteresisMs = 60000, string $suffix = ''): RedisRiskStateStore
    {
        return new RedisRiskStateStore(
            $this->client,
            namespace: 'test' . $suffix . bin2hex(random_bytes(4)),
            hysteresisMs: $hysteresisMs,
        );
    }

    private function observation(
        string $eventId,
        int $scope = 0,
        int $nowMs = self::T0,
        int $networkRisk = 0,
        RiskEventKind $event = RiskEventKind::PreIssue,
        ?string $sessionId = null,
        ?string $principalId = null,
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
            nowMs: $nowMs,
        );
    }

    /** The Redis server clock in epoch milliseconds (TIME is the script's clock authority). */
    private function redisNowMs(): int
    {
        $t = $this->client->time();
        return ((int) $t[0]) * 1000 + intdiv((int) $t[1], 1000);
    }

    /**
     * The possible normalized value of `raw` after the real elapsed window
     * bracketed by [minElapsedMs, maxElapsedMs] (TIME measured around the
     * observations): leak = floor(elapsed*rate/1000), leaked = max(0, raw -
     * leak), value = floor(leaked*1000/sat). The Lua computes its elapsed
     * from Redis TIME inside the script, which always falls inside the
     * bracket, so the true value is within the returned [min, max] range.
     *
     * @return array{0: int, 1: int} [min, max]
     */
    private function expectedLeakRange(int $raw, int $ratePerSec, int $sat, int $minElapsedMs, int $maxElapsedMs): array
    {
        $value = static fn (int $elapsed): int => intdiv(max(0, $raw - intdiv($elapsed * $ratePerSec, 1000)) * 1000, $sat);
        return [$value($maxElapsedMs), $value($minElapsedMs)];
    }

    public function testSingleEvent(): void
    {
        $store = $this->store();
        $vector = $store->observe($this->observation(str_repeat('1', 32)));

        self::assertSame(125, $vector->sourceFast);   // 1000*1000/8000
        self::assertSame(10, $vector->sourceSlow);    // 1000*1000/100000
        self::assertSame(125, $vector->subnetFast);
        self::assertSame(0, $vector->issueDebt);
        self::assertSame(28, $vector->globalPressure); // 2000*1000/70000
        self::assertSame(0, $vector->networkRisk);    // classifier side-channel override
        self::assertSame(0, $vector->principalCredit); // no principal state
        self::assertSame(0, $store->lastGlobalLevel());
        self::assertFalse($store->lastIsDuplicate());
    }

    public function testPrincipalCreditIsReal(): void
    {
        // AuthenticationSuccess (10) against a PRESENT principal: +1500 raw
        // source trust and +2000 raw principal trust. The trust split means
        // NO double subtraction: trust_credit covers source+session only
        // (1500 -> 150), principal_credit is the principal's own (2000 -> 200).
        $store = $this->store();
        $vector = $store->observe($this->observation(
            str_repeat('a', 32),
            0,
            self::T0,
            0,
            RiskEventKind::AuthenticationSuccess,
            null,
            str_repeat('f', 32),
        ));
        self::assertSame(200, $vector->principalCredit);
        self::assertSame(150, $vector->trustCredit); // source trust only, never the principal's

        // SolveSuccess (3) against a PRESENT session on a FRESH store:
        // session trust +150 -> 150*1000/10000 = 15.
        $store = $this->store();
        $vector = $store->observe($this->observation(
            str_repeat('b', 32),
            0,
            self::T0,
            0,
            RiskEventKind::SolveSuccess,
            str_repeat('e', 32),
            null,
        ));
        self::assertSame(15, $vector->trustCredit);
        self::assertSame(0, $vector->principalCredit);

        // No session/principal: no credit at all.
        $store = $this->store();
        $vector = $store->observe($this->observation(str_repeat('c', 32)));
        self::assertSame(0, $vector->principalCredit);
        self::assertSame(0, $vector->trustCredit);
    }

    public function testRotatedEpochPseudonymsSumNotMax(): void
    {
        // A burst split across an epoch boundary: the first request writes
        // epoch 12345's bucket, the second (at epoch 12346) writes the NEXT
        // epoch and reads 12345 as its PREV bucket. v3 SUMs the rotated
        // pseudonyms of one identity (2000 raw rf), so the second
        // observation sees ~250 sourceFast — under a max it would be 125.
        // The first bucket has decayed by the REAL elapsed time between the
        // two script executions (Redis TIME), so the expectation is derived
        // from the bracketed elapsed.
        $store = $this->store();
        $tBeforeFirst = $this->redisNowMs();
        $store->observe(new RiskObservation(
            event: RiskEventKind::PreIssue,
            scope: 1,
            sourceEpoch: 12345,
            sourceIdPrev: str_repeat('a', 32),
            sourceId: str_repeat('b', 32),
            sourceIdNext: str_repeat('c', 32),
            subnetEpoch: 12345,
            subnetIdPrev: str_repeat('d', 32),
            subnetId: str_repeat('e', 32),
            subnetIdNext: str_repeat('f', 32),
            sessionId: null,
            principalId: null,
            eventId: str_repeat('1', 32),
            networkRisk: 0,
            nowMs: self::T0,
        ));
        $tAfterFirst = $this->redisNowMs();
        $tBeforeSecond = $this->redisNowMs();
        $vector = $store->observe(new RiskObservation(
            event: RiskEventKind::PreIssue,
            scope: 1,
            sourceEpoch: 12346,
            sourceIdPrev: str_repeat('b', 32), // the identity's epoch-12345 pseudonym
            sourceId: str_repeat('c', 32),
            sourceIdNext: str_repeat('d', 32),
            subnetEpoch: 12346,
            subnetIdPrev: str_repeat('e', 32), // the identity's epoch-12345 pseudonym
            subnetId: str_repeat('f', 32),
            subnetIdNext: str_repeat('d', 32),
            sessionId: null,
            principalId: null,
            eventId: str_repeat('2', 32),
            networkRisk: 0,
            nowMs: self::T0,
        ));
        $tAfterSecond = $this->redisNowMs();

        // 2000 raw rf (sum3) minus the real decay of the first bucket.
        [$minFast, $maxFast] = $this->expectedLeakRange(
            2000,
            250,
            8000,
            $tBeforeSecond - $tAfterFirst,
            $tAfterSecond - $tBeforeFirst,
        );
        [$minSlow, $maxSlow] = $this->expectedLeakRange(
            2000,
            20,
            100000,
            $tBeforeSecond - $tAfterFirst,
            $tAfterSecond - $tBeforeFirst,
        );
        self::assertGreaterThanOrEqual($minFast, $vector->sourceFast, 'sum3: 2000 raw rf across epochs, decayed by real elapsed');
        self::assertLessThanOrEqual($maxFast, $vector->sourceFast);
        self::assertGreaterThanOrEqual($minSlow, $vector->sourceSlow);
        self::assertLessThanOrEqual($maxSlow, $vector->sourceSlow);
        self::assertGreaterThanOrEqual(250 - 1, $vector->sourceFast, 'ms-scale real elapsed must keep the sum near 250 (no max-collapse)');

        // 4000 raw global (rf+rs across both epochs) minus real decay.
        $globalValue = static fn (int $elapsed): int => intdiv(
            max(0, 4000 - intdiv($elapsed * 250, 1000) - intdiv($elapsed * 20, 1000)) * 1000,
            70000,
        );
        self::assertGreaterThanOrEqual($globalValue($tAfterSecond - $tBeforeFirst), $vector->globalPressure);
        self::assertLessThanOrEqual($globalValue($tBeforeSecond - $tAfterFirst), $vector->globalPressure);
        self::assertSame(0, $store->lastGlobalLevel());
    }

    public function testSourceAndSessionMaxNotSum(): void
    {
        // One PreIssue increments BOTH the source and the session velocity.
        // They are DIFFERENT identity dimensions observing the same request,
        // so the aggregate MAXes — never double-counts.
        $store = $this->store();
        $vector = $store->observe($this->observation(
            str_repeat('1', 32),
            1,
            self::T0,
            0,
            RiskEventKind::PreIssue,
            str_repeat('a', 32),
        ));
        self::assertSame(125, $vector->sourceFast, 'source 1000 vs session 1000 -> max 1000, not 2000');
        self::assertSame(10, $vector->sourceSlow);
        self::assertSame(125, $vector->subnetFast);
    }

    public function testPrincipalDimensionMaxesWithSource(): void
    {
        // AuthenticationFailure adds source af +2000 AND principal af +2500.
        // bad/mal/af aggregate with max4(src, sess, prin): 2500 -> 416,
        // never 4500 (sum would be 750).
        $store = $this->store();
        $vector = $store->observe($this->observation(
            str_repeat('1', 32),
            0,
            self::T0,
            0,
            RiskEventKind::AuthenticationFailure,
            null,
            str_repeat('b', 32),
        ));
        self::assertSame(416, $vector->actionFailure); // 2500*1000/6000
        self::assertSame(0, $vector->trustCredit);
        self::assertSame(0, $vector->principalCredit, 'failures never credit');
    }

    public function testDuplicateEventIdReturnsCurrentSignalsWithDuplicateFlag(): void
    {
        $store = $this->store();
        $eventId = str_repeat('7', 32);

        $first = $store->observe($this->observation($eventId));
        self::assertSame(125, $first->sourceFast);
        self::assertFalse($store->lastIsDuplicate());

        // Duplicate: state NOT applied again, but the CURRENT (real-time
        // decayed) signals ARE returned with is_duplicate = 1.
        $tAfterFirst = $this->redisNowMs();
        $tBeforeDup = $this->redisNowMs();
        $duplicate = $store->observe($this->observation($eventId));
        $tAfterDup = $this->redisNowMs();
        self::assertTrue($store->lastIsDuplicate());
        [$min, $max] = $this->expectedLeakRange(
            1000,
            250,
            8000,
            $tBeforeDup - $tAfterFirst,
            $tAfterDup - $tAfterFirst,
        );
        self::assertGreaterThanOrEqual($min, $duplicate->sourceFast, 'duplicate must return the decayed current signals');
        self::assertLessThanOrEqual($max, $duplicate->sourceFast);
        self::assertGreaterThanOrEqual(124, $duplicate->sourceFast, 'ms-scale real elapsed cannot decay a fresh burst below 124');

        // A distinct event observes the state from a SINGLE increment
        // (2000 raw minus the real decay of the first bucket).
        $tBeforeThird = $this->redisNowMs();
        $third = $store->observe($this->observation(str_repeat('8', 32)));
        $tAfterThird = $this->redisNowMs();
        self::assertFalse($store->lastIsDuplicate());
        [$min, $max] = $this->expectedLeakRange(
            2000,
            250,
            8000,
            $tBeforeThird - $tAfterFirst,
            $tAfterThird - $tAfterFirst,
        );
        self::assertGreaterThanOrEqual($min, $third->sourceFast);
        self::assertLessThanOrEqual($max, $third->sourceFast);
        self::assertGreaterThanOrEqual(247, $third->sourceFast, 'two increments minus ms-scale decay (real-time tolerance)');
    }

    public function testNetworkRiskOverrideSlot(): void
    {
        $store = $this->store();
        $vector = $store->observe($this->observation(str_repeat('3', 32), 0, self::T0, 600));
        self::assertSame(600, $vector->networkRisk);
        self::assertSame(0, $vector->principalCredit);
    }

    public function testHundredSequentialEventsSaturate(): void
    {
        $store = $this->store();
        $vector = null;
        for ($i = 0; $i < 100; $i++) {
            $vector = $store->observe($this->observation(sprintf('%032x', $i)));
        }
        // 100 PreIssues = 200000 raw; even ~1 s of real leak (rf 250/s +
        // rs 20/s) cannot pull the totals below saturation.
        self::assertSame(1000, $vector->sourceFast);
        self::assertSame(1000, $vector->sourceSlow);
        self::assertSame(1000, $vector->subnetFast);
        self::assertSame(1000, $vector->globalPressure);
        self::assertSame(4, $store->lastGlobalLevel());
    }

    public function testGlobalHysteresis(): void
    {
        // Storm: each PreIssue adds 2000 raw (rf 1000 + rs 1000); 32 events
        // -> gp 64000 -> 914 -> level 4. All events run back-to-back, so
        // real decay between them is ms-scale and negligible for the level.
        $big = $this->store(60_000, 'big');
        $tBeforeStorm = $this->redisNowMs();
        for ($i = 1; $i <= 32; $i++) {
            $big->observe($this->observation(str_pad((string) $i, 32, '0', STR_PAD_LEFT), 2));
        }
        $tAfterStorm = $this->redisNowMs();
        self::assertSame(4, $big->lastGlobalLevel(), '32 events must reach level 4');

        // The cooldown is ARMED by the level ratchet: Redis TIME at the last
        // rise + the hysteresis window (never the injected now_ms).
        self::assertGreaterThanOrEqual($tBeforeStorm + 60_000, $big->lastCooldownUntilMs());
        self::assertLessThanOrEqual($tAfterStorm + 60_000, $big->lastCooldownUntilMs());

        // Inside the window the level holds (the target is still 4 at this
        // pressure) and the cooldown deadline is untouched (no new rise).
        $big->observe($this->observation(str_repeat('9', 32), 2));
        self::assertSame(4, $big->lastGlobalLevel(), 'level holds while the pressure target is still 4');
        self::assertLessThanOrEqual($tAfterStorm + 60_000, $big->lastCooldownUntilMs());

        // DROP TEST (short hysteresis + REAL sleep): with a 2000 ms window,
        // a ~17 s real sleep lets the pressure decay below the L4 exit
        // threshold (exit[4] = 850; rf leak 250/s + rs leak 20/s:
        // 914 - (270 raw/s * ~17 s) -> ~848) and the expired window then
        // releases the level to the target 3. RiskDenied (17) adds NO
        // pressure, so the drop observation itself cannot re-raise the
        // target. (~2.1 s cannot produce a drop: the raw decay rate of
        // PreIssue pressure is 270/s, so any level exit needs >= ~16.6 s
        // regardless of the hysteresis window.)
        $drop = $this->store(2_000, 'drop');
        for ($i = 1; $i <= 32; $i++) {
            $drop->observe($this->observation(str_pad((string) $i, 32, '0', STR_PAD_LEFT), 2));
        }
        self::assertSame(4, $drop->lastGlobalLevel());
        $tAfterStorm = $this->redisNowMs();
        self::assertLessThanOrEqual($tAfterStorm + 2_000, $drop->lastCooldownUntilMs());
        self::assertGreaterThanOrEqual($tAfterStorm, $drop->lastCooldownUntilMs(), 'the drop cooldown is TIME + 2000 ms');

        usleep(17_000_000); // >= ~16.6 s needed to cross exit[4] = 850

        $drop->observe($this->observation(str_repeat('d', 32), 2, self::T0, 0, RiskEventKind::RiskDenied));
        self::assertSame(3, $drop->lastGlobalLevel(), 'level must drop to the decayed target after the short window expires');
        self::assertSame(0, $drop->lastCooldownUntilMs(), 'the drop clears the cooldown');
    }

    public function testKeySlotAndCrc16(): void
    {
        self::assertSame(0x31C3, RedisRiskStateStore::crc16('123456789'));

        $store = $this->store();
        // Contract key set for one observation: each epoch uses ITS OWN
        // pseudonym (prev/current/next differ).
        $tag = '{kiwi:' . 'slot' . '}';
        $keys = [
            "{$tag}:risk:src:12345:" . str_repeat('b', 32),
            "{$tag}:risk:src:12344:" . str_repeat('a', 32),
            "{$tag}:risk:src:12346:" . str_repeat('c', 32),
            "{$tag}:risk:net:12345:" . str_repeat('e', 32),
            "{$tag}:risk:net:12344:" . str_repeat('d', 32),
            "{$tag}:risk:net:12346:" . str_repeat('f', 32),
            "{$tag}:risk:session:" . str_repeat('0', 32),
            "{$tag}:risk:principal:" . str_repeat('0', 32),
            "{$tag}:risk:global",
            "{$tag}:risk:dedupe:" . str_repeat('c', 32),
        ];
        $store->assertSameSlot($keys); // must not throw

        $broken = $keys;
        $broken[0] = str_replace($tag, '{kiwi:other}', $broken[0]);
        $this->expectException(\LogicException::class);
        $store->assertSameSlot($broken);
    }

    public function testNamespaceAccessor(): void
    {
        $store = new RedisRiskStateStore($this->client, namespace: 'deploy42');
        self::assertSame('deploy42', $store->namespace());
    }
}
