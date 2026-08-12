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
 * The Lua script executes atomically, so sequential calls in one process
 * are equivalent to concurrent ones for state semantics; the store asserts
 * that all keys share one Redis Cluster slot. Each epoch key uses its OWN
 * epoch's pseudonym (prev/current/next differ).
 */
final class RedisRiskStateStoreTest extends TestCase
{
    private const T0 = 1_700_000_000_000; // fixed ms clock: no decay between same-ts events

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
        // AuthenticationSuccess (10) against a PRESENT principal: +2000 raw
        // principal trust -> 2000*1000/10000 = 200.
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
        self::assertSame(200, $vector->trustCredit); // max3(src, sess, prin) = prin

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

    public function testDuplicateEventIdReturnsCurrentSignalsWithDuplicateFlag(): void
    {
        $store = $this->store();
        $eventId = str_repeat('7', 32);

        $first = $store->observe($this->observation($eventId));
        self::assertSame(125, $first->sourceFast);
        self::assertFalse($store->lastIsDuplicate());

        // Duplicate: state NOT applied again, but the CURRENT signals ARE
        // returned with is_duplicate = 1 (no -1 marker anymore).
        $duplicate = $store->observe($this->observation($eventId));
        self::assertSame(125, $duplicate->sourceFast, 'duplicate must return the current signals');
        self::assertSame(10, $duplicate->sourceSlow);
        self::assertTrue($store->lastIsDuplicate());

        // A distinct event must observe the state from a SINGLE increment.
        $third = $store->observe($this->observation(str_repeat('8', 32)));
        self::assertSame(250, $third->sourceFast);
        self::assertSame(20, $third->sourceSlow);
        self::assertFalse($store->lastIsDuplicate());
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
        self::assertSame(1000, $vector->sourceFast);
        self::assertSame(1000, $vector->sourceSlow);
        self::assertSame(1000, $vector->subnetFast);
        self::assertSame(1000, $vector->globalPressure);
        self::assertSame(4, $store->lastGlobalLevel());
    }

    public function testGlobalHysteresis(): void
    {
        $t0 = self::T0;

        // Normalized global thresholds: L1 >= 300, L2 >= 550, L3 >= 750,
        // L4 >= 900 (raw gp scaled by sat_global 70000). Each PreIssue adds
        // 2000 raw (rf 1000 + rs 1000): 20 events -> gp 40000 -> 571 (L2);
        // 32 events -> gp 64000 -> 914 (L4). Leak: rf 250/s, rs 20/s.
        $big = $this->store(60_000, 'big');
        for ($i = 1; $i <= 20; $i++) {
            $big->observe($this->observation(str_pad((string) $i, 32, '0', STR_PAD_LEFT), 2, $t0));
        }
        self::assertSame(2, $big->lastGlobalLevel(), '20 events must reach level 2');
        for ($i = 21; $i <= 32; $i++) {
            $big->observe($this->observation(str_pad((string) $i, 32, '0', STR_PAD_LEFT), 2, $t0));
        }
        self::assertSame(4, $big->lastGlobalLevel(), '32 events must reach level 4');
        self::assertSame($t0 + 60_000, $big->lastCooldownUntilMs());

        // t0+61s: rf 32000 - 15250 = 16750; rs 32000 - 1220 = 30780;
        // gp 49530 -> 707 -> target L2 (< L4). The window has passed, so the
        // level drops to the target (hysteresis hold expired).
        $big->observe($this->observation(str_repeat('9', 32), 2, $t0 + 61_000));
        self::assertSame(2, $big->lastGlobalLevel(), 'level must drop to target after the hysteresis window');
        self::assertSame(0, $big->lastCooldownUntilMs());

        // A 50 ms window leaves as soon as the window passes.
        $tiny = $this->store(50, 'tiny');
        for ($i = 1; $i <= 32; $i++) {
            $tiny->observe($this->observation(str_pad((string) $i, 32, '0', STR_PAD_LEFT), 2, $t0));
        }
        self::assertSame(4, $tiny->lastGlobalLevel());
        // Inside the 50ms window the level holds (target still L4 at this
        // pressure). The cooldown was armed by the FIRST event's ratchet
        // ($t0+50) and only re-arms on a level RISE — at level 4 it stays
        // at its first value.
        $tiny->observe($this->observation(str_pad('8', 32, '0', STR_PAD_LEFT), 2, $t0 + 10));
        self::assertSame(4, $tiny->lastGlobalLevel(), 'level holds inside the window');
        self::assertSame($t0 + 50, $tiny->lastCooldownUntilMs());
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
