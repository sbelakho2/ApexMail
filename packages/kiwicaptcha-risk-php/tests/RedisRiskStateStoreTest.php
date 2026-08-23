<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use KiwiCaptcha\Risk\Storage\RiskStateStoreInterface;
use Predis\Client;
use Predis\Command\CommandInterface;
use PHPUnit\Framework\TestCase;

/**
 * Redis-backed store tests. Skipped unless the Redis test URL is set
 * (e.g. tcp://127.0.0.1:6399 with `docker run -d -p 6399:6379 redis:7-alpine`).
 *
 * The risk-v1 Lua derives `now` from Redis time (argv[3] now_ms is
 * informational, wire compat only), so expectations that depend on
 * decay are derived from real elapsed time (bracketed time
 * measurements around the observations) instead of injected
 * timestamps. The Lua executes atomically, so sequential calls in one
 * process are equivalent to concurrent ones for state semantics; the
 * store asserts that all keys share one Redis Cluster slot.
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

    /** The Redis server clock in epoch milliseconds (time is the script's clock authority). */
    private function redisNowMs(): int
    {
        $t = $this->client->time();
        return ((int) $t[0]) * 1000 + intdiv((int) $t[1], 1000);
    }

    /**
     * The possible normalized value of `raw` after the real elapsed window
     * bracketed by [minElapsedMs, maxElapsedMs] (time measured around the
     * observations): leak = floor(elapsed*rate/1000), leaked = max(0, raw -
     * leak), value = floor(leaked*1000/sat). The Lua computes its elapsed
     * from Redis time inside the script, which always falls inside the
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
        // AuthenticationSuccess (10) against a present principal: +1500 raw
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

        // SolveSuccess (3) against a present session on a fresh store:
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
        // epoch 12345's bucket, the second (at epoch 12346) writes the next
        // epoch and reads 12345 as its prev bucket. v3 SUMs the rotated
        // pseudonyms of one identity (2000 raw rf), so the second
        // observation sees ~250 sourceFast — under a max it would be 125.
        // The first bucket has decayed by the real elapsed time between the
        // two script executions (Redis time), so the expectation is derived
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
        // One PreIssue increments both the source and the session velocity.
        // They are different identity dimensions observing the same request,
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

        // Duplicate: state NOT applied again, but the current (real-time
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

        // A distinct event observes the state from a single increment
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

    public function testSourceRateLimitHitIsSourceSessionOnly(): void
    {
        // Event 15 (SourceRateLimitHit) must add bad pressure to
        // source/session only — never subnet, global, or principal state
        // (a per-source limit is not deployment overload and must not
        // raise the global attack level for all visitors).
        $store = $this->store();

        $feedback = $store->observe($this->observation(
            str_repeat('1', 64),
            event: RiskEventKind::SourceRateLimitHit,
            sessionId: str_repeat('f', 32),
        ));
        // src.bad + 3000 (sat 4000) and sess.bad + 3000 surface as bad_proof.
        self::assertSame(750, $feedback->badProof, 'source/session bad pressure must surface');
        // Feedback is NOT velocity: no rf/rs anywhere.
        self::assertSame(0, $feedback->sourceFast);
        self::assertSame(0, $feedback->sourceSlow);
        self::assertSame(0, $feedback->subnetFast);
        // Global state must be untouched: no bad, no level.
        self::assertSame(0, $feedback->globalPressure);
        self::assertSame(0, $store->lastGlobalLevel());

        // Control: a PreIssue does raise global pressure.
        $preissue = $store->observe($this->observation(str_repeat('2', 64), event: RiskEventKind::PreIssue));
        self::assertGreaterThan(0, $preissue->globalPressure);
    }

    /**
     * The ChallengeCancelled risk-neutrality contract: a cancellation
     * applies no state change, so the issued-and-abandoned challenge
     * keeps its issue-debt contribution. The raw iss channel moves only
     * by the natural leak (40 raw/s) inside the real elapsed bracket,
     * never by a −1000 refund (a debt-restoring arm would have clamped
     * it to 0). The raw channel is read from the Lua state hash itself,
     * exactly like the parity assertions.
     */
    public function testCancellationIsRiskNeutral(): void
    {
        $store = $this->store();
        $source = str_repeat('b', 32);
        $ns = $store->namespace();
        $stateKey = "{kiwi:{$ns}}:risk:src:12345:{$source}";
        $rawIss = fn (): int => (int) $this->client->hget($stateKey, 'iss');

        $t0 = $this->redisNowMs();
        $store->observe($this->observationWithSource($source, str_repeat('1', 32), RiskEventKind::ChallengeIssued));
        $t1 = $this->redisNowMs();
        self::assertSame(1000, $rawIss(), 'the issuance leaves exactly one unit of issue debt');

        $t2 = $this->redisNowMs();
        $cancelled = $store->observe($this->observationWithSource($source, str_repeat('2', 32), RiskEventKind::ChallengeCancelled));
        $t3 = $this->redisNowMs();
        $leak = static fn (int $elapsedMs): int => max(0, 1000 - intdiv($elapsedMs * 40, 1000));
        self::assertGreaterThanOrEqual($leak($t3 - $t0), $rawIss(), 'the cancellation must not subtract the issue debt');
        self::assertLessThanOrEqual($leak(max(0, $t2 - $t1)), $rawIss(), 'the debt can only decay with real time, never be refunded');
        self::assertGreaterThan(0, $rawIss(), 'the issued-and-abandoned challenge keeps its issue-debt contribution');
        self::assertSame(intdiv($rawIss() * 1000, 6000), $cancelled->issueDebt, 'the returned vector mirrors the unchanged raw channel');
        self::assertSame(0, $cancelled->sourceFast, 'feedback events are never velocity');
    }

    /**
     * Adversarial shape: the cancellation is attributed to a different
     * source identity (B) than the one that issued the challenge (A).
     * Neither identity's debt changes: A's raw iss is exactly its
     * post-issue value (B's observation never touches A's state hash) and
     * B's stays zero.
     */
    public function testCancellationFromAnotherSourceIsRiskNeutralForBothIdentities(): void
    {
        $store = $this->store();
        $ns = $store->namespace();
        $sourceA = str_repeat('b', 32);
        $sourceB = str_repeat('c', 32);
        $rawIss = fn (string $source): int => (int) $this->client->hget("{kiwi:{$ns}}:risk:src:12345:{$source}", 'iss');

        $store->observe($this->observationWithSource($sourceA, str_repeat('1', 32), RiskEventKind::ChallengeIssued));
        self::assertSame(1000, $rawIss($sourceA), 'source A holds the issued debt');
        self::assertSame(0, $rawIss($sourceB), 'source B has no debt');

        $store->observe($this->observationWithSource($sourceB, str_repeat('2', 32), RiskEventKind::ChallengeCancelled));
        self::assertSame(1000, $rawIss($sourceA), "a cancellation from B never touches A's issue debt (exact — A's hash is untouched)");
        self::assertSame(0, $rawIss($sourceB), "B's debt is unchanged");
    }

    /**
     * Repeated cancellations move the raw issue-debt channel only by the
     * natural leak inside the real elapsed bracket — never by repeated
     * −1000 steps, so a client cannot erase its issued-but-unsolved
     * signal by cancelling.
     */
    public function testRepeatedCancellationsNeverRefundTheDebt(): void
    {
        $store = $this->store();
        $source = str_repeat('b', 32);
        $ns = $store->namespace();
        $stateKey = "{kiwi:{$ns}}:risk:src:12345:{$source}";
        $rawIss = fn (): int => (int) $this->client->hget($stateKey, 'iss');

        $store->observe($this->observationWithSource($source, str_repeat('1', 32), RiskEventKind::ChallengeIssued));
        self::assertSame(1000, $rawIss());
        $t2 = $this->redisNowMs();
        for ($i = 2; $i <= 6; $i++) {
            $store->observe($this->observationWithSource($source, str_pad((string) $i, 32, '0', STR_PAD_LEFT), RiskEventKind::ChallengeCancelled));
        }
        $t3 = $this->redisNowMs();
        $leak = static fn (int $elapsedMs): int => max(0, 1000 - intdiv($elapsedMs * 40, 1000));
        self::assertGreaterThanOrEqual($leak($t3 - $t2), $rawIss(), 'five cancellations move the debt by at most natural decay');
        self::assertLessThanOrEqual(1000, $rawIss());
        self::assertGreaterThan(0, $rawIss(), 'repeated cancellations never erase the issued-and-abandoned signal');
    }

    /**
     * A real SolveSuccess still repays the debt (the existing behavior is
     * untouched): the raw iss clamps at zero after the solve, whatever the
     * real elapsed window was.
     */
    public function testSolveStillRepaysTheIssueDebt(): void
    {
        $store = $this->store();
        $source = str_repeat('b', 32);
        $ns = $store->namespace();
        $stateKey = "{kiwi:{$ns}}:risk:src:12345:{$source}";
        $rawIss = fn (): int => (int) $this->client->hget($stateKey, 'iss');

        $store->observe($this->observationWithSource($source, str_repeat('1', 32), RiskEventKind::ChallengeIssued));
        self::assertSame(1000, $rawIss());
        $store->observe($this->observationWithSource($source, str_repeat('2', 32), RiskEventKind::SolveSuccess));
        self::assertSame(0, $rawIss(), 'a real SolveSuccess still repays the debt (clamped at zero)');
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

        // The cooldown is armed by the level ratchet: Redis time at the last
        // rise + the hysteresis window (never the injected now_ms).
        self::assertGreaterThanOrEqual($tBeforeStorm + 60_000, $big->lastCooldownUntilMs());
        self::assertLessThanOrEqual($tAfterStorm + 60_000, $big->lastCooldownUntilMs());

        // Inside the window the level holds (the target is still 4 at this
        // pressure) and the cooldown deadline is untouched (no new rise).
        $big->observe($this->observation(str_repeat('9', 32), 2));
        self::assertSame(4, $big->lastGlobalLevel(), 'level holds while the pressure target is still 4');
        self::assertLessThanOrEqual($tAfterStorm + 60_000, $big->lastCooldownUntilMs());

        // Drop test (short hysteresis + real sleep): with a 2000 ms window,
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

    /**
     * The always-on outcome ledger (calibration-independent): register ->
     * confirm exactly once -> correct flips the ledger. This is the
     * authority behind ConfirmedLegitimate/ConfirmedAbuse when
     * calibration is disabled.
     */
    public function testOutcomeLedgerRegisterConfirmCorrect(): void
    {
        $store = $this->store();
        $ns = $store->namespace();
        $hour = intdiv((int) floor(microtime(true) * 1000), 3_600_000);
        $ledgerKey = "{kiwi:{$ns}}:outcome:dec-1";

        // Register: the pending entry carries scope/hour/score.
        self::assertTrue($store->registerOutcome('dec-1', 7, $hour, 500));
        $ledger = json_decode((string) $this->client->get($ledgerKey), true);
        self::assertSame('P', $ledger['o']);
        self::assertSame(7, $ledger['scope']);
        self::assertSame($hour, $ledger['hour']);
        self::assertSame(500, $ledger['score']);
        self::assertSame(1, $ledger['w']);

        // Duplicate registration is refused (SET NX).
        self::assertFalse($store->registerOutcome('dec-1', 7, $hour, 500), 'a duplicate registration must be refused');

        // First confirmation flips P -> A exactly once.
        self::assertSame(1, $store->confirmOutcome('dec-1', false), 'the first confirmation is the accepted-outcome status 1');
        self::assertSame(0, $store->confirmOutcome('dec-1', false), 'a retried confirmation is status 0 (ledger already confirmed)');
        self::assertSame('A', json_decode((string) $this->client->get($ledgerKey), true)['o'], 'the ledger records the abuse outcome exactly once');

        // Correction flips A -> L (authoritative for future events).
        self::assertTrue($store->correctOutcome('dec-1', true));
        self::assertSame('L', json_decode((string) $this->client->get($ledgerKey), true)['o']);
        self::assertFalse($store->correctOutcome('dec-1', true), 'correcting to the CURRENT outcome is a no-op');
        self::assertTrue($store->correctOutcome('dec-1', false), 'flipping back applies');
        self::assertSame('A', json_decode((string) $this->client->get($ledgerKey), true)['o']);

        // Unknown decisions: confirm 0, correct false.
        self::assertSame(0, $store->confirmOutcome('dec-missing', true));
        self::assertFalse($store->correctOutcome('dec-missing', true));
    }

    public function testOutcomeLedgerHonorsOutcomeTtl(): void
    {
        $store = new RedisRiskStateStore($this->client, namespace: 'ledger-ttl' . bin2hex(random_bytes(4)), outcomeTtlSecs: 3600);
        self::assertTrue($store->registerOutcome('ttl-dec', 1, intdiv((int) floor(microtime(true) * 1000), 3_600_000), 100));
        $ttl = (int) $this->client->ttl($store->ledgerKey('ttl-dec'));
        self::assertGreaterThan(0, $ttl);
        self::assertLessThanOrEqual(3600, $ttl, 'the outcome ledger TTL comes from the constructor knob');

        // The default is the outcome TTL constant (86400).
        $default = $this->store();
        self::assertTrue($default->registerOutcome('ttl-dec-2', 1, intdiv((int) floor(microtime(true) * 1000), 3_600_000), 100));
        $ttl = (int) $this->client->ttl($default->ledgerKey('ttl-dec-2'));
        self::assertGreaterThan(0, $ttl);
        self::assertLessThanOrEqual(RedisRiskStateStore::DEFAULT_OUTCOME_TTL_SECS, $ttl);
    }

    /** An observation with a caller-chosen source pseudonym (fixed subnet pseudonym). */
    private function observationWithSource(string $sourceId, string $eventId, RiskEventKind $event = RiskEventKind::PreIssue, int $scope = 0): RiskObservation
    {
        return new RiskObservation(
            event: $event,
            scope: $scope,
            sourceEpoch: 12345,
            sourceIdPrev: str_repeat('a', 32), // never written: stays zero
            sourceId: $sourceId,
            sourceIdNext: str_repeat('c', 32), // never written: stays zero
            subnetEpoch: 12345,
            subnetIdPrev: str_repeat('d', 32),
            subnetId: str_repeat('e', 32), // the shared /64-style network aggregate
            subnetIdNext: str_repeat('f', 32),
            sessionId: null,
            principalId: null,
            eventId: $eventId,
            networkRisk: 0,
            nowMs: self::T0,
        );
    }

    /**
     * Poisoned-source absolute cap: hundreds of invalid proofs (plus
     * request velocity and replay pressure) saturate the channels; the
     * score clamps at 1000 and the policy action reaches Deny but never
     * exceeds either, so there is no unbounded punishment mode.
     */
    public function testPoisonedSourceReachesTheCapButNeverExceedsIt(): void
    {
        $store = $this->store();
        $scorer = new \KiwiCaptcha\Risk\RiskScorer();
        $weights = new \KiwiCaptcha\Risk\RiskWeights();
        $policy = \KiwiCaptcha\Risk\RiskPolicy::fromConfig([
            'version' => 3,
            'weights' => $weights->toArray(),
            'scopes' => [1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20']],
            'global_floors' => [1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
        ]);

        $source = str_repeat('b', 32);
        $maxScore = 0;
        $i = 0;
        // 100 request velocity + 300 invalid proofs + 200 replay attempts:
        // rf/rs/bad/rep/global all saturate -> the score MUST clamp at 1000.
        for ($r = 0; $r < 100; $r++) {
            $vector = $store->observe($this->observationWithSource($source, sprintf('%032x', $i++)));
            $maxScore = max($maxScore, $scorer->score(100, $vector, $weights));
        }
        for ($p = 0; $p < 300; $p++) {
            $vector = $store->observe($this->observationWithSource($source, sprintf('%032x', $i++), RiskEventKind::InvalidProof));
            $maxScore = max($maxScore, $scorer->score(100, $vector, $weights));
        }
        for ($r = 0; $r < 200; $r++) {
            $vector = $store->observe($this->observationWithSource($source, sprintf('%032x', $i++), RiskEventKind::ReplayAttempt));
            $maxScore = max($maxScore, $scorer->score(100, $vector, $weights));
        }
        self::assertLessThanOrEqual(1000, $maxScore, 'the score must never exceed the 0..1000 cap while poisoning');

        $final = $store->observe($this->observationWithSource($source, sprintf('%032x', $i++)));
        $score = $scorer->score(100, $final, $weights);
        self::assertSame(1000, $score, 'a fully poisoned source must reach the cap exactly');
        $decision = $policy->decide(1, $score, $final, new \KiwiCaptcha\Risk\ResourcePressure(1000, 1000), 0, self::T0);
        self::assertSame(RiskAction::Deny, $decision->action, 'the cap action is the ladder top (Deny)');
        self::assertSame(RiskAction::Deny->rank(), $decision->action->rank(), 'the ladder top is the absolute maximum action');
        foreach ($final->toArray() as $field => $value) {
            self::assertLessThanOrEqual(1000, $value, "signal $field must stay bounded at 1000");
        }
    }

    /**
     * /64-style network aggregate weak per-signal effect: many bad proofs
     * across many IPs in one network saturate the shared network channel,
     * but the network signal stays bounded at 1000 and the exact-IP
     * signals of a single attacker dominate its score.
     */
    public function testNetworkAggregateRisesBoundedWhileExactIpDominates(): void
    {
        $store = $this->store();
        $scorer = new \KiwiCaptcha\Risk\RiskScorer();
        $weights = new \KiwiCaptcha\Risk\RiskWeights();

        // 200 distinct sources (IPs) in one network: each sends one request
        // with one invalid proof into the shared subnet pseudonym.
        $i = 0;
        for ($ip = 1; $ip <= 200; $ip++) {
            $source = sprintf('%032x', $ip);
            $store->observe($this->observationWithSource($source, sprintf('%032x', $i++)));
            $store->observe($this->observationWithSource($source, sprintf('%032x', $i++), RiskEventKind::InvalidProof));
        }

        // One attacker's exact-IP signals: 1 request + 1 bad proof.
        $attacker = $store->observe($this->observationWithSource(sprintf('%032x', 1), sprintf('%032x', $i++)));
        $subnet = $attacker->subnetFast; // shared network velocity, 200 requests
        self::assertSame(1000, $subnet, 'the network aggregate saturates at 1000');
        self::assertLessThanOrEqual(1000, $subnet, 'the network signal must stay bounded at 1000');
        self::assertGreaterThan(0, $subnet, 'many bad proofs across the network DO raise the shared signal');

        $exactIp = $scorer->score(0, SignalVector::fromArray([
            'source_fast' => $attacker->sourceFast,
            'source_slow' => $attacker->sourceSlow,
            'bad_proof' => $attacker->badProof,
        ]), $weights);
        $networkOnly = $scorer->score(0, SignalVector::fromArray(['subnet_fast' => $subnet]), $weights);
        self::assertGreaterThan(
            $networkOnly,
            $exactIp,
            sprintf(
                'the exact-IP signals (%d) must dominate the network aggregate signal (%d) even at network saturation',
                $exactIp,
                $networkOnly
            )
        );
        self::assertLessThanOrEqual(
            1000,
            $exactIp + $networkOnly,
            'even combined the attacker\'s score is bounded'
        );
    }

    /**
     * The risk-v2 session client-context record: SET NX first-write-wins
     * with the session TTL. The first tag a session presents is recorded
     * and returned forever; a later different tag still yields the first
     * one, from which the engine derives the inconsistency signal.
     */
    public function testSessionFirstContextTagRecordsTheFirstTagWithTheSessionTtl(): void
    {
        $store = $this->store();
        $sessionId = str_repeat('5a', 16);

        // First tag-bearing request: the tag is recorded and returned.
        self::assertSame('aa', $store->sessionFirstContextTag($sessionId, 'aa'));

        // Same tag again: the recorded first tag is returned unchanged.
        self::assertSame('aa', $store->sessionFirstContextTag($sessionId, 'aa'));

        // A different tag: the first tag wins (the inconsistency signal
        // derives from this comparison).
        self::assertSame('aa', $store->sessionFirstContextTag($sessionId, 'bb'), 'the first-seen tag must win');

        // The record carries the session TTL (1800 s), like the risk-v1
        // session state hash.
        $key = "{kiwi:{$store->namespace()}}:risk:ctx:{$sessionId}";
        $ttl = (int) $this->client->ttl($key);
        self::assertGreaterThan(0, $ttl, 'the record must expire with the session TTL');
        self::assertLessThanOrEqual(1800, $ttl);

        // A different session has its own record.
        self::assertSame('zz', $store->sessionFirstContextTag(str_repeat('2b', 16), 'zz'));
    }

    /**
     * The consolidated assessment: one atomic script call runs the v1
     * observation, records the first-seen client-context + TLS tags and
     * registers the decision's pending outcome-ledger entry. The ledger
     * mirrors registerOutcome() byte-for-byte (the score is computed
     * inside the script from the exact base risk and weights the engine
     * scores with).
     */
    public function testAssessV2RegistersLedgerTagsAndReturnsStatus(): void
    {
        $store = $this->store();
        $sessionId = str_repeat('9c', 16);
        $obs = $this->observation(str_repeat('5', 32), 1, self::T0, 600, RiskEventKind::PreIssue, $sessionId);
        $weights = new \KiwiCaptcha\Risk\RiskWeights();
        $v2Weights = new \KiwiCaptcha\Risk\RiskV2Weights();
        $registration = new \KiwiCaptcha\Risk\Storage\OutcomeRegistration(
            decisionId: 'dec-cons-1',
            decisionHour: 472222,
            baseRisk: 100,
            globalPressureEnabled: true,
            honeypotHit: false,
            weights: $weights,
            v2Weights: $v2Weights,
        );

        [$vector, $ctx, $tls, $registered] = $store->assessV2($obs, 'aa', 'tls13|http2', $registration);
        self::assertTrue($registered, 'the pending ledger entry must be created on the first registration');
        self::assertSame('aa', $ctx);
        self::assertSame('tls13|http2', $tls);
        self::assertSame(125, $vector->sourceFast, 'the v1 observation must run identically');

        // The ledger is byte-for-byte the registerOutcome() entry: the
        // script computes the exact decision score from the signals,
        // weights and base risk (100 + weighted 125,190 + weighted
        // 10,110 + weighted 125,80 + weighted 28,170 + weighted
        // 600,100 = 198).
        $ledger = json_decode((string) $this->client->get($store->ledgerKey('dec-cons-1')), true);
        self::assertSame('P', $ledger['o']);
        self::assertSame(1, $ledger['scope']);
        self::assertSame(472222, $ledger['hour']);
        self::assertSame(198, $ledger['score']);
        self::assertSame(1, $ledger['w']);

        // A retried decision_id is refused (SET NX).
        [$vector2, $ctx2, $tls2, $registered2] = $store->assessV2($obs, 'aa', 'tls13|http2', $registration);
        self::assertFalse($registered2, 'a duplicate decision_id must not overwrite the ledger');
        self::assertSame('aa', $ctx2, 'the first-seen tag wins on repeat assessments');
        self::assertSame('tls13|http2', $tls2);

        // Changed tags on an established session return the first tags.
        [$vector3, $ctx3, $tls3, $registered3] = $store->assessV2(
            $this->observation(str_repeat('6', 32), 1, self::T0, 600, RiskEventKind::PreIssue, $sessionId),
            'bb',
            'tls12|http1',
            new \KiwiCaptcha\Risk\Storage\OutcomeRegistration('dec-cons-2', 472222, 100, true, false, $weights, $v2Weights),
        );
        self::assertSame('aa', $ctx3, "the session's first context tag is the comparison baseline");
        self::assertSame('tls13|http2', $tls3, "the session's first TLS tag is the comparison baseline");
        self::assertTrue($registered3);

        // The tag records carry the session TTL, exactly like the
        // individual session_first_* record surfaces.
        $ctxKey = "{kiwi:{$store->namespace()}}:risk:ctx:{$sessionId}";
        $tlsKey = "{kiwi:{$store->namespace()}}:risk:tls:{$sessionId}";
        self::assertGreaterThan(0, (int) $this->client->ttl($ctxKey));
        self::assertLessThanOrEqual(1800, (int) $this->client->ttl($ctxKey));
        self::assertGreaterThan(0, (int) $this->client->ttl($tlsKey));
        self::assertLessThanOrEqual(1800, (int) $this->client->ttl($tlsKey));
    }

    /** The consolidated script's registration is skipped when no registration is passed. */
    public function testAssessV2WithoutRegistrationSkipsTheLedger(): void
    {
        $store = $this->store();
        $sessionId = str_repeat('2f', 16);
        [$vector, $ctx, $tls, $registered] = $store->assessV2(
            $this->observation(str_repeat('7', 32), 1, self::T0, 0, RiskEventKind::PreIssue, $sessionId),
            'aa',
            'tls13|http2',
            null,
        );
        self::assertFalse($registered, 'without a registration payload no ledger entry is created');
        self::assertSame('aa', $ctx, 'the tag records still apply');
        self::assertSame(125, $vector->sourceFast);
        self::assertNull($this->client->get($store->ledgerKey('dec-missing')));
    }

    /**
     * The established-session assessment issues exactly one script call:
     * the engine's full calibration-less assessment path (observation +
     * first-seen tags + outcome registration) runs as a single evalsha
     * once the script is loaded.
     */
    public function testEstablishedSessionAssessmentIssuesExactlyOneScriptCall(): void
    {
        $client = new CommandCountingClient(getenv('RISK_REDIS_URL'));
        $store = new RedisRiskStateStore($client, namespace: 'count' . bin2hex(random_bytes(4)));
        $engine = $this->engine($store);
        $session = str_repeat('4a', 16);
        $context = $this->context(RiskEventKind::PreIssue, $session);

        // Prime: the first assessment loads the script (script load +
        // evalsha) and establishes the session tag records.
        $first = $engine->assessPreIssueV2($context, $this->v2(tag: 'aa', tlsTag: 'tls13|http2'));

        // Established session: the whole assessment is ONE script call.
        $before = $client->commands;
        $second = $engine->assessPreIssueV2($context, $this->v2(tag: 'aa', tlsTag: 'tls13|http2'));
        self::assertSame($before + 1, $client->commands, 'the established-session assessment must issue exactly ONE script call');

        // And the decision's pending ledger entry exists with the exact
        // decision score (the registration ran inside that one call).
        $ns = $store->namespace();
        $ledger = json_decode((string) $client->get("{kiwi:{$ns}}:outcome:{$second->decisionId}"), true);
        self::assertSame('P', $ledger['o']);
        self::assertSame($second->score, $ledger['score'], 'the consolidated ledger score must be the exact decision score');
        self::assertNotSame($first->decisionId, $second->decisionId, 'each assessment registers its own decision');
    }

    private function engine(RiskStateStoreInterface $store): \KiwiCaptcha\Risk\AdaptiveRiskEngine
    {
        $keys = \KiwiCaptcha\Risk\RiskKeys::fromMaster(str_repeat(chr(0x42), 32));
        $classifier = new \KiwiCaptcha\Risk\Network\CidrNetworkClassifier([
            ['cidr' => '203.0.113.0/24', 'flags' => ['hosting']],
        ]);
        return new \KiwiCaptcha\Risk\AdaptiveRiskEngine(
            store: $store,
            classifier: $classifier,
            identityFactory: new \KiwiCaptcha\Risk\RiskIdentityFactory($keys),
            scorer: new \KiwiCaptcha\Risk\RiskScorer(),
            policy: \KiwiCaptcha\Risk\RiskPolicy::fromConfig([
                'version' => 3,
                'weights' => (new \KiwiCaptcha\Risk\RiskWeights())->toArray(),
                'scopes' => [1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'sha20']],
                'global_floors' => [1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            ]),
            keys: $keys,
            breaker: new \KiwiCaptcha\Risk\Breaker\CircuitBreaker(),
        );
    }

    private function context(RiskEventKind $event, ?string $sessionId = null): \KiwiCaptcha\Risk\RiskContext
    {
        return new \KiwiCaptcha\Risk\RiskContext(
            scope: 1,
            sourceIp: '203.0.113.27',
            sessionId: $sessionId,
            principalId: null,
            event: $event,
            networkFlags: (new \KiwiCaptcha\Risk\Network\CidrNetworkClassifier([['cidr' => '203.0.113.0/24', 'flags' => ['hosting']]]))->classify('203.0.113.27'),
            resources: new \KiwiCaptcha\Risk\ResourcePressure(1000, 1000),
        );
    }

    private function v2(bool $honeypotHit = false, ?string $tag = null, ?string $tlsTag = null): \KiwiCaptcha\Risk\RiskV2Context
    {
        return new \KiwiCaptcha\Risk\RiskV2Context(honeypotHit: $honeypotHit, clientContextTag: $tag, tlsTag: $tlsTag);
    }
}

/** Predis client that counts every command executed (one round trip each). */
final class CommandCountingClient extends Client
{
    public int $commands = 0;

    public function executeCommand(CommandInterface $command)
    {
        $this->commands++;
        return parent::executeCommand($command);
    }
}
