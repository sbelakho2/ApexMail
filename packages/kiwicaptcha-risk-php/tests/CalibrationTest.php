<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Calibration\AggregateCalibrator;
use KiwiCaptcha\Risk\Calibration\CalibrationRecorder;
use KiwiCaptcha\Risk\Calibration\CalibrationStore;
use KiwiCaptcha\Risk\RiskAction;
use Predis\Client;
use Predis\Command\CommandInterface;
use PHPUnit\Framework\TestCase;

/**
 * Redis-backed calibration tests (TRUE-score semantics of the canonical
 * calibration.lua: fn_pressure = Σ abuse×(1000−band×100), fp_pressure =
 * Σ legit×(band×100), raw = (fn−fp)×2/(total×10), proportional rate
 * limiter over milli-points). AggregateCalibrator cases are skipped unless
 * RISK_REDIS_URL is set; the recorder interface test runs always.
 */
final class CalibrationTest extends TestCase
{
    private ?Client $client = null;

    protected function setUp(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if (is_string($url) && $url !== '') {
            $this->client = AggregateCalibrator::createClient($url);
        }
    }

    private function calibrator(): AggregateCalibrator
    {
        if ($this->client === null) {
            self::markTestSkipped('RISK_REDIS_URL not set; start redis with: docker run -d -p 6399:6379 redis:7-alpine');
        }
        return new AggregateCalibrator($this->client, namespace: 'cal' . bin2hex(random_bytes(4)));
    }

    private function record(AggregateCalibrator $c, int $n, bool $legit, int $band = 5, RiskAction $action = RiskAction::Sha20, int $scope = 1): void
    {
        for ($i = 0; $i < $n; $i++) {
            $c->record($scope, $band, $action, $legit);
        }
    }

    private function nowMs(): int
    {
        return (int) floor(microtime(true) * 1000);
    }

    /**
     * A fixed synthetic timestamp inside the CURRENT hour (buckets are
     * hourly), so biasForScope calls advanced by up to ~59 minutes never
     * shift the bucket window away from the recorded hour.
     */
    private function t0(): int
    {
        return intdiv($this->nowMs(), 3_600_000) * 3_600_000 + 5_000;
    }

    private function requireClient(): Client
    {
        if ($this->client === null) {
            self::markTestSkipped('RISK_REDIS_URL not set; start redis with: docker run -d -p 6399:6379 redis:7-alpine');
        }
        return $this->client;
    }

    /** Drops the in-process 30 s bias cache so the next call hits Redis. */
    private function clearCache(AggregateCalibrator $c): void
    {
        $prop = new \ReflectionProperty(AggregateCalibrator::class, 'biasCache');
        $prop->setValue($c, []);
    }

    public function testEmptyScopeHasZeroBias(): void
    {
        $c = $this->calibrator();
        self::assertSame(0, $c->biasForScope(1, $this->nowMs()));
    }

    public function testPerfectSeparatorStaysNearZero(): void
    {
        // A perfectly separating classifier (legit @ band 0, abuse @
        // band 10) contributes ~zero calibration pressure: fn_pressure =
        // 1000×(1000−1000) = 0, fp_pressure = 1000×0 = 0 -> raw 0.
        $c = $this->calibrator();
        $this->record($c, 1000, true, 0);
        $this->record($c, 1000, false, 10);
        $t = $this->t0();
        self::assertSame(0, $c->biasForScope(1, $t), 'first call ever seeds the rate-limit state and returns 0');
        $this->clearCache($c);
        self::assertSame(0, $c->biasForScope(1, $t + 900_000), 'perfect separation must keep the bias at 0 even with full movement allowance');
    }

    public function testAbuseAtLowBandPushesBiasUpAndIsBounded(): void
    {
        // 1000 abuse @ band 1: fn_pressure = 1000×900 = 900000,
        // raw = 900000×2/10000 = 180 -> clamped to maxAdjustment +150.
        $c = $this->calibrator();
        $this->record($c, 1000, false, 1);
        $t = $this->t0();
        // The first call ever seeds the rate-limit state (bias_mp = 0 /
        // ts = now) BEFORE the threshold check and returns 0 — a fresh
        // scope can never jump straight to ±maxAdjustment.
        self::assertSame(0, $c->biasForScope(1, $t));
        // Reaching +150 takes 15 minutes at maxChangePerMinute 10
        // (10 points/minute * 15).
        $this->clearCache($c);
        self::assertSame(150, $c->biasForScope(1, $t + 900_000));
    }

    public function testLegitAtHighBandPushesBiasDownAndIsBounded(): void
    {
        // 1000 legit @ band 9: fp_pressure = 1000×900 = 900000,
        // raw = −900000×2/10000 = −180 -> clamped to −maxAdjustment.
        $c = $this->calibrator();
        $this->record($c, 1000, true, 9);
        $t = $this->t0();
        self::assertSame(0, $c->biasForScope(1, $t));
        $this->clearCache($c);
        self::assertSame(-150, $c->biasForScope(1, $t + 900_000));
    }

    public function testBalancedSameBandBiasIsZero(): void
    {
        // Balanced at the same band: fn = fp = 500×500 = 250000 -> raw 0.
        $c = $this->calibrator();
        $this->record($c, 500, true);
        $this->record($c, 500, false);
        $t = $this->t0();
        self::assertSame(0, $c->biasForScope(1, $t));
        $this->clearCache($c);
        self::assertSame(0, $c->biasForScope(1, $t + 900_000));
    }

    public function testMixedBiasScoreSensitive(): void
    {
        // 750 abuse + 250 legit @ band 5: fn = 375000, fp = 125000,
        // raw = 250000×2/10000 = 50, reachable after 5 minutes at
        // maxChangePerMinute 10.
        $c = $this->calibrator();
        $this->record($c, 750, false);
        $this->record($c, 250, true);
        $t = $this->t0();
        self::assertSame(0, $c->biasForScope(1, $t));
        $this->clearCache($c);
        self::assertSame(50, $c->biasForScope(1, $t + 300_000));

        // 550 abuse + 450 legit @ band 5: fn = 275000, fp = 225000,
        // raw = 50000×2/10000 = 10 (1 min).
        $c = $this->calibrator();
        $this->record($c, 550, false);
        $this->record($c, 450, true);
        $t = $this->t0();
        self::assertSame(0, $c->biasForScope(1, $t));
        $this->clearCache($c);
        self::assertSame(10, $c->biasForScope(1, $t + 60_000));
    }

    public function testScopesAreIndependent(): void
    {
        $c = $this->calibrator();
        $this->record($c, 1000, false, 1, RiskAction::Sha20, 1);
        $this->record($c, 1000, true, 9, RiskAction::Sha20, 2);
        $t = $this->t0();
        self::assertSame(0, $c->biasForScope(1, $t));
        self::assertSame(0, $c->biasForScope(2, $t));
        $this->clearCache($c);
        self::assertSame(150, $c->biasForScope(1, $t + 900_000));
        $this->clearCache($c);
        self::assertSame(-150, $c->biasForScope(2, $t + 900_000));
    }

    public function testBucketsAreBoundedByWindowAndTtl(): void
    {
        $c = $this->calibrator();
        $ns = $c->namespace();
        $this->record($c, 1000, false);

        // Buckets are hourly hashes with a 48 h TTL and at most 24 keys in
        // the bias window; an ancient bucket does not contribute.
        $nowMs = $this->nowMs();
        $hour = intdiv($nowMs, 3_600_000);
        self::assertSame('1000', (string) $this->client->hget("{kiwi:{$ns}}:cal:1:{$hour}", 'b5asha20:abuse'));
        self::assertNull($this->client->hget("{kiwi:{$ns}}:cal:1:" . ($hour - 25), 'b5asha20:abuse'));

        // 1000 abuse in-window @ band 5 -> raw 100 (fn = 500000 →
        // 1000000/10000), reached after the proportional ramp; the
        // 25-hours-old bucket is outside the 24-hour window and
        // contributes nothing.
        $t = $this->t0();
        self::assertSame(0, $c->biasForScope(1, $t));
        $this->clearCache($c);
        self::assertSame(100, $c->biasForScope(1, $t + 900_000));
    }

    public function testBelowMinSamplesIsZero(): void
    {
        $c = $this->calibrator();
        $this->record($c, 999, false, 1, RiskAction::Sha20, 1);
        $t = $this->t0();
        self::assertSame(0, $c->biasForScope(1, $t), 'no nonzero bias below minSamples');

        // At the threshold the bias appears, rate-limited from the seeded
        // 0 (fresh scope): 150 points need 15 minutes at
        // maxChangePerMinute 10.
        $this->record($c, 1000, false, 1, RiskAction::Sha20, 2);
        $this->clearCache($c);
        self::assertSame(0, $c->biasForScope(2, $t));
        $this->clearCache($c);
        self::assertSame(150, $c->biasForScope(2, $t + 900_000));
    }

    public function testBelowThresholdMovesTowardZeroAtAllowedRate(): void
    {
        // Below min_samples the TARGET is 0, but the stored bias moves
        // toward 0 THROUGH the proportional rate limiter — a sample count
        // that dips below the threshold can never snap +150 → 0 instantly.
        $c = $this->calibrator();
        $ns = $c->namespace();
        $this->record($c, 999, false, 1, RiskAction::Sha20, 3);
        $t = $this->t0();

        // Drive the stored bias to +150 (milli-points) and pin ts = t.
        $this->client->hset("{kiwi:{$ns}}:cal:state:3", 'bias_mp', 150000);
        $this->client->hset("{kiwi:{$ns}}:cal:state:3", 'ts', $t);

        // 5 s later the target is 0 but only ~mpm/12 points may move:
        // allowed = 10×1000×5000/60000 = 833 milli-points -> 149, never 0.
        $this->clearCache($c);
        self::assertSame(149, $c->biasForScope(3, $t + 5_000));

        // 1 minute later: allowed = 10 points -> 139.
        $this->clearCache($c);
        self::assertSame(139, $c->biasForScope(3, $t + 65_000));

        // Crossing the threshold again (1000 samples): the target jumps to
        // +150, but the movement allowance counts from the LAST call's ts
        // (refreshed on every call, below threshold too) — only ~0.17
        // points are allowed, so the bias stays put, never an instant 150.
        $this->record($c, 1, false, 1, RiskAction::Sha20, 3);
        $this->clearCache($c);
        self::assertSame(139, $c->biasForScope(3, $t + 66_000));
    }

    public function testConstructorKnobs(): void
    {
        $c = new AggregateCalibrator(
            $this->requireClient(),
            namespace: 'knob' . bin2hex(random_bytes(4)),
            minSamples: 10,
            maxAdjustment: 25,
            maxChangePerMinute: 5,
        );
        $this->record($c, 9, false, 1, RiskAction::Sha20, 1);
        $t = $this->t0();
        self::assertSame(0, $c->biasForScope(1, $t));
        $this->record($c, 10, false, 1, RiskAction::Sha20, 2);
        // raw 180 -> clamped to the custom maxAdjustment 25; the
        // proportional ramp allows 5 points per minute.
        $this->clearCache($c);
        self::assertSame(0, $c->biasForScope(2, $t));
        $this->clearCache($c);
        self::assertSame(5, $c->biasForScope(2, $t + 60_000));
        $this->clearCache($c);
        self::assertSame(25, $c->biasForScope(2, $t + 300_000));

        $this->expectException(\InvalidArgumentException::class);
        new AggregateCalibrator($this->requireClient(), namespace: 'bad' . bin2hex(random_bytes(4)), minSamples: 0);
    }

    public function testRateOfChangeClampIsProportional(): void
    {
        // maxChangePerMinute 120 points/min: the movement allowance is
        // proportional to the elapsed time
        // (maxChangePerMinute * 1000 * elapsedMs / 60000, milli-points).
        $c = new AggregateCalibrator(
            $this->requireClient(),
            namespace: 'roc' . bin2hex(random_bytes(4)),
            minSamples: 10,
            maxAdjustment: 150,
            maxChangePerMinute: 120,
        );
        $this->record($c, 1000, false, 1, RiskAction::Sha20, 3);
        $t = $this->t0();

        // First call ever seeds bias_mp = 0 / ts = now before the
        // threshold check: the initial bias is 0, never ±maxAdjustment.
        self::assertSame(0, $c->biasForScope(3, $t));

        // Two calls 5 s apart move at most ~mpm/12 points (120 / 12 = 10).
        $this->clearCache($c);
        self::assertSame(10, $c->biasForScope(3, $t + 5_000));

        // 1 minute later the allowance is the full 120 points/min; the
        // raw 150 clamps to the allowance.
        $this->clearCache($c);
        self::assertSame(120, $c->biasForScope(3, $t + 60_000));

        // 1.5 minutes: allowance 180 >= raw, so maxAdjustment wins.
        $this->clearCache($c);
        self::assertSame(150, $c->biasForScope(3, $t + 90_000));

        // The window is now balanced (1000 legit @ band 9 offsets the
        // abuse @ band 1: fn = fp = 900000): raw would be 0, but the bias
        // may only move DOWN by the proportional allowance (120 points
        // over the elapsed minute) — never jump straight to 0.
        $this->record($c, 1000, true, 9, RiskAction::Sha20, 3);
        $this->clearCache($c);
        self::assertSame(30, $c->biasForScope(3, $t + 150_000));
    }

    public function testAggregateIsOneRoundTripAndCached(): void
    {
        $client = $this->countingClient();        $c = new AggregateCalibrator($client, namespace: 'rt' . bin2hex(random_bytes(4)));
        $this->record($c, 1000, false);

        $before = $client->commands;
        self::assertSame(0, $c->biasForScope(1, $this->nowMs()), 'first call seeds the state');
        self::assertSame($before + 1, $client->commands, '24 buckets + rate clamp + state write must be ONE round trip');

        self::assertSame(0, $c->biasForScope(1, $this->nowMs()));
        self::assertSame($before + 1, $client->commands, 'cache hit must not touch Redis');
    }

    public function testRecordInvalidatesScopeCache(): void
    {
        $client = $this->countingClient();
        $c = new AggregateCalibrator($client, namespace: 'inv' . bin2hex(random_bytes(4)));
        $this->record($c, 1000, false);

        $before = $client->commands;
        self::assertSame(0, $c->biasForScope(1, $this->nowMs()));
        self::assertSame($before + 1, $client->commands);

        // A fresh outcome for the SAME scope invalidates its cached bias:
        // the next read must hit Redis again.
        $this->record($c, 1, false, 5, RiskAction::Sha20, 1);
        $c->biasForScope(1, $this->nowMs());
        self::assertSame($before + 4, $client->commands, 'record() must invalidate the recorded scope cache');

        // A fresh outcome for ANOTHER scope must not invalidate this one.
        $this->record($c, 1, false, 5, RiskAction::Sha20, 2);
        $c->biasForScope(1, $this->nowMs());
        self::assertSame($before + 6, $client->commands, 'a record for another scope must not invalidate this scope');
    }

    public function testReceiptTtlUsesConstructorParameter(): void
    {
        $c = new AggregateCalibrator(
            $this->requireClient(),
            namespace: 'ttl' . bin2hex(random_bytes(4)),
            receiptTtlSecs: 60,
        );
        $c->recordReceipt('receipt-ttl-1', 1, 5, RiskAction::Sha20);
        $ttl = (int) $this->client->ttl("{kiwi:{$c->namespace()}}:cal:receipt:receipt-ttl-1");
        self::assertGreaterThan(0, $ttl);
        self::assertLessThanOrEqual(60, $ttl);

        // The default is the RECEIPT_TTL_SECS constant (300).
        $d = $this->calibrator();
        $d->recordReceipt('receipt-ttl-2', 1, 5, RiskAction::Sha20);
        $ttl = (int) $this->client->ttl("{kiwi:{$d->namespace()}}:cal:receipt:receipt-ttl-2");
        self::assertGreaterThan(0, $ttl);
        self::assertLessThanOrEqual(AggregateCalibrator::RECEIPT_TTL_SECS, $ttl);
    }

    public function testZeroBiasIsCachedToo(): void
    {
        $client = $this->countingClient();
        $c = new AggregateCalibrator($client, namespace: 'zc' . bin2hex(random_bytes(4)));
        self::assertSame(0, $c->biasForScope(1, $this->nowMs()));
        $before = $client->commands;
        self::assertSame(0, $c->biasForScope(1, $this->nowMs()));
        self::assertSame($before, $client->commands, 'a cached 0 (below minSamples) must not touch Redis');
    }

    public function testCacheIsBounded(): void
    {
        $client = $this->countingClient();
        $c = new AggregateCalibrator($client, namespace: 'cap' . bin2hex(random_bytes(4)));
        for ($i = 1; $i <= 1024; $i++) {
            $c->biasForScope($i, $this->nowMs());
        }

        // Full: a NEW scope evicts the oldest (scope 1) before inserting.
        $before = $client->commands;
        $c->biasForScope(2049, $this->nowMs());
        self::assertSame($before + 1, $client->commands, 'new scope past the cap must run and evict the oldest');
        $c->biasForScope(1, $this->nowMs());
        self::assertSame($before + 2, $client->commands, 'the evicted oldest scope must miss the cache');
        $c->biasForScope(1024, $this->nowMs());
        self::assertSame($before + 2, $client->commands, 'recently cached scope must still hit');
    }

    public function testReceiptRoundTripAndSingleConsume(): void
    {
        $c = $this->calibrator();
        $c->recordReceipt('deadbeef', 7, 4, RiskAction::Argon16);

        $receipt = $c->consumeReceipt('deadbeef');
        self::assertSame(['scope' => 7, 'band' => 4, 'action' => 'argon16'], $receipt);

        // GETDEL semantics: the second consume finds nothing.
        self::assertNull($c->consumeReceipt('deadbeef'));
    }

    public function testCalibrationRecorderMapsScoreToBand(): void
    {
        $captured = [];
        $store = new class($captured) implements CalibrationStore {
            public function __construct(private array &$captured)
            {
            }

            public function record(int $scope, int $band, RiskAction $action, bool $legitimate): void
            {
                $this->captured[] = [$scope, $band, $action, $legitimate];
            }

            public function biasForScope(int $scope, int $now): int
            {
                return 0;
            }

            public function recordReceipt(string $decisionId, int $scope, int $band, RiskAction $action): void
            {
            }

            public function consumeReceipt(string $decisionId): ?array
            {
                return null;
            }
        };
        $recorder = new CalibrationRecorder($store);
        $recorder->record(2, 550, RiskAction::Sha20, true);
        $recorder->record(2, 0, RiskAction::Allow, false);
        $recorder->record(2, 1000, RiskAction::Deny, false);
        self::assertSame([[2, 5, RiskAction::Sha20, true], [2, 0, RiskAction::Allow, false], [2, 10, RiskAction::Deny, false]], $captured);
    }

    private function countingClient(): CountingClient
    {
        $url = getenv('RISK_REDIS_URL');
        if (!is_string($url) || $url === '') {
            self::markTestSkipped('RISK_REDIS_URL not set; start redis with: docker run -d -p 6399:6379 redis:7-alpine');
        }
        return new CountingClient($url);
    }
}

/** Predis client that counts every command executed (one round trip each). */
final class CountingClient extends Client
{
    public int $commands = 0;

    public function executeCommand(CommandInterface $command)
    {
        $this->commands++;
        return parent::executeCommand($command);
    }
}
