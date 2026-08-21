<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Calibration\AggregateCalibrator;
use KiwiCaptcha\Risk\RiskAction;
use Predis\Client;
use Predis\Command\CommandInterface;
use Predis\Response\ServerException;
use PHPUnit\Framework\TestCase;

/**
 * Redis-backed calibration tests of the canonical calibration.lua plus
 * register_decision.lua/confirm.lua/correction.lua/sampling_metrics.lua.
 * The semantics: fp_mean = legit_score_sum/legit_count, fn_mean =
 * (abuse_count*1000 - abuse_score_sum)/abuse_count, error =
 * fn_mean*fn_cost - fp_mean*fp_cost, raw = trunc(error*2/10) clamped
 * ±maxAdjustment. Also covered: a proportional rate limiter over
 * milli-points clocked by Redis time, and a per-scope random-sample
 * resolution gate over the 24-bucket sample_total/sample_resolved window.
 * Receipts carry score + sampled + decision_hour and are created
 * atomically with the sample denominator and the pending outcome-ledger
 * entry by register_decision.lua, consumed exactly once by the atomic
 * confirm script with the shared status 0/1/2. AggregateCalibrator cases
 * are skipped unless the Redis test URL is set.
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

    /** Mode 'complete': every confirmation is recorded (deterministic). */
    private function calibrator(): AggregateCalibrator
    {
        if ($this->client === null) {
            self::markTestSkipped('RISK_REDIS_URL not set; start redis with: docker run -d -p 6399:6379 redis:7-alpine');
        }
        return new AggregateCalibrator($this->client, namespace: 'cal' . bin2hex(random_bytes(4)), samplingMode: 'complete');
    }

    /** Fast exact-score calibrator: minSamples 100, complete mode. */
    private function scoreCalibrator(): AggregateCalibrator
    {
        if ($this->client === null) {
            self::markTestSkipped('RISK_REDIS_URL not set; start redis with: docker run -d -p 6399:6379 redis:7-alpine');
        }
        return new AggregateCalibrator($this->client, namespace: 'sc' . bin2hex(random_bytes(4)), minSamples: 100, samplingMode: 'complete');
    }

    /**
     * Records n confirmed outcomes at an exact score through the full
     * register_decision.lua -> confirm.lua path (each confirmation must
     * return status 1, the first confirmation). The receipts are booked
     * as sampled so the sample counters follow the outcomes.
     */
    private function recordOutcomes(AggregateCalibrator $c, int $n, int $score, bool $legit, int $scope = 1, string $prefix = 'd'): void
    {
        for ($i = 0; $i < $n; $i++) {
            $id = "{$prefix}-{$scope}-{$i}";
            self::assertTrue($c->recordReceipt($id, $scope, intdiv(max(0, min(1000, $score)), 100), RiskAction::Sha20, $score, 1, $this->decisionHour()), "receipt {$id} must register");
            self::assertSame(1, $c->confirmOutcome($id, $legit), "outcome {$id} must be recorded (status 1) against scope {$scope}");
        }
    }

    private function nowMs(): int
    {
        return (int) floor(microtime(true) * 1000);
    }

    private function decisionHour(): int
    {
        return intdiv($this->nowMs(), 3_600_000);
    }

    /**
     * A fixed synthetic timestamp inside the current hour (buckets are
     * hourly), so biasForScope calls never shift the bucket window away
     * from the recorded hour. The timestamp is epoch math only — the
     * script's rate-limit clock is Redis time.
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

    private function bucket(AggregateCalibrator $c, int $scope, ?int $hour = null): string
    {
        return "{kiwi:{$c->namespace()}}:cal:{$scope}:" . ($hour ?? intdiv($this->nowMs(), 3_600_000));
    }

    /** The Redis server clock in epoch milliseconds (the script's clock authority). */
    private function redisNowMs(): int
    {
        $t = $this->client->time();
        return ((int) $t[0]) * 1000 + intdiv((int) $t[1], 1000);
    }

    /**
     * Seeds the rate-limit state {kiwi:<ns>}:cal:state:<scope> so the next
     * biasForScope call sees a proportional allowance for exactly
     * $elapsedMs: bias_mp = $biasMp, ts = real Redis time - $elapsedMs.
     * The script derives its elapsed from Redis time, so the seeded window
     * is exact to within a couple of ms (sub-milli-point at the default
     * maxChangePerMinute — safe for integer floor stability).
     */
    private function seedRateWindow(AggregateCalibrator $c, int $scope, int $biasMp, int $elapsedMs): void
    {
        $key = "{kiwi:{$c->namespace()}}:cal:state:{$scope}";
        $this->client->hset($key, 'bias_mp', (string) $biasMp);
        $this->client->hset($key, 'ts', (string) ($this->redisNowMs() - $elapsedMs));
    }

    public function testEmptyScopeHasZeroBias(): void
    {
        $c = $this->calibrator();
        self::assertSame(0, $c->biasForScope(1, $this->nowMs()));
    }

    public function testExactScoreLegitHighPushesBiasDownAndIsBounded(): void
    {
        // 100 legit @ exact score 900: fp_mean = 900 -> error = -900*1.0
        // -> raw = -180 -> clamped to -maxAdjustment.
        $c = $this->scoreCalibrator();
        $this->recordOutcomes($c, 100, 900, true, 1, 'ex-legit');
        $t = $this->t0();
        // The first call ever seeds the rate-limit state (bias_mp = 0 /
        // ts = Redis time) before the threshold check and returns 0 — a
        // fresh scope can never jump straight to ±maxAdjustment.
        self::assertSame(0, $c->biasForScope(1, $t));
        // The proportional ramp allows 10 points/minute: the seeded window
        // is exact to sub-milli-point, so -10 after 1 minute, -150 after 15.
        $this->seedRateWindow($c, 1, 0, 60_000);
        $this->clearCache($c);
        self::assertSame(-10, $c->biasForScope(1, $t));
        $this->seedRateWindow($c, 1, 0, 900_000);
        $this->clearCache($c);
        self::assertSame(-150, $c->biasForScope(1, $t));
    }

    public function testExactScoreAbuseLowPushesBiasUpAndIsBounded(): void
    {
        // 100 abuse @ exact score 100: fn_mean = (100000-10000)/100 = 900
        // -> error = 900*2.0 = 1800 -> raw = 360 -> clamped to
        // +maxAdjustment.
        $c = $this->scoreCalibrator();
        $this->recordOutcomes($c, 100, 100, false, 1, 'ex-abuse');
        $t = $this->t0();
        self::assertSame(0, $c->biasForScope(1, $t));
        $this->seedRateWindow($c, 1, 0, 60_000);
        $this->clearCache($c);
        self::assertSame(10, $c->biasForScope(1, $t));
        $this->seedRateWindow($c, 1, 0, 900_000);
        $this->clearCache($c);
        self::assertSame(150, $c->biasForScope(1, $t));
    }

    public function testPerfectSeparatorStaysNearZero(): void
    {
        // A perfectly separating classifier (legit @ score 0, abuse @
        // score 1000) contributes ~zero calibration pressure: fp_mean = 0,
        // fn_mean = 0 -> raw 0.
        $c = $this->scoreCalibrator();
        $this->recordOutcomes($c, 100, 0, true, 1, 'sep-l');
        $this->recordOutcomes($c, 100, 1000, false, 1, 'sep-a');
        $t = $this->t0();
        self::assertSame(0, $c->biasForScope(1, $t), 'first call ever seeds the rate-limit state and returns 0');
        $this->seedRateWindow($c, 1, 0, 900_000);
        $this->clearCache($c);
        self::assertSame(0, $c->biasForScope(1, $t), 'perfect separation must keep the bias at 0 even with full movement allowance');
    }

    public function testBalancedSameScoreBiasIsZero(): void
    {
        // Cost-weighted balance: fn_mean*2.0 == fp_mean*1.0 -> error 0.
        // (legit @ 1000 + abuse @ 500: fp_mean 1000, fn_mean 500.)
        $c = $this->scoreCalibrator();
        $this->recordOutcomes($c, 50, 1000, true, 1, 'bal-l');
        $this->recordOutcomes($c, 50, 500, false, 1, 'bal-a');
        $t = $this->t0();
        self::assertSame(0, $c->biasForScope(1, $t));
        $this->seedRateWindow($c, 1, 0, 900_000);
        $this->clearCache($c);
        self::assertSame(0, $c->biasForScope(1, $t));

        // Same score both classes is NOT zero under the asymmetric default
        // costs (fn 2.0 vs fp 1.0): error = 500*2 - 500*1 = 500 -> raw 100.
        $c = $this->scoreCalibrator();
        $this->recordOutcomes($c, 50, 500, true, 1, 'bal2-l');
        $this->recordOutcomes($c, 50, 500, false, 1, 'bal2-a');
        self::assertSame(0, $c->biasForScope(1, $t));
        $this->seedRateWindow($c, 1, 0, 900_000);
        $this->clearCache($c);
        self::assertSame(100, $c->biasForScope(1, $t), 'fn_mean 500 * 2.0 - fp_mean 500 * 1.0 = 500 -> raw 100');
    }

    public function testClassNormalizedBiasScoreSensitive(): void
    {
        // Class-normalized (volume-independent): 75 abuse + 25 legit @
        // exact score 500 -> fn_mean = 500, fp_mean = 500, error =
        // 500*2.0 - 500*1.0 = 500 -> raw = 100 (5 min at
        // maxChangePerMinute 10).
        $c = $this->scoreCalibrator();
        $this->recordOutcomes($c, 75, 500, false, 1, 'mix-a');
        $this->recordOutcomes($c, 25, 500, true, 1, 'mix-l');
        $t = $this->t0();
        self::assertSame(0, $c->biasForScope(1, $t));
        $this->seedRateWindow($c, 1, 0, 600_000);
        $this->clearCache($c);
        self::assertSame(100, $c->biasForScope(1, $t));

        // Volume parity: 55 abuse + 45 legit at the same scores have the
        // Same means (class normalization removes label-volume dominance).
        $c = $this->scoreCalibrator();
        $this->recordOutcomes($c, 55, 500, false, 1, 'mix2-a');
        $this->recordOutcomes($c, 45, 500, true, 1, 'mix2-l');
        self::assertSame(0, $c->biasForScope(1, $t));
        $this->seedRateWindow($c, 1, 0, 600_000);
        $this->clearCache($c);
        self::assertSame(100, $c->biasForScope(1, $t));
    }

    public function testScopesAreIndependent(): void
    {
        $c = $this->scoreCalibrator();
        $this->recordOutcomes($c, 100, 100, false, 1, 'ind-a');
        $this->recordOutcomes($c, 100, 900, true, 2, 'ind-l');
        $t = $this->t0();
        self::assertSame(0, $c->biasForScope(1, $t));
        self::assertSame(0, $c->biasForScope(2, $t));
        $this->seedRateWindow($c, 1, 0, 900_000);
        $this->clearCache($c);
        self::assertSame(150, $c->biasForScope(1, $t));
        $this->seedRateWindow($c, 2, 0, 900_000);
        $this->clearCache($c);
        self::assertSame(-150, $c->biasForScope(2, $t));
    }

    public function testBucketsAreBoundedByWindowAndTtl(): void
    {
        $c = $this->calibrator();
        $ns = $c->namespace();
        // 1000 abuse @ exact score 500: fn_mean = 500 -> error = 1000 ->
        // raw = 200 -> clamped 150.
        $this->recordOutcomes($c, 1000, 500, false, 1, 'bnd');

        // Buckets are hourly hashes with a 48 h TTL and at most 24 keys in
        // the bias window; an ancient bucket does not contribute.
        $nowMs = $this->nowMs();
        $hour = intdiv($nowMs, 3_600_000);
        self::assertSame('1000', (string) $this->client->hget("{kiwi:{$ns}}:cal:1:{$hour}", 'abuse_count'));
        self::assertSame('500000', (string) $this->client->hget("{kiwi:{$ns}}:cal:1:{$hour}", 'abuse_score_sum'));
        self::assertNull($this->client->hget("{kiwi:{$ns}}:cal:1:" . ($hour - 25), 'abuse_count'));

        $t = $this->t0();
        self::assertSame(0, $c->biasForScope(1, $t));
        $this->seedRateWindow($c, 1, 0, 900_000);
        $this->clearCache($c);
        self::assertSame(150, $c->biasForScope(1, $t));
    }

    public function testBelowMinSamplesIsZero(): void
    {
        $c = $this->scoreCalibrator();
        $this->recordOutcomes($c, 99, 100, false, 1, 'bms');
        $t = $this->t0();
        self::assertSame(0, $c->biasForScope(1, $t), 'no nonzero bias below minSamples');

        // At the threshold the bias appears, rate-limited from the seeded
        // 0 (fresh scope): 150 points need 15 minutes at
        // maxChangePerMinute 10.
        $this->recordOutcomes($c, 100, 100, false, 2, 'bms');
        $this->clearCache($c);
        self::assertSame(0, $c->biasForScope(2, $t));
        $this->seedRateWindow($c, 2, 0, 900_000);
        $this->clearCache($c);
        self::assertSame(150, $c->biasForScope(2, $t));
    }

    public function testBelowThresholdMovesTowardZeroAtAllowedRate(): void
    {
        // Below min_samples the target is 0, but the stored bias moves
        // toward 0 through the proportional rate limiter — a sample count
        // that dips below the threshold can never snap +150 → 0 instantly.
        $c = $this->scoreCalibrator();
        $this->recordOutcomes($c, 99, 100, false, 3, 'decay');
        $t = $this->t0();

        // 5 s window: allowed = 10*1000*5000/60000 = 833 milli-points ->
        // 150000 - 833 = 149167 -> 149, never 0.
        $this->seedRateWindow($c, 3, 150000, 5_000);
        $this->clearCache($c);
        self::assertSame(149, $c->biasForScope(3, $t));

        // 1 minute later: allowed = 10 points -> 139.
        $this->seedRateWindow($c, 3, 149167, 60_000);
        $this->clearCache($c);
        self::assertSame(139, $c->biasForScope(3, $t));

        // Crossing the threshold again (100 samples): the target jumps to
        // +150, but the movement allowance counts from the seeded window —
        // only ~0.08 points are allowed, so the bias stays put, never an
        // instant 150.
        $this->recordOutcomes($c, 1, 100, false, 3, 'decay');
        $this->seedRateWindow($c, 3, 139167, 500);
        $this->clearCache($c);
        self::assertSame(139, $c->biasForScope(3, $t));
    }

    public function testConstructorKnobs(): void
    {
        $c = new AggregateCalibrator(
            $this->requireClient(),
            namespace: 'knob' . bin2hex(random_bytes(4)),
            minSamples: 10,
            maxAdjustment: 25,
            maxChangePerMinute: 5,
            samplingMode: 'complete',
        );
        $this->recordOutcomes($c, 9, 100, false, 1, 'knob');
        $t = $this->t0();
        self::assertSame(0, $c->biasForScope(1, $t));
        $this->recordOutcomes($c, 10, 100, false, 2, 'knob');
        // raw 360 -> clamped to the custom maxAdjustment 25; the
        // proportional ramp allows 5 points per minute.
        $this->clearCache($c);
        self::assertSame(0, $c->biasForScope(2, $t));
        $this->seedRateWindow($c, 2, 0, 60_000);
        $this->clearCache($c);
        self::assertSame(5, $c->biasForScope(2, $t));
        $this->seedRateWindow($c, 2, 0, 300_000);
        $this->clearCache($c);
        self::assertSame(25, $c->biasForScope(2, $t));

        $this->expectException(\InvalidArgumentException::class);
        new AggregateCalibrator($this->requireClient(), namespace: 'bad' . bin2hex(random_bytes(4)), minSamples: 0);
    }

    public function testSamplingModeAndPpmValidation(): void
    {
        try {
            new AggregateCalibrator($this->requireClient(), namespace: 'm1' . bin2hex(random_bytes(4)), samplingMode: 'nonsense');
            self::fail('an invalid samplingMode must throw');
        } catch (\InvalidArgumentException) {
        }
        try {
            new AggregateCalibrator($this->requireClient(), namespace: 'm2' . bin2hex(random_bytes(4)), samplingProbabilityPpm: 0);
            self::fail('ppm 0 must throw');
        } catch (\InvalidArgumentException) {
        }
        try {
            new AggregateCalibrator($this->requireClient(), namespace: 'm3' . bin2hex(random_bytes(4)), samplingProbabilityPpm: 1_000_001);
            self::fail('ppm > 1000000 must throw');
        } catch (\InvalidArgumentException) {
        }
        try {
            new AggregateCalibrator($this->requireClient(), namespace: 'm4' . bin2hex(random_bytes(4)), outcomeTtlSecs: 0);
            self::fail('outcomeTtlSecs 0 must throw');
        } catch (\InvalidArgumentException) {
        }
        self::assertTrue(true);
    }

    public function testResolutionRatioAndCostKnobValidation(): void
    {
        $bad = [
            ['minimumResolutionRatio' => 1.01],
            ['minimumResolutionRatio' => -0.01],
            ['falsePositiveCost' => 0.05],
            ['falsePositiveCost' => 10.01],
            ['falseNegativeCost' => 0.05],
            ['falseNegativeCost' => 10.01],
        ];
        foreach ($bad as $i => $knob) {
            try {
                $args = ['client' => $this->requireClient(), 'namespace' => 'k' . $i . bin2hex(random_bytes(4))];
                $args += $knob;
                new AggregateCalibrator(...$args);
                self::fail('out-of-range calibration knob must throw: ' . json_encode($knob));
            } catch (\InvalidArgumentException) {
            }
        }
        // Boundary values are accepted.
        new AggregateCalibrator($this->requireClient(), namespace: 'kb' . bin2hex(random_bytes(4)), minimumResolutionRatio: 1.0, falsePositiveCost: 0.1, falseNegativeCost: 10.0);
        self::assertTrue(true);
    }

    public function testSampleDecision(): void
    {
        // complete and weighted always sample.
        self::assertTrue((new AggregateCalibrator($this->requireClient(), namespace: 's1' . bin2hex(random_bytes(4)), samplingMode: 'complete'))->sample());
        self::assertTrue((new AggregateCalibrator($this->requireClient(), namespace: 's2' . bin2hex(random_bytes(4)), samplingMode: 'weighted'))->sample());

        // random_sample at ppm 1000000 always samples.
        $c = new AggregateCalibrator($this->requireClient(), namespace: 's3' . bin2hex(random_bytes(4)), samplingMode: 'random_sample', samplingProbabilityPpm: 1_000_000);
        for ($i = 0; $i < 10; $i++) {
            self::assertTrue($c->sample(), 'ppm 1000000 must always sample');
        }

        // random_sample at 50% honors the ppm (both outcomes occur).
        $c = new AggregateCalibrator($this->requireClient(), namespace: 's4' . bin2hex(random_bytes(4)), samplingMode: 'random_sample', samplingProbabilityPpm: 500_000);
        $yes = 0;
        $no = 0;
        for ($i = 0; $i < 200; $i++) {
            $c->sample() ? $yes++ : $no++;
        }
        self::assertGreaterThan(0, $yes, '50% ppm must eventually sample');
        self::assertGreaterThan(0, $no, '50% ppm must eventually skip');

        // sample() is pure: no singleton counters are touched —
        // the denominator is booked atomically with the receipt.
        $client = $this->requireClient();
        $r = new AggregateCalibrator($client, namespace: 'spure' . bin2hex(random_bytes(4)), samplingMode: 'random_sample', samplingProbabilityPpm: 1_000_000);
        $r->sample();
        $r->sample();
        self::assertNull($client->get("{kiwi:{$r->namespace()}}:cal:sample:total"), 'the lifetime singleton counter key is GONE');
        self::assertNull($client->get("{kiwi:{$r->namespace()}}:cal:sample:resolved"), 'the lifetime singleton resolved key is GONE');
    }

    public function testSamplingMetricsPerScope(): void
    {
        $client = $this->requireClient();
        $c = new AggregateCalibrator($client, namespace: 'smet' . bin2hex(random_bytes(4)), samplingMode: 'random_sample', samplingProbabilityPpm: 1_000_000);
        $ns = $c->namespace();
        $now = $this->nowMs();
        $hour = intdiv($now, 3_600_000);

        // A fresh scope has zero totals and a fully-resolved ratio (1.0).
        self::assertSame(
            ['sampledTotal' => 0, 'sampledResolved' => 0, 'resolutionRatio' => 0.0, 'sampledExpired' => 0],
            $c->samplingMetrics(1, $now),
        );

        // Three sampled receipts: the denominator is booked atomically with
        // each receipt (no markSampled — no singleton counters).
        for ($i = 0; $i < 3; $i++) {
            $c->recordReceipt("smet-{$i}", 1, 1, RiskAction::Sha20, 100, 1, $hour);
        }
        self::assertSame('3', (string) $client->hget($this->bucket($c, 1), 'sample_total'), 'each sampled decision books sample_total exactly once');

        // One resolution: 1/3 resolved, 2 in flight (expired approximation).
        self::assertSame(1, $c->confirmOutcome('smet-0', true), 'the sampled confirmation resolves');
        $metrics = $c->samplingMetrics(1, $now);
        self::assertSame(3, $metrics['sampledTotal']);
        self::assertSame(1, $metrics['sampledResolved']);
        self::assertSame(1 / 3, $metrics['resolutionRatio']);
        self::assertSame(2, $metrics['sampledExpired'], 'sampledExpired = max(0, total - resolved) — includes in-flight receipts');

        // An unsampled receipt (sampled=0) books no denominator and is
        // consumed with status 2 without resolving.
        $c->recordReceipt('smet-unsampled', 1, 1, RiskAction::Sha20, 100, 0, $hour);
        self::assertSame(2, $c->confirmOutcome('smet-unsampled', true));
        self::assertSame(3, $c->samplingMetrics(1, $now)['sampledTotal'], 'an unsampled decision never books the denominator');
        self::assertSame(1, $c->samplingMetrics(1, $now)['sampledResolved']);

        // Metrics are per-scope: scope 2 (with one sampled receipt) does
        // not see scope 1's window.
        $c->recordReceipt('smet-other', 2, 1, RiskAction::Sha20, 100, 1, $hour);
        $other = $c->samplingMetrics(2, $now);
        self::assertSame(1, $other['sampledTotal']);
        self::assertSame(0, $other['sampledResolved']);
        self::assertSame(0.0, $other['resolutionRatio']);
        self::assertSame(1, $other['sampledExpired']);
    }

    public function testRandomSampleDiscardsUnsampledConfirmations(): void
    {
        $c = new AggregateCalibrator($this->requireClient(), namespace: 'rs' . bin2hex(random_bytes(4)), samplingMode: 'random_sample', samplingProbabilityPpm: 1_000_000);
        $ns = $c->namespace();
        $hour = $this->decisionHour();
        // Unsampled: status 2 — the receipt is consumed (never calibrated,
        // the label can never select itself into the population).
        $c->recordReceipt('rs-unsampled', 1, 1, RiskAction::Sha20, 100, 0, $hour);
        self::assertSame(2, $c->confirmOutcome('rs-unsampled', false), 'an unsampled decision must be consumed with status 2, never recorded');
        self::assertSame([], $this->client->hgetall($this->bucket($c, 1)), 'no bucket fields may be written for a consumed unsampled confirmation');
        self::assertNull($this->client->get("{kiwi:{$ns}}:cal:receipt:rs-unsampled"), 'the unsampled receipt must still be consumed');

        // A sampled receipt confirms normally (status 1) and resolves.
        $c->recordReceipt('rs-sampled', 1, 1, RiskAction::Sha20, 100, 1, $hour);
        self::assertSame(1, $c->confirmOutcome('rs-sampled', false));
        self::assertSame('1', (string) $this->client->hget($this->bucket($c, 1), 'abuse_count'));
        self::assertSame('100', (string) $this->client->hget($this->bucket($c, 1), 'abuse_score_sum'));
        self::assertSame('1', (string) $this->client->hget($this->bucket($c, 1), 'sample_resolved'));
        self::assertSame('1', (string) $this->client->hget($this->bucket($c, 1), 'sample_total'));
    }

    public function testCompleteModeRecordsRegardlessOfSampledFlag(): void
    {
        $c = $this->calibrator();
        $c->recordReceipt('cm-unsampled', 1, 1, RiskAction::Sha20, 100, 0, $this->decisionHour());
        self::assertSame(1, $c->confirmOutcome('cm-unsampled', false), 'complete mode must record even an unsampled receipt');
        self::assertSame('1', (string) $this->client->hget($this->bucket($c, 1), 'abuse_count'));
    }

    public function testWeightedModeRecordsWithSuppliedWeight(): void
    {
        $c = new AggregateCalibrator($this->requireClient(), namespace: 'wg' . bin2hex(random_bytes(4)), samplingMode: 'weighted');
        // Weight 10: every confirmed outcome counts 10 (host-supplied
        // inverse sampling probability).
        $c->recordReceipt('wg-1', 1, 1, RiskAction::Sha20, 100, 0, $this->decisionHour());
        self::assertSame(1, $c->confirmOutcome('wg-1', true, 10.0));
        self::assertSame('10', (string) $this->client->hget($this->bucket($c, 1), 'legit_count'));
        self::assertSame('1000', (string) $this->client->hget($this->bucket($c, 1), 'legit_score_sum'), 'score 100 x weight 10');

        // The default weight is 1.0 when supplied explicitly.
        $c->recordReceipt('wg-2', 1, 1, RiskAction::Sha20, 200, 0, $this->decisionHour());
        self::assertSame(1, $c->confirmOutcome('wg-2', true, 1.0));
        self::assertSame('11', (string) $this->client->hget($this->bucket($c, 1), 'legit_count'));
        self::assertSame('1200', (string) $this->client->hget($this->bucket($c, 1), 'legit_score_sum'));
    }

    public function testWeightedModeRejectsNullWeight(): void
    {
        $c = new AggregateCalibrator($this->requireClient(), namespace: 'wgn' . bin2hex(random_bytes(4)), samplingMode: 'weighted');
        $ns = $c->namespace();
        $c->recordReceipt('wgn-1', 1, 1, RiskAction::Sha20, 100, 0, $this->decisionHour());

        // A PHP-side validation error: weighted mode requires the
        // inverse-sampling weight — the script never runs and the receipt
        // survives (a retry with the weight applies exactly once).
        try {
            $c->confirmOutcome('wgn-1', true);
            self::fail('weighted mode with a null weight must throw');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('weighted mode requires a sampling probability weight', $e->getMessage());
        }
        self::assertNotNull($this->client->get("{kiwi:{$ns}}:cal:receipt:wgn-1"), 'the receipt must survive the rejected confirmation');
        self::assertSame([], $this->client->hgetall($this->bucket($c, 1)), 'no bucket fields may be written without a weight');

        // With the weight the same confirmation applies (status 1).
        self::assertSame(1, $c->confirmOutcome('wgn-1', true, 2.0));
        self::assertSame('2', (string) $this->client->hget($this->bucket($c, 1), 'legit_count'));
    }

    public function testReceiptCarriesScoreSampledAndDecisionHour(): void
    {
        $c = $this->calibrator();
        $ns = $c->namespace();
        $hour = $this->decisionHour();
        $c->recordReceipt('carry-1', 7, 4, RiskAction::Argon16, 900, 1, $hour);
        $raw = $this->client->get("{kiwi:{$ns}}:cal:receipt:carry-1");
        self::assertSame(
            ['scope' => 7, 'band' => 4, 'action' => 'argon16', 'decision_hour' => $hour, 'score' => 900, 'sampled' => 1],
            json_decode((string) $raw, true),
            'the receipt must carry the exact score, the sampling flag and the decision hour'
        );
        self::assertSame(1, $c->confirmOutcome('carry-1', true));
        self::assertSame('1', (string) $this->client->hget($this->bucket($c, 7), 'legit_count'));
        self::assertSame('900', (string) $this->client->hget($this->bucket($c, 7), 'legit_score_sum'), 'the EXACT score must reach the bucket');
    }

    public function testConfirmOutcomeSharedStatus(): void
    {
        $c = $this->calibrator();
        $ns = $c->namespace();

        // Missing receipt -> status 0 (nothing consumed).
        self::assertSame(0, $c->confirmOutcome('missing-1', false));

        // Corrupt receipts -> status 0 via the NON-destructive pre-read
        // (json that is not a receipt object; the script never runs, so
        // the receipt survives — parity with the Rust pre-read, which also
        // short-circuits before the script).
        $this->client->set("{kiwi:{$ns}}:cal:receipt:corrupt-1", '42', 'EX', 300);
        self::assertSame(0, $c->confirmOutcome('corrupt-1', false));
        self::assertSame('42', (string) $this->client->get("{kiwi:{$ns}}:cal:receipt:corrupt-1"), 'the pre-read must not delete the receipt');
        $this->client->set("{kiwi:{$ns}}:cal:receipt:corrupt-2", 'not-json', 'EX', 300);
        self::assertSame(0, $c->confirmOutcome('corrupt-2', false));
        self::assertSame('not-json', (string) $this->client->get("{kiwi:{$ns}}:cal:receipt:corrupt-2"), 'the pre-read must not delete the receipt');

        // First confirmation -> status 1; the retry -> status 0 (the
        // outcome-ledger CAS is the exactly-once authority).
        $c->recordReceipt('once-1', 7, 4, RiskAction::Argon16, 500, 1, $this->decisionHour());
        self::assertSame(1, $c->confirmOutcome('once-1', true), 'the first confirmation is status 1');
        self::assertSame(0, $c->confirmOutcome('once-1', true), 'a retried confirmation is status 0 (already confirmed)');
        self::assertSame('1', (string) $this->client->hget($this->bucket($c, 7), 'legit_count'), 'exactly one outcome recorded');
        $ledger = json_decode((string) $this->client->get("{kiwi:{$ns}}:outcome:once-1"), true);
        self::assertSame('L', $ledger['o'], 'the outcome ledger records the confirmation exactly once');
    }

    public function testRateOfChangeClampIsProportional(): void
    {
        // maxChangePerMinute 6 points/min (0.1 milli-points/ms — the seeded
        // windows stay integer-exact to sub-milli-point): the movement
        // allowance is proportional to the elapsed time.
        $c = new AggregateCalibrator(
            $this->requireClient(),
            namespace: 'roc' . bin2hex(random_bytes(4)),
            minSamples: 10,
            maxAdjustment: 150,
            maxChangePerMinute: 6,
            samplingMode: 'complete',
        );
        $this->recordOutcomes($c, 100, 100, false, 3, 'roc');
        $t = $this->t0();

        // First call ever seeds bias_mp = 0 / ts = Redis time before the
        // threshold check: the initial bias is 0, never ±maxAdjustment.
        self::assertSame(0, $c->biasForScope(3, $t));

        // 10 s window: allowed = 6*1000*10000/60000 = 1000 mp = 1 point.
        $this->seedRateWindow($c, 3, 0, 10_000);
        $this->clearCache($c);
        self::assertSame(1, $c->biasForScope(3, $t));

        // 1 minute: allowed = 6 points.
        $this->seedRateWindow($c, 3, 0, 60_000);
        $this->clearCache($c);
        self::assertSame(6, $c->biasForScope(3, $t));

        // 10 minutes: allowed = 60 points.
        $this->seedRateWindow($c, 3, 0, 600_000);
        $this->clearCache($c);
        self::assertSame(60, $c->biasForScope(3, $t));

        // 15 minutes: allowed = 90 points (raw 360 -> still clamped by the
        // allowance).
        $this->seedRateWindow($c, 3, 0, 900_000);
        $this->clearCache($c);
        self::assertSame(90, $c->biasForScope(3, $t));

        // 25 minutes: allowed = 150 >= raw clamp -> maxAdjustment wins.
        $this->seedRateWindow($c, 3, 0, 1_500_000);
        $this->clearCache($c);
        self::assertSame(150, $c->biasForScope(3, $t));

        // The window is now balanced (100 legit @ 100 + 100 abuse @ 950 in
        // a fresh scope: fp_mean 100, fn_mean 50 -> error = 50*2 - 100*1
        // = 0): the target is 0, but the bias may only move down by the
        // proportional allowance (6 points over the seeded minute) — never
        // jump straight to 0.
        $this->recordOutcomes($c, 100, 100, true, 4, 'roc');
        $this->recordOutcomes($c, 100, 950, false, 4, 'roc');
        $this->seedRateWindow($c, 4, 90000, 60_000);
        $this->clearCache($c);
        self::assertSame(84, $c->biasForScope(4, $t));
    }

    public function testAggregateIsOneRoundTripAndCached(): void
    {
        $client = $this->countingClient();
        $c = new AggregateCalibrator($client, namespace: 'rt' . bin2hex(random_bytes(4)), samplingMode: 'complete', minSamples: 100);
        $this->recordOutcomes($c, 100, 100, false);

        $before = $client->commands;
        self::assertSame(0, $c->biasForScope(1, $this->nowMs()), 'first call seeds the state');
        self::assertSame($before + 1, $client->commands, '24 buckets + rate clamp + state must be ONE round trip (no singleton counters)');

        self::assertSame(0, $c->biasForScope(1, $this->nowMs()));
        self::assertSame($before + 1, $client->commands, 'cache hit must not touch Redis');
    }

    public function testConfirmInvalidatesScopeCache(): void
    {
        $client = $this->countingClient();
        $c = new AggregateCalibrator($client, namespace: 'inv' . bin2hex(random_bytes(4)), samplingMode: 'complete', minSamples: 100);
        $this->recordOutcomes($c, 100, 100, false);

        $before = $client->commands;
        self::assertSame(0, $c->biasForScope(1, $this->nowMs()));
        self::assertSame($before + 1, $client->commands);

        // A fresh outcome for the same scope invalidates its cached bias:
        // the next read must hit Redis again. The confirm itself is the
        // bucket pre-read GET + the atomic script.
        $c->recordReceipt('inv-fresh', 1, 1, RiskAction::Sha20, 100, 1, $this->decisionHour());
        $c->confirmOutcome('inv-fresh', false);
        $c->biasForScope(1, $this->nowMs());
        self::assertSame($before + 5, $client->commands, 'confirmOutcome() must invalidate the confirmed scope cache');

        // A fresh outcome for another scope must not invalidate this one.
        $c->recordReceipt('inv-other', 2, 1, RiskAction::Sha20, 100, 1, $this->decisionHour());
        $c->confirmOutcome('inv-other', false);
        $c->biasForScope(1, $this->nowMs());
        self::assertSame($before + 8, $client->commands, 'a confirm for another scope must not invalidate this scope');
    }

    public function testResolutionGateIsPerScopeWindow(): void
    {
        // random_sample mode with the default minimumResolutionRatio 0.80:
        // the gate compares the per-scope 24-bucket sample totals — two
        // scopes with different resolution ratios gate independently (the
        // lifetime singleton counters are gone).
        $c = new AggregateCalibrator(
            $this->requireClient(),
            namespace: 'gate' . bin2hex(random_bytes(4)),
            minSamples: 100,
            samplingMode: 'random_sample',
            samplingProbabilityPpm: 1_000_000,
        );
        $client = $this->requireClient();
        $t = $this->t0();
        $hour = intdiv($t, 3_600_000);

        // Scope 1: 100 sampled abuse @ 100, ALL resolved -> ratio 1.0,
        // gate open -> the bias moves to the raw (150 with full allowance).
        $this->recordOutcomes($c, 100, 100, false, 1, 'gate');
        self::assertSame('100', (string) $client->hget($this->bucket($c, 1), 'sample_total'));
        self::assertSame('100', (string) $client->hget($this->bucket($c, 1), 'sample_resolved'));
        $this->seedRateWindow($c, 1, 0, 900_000);
        $this->clearCache($c);
        self::assertSame(150, $c->biasForScope(1, $t), 'a fully-resolved scope must move');

        // Scope 2: 100 sampled abuse @ 100, only 79 resolved -> ratio 0.79
        // < 0.80, gate closed -> the target stays 0 even with full
        // movement allowance (a different scope's resolution cannot open
        // this window).
        $this->recordOutcomes($c, 100, 100, false, 2, 'gate2');
        $client->hset($this->bucket($c, 2, $hour), 'sample_resolved', 79);
        $this->seedRateWindow($c, 2, 0, 900_000);
        $this->clearCache($c);
        self::assertSame(0, $c->biasForScope(2, $t), 'the gate must hold the bias at 0 while resolved < 80% of the per-scope total');

        // Rewind scope 2's resolved below the exact boundary (79 < 80).
        self::assertSame(0, $c->biasForScope(2, $t));

        // Exactly 80 resolves: 80 < 80 is false -> the gate opens. (The
        // previous call refreshed the rate-limit clock, so re-seed the
        // proportional window.)
        $client->hset($this->bucket($c, 2, $hour), 'sample_resolved', 80);
        $this->seedRateWindow($c, 2, 0, 900_000);
        $this->clearCache($c);
        self::assertSame(150, $c->biasForScope(2, $t), 'the bias moves once the per-scope resolution ratio is met');

        // Scope 1 is untouched by scope 2's rewinds (still open).
        $this->seedRateWindow($c, 1, 0, 900_000);
        $this->clearCache($c);
        self::assertSame(150, $c->biasForScope(1, $t));

        // The gate never applies to complete mode (mode != 1).
        $c2 = new AggregateCalibrator($this->requireClient(), namespace: 'gatec' . bin2hex(random_bytes(4)), minSamples: 100, samplingMode: 'complete');
        $this->recordOutcomes($c2, 100, 100, false, 1, 'gatec');
        $this->seedRateWindow($c2, 1, 0, 900_000);
        self::assertSame(150, $c2->biasForScope(1, $t), 'complete mode has no resolution gate');

        // A ratio of 0 disables the gate entirely.
        $c3 = new AggregateCalibrator($this->requireClient(), namespace: 'gate0' . bin2hex(random_bytes(4)), minSamples: 100, samplingMode: 'random_sample', minimumResolutionRatio: 0.0);
        $this->recordOutcomes($c3, 100, 100, false, 1, 'gate0');
        $this->seedRateWindow($c3, 1, 0, 900_000);
        self::assertSame(150, $c3->biasForScope(1, $t), 'minimumResolutionRatio 0 disables the gate');
    }

    public function testCostKnobsAffectTheRawBias(): void
    {
        // 100 legit @ 900 + 100 abuse @ 100: fp_mean = 900, fn_mean = 900.
        // error = 900*fn_cost - 900*fp_cost; raw = trunc(error*2/10).
        $t = $this->t0();
        $make = function (float $fp, float $fn) {
            $c = new AggregateCalibrator(
                $this->requireClient(),
                namespace: 'cost' . bin2hex(random_bytes(4)),
                minSamples: 100,
                samplingMode: 'complete',
                falsePositiveCost: $fp,
                falseNegativeCost: $fn,
            );
            $this->recordOutcomes($c, 100, 900, true, 1, 'cost-l');
            $this->recordOutcomes($c, 100, 100, false, 1, 'cost-a');
            $this->seedRateWindow($c, 1, 0, 900_000);
            return $c;
        };

        // Defaults (fp 1.0 / fn 2.0): error = 900 -> raw 180 -> clamped 150.
        self::assertSame(150, $make(1.0, 2.0)->biasForScope(1, $t));

        // fn priced below fp: error = 900*1.0 - 900*2.0 = -900 -> -150.
        self::assertSame(-150, $make(2.0, 1.0)->biasForScope(1, $t));

        // Equal costs: error 0 -> bias 0.
        self::assertSame(0, $make(1.0, 1.0)->biasForScope(1, $t));

        // A low fn cost leaves the raw UNclamped: 100 abuse @ 100 only
        // (fp_mean 0) with fn_cost 0.1 -> error = 90 -> raw = 18.
        $low = new AggregateCalibrator(
            $this->requireClient(),
            namespace: 'costlow' . bin2hex(random_bytes(4)),
            minSamples: 100,
            samplingMode: 'complete',
            falseNegativeCost: 0.1,
        );
        $this->recordOutcomes($low, 100, 100, false, 1, 'costlow');
        $this->seedRateWindow($low, 1, 0, 900_000);
        self::assertSame(18, $low->biasForScope(1, $t), 'fn_mean 900 * 0.1 = 90 -> raw 18 (unclamped)');
    }

    public function testReceiptTtlUsesConstructorParameter(): void
    {
        $c = new AggregateCalibrator(
            $this->requireClient(),
            namespace: 'ttl' . bin2hex(random_bytes(4)),
            receiptTtlSecs: 60,
            samplingMode: 'complete',
        );
        $c->recordReceipt('receipt-ttl-1', 1, 5, RiskAction::Sha20, 500, 1, $this->decisionHour());
        $ttl = (int) $this->client->ttl("{kiwi:{$c->namespace()}}:cal:receipt:receipt-ttl-1");
        self::assertGreaterThan(0, $ttl);
        self::assertLessThanOrEqual(60, $ttl);

        // The default is the receipt TTL constant (300).
        $d = $this->calibrator();
        $d->recordReceipt('receipt-ttl-2', 1, 5, RiskAction::Sha20, 500, 1, $this->decisionHour());
        $ttl = (int) $this->client->ttl("{kiwi:{$d->namespace()}}:cal:receipt:receipt-ttl-2");
        self::assertGreaterThan(0, $ttl);
        self::assertLessThanOrEqual(AggregateCalibrator::RECEIPT_TTL_SECS, $ttl);
    }

    public function testZeroBiasIsCachedToo(): void
    {
        $client = $this->countingClient();
        $c = new AggregateCalibrator($client, namespace: 'zc' . bin2hex(random_bytes(4)), samplingMode: 'complete');
        self::assertSame(0, $c->biasForScope(1, $this->nowMs()));
        $before = $client->commands;
        self::assertSame(0, $c->biasForScope(1, $this->nowMs()));
        self::assertSame($before, $client->commands, 'a cached 0 (below minSamples) must not touch Redis');
    }

    public function testCacheIsBounded(): void
    {
        $client = $this->countingClient();
        $c = new AggregateCalibrator($client, namespace: 'cap' . bin2hex(random_bytes(4)), samplingMode: 'complete');
        for ($i = 1; $i <= 1024; $i++) {
            $c->biasForScope($i, $this->nowMs());
        }

        // Full: a NEW scope evicts the least-recently-used entry (scope 1) before inserting.
        $before = $client->commands;
        $c->biasForScope(2049, $this->nowMs());
        self::assertSame($before + 1, $client->commands, 'new scope past the cap must run and evict the least-recently-used entry');
        $c->biasForScope(1, $this->nowMs());
        self::assertSame($before + 2, $client->commands, 'the evicted least-recently-used scope must miss the cache');
        $c->biasForScope(1024, $this->nowMs());
        self::assertSame($before + 2, $client->commands, 'recently cached scope must still hit');
    }

    public function testRegisterIsAtomicWithReceiptAndDenominator(): void
    {
        // register_decision.lua creates the receipt, the sampled-total
        // denominator and the pending ledger entry in one invocation: a
        // duplicate registration returns false and can never double-book
        // the denominator (no orphaned counters).
        $c = $this->calibrator();
        $client = $this->requireClient();
        $ns = $c->namespace();
        $hour = $this->decisionHour();

        $bucketKey = $this->bucket($c, 7, $hour);
        self::assertTrue($c->recordReceipt('atomic-reg', 7, 4, RiskAction::Argon16, 100, 1, $hour));
        self::assertSame('1', (string) $client->hget($bucketKey, 'sample_total'));
        self::assertNotNull($client->get("{kiwi:{$ns}}:cal:receipt:atomic-reg"), 'the receipt exists');

        // The same decision again: nothing is registered, the denominator
        // is NOT incremented — a sample can never be counted without its
        // receipt.
        self::assertFalse($c->recordReceipt('atomic-reg', 7, 4, RiskAction::Argon16, 100, 1, $hour), 'a duplicate registration is refused');
        self::assertSame('1', (string) $client->hget($bucketKey, 'sample_total'), 'the denominator must be booked exactly once');

        // An unsampled registration never touches the bucket at all.
        self::assertTrue($c->recordReceipt('atomic-reg-unsampled', 7, 4, RiskAction::Argon16, 100, 0, $hour));
        self::assertSame('1', (string) $client->hget($bucketKey, 'sample_total'), 'an unsampled decision books no denominator');
        self::assertNull($client->hget($bucketKey, 'sample_resolved'), 'nothing resolves at registration');

        // Every registered decision has a pending outcome-ledger entry.
        $ledger = json_decode((string) $client->get("{kiwi:{$ns}}:outcome:atomic-reg"), true);
        self::assertSame('P', $ledger['o'], 'the ledger entry is PENDING at registration');
        self::assertSame(7, $ledger['scope']);
        self::assertSame($hour, $ledger['hour']);
        self::assertSame(100, $ledger['score']);
    }

    public function testDecisionHourBucketing(): void
    {
        // A decision made at hour H is bucketed at H — a confirmation
        // hours later must land in the decision-time bucket, never in the
        // confirmation-time bucket. (random_sample mode so the resolution
        // counter is exercised too.)
        $client = $this->requireClient();
        $c = new AggregateCalibrator($client, namespace: 'dhb' . bin2hex(random_bytes(4)), samplingMode: 'random_sample', samplingProbabilityPpm: 1_000_000);
        $ns = $c->namespace();
        $decisionHour = intdiv($this->nowMs(), 3_600_000) - 3; // 3 hours ago
        $nowHour = intdiv($this->nowMs(), 3_600_000);

        self::assertTrue($c->recordReceipt('hour-dec', 9, 3, RiskAction::Sha20, 700, 1, $decisionHour));
        self::assertSame('1', (string) $client->hget("{kiwi:{$ns}}:cal:9:{$decisionHour}", 'sample_total'), 'the denominator is booked in the DECISION-hour bucket');

        // "Hours later": the confirmation runs now, but the receipt's
        // decision_hour anchors the outcome to the decision hour.
        self::assertSame(1, $c->confirmOutcome('hour-dec', true));
        self::assertSame('1', (string) $client->hget("{kiwi:{$ns}}:cal:9:{$decisionHour}", 'legit_count'), 'the outcome lands in the DECISION-hour bucket');
        self::assertSame('700', (string) $client->hget("{kiwi:{$ns}}:cal:9:{$decisionHour}", 'legit_score_sum'));
        self::assertSame('1', (string) $client->hget("{kiwi:{$ns}}:cal:9:{$decisionHour}", 'sample_resolved'), 'the resolution counter lands in the DECISION-hour bucket');
        self::assertSame([], $client->hgetall("{kiwi:{$ns}}:cal:9:{$nowHour}"), 'the confirmation-time bucket must stay empty');

        // The bias window reads the decision-hour bucket (the t0 window
        // spans it when it falls inside the last 24 hours).
        $windowStart = intdiv($this->t0(), 3_600_000) - AggregateCalibrator::WINDOW_HOURS + 1;
        self::assertLessThanOrEqual($decisionHour, $windowStart, 'the decision hour must be inside the 24-bucket window');
    }

    public function testAtomicConfirmConsumesReceiptExactlyOnce(): void
    {
        $client = $this->countingClient();
        $c = new AggregateCalibrator($client, namespace: 'atm' . bin2hex(random_bytes(4)), samplingMode: 'complete');
        $c->recordReceipt('atomic-1', 7, 4, RiskAction::Argon16, 100, 1, $this->decisionHour());

        // The confirm is the bucket-key pre-read + ONE atomic script (the
        // receipt delete, the ledger CAS and the bucket increment cannot be
        // split).
        $before = $client->commands;
        self::assertSame(1, $c->confirmOutcome('atomic-1', false));
        self::assertSame($before + 2, $client->commands, 'the confirm must be a pre-read GET + a single EVAL');
        self::assertNull($client->get("{kiwi:{$c->namespace()}}:cal:receipt:atomic-1"), 'the receipt must be consumed by the script');

        // A second confirm finds nothing in the pre-read: no script runs,
        // so nothing can be double-counted.
        $before = $client->commands;
        self::assertSame(0, $c->confirmOutcome('atomic-1', false), 'a consumed receipt returns status 0');
        self::assertSame($before + 1, $client->commands, 'a consumed receipt must only cost the pre-read GET, never a second EVAL');
        self::assertSame('1', (string) $client->hget($this->bucket($c, 7), 'abuse_count'), 'exactly one outcome recorded');
    }

    public function testConcurrentDoubleConfirmRecordsExactlyOnce(): void
    {
        // The Lua script executes atomically, so sequential confirms from
        // two independent calibrator instances are equivalent to
        // concurrent ones: whoever runs the script first records; the
        // other finds the receipt gone and the ledger already flipped.
        $ns = 'cc' . bin2hex(random_bytes(4));
        $a = new AggregateCalibrator($this->requireClient(), namespace: $ns, samplingMode: 'complete');
        $b = new AggregateCalibrator($this->requireClient(), namespace: $ns, samplingMode: 'complete');
        $a->recordReceipt('cc-1', 7, 4, RiskAction::Argon16, 100, 1, $this->decisionHour());

        self::assertSame(1, $a->confirmOutcome('cc-1', false));
        self::assertSame(0, $b->confirmOutcome('cc-1', false), 'the second independent confirm must find the receipt already consumed');

        self::assertSame('1', (string) $this->client->hget($this->bucket($a, 7), 'abuse_count'));
        self::assertSame('100', (string) $this->client->hget($this->bucket($a, 7), 'abuse_score_sum'));
        $ledger = json_decode((string) $this->client->get("{kiwi:{$ns}}:outcome:cc-1"), true);
        self::assertSame('A', $ledger['o'], 'the shared ledger records the outcome exactly once');
    }

    public function testConfirmLuaValidatesArgumentsBeforeDeletion(): void
    {
        $client = $this->requireClient();
        $ns = 'val' . bin2hex(random_bytes(4));
        $c = new AggregateCalibrator($client, namespace: $ns, samplingMode: 'complete');
        $script = (string) file_get_contents(dirname(__DIR__) . '/resources/confirm.lua');
        $hour = $this->decisionHour();
        $bucketKey = "{kiwi:{$ns}}:cal:1:{$hour}";

        // Invalid mode -> error reply before the DEL: the receipt survives.
        $c->recordReceipt('val-mode', 1, 1, RiskAction::Sha20, 100, 1, $hour);
        $keys = [
            "{kiwi:{$ns}}:cal:receipt:val-mode",
            $bucketKey,
            "{kiwi:{$ns}}:outcome:val-mode",
        ];
        try {
            $client->eval($script, 3, ...array_merge($keys, ['9', '1', '1', (string) AggregateCalibrator::BUCKET_TTL_SECS, (string) AggregateCalibrator::DEFAULT_OUTCOME_TTL_SECS, '1', (string) $hour]));
            self::fail('an invalid calibration mode must be refused with an error reply');
        } catch (ServerException $e) {
            self::assertStringContainsString('invalid calibration mode', $e->getMessage());
        }
        self::assertNotNull($client->get($keys[0]), 'the receipt must NOT be deleted on a validation failure');

        // Invalid weight in weighted mode (zero / non-finite) -> error
        // reply, receipt intact.
        foreach (['0', '-1', 'NaN', 'abc'] as $badWeight) {
            $c->recordReceipt('val-weight-' . $badWeight, 1, 1, RiskAction::Sha20, 100, 1, $hour);
            $keys[0] = "{kiwi:{$ns}}:cal:receipt:val-weight-" . $badWeight;
            $keys[2] = "{kiwi:{$ns}}:outcome:val-weight-" . $badWeight;
            try {
                $client->eval($script, 3, ...array_merge($keys, ['2', $badWeight, '1', (string) AggregateCalibrator::BUCKET_TTL_SECS, (string) AggregateCalibrator::DEFAULT_OUTCOME_TTL_SECS, '1', (string) $hour]));
                self::fail('an invalid calibration weight must be refused with an error reply');
            } catch (ServerException $e) {
                self::assertStringContainsString('invalid calibration weight', $e->getMessage());
            }
            self::assertNotNull($client->get($keys[0]), "the receipt must NOT be deleted on a validation failure (weight {$badWeight})");
        }

        // A valid confirmation records with status 1 (ledger CAS included).
        $c->recordReceipt('val-ok', 1, 1, RiskAction::Sha20, 100, 1, $hour);
        $keys[0] = "{kiwi:{$ns}}:cal:receipt:val-ok";
        $keys[2] = "{kiwi:{$ns}}:outcome:val-ok";
        self::assertSame(1, (int) $client->eval($script, 3, ...array_merge($keys, ['2', '2.0', '1', (string) AggregateCalibrator::BUCKET_TTL_SECS, (string) AggregateCalibrator::DEFAULT_OUTCOME_TTL_SECS, '1', (string) $hour])), 'a valid weighted confirmation records with status 1');
        self::assertNull($client->get($keys[0]), 'a valid confirmation consumes the receipt');
        $ledger = json_decode((string) $client->get($keys[2]), true);
        self::assertSame('L', $ledger['o']);
        self::assertSame(2.0, (float) $ledger['w'], 'the ledger records the actual confirmation weight');
    }

    public function testCorrectionReversesBucketCounts(): void
    {
        // An abuse confirmation at score 500 is corrected to legitimate:
        // the original contribution is reversed with the exact recorded
        // weight (abuse_count -1, abuse_score_sum -500, clamped at zero)
        // and the corrected contribution added (legit_count +1,
        // legit_score_sum +500). The ledger flips A -> L.
        $c = $this->calibrator();
        $client = $this->requireClient();
        $ns = $c->namespace();
        $hour = $this->decisionHour();
        $bucketKey = $this->bucket($c, 7, $hour);

        self::assertTrue($c->recordReceipt('corr-1', 7, 4, RiskAction::Argon16, 500, 1, $hour));
        self::assertSame(1, $c->confirmOutcome('corr-1', false), 'first confirmed as abuse');
        self::assertSame('1', (string) $client->hget($bucketKey, 'abuse_count'));
        self::assertSame('500', (string) $client->hget($bucketKey, 'abuse_score_sum'));

        self::assertTrue($c->correctOutcome('corr-1', true), 'the correction flips abuse -> legitimate');
        self::assertSame('0', (string) $client->hget($bucketKey, 'abuse_count'), 'the original abuse contribution is reversed');
        self::assertSame('0', (string) $client->hget($bucketKey, 'abuse_score_sum'));
        self::assertSame('1', (string) $client->hget($bucketKey, 'legit_count'), 'the corrected contribution is added');
        self::assertSame('500', (string) $client->hget($bucketKey, 'legit_score_sum'), 'the score sum moves with the correction');
        $ledger = json_decode((string) $client->get("{kiwi:{$ns}}:outcome:corr-1"), true);
        self::assertSame('L', $ledger['o'], 'the ledger flips to the corrected outcome');

        // Flipping back (legitimate -> abuse) reverses the legit
        // contribution and restores the abuse one.
        self::assertTrue($c->correctOutcome('corr-1', false));
        self::assertSame('0', (string) $client->hget($bucketKey, 'legit_count'));
        self::assertSame('0', (string) $client->hget($bucketKey, 'legit_score_sum'));
        self::assertSame('1', (string) $client->hget($bucketKey, 'abuse_count'));
        self::assertSame('500', (string) $client->hget($bucketKey, 'abuse_score_sum'));

        // Already carrying the target outcome -> refused.
        self::assertFalse($c->correctOutcome('corr-1', false), 'correcting to the CURRENT outcome is a no-op');

        // Unknown / never-confirmed decisions are refused too.
        self::assertFalse($c->correctOutcome('corr-missing', true));
    }

    public function testCorrectionWithWeightAppliesRecordedWeight(): void
    {
        // The reversal uses the exact weight recorded by the first
        // confirmation (ledger.w), and the correction is re-weighted with
        // the supplied weight.
        $c = new AggregateCalibrator($this->requireClient(), namespace: 'corw' . bin2hex(random_bytes(4)), samplingMode: 'weighted');
        $client = $this->requireClient();
        $ns = $c->namespace();
        $hour = $this->decisionHour();
        $bucketKey = "{kiwi:{$ns}}:cal:3:{$hour}";

        self::assertTrue($c->recordReceipt('corw-1', 3, 2, RiskAction::Sha20, 200, 1, $hour));
        self::assertSame(1, $c->confirmOutcome('corw-1', false, 10.0));
        self::assertSame('10', (string) $client->hget($bucketKey, 'abuse_count'));
        self::assertSame('2000', (string) $client->hget($bucketKey, 'abuse_score_sum'));

        // Correction with a different weight: -10 abuse (recorded weight),
        // +5 legit (the correction weight).
        self::assertTrue($c->correctOutcome('corw-1', true, 5.0));
        self::assertSame('0', (string) $client->hget($bucketKey, 'abuse_count'));
        self::assertSame('0', (string) $client->hget($bucketKey, 'abuse_score_sum'));
        self::assertSame('5', (string) $client->hget($bucketKey, 'legit_count'));
        self::assertSame('1000', (string) $client->hget($bucketKey, 'legit_score_sum'), 'score 200 x correction weight 5');
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
