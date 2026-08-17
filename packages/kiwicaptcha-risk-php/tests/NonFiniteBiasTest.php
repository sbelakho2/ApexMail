<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Calibration\AggregateCalibrator;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\SignalVector;
use Predis\Client;
use PHPUnit\Framework\TestCase;

/**
 * NON-FINITE RISK GUARDS: every float boundary in the
 * scoring/calibration path must produce a BOUNDED integer output — never
 * NaN, never lower-risk-than-max.
 *
 * Boundaries audited:
 *   (a) the PHP calibrator's bias conversion (float → int): NaN/±Inf from
 *       a corrupted bucket value must map to +maxAdjustment (fail high,
 *       never 0 — a plain `(int)` cast maps both NaN and Inf to 0);
 *   (b) the resolution-ratio division (resolved/total): total 0 → 0.0;
 *       the ratio is integer-division-derived (always finite) with a
 *       defensive non-finite guard;
 *   (c) the SCORE is pure integer math (intdiv in RiskScorer) — there is
 *       no float boundary; verified + documented here.
 *
 * The canonical calibration.lua guards its own output (non-finite
 * final_mp → +max_adjustment*1000), so these Redis cases exercise the
 * FULL guard chain (corrupted state → Lua guard → bounded integer reply →
 * PHP conversion clamp).
 */
final class NonFiniteBiasTest extends TestCase
{
    private ?Client $client = null;

    protected function setUp(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if (is_string($url) && $url !== '') {
            $this->client = AggregateCalibrator::createClient($url);
        }
    }

    private function requireClient(): Client
    {
        if ($this->client === null) {
            self::markTestSkipped('RISK_REDIS_URL not set; start redis with: docker run -d -p 6399:6379 redis:7-alpine');
        }
        return $this->client;
    }

    private function calibrator(int $minSamples, string $mode = 'complete', int $maxChangePerMinute = 10): AggregateCalibrator
    {
        $this->requireClient();
        return new AggregateCalibrator($this->client, namespace: 'nf' . bin2hex(random_bytes(4)), minSamples: $minSamples, samplingMode: $mode, maxChangePerMinute: $maxChangePerMinute);
    }

    private function nowMs(): int
    {
        return (int) floor(microtime(true) * 1000);
    }

    private function hour(): int
    {
        return intdiv($this->nowMs(), 3_600_000);
    }

    private function bucketKey(AggregateCalibrator $c, int $scope): string
    {
        return "{kiwi:{$c->namespace()}}:cal:{$scope}:{$this->hour()}";
    }

    private function stateKey(AggregateCalibrator $c, int $scope): string
    {
        return "{kiwi:{$c->namespace()}}:cal:state:{$scope}";
    }

    /** Drops the in-process 30 s bias cache so the next call hits Redis. */
    private function clearCache(AggregateCalibrator $c): void
    {
        $prop = new \ReflectionProperty(AggregateCalibrator::class, 'biasCache');
        $prop->setValue($c, []);
    }

    /**
     * (a) Property test of the PHP conversion boundary: feeding NaN, ±Inf,
     * -0.0, overflow and extreme values MUST yield a bounded integer —
     * non-finite maps to exactly +maxAdjustment (fail high), everything
     * else clamps to ±maxAdjustment.
     */
    public function testBiasConversionBoundaryIsBoundedForNonFiniteInputs(): void
    {
        foreach ([150, 1, 10, 1000] as $maxAdjustment) {
            foreach ([NAN, INF, -INF] as $nonFinite) {
                $bias = AggregateCalibrator::toBoundedBias($nonFinite, $maxAdjustment);
                self::assertIsInt($bias, 'non-finite raw bias must map to a bounded int');
                self::assertSame($maxAdjustment, $bias, 'non-finite must fail HIGH to +maxAdjustment, never 0');
            }
            foreach ([-0.0, 0.0, 0, '0', 150.0, 150.9, -150.9, '150', '1e999', 1e300, -1e300, PHP_INT_MAX, PHP_INT_MIN, 1e9, -1e9] as $raw) {
                $bias = AggregateCalibrator::toBoundedBias($raw, $maxAdjustment);
                self::assertIsInt($bias, 'every finite raw bias must map to an int');
                self::assertGreaterThanOrEqual(-$maxAdjustment, $bias, 'bounded below');
                self::assertLessThanOrEqual($maxAdjustment, $bias, 'bounded above');
            }
        }
    }

    /**
     * (a) Integration: a corrupted bucket value ("1e999" — Lua 5.1
     * tonumber = +Inf) makes fp_mean = Inf/Inf = NaN; the Lua guard maps
     * the NaN final_mp to +max_adjustment*1000 and the PHP conversion
     * yields exactly +maxAdjustment — never 0, never an eval error.
     */
    public function testCorruptedBucketNaNPathsFailHighToPlusMaxAdjustment(): void
    {
        $c = $this->calibrator(minSamples: 100);
        $client = $this->requireClient();
        $scope = 1;

        // NaN path: legit_score_sum = Inf and legit_count = Inf ->
        // fp_mean = NaN -> raw = NaN -> final_mp = NaN -> guard -> +150.
        $client->hset($this->bucketKey($c, $scope), 'legit_count', '1e999');
        $client->hset($this->bucketKey($c, $scope), 'legit_score_sum', '1e999');

        self::assertSame(150, $c->biasForScope($scope, $this->nowMs()), 'NaN must fail HIGH to +maxAdjustment (never 0)');
        $this->clearCache($c);
        self::assertSame(150, $c->biasForScope($scope, $this->nowMs()), 'the guarded bias must be stable across re-reads');
    }

    /**
     * (a) Integration: corrupted bucket value "1e999" with a finite count
     * (fp_mean = +Inf -> error = -Inf) clamps at the raw -maxAdjustment
     * clamp inside the script — bounded int output, never NaN. The rate
     * window is pre-seeded so the proportional allowance (maxChangePerMinute
     * 1e6 over 60 s >> 150) does not clamp the first call to 0.
     */
    public function testCorruptedBucketNegativeInfClampsToMinusMaxAdjustment(): void
    {
        $c = $this->calibrator(minSamples: 100, maxChangePerMinute: 1_000_000);
        $client = $this->requireClient();
        $scope = 2;

        $client->hset($this->bucketKey($c, $scope), 'legit_count', '100');
        $client->hset($this->bucketKey($c, $scope), 'legit_score_sum', '1e999');
        // Seed bias_mp = 0 / ts = Redis now - 60 s: the allowance is
        // 1_000_000 * 1000 * 60000 / 60000 = 1e9 milli-points >> 150 points.
        $client->hset($this->stateKey($c, $scope), 'bias_mp', '0');
        $client->hset($this->stateKey($c, $scope), 'ts', (string) ((int) $client->time()[0] * 1000 - 60_000));

        $bias = $c->biasForScope($scope, $this->nowMs());
        self::assertIsInt($bias);
        self::assertSame(-150, $bias, 'a +Inf fp_mean (error -Inf) must clamp to -maxAdjustment (bounded, never NaN)');
    }

    /**
     * (a) Integration: corrupted rate-limit STATE (bias_mp = "1e999" ->
     * +Inf) drags final_mp to +Inf through the lower clamp even when the
     * target is 0 (below minSamples) — the Lua guard must fail HIGH to
     * +maxAdjustment, never return the target 0.
     */
    public function testCorruptedStateInfNeverMapsToZero(): void
    {
        $c = $this->calibrator(minSamples: 1_000_000_000); // target stays 0
        $client = $this->requireClient();
        $scope = 3;

        $client->hset($this->stateKey($c, $scope), 'bias_mp', '1e999');
        $client->hset($this->stateKey($c, $scope), 'ts', (string) ((int) $client->time()[0] * 1000));

        self::assertSame(150, $c->biasForScope($scope, $this->nowMs()), 'a corrupted +Inf bias_mp must fail HIGH to +maxAdjustment, never the 0 target');
    }

    /**
     * (b) The resolution-ratio division is integer-derived: total 0 -> 0.0,
     * extreme ints stay finite; the defensive guard never yields NaN.
     */
    public function testResolutionRatioDivisionIsAlwaysFinite(): void
    {
        $c = $this->calibrator(minSamples: 100);
        $client = $this->requireClient();
        $scope = 4;
        $key = $this->bucketKey($c, $scope);

        // Empty buckets -> total 0 -> ratio exactly 0.0.
        $metrics = $c->samplingMetrics($scope, $this->nowMs());
        self::assertSame(0, $metrics['sampledTotal']);
        self::assertSame(0.0, $metrics['resolutionRatio']);

        // Extreme integer counters: the ratio stays finite and in [0, 1].
        $client->hset($key, 'sample_total', (string) PHP_INT_MAX);
        $client->hset($key, 'sample_resolved', (string) PHP_INT_MAX);
        $metrics = $c->samplingMetrics($scope, $this->nowMs());
        // The canonical script clamps corrupted totals at MAX_SAMPLE_COUNTER
        // (1e9) — the int cast of an out-of-range float is UB pre-PHP-8.5.
        self::assertSame(1_000_000_000, $metrics['sampledTotal']);
        self::assertSame(1.0, $metrics['resolutionRatio']);
        self::assertTrue(is_finite($metrics['resolutionRatio']), 'the ratio must never be NaN/Inf');

        $client->hset($key, 'sample_resolved', '0');
        $metrics = $c->samplingMetrics($scope, $this->nowMs());
        self::assertSame(0.0, $metrics['resolutionRatio'], 'resolved 0 -> ratio 0.0');
    }

    /**
     * (c) The SCORE is integer math (intdiv) — there is no float boundary
     * in the scorer. Verified: extreme signal vectors always produce an
     * int score in 0..1000 (never NaN — PHP ints cannot be NaN).
     */
    public function testScoreIsPureIntegerMathWithNoFloatBoundary(): void
    {
        $scorer = new RiskScorer();
        $weights = new RiskWeights();
        $extreme = SignalVector::fromArray([
            'source_fast' => 1000, 'source_slow' => 1000, 'subnet_fast' => 1000,
            'issue_debt' => 1000, 'bad_proof' => 1000, 'malformed' => 1000,
            'replay' => 1000, 'action_failure' => 1000, 'scope_switch' => 1000,
            'global_pressure' => 1000, 'network_risk' => 1000,
            'trust_credit' => 1000, 'principal_credit' => 1000,
        ]);
        $score = $scorer->score(1000, $extreme, $weights);
        self::assertIsInt($score, 'the score is integer math (intdiv) — no float boundary');
        self::assertGreaterThanOrEqual(0, $score);
        self::assertLessThanOrEqual(1000, $score);
        self::assertSame(1000, $scorer->score(0, $extreme, $weights), 'saturation reaches the cap');
    }
}
