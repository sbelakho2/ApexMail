<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Calibration\AggregateCalibrator;
use KiwiCaptcha\Risk\Calibration\CalibrationStore;
use KiwiCaptcha\Risk\RiskAction;
use Predis\Client;
use Predis\Command\CommandInterface;
use PHPUnit\Framework\TestCase;

/**
 * Redis-backed calibration tests (EXACT-score semantics of the canonical
 * calibration.lua + confirm.lua pair: fp_pressure = legit_score_sum,
 * fn_pressure = abuse_count*1000 - abuse_score_sum, raw = (fn-fp)*2/
 * (total*10), proportional rate limiter over milli-points; receipts carry
 * score + sampled and are consumed EXACTLY ONCE by the atomic confirm
 * script). AggregateCalibrator cases are skipped unless RISK_REDIS_URL is
 * set.
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
     * Records n confirmed outcomes at an EXACT score through the full
     * receipt -> confirm.lua path (each confirmation must return its scope).
     */
    private function recordOutcomes(AggregateCalibrator $c, int $n, int $score, bool $legit, int $scope = 1, string $prefix = 'd'): void
    {
        for ($i = 0; $i < $n; $i++) {
            $id = "{$prefix}-{$scope}-{$i}";
            $c->recordReceipt($id, $scope, intdiv(max(0, min(1000, $score)), 100), RiskAction::Sha20, $score, 1);
            self::assertSame($scope, $c->confirmOutcome($id, $legit), "outcome {$id} must be recorded against scope {$scope}");
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

    private function bucket(AggregateCalibrator $c, int $scope): string
    {
        return "{kiwi:{$c->namespace()}}:cal:{$scope}:" . intdiv($this->nowMs(), 3_600_000);
    }

    public function testEmptyScopeHasZeroBias(): void
    {
        $c = $this->calibrator();
        self::assertSame(0, $c->biasForScope(1, $this->nowMs()));
    }

    public function testExactScoreLegitHighPushesBiasDownAndIsBounded(): void
    {
        // 100 legit @ EXACT score 900: fp_pressure = legit_score_sum =
        // 90000, raw = -90000*2/1000 = -180 -> clamped to -maxAdjustment.
        $c = $this->scoreCalibrator();
        $this->recordOutcomes($c, 100, 900, true, 1, 'ex-legit');
        $t = $this->t0();
        // The first call ever seeds the rate-limit state (bias_mp = 0 /
        // ts = now) BEFORE the threshold check and returns 0 — a fresh
        // scope can never jump straight to ±maxAdjustment.
        self::assertSame(0, $c->biasForScope(1, $t));
        // The proportional ramp allows 10 points/minute: -10 after 1
        // minute, -150 after 15 minutes.
        $this->clearCache($c);
        self::assertSame(-10, $c->biasForScope(1, $t + 60_000));
        $this->clearCache($c);
        self::assertSame(-150, $c->biasForScope(1, $t + 900_000));
    }

    public function testExactScoreAbuseLowPushesBiasUpAndIsBounded(): void
    {
        // 100 abuse @ EXACT score 100: fn_pressure = abuse_count*1000 -
        // abuse_score_sum = 100000 - 10000 = 90000, raw = 180 -> clamped
        // to +maxAdjustment.
        $c = $this->scoreCalibrator();
        $this->recordOutcomes($c, 100, 100, false, 1, 'ex-abuse');
        $t = $this->t0();
        self::assertSame(0, $c->biasForScope(1, $t));
        $this->clearCache($c);
        self::assertSame(10, $c->biasForScope(1, $t + 60_000));
        $this->clearCache($c);
        self::assertSame(150, $c->biasForScope(1, $t + 900_000));
    }

    public function testPerfectSeparatorStaysNearZero(): void
    {
        // A perfectly separating classifier (legit @ score 0, abuse @
        // score 1000) contributes ~zero calibration pressure: fp = 0,
        // fn = 1000*1000 - 1000*1000 = 0 -> raw 0.
        $c = $this->scoreCalibrator();
        $this->recordOutcomes($c, 100, 0, true, 1, 'sep-l');
        $this->recordOutcomes($c, 100, 1000, false, 1, 'sep-a');
        $t = $this->t0();
        self::assertSame(0, $c->biasForScope(1, $t), 'first call ever seeds the rate-limit state and returns 0');
        $this->clearCache($c);
        self::assertSame(0, $c->biasForScope(1, $t + 900_000), 'perfect separation must keep the bias at 0 even with full movement allowance');
    }

    public function testBalancedSameScoreBiasIsZero(): void
    {
        // Balanced at the same exact score: fn = fp -> raw 0.
        $c = $this->scoreCalibrator();
        $this->recordOutcomes($c, 50, 500, true, 1, 'bal-l');
        $this->recordOutcomes($c, 50, 500, false, 1, 'bal-a');
        $t = $this->t0();
        self::assertSame(0, $c->biasForScope(1, $t));
        $this->clearCache($c);
        self::assertSame(0, $c->biasForScope(1, $t + 900_000));
    }

    public function testMixedBiasScoreSensitive(): void
    {
        // 75 abuse + 25 legit @ exact score 500: fn = 75000-37500 =
        // 37500, fp = 12500, raw = 25000*2/1000 = 50 (5 min at
        // maxChangePerMinute 10).
        $c = $this->scoreCalibrator();
        $this->recordOutcomes($c, 75, 500, false, 1, 'mix-a');
        $this->recordOutcomes($c, 25, 500, true, 1, 'mix-l');
        $t = $this->t0();
        self::assertSame(0, $c->biasForScope(1, $t));
        $this->clearCache($c);
        self::assertSame(50, $c->biasForScope(1, $t + 300_000));

        // 55 abuse + 45 legit @ exact score 500: fn = 55000-27500 =
        // 27500, fp = 22500, raw = 5000*2/1000 = 10 (1 min).
        $c = $this->scoreCalibrator();
        $this->recordOutcomes($c, 55, 500, false, 1, 'mix2-a');
        $this->recordOutcomes($c, 45, 500, true, 1, 'mix2-l');
        $t = $this->t0();
        self::assertSame(0, $c->biasForScope(1, $t));
        $this->clearCache($c);
        self::assertSame(10, $c->biasForScope(1, $t + 60_000));
    }

    public function testScopesAreIndependent(): void
    {
        $c = $this->scoreCalibrator();
        $this->recordOutcomes($c, 100, 100, false, 1, 'ind-a');
        $this->recordOutcomes($c, 100, 900, true, 2, 'ind-l');
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
        // 1000 abuse @ exact score 500: fn = 1000000-500000 = 500000,
        // raw = 1000000/10000 = 100.
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
        $this->clearCache($c);
        self::assertSame(100, $c->biasForScope(1, $t + 900_000));
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
        $this->clearCache($c);
        self::assertSame(150, $c->biasForScope(2, $t + 900_000));
    }

    public function testBelowThresholdMovesTowardZeroAtAllowedRate(): void
    {
        // Below min_samples the TARGET is 0, but the stored bias moves
        // toward 0 THROUGH the proportional rate limiter — a sample count
        // that dips below the threshold can never snap +150 → 0 instantly.
        $c = $this->scoreCalibrator();
        $ns = $c->namespace();
        $this->recordOutcomes($c, 99, 100, false, 3, 'decay');
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

        // Crossing the threshold again (100 samples): the target jumps to
        // +150, but the movement allowance counts from the LAST call's ts
        // (refreshed on every call, below threshold too) — only ~0.17
        // points are allowed, so the bias stays put, never an instant 150.
        $this->recordOutcomes($c, 1, 100, false, 3, 'decay');
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
            samplingMode: 'complete',
        );
        $this->recordOutcomes($c, 9, 100, false, 1, 'knob');
        $t = $this->t0();
        self::assertSame(0, $c->biasForScope(1, $t));
        $this->recordOutcomes($c, 10, 100, false, 2, 'knob');
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
    }

    public function testRandomSampleDiscardsUnsampledConfirmations(): void
    {
        $c = new AggregateCalibrator($this->requireClient(), namespace: 'rs' . bin2hex(random_bytes(4)), samplingMode: 'random_sample', samplingProbabilityPpm: 1_000_000);
        $ns = $c->namespace();
        $c->recordReceipt('rs-unsampled', 1, 1, RiskAction::Sha20, 100, 0);
        self::assertNull($c->confirmOutcome('rs-unsampled', false), 'an unsampled decision must be discarded, never recorded');
        self::assertSame([], $this->client->hgetall($this->bucket($c, 1)), 'no bucket fields may be written for a discarded confirmation');
        self::assertNull($this->client->get("{kiwi:{$ns}}:cal:receipt:rs-unsampled"), 'the discarded receipt must still be consumed');

        // A sampled receipt confirms normally.
        $c->recordReceipt('rs-sampled', 1, 1, RiskAction::Sha20, 100, 1);
        self::assertSame(1, $c->confirmOutcome('rs-sampled', false));
        self::assertSame('1', (string) $this->client->hget($this->bucket($c, 1), 'abuse_count'));
        self::assertSame('100', (string) $this->client->hget($this->bucket($c, 1), 'abuse_score_sum'));
    }

    public function testCompleteModeRecordsRegardlessOfSampledFlag(): void
    {
        $c = $this->calibrator();
        $c->recordReceipt('cm-unsampled', 1, 1, RiskAction::Sha20, 100, 0);
        self::assertSame(1, $c->confirmOutcome('cm-unsampled', false), 'complete mode must record even an unsampled receipt');
        self::assertSame('1', (string) $this->client->hget($this->bucket($c, 1), 'abuse_count'));
    }

    public function testWeightedModeRecordsWithSuppliedWeight(): void
    {
        $c = new AggregateCalibrator($this->requireClient(), namespace: 'wg' . bin2hex(random_bytes(4)), samplingMode: 'weighted');
        // Weight 10: every confirmed outcome counts 10 (host-supplied
        // inverse sampling probability).
        $c->recordReceipt('wg-1', 1, 1, RiskAction::Sha20, 100, 0);
        self::assertSame(1, $c->confirmOutcome('wg-1', true, 10.0));
        self::assertSame('10', (string) $this->client->hget($this->bucket($c, 1), 'legit_count'));
        self::assertSame('1000', (string) $this->client->hget($this->bucket($c, 1), 'legit_score_sum'), 'score 100 x weight 10');

        // The default weight is 1.0.
        $c->recordReceipt('wg-2', 1, 1, RiskAction::Sha20, 200, 0);
        self::assertSame(1, $c->confirmOutcome('wg-2', true));
        self::assertSame('11', (string) $this->client->hget($this->bucket($c, 1), 'legit_count'));
        self::assertSame('1200', (string) $this->client->hget($this->bucket($c, 1), 'legit_score_sum'));
    }

    public function testReceiptCarriesScoreAndSampled(): void
    {
        $c = $this->calibrator();
        $ns = $c->namespace();
        $c->recordReceipt('carry-1', 7, 4, RiskAction::Argon16, 900, 1);
        $raw = $this->client->get("{kiwi:{$ns}}:cal:receipt:carry-1");
        self::assertSame(
            ['scope' => 7, 'band' => 4, 'action' => 'argon16', 'score' => 900, 'sampled' => 1],
            json_decode((string) $raw, true),
            'the receipt must carry the exact score and the sampling flag'
        );
        self::assertSame(7, $c->confirmOutcome('carry-1', true));
        self::assertSame('1', (string) $this->client->hget($this->bucket($c, 7), 'legit_count'));
        self::assertSame('900', (string) $this->client->hget($this->bucket($c, 7), 'legit_score_sum'), 'the EXACT score must reach the bucket');
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
            samplingMode: 'complete',
        );
        $this->recordOutcomes($c, 100, 100, false, 3, 'roc');
        $t = $this->t0();

        // First call ever seeds bias_mp = 0 / ts = now before the
        // threshold check: the initial bias is 0, never ±maxAdjustment.
        self::assertSame(0, $c->biasForScope(3, $t));

        // Two calls 5 s apart move at most ~mpm/12 points (120 / 12 = 10).
        $this->clearCache($c);
        self::assertSame(10, $c->biasForScope(3, $t + 5_000));

        // 1 minute later the allowance is the full 120 points/min; the
        // raw 180 clamps to the allowance.
        $this->clearCache($c);
        self::assertSame(120, $c->biasForScope(3, $t + 60_000));

        // 1.5 minutes: allowance 180 >= raw, so maxAdjustment wins.
        $this->clearCache($c);
        self::assertSame(150, $c->biasForScope(3, $t + 90_000));

        // The window is now balanced (100 legit @ score 900 offsets the
        // abuse @ score 100: fn = fp = 90000): raw would be 0, but the
        // bias may only move DOWN by the proportional allowance (120
        // points over the elapsed minute) — never jump straight to 0.
        $this->recordOutcomes($c, 100, 900, true, 3, 'roc');
        $this->clearCache($c);
        self::assertSame(30, $c->biasForScope(3, $t + 150_000));
    }

    public function testAggregateIsOneRoundTripAndCached(): void
    {
        $client = $this->countingClient();
        $c = new AggregateCalibrator($client, namespace: 'rt' . bin2hex(random_bytes(4)), samplingMode: 'complete', minSamples: 100);
        $this->recordOutcomes($c, 100, 100, false);

        $before = $client->commands;
        self::assertSame(0, $c->biasForScope(1, $this->nowMs()), 'first call seeds the state');
        self::assertSame($before + 1, $client->commands, '24 buckets + rate clamp + state write must be ONE round trip');

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

        // A fresh outcome for the SAME scope invalidates its cached bias:
        // the next read must hit Redis again. The confirm itself is the
        // bucket pre-read GET + the atomic script.
        $c->recordReceipt('inv-fresh', 1, 1, RiskAction::Sha20, 100, 1);
        $c->confirmOutcome('inv-fresh', false);
        $c->biasForScope(1, $this->nowMs());
        self::assertSame($before + 5, $client->commands, 'confirmOutcome() must invalidate the confirmed scope cache');

        // A fresh outcome for ANOTHER scope must not invalidate this one.
        $c->recordReceipt('inv-other', 2, 1, RiskAction::Sha20, 100, 1);
        $c->confirmOutcome('inv-other', false);
        $c->biasForScope(1, $this->nowMs());
        self::assertSame($before + 8, $client->commands, 'a confirm for another scope must not invalidate this scope');
    }

    public function testReceiptTtlUsesConstructorParameter(): void
    {
        $c = new AggregateCalibrator(
            $this->requireClient(),
            namespace: 'ttl' . bin2hex(random_bytes(4)),
            receiptTtlSecs: 60,
            samplingMode: 'complete',
        );
        $c->recordReceipt('receipt-ttl-1', 1, 5, RiskAction::Sha20, 500, 1);
        $ttl = (int) $this->client->ttl("{kiwi:{$c->namespace()}}:cal:receipt:receipt-ttl-1");
        self::assertGreaterThan(0, $ttl);
        self::assertLessThanOrEqual(60, $ttl);

        // The default is the RECEIPT_TTL_SECS constant (300).
        $d = $this->calibrator();
        $d->recordReceipt('receipt-ttl-2', 1, 5, RiskAction::Sha20, 500, 1);
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

        // Full: a NEW scope evicts the oldest (scope 1) before inserting.
        $before = $client->commands;
        $c->biasForScope(2049, $this->nowMs());
        self::assertSame($before + 1, $client->commands, 'new scope past the cap must run and evict the oldest');
        $c->biasForScope(1, $this->nowMs());
        self::assertSame($before + 2, $client->commands, 'the evicted oldest scope must miss the cache');
        $c->biasForScope(1024, $this->nowMs());
        self::assertSame($before + 2, $client->commands, 'recently cached scope must still hit');
    }

    public function testAtomicConfirmConsumesReceiptExactlyOnce(): void
    {
        $client = $this->countingClient();
        $c = new AggregateCalibrator($client, namespace: 'atm' . bin2hex(random_bytes(4)), samplingMode: 'complete');
        $c->recordReceipt('atomic-1', 7, 4, RiskAction::Argon16, 100, 1);

        // The confirm is the bucket-key pre-read + ONE atomic script (the
        // receipt delete and the bucket increment cannot be split).
        $before = $client->commands;
        self::assertSame(7, $c->confirmOutcome('atomic-1', false));
        self::assertSame($before + 2, $client->commands, 'the confirm must be a pre-read GET + a single EVAL');
        self::assertNull($client->get("{kiwi:{$c->namespace()}}:cal:receipt:atomic-1"), 'the receipt must be consumed by the script');

        // A second confirm finds nothing in the pre-read: no script runs,
        // so nothing can be double-counted.
        $before = $client->commands;
        self::assertNull($c->confirmOutcome('atomic-1', false));
        self::assertSame($before + 1, $client->commands, 'a consumed receipt must only cost the pre-read GET, never a second EVAL');
        self::assertSame('1', (string) $client->hget($this->bucket($c, 7), 'abuse_count'), 'exactly one outcome recorded');
    }

    public function testConcurrentDoubleConfirmRecordsExactlyOnce(): void
    {
        // The Lua script executes atomically, so sequential confirms from
        // two INDEPENDENT calibrator instances are equivalent to
        // concurrent ones: whoever runs the script first records; the
        // other finds the receipt gone.
        $ns = 'cc' . bin2hex(random_bytes(4));
        $a = new AggregateCalibrator($this->requireClient(), namespace: $ns, samplingMode: 'complete');
        $b = new AggregateCalibrator($this->requireClient(), namespace: $ns, samplingMode: 'complete');
        $a->recordReceipt('cc-1', 7, 4, RiskAction::Argon16, 100, 1);

        self::assertSame(7, $a->confirmOutcome('cc-1', false));
        self::assertNull($b->confirmOutcome('cc-1', false), 'the second independent confirm must find the receipt already consumed');

        self::assertSame('1', (string) $this->client->hget($this->bucket($a, 7), 'abuse_count'));
        self::assertSame('100', (string) $this->client->hget($this->bucket($a, 7), 'abuse_score_sum'));
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
