<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Calibration\AggregateCalibrator;
use KiwiCaptcha\Risk\Calibration\AggregateCalibratorV2;
use KiwiCaptcha\Risk\Calibration\ProvenanceClass;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\Outcomes\KiwiOutcomes;
use KiwiCaptcha\Risk\Outcomes\Outcome;
use KiwiCaptcha\Risk\Outcomes\OutcomeHandle;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use PHPUnit\Framework\TestCase;
use Predis\Client;

/**
 * Redis-backed calibration v2 tests: the provenance classes and their
 * frozen weights, the per-source window caps, the weighted-mean estimator
 * over clipped boundary distances and the version discovery rule. New
 * ledgers are v2; every ledger that predates the v2 store keeps v1. The
 * done-when case floods 100000 forged ConfirmedLegitimate labels through
 * every public report path — the typed outcomes API, the engine's
 * confirmed-outcome feedback path and the direct store confirmation —
 * and asserts the measured boundary shift stays within 1 point. The
 * measured number is printed. The Redis-backed cases are skipped unless
 * the Redis test URL is set.
 */
final class CalibrationV2Test extends TestCase
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

    /** A v2 store in complete sampling mode with a fast estimator (the proportional allowance never binds). */
    private function fastV2(string $namespace, int $minSamples = 1, int $cap = AggregateCalibratorV2::PER_SOURCE_WINDOW_CAP): AggregateCalibratorV2
    {
        return new AggregateCalibratorV2(
            $this->requireClient(),
            namespace: $namespace,
            minSamples: $minSamples,
            maxChangePerMinute: 100_000,
            samplingMode: 'complete',
            minimumResolutionRatio: 0.0,
            perSourceWindowCap: $cap,
        );
    }

    private function uniqueNamespace(string $prefix): string
    {
        return $prefix . bin2hex(random_bytes(4));
    }

    private function nowMs(): int
    {
        return (int) floor(microtime(true) * 1000);
    }

    private function decisionHour(): int
    {
        return intdiv($this->nowMs(), 3_600_000);
    }

    private function bucket(AggregateCalibratorV2 $c, int $scope): string
    {
        return "{kiwi:{$c->namespace()}}:cal:{$c->scopeKey($scope)}:" . $this->decisionHour();
    }

    private function hgetFloat(string $key, string $field): float
    {
        $v = $this->requireClient()->hget($key, $field);

        return is_string($v) ? (float) $v : 0.0;
    }

    private function hgetInt(string $key, string $field): int
    {
        $v = $this->requireClient()->hget($key, $field);

        return is_string($v) ? (int) $v : 0;
    }

    /** Clears the in-process 30 s bias cache so the next call hits Redis. */
    private function clearCache(AggregateCalibratorV2 $c): void
    {
        $prop = new \ReflectionProperty(AggregateCalibratorV2::class, 'biasCache');
        $prop->setValue($c, []);
    }

    public function testV2ScriptCopiesAreByteIdentical(): void
    {
        $package = dirname(__DIR__);
        $canonical = dirname($package, 2) . '/protocol/risk-v1';
        foreach (['calibration_v2.lua', 'confirm_v2.lua', 'correction_v2.lua'] as $name) {
            self::assertFileExists("{$canonical}/{$name}");
            self::assertFileEquals(
                "{$canonical}/{$name}",
                "{$package}/resources/{$name}",
                "{$name} copies must be byte-identical",
            );
        }
    }

    public function testProvenanceWeightsAreTheFrozenConstants(): void
    {
        self::assertSame(1.0, ProvenanceClass::HumanReview->weight());
        self::assertSame(0.8, ProvenanceClass::SecurityEvent->weight());
        self::assertSame(1.2, ProvenanceClass::PaymentNetwork->weight());
        self::assertSame(0, ProvenanceClass::HumanReview->value);
        self::assertSame(1, ProvenanceClass::SecurityEvent->value);
        self::assertSame(2, ProvenanceClass::PaymentNetwork->value);
        self::assertSame(100, AggregateCalibratorV2::PER_SOURCE_WINDOW_CAP);
        self::assertSame(8, AggregateCalibratorV2::MAX_REPORTING_SOURCES);
    }

    public function testV1AndV2StoresShareTheKeyLayout(): void
    {
        $ns = $this->uniqueNamespace('keyv2');
        $v1 = new AggregateCalibrator($this->requireClient(), $ns);
        $v2 = new AggregateCalibratorV2($this->requireClient(), $ns);
        self::assertSame($v1->namespace(), $v2->namespace());
        $scope = 7;
        $hour = 12345;
        self::assertSame(
            "{kiwi:{$v1->namespace()}}:cal:{$v1->scopeKey($scope)}:{$hour}",
            $this->bucketAt($v2, $scope, $hour),
        );
        self::assertSame(
            "{kiwi:{$v1->namespace()}}:cal:state:{$v1->scopeKey($scope)}",
            $this->stateAt($v2, $scope),
        );
        self::assertSame($v1->ledgerKey('d-1'), $v2->ledgerKey('d-1'));
    }

    private function bucketAt(AggregateCalibratorV2 $c, int $scope, int $hour): string
    {
        return "{kiwi:{$c->namespace()}}:cal:{$c->scopeKey($scope)}:{$hour}";
    }

    private function stateAt(AggregateCalibratorV2 $c, int $scope): string
    {
        return '{kiwi:' . $c->namespace() . '}:cal:state:' . $c->scopeKey($scope);
    }

    public function testProvenanceClassWeightsScaleTheBucketContribution(): void
    {
        $c = $this->fastV2($this->uniqueNamespace('pv2w'));
        foreach ([
            ['pv2-hr', ProvenanceClass::HumanReview, 0],
            ['pv2-se', ProvenanceClass::SecurityEvent, 1],
            ['pv2-pn', ProvenanceClass::PaymentNetwork, 2],
        ] as [$id, $class, $source]) {
            self::assertTrue($c->recordReceipt($id, 1, 6, RiskAction::Argon16, 900, 1, $this->decisionHour()));
            self::assertSame(1, $c->confirmOutcomeWithProvenance($id, true, $class, $source));
        }
        $bucket = $this->bucket($c, 1);
        self::assertEqualsWithDelta(3.0, $this->hgetFloat($bucket, 'legit_count'), 1e-9, 'the class-scaled mass lands in the v1 count field');
        self::assertEqualsWithDelta(3.0, $this->hgetFloat($bucket, 'lh2_300'), 1e-9, '1.0 + 0.8 + 1.2 at distance 300');
        self::assertSame(3, $this->hgetInt($bucket, 'n2'), 'the admitted counter is unweighted');
        self::assertSame(1, $this->hgetInt($bucket, 'sc0'));
        self::assertSame(1, $this->hgetInt($bucket, 'sc1'));
        self::assertSame(1, $this->hgetInt($bucket, 'sc2'));
        $ledger = $this->requireClient()->get($c->ledgerKey('pv2-pn'));
        self::assertIsString($ledger);
        self::assertStringContainsString('"v":3', $ledger, 'the generation-3 writer marker');
        self::assertStringContainsString('"pc":2', $ledger, 'the provenance class id');
    }

    public function testPerSourceWindowCapWithholdsCalibrationAndBooksTheOutcome(): void
    {
        // Cap 2, minSamples 3: four labels through source 1 — the first
        // two are admitted (below minSamples: no movement yet), the last
        // two are capped out. The estimator must stay at 0 because
        // capped labels contribute no admitted count.
        $c = $this->fastV2($this->uniqueNamespace('pv2c'), minSamples: 3, cap: 2);
        foreach (range(0, 3) as $i) {
            $id = "cap-{$i}";
            self::assertTrue($c->recordReceipt($id, 1, 6, RiskAction::Argon16, 1000, 1, $this->decisionHour()));
            // Beyond the caps a trust-granting label reports 4: the
            // volume cap would say 3, but the trust cap of the same
            // width binds on the L stream and withholds the reputation
            // credit outright.
            self::assertSame($i < 2 ? 1 : 4, $c->confirmOutcomeWithProvenance($id, true, ProvenanceClass::HumanReview, 1));
        }
        $bucket = $this->bucket($c, 1);
        self::assertSame(4, $this->hgetInt($bucket, 'sc1'));
        self::assertSame(2, $this->hgetInt($bucket, 'sc1c'), 'the capped-out counter');
        self::assertSame(2, $this->hgetInt($bucket, 'n2'));
        self::assertEqualsWithDelta(2.0, $this->hgetFloat($bucket, 'legit_count'), 1e-9);
        self::assertSame(0, $c->biasForScope(1, $this->nowMs()), 'capped labels must not feed the estimator');
        // Source 0 is unaffected by source 1's cap.
        self::assertTrue($c->recordReceipt('cap-other', 1, 6, RiskAction::Argon16, 1000, 1, $this->decisionHour()));
        self::assertSame(1, $c->confirmOutcomeWithProvenance('cap-other', true, ProvenanceClass::HumanReview, 0));
        // A capped label still flipped its ledger exactly once (the
        // outcome is real; only its calibration weight is withheld).
        $ledger = $this->requireClient()->get($c->ledgerKey('cap-3'));
        self::assertIsString($ledger);
        self::assertStringContainsString('"o":"L"', $ledger);
        self::assertStringContainsString('"c":0', $ledger);
        self::assertStringContainsString('"v":3', $ledger);
    }

    public function testTrustGrantingReputationIsCappedPerSourceAndPerIdentity(): void
    {
        // Per identity: three sources, one L label each, all crediting
        // the same identity — the volume cap never binds, so the third
        // status isolates the identity trust cap.
        $c = $this->fastV2($this->uniqueNamespace('tci'), minSamples: 1, cap: 2);
        $identity = str_repeat('ab', 16);
        $statuses = [];
        foreach (range(0, 2) as $i) {
            $id = "tci-{$i}";
            self::assertTrue($c->recordReceipt($id, 1, 6, RiskAction::Argon16, 900, 1, $this->decisionHour()));
            $statuses[] = $c->confirmOutcomeWithProvenance($id, true, ProvenanceClass::HumanReview, $i, null, $identity);
        }
        self::assertSame([1, 1, 4], $statuses, 'the third trust grant is capped');

        // Per source: two abuse labels fill the volume cap, then three L
        // labels — the trust cap reports 4 where the volume cap says 3.
        $s = $this->fastV2($this->uniqueNamespace('tcs'), minSamples: 1, cap: 2);
        $statuses = [];
        foreach (range(0, 4) as $i) {
            $id = "tcs-{$i}";
            self::assertTrue($s->recordReceipt($id, 1, 6, RiskAction::Argon16, 900, 1, $this->decisionHour()));
            $statuses[] = $s->confirmOutcomeWithProvenance($id, $i >= 2, ProvenanceClass::HumanReview, 7);
        }
        self::assertSame([1, 1, 3, 3, 4], $statuses);
        self::assertSame(3, $this->hgetInt($this->bucket($s, 1), 'tcs7'));
    }

    public function testHistogramFieldsFloorAFractionalReceiptScore(): void
    {
        $c = $this->fastV2($this->uniqueNamespace('flr'));
        $id = 'flr-frac';
        self::assertTrue($c->recordReceipt($id, 1, 6, RiskAction::Argon16, 0, 1, $this->decisionHour()));
        // Rewrite the receipt with a fractional score (the typed writer
        // floors before it gets here; a direct script caller does not).
        $client = $this->requireClient();
        $key = '{kiwi:' . $c->namespace() . '}:cal:receipt:' . $id;
        $raw = $client->get($key);
        self::assertIsString($raw);
        $client->set($key, str_replace('"score":0', '"score":899.5', $raw));
        self::assertSame(1, $c->confirmOutcomeWithProvenance($id, true, ProvenanceClass::HumanReview, 0));
        $bucket = $this->bucket($c, 1);
        self::assertEqualsWithDelta(1.0, $this->hgetFloat($bucket, 'lh2_299'), 1e-9);
        self::assertSame(0.0, $this->hgetFloat($bucket, 'lh2_299.5'));
        self::assertSame(0.0, $this->hgetFloat($bucket, 'lh2_300'));
    }

    public function testV1LedgersKeepV1SemanticsAndNewLedgersAreV2(): void
    {
        $ns = $this->uniqueNamespace('pv2v');
        $c = $this->fastV2($ns);
        // A ledger that predates the v2 deployment: registered by the v1
        // store (no cv field in its receipt).
        $legacy = new AggregateCalibrator($this->requireClient(), $ns, 1, 150, 100_000, samplingMode: 'complete');
        self::assertTrue($legacy->recordReceipt('legacy-1', 1, 6, RiskAction::Argon16, 900, 1, $this->decisionHour()));
        // The v2 store confirms it: version discovered at the receipt,
        // the v1 script runs, the v1 semantics hold.
        self::assertSame(1, $c->confirmOutcome('legacy-1', true));
        $bucket = $this->bucket($c, 1);
        self::assertEqualsWithDelta(1.0, $this->hgetFloat($bucket, 'legit_count'), 1e-9);
        self::assertSame(0, $this->hgetInt($bucket, 'n2'), 'a v1 confirmation never feeds the v2 estimator');
        $ledger = $this->requireClient()->get($c->ledgerKey('legacy-1'));
        self::assertIsString($ledger);
        self::assertStringContainsString('"v":2', $ledger, 'the legacy ledger keeps its v1 writer generation');
        self::assertStringNotContainsString('"pc"', $ledger);
        // A v2 receipt confirms through the v2 script.
        self::assertTrue($c->recordReceipt('fresh-1', 1, 6, RiskAction::Argon16, 900, 1, $this->decisionHour()));
        self::assertSame(1, $c->confirmOutcome('fresh-1', true));
        self::assertSame(1, $this->hgetInt($bucket, 'n2'));
        $ledger = $this->requireClient()->get($c->ledgerKey('fresh-1'));
        self::assertIsString($ledger);
        self::assertStringContainsString('"v":3', $ledger);
        self::assertStringContainsString('"pc":0', $ledger);
    }

    public function testV2CorrectionReversesAndRedoesTheV2Legs(): void
    {
        $c = $this->fastV2($this->uniqueNamespace('pv2k'));
        self::assertTrue($c->recordReceipt('corr-1', 1, 6, RiskAction::Argon16, 900, 1, $this->decisionHour()));
        self::assertSame(1, $c->confirmOutcomeWithProvenance('corr-1', true, ProvenanceClass::PaymentNetwork, 0));
        // The correction flips the outcome and reverses the v2 mass
        // (class weight 1.2 recorded on the ledger) before redoing it
        // with the same class weight. The score stays 900, so the
        // corrected abuse label carries distance 0 (900 is on the far
        // side of the boundary for an abuse label).
        self::assertTrue($c->correctOutcome('corr-1', false));
        $bucket = $this->bucket($c, 1);
        self::assertEqualsWithDelta(0.0, $this->hgetFloat($bucket, 'legit_count'), 1e-9);
        self::assertEqualsWithDelta(1.2, $this->hgetFloat($bucket, 'abuse_count'), 1e-9);
        self::assertEqualsWithDelta(0.0, $this->hgetFloat($bucket, 'lh2_300'), 1e-9);
        self::assertEqualsWithDelta(1.2, $this->hgetFloat($bucket, 'ah2_0'), 1e-9);
        self::assertSame(1, $this->hgetInt($bucket, 'n2'), 'the sample stays admitted');
        self::assertSame(0, $c->biasForScope(1, $this->nowMs()), 'both means are 0 after the flip');
        // The flip is exactly once.
        self::assertFalse($c->correctOutcome('corr-1', false));
    }

    public function testSubTenPercentErrorMassMovesTheBias(): void
    {
        $ns = $this->uniqueNamespace('pv2t');
        $c = $this->fastV2($ns, cap: 1_000_000);
        // 900 honest legit labels at score 100 (distance 0) and 100
        // forged "legitimate" labels at score 1000 (distance 400): a
        // tenth of the population misclassified, and the plain mean
        // must see it. fp_mean = 400 x 100 / 1000 = 40, error -40,
        // raw = trunc(-80 / 10) = -8.
        foreach (range(0, 899) as $i) {
            self::assertTrue($c->recordReceipt("honest-{$i}", 1, 1, RiskAction::Sha20, 100, 1, $this->decisionHour()));
            self::assertSame(1, $c->confirmOutcome("honest-{$i}", true));
        }
        foreach (range(0, 99) as $i) {
            self::assertTrue($c->recordReceipt("forge-{$i}", 1, 6, RiskAction::Argon16, 1000, 1, $this->decisionHour()));
            self::assertSame(1, $c->confirmOutcome("forge-{$i}", true));
        }
        // The first read seeds the rate-limit state and returns 0 (the
        // seeding contract); after a real sleep the allowance serves the
        // raw target in full under the fast estimator.
        self::assertSame(0, $c->biasForScope(1, $this->nowMs()), 'the first read seeds the state');
        usleep(300_000);
        $this->clearCache($c);
        self::assertSame(-8, $c->biasForScope(1, $this->nowMs()), 'a tenth of the population misclassified is visible in the bias');
        // 100 more forged labels: fp_mean = 400 x 200 / 1100 = 72.72,
        // raw = trunc(-14.54) = -14.
        foreach (range(100, 199) as $i) {
            self::assertTrue($c->recordReceipt("forge-{$i}", 1, 6, RiskAction::Argon16, 1000, 1, $this->decisionHour()));
            self::assertSame(1, $c->confirmOutcome("forge-{$i}", true));
        }
        usleep(300_000);
        $this->clearCache($c);
        self::assertSame(-14, $c->biasForScope(1, $this->nowMs()));
    }

    public function testTheEstimatorSeesTwoAndFivePercentErrorRates(): void
    {
        // Two percent: 980 honest at distance 0 plus 20 forged at
        // distance 400. fp_mean = 8000 / 1000 = 8, raw = trunc(-1.6) = -1.
        $c2 = $this->fastV2($this->uniqueNamespace('pv22'), cap: 1_000_000);
        foreach (range(0, 979) as $i) {
            self::assertTrue($c2->recordReceipt("honest2-{$i}", 1, 1, RiskAction::Sha20, 100, 1, $this->decisionHour()));
            self::assertSame(1, $c2->confirmOutcome("honest2-{$i}", true));
        }
        foreach (range(0, 19) as $i) {
            self::assertTrue($c2->recordReceipt("forge2-{$i}", 1, 6, RiskAction::Argon16, 1000, 1, $this->decisionHour()));
            self::assertSame(1, $c2->confirmOutcome("forge2-{$i}", true));
        }
        self::assertSame(0, $c2->biasForScope(1, $this->nowMs()));
        usleep(300_000);
        $this->clearCache($c2);
        self::assertSame(-1, $c2->biasForScope(1, $this->nowMs()), 'a two-percent error rate registers');

        // Five percent: 950 honest plus 50 forged (1000 total).
        // fp_mean = 20000 / 1000 = 20, raw = trunc(-4) = -4.
        $c5 = $this->fastV2($this->uniqueNamespace('pv25'), cap: 1_000_000);
        foreach (range(0, 949) as $i) {
            self::assertTrue($c5->recordReceipt("honest5-{$i}", 1, 1, RiskAction::Sha20, 100, 1, $this->decisionHour()));
            self::assertSame(1, $c5->confirmOutcome("honest5-{$i}", true));
        }
        foreach (range(0, 49) as $i) {
            self::assertTrue($c5->recordReceipt("forge5-{$i}", 1, 6, RiskAction::Argon16, 1000, 1, $this->decisionHour()));
            self::assertSame(1, $c5->confirmOutcome("forge5-{$i}", true));
        }
        self::assertSame(0, $c5->biasForScope(1, $this->nowMs()));
        usleep(300_000);
        $this->clearCache($c5);
        self::assertSame(-4, $c5->biasForScope(1, $this->nowMs()), 'a five-percent error rate registers');
    }

    public function testPaymentNetworkMassOutvotesHumanReviewMass(): void
    {
        // Two misclassified legit labels at distances 100 and 300. With
        // uniform human-review mass the mean is 200 (raw -40); naming
        // the 300-distance label payment_network pulls its mass to 1.2
        // and the estimate to (100 + 360) / 2.2 = 209.09 (raw -41): the
        // higher-trust channel dominates the blend.
        $nsUniform = $this->uniqueNamespace('pv2u');
        $uniform = $this->fastV2($nsUniform);
        self::assertTrue($uniform->recordReceipt('u-near', 1, 6, RiskAction::Argon16, 700, 1, $this->decisionHour()));
        self::assertSame(1, $uniform->confirmOutcome('u-near', true));
        self::assertTrue($uniform->recordReceipt('u-far', 1, 6, RiskAction::Argon16, 900, 1, $this->decisionHour()));
        self::assertSame(1, $uniform->confirmOutcome('u-far', true));
        $this->seedBias($uniform);
        self::assertSame(-40, $uniform->biasForScope(1, $this->nowMs()));

        $nsWeighted = $this->uniqueNamespace('pv2p');
        $weighted = $this->fastV2($nsWeighted);
        self::assertTrue($weighted->recordReceipt('w-near', 1, 6, RiskAction::Argon16, 700, 1, $this->decisionHour()));
        self::assertSame(1, $weighted->confirmOutcome('w-near', true));
        self::assertTrue($weighted->recordReceipt('w-far', 1, 6, RiskAction::Argon16, 900, 1, $this->decisionHour()));
        self::assertSame(1, $weighted->confirmOutcomeWithProvenance('w-far', true, ProvenanceClass::PaymentNetwork, 0));
        $this->seedBias($weighted);
        self::assertSame(-41, $weighted->biasForScope(1, $this->nowMs()));
    }

    /**
     * The first read seeds the rate-limit state (and returns 0); a real
     * sleep then buys the proportional allowance, so a cache-cleared
     * read serves the raw estimator target in full.
     */
    private function seedBias(AggregateCalibratorV2 $c, int $scope = 1): void
    {
        self::assertSame(0, $c->biasForScope($scope, $this->nowMs()), 'the first read seeds the state');
        usleep(300_000);
        $this->clearCache($c);
    }

    public function testTheRateLimitStateIsSharedAcrossGenerations(): void
    {
        $ns = $this->uniqueNamespace('pv2s');
        // The v1 estimator stores a +150 bias (10 abuse@100: fn_mean
        // 500, error 1000, raw 200 clamped 150).
        $v1 = new AggregateCalibrator($this->requireClient(), $ns, 1, 150, 100_000, samplingMode: 'complete');
        foreach (range(0, 9) as $i) {
            self::assertTrue($v1->recordReceipt("s1-{$i}", 1, 1, RiskAction::Sha20, 100, 0, $this->decisionHour()));
            $v1->confirmOutcome("s1-{$i}", false);
        }
        // The first-ever read seeds the state and returns 0; a cold v1
        // view after a real sleep serves the raw target in full.
        self::assertSame(0, $v1->biasForScope(1, $this->nowMs()), 'the first read seeds the state');
        usleep(300_000);
        $cold = new AggregateCalibrator($this->requireClient(), $ns, 1, 150, 100_000, samplingMode: 'complete');
        self::assertSame(150, $cold->biasForScope(1, $this->nowMs()), 'the v1 target is +150');
        // The v2 estimator reads the same state key: with a tight
        // allowance it continues from the stored value instead of
        // jumping from a fresh zero (a fresh state would serve only the
        // few points of allowance the elapsed time buys).
        usleep(300_000);
        $v2 = new AggregateCalibratorV2(
            $this->requireClient(),
            namespace: $ns,
            minSamples: 1,
            maxChangePerMinute: 60,
            samplingMode: 'complete',
            minimumResolutionRatio: 0.0,
        );
        $bias = $v2->biasForScope(1, $this->nowMs());
        self::assertGreaterThanOrEqual(100, $bias, "the v2 read must continue from the v1-stored bias, got {$bias}");
        self::assertLessThanOrEqual(150, $bias);
    }

    private function stateAtV1(AggregateCalibrator $c, int $scope = 1): string
    {
        return '{kiwi:' . $c->namespace() . '}:cal:state:' . $c->scopeKey($scope);
    }

    /**
     * The done-when: 100000 forged ConfirmedLegitimate labels through
     * every public report path — the typed outcomes API, the engine's
     * confirmed-outcome feedback path and the direct store confirmation
     * — move the calibration bias at most 1 point. The measured shift is
     * printed.
     */
    public function testHundredThousandForgedLabelsMoveTheBiasAtMostOnePoint(): void
    {
        $ns = $this->uniqueNamespace('pv2done');
        $direct = $this->fastV2($ns, minSamples: 1000);
        $before = $direct->biasForScope(1, $this->nowMs());

        // The engine composition: the v2 store attaches through the same
        // constructor hook the v1 store uses.
        $engineStore = new RedisRiskStateStore($this->requireClient(), $ns);
        $keys = RiskKeys::fromMaster(str_repeat(chr(0x42), 32));
        $engine = new AdaptiveRiskEngine(
            store: $engineStore,
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
            calibration: $this->fastV2($ns, minSamples: 1000),
        );
        $marksStore = new RedisRiskStateStore($this->requireClient(), $ns);
        $outcomes = new KiwiOutcomes($engine, $marksStore);
        $context = static fn (): RiskContext => new RiskContext(
            scope: 1,
            sourceIp: '203.0.113.27',
            sessionId: null,
            principalId: null,
            event: RiskEventKind::ConfirmedLegitimate,
            networkFlags: (new CidrNetworkClassifier([]))->classify('203.0.113.27'),
            resources: new ResourcePressure(1000, 1000),
        );

        $total = 100_000;
        $viaOutcomesApi = intdiv($total, 3);
        $viaFeedback = intdiv($total, 3);
        for ($i = 0; $i < $total; $i++) {
            $id = "forge-{$i}";
            // The forged decision: score 1000, the far side of the
            // boundary T=600, so every label carries distance 400.
            self::assertTrue($direct->recordReceipt($id, 1, 6, RiskAction::Argon16, 1000, 1, $this->decisionHour()));
            if ($i < $viaOutcomesApi) {
                // Path 1: the typed outcomes API.
                $receipt = $outcomes->report(
                    Outcome::ConfirmedLegitimate,
                    OutcomeHandle::decisionId($id),
                    "idem-{$i}",
                    $context(),
                );
                self::assertNotSame(0, $receipt->status, 'every forged label is a first confirmation');
            } elseif ($i < $viaOutcomesApi + $viaFeedback) {
                // Path 2: the engine's confirmed-outcome feedback path
                // (record_feedback rejects confirmed events by design;
                // confirmedLegitimate is its calibration-carrying
                // wrapper, which swallows the confirm status). The
                // reputation event is booked only while the trust caps
                // admit the label; the outcome itself always lands, and
                // the bias bound below is the assertion that matters.
                $engine->confirmedLegitimate($context(), $id, "idem-{$i}");
            } else {
                // Path 3: the direct store confirmation.
                $status = $direct->confirmOutcome($id, true);
                self::assertNotSame(0, $status, 'every forged label is a first confirmation');
            }
        }

        $this->clearCache($direct);
        $after = $direct->biasForScope(1, $this->nowMs());
        $shift = $after - $before;
        // The ground truth from the buckets: admitted samples (n2) and
        // capped-out samples (the per-source capped counter). All three
        // paths report on the default source slot, so the one shared cap
        // bounds the total admission to a single window. The flood can
        // span an hour boundary, so the counters are summed over the
        // current and the previous hourly bucket (a long flood cannot
        // reach further back).
        $hour = intdiv($this->nowMs(), 3_600_000);
        $admitted = 0;
        $capped = 0;
        foreach ([$hour, $hour - 1] as $h) {
            $bucket = $this->bucketAt($direct, 1, $h);
            $admitted += $this->hgetInt($bucket, 'n2');
            $capped += $this->hgetInt($bucket, 'sc0c');
        }
        $bucket = $this->bucket($direct, 1);
        printf(
            'done-when: 100000 forged labels through 3 report paths (admitted %d, capped %d): measured boundary shift %d point(s) (bias %d -> %d)' . "\n",
            $admitted,
            $capped,
            $shift,
            $before,
            $after,
        );
        self::assertLessThanOrEqual(1, abs($shift), "100000 forged labels moved the bias by {$shift} points");
        // The mechanism, not just the number: the shared per-source cap
        // admitted at most one window for the default source, and every
        // other label was capped out with its outcome still booked.
        self::assertLessThanOrEqual(AggregateCalibratorV2::PER_SOURCE_WINDOW_CAP, $admitted, 'the cap must bound the admission');
        self::assertSame($total - $admitted, $capped, 'every non-admitted label must be capped out');
        // The estimator never woke: the admitted volume stays below the
        // minSamples gate.
        self::assertLessThan(1000, $admitted);
    }
}
