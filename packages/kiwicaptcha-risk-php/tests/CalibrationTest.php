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
 * Redis-backed calibration tests. AggregateCalibrator cases are skipped
 * unless RISK_REDIS_URL is set; the recorder interface test runs always.
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

    public function testAllAbuseBiasIsPositiveAndBounded(): void
    {
        $c = $this->calibrator();
        $this->record($c, 1000, false);
        // raw = ((1000 - 0) * 1000 / 1000) * 2 / 10 = 200 -> clamped to
        // the constructor maxAdjustment (+150).
        self::assertSame(150, $c->biasForScope(1, $this->nowMs()));
    }

    public function testAllLegitBiasIsNegativeAndBounded(): void
    {
        $c = $this->calibrator();
        $this->record($c, 1000, true);
        self::assertSame(-150, $c->biasForScope(1, $this->nowMs()));
    }

    public function testBalancedBiasIsZero(): void
    {
        $c = $this->calibrator();
        $this->record($c, 500, true);
        $this->record($c, 500, false);
        self::assertSame(0, $c->biasForScope(1, $this->nowMs()));
    }

    public function testMixedBiasIntegerMath(): void
    {
        $c = $this->calibrator();
        // 750 abuse, 250 legit: ((500 * 1000) / 1000) * 2 / 10 = 100
        $this->record($c, 750, false);
        $this->record($c, 250, true);
        self::assertSame(100, $c->biasForScope(1, $this->nowMs()));

        // 550 abuse, 450 legit: ((100 * 1000) / 1000) * 2 / 10 = 20
        $c = $this->calibrator();
        $this->record($c, 550, false);
        $this->record($c, 450, true);
        self::assertSame(20, $c->biasForScope(1, $this->nowMs()));
    }

    public function testScopesAreIndependent(): void
    {
        $c = $this->calibrator();
        $this->record($c, 1000, false, 5, RiskAction::Sha20, 1);
        $this->record($c, 1000, true, 5, RiskAction::Sha20, 2);
        self::assertSame(150, $c->biasForScope(1, $this->nowMs()));
        self::assertSame(-150, $c->biasForScope(2, $this->nowMs()));
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

        // 1000 abuse in-window -> bias +150; the 25-hours-old bucket is
        // outside the 24-hour window and contributes nothing.
        self::assertSame(150, $c->biasForScope(1, $nowMs));
    }

    public function testBelowMinSamplesIsZero(): void
    {
        $c = $this->calibrator();
        $this->record($c, 999, false, 5, RiskAction::Sha20, 1);
        self::assertSame(0, $c->biasForScope(1, $this->nowMs()), 'no nonzero bias below minSamples');

        // At the threshold the bias appears (fresh scope: no rate-limit
        // state, so the first-ever value is written unclamped).
        $this->record($c, 1000, false, 5, RiskAction::Sha20, 2);
        self::assertSame(150, $c->biasForScope(2, $this->nowMs()));
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
        $this->record($c, 9, false, 5, RiskAction::Sha20, 1);
        self::assertSame(0, $c->biasForScope(1, $this->nowMs()));
        $this->record($c, 10, false, 5, RiskAction::Sha20, 2);
        // raw 200 -> clamped to the custom maxAdjustment 25.
        self::assertSame(25, $c->biasForScope(2, $this->nowMs()));

        $this->expectException(\InvalidArgumentException::class);
        new AggregateCalibrator($this->requireClient(), namespace: 'bad' . bin2hex(random_bytes(4)), minSamples: 0);
    }

    public function testRateOfChangeClamp(): void
    {
        $c = $this->calibrator();
        $this->record($c, 1000, false, 5, RiskAction::Sha20, 3);
        $now = $this->nowMs();
        self::assertSame(150, $c->biasForScope(3, $now));

        // The window is now balanced: raw would be 0, but the bias may move
        // by only maxChangePerMinute per elapsed minute (10 * 1 = 10).
        $this->record($c, 1000, true, 5, RiskAction::Sha20, 3);
        $this->clearCache($c);
        self::assertSame(140, $c->biasForScope(3, $now + 60_000));

        // 9 more minutes: the allowed jump is 10 * 9 = 90 below the
        // previous 140 -> 50.
        $this->clearCache($c);
        self::assertSame(50, $c->biasForScope(3, $now + 600_000));
    }

    public function testAggregateIsOneRoundTripAndCached(): void
    {
        $client = $this->countingClient();        $c = new AggregateCalibrator($client, namespace: 'rt' . bin2hex(random_bytes(4)));
        $this->record($c, 1000, false);

        $before = $client->commands;
        self::assertSame(150, $c->biasForScope(1, $this->nowMs()));
        self::assertSame($before + 1, $client->commands, '24 buckets + rate clamp + state write must be ONE round trip');

        self::assertSame(150, $c->biasForScope(1, $this->nowMs()));
        self::assertSame($before + 1, $client->commands, 'cache hit must not touch Redis');
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
