<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Calibration\AggregateCalibrator;
use KiwiCaptcha\Risk\Calibration\CalibrationRecorder;
use KiwiCaptcha\Risk\Calibration\CalibrationStore;
use KiwiCaptcha\Risk\RiskAction;
use PHPUnit\Framework\TestCase;

final class CalibrationTest extends TestCase
{
    private int $clock = 0;

    private function calibrator(): AggregateCalibrator
    {
        $this->clock = 1_700_000_000;
        return new AggregateCalibrator(fn (): int => $this->clock);
    }

    private function record(AggregateCalibrator $c, int $n, float $legitRate, int $scope = 1): void
    {
        $legitCount = (int) round($n * $legitRate);
        for ($i = 0; $i < $n; $i++) {
            $c->record($scope, 5, RiskAction::Sha20, $i < $legitCount);
        }
    }

    public function testMinSamplesGate(): void
    {
        $c = $this->calibrator();
        $this->record($c, 999, 0.1);
        self::assertSame(0, $c->biasForScope(1, $this->clock));
    }

    public function testBiasComputedAfterMinSamplesWithDirectionHeld(): void
    {
        $c = $this->calibrator();
        $this->record($c, 1000, 0.1);
        // First read establishes the direction; hysteresis holds it.
        self::assertSame(0, $c->biasForScope(1, $this->clock));
        self::assertSame(0, $c->biasForScope(1, $this->clock + 599));
        // 10 minutes held -> apply, capped by max-change 10/min over ~10 min.
        self::assertSame(100, $c->biasForScope(1, $this->clock + 600));
        // Then it ratchets toward the raw target (+120) at 10/min.
        self::assertSame(110, $c->biasForScope(1, $this->clock + 601));
        self::assertSame(120, $c->biasForScope(1, $this->clock + 602));
        self::assertSame(120, $c->biasForScope(1, $this->clock + 603));
    }

    public function testBiasRangeIsBounded(): void
    {
        $c = $this->calibrator();
        $this->record($c, 1000, 0.0);
        self::assertSame(0, $c->biasForScope(1, $this->clock));
        $bias = $c->biasForScope(1, $this->clock + 600);
        self::assertLessThanOrEqual(AggregateCalibrator::BIAS_MAX, $bias);

        $c2 = $this->calibrator();
        $this->record($c2, 1000, 1.0);
        self::assertSame(0, $c2->biasForScope(1, $this->clock));
        $bias2 = $c2->biasForScope(1, $this->clock + 600);
        self::assertGreaterThanOrEqual(AggregateCalibrator::BIAS_MIN, $bias2);
        self::assertLessThan(0, $bias2);
    }

    public function testHysteresisRequiresDirectionToHold(): void
    {
        $c = $this->calibrator();
        $this->record($c, 1000, 0.1);
        self::assertSame(0, $c->biasForScope(1, $this->clock));
        self::assertSame(0, $c->biasForScope(1, $this->clock + 300));
        self::assertSame(0, $c->biasForScope(1, $this->clock + 599));
        self::assertSame(100, $c->biasForScope(1, $this->clock + 600));
    }

    public function testRetentionPrunesAfter24h(): void
    {
        $c = $this->calibrator();
        $this->record($c, 1000, 0.1);
        // Jump 25 hours: every sample is pruned, so the gate re-applies.
        self::assertSame(0, $c->biasForScope(1, $this->clock + 25 * 3600));
    }

    public function testRetentionKeepsFreshSamples(): void
    {
        $c = $this->calibrator();
        $this->record($c, 1000, 0.1);
        self::assertSame(0, $c->biasForScope(1, $this->clock));
        self::assertSame(100, $c->biasForScope(1, $this->clock + 600));
    }

    public function testScopesAreIndependent(): void
    {
        $c = $this->calibrator();
        $this->record($c, 1000, 0.1, 1);
        $this->record($c, 1000, 0.9, 2);
        self::assertSame(0, $c->biasForScope(1, $this->clock));
        self::assertSame(0, $c->biasForScope(2, $this->clock));
        self::assertSame(100, $c->biasForScope(1, $this->clock + 600));
        self::assertSame(-100, $c->biasForScope(2, $this->clock + 600));
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
        };
        $recorder = new CalibrationRecorder($store);
        $recorder->record(2, 550, RiskAction::Sha20, true);
        $recorder->record(2, 0, RiskAction::Allow, false);
        $recorder->record(2, 1000, RiskAction::Deny, false);
        self::assertSame([[2, 5, RiskAction::Sha20, true], [2, 0, RiskAction::Allow, false], [2, 10, RiskAction::Deny, false]], $captured);
    }
}
