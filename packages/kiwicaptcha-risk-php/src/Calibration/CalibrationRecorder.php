<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Calibration;

use KiwiCaptcha\Risk\RiskAction;

/**
 * Maps a risk score to its band (score / 100) and records the outcome
 * with the action that was taken.
 */
final class CalibrationRecorder
{
    public function __construct(private readonly CalibrationStore $store)
    {
    }

    public function record(int $scope, int $score, RiskAction $action, bool $legitimate): void
    {
        $band = intdiv(max(0, min(1000, $score)), 100);
        $this->store->record($scope, $band, $action, $legitimate);
    }
}
