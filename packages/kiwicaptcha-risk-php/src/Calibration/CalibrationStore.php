<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Calibration;

use KiwiCaptcha\Risk\RiskAction;

/**
 * Outcome-feedback calibration store: records whether scored requests were
 * legitimate (post-hoc, e.g. from support flags) and produces a bias
 * adjustment per scope. The bias is added to the raw risk score.
 */
interface CalibrationStore
{
    public function record(int $scope, int $band, RiskAction $action, bool $legitimate): void;

    /** Bias adjustment for a scope at `now` (epoch seconds). */
    public function biasForScope(int $scope, int $now): int;
}
