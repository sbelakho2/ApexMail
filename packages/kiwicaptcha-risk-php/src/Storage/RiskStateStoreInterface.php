<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\SignalVector;

/**
 * Risk state store: atomically applies an observation and returns the
 * resulting SignalVector.
 */
interface RiskStateStoreInterface
{
    /**
     * Applies the observation exactly once (event_id dedupe) and returns
     * the current signal vector.
     *
     * A duplicate event_id is a documented no-op that returns the empty
     * vector; the engine's degraded path is NOT triggered.
     *
     * @throws RiskStoreException when the underlying state backend fails
     */
    public function observe(RiskObservation $observation): SignalVector;
}
