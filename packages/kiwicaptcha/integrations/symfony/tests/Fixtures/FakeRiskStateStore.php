<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\RiskStateStoreInterface;
use KiwiCaptcha\Risk\Storage\RiskStoreException;

/**
 * In-memory risk state store for the adaptive-risk integration tests: returns
 * a caller-controlled SignalVector and records every observation, so tests
 * can drive decisions (allow/deny/escalation) and assert the engine's
 * PRE-ISSUE / POST-SOLVE event feed without Redis.
 */
final class FakeRiskStateStore implements RiskStateStoreInterface
{
    /** @var list<RiskObservation> */
    public array $observations = [];

    /** When true, observe() throws (simulates a state backend outage). */
    public bool $throwing = false;

    public function __construct(private ?SignalVector $vector = null)
    {
    }

    public function setVector(SignalVector $vector): void
    {
        $this->vector = $vector;
    }

    public function observe(RiskObservation $observation): SignalVector
    {
        if ($this->throwing) {
            throw new RiskStoreException('simulated risk state backend outage');
        }
        $this->observations[] = $observation;

        return $this->vector ?? SignalVector::zero();
    }
}
