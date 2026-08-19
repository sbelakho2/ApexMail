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

    /** @var array<string, array{scope: int, hour: int, status: int}> the outcome ledger */
    public array $ledger = [];

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

    public function registerOutcome(string $decisionId, int $scope, int $decisionHour, int $score): bool
    {
        if (isset($this->ledger[$decisionId])) {
            return false;
        }
        $this->ledger[$decisionId] = ['scope' => $scope, 'hour' => $decisionHour, 'score' => $score, 'status' => 0];

        return true;
    }

    public function confirmOutcome(string $decisionId, bool $legitimate): int
    {
        $entry = $this->ledger[$decisionId] ?? null;
        if ($entry === null) {
            return 0;
        }
        if ($entry['status'] !== 0) {
            return 0;
        }
        $this->ledger[$decisionId]['status'] = 1;

        return 1;
    }

    public function correctOutcome(string $decisionId, bool $legitimate): bool
    {
        $entry = $this->ledger[$decisionId] ?? null;
        if ($entry === null || $entry['status'] === 2) {
            return false;
        }
        $this->ledger[$decisionId]['status'] = 2;

        return true;
    }

    /**
     * In-memory SET NX semantics: the FIRST risk-v2 client-context tag a
     * session pseudonym presents is recorded and returned forever (the
     * engine derives the session-consistency signal from the comparison).
     *
     * @var array<string, string>
     */
    public array $contextTags = [];

    public function sessionFirstContextTag(string $sessionId, string $tag): ?string
    {
        return $this->contextTags[$sessionId] ??= $tag;
    }
}
