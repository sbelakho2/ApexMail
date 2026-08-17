<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\RiskStateStoreInterface;

/**
 * Shared store stub for the engine tests: the outcome-ledger methods are
 * RECORDING stubs (default first-confirmation status 1) so the
 * headline contract — ConfirmedLegitimate/ConfirmedAbuse work identically
 * with or without calibration — is exercised against the ledger, never
 * against silent no-ops. Anonymous test classes extend it and override
 * observe() (and optionally the ledger behavior via the public hooks).
 */
abstract class RiskStateStoreStub implements RiskStateStoreInterface
{
    /** Status returned by confirmOutcome(): 1 = first confirmation. */
    public int $confirmOutcomeStatus = 1;

    /** @var list<array{0: string, 1: string, 2?: int|bool, 3?: int}> ledger calls */
    public array $ledgerCalls = [];

    public function registerOutcome(string $decisionId, int $scope, int $decisionHour, int $score): bool
    {
        $this->ledgerCalls[] = ['register', $decisionId, $scope, $decisionHour, $score];
        return true;
    }

    public function confirmOutcome(string $decisionId, bool $legitimate): int
    {
        $this->ledgerCalls[] = ['confirm', $decisionId, $legitimate];
        return $this->confirmOutcomeStatus;
    }

    public function correctOutcome(string $decisionId, bool $legitimate): bool
    {
        $this->ledgerCalls[] = ['correct', $decisionId, $legitimate];
        return true;
    }
}
