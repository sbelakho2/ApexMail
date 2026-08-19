<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\RiskStateStoreInterface;
use KiwiCaptcha\Risk\Storage\SessionContextTagStoreInterface;
use KiwiCaptcha\Risk\Storage\SessionTlsTagStoreInterface;

/**
 * Shared store stub for the engine tests: the outcome-ledger methods are
 * RECORDING stubs (default first-confirmation status 1) so the
 * headline contract — ConfirmedLegitimate/ConfirmedAbuse work identically
 * with or without calibration — is exercised against the ledger, never
 * against silent no-ops. Anonymous test classes extend it and override
 * observe() (and optionally the ledger behavior via the public hooks).
 * The stub implements the OPTIONAL risk-v2 session-first-tag capability
 * interfaces so the v2 engine tests keep exercising the record surface.
 */
abstract class RiskStateStoreStub implements RiskStateStoreInterface, SessionContextTagStoreInterface, SessionTlsTagStoreInterface
{
    /** Status returned by confirmOutcome(): 1 = first confirmation. */
    public int $confirmOutcomeStatus = 1;

    /** @var list<array{0: string, 1: string, 2?: int|bool, 3?: int}> ledger calls */
    public array $ledgerCalls = [];

    /** @var array<string, string> first-seen risk-v2 client-context tags keyed by session pseudonym */
    public array $contextTags = [];

    /** @var array<string, string> first-seen risk-v2 trusted-edge TLS tags keyed by session pseudonym */
    public array $tlsTags = [];

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

    /**
     * In-memory SET NX semantics: the FIRST tag a session pseudonym
     * presents is recorded and returned forever.
     */
    public function sessionFirstContextTag(string $sessionId, string $tag): ?string
    {
        return $this->contextTags[$sessionId] ??= $tag;
    }

    /**
     * In-memory SET NX semantics for the trusted-edge TLS record: the
     * FIRST tag a session pseudonym presents is recorded and returned
     * forever.
     */
    public function sessionFirstTlsTag(string $sessionId, string $tag): ?string
    {
        return $this->tlsTags[$sessionId] ??= $tag;
    }
}
