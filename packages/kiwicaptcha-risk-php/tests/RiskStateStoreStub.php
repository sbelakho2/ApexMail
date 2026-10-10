<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\OutcomeMarksStoreInterface;
use KiwiCaptcha\Risk\Storage\RiskStateStoreInterface;
use KiwiCaptcha\Risk\Storage\SessionContextTagStoreInterface;
use KiwiCaptcha\Risk\Storage\SessionTlsTagStoreInterface;

/**
 * Shared store stub for the engine tests: the outcome-ledger methods are
 * recording stubs (default first-confirmation status 1) so the
 * headline contract — ConfirmedLegitimate/ConfirmedAbuse work identically
 * with or without calibration — is exercised against the ledger, never
 * against silent no-ops. Anonymous test classes extend it and override
 * observe() (and optionally the ledger behavior via the public hooks).
 * The stub implements the optional risk-v2 session-first-tag capability
 * interfaces so the v2 engine tests keep exercising the record surface,
 * and the long-memory mark surface (in-memory) so the typed outcomes
 * tests exercise report()/forget() without a backend.
 */
abstract class RiskStateStoreStub implements RiskStateStoreInterface, SessionContextTagStoreInterface, SessionTlsTagStoreInterface, OutcomeMarksStoreInterface, \KiwiCaptcha\Risk\Storage\TargetStateStoreInterface
{
    /** Status returned by confirmOutcome(): 1 = first confirmation. */
    public int $confirmOutcomeStatus = 1;

    /** @var list<array{0: string, 1: string, 2?: int|bool, 3?: int}> ledger calls */
    public array $ledgerCalls = [];

    /** @var array<string, string> first-seen risk-v2 client-context tags keyed by session pseudonym */
    public array $contextTags = [];

    /** @var array<string, string> first-seen risk-v2 trusted-edge TLS tags keyed by session pseudonym */
    public array $tlsTags = [];

    /** @var array<string, array{kind: string, last_kind: string, count: int, first_ms: int, last_ms: int}> marks keyed by "dim:id" */
    public array $marks = [];

    /** @var array<string, true> consumed mark event ids keyed by "dim:id:event" */
    public array $seenMarkEvents = [];

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
     * In-memory SET NX semantics: the first tag a session pseudonym
     * presents is recorded and returned forever.
     */
    public function sessionFirstContextTag(string $sessionId, string $tag): ?string
    {
        return $this->contextTags[$sessionId] ??= $tag;
    }

    /**
     * In-memory SET NX semantics for the trusted-edge TLS record: the
     * first tag a session pseudonym presents is recorded and returned
     * forever.
     */
    public function sessionFirstTlsTag(string $sessionId, string $tag): ?string
    {
        return $this->tlsTags[$sessionId] ??= $tag;
    }

    public function markKey(string $dimension, string $id): string
    {
        return "mark:{kiwi:test}:{$dimension}:{$id}";
    }

    public function writeMark(string $dimension, string $id, string $kind, int $nowMs, string $eventId = ''): int
    {
        $key = "{$dimension}:{$id}";
        if ($eventId !== '') {
            $dedupe = "{$dimension}:{$id}:{$eventId}";
            if (isset($this->seenMarkEvents[$dedupe])) {
                return $this->marks[$key]['count'] ?? 0;
            }
            $this->seenMarkEvents[$dedupe] = true;
        }
        $existing = $this->marks[$key] ?? null;
        $keptKind = $existing['kind'] ?? $kind;
        if (self::markKindSeverity($kind) > self::markKindSeverity($keptKind)) {
            $keptKind = $kind;
        }
        $this->marks[$key] = [
            'kind' => $keptKind,
            'last_kind' => $kind,
            'count' => ($existing['count'] ?? 0) + 1,
            'first_ms' => $existing['first_ms'] ?? $nowMs,
            'last_ms' => $nowMs,
        ];

        return $this->marks[$key]['count'];
    }

    /**
     * The frozen mark-kind severity ranks (mirrors marks.lua).
     */
    public static function markKindSeverity(string $kind): int
    {
        return match ($kind) {
            'spamReported' => 1,
            'accountBanned' => 2,
            'fraudConfirmed' => 3,
            'chargeback' => 4,
            default => 0,
        };
    }

    public function readMark(string $dimension, string $id): ?array
    {
        return $this->marks["{$dimension}:{$id}"] ?? null;
    }

    /** @var array<string, array{fails: int, spread_sources: int, spread_asns: int, first_ms: int, last_ms: int}> */
    public array $targetState = [];

    /** @var array<string, array<string, true>> */
    public array $targetSpread = [];

    public function registerTargetFailure(string $targetId, string $source, string $asn): array
    {
        $entry = $this->targetState[$targetId] ?? ['fails' => 0, 'spread_sources' => 0, 'spread_asns' => 0, 'first_ms' => 0, 'last_ms' => 0];
        $entry['fails'] += 1;
        $entry['last_ms'] = (int) floor(microtime(true) * 1000);
        if ($entry['first_ms'] === 0) {
            $entry['first_ms'] = $entry['last_ms'];
        }
        $set = $this->targetSpread[$targetId] ?? [];
        if ($source !== '') {
            $set["src:$source"] = true;
        }
        if ($asn !== '') {
            $set["asn:$asn"] = true;
        }
        $this->targetSpread[$targetId] = $set;
        $entry['spread_sources'] = \count(array_filter(array_keys($set), static fn (string $k): bool => str_starts_with($k, 'src:')));
        $entry['spread_asns'] = \count(array_filter(array_keys($set), static fn (string $k): bool => str_starts_with($k, 'asn:')));
        $this->targetState[$targetId] = $entry;

        return $entry;
    }

    public function clearTargetFailures(string $targetId): void
    {
        $entry = $this->targetState[$targetId] ?? null;
        if ($entry !== null) {
            $entry['fails'] = 0;
            $this->targetState[$targetId] = $entry;
        }
    }

    public function readTargetState(string $targetId): array
    {
        return $this->targetState[$targetId] ?? ['fails' => 0, 'spread_sources' => 0, 'spread_asns' => 0, 'first_ms' => 0, 'last_ms' => 0];
    }

    public function forgetMarks(string $dimension, string $id): int
    {
        $key = "{$dimension}:{$id}";
        if (!isset($this->marks[$key])) {
            return 0;
        }
        unset($this->marks[$key]);

        return 1;
    }
}
