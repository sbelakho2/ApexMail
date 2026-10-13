<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\OutcomeMarksStoreInterface;
use KiwiCaptcha\Risk\Storage\PrincipalNetworkTagStoreInterface;
use KiwiCaptcha\Risk\Storage\RiskStateStoreInterface;
use KiwiCaptcha\Risk\Storage\SessionBucketTrustStoreInterface;
use KiwiCaptcha\Risk\Storage\SessionContextTagStoreInterface;
use KiwiCaptcha\Risk\Storage\SessionTlsTagStoreInterface;
use KiwiCaptcha\Risk\Storage\TargetStateStoreInterface;

/**
 * The journey in-memory risk surface. It carries every capability the
 * engine pipeline may consult. That covers state, outcome marks,
 * principal network tags, session tags, bucket trust, and target
 * state. All of them share one in-memory map.
 */
final class JourneyRiskStore implements
    RiskStateStoreInterface,
    OutcomeMarksStoreInterface,
    PrincipalNetworkTagStoreInterface,
    SessionContextTagStoreInterface,
    SessionTlsTagStoreInterface,
    SessionBucketTrustStoreInterface,
    TargetStateStoreInterface
{
    /** @var array<string, array{kind: string, last_kind: string, count: int, first_ms: int, last_ms: int}> */
    private array $marks = [];

    /** @var array<string, array<string, true>> principal => network tag */
    private array $networks = [];
    /** @var array<string, array<string, true>> principal => trusted tag */
    private array $trustedTags = [];

    /** @var list<array{0: string, 1: string}> every network-tag write */
    public array $networkWrites = [];

    /** @var array<string, int> */
    private array $bucketTrust = [];

    /** @var array<string, string> */
    private array $contextTags = [];

    /** @var array<string, string> */
    private array $tlsTags = [];

    /** @var array<string, array{fails: int, spread_sources: int, spread_asns: int, first_ms: int, last_ms: int}> */
    private array $targets = [];

    /** @var array<string, array{scope: int, hour: int, status: int}> */
    private array $ledger = [];

    /** @var list<RiskObservation> */
    public array $observations = [];

    public function observe(RiskObservation $observation): SignalVector
    {
        $this->observations[] = $observation;

        return SignalVector::zero();
    }

    public function registerOutcome(string $decisionId, int $scope, int $decisionHour, int $score): bool
    {
        if (isset($this->ledger[$decisionId])) {
            return false;
        }
        $this->ledger[$decisionId] = ['scope' => $scope, 'hour' => $decisionHour, 'status' => 0];

        return true;
    }

    public function confirmOutcome(string $decisionId, bool $legitimate): int
    {
        if (($this->ledger[$decisionId]['status'] ?? 1) !== 0) {
            return 0;
        }
        $this->ledger[$decisionId]['status'] = 1;

        return 1;
    }

    public function correctOutcome(string $decisionId, bool $legitimate): bool
    {
        return isset($this->ledger[$decisionId]);
    }

    public function markKey(string $dimension, string $id): string
    {
        return 'mark:'.$dimension.':'.$id;
    }

    public function writeMark(string $dimension, string $id, string $kind, int $nowMs, string $eventId = ''): int
    {
        $key = $this->markKey($dimension, $id);
        $existing = $this->marks[$key] ?? null;
        $this->marks[$key] = [
            'kind' => $existing['kind'] ?? $kind,
            'last_kind' => $kind,
            'count' => ($existing['count'] ?? 0) + 1,
            'first_ms' => $existing['first_ms'] ?? $nowMs,
            'last_ms' => $nowMs,
        ];

        return $this->marks[$key]['count'];
    }

    public function readMark(string $dimension, string $id): ?array
    {
        return $this->marks[$this->markKey($dimension, $id)] ?? null;
    }

    public function forgetMarks(string $dimension, string $id): int
    {
        $key = $this->markKey($dimension, $id);
        if (!isset($this->marks[$key])) {
            return 0;
        }
        unset($this->marks[$key]);

        return 1;
    }

    public function principalNetworkSeen(string $principalId, string $network): ?bool
    {
        return isset($this->networks[$principalId][$network]);
    }

    public function recordPrincipalNetworkTag(string $principalId, string $network, bool $trusted = false): bool
    {
        $this->networkWrites[] = [$principalId, $network];
        if (isset($this->networks[$principalId][$network])) {
            return false;
        }
        $this->networks[$principalId][$network] = true;
        if ($trusted) {
            $this->trustedTags[$principalId][$network] = true;
        }

        return true;
    }

    public function principalHasTrustedNetwork(string $principalId): ?bool
    {
        return isset($this->networks[$principalId]) && $this->networks[$principalId] !== [];
    }

    public function tagIsTrusted(string $principalId, string $network): ?bool
    {
        return isset($this->trustedTags[$principalId][$network]);
    }

    public function forgetDevices(string $principalId): void
    {
        foreach (array_keys($this->networks[$principalId] ?? []) as $tag) {
            if (str_starts_with($tag, 'session:') || str_starts_with($tag, 'device:')) {
                unset($this->networks[$principalId][$tag], $this->trustedTags[$principalId][$tag]);
            }
        }
    }

    public function sessionFirstContextTag(string $sessionId, string $tag): ?string
    {
        return $this->contextTags[$sessionId] ??= $tag;
    }

    public function sessionFirstTlsTag(string $sessionId, string $tag): ?string
    {
        return $this->tlsTags[$sessionId] ??= $tag;
    }

    public function bucketTrustKey(string $sessionId, string $bucket): string
    {
        return 'trust:'.$sessionId.':'.$bucket;
    }

    public function readBucketTrust(string $sessionId, string $bucket): int
    {
        return $this->bucketTrust[$this->bucketTrustKey($sessionId, $bucket)] ?? 0;
    }

    public function creditBucketTrust(string $sessionId, string $bucket, int $delta): int
    {
        $key = $this->bucketTrustKey($sessionId, $bucket);

        return $this->bucketTrust[$key] = max(0, ($this->bucketTrust[$key] ?? 0) + $delta);
    }

    public function decayBucketTrust(string $sessionId, string $bucket, int $delta): int
    {
        return $this->creditBucketTrust($sessionId, $bucket, -$delta);
    }

    public function registerTargetFailure(string $targetId, string $source, string $asn): array
    {
        $state = $this->targets[$targetId] ?? ['fails' => 0, 'spread_sources' => 0, 'spread_asns' => 0, 'first_ms' => 0, 'last_ms' => 0];
        $state['fails']++;
        $state['spread_sources']++;
        $state['spread_asns']++;
        $state['last_ms'] = (int) (microtime(true) * 1000);
        $state['first_ms'] ??= $state['last_ms'];

        return $this->targets[$targetId] = $state;
    }

    public function clearTargetFailures(string $targetId): void
    {
        if (isset($this->targets[$targetId])) {
            $this->targets[$targetId]['fails'] = 0;
        }
    }

    public function readTargetState(string $targetId): array
    {
        return $this->targets[$targetId] ?? ['fails' => 0, 'spread_sources' => 0, 'spread_asns' => 0, 'first_ms' => 0, 'last_ms' => 0];
    }
}
