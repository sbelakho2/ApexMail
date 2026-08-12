<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

use KiwiCaptcha\Risk\Breaker\CircuitBreaker;
use KiwiCaptcha\Risk\Calibration\CalibrationStore;
use KiwiCaptcha\Risk\Metrics\RiskMetrics;
use KiwiCaptcha\Risk\Network\NetworkClassifierInterface;
use KiwiCaptcha\Risk\Storage\LocalEmergencyLimiter;
use KiwiCaptcha\Risk\Storage\RiskStateStoreInterface;
use KiwiCaptcha\Risk\Storage\RiskStoreException;

/**
 * Adaptive risk engine: assesses one request and returns a RiskDecision.
 *
 * Pipeline: emergency limiter (source window THEN global window, both
 * before any state backend) -> observation -> circuit breaker -> state
 * store (EVALSHA) -> scorer -> policy. Backend failure degrades instead of
 * failing the request.
 *
 * assess() is the PRE-ISSUE path (request velocity + decision);
 * record_feedback() is the FEEDBACK path (no limiter, no decision — a
 * plain EventReceipt). record() is a deprecated alias of record_feedback.
 *
 * The epoch/ttl/saturation parameters are the engine-level configuration
 * and are expected to match the injected RedisRiskStateStore (which carries
 * its own copies); they are kept on the engine for the spec'd constructor
 * shape and forward-compatibility.
 */
final class AdaptiveRiskEngine
{
    public const DEFAULT_SATURATIONS = [
        'src_fast' => 8000,
        'src_slow' => 100000,
        'issue' => 6000,
        'bad' => 4000,
        'mal' => 3000,
        'rep' => 2000,
        'action' => 6000,
        'switch' => 10000,
        'global' => 70000,
        'trust' => 10000,
        'principal' => 10000,
    ];

    public function __construct(
        private readonly RiskStateStoreInterface $store,
        private readonly NetworkClassifierInterface $classifier,
        private readonly RiskIdentityFactory $identityFactory,
        private readonly RiskScorer $scorer,
        private readonly RiskPolicy $policy,
        private readonly RiskKeys $keys,
        private readonly int $sourceEpochSecs = 900,
        private readonly int $subnetEpochSecs = 900,
        private readonly int $stateTtlSecs = 1800,
        private readonly int $principalTtlSecs = 86400,
        private readonly int $dedupeTtlSecs = 60,
        private readonly array $saturations = self::DEFAULT_SATURATIONS,
        private readonly CircuitBreaker $breaker = new CircuitBreaker(),
        private readonly LocalEmergencyLimiter $limiter = new LocalEmergencyLimiter(),
        private readonly RiskMetrics $metrics = new RiskMetrics(),
        private readonly ?CalibrationStore $calibration = null,
    ) {
    }

    public function metrics(): RiskMetrics
    {
        return $this->metrics;
    }

    /**
     * PRE-ISSUE assessment: emergency limiter (source window THEN global
     * window) -> PreIssue observation -> store -> scorer -> policy.
     *
     * @param string|null $idempotencyKey caller-supplied event_id used
     *                                    VERBATIM (retries with the same key
     *                                    are deduped by the Lua); null =
     *                                    fresh random 16-byte hex
     */
    public function assess(RiskContext $c, ?string $idempotencyKey = null): RiskDecision
    {
        $nowMs = (int) floor(microtime(true) * 1000);

        if (!$this->limiter->allow() || !$this->limiter->allowGlobal()) {
            $this->metrics->increment('denied:limiter');
            $decision = new RiskDecision(
                score: 1000,
                action: RiskAction::Deny,
                reasons: [RiskReason::HardRateLimit],
                policyVersion: $this->policy->version,
                globalLevel: $this->storeGlobalLevel(),
                retryAfterMs: 1000,
                band: 10,
            );
            $this->recordDecisionMetrics($c->scope, $decision);
            $this->registerCalibrationReceipt($c->scope, $decision);
            return $decision;
        }

        $observation = $this->buildObservation($c, $nowMs, $idempotencyKey);

        if ($this->breaker->isOpen()) {
            $this->metrics->increment('degraded:breaker');
            $decision = $this->policy->degradedDecision($c->scope, $this->storeGlobalLevel());
            $this->recordDecisionMetrics($c->scope, $decision);
            $this->registerCalibrationReceipt($c->scope, $decision);
            return $decision;
        }

        $start = microtime(true);
        try {
            $vector = $this->store->observe($observation);
        } catch (RiskStoreException $e) {
            $this->breaker->recordFailure();
            $this->metrics->increment('degraded:store');
            $decision = $this->policy->degradedDecision($c->scope, $this->storeGlobalLevel());
            $this->recordDecisionMetrics($c->scope, $decision);
            $this->registerCalibrationReceipt($c->scope, $decision);
            return $decision;
        }
        $this->metrics->recordLatency('store:observe', (microtime(true) - $start) * 1000);
        $this->breaker->recordSuccess();

        $base = $this->policy->baseRisk($c->scope);
        if ($this->calibration !== null) {
            // Bounded automatic calibration: adjust ONLY the scope bias
            // (-200..+200) from the Redis aggregate score-bucket
            // statistics; never rewrite weights autonomously. A failing
            // calibration backend is silent — it never breaks issuance.
            try {
                $bias = $this->calibration->biasForScope($c->scope, $nowMs);
            } catch (\Throwable) {
                $bias = 0;
            }
            $base = max(0, min(1000, $base + $bias));
        }
        $score = $this->scorer->score($base, $vector, $this->policy->weights);
        $decision = $this->policy->decide(
            scope: $c->scope,
            score: $score,
            s: $vector,
            r: $c->resources,
            globalLevel: $this->storeGlobalLevel(),
            nowMs: $nowMs,
            cooldownUntilMs: $this->storeCooldownUntilMs(),
        );

        $this->metrics->gauge('global:level', $decision->globalLevel);
        $this->metrics->gauge('resources:argon_capacity', $c->resources->argonCapacity);
        $this->recordDecisionMetrics($c->scope, $decision);
        $this->registerCalibrationReceipt($c->scope, $decision);
        return $decision;
    }

    /**
     * Outcome feedback path (e.g. a post-solve protected action). NEVER
     * runs the emergency limiter and NEVER produces a decision: the
     * observation is stored and the current signals returned as an
     * EventReceipt. Store failures are silent (zero signals, not a
     * duplicate).
     *
     * When the event is ConfirmedLegitimate/ConfirmedAbuse AND $decisionId
     * is given, the calibration receipt registered for that decision is
     * consumed and the outcome recorded against the ORIGINAL decision's
     * scope/band/action.
     *
     * @param string|null $idempotencyKey caller-supplied event_id used
     *                                    VERBATIM (dedupe), null = fresh
     * @param string|null $decisionId     the RiskDecision::decisionId being
     *                                    confirmed (calibration pairing)
     */
    public function record_feedback(RiskEventKind $event, RiskContext $c, ?string $idempotencyKey = null, ?string $decisionId = null): EventReceipt
    {
        $nowMs = (int) floor(microtime(true) * 1000);
        $observation = $this->buildObservation($c, $nowMs, $idempotencyKey, $event);
        try {
            $vector = $this->store->observe($observation);
            $isDuplicate = method_exists($this->store, 'lastIsDuplicate') && (bool) $this->store->lastIsDuplicate();
        } catch (RiskStoreException $e) {
            $this->breaker->recordFailure();
            $vector = SignalVector::zero();
            $isDuplicate = false;
        }

        if (($event === RiskEventKind::ConfirmedLegitimate || $event === RiskEventKind::ConfirmedAbuse) && $decisionId !== null) {
            $this->consumeCalibrationReceipt($decisionId, $event === RiskEventKind::ConfirmedLegitimate);
        }

        return new EventReceipt(
            eventId: $observation->eventId,
            isDuplicate: $isDuplicate,
            signals: $vector,
        );
    }

    /**
     * @deprecated use record_feedback() (same behavior; the feedback path
     *             never runs the limiter and never produces a decision)
     */
    public function record(RiskEventKind $kind, int $scope, string $ip, ?string $sessionId = null, ?string $principalId = null): EventReceipt
    {
        return $this->record_feedback($kind, new RiskContext(
            scope: $scope,
            sourceIp: $ip,
            sessionId: $sessionId,
            principalId: $principalId,
            event: $kind,
            networkFlags: $this->classifier->classify($ip),
            resources: new ResourcePressure(1000, 1000, 1000),
        ));
    }

    public function confirmedLegitimate(string $scope, string $ip, ?string $principalId = null): void
    {
        try {
            $this->calibration?->record($this->scopeId($scope), 0, RiskAction::Allow, true);
        } catch (\Throwable) {
            // calibration must never break feedback
        }

        $this->record(RiskEventKind::ConfirmedLegitimate, $this->scopeId($scope), $ip, null, $principalId);
    }

    public function confirmedAbuse(string $scope, string $ip, ?string $principalId = null): void
    {
        try {
            $this->calibration?->record($this->scopeId($scope), 10, RiskAction::Deny, false);
        } catch (\Throwable) {
            // calibration must never break feedback
        }

        $this->record(RiskEventKind::ConfirmedAbuse, $this->scopeId($scope), $ip, null, $principalId);
    }

    private function buildObservation(RiskContext $c, int $nowMs, ?string $idempotencyKey = null, ?RiskEventKind $event = null): RiskObservation
    {
        $event ??= $c->event;
        $nowSecs = intdiv($nowMs, 1000);
        $srcEpoch = intdiv($nowSecs, $this->sourceEpochSecs);
        $netEpoch = intdiv($nowSecs, $this->subnetEpochSecs);
        return new RiskObservation(
            event: $event,
            scope: $c->scope,
            sourceEpoch: $srcEpoch,
            sourceIdPrev: $this->identityFactory->sourceIdForEpoch($c, $srcEpoch - 1),
            sourceId: $this->identityFactory->sourceIdForEpoch($c, $srcEpoch),
            sourceIdNext: $this->identityFactory->sourceIdForEpoch($c, $srcEpoch + 1),
            subnetEpoch: $netEpoch,
            subnetIdPrev: $this->identityFactory->subnetIdForEpoch($c, $netEpoch - 1),
            subnetId: $this->identityFactory->subnetIdForEpoch($c, $netEpoch),
            subnetIdNext: $this->identityFactory->subnetIdForEpoch($c, $netEpoch + 1),
            sessionId: $c->sessionId !== null ? $this->identityFactory->sessionId($c->sessionId) : null,
            principalId: $c->principalId !== null ? $this->identityFactory->principalId($c->principalId) : null,
            eventId: $idempotencyKey ?? RiskObservation::newEventId(),
            networkRisk: $c->networkFlags->networkRisk(),
            nowMs: $nowMs,
        );
    }

    private function storeGlobalLevel(): int
    {
        if (method_exists($this->store, 'lastGlobalLevel')) {
            return $this->store->lastGlobalLevel();
        }
        return 0;
    }

    private function storeCooldownUntilMs(): int
    {
        if (method_exists($this->store, 'lastCooldownUntilMs')) {
            return $this->store->lastCooldownUntilMs();
        }
        return 0;
    }

    /** Stable scope-name -> int id (crc32 & 0x7fffffff), for the label helpers. */
    private function scopeId(string $scope): int
    {
        return crc32($scope) & 0x7fffffff;
    }

    /**
     * Registers the calibration receipt for one decision so a later
     * confirmed outcome can be paired back to its scope/band/action.
     * Failures are silent — calibration never breaks issuance.
     */
    private function registerCalibrationReceipt(int $scope, RiskDecision $decision): void
    {
        if ($this->calibration === null) {
            return;
        }
        try {
            $this->calibration->recordReceipt($decision->decisionId, $scope, $decision->band, $decision->action);
        } catch (\Throwable) {
            // calibration must never break issuance
        }
    }

    /**
     * Consumes the calibration receipt for $decisionId (if any) and records
     * the confirmed outcome against the ORIGINAL decision's
     * scope/band/action. Failures are silent.
     */
    private function consumeCalibrationReceipt(string $decisionId, bool $legitimate): void
    {
        if ($this->calibration === null) {
            return;
        }
        try {
            $receipt = $this->calibration->consumeReceipt($decisionId);
        } catch (\Throwable) {
            return;
        }
        if ($receipt === null) {
            return;
        }
        $action = RiskAction::tryFrom((string) ($receipt['action'] ?? '')) ?? RiskAction::Allow;
        $this->calibration->record((int) ($receipt['scope'] ?? 0), (int) ($receipt['band'] ?? 0), $action, $legitimate);
    }

    private function recordDecisionMetrics(int $scope, RiskDecision $decision): void
    {
        $this->metrics->increment(sprintf('decisions:%d:%s:%d', $scope, $decision->action->value, $decision->band));
    }
}
