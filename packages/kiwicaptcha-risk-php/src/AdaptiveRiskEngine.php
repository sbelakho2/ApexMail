<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

use KiwiCaptcha\Risk\Breaker\CircuitBreaker;
use KiwiCaptcha\Risk\Calibration\CalibrationStore;
use KiwiCaptcha\Risk\Metrics\RiskMetrics;
use KiwiCaptcha\Risk\Network\NetworkClassifierInterface;
use KiwiCaptcha\Risk\Storage\ProcessEmergencyCap;
use KiwiCaptcha\Risk\Storage\RiskStateStoreInterface;
use KiwiCaptcha\Risk\Storage\RiskStoreException;

/**
 * Adaptive risk engine: assesses one request and returns a RiskDecision.
 *
 * Pipeline: emergency limiter (single per-process window, before any state
 * backend) -> observation -> circuit breaker -> state store (EVALSHA) ->
 * scorer -> policy. Backend failure degrades instead of failing the
 * request.
 *
 * assessPreIssue() is the PRE-ISSUE path (emergency limiter + request
 * velocity + decision); reassess() is the POST-SOLVE recheck (identical
 * pipeline WITHOUT any limiter gate — a solved challenge is never denied
 * by the emergency caps); record_feedback() is the FEEDBACK path (no
 * limiter, no decision — a plain EventReceipt). record() is a deprecated
 * alias of record_feedback, assess() a deprecated alias of assessPreIssue.
 *
 * Every entry point NORMALIZES the caller-supplied idempotency key before
 * it is used as the Redis dedupe suffix: HMAC-SHA256 keyed by the
 * master-derived EVENT key, domain-separated by the event kind and scope
 * (a null/empty key becomes a fresh random 32-hex id). The store only ever
 * receives the normalized 64-hex value — the caller's raw key never
 * appears in Redis, and low-entropy keys are not dictionary-recoverable
 * (the HMAC key is derived from the deployment master, not from the
 * caller-supplied input).
 *
 * enableGlobalPressure=false zeroes the global-pressure signal, the global
 * level and the cooldown deadline after observe(), so the policy can never
 * escalate or cooldown-deny on global pressure (the bundle must also floor
 * the policy to Allow when disabled).
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
        private readonly ProcessEmergencyCap $limiter = new ProcessEmergencyCap(),
        private readonly RiskMetrics $metrics = new RiskMetrics(),
        private readonly ?CalibrationStore $calibration = null,
        private readonly bool $enableGlobalPressure = true,
    ) {
    }

    public function metrics(): RiskMetrics
    {
        return $this->metrics;
    }

    /**
     * @deprecated use assessPreIssue() (identical behavior)
     */
    public function assess(RiskContext $c, ?string $idempotencyKey = null): RiskDecision
    {
        return $this->assessPreIssue($c, $idempotencyKey);
    }

    /**
     * PRE-ISSUE assessment: emergency limiter (single per-process window)
     * -> PreIssue observation -> store -> scorer -> policy.
     *
     * @param string|null $idempotencyKey caller-supplied event_id; NORMALIZED
     *                                    (HMAC-SHA256 keyed by the event key,
     *                                    domain-separated by event+scope)
     *                                    before use as the dedupe suffix —
     *                                    retries with the same key hash
     *                                    identically and are deduped by the
     *                                    Lua; null/empty = fresh random
     *                                    16-byte hex
     */
    public function assessPreIssue(RiskContext $c, ?string $idempotencyKey = null): RiskDecision
    {
        $nowMs = (int) floor(microtime(true) * 1000);

        if (!$this->limiter->allow()) {
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

        return $this->runPipeline($c, $nowMs, $idempotencyKey);
    }

    /**
     * POST-SOLVE reassessment: identical pipeline to assessPreIssue
     * (observation with the context's event -> store -> scorer -> policy ->
     * calibration -> reasons -> decision receipt) but WITHOUT any emergency
     * limiter check — the admission caps apply only to pre-issue challenge
     * assessments, never to the recheck of a challenge the caller already
     * solved.
     *
     * @param string|null $idempotencyKey caller-supplied event_id; NORMALIZED
     *                                    (HMAC-SHA256, event+scope domain
     *                                    separated) as in assessPreIssue
     */
    public function reassess(RiskContext $c, ?string $idempotencyKey = null): RiskDecision
    {
        return $this->runPipeline($c, (int) floor(microtime(true) * 1000), $idempotencyKey);
    }

    /**
     * Shared assessment pipeline behind assessPreIssue() and reassess():
     * build the observation -> circuit breaker -> store -> scorer -> policy.
     */
    private function runPipeline(RiskContext $c, int $nowMs, ?string $idempotencyKey): RiskDecision
    {
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

        if (!$this->enableGlobalPressure) {
            // Global pressure disabled: zero the signal so the scorer and
            // the policy never see it (the level/cooldown are zeroed by
            // storeGlobalLevel()/storeCooldownUntilMs() below).
            $vector = SignalVector::fromArray(array_replace($vector->toArray(), ['global_pressure' => 0]));
        }

        $base = $this->policy->baseRisk($c->scope);
        if ($this->calibration !== null) {
            // Bounded automatic calibration: adjust ONLY the scope bias
            // (clamped to the calibrator's maxAdjustment, rate-limited,
            // cached 30 s) from the Redis aggregate score-bucket statistics;
            // never rewrite weights autonomously. A failing calibration
            // backend is silent — it never breaks issuance.
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
     * @param string|null $idempotencyKey caller-supplied event_id; NORMALIZED
     *                                    (HMAC-SHA256, event+scope domain
     *                                    separated) before use as the dedupe
     *                                    suffix; null/empty = fresh random id
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
            resources: new ResourcePressure(1000, 1000),
        ));
    }

    /**
     * Confirmed-legitimate outcome: REQUIRES the id of the decision being
     * confirmed so the outcome is recorded against the ORIGINAL decision's
     * scope/band/action (calibration receipt). Delegates EXCLUSIVELY
     * through record_feedback() — there is no band-0/Allow fallback.
     *
     * @throws \InvalidArgumentException when $decisionId is null or empty
     */
    public function confirmedLegitimate(RiskContext $ctx, ?string $decisionId, ?string $idempotencyKey = null): EventReceipt
    {
        if ($decisionId === null || $decisionId === '') {
            throw new \InvalidArgumentException('confirmedLegitimate requires the decision id being confirmed');
        }
        return $this->record_feedback(RiskEventKind::ConfirmedLegitimate, $ctx, $idempotencyKey, $decisionId);
    }

    /**
     * Confirmed-abuse outcome: REQUIRES the id of the decision being
     * confirmed so the outcome is recorded against the ORIGINAL decision's
     * scope/band/action (calibration receipt). Delegates EXCLUSIVELY
     * through record_feedback() — there is no band-10/Deny fallback.
     *
     * @throws \InvalidArgumentException when $decisionId is null or empty
     */
    public function confirmedAbuse(RiskContext $ctx, ?string $decisionId, ?string $idempotencyKey = null): EventReceipt
    {
        if ($decisionId === null || $decisionId === '') {
            throw new \InvalidArgumentException('confirmedAbuse requires the decision id being confirmed');
        }
        return $this->record_feedback(RiskEventKind::ConfirmedAbuse, $ctx, $idempotencyKey, $decisionId);
    }

    /**
     * Per-source rate-limit feedback: the caller's distributed keyed
     * limiter hit its per-source cap. Plain feedback path (event 15 —
     * bad +3000 on source/session), never runs the emergency limiter.
     */
    public function sourceRateLimitHit(RiskContext $c, ?string $idempotencyKey = null): EventReceipt
    {
        return $this->record_feedback(RiskEventKind::SourceRateLimitHit, $c, $idempotencyKey);
    }

    /**
     * Deployment-capacity feedback: the global capacity controller hit its
     * cap. Plain feedback path (event 16 — global-only bad +3000, never
     * identity states), never runs the emergency limiter.
     */
    public function globalCapacityHit(RiskContext $c, ?string $idempotencyKey = null): EventReceipt
    {
        return $this->record_feedback(RiskEventKind::GlobalCapacityHit, $c, $idempotencyKey);
    }

    /**
     * Risk-decision feedback: a decision that already denied must not be
     * double-counted. Plain feedback path (event 17 — deliberate no-op),
     * never runs the emergency limiter.
     */
    public function riskDenied(RiskContext $c, ?string $idempotencyKey = null): EventReceipt
    {
        return $this->record_feedback(RiskEventKind::RiskDenied, $c, $idempotencyKey);
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
            eventId: $this->normalizeEventId($event, $c->scope, $idempotencyKey),
            networkRisk: $c->networkFlags->networkRisk(),
            nowMs: $nowMs,
        );
    }

    /**
     * Normalizes a caller-supplied idempotency key before it is used as a
     * Redis key suffix: HMAC-SHA256 of the domain-separated message
     * (pack('N', scope) . chr(event) . input), keyed by the master-derived
     * EVENT key — 64 lowercase hex chars. Domain separation (event kind +
     * scope) means the same raw key dedupes independently per event/scope,
     * and the HMAC (not a bare sha256) means low-entropy keys are not
     * dictionary-recoverable from the Redis dedupe keys; the caller's raw
     * key never appears verbatim in Redis. null/empty -> a fresh random
     * 32-hex id; longer than 4096 bytes -> InvalidArgumentException. Rust
     * mirrors this exactly.
     */
    private function normalizeEventId(RiskEventKind $event, int $scope, ?string $input): string
    {
        if ($input === null || $input === '') {
            return bin2hex(random_bytes(16));
        }
        if (strlen($input) > 4096) {
            throw new \InvalidArgumentException('idempotency key too long');
        }
        return hash_hmac('sha256', pack('N', $scope) . chr($event->value) . $input, $this->keys->event);
    }

    private function storeGlobalLevel(): int
    {
        if (!$this->enableGlobalPressure) {
            return 0;
        }
        if (method_exists($this->store, 'lastGlobalLevel')) {
            return $this->store->lastGlobalLevel();
        }
        return 0;
    }

    private function storeCooldownUntilMs(): int
    {
        if (!$this->enableGlobalPressure) {
            return 0;
        }
        if (method_exists($this->store, 'lastCooldownUntilMs')) {
            return $this->store->lastCooldownUntilMs();
        }
        return 0;
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
