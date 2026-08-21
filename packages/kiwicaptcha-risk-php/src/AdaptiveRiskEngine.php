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
use KiwiCaptcha\Risk\Storage\SessionContextTagStoreInterface;
use KiwiCaptcha\Risk\Storage\SessionTlsTagStoreInterface;

/**
 * Adaptive risk engine: assesses one request and returns a RiskDecision.
 *
 * Pipeline: emergency limiter (single per-process window, before any state
 * backend) -> observation -> circuit breaker -> state store (evalsha) ->
 * scorer -> policy (with the per-process scope-action hysteresis map:
 * enter/exit smoothing of the score band selection) -> decision.
 * Backend failure degrades instead of failing the request.
 *
 * assessPreIssue() is the pre-issue path (emergency limiter + request
 * velocity + decision). reassess() is the post-solve recheck: the same
 * pipeline without any limiter gate, so a solved challenge is never denied
 * by the emergency caps. record_feedback() is the feedback path with no
 * limiter and no decision, just a plain EventReceipt. record() is a
 * deprecated alias of record_feedback, assess() a deprecated alias of
 * assessPreIssue.
 *
 * The risk-v2 variants (assessPreIssueV2/reassessV2) run the identical
 * pipeline plus the additive risk-v2 evidence factors (honeypot/decoy
 * evidence, session client-context consistency, trusted-edge TLS
 * consistency) — probabilistic evidence only, never a security gate,
 * never a change to the risk-v1 state contract. The v2 entry points
 * accept an optional operator-tunable RiskV2Weights override; null uses
 * the default weights (byte-identical scores to today).
 *
 * Every entry point normalizes the caller-supplied idempotency key before
 * it is used as the Redis dedupe suffix: HMAC-SHA256 keyed by the
 * master-derived event key, domain-separated by the event kind and scope
 * (a null/empty key becomes a fresh random 32-hex id). The store only
 * ever receives the normalized 64-hex value, so the caller's raw key
 * never appears in Redis, and low-entropy keys are not
 * dictionary-recoverable (the HMAC key is derived from the deployment
 * master, not from the caller-supplied input).
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
        private readonly ScopeActionHysteresis $hysteresis = new ScopeActionHysteresis(),
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
     * Pre-issue assessment: emergency limiter (single per-process window)
     * -> PreIssue observation -> store -> scorer -> policy.
     *
     * @param string|null $idempotencyKey caller-supplied event_id; normalized
     *                                    (HMAC-SHA256 keyed by the event key,
     *                                    domain-separated by event+scope)
     *                                    before use as the dedupe suffix.
     *                                    Retries with the same key hash
     *                                    identically and are deduped by the
     *                                    Lua; null/empty = fresh random
     *                                    16-byte hex
     */
    public function assessPreIssue(RiskContext $c, ?string $idempotencyKey = null): RiskDecision
    {
        return $this->assessPreIssueInternal($c, $idempotencyKey, null);
    }

    /**
     * Risk-v2 variant of assessPreIssue(): the identical pipeline plus the
     * additive risk-v2 evidence factors (honeypot/decoy evidence, session
     * client-context consistency, trusted-edge TLS consistency) from $v2.
     * The risk-v1 contract semantics are unchanged — with an empty $v2
     * context the decision is identical to the v1 path.
     *
     * @param string|null $idempotencyKey caller-supplied event_id; normalized
     *                                    as in assessPreIssue
     * @param RiskV2Weights|null $v2Weights operator-tunable weights for the
     *                                      additive risk-v2 factors; null
     *                                      uses the default weights
     *                                      (identical scores to today)
     */
    public function assessPreIssueV2(RiskContext $c, RiskV2Context $v2, ?string $idempotencyKey = null, ?RiskV2Weights $v2Weights = null): RiskDecision
    {
        return $this->assessPreIssueInternal($c, $idempotencyKey, $v2, $v2Weights);
    }

    private function assessPreIssueInternal(RiskContext $c, ?string $idempotencyKey, ?RiskV2Context $v2, ?RiskV2Weights $v2Weights = null): RiskDecision
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
            $this->registerDecisionOutcome($c->scope, $decision, $nowMs);
            return $decision;
        }

        return $this->runPipeline($c, $nowMs, $idempotencyKey, $v2, $v2Weights);
    }

    /**
     * Post-solve reassessment: identical pipeline to assessPreIssue
     * (observation with the context's event -> store -> scorer -> policy ->
     * calibration -> reasons -> decision receipt) but without any emergency
     * limiter check. The admission caps apply only to pre-issue challenge
     * assessments, never to the recheck of a challenge the caller already
     * solved.
     *
     * @param string|null $idempotencyKey caller-supplied event_id; normalized
     *                                    (HMAC-SHA256, event+scope domain
     *                                    separated) as in assessPreIssue
     */
    public function reassess(RiskContext $c, ?string $idempotencyKey = null): RiskDecision
    {
        return $this->runPipeline($c, (int) floor(microtime(true) * 1000), $idempotencyKey, null);
    }

    /**
     * Risk-v2 variant of reassess(): the identical pipeline plus the
     * additive risk-v2 evidence factors from $v2 (honeypot evidence,
     * session client-context consistency, trusted-edge TLS consistency).
     *
     * @param string|null $idempotencyKey caller-supplied event_id; normalized
     *                                    as in reassess
     * @param RiskV2Weights|null $v2Weights operator-tunable weights for the
     *                                      additive risk-v2 factors; null
     *                                      uses the default weights
     *                                      (identical scores to today)
     */
    public function reassessV2(RiskContext $c, RiskV2Context $v2, ?string $idempotencyKey = null, ?RiskV2Weights $v2Weights = null): RiskDecision
    {
        return $this->runPipeline($c, (int) floor(microtime(true) * 1000), $idempotencyKey, $v2, $v2Weights);
    }

    /**
     * Shared assessment pipeline behind assessPreIssue()/assessPreIssueV2()
     * and reassess()/reassessV2(): build the observation -> circuit breaker
     * -> store -> scorer -> policy.
     */
    private function runPipeline(RiskContext $c, int $nowMs, ?string $idempotencyKey, ?RiskV2Context $v2 = null, ?RiskV2Weights $v2Weights = null): RiskDecision
    {
        $observation = $this->buildObservation($c, $nowMs, $idempotencyKey);

        if ($this->breaker->isOpen()) {
            $this->metrics->increment('degraded:breaker');
            $decision = $this->policy->degradedDecision($c->scope, $this->storeGlobalLevel());
            $this->recordDecisionMetrics($c->scope, $decision);
            $this->registerDecisionOutcome($c->scope, $decision, $nowMs);
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
            $this->registerDecisionOutcome($c->scope, $decision, $nowMs);
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
            // Bounded automatic calibration: adjust only the scope bias
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
        // Risk-v2 evidence factors: honeypot/decoy evidence, the session
        // client-context consistency and the trusted-edge TLS consistency,
        // derived from the v2 context (a session-first-tag record read that
        // degrades to "consistent" on any backend miss — probabilistic
        // evidence never breaks an assessment). The v2 weights are the
        // operator override when given, else the default weights (byte-
        // identical scores to today).
        $v2Signals = $v2 !== null ? $this->buildV2Signals($v2, $c, $observation) : null;
        $score = $v2Signals !== null
            ? $this->scorer->scoreV2($base, $vector, $this->policy->weights, $v2Signals, $v2Weights ?? new RiskV2Weights())
            : $this->scorer->score($base, $vector, $this->policy->weights);
        $decision = $this->policy->decide(
            scope: $c->scope,
            score: $score,
            s: $vector,
            r: $c->resources,
            globalLevel: $this->storeGlobalLevel(),
            nowMs: $nowMs,
            cooldownUntilMs: $this->storeCooldownUntilMs(),
            hysteresis: $this->hysteresis,
        );

        $this->metrics->gauge('global:level', $decision->globalLevel);
        $this->metrics->gauge('resources:argon_capacity', $c->resources->argonCapacity);
        $this->recordDecisionMetrics($c->scope, $decision);
        $this->registerDecisionOutcome($c->scope, $decision, $nowMs);
        return $decision;
    }

    /**
     * Outcome feedback path (e.g. a post-solve protected action). Never
     * runs the emergency limiter and never produces a decision: the
     * observation is stored and the current signals returned as an
     * EventReceipt. Store failures are silent (zero signals, not a
     * duplicate).
     *
     * Confirmation events are rejected: ConfirmedLegitimate and
     * ConfirmedAbuse must be routed through confirmedLegitimate()/
     * confirmedAbuse() or confirmOutcome(), which first run the
     * always-on outcome ledger exactly once and then record the reputation
     * event through the internal feedback path. A plain feedback call for
     * a confirmation event would bypass the ledger's exactly-once CAS.
     *
     * @throws \LogicException when $event is ConfirmedLegitimate or
     *                         ConfirmedAbuse (use confirmed* instead).
     * @param string|null $idempotencyKey caller-supplied event_id; normalized
     *                                    (HMAC-SHA256, event+scope domain
     *                                    separated) before use as the dedupe
     *                                    suffix; null/empty = fresh random
     *                                    id.
     * @param string|null $decisionId     accepted for backward
     *                                    compatibility; the confirmation is
     *                                    handled by confirmedLegitimate()/
     *                                    confirmedAbuse() via confirmOutcome().
     */
    public function record_feedback(RiskEventKind $event, RiskContext $c, ?string $idempotencyKey = null, ?string $decisionId = null): EventReceipt
    {
        if ($event === RiskEventKind::ConfirmedLegitimate || $event === RiskEventKind::ConfirmedAbuse) {
            throw new \LogicException('Confirmed outcomes must use confirmOutcome/confirmed*');
        }
        return $this->emitFeedback($event, $c, $idempotencyKey);
    }

    /**
     * The internal feedback path behind record_feedback(): the plain
     * observation -> store -> EventReceipt flow without the confirmation-
     * event guard. Only the confirmed* methods may reach it (the outcome
     * ledger has already authorized the event exactly once).
     */
    private function emitFeedback(RiskEventKind $event, RiskContext $c, ?string $idempotencyKey = null): EventReceipt
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
     * Best-effort atomic outcome confirmation: consumes the decision's
     * receipt exactly once (single canonical confirm.lua script with
     * calibration; the store's outcome_confirm.lua ledger CAS without) and
     * records the outcome against the original decision's scope bucket.
     * The outcome ledger is always on and independent of calibration:
     * ConfirmedLegitimate/ConfirmedAbuse work identically with or without
     * calibration. With calibration the ledger and the calibration are
     * recorded by the calibrator's script; without calibration the store
     * flips the ledger only (status is never 2 without a receipt).
     *
     * Returns the shared accepted-outcome status, wire contract with the
     * Rust mirror. Status 0 = nothing consumed (missing / already
     * confirmed / corrupt / backend failure). Status 1 = first
     * confirmation with calibration recorded. Status 2 = first
     * confirmation deliberately unsampled (only when calibration is
     * enabled). Statuses 1 and 2 authorize the first-party reputation
     * event exactly once; status 0 must never book one, so a webhook
     * retry can never amplify. Never throws for backend failures; they
     * surface as status 0 and the receipt survives, so a retry applies
     * the outcome exactly once.
     *
     * @throws \InvalidArgumentException when the calibration sampling mode
     *                                   is 'weighted' and $weight is null
     *                                   (weighted mode requires a sampling
     *                                   probability weight)
     */
    public function confirmOutcome(string $decisionId, bool $legitimate, ?float $weight = null): int
    {
        if ($this->calibration !== null) {
            try {
                return $this->calibration->confirmOutcome($decisionId, $legitimate, $weight);
            } catch (\InvalidArgumentException $e) {
                throw $e;
            } catch (\Throwable) {
                return 0;
            }
        }
        try {
            return $this->store->confirmOutcome($decisionId, $legitimate);
        } catch (\Throwable) {
            return 0;
        }
    }

    /**
     * Confirmed-legitimate outcome: requires the id of the decision being
     * confirmed so the outcome is recorded against the original decision's
     * scope bucket. First runs the always-on outcome-ledger confirmation
     * (ledger CAS pending -> legitimate exactly once, with or without
     * calibration), then, only when the confirmation is the first one
     * (status 1 or 2), records the ConfirmedLegitimate reputation event.
     * Reputation gating: a status-0 outcome (ledger already consumed /
     * missing / backend failure) is a no-op returning an EventReceipt
     * marked isDuplicate with zero signals and no observation. One real-
     * world outcome produces at most one reputation mutation, so webhook
     * retries can never amplify.
     *
     * $samplingProbabilityPpm (1..1_000_000) is the application-supplied
     * inverse sampling probability for 'weighted' calibration mode,
     * converted to weight = 1_000_000 / ppm; null passes no weight (the
     * calibrator's own sampling knobs apply).
     *
     * @throws \InvalidArgumentException when $decisionId is null or empty
     */
    public function confirmedLegitimate(RiskContext $ctx, ?string $decisionId, ?string $idempotencyKey = null, ?int $samplingProbabilityPpm = null): EventReceipt
    {
        if ($decisionId === null || $decisionId === '') {
            throw new \InvalidArgumentException('confirmedLegitimate requires the decision id being confirmed');
        }
        $weight = $samplingProbabilityPpm === null ? null : 1_000_000 / $samplingProbabilityPpm;
        if ($this->confirmOutcome($decisionId, true, $weight) === 0) {
            return $this->skippedConfirmationReceipt(RiskEventKind::ConfirmedLegitimate, $ctx, $idempotencyKey);
        }
        return $this->emitFeedback(RiskEventKind::ConfirmedLegitimate, $ctx, $idempotencyKey);
    }

    /**
     * Confirmed-abuse outcome: requires the id of the decision being
     * confirmed so the outcome is recorded against the original decision's
     * scope bucket. First runs the always-on outcome-ledger confirmation
     * (ledger CAS pending -> abuse exactly once, with or without
     * calibration), then, only when the confirmation is the first one
     * (status 1 or 2), records the ConfirmedAbuse reputation event.
     * Reputation gating: a status-0 outcome (ledger already consumed /
     * missing / backend failure) is a no-op returning an EventReceipt
     * marked isDuplicate with zero signals and no observation. One real-
     * world outcome produces at most one reputation mutation, so webhook
     * retries can never re-penalize the source with repeated +6000
     * ConfirmedAbuse.
     *
     * $samplingProbabilityPpm (1..1_000_000) is the application-supplied
     * inverse sampling probability for 'weighted' calibration mode,
     * converted to weight = 1_000_000 / ppm; null passes no weight (the
     * calibrator's own sampling knobs apply).
     *
     * @throws \InvalidArgumentException when $decisionId is null or empty
     */
    public function confirmedAbuse(RiskContext $ctx, ?string $decisionId, ?string $idempotencyKey = null, ?int $samplingProbabilityPpm = null): EventReceipt
    {
        if ($decisionId === null || $decisionId === '') {
            throw new \InvalidArgumentException('confirmedAbuse requires the decision id being confirmed');
        }
        $weight = $samplingProbabilityPpm === null ? null : 1_000_000 / $samplingProbabilityPpm;
        if ($this->confirmOutcome($decisionId, false, $weight) === 0) {
            return $this->skippedConfirmationReceipt(RiskEventKind::ConfirmedAbuse, $ctx, $idempotencyKey);
        }
        return $this->emitFeedback(RiskEventKind::ConfirmedAbuse, $ctx, $idempotencyKey);
    }

    /**
     * Corrects a prior label via the canonical correction.lua (with
     * calibration) or the store's outcome_correct.lua (without): flips the
     * always-on outcome ledger L <-> A. The corrected outcome is
     * authoritative for future events; ephemeral reputation pressure is
     * left to decay naturally (no synthetic identities are involved).
     * With calibration the correction also reverses the original bucket
     * contribution (exact recorded weight, clamped at zero) and adds the
     * corrected contribution.
     *
     * $legitimate mirrors the (mistaken) first confirmed outcome — a first
     * confirmation of legitimate=true (trust) is corrected to abuse and
     * vice versa. Returns true when the correction was applied
     * (best-effort — a state-backend failure is silent and the retry may
     * apply it later); false when the decision is unknown/expired or
     * already carries the target outcome.
     *
     * @throws \InvalidArgumentException when $decisionId is empty
     */
    public function confirmCorrection(string $decisionId, bool $legitimate, ?float $weight = null): bool
    {
        if ($decisionId === '') {
            throw new \InvalidArgumentException('confirmCorrection requires a non-empty decision id');
        }
        if ($this->calibration !== null) {
            try {
                return $this->calibration->correctOutcome($decisionId, $legitimate, $weight);
            } catch (\InvalidArgumentException $e) {
                throw $e;
            } catch (\Throwable) {
                return false;
            }
        }
        try {
            return $this->store->correctOutcome($decisionId, $legitimate);
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * The no-op receipt for a status-0 confirmation (already confirmed /
     * missing / backend failure): the event id is derived exactly like the
     * feedback path would, but NO observation reaches the store — the
     * caller sees a duplicate-marked, zero-signal receipt.
     */
    private function skippedConfirmationReceipt(RiskEventKind $event, RiskContext $ctx, ?string $idempotencyKey): EventReceipt
    {
        return new EventReceipt(
            eventId: $this->normalizeEventId($event, $ctx->scope, $idempotencyKey),
            isDuplicate: true,
            signals: SignalVector::zero(),
        );
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

    /**
     * Derives the bounded risk-v2 signal vector from the v2 context.
     *
     * - honeypot = 1000 when the context reports a honeypot hit OR the
     *   current observation is one of the honeypot event kinds. Any of the
     *   three derives the signal; probabilistic evidence, never a gate.
     * - sessionInconsistency = 1000 when the session's first-seen
     *   client-context tag differs from the current tag. It is 0 when the
     *   tag is absent (first request), the session is absent, or the
     *   record read fails (neutral degradation). A store lacking the
     *   optional SessionContextTagStoreInterface capability degrades
     *   exactly like a backend miss.
     * - tlsInconsistency = 1000 when the session's first-seen trusted-edge
     *   TLS classification tag differs from the current tag. It is 0 when
     *   the tag is absent (first request), the session is absent, the tag
     *   exceeds the 64-char bound (treated as absent), the record read
     *   fails (neutral degradation), or the store lacks the optional
     *   SessionTlsTagStoreInterface capability.
     */
    private function buildV2Signals(RiskV2Context $v2, RiskContext $c, RiskObservation $observation): RiskV2Signals
    {
        $honeypot = ($v2->honeypotHit || $c->event->isHoneypot()) ? 1000 : 0;
        $inconsistent = 0;
        if (
            $v2->clientContextTag !== null && $v2->clientContextTag !== ''
            && $observation->sessionId !== null
            && $this->store instanceof SessionContextTagStoreInterface
        ) {
            try {
                $first = $this->store->sessionFirstContextTag($observation->sessionId, $v2->clientContextTag);
                if ($first !== null && $first !== $v2->clientContextTag) {
                    $inconsistent = 1000;
                }
            } catch (\Throwable) {
                // Best-effort record: a failed read degrades to consistent
                // (neutral) — probabilistic evidence never breaks an
                // assessment.
            }
        }
        $tlsInconsistent = 0;
        $tlsTag = $v2->tlsTag;
        if (
            $tlsTag !== null && $tlsTag !== '' && strlen($tlsTag) <= 64
            && $observation->sessionId !== null
            && $this->store instanceof SessionTlsTagStoreInterface
        ) {
            try {
                $firstTls = $this->store->sessionFirstTlsTag($observation->sessionId, $tlsTag);
                if ($firstTls !== null && $firstTls !== $tlsTag) {
                    $tlsInconsistent = 1000;
                }
            } catch (\Throwable) {
                // Best-effort record: a failed read degrades to consistent
                // (neutral) — probabilistic evidence never breaks an
                // assessment.
            }
        }

        return new RiskV2Signals(honeypot: $honeypot, sessionInconsistency: $inconsistent, tlsInconsistency: $tlsInconsistent);
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
     * pack('N', scope) . chr(event) . input, keyed by the master-derived
     * event key, giving 64 lowercase hex chars. Domain separation (event
     * kind + scope) means the same raw key dedupes independently per
     * event/scope, and the HMAC (not a bare sha256) means low-entropy keys
     * are not dictionary-recoverable from the Redis dedupe keys. The
     * caller's raw key never appears verbatim in Redis. null/empty gives
     * a fresh random 32-hex id; longer than 4096 bytes throws
     * InvalidArgumentException. Rust mirrors this exactly.
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
     * Registers one decision in the always-on outcome ledger, the
     * exactly-once authority for later confirmed outcomes. With
     * calibration, the canonical register_decision.lua creates the receipt
     * (with the assessment-time sampling flag), the sampled total
     * denominator (when sampled) and the pending ledger entry, all
     * atomically. Without calibration, the store's outcome_register.lua
     * creates the pending ledger entry only.
     * The sampled flag is sample() (pure; the denominator is booked
     * atomically by the script) and true when calibration is null.
     * decisionHour anchors the outcome to the hour the decision was made.
     * Failures are silent, so registration never breaks issuance.
     */
    private function registerDecisionOutcome(int $scope, RiskDecision $decision, int $nowMs): void
    {
        $decisionHour = intdiv($nowMs, 3_600_000);
        try {
            $sampled = $this->calibration?->sample() ?? true;
            if ($this->calibration !== null) {
                $this->calibration->recordReceipt(
                    $decision->decisionId,
                    $scope,
                    $decision->band,
                    $decision->action,
                    $decision->score,
                    $sampled ? 1 : 0,
                    $decisionHour,
                );
            } else {
                $this->store->registerOutcome($decision->decisionId, $scope, $decisionHour, $decision->score);
            }
        } catch (\Throwable) {
            // registration must never break issuance
        }
    }

    private function recordDecisionMetrics(int $scope, RiskDecision $decision): void
    {
        $this->metrics->increment(sprintf('decisions:%d:%s:%d', $scope, $decision->action->value, $decision->band));
    }
}
