<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

use KiwiCaptcha\Risk\Asn\AsnBucket;
use KiwiCaptcha\Risk\Asn\AsnDataset;
use KiwiCaptcha\Risk\Breaker\CircuitBreaker;
use KiwiCaptcha\Risk\Calibration\CalibrationStore;
use KiwiCaptcha\Risk\Evidence\DecoyEscalation;
use KiwiCaptcha\Risk\Evidence\DecoyEscalationReaderInterface;
use KiwiCaptcha\Risk\Evidence\EvidenceModel;
use KiwiCaptcha\Risk\Marks\FirstAttemptEvidence;
use KiwiCaptcha\Risk\Marks\MarksEscalation;
use KiwiCaptcha\Risk\Marks\MarksReaderInterface;
use KiwiCaptcha\Risk\Marks\MarksRequest;
use KiwiCaptcha\Risk\Metrics\RiskMetrics;
use KiwiCaptcha\Risk\Network\NetworkClassifierInterface;
use KiwiCaptcha\Risk\Pricing\PriceContextSourceInterface;
use KiwiCaptcha\Risk\Pricing\PriceInputs;
use KiwiCaptcha\Risk\Pricing\PriceModel;
use KiwiCaptcha\Risk\Pricing\PriceRequest;
use KiwiCaptcha\Risk\Storage\ProcessEmergencyCap;
use KiwiCaptcha\Risk\Storage\ConsolidatedAssessmentStoreInterface;
use KiwiCaptcha\Risk\Storage\OutcomeRegistration;
use KiwiCaptcha\Risk\Storage\RiskStateStoreInterface;
use KiwiCaptcha\Risk\Storage\RiskStoreException;
use KiwiCaptcha\Risk\Storage\SessionContextTagStoreInterface;
use KiwiCaptcha\Risk\Storage\SessionTlsTagStoreInterface;

/**
 * Adaptive risk engine: assesses one request and returns a RiskDecision.
 *
 * Pipeline: emergency limiter (single per-process window, before any state
 * backend) -> observation -> circuit breaker -> state store (evalsha) ->
 * scorer -> policy (with the per-client scope-action hysteresis map:
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

    /**
     * The immutable policy the engine decides under. Callers that
     * construct gateways around the engine can verify their synthetic
     * policy rows against exactly the object the engine will consult,
     * so the gateway's unknown-scope contract and the engine's policy
     * can never silently disagree.
     */
    public function policy(): RiskPolicy
    {
        return $this->policy;
    }

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
        private readonly ?TargetIdentifierResolverInterface $targetResolver = null,
        private readonly ?MarksReaderInterface $marksReader = null,
        private readonly ?PriceContextSourceInterface $priceContext = null,
        private readonly ?DecoyEscalationReaderInterface $decoyEscalationReader = null,
        private readonly ?AsnDataset $asnDataset = null,
        /**
         * Novelty enforcement mode: 'learn' (default) seeds network tags
         * on every successful login without demanding a step-up, so a
         * rollout never locks out existing users. 'enforce' demands
         * step-up on a genuinely novel network. Switch to 'enforce'
         * after the learning window.
         */
        private readonly string $noveltyEnforcement = 'learn',
        private readonly ?\KiwiCaptcha\Risk\Storage\PrincipalNetworkTagStoreInterface $principalNetworks = null,
    ) {
        // The timing configuration is validated at the construction
        // boundary: a zero epoch divides by zero in the observation
        // pipeline, and a non-positive TTL expires or persists risk state
        // immediately. The Redis store enforces the same invariants on
        // its own copy of these knobs.
        foreach ([
            'sourceEpochSecs' => $sourceEpochSecs,
            'subnetEpochSecs' => $subnetEpochSecs,
            'stateTtlSecs' => $stateTtlSecs,
            'principalTtlSecs' => $principalTtlSecs,
            'dedupeTtlSecs' => $dedupeTtlSecs,
        ] as $knob => $value) {
            if ($value < 1) {
                throw new \InvalidArgumentException(sprintf('%s must be >= 1 (got %d)', $knob, $value));
            }
        }
    }

    /**
     * True when the current assessment's consolidated store call already
     * registered the decision's pending outcome-ledger entry atomically
     * (calibration-less consolidated path); registerDecisionOutcome() then
     * skips its separate registration. Per-assessment, reset at the top of
     * runPipeline().
     */
    private bool $outcomeRegisteredByConsolidated = false;

    public function metrics(): RiskMetrics
    {
        return $this->metrics;
    }

    /**
     * The target pseudonym of one assessment, as an optional side
     * channel beside the frozen risk-v1 observation wire.
     *
     * The observation's Lua argv contract is frozen, so the target
     * dimension rides its own API instead of the observation struct: a
     * later plane consumes this HMAC and keys its state under it. The
     * resolver maps the scope to its configured form field and returns
     * the raw submitted value; this method normalizes it and returns
     * only the derived pseudonym. The raw and the normalized value
     * never leave this boundary, never reach the store, and never
     * appear in metrics.
     *
     * Returns null when no resolver is configured, the scope carries no
     * target field, the field value is empty, or the value normalizes
     * to the empty string: that assessment simply has no target
     * dimension. Scoring is untouched by this call.
     *
     * @param array<string, string> $fields the request's submitted form
     *                                      field values keyed by field
     *                                      name
     *
     * @throws \InvalidArgumentException when a normalization stage is
     *                                   unavailable (fail-closed)
     * @throws \RuntimeException         when the raw value is not valid
     *                                   UTF-8
     */
    public function resolveTargetId(int $scope, array $fields): ?string
    {
        if ($this->targetResolver === null) {
            return null;
        }
        $raw = $this->targetResolver->resolve($scope, $fields);
        if ($raw === null) {
            return null;
        }
        $normalized = TargetIdentifierNormalizer::normalize($raw);
        if ($normalized === '') {
            return null;
        }

        return $this->identityFactory->targetId($normalized);
    }

    /**
     * Assesses one pre-issue request and attaches the names-only
     * decision explanation (change.md 3.8.3) to the result: the top
     * contributing reasons, the identity dimension names involved, the
     * chosen action and, when a pricing stage is composed by the
     * caller, the rung name. Identical pipeline to assessPreIssue();
     * only the return type grows the additive explanation field.
     *
     * The engine reports the dimensions it can see on the request:
     * source, subnet, the session and principal dimensions when the
     * context carries those identities, and the target dimension when
     * a target resolver is attached. The asn and agent dimensions
     * belong to the caller's IdentityVector; pass their names through
     * ExplainedDecision::wrap() to compose the full set. No pseudonym
     * value ever enters the explanation.
     */
    public function assessPreIssueWithExplanation(RiskContext $c, ?string $idempotencyKey = null): ExplainedDecision
    {
        $dimensions = $this->explanationDimensions($c);

        return ExplainedDecision::wrap($this->assessPreIssue($c, $idempotencyKey), $dimensions);
    }

    /**
     * The identity dimension names the engine derives from the
     * assessment context alone, beside the documented engine surface.
     *
     * @return list<string>
     */
    private function explanationDimensions(RiskContext $c): array
    {
        $dimensions = ['source', 'subnet'];
        if ($c->sessionId !== null) {
            $dimensions[] = 'session';
        }
        if ($c->principalId !== null) {
            $dimensions[] = 'principal';
        }
        if ($this->targetResolver !== null) {
            $dimensions[] = 'target';
        }

        return $dimensions;
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
        $this->validateV2Context($v2);

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
            // A limiter hard-deny never reached the state backend; the
            // ledger/receipt registration is skipped for the same reason
            // (no backend call on a decision the backend never saw).
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
        $this->validateV2Context($v2);
        $observation = $this->buildObservation($c, $nowMs, $idempotencyKey);
        $this->outcomeRegisteredByConsolidated = false;

        if ($this->breaker->isOpen()) {
            $this->metrics->increment('degraded:breaker');
            $decision = $this->policy->degradedDecision($c->scope, $this->storeGlobalLevel());
            $this->recordDecisionMetrics($c->scope, $decision);
            // While the breaker is open the engine skips the state backend
            // entirely — including the ledger/receipt registration.
            return $decision;
        }

        // The pending outcome-ledger registration to fold into the
        // consolidated assessment. Only the calibration-less path
        // consolidates: with calibration attached, the calibrator's
        // register_decision.lua books the receipt + sample denominator +
        // ledger atomically, so the engine keeps that as the sole
        // authority. The decision_id is generated here so the ledger and
        // the returned decision carry the same id.
        $decisionId = null;
        $registration = null;
        if ($this->calibration === null && $this->store instanceof ConsolidatedAssessmentStoreInterface) {
            $decisionId = bin2hex(random_bytes(16));
            $registration = new OutcomeRegistration(
                decisionId: $decisionId,
                decisionHour: intdiv($nowMs, 3_600_000),
                baseRisk: $this->policy->baseRisk($c->scope),
                globalPressureEnabled: $this->enableGlobalPressure,
                honeypotHit: $v2?->honeypotHit ?? false,
                weights: $this->policy->weights,
                v2Weights: $v2Weights ?? new RiskV2Weights(),
            );
        }

        $start = microtime(true);
        // Global level / cooldown: taken from the reply object when the
        // store offers one (call-scoped, immutable — no racy
        // shared-mutable side-channel reads under coroutine runtimes);
        // null defers to the side channels for stores without the surface.
        $globalLevel = null;
        $cooldownUntilMs = null;
        $targetFailures = 0;
        $targetSpreadSources = 0;
        $targetSpreadAsns = 0;
        try {
            if ($this->store instanceof ConsolidatedAssessmentStoreInterface) {
                // Consolidated assessment: ONE atomic script call runs the
                // v1 observation AND the first-seen session tag records
                // (SET NX, session TTL) AND the pending outcome-ledger
                // registration, returning the vector plus the recorded
                // tags plus the registration status — an established
                // risk-v2 session costs one script call instead of the
                // separate tag round trips and the separate registration.
                if (method_exists($this->store, 'assessV2WithReply')) {
                    $reply = $this->store->assessV2WithReply(
                        $observation,
                        $this->presentedContextTag($v2, $observation),
                        $this->presentedTlsTag($v2, $observation),
                        $registration,
                    );
                    $vector = $reply->vector;
                    $globalLevel = $reply->globalLevel;
                    $cooldownUntilMs = $reply->cooldownUntilMs;
                    $existingContextTag = $reply->existingContextTag;
                    $existingTlsTag = $reply->existingTlsTag;
                    $targetFailures = (int) ($reply->targetFailures ?? 0);
                    $targetSpreadSources = (int) ($reply->targetSpreadSources ?? 0);
                    $targetSpreadAsns = (int) ($reply->targetSpreadAsns ?? 0);
                } else {
                    [$vector, $existingContextTag, $existingTlsTag, $_registered] = $this->store->assessV2(
                        $observation,
                        $this->presentedContextTag($v2, $observation),
                        $this->presentedTlsTag($v2, $observation),
                        $registration,
                    );
                }
                if ($registration !== null) {
                    // The pending ledger entry was created (or already
                    // existed for a retried decision_id) atomically with
                    // the observation — no separate registration call.
                    $this->outcomeRegisteredByConsolidated = true;
                }
            } elseif (method_exists($this->store, 'observeWithReply')) {
                $reply = $this->store->observeWithReply($observation);
                $vector = $reply->vector;
                $globalLevel = $reply->globalLevel;
                $cooldownUntilMs = $reply->cooldownUntilMs;
                $existingContextTag = null;
                $existingTlsTag = null;
            } else {
                $vector = $this->store->observe($observation);
                $existingContextTag = null;
                $existingTlsTag = null;
            }
        } catch (RiskStoreException $e) {
            $this->breaker->recordFailure();
            $this->metrics->increment('degraded:store');
            $decision = $this->policy->degradedDecision($c->scope, $this->storeGlobalLevel());
            $this->recordDecisionMetrics($c->scope, $decision);
            // The store just failed on this assessment: no ledger/receipt
            // registration against the failing backend.
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
        // evidence never breaks an assessment). With a consolidated store
        // the recorded tags already came back with the observation; a
        // store without the capability falls back to the individual
        // record reads. The v2 weights are the operator override when
        // given, else the default weights (byte-identical scores to today).
        $v2Signals = null;
        if ($v2 !== null) {
            $v2Signals = $this->store instanceof ConsolidatedAssessmentStoreInterface
                ? $this->deriveV2SignalsFromRecords($v2, $c, $existingContextTag, $existingTlsTag, $targetFailures, $targetSpreadSources, $targetSpreadAsns)
                : $this->buildV2Signals($v2, $c, $observation);
        }
        $score = $v2Signals !== null
            ? $this->scorer->scoreV2($base, $vector, $this->policy->weights, $v2Signals, $v2Weights ?? new RiskV2Weights())
            : $this->scorer->score($base, $vector, $this->policy->weights);
        if (!$this->enableGlobalPressure) {
            $globalLevel = 0;
            $cooldownUntilMs = 0;
        } else {
            $globalLevel ??= $this->storeGlobalLevel();
            $cooldownUntilMs ??= $this->storeCooldownUntilMs();
        }
        $decision = $this->policy->decide(
            scope: $c->scope,
            score: $score,
            s: $vector,
            r: $c->resources,
            globalLevel: $globalLevel,
            nowMs: $nowMs,
            cooldownUntilMs: $cooldownUntilMs,
            hysteresis: $this->hysteresis,
            decisionId: $decisionId,
            clientKey: $observation->sessionId ?? $observation->sourceId,
        );

        // The decisive attacker stage: additive, after the plain policy
        // decision, and only when a marks reader is wired. An unreadable
        // marks surface floors the request at the maximum challenge rung
        // fail-closed instead of fabricating a deny.
        if ($this->marksReader !== null) {
            $decision = $this->applyMarksStage($decision, $c, $observation, $vector, $v2, $nowMs);
        }

        // The decoy escalation stage: additive, after the marks stage,
        // and only when a decoy-escalation reader is wired. An unreadable
        // escalation surface degrades to not-live (the stage is a
        // temporary price raise, so a backend miss must never escalate).
        if ($this->decoyEscalationReader !== null) {
            $decision = DecoyEscalation::apply(
                $decision,
                $this->decoyEscalationReader->escalationLive($observation->sessionId),
            );
            $decision = $this->dropQuarantineOnEscalation($decision);
        }

        // The evidence stage (change.md 3.2.1 and 3.2.3): additive,
        // after the decoy escalation and before the pricing stage. It
        // composes whenever the assessment carries evidence inputs (no
        // separate wiring), and an absent or rejected payload is the
        // neutral-unknown state: the stage passes the decision through
        // byte-identically and may only raise.
        if ($v2 !== null && ($v2->telemetryPayload !== null || $v2->solveMs !== null)) {
            $decision = EvidenceModel::apply(
                $decision,
                EvidenceModel::inputs($v2->telemetryPayload, $v2->solveMs, $v2->solveRung),
                $c->resources,
            );
            $decision = $this->dropQuarantineOnEscalation($decision);
        }

        // The continuous pricing stage: additive, after the marks stage,
        // and only when a price-context source is wired. The observed
        // global-pressure signal is the untrusted-scope pressure, so the
        // ramp is inert exactly when the global channel is disabled. An
        // unreadable pricing surface prices the request fail-closed as an
        // unproven identity (zero bucket credit, full ramp).
        if ($this->priceContext !== null) {
            $decision = $this->applyPriceStage($decision, $c, $observation, $vector);
            $decision = $this->dropQuarantineOnEscalation($decision);
        }

        $this->metrics->gauge('global:level', $decision->globalLevel);
        $this->metrics->gauge('resources:argon_capacity', $c->resources->argonCapacity);
        $this->recordDecisionMetrics($c->scope, $decision);
        $this->registerDecisionOutcome($c->scope, $decision, $nowMs);
        return $decision;
    }

    /**
     * The continuous pricing stage behind runPipeline(): resolves the
     * request's pricing inputs through the wired source and composes the
     * priced rung with the plain decision. The price may only raise the
     * composed action; an unreadable source prices the request
     * fail-closed as an unproven identity.
     */
    private function applyPriceStage(
        RiskDecision $decision,
        RiskContext $c,
        RiskObservation $observation,
        SignalVector $vector,
    ): RiskDecision {
        $request = new PriceRequest(
            scope: $c->scope,
            sourceIp: $c->sourceIp,
            session: $observation->sessionId,
            principal: $observation->principalId,
        );
        try {
            $inputs = $this->priceContext->priceInputs($request);
        } catch (\Throwable) {
            $inputs = PriceInputs::failClosed();
        }

        return PriceModel::apply($decision, $inputs, $vector->globalPressure, $c->resources);
    }

    /**
     * The decisive attacker stage behind runPipeline(): reads the
     * request's marks view through the wired reader and combines it with
     * the plain decision. The engine hands the reader the session and
     * principal pseudonyms it derived; the reader adds the deployment's
     * own dimensions (agent, ASN bucket, the login target). The
     * quarantine selection (change.md 1.3 and 3.3.4) is part of the
     * decision plane's posture: a server-confirmed spam identity with a
     * clean request quarantines instead of escalating, wire-identical
     * to allow.
     */
    private function applyMarksStage(
        RiskDecision $decision,
        RiskContext $c,
        RiskObservation $observation,
        SignalVector $vector,
        ?RiskV2Context $v2,
        int $nowMs,
    ): RiskDecision {
        $request = new MarksRequest(
            scope: $c->scope,
            sourceIp: $c->sourceIp,
            session: $observation->sessionId,
            principal: $observation->principalId,
        );
        $decoyEvidence = $c->event->isHoneypot() || ($v2?->honeypotHit ?? false);
        $firstAttempt = $this->firstAttemptEvidence($c, $observation, $vector, $v2, $decision);
        try {
            $view = $this->marksReader->requestMarks($request);
        } catch (\Throwable) {
            return MarksEscalation::applyUnreadable($decision, $nowMs, $c->resources);
        }

        return MarksEscalation::apply(
            $decision,
            $view->withFirstAttempt($firstAttempt),
            MarksEscalation::corroborated($vector, $decoyEvidence),
            $nowMs,
            $this->marksReader->markTtlMs(),
            $c->resources,
            true,
        );
    }

    /**
     * The first-attempt prevention evidence (P0-1) of one assessment:
     * the signals that stop a valid stolen credential before any failure
     * has accumulated anywhere (Rust mirror:
     * RiskEngine::first_attempt_evidence).
     *
     * - novelNetwork: on an AuthenticationSuccess / first login, the
     *   principal has never been seen from this network bucket (/64 for
     *   IPv6, the IPv4 itself) OR the account carries no prior trusted
     *   network. A store without the record surface degrades to neutral
     *   (never novel), like the session tags.
     * - breachedCredential: the caller's v2 context asserts a
     *   known-breached credential (the same step-up-worthy shape as
     *   honeypot evidence).
     * - scopePressure: global pressure is enabled and the scope
     *   failure-ratio pressure is running at/above
     *   MarksEscalation::`SCOPE_PRESSURE`_FLOOR / `SCOPE_PRESSURE`_LEVEL —
     *   every first-attempt login escalates, not only the attacked
     *   target's.
     */
    private function firstAttemptEvidence(
        RiskContext $c,
        RiskObservation $observation,
        SignalVector $vector,
        ?RiskV2Context $v2,
        RiskDecision $decision,
    ): FirstAttemptEvidence {
        $isLogin = $c->event === RiskEventKind::AuthenticationSuccess
            || $c->event === RiskEventKind::AuthenticationFailure;
        $novelNetwork = false;
        $scopePressure = false;
        if ($isLogin) {
            if ($this->principalNetworks !== null && $observation->principalId !== null) {
                // Novelty is judged on the ASN bucket first: carriers
                // rotate IPv6 /64s and cgnat addresses per connection,
                // so a /64 key alone would step up most mobile logins.
                // A known ASN is never novel; an unknown ASN is novel.
                // The /64 bucket is a contributing signal only (it can
                // raise novelty when the principal has no trusted
                // network at all, never on its own against a known ASN).
                $network = self::networkBucket($c->sourceIp);
                $asn = $this->asnBucketOf($c->sourceIp);
                try {
                    $asnSeen = $asn !== '' && $asn !== '0'
                        ? $this->principalNetworks->principalNetworkSeen($observation->principalId, 'asn:'.$asn)
                        : null;
                    $trusted = $this->principalNetworks->principalHasTrustedNetwork($observation->principalId);
                    $netSeen = $this->principalNetworks->principalNetworkSeen($observation->principalId, $network);
                } catch (\Throwable) {
                    $asnSeen = null;
                    $trusted = null;
                    $netSeen = null;
                }
                $isNovel = false;
                if ($asnSeen === false) {
                    // Never-seen ASN: novel regardless of the /64.
                    $isNovel = true;
                } elseif ($asnSeen === true) {
                    // Known ASN: /64 novelty alone never fires.
                    $isNovel = false;
                } else {
                    // No ASN data: fall back to the /64 bucket, and to
                    // the no-trusted-network condition.
                    $isNovel = ($netSeen === false) || ($trusted === false);
                }
                // Migration grace: in 'learn' mode a novel network is
                // recorded but never escalates. Every existing account
                // has no network history on the day this ships; without
                // this window every user would be stepped up at once.
                if ($isNovel) {
                    try {
                        $this->principalNetworks->recordPrincipalNetworkTag($observation->principalId, $network);
                        if ($asn !== '' && $asn !== '0') {
                            $this->principalNetworks->recordPrincipalNetworkTag($observation->principalId, 'asn:'.$asn);
                        }
                    } catch (\Throwable) {
                        // Best effort: the tag write never breaks login.
                    }
                }
                $novelNetwork = $isNovel && $this->noveltyEnforcement === 'enforce';
            }
            if (
                $this->enableGlobalPressure
                && $decision->globalLevel >= MarksEscalation::SCOPE_PRESSURE_LEVEL
            ) {
                $scopePressure = true;
            }
            if (
                $this->enableGlobalPressure
                && $vector->globalPressure >= MarksEscalation::SCOPE_PRESSURE_FLOOR
            ) {
                $scopePressure = true;
            }
        }

        return new FirstAttemptEvidence(
            novelNetwork: $novelNetwork,
            breachedCredential: $v2?->breachedCredential ?? false,
            scopePressure: $scopePressure,
        );
    }

    /**
     * The network bucket of a source address for the novel-network gate:
     * the IPv4 address itself, or the IPv6 /64 prefix. Stable spelling
     * (family byte + masked packed bytes, hex), byte-identical with the
     * Rust network_bucket().
     */
    public static function networkBucket(string $ip): string
    {
        $packed = inet_pton($ip);
        if ($packed === false) {
            return '';
        }
        if (\strlen($packed) === 4) {
            return bin2hex("\x04".$packed);
        }
        return bin2hex("\x06".substr($packed, 0, 8));
    }

    /** The ASN bucket of a source address, '' when no dataset is wired. */
    private function asnBucketOf(string $ip): string
    {
        if ($this->asnDataset === null) {
            return '';
        }
        try {
            $info = $this->asnDataset->lookup($ip);

            return (string) ($info->asn ?? $info->bucket);
        } catch (\Throwable) {
            return '';
        }
    }

    /**
     * The severity-monotonic precedence of the composed pipeline: a
     * quarantine disposition never survives an escalation. When a stage
     * after the marks stage (decoy, evidence, pricing) raised the action
     * above Allow, the raised action wins and the quarantine flag drops;
     * an inert stage keeps the decision byte-identical, quarantine
     * included.
     */
    private function dropQuarantineOnEscalation(RiskDecision $decision): RiskDecision
    {
        if ($decision->quarantined && $decision->action !== RiskAction::Allow) {
            return $decision->withoutQuarantine();
        }

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
     *
     * The pseudonym overrides carry the typed outcomes API's pre-derived
     * session/principal pseudonyms. An outcome reported on an identity
     * handle addresses exactly the identity the caller named, so the
     * observation rides the handle's pseudonym instead of re-deriving
     * the context's raw identifier.
     */
    private function emitFeedback(
        RiskEventKind $event,
        RiskContext $c,
        ?string $idempotencyKey = null,
        ?string $sessionPseudonym = null,
        ?string $principalPseudonym = null,
    ): EventReceipt {
        $nowMs = (int) floor(microtime(true) * 1000);
        $observation = $this->buildObservation($c, $nowMs, $idempotencyKey, $event, $sessionPseudonym, $principalPseudonym);
        try {
            if (method_exists($this->store, 'observeWithReply')) {
                // Reply-object surface: the dedupe verdict comes back with
                // the observation — no racy side-channel read.
                $reply = $this->store->observeWithReply($observation);
                $vector = $reply->vector;
                $isDuplicate = $reply->isDuplicate;
            } else {
                $vector = $this->store->observe($observation);
                $isDuplicate = method_exists($this->store, 'lastIsDuplicate') && (bool) $this->store->lastIsDuplicate();
            }
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
     * The dedupe id of one typed outcome report: the exact
     * normalizeEventId() result the feedback path books under, so the
     * long-memory mark write and the feedback event share one
     * idempotency domain. An absent or empty caller key returns ''
     * (mark dedupe disabled — no marker key is written for a report
     * that cannot be retried). Rust mirror: derive_outcome_event_id.
     *
     * @internal reserved for the Outcomes facade
     */
    public function deriveOutcomeEventId(?string $idempotencyKey, int $scope, RiskEventKind $event): string
    {
        if ($idempotencyKey === null || $idempotencyKey === '') {
            return '';
        }

        return $this->normalizeEventId($event, $scope, $idempotencyKey);
    }

    /**
     * The spread elements one outcome report contributes to the target
     * dimension's HLLs: a non-rotating element scoped to the target.
     *
     * The source element is HMAC(spread_key, target_id || '/' ||
     * /64-or-IPv4) (the full IPv4 address, or the IPv6 /64) and the ASN
     * element HMAC(spread_key, target_id || '/' || asn_bucket). Both are
     * keyed by the target-dimension HKDF key. The elements never rotate
     * with the 15-minute source epoch, so one IP cannot mint a fresh
     * "distinct source" every epoch and inflate the spread into an
     * elapsed-time meter. The ASN bucket is the attached dataset's
     * lookup, else the unlisted-namespace bucket. See
     * {@see AsnBucket::forUnlistedIp()}. An absent context records no
     * spread element. Rust mirror:
     * `RiskEngine::target_spread_elements`.
     *
     * @internal reserved for the Outcomes facade
     *
     * @return array{string, string} [source, asn]
     */
    public function targetSpreadElements(string $targetId, ?RiskContext $c): array
    {
        if ($c === null) {
            return ['', ''];
        }
        $net = $this->identityFactory->maskIp($c->sourceIp, 32, 64);
        $source = $this->spreadElement($targetId . '/' . $net);
        $asnBucket = $this->asnDataset !== null
            ? $this->asnDataset->bucketId($c->sourceIp)
            : AsnBucket::forUnlistedIp($c->sourceIp);
        $asn = $this->spreadElement($targetId . '/' . $asnBucket);

        return [$source, $asn];
    }

    /** The hex HLL element of one target-spread contribution. */
    private function spreadElement(string $message): string
    {
        return bin2hex(substr(hash_hmac('sha256', $message, $this->keys->target, true), 0, 16));
    }

    /**
     * The typed outcomes API's feedback entry: books the mapped risk-v1
     * event through the internal feedback path, optionally riding the
     * handle's pre-derived session/principal pseudonyms. The typed API
     * itself is the server-side authority here (an identity handle has
     * no ledger entry to confirm first), so the confirmation-event guard
     * of record_feedback() is deliberately absent; the caller's
     * idempotency key is the dedupe authority of the report.
     *
     * @internal reserved for the Outcomes facade; application code uses
     *           KiwiOutcomes::report()
     */
    public function recordOutcomeFeedback(
        RiskEventKind $event,
        RiskContext $c,
        ?string $idempotencyKey = null,
        ?string $sessionPseudonym = null,
        ?string $principalPseudonym = null,
    ): EventReceipt {
        return $this->emitFeedback($event, $c, $idempotencyKey, $sessionPseudonym, $principalPseudonym);
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
     * Reputation authorization of one accepted-outcome status: statuses
     * 1 and 2 always. Status 3 (a capped label) is authorized only when
     * the outcome is abusive. A capped trust label must never mint
     * unlimited reputation credit. Status 4 is the v2 confirm's trust
     * cap and never authorizes. Rust mirror: emit_feedback's confirm gate.
     */
    private static function reputationAuthorized(int $status, bool $legitimate): bool
    {
        return $status === 1 || $status === 2 || ($status === 3 && !$legitimate);
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
        if ($samplingProbabilityPpm !== null && ($samplingProbabilityPpm < 1 || $samplingProbabilityPpm > 1_000_000)) {
            throw new \InvalidArgumentException('samplingProbabilityPpm must be within 1..1000000');
        }
        $weight = $samplingProbabilityPpm === null ? null : 1_000_000 / $samplingProbabilityPpm;
        if (!self::reputationAuthorized($this->confirmOutcome($decisionId, true, $weight), true)) {
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
        if ($samplingProbabilityPpm !== null && ($samplingProbabilityPpm < 1 || $samplingProbabilityPpm > 1_000_000)) {
            throw new \InvalidArgumentException('samplingProbabilityPpm must be within 1..1000000');
        }
        $weight = $samplingProbabilityPpm === null ? null : 1_000_000 / $samplingProbabilityPpm;
        if (!self::reputationAuthorized($this->confirmOutcome($decisionId, false, $weight), false)) {
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
     * Rejects a risk-v2 context whose client-context tag exceeds the
     * 64-byte contract bound (fail-closed: the assessment input is
     * rejected, never silently truncated — a truncation would split one
     * session's identity across tag records). The TLS tag keeps its
     * documented over-bound handling (treated as absent). Rust mirrors
     * this exactly.
     */
    private function validateV2Context(?RiskV2Context $v2): void
    {
        if ($v2 === null) {
            return;
        }
        if ($v2->clientContextTag !== null
            && strlen($v2->clientContextTag) > RiskV2Context::MAX_TAG_BYTES) {
            throw new \InvalidArgumentException(sprintf(
                'client context tag must not exceed %d bytes',
                RiskV2Context::MAX_TAG_BYTES
            ));
        }
        if ($v2->telemetryPayload !== null
            && strlen($v2->telemetryPayload) > RiskV2Context::MAX_TELEMETRY_PAYLOAD_BYTES) {
            throw new \InvalidArgumentException(sprintf(
                'telemetry payload must not exceed %d bytes',
                RiskV2Context::MAX_TELEMETRY_PAYLOAD_BYTES
            ));
        }
        if (($v2->solveMs === null) !== ($v2->solveRung === null)) {
            throw new \InvalidArgumentException('solve facts must carry both the duration and the rung key');
        }
    }

    /**
     * The client-context tag to present to the consolidated assessment
     * call: the v2 context's tag when a session pseudonym exists and the
     * tag is non-empty, else null (no record is written). Mirrors the
     * guards of the fallback buildV2Signals() path exactly. The 64-byte
     * bound is enforced by validateV2Context() before any store call.
     */
    private function presentedContextTag(?RiskV2Context $v2, RiskObservation $observation): ?string
    {
        if ($v2 === null || $observation->sessionId === null) {
            return null;
        }
        if ($v2->clientContextTag === null || $v2->clientContextTag === '') {
            return null;
        }

        return $v2->clientContextTag;
    }

    /**
     * The trusted-edge TLS tag to present to the consolidated assessment
     * call: the v2 context's tag when a session pseudonym exists and the
     * tag is non-empty and within the 64-char bound, else null (no record
     * is written). Mirrors the guards of the fallback buildV2Signals()
     * path exactly.
     */
    private function presentedTlsTag(?RiskV2Context $v2, RiskObservation $observation): ?string
    {
        if ($v2 === null || $observation->sessionId === null) {
            return null;
        }
        if ($v2->tlsTag === null || $v2->tlsTag === '' || strlen($v2->tlsTag) > 64) {
            return null;
        }

        return $v2->tlsTag;
    }

    /**
     * Derives the bounded risk-v2 signal vector from the tags recorded by
     * the consolidated assessment call (the store has already applied the
     * first-seen records atomically with the observation).
     *
     * - honeypot = 1000 when the context reports a honeypot hit OR the
     *   current observation is one of the honeypot event kinds. Any of the
     *   three derives the signal; probabilistic evidence, never a gate.
     * - sessionInconsistency = 1000 when the session's recorded
     *   first-seen client-context tag differs from the current tag. It is
     *   0 when no record exists (first request), the tag is absent, or
     *   the record read failed (neutral degradation).
     * - tlsInconsistency = 1000 when the session's recorded first-seen
     *   trusted-edge TLS classification tag differs from the current tag.
     *   It is 0 when no record exists (first request), the tag is absent,
     *   or the record read failed (neutral degradation).
     */
    private function deriveV2SignalsFromRecords(RiskV2Context $v2, RiskContext $c, ?string $existingContextTag, ?string $existingTlsTag, int $targetFailures = 0, int $targetSpreadSources = 0, int $targetSpreadAsns = 0): RiskV2Signals
    {
        $honeypot = ($v2->honeypotHit || $c->event->isHoneypot()) ? 1000 : 0;
        $inconsistent = ($existingContextTag !== null && $existingContextTag !== '' && $existingContextTag !== $v2->clientContextTag) ? 1000 : 0;
        $tlsInconsistent = ($existingTlsTag !== null && $existingTlsTag !== '' && $existingTlsTag !== $v2->tlsTag) ? 1000 : 0;

        return new RiskV2Signals(honeypot: $honeypot, sessionInconsistency: $inconsistent, tlsInconsistency: $tlsInconsistent, targetFailurePressure: self::targetPressureSignal($targetFailures), targetSpread: self::targetSpreadSignal(max($targetSpreadSources, $targetSpreadAsns)));
    }

    /**
     * Derives the bounded risk-v2 signal vector from the v2 context via
     * the individual session-first-tag record reads. Fallback path for
     * stores without the consolidated assessment capability; identical
     * semantics to deriveV2SignalsFromRecords().
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
    private function buildV2Signals(RiskV2Context $v2, RiskContext $c, RiskObservation $observation, int $targetFailures = 0, int $targetSpreadSources = 0, int $targetSpreadAsns = 0): RiskV2Signals
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

        return new RiskV2Signals(honeypot: $honeypot, sessionInconsistency: $inconsistent, tlsInconsistency: $tlsInconsistent, targetFailurePressure: self::targetPressureSignal($targetFailures), targetSpread: self::targetSpreadSignal(max($targetSpreadSources, $targetSpreadAsns)));
    }


    /** Five failures (the attack threshold) saturate at 1000. */
    private static function targetPressureSignal(int $fails): int
    {
        return (int) min(1000, intdiv(max(0, $fails) * 1000, 5));
    }

    /** Twenty distinct sources saturate at 1000. */
    private static function targetSpreadSignal(int $spread): int
    {
        return (int) min(1000, intdiv(max(0, $spread) * 1000, 20));
    }

    /**
     * Builds the observation of one assessment or feedback event. The
     * pseudonym overrides carry the typed outcomes API's pre-derived
     * session/principal pseudonyms: when given, the observation rides
     * the caller's pseudonym verbatim instead of deriving the context's
     * raw identifier. An outcome reported on an identity handle names
     * its subject exactly; a wrong re-derivation would split it.
     */
    private function buildObservation(
        RiskContext $c,
        int $nowMs,
        ?string $idempotencyKey = null,
        ?RiskEventKind $event = null,
        ?string $sessionPseudonym = null,
        ?string $principalPseudonym = null,
    ): RiskObservation {
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
            sessionId: $sessionPseudonym ?? ($c->sessionId !== null ? $this->identityFactory->sessionId($c->sessionId) : null),
            principalId: $principalPseudonym ?? ($c->principalId !== null ? $this->identityFactory->principalId($c->principalId) : null),
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
     * InvalidArgumentException; a scope outside the u32 wire range throws
     * (the pack call would truncate it onto another scope's domain). Rust
     * mirrors this exactly.
     */
    private function normalizeEventId(RiskEventKind $event, int $scope, ?string $input): string
    {
        // The wire scope is a u32: the dedupe HMAC frames it with
        // pack('N'), which silently truncates an out-of-u32 PHP int onto
        // another scope's domain: -1 maps to 0xffffffff and 2^32 maps to
        // 0. Refusing the range keeps the scope a faithful domain
        // separator instead of folding distinct scopes together. The
        // Rust mirror's scope is a u32 and cannot represent the
        // offending values at all.
        if ($scope < 0 || $scope > 4294967295) {
            throw new \InvalidArgumentException(sprintf(
                'scope must be a canonical u32 within 0..4294967295 (got %d)',
                $scope,
            ));
        }
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
     *
     * The degraded paths never call this: a limiter hard-deny never
     * reached the state backend, and while the breaker is open or right
     * after a store failure the engine skips the state backend entirely —
     * receipt/ledger registration included.
     */
    private function registerDecisionOutcome(int $scope, RiskDecision $decision, int $nowMs): void
    {
        if ($this->outcomeRegisteredByConsolidated) {
            // The consolidated assessment registered the pending ledger
            // entry atomically with the observation (calibration-less
            // consolidated path); the separate call would duplicate it.
            return;
        }
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
        // The disposition label: a quarantined decision counts as its own
        // action label (its wire action stays allow), so the quarantine
        // volume is observable without touching the ladder vocabulary.
        $this->metrics->increment(sprintf('decisions:%d:%s:%d', $scope, $decision->dispositionLabel(), $decision->band));
    }
}
