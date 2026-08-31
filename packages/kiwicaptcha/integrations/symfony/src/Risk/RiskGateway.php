<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\ChallengeProfile;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Calibration\CalibrationStore;
use KiwiCaptcha\Risk\EventReceipt;
use KiwiCaptcha\Risk\Network\NetworkClassifierInterface;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskDecision;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskReason;
use KiwiCaptcha\Risk\RiskV2Context;
use KiwiCaptcha\Risk\RiskV2Weights;
use KiwiCaptcha\Risk\Storage\ProcessEmergencyCap;
use KiwiCaptcha\VerifyError;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Bundle-side facade over the adaptive risk engine.
 *
 * Builds the risk-v1 context (scope id, source/subnet/session pseudonyms
 * via the engine's identity derivation, network flags, live resource
 * pressure) for the challenge controller's pre-issue assessment, feeds
 * the engine's post-solve outcome signals, and maps decisions to
 * challenge profiles. Decisions are logged without ever logging an IP,
 * cookie value, principal or decision id.
 *
 * All engine calls go through the contract surface:
 *  - `assessPreIssue(ctx, idempotencyKey)` for the pre-issue decision
 *    (emergency limiter + observation + decision).
 *  - `reassess(ctx, idempotencyKey)` for the post-solve decision: a fresh
 *    decision without consuming the emergency admission budget, so a low
 *    limiter cap can never deny a valid solve.
 *  - `record_feedback(event, ctx, idempotencyKey, decisionId)` for outcome
 *    signals (no limits, no decision), so decision ids flow end-to-end and
 *    the calibration receipts keyed on them are consumed. The engine
 *    refuses ConfirmedLegitimate / ConfirmedAbuse through record_feedback
 *    (LogicException): confirmed outcomes are application signals only.
 *    The gateway never derives them from its own decisions and routes them
 *    exclusively through the engine's first-class confirmedLegitimate() /
 *    confirmedAbuse() (the engine requires a decision id for them and
 *    throws InvalidArgumentException without one).
 *
 * Confirmation split: outcome confirmation is two deliberately separate
 * paths:
 *  - {@see confirmDecisionOutcome()} is calibration-only: a decision id
 *    plus an outcome (and optionally the inverse sampling probability for
 *    weighted calibration), with no network identity and no scope. It
 *    targets delayed confirmations (email confirmation, fraud review,
 *    chargeback, moderation) where the original request context is long
 *    gone, and delegates to the engine's confirmOutcome (the atomic
 *    canonical confirm.lua consumes the receipt and records the
 *    score-weighted outcome in one script).
 *  - {@see recordConfirmedReputation()} (and the confirmedLegitimate /
 *    confirmedAbuse wrappers) is the context-ful path: when the
 *    source/session/principal context is available, the engine confirms the
 *    decision atomically (ledger-based once-only) and then records the
 *    reputation event against the source/session/principal pseudonyms.
 *    The optional $samplingProbabilityPpm (inverse sampling probability,
 *    parts per million) flows through to the engine's confirmed* methods
 *    (weight = 1_000_000/ppm for weighted calibration). Null in weighted
 *    mode makes the calibrator throw InvalidArgumentException, and the
 *    gateway lets that enforcement surface.
 *  - {@see samplingMetrics()} exposes the calibrator's sampling-resolution
 *    counters (zeros when calibration is disabled).
 *
 * Every feedback path is guarded against unknown scopes: when the scope is
 * not configured and unknown_scope.mode is "reject"/"baseline" (the engine
 * declines to evaluate), the signal is skipped with a debug log, so
 * feedback never crashes the request path.
 *
 * Resource pressure comes from the injected provider
 * ({@see ResourcePressureProviderInterface}); without one every dimension is
 * nominal (1000 = no pressure).
 *
 * Principal reputation: when a {@see PrincipalResolverInterface} service is
 * wired (and a RequestStack is available), the raw principal of the current
 * request flows into every context built here, pre-issue, post-solve and
 * all feedback signals, so the engine's principal counter is exercised. The
 * raw principal exists only in process memory; the engine's
 * RiskIdentityFactory HMAC-pseudonymizes it before Redis storage.
 *
 * Decision handles: {@see preIssue()} and {@see postSolveDecision()} record
 * the decision id of the current request via {@see setCurrentDecisionId()}.
 * It is request-local (the RequestStack main request's
 * `_kiwi_risk_decision_id` attribute, read via {@see currentDecisionId()}),
 * so a long-running worker can never leak one request's decision into the
 * next. For cross-request confirmation the controller pairs the minted
 * challenge nonce to the decision id via {@see attachDecisionForNonce()}: a
 * short-lived server-side mapping in the risk Redis
 * ({kiwi:<ns>}:decision:<nonce>, TTL = risk.nonce_to_decision_ttl_secs,
 * default 300) consumed once with GETDEL via
 * {@see resolveDecisionForNonce()}. The mapping carries only the decision
 * id, no IP and no identity.
 */
final class RiskGateway
{
    /** Request attribute holding the current request's decision id. */
    private const DECISION_ATTRIBUTE = '_kiwi_risk_decision_id';

    /**
     * @param array<string, int>                  $scopeIds         application scope string => risk-v1 int scope.
     * @param array<string, bool>                 $postSolveScopes  application scope string => post_solve_check flag.
     * @param 'reject'|'baseline'|'minimum'       $unknownScopeMode behavior for scopes absent from $scopeIds.
     * @param int|null                            $unknownScopeId   synthetic policy scope id used in 'minimum' mode.
     * @param string                              $decisionKeyPrefix full nonce->decision key prefix including the
     *                                                               hash tag, e.g. "{kiwi:prod}:decision:".
 * @param int                                 $decisionTtlSecs  TTL of the nonce->decision mapping
 *                                                               (risk.nonce_to_decision_ttl_secs,
 *                                                               default 300 s).
 * @param RiskPolicy|null                     $policy           the risk-v1 policy, required for
 *                                                               {@see degradedDecisionForScope()} (the extension
 *                                                               wires it automatically).
 * @param CalibrationStore|null               $calibration      the calibration store, wired only when
 *                                                               risk.calibration.enabled (drives
 *                                                               {@see samplingMetrics()}).
 */
    public function __construct(
        private readonly AdaptiveRiskEngine $engine,
        private readonly NetworkClassifierInterface $classifier,
        private readonly RiskProfileResolver $resolver,
        private readonly array $scopeIds,
        private readonly ?LoggerInterface $logger = null,
        private readonly ?ResourcePressureProviderInterface $resources = null,
        private readonly array $postSolveScopes = [],
        private readonly string $unknownScopeMode = 'reject',
        private readonly ?int $unknownScopeId = null,
        private readonly ?PrincipalResolverInterface $principalResolver = null,
        private readonly ?RequestStack $requestStack = null,
        private readonly ?\Predis\Client $decisionRedis = null,
        private readonly string $decisionKeyPrefix = '{kiwi:kiwi}:decision:',
        private readonly int $decisionTtlSecs = 300,
        private readonly ?RiskPolicy $policy = null,
        private readonly ?CalibrationStore $calibration = null,
        private readonly ?ProcessEmergencyCap $emergencyCap = null,
        /**
         * The operator-configured risk-v2 additive weights
         * (risk.v2.*, wired by the extension). Null keeps the contract
         * default weights (identical scores); a caller-explicit $v2Weights
         * argument on preIssue/postSolveDecisionV2 always wins.
         */
        private readonly ?RiskV2Weights $v2Weights = null,
    ) {
        if (!\in_array($unknownScopeMode, ['reject', 'baseline', 'minimum'], true)) {
            throw new \InvalidArgumentException(sprintf('unknownScopeMode must be "reject", "baseline" or "minimum" (got "%s")', $unknownScopeMode));
        }
    }

    /** The configured unknown-scope mode ('reject' | 'baseline' | 'minimum'). */
    public function unknownScopeMode(): string
    {
        return $this->unknownScopeMode;
    }

    /**
     * Whether the process-local emergency window is currently saturated:
     * the cheap local admission step the challenge controller runs before
     * any Redis issuance limiter. Non-consuming, see
     * {@see ProcessEmergencyCap::isOpen()}: the controller never marks
     * an allowance here, so the engine's own consuming check inside
     * assessPreIssue() stays the single consumer of the budget (no
     * double-counting). Returns false when no cap is wired (risk disabled).
     */
    public function emergencyCapSaturated(): bool
    {
        return $this->emergencyCap?->isOpen() ?? false;
    }

    /**
     * The risk-v1 int scope for an application scope string: the configured
     * id when present, otherwise the unknown-scope policy.
     *
     * @throws UnknownScopeException when the scope is not configured and
     *                               unknown_scope.mode is "reject" or
     *                               "baseline" (the adaptive engine declines
     *                               to evaluate)
     */
    public function scopeId(string $scope): int
    {
        if (isset($this->scopeIds[$scope])) {
            return $this->scopeIds[$scope];
        }
        if ($this->unknownScopeMode === 'minimum') {
            // 'minimum' mode: every unknown scope is assessed under the
            // shared synthetic policy (base_risk 100, minimum/degraded
            // sha20).
            return $this->unknownScopeId ?? (crc32($scope) & 0x7fffffff);
        }

        // 'reject' and 'baseline' modes: the adaptive engine declines to
        // evaluate unknown scopes. 'reject' surfaces as a rejection (the
        // controller returns the risk-denied 429); 'baseline' lets the
        // controller fall back to the default challenge profile.
        throw new UnknownScopeException(sprintf(
            'Risk scope "%s" is not configured and unknown_scope.mode is "%s" — the adaptive engine declines to evaluate it',
            $scope,
            $this->unknownScopeMode,
        ));
    }

    /**
     * Whether a valid solve of this scope must pass the post-solve
     * re-assessment. Null scope = an accept-any-scope constraint, which
     * never demands a post-solve re-assessment (the per-scope table is
     * keyed by the issued scope).
     */
    public function postSolveCheck(?string $scope): bool
    {
        return $scope !== null ? ($this->postSolveScopes[$scope] ?? false) : false;
    }

    /**
     * The decision id of the current request's decision (set by preIssue /
     * postSolveDecision / the validator's nonce consumption), or null when
     * the risk engine was not consulted.
     *
     * Request-local: the id lives on the RequestStack main request's
     * `_kiwi_risk_decision_id` attribute, so one worker serving many
     * requests can never leak a previous request's decision into the next
     * (a fresh request carries an empty attribute set).
     */
    public function currentDecisionId(): ?string
    {
        $id = $this->requestStack?->getMainRequest()?->attributes->get(self::DECISION_ATTRIBUTE);

        return \is_string($id) && $id !== '' ? $id : null;
    }

    /**
     * Record the decision id of the current request's decision on the
     * RequestStack main request (request-local; no-op without a request in
     * scope). The application reads it back via {@see currentDecisionId()}
     * to confirm this challenge's decision (e.g. a later
     * ConfirmedLegitimate / ConfirmedAbuse signal).
     */
    public function setCurrentDecisionId(string $decisionId): void
    {
        $this->requestStack?->getMainRequest()?->attributes->set(self::DECISION_ATTRIBUTE, $decisionId);
    }

    /**
     * Pre-issue assessment: one observation (event PreIssue) plus a
     * decision via {@see AdaptiveRiskEngine::assessPreIssue()} (emergency
     * limiter + observation + decision). The decision id is recorded on
     * the request-local decision context, see
     * {@see setCurrentDecisionId()}.
     *
     * The optional risk-v2 context, see {@see clientContextV2()}, feeds the
     * additive evidence factors (honeypot/decoy evidence, session
     * client-context consistency, trusted-edge TLS consistency) into the
     * assessment. This is probabilistic evidence only, never a security
     * gate. The optional risk-v2 weights override ({@see RiskV2Weights})
     * tunes those additive factors; null uses the configured weights
     * (risk.v2.*, itself defaulting to the contract defaults, so scores
     * are identical to the unset config).
     *
     * @throws UnknownScopeException   when the scope is unknown in 'reject'/'baseline' mode.
     * @throws \InvalidArgumentException when the client IP is not a valid
     *                                   IPv4/IPv6 address (the caller treats
     *                                   this as "no risk signal" and applies
     *                                   the degraded decision).
     */
    public function preIssue(string $scope, string $ip, ?string $session, ?string $idempotencyKey = null, ?RiskV2Context $v2 = null, ?RiskV2Weights $v2Weights = null): RiskDecision
    {
        $context = new RiskContext(
            scope: $this->scopeId($scope),
            sourceIp: $ip,
            // The engine derives the keyed session pseudonym itself
            // (buildObservation); pass the raw cookie value.
            sessionId: $session,
            principalId: $this->resolvePrincipal($scope),
            event: RiskEventKind::PreIssue,
            networkFlags: $this->classifier->classify($ip),
            resources: $this->resources(),
        );
        $decision = $v2 !== null
            ? $this->engine->assessPreIssueV2($context, $v2, $idempotencyKey, $v2Weights ?? $this->v2Weights)
            : $this->engine->assessPreIssue($context, $idempotencyKey);
        $this->setCurrentDecisionId($decision->decisionId);
        $this->logDecision($scope, $decision);

        return $decision;
    }

    /**
     * Post-solve decision: a fresh assessment with the SolveSuccess event
     * via {@see AdaptiveRiskEngine::reassess()}. A full decision without
     * consuming the emergency admission budget, so a low limiter cap can
     * never deny a valid solve. A materially changed security context
     * (e.g. a global attack storm while the client was solving) can still
     * demand Deny or StepUp even after a valid proof. The decision id is
     * recorded on the request-local decision context, see
     * {@see setCurrentDecisionId()}.
     *
     * The outcome is not fed back by the gateway: ConfirmedLegitimate and
     * ConfirmedAbuse are application-only signals that require a decision
     * id. The caller decides whether the solve really was a success and
     * records the confirmation itself with the returned decision id.
     *
     * @return RiskDecision|null the post-solve decision, or null when the
     *                           scope is unknown and the engine declines to
     *                           evaluate (feedback paths must never crash
     *                           on unknown scopes).
     */
    public function postSolveDecision(string $scope, string $ip, ?string $session = null, ?string $principal = null, ?string $idempotencyKey = null): ?RiskDecision
    {
        $scopeId = $this->tryScopeId($scope);
        if ($scopeId === null) {
            return null;
        }
        $context = new RiskContext(
            scope: $scopeId,
            sourceIp: $ip,
            sessionId: $session,
            principalId: $principal ?? $this->resolvePrincipal($scope),
            event: RiskEventKind::SolveSuccess,
            networkFlags: $this->classifier->classify($ip),
            resources: $this->resources(),
        );
        $decision = $this->engine->reassess($context, $idempotencyKey);
        $this->setCurrentDecisionId($decision->decisionId);
        $this->logDecision($scope, $decision);

        return $decision;
    }

    /**
     * Post-solve decision with the risk-v2 additive evidence: identical to
     * {@see postSolveDecision()} (fresh SolveSuccess assessment without
     * consuming the emergency admission budget) but routed through the
     * engine's reassessV2 with the given risk-v2 context (honeypot/decoy
     * evidence, session client-context consistency, trusted-edge TLS
     * consistency). The v2 weights are the caller-explicit override when
     * given, else the configured weights (risk.v2.*, themselves the
     * contract defaults when unset; an empty context scores identically
     * to the v1 path). The decision id is recorded on the request-local
     * decision context, see {@see setCurrentDecisionId()}.
     *
     * @return RiskDecision|null the post-solve decision, or null when the
     *                           scope is unknown and the engine declines to
     *                           evaluate (feedback paths must never crash
     *                           on unknown scopes).
     */
    public function postSolveDecisionV2(string $scope, string $ip, ?string $session = null, ?string $principal = null, ?string $idempotencyKey = null, ?RiskV2Context $v2 = null, ?RiskV2Weights $v2Weights = null): ?RiskDecision
    {
        $scopeId = $this->tryScopeId($scope);
        if ($scopeId === null) {
            return null;
        }
        $context = new RiskContext(
            scope: $scopeId,
            sourceIp: $ip,
            sessionId: $session,
            principalId: $principal ?? $this->resolvePrincipal($scope),
            event: RiskEventKind::SolveSuccess,
            networkFlags: $this->classifier->classify($ip),
            resources: $this->resources(),
        );
        $decision = $v2 !== null
            ? $this->engine->reassessV2($context, $v2, $idempotencyKey, $v2Weights ?? $this->v2Weights)
            : $this->engine->reassess($context, $idempotencyKey);
        $this->setCurrentDecisionId($decision->decisionId);
        $this->logDecision($scope, $decision);

        return $decision;
    }

    /**
     * The risk-v2 client-context tag for the current request: a bounded,
     * ephemeral base36 tag derived from the coarse capability descriptor,
     * see {@see ClientContextTag::derive()}, keyed to the deployment
     * namespace and the continuity session, never a stable device
     * identifier. The tag is stable for the session's whole lifetime (no
     * hourly re-key), so the session's first tag stays the comparison
     * baseline. Null when there is no session or no descriptor (no
     * consistency signal is derived).
     */
    public function clientContextTag(?string $session, ?string $descriptor): ?string
    {
        if ($session === null || $descriptor === null || $descriptor === '') {
            return null;
        }

        return ClientContextTag::derive($this->contextNamespace(), $session, $descriptor);
    }

    /**
     * The risk-v2 context for one request: honeypot evidence plus the
     * ephemeral client-context tag and the trusted-edge TLS classification
     * tag (coarse, server-attested by trusted proxy/CDN infrastructure).
     * The engine only ever stores the ephemeral classification as the
     * session's first-seen record, never a raw fingerprint database.
     * Returns null when the request carries no risk-v2 evidence at all
     * (the assessment then stays on the pure risk-v1 path).
     */
    public function clientContextV2(bool $honeypotHit, ?string $session, ?string $descriptor, ?string $tlsTag = null): ?RiskV2Context
    {
        $tag = $this->clientContextTag($session, $descriptor);
        if (!$honeypotHit && $tag === null && ($tlsTag === null || $tlsTag === '')) {
            return null;
        }

        return new RiskV2Context(
            honeypotHit: $honeypotHit,
            clientContextTag: $tag,
            tlsTag: $tlsTag,
        );
    }

    /**
     * Risk-v2 honeypot/decoy evidence feedback: records one of the three
     * honeypot event kinds, see {@see RiskEventKind::isHoneypot()}, through
     * the engine's feedback path. The event rides the same observation
     * pipeline as every other evidence signal (dedupe receipt; the state
     * script treats it as a no-op, and the honeypot signal itself is
     * scored from the risk-v2 context of the assessment). Never a
     * security gate: this only books probabilistic evidence.
     *
     * @throws \InvalidArgumentException when $kind is not one of the three
     *                                   honeypot/decoy event kinds.
     */
    public function honeypotEvidence(RiskEventKind $kind, string $scope, string $ip, ?string $session = null, ?string $idempotencyKey = null, ?string $decisionId = null): ?EventReceipt
    {
        if (!$kind->isHoneypot()) {
            throw new \InvalidArgumentException(sprintf(
                'honeypotEvidence accepts honeypot event kinds only (got %s)',
                $kind->name,
            ));
        }

        return $this->recordFeedback($kind, $scope, $ip, $session, $idempotencyKey, $decisionId);
    }

    /** Post-issue signal: the challenge was actually minted (issue-debt). */
    public function challengeIssued(string $scope, string $ip, ?string $session, ?string $decisionId = null): void
    {
        $this->recordFeedback(RiskEventKind::ChallengeIssued, $scope, $ip, $session, null, $decisionId);
    }

    /**
     * Post-solve feedback: the outcome of a verification attempt, mapped
     * to its risk-v1 event kind ({@see RiskFeedback}). Infrastructure
     * failures are mapped to null and skipped, never recorded as client
     * abuse. An unparseable client IP is not a risk signal and is skipped
     * too (the engine's identity derivation requires a valid IPv4/IPv6
     * address).
     *
     * A missing source address (null or empty — a request without a
     * usable remoteip, e.g. a Siteverify redemption with `remoteip`
     * omitted under binding_mode: none) has nothing to attribute the
     * signal to: the feedback is skipped entirely, never a throw. This
     * mirrors {@see recordFeedback()}'s unusable-IP skip, but one level
     * up, so callers may pass a nullable IP without a TypeError under
     * strict_types.
     *
     * Solve duration (graded evidence, partially consumed): the optional
     * $solveDurationMs carries the server-measured solve duration of the
     * verified outcome, computed from the unforgeable issuedAtNs receipt
     * time, never the client-reported durationMs. The risk-v1/v2
     * feedback surface is categorical: RiskEventKind is a fixed
     * cross-language contract, values 1..21 byte-identical with the Rust
     * mirror and the canonical risk.lua. The risk-v2 context carries
     * only categorical fields, honeypot bool and context/TLS tags, and
     * its numeric 0..1000 signals are derived inside the engine, never
     * caller-supplied. A graded fast-solve bucket, e.g. below a
     * configurable multiple of the min-duration floor, therefore cannot
     * be expressed without a protocol change: a new additive risk-v2
     * context/signal/weight triple mirrored in PHP, Rust and Lua. Until
     * such a channel exists the measured duration is consumed as
     * bounded observability only, a debug log line with scope and
     * duration, no IP, no identity, so operators can alert on
     * implausibly fast solves today. The plumbing is live: the moment
     * the engine grows a graded input, this parameter is the single
     * wiring point.
     */
    public function solveOutcome(string $scope, ?string $ip, ?string $session, ?VerifyError $error, ?string $decisionId = null, ?int $solveDurationMs = null): void
    {
        if ($solveDurationMs !== null && $solveDurationMs >= 0) {
            $this->logger?->debug('kiwicaptcha.risk: measured solve duration (graded evidence channel pending, observability only)', [
                'scope' => $scope,
                'solve_duration_ms' => $solveDurationMs,
            ]);
        }
        if ($ip === null || $ip === '') {
            return;
        }
        $event = RiskFeedback::eventFor($error);
        if ($event === null) {
            return;
        }
        $this->recordFeedback($event, $scope, $ip, $session, null, $decisionId);
    }

    /**
     * Null-safe extraction of the core VerifyOutcome's additive
     * solve-duration surface, a core addition computed from the
     * unforgeable issuedAtNs. Returns the measured duration in
     * milliseconds when the installed core exposes it, method or public
     * property, ms first with a microsecond variant converted. Returns
     * null when the core predates the field, or when the value is not a
     * measurable non-negative integer. The bridge is feature-checked so
     * the consumption activates the moment the core lands, without
     * requiring a hard dependency bump.
     */
    public static function solveDurationMsOf(object $outcome): ?int
    {
        foreach (['solveDurationMs', 'solveDurationMicros', 'solveDurationUs'] as $accessor) {
            if (!method_exists($outcome, $accessor)) {
                continue;
            }
            $value = $outcome->$accessor();
            if ($value === null) {
                return null;
            }
            if (!\is_int($value) || $value < 0) {
                return null;
            }

            return str_ends_with($accessor, 'Micros') || str_ends_with($accessor, 'Us')
                ? intdiv($value, 1000)
                : $value;
        }
        if (isset($outcome->solveDurationMs) && \is_int($outcome->solveDurationMs) && $outcome->solveDurationMs >= 0) {
            return $outcome->solveDurationMs;
        }

        return null;
    }

    /**
     * Calibration-only confirmation of a decision outcome, with no network
     * identity, no scope and no session: the target of delayed
     * confirmations (email confirmation, fraud review, chargeback,
     * moderation) where the original request's source/session/principal
     * context is long gone. Confirms the decision against its outcome
     * ledger atomically via the engine's confirmOutcome (the canonical
     * confirm.lua checks the ledger, consumes the receipt and records the
     * score-weighted outcome in one script).
     *
     * Sampling contract: with the calibration mode 'random_sample', Kiwi
     * sampled the decision at assessment time (the receipt carries a
     * "sampled" flag) and an unsampled receipt is discarded, so the label
     * can never select itself into the calibration population. With mode
     * 'weighted', the application supplies the inverse sampling probability
     * $samplingProbabilityPpm (parts per million, 1..1_000_000), and the
     * gateway converts it to weight = 1_000_000/ppm so labels with known
     * selection bias are re-weighted into the population. An IP is never
     * required: there is nothing to attribute a delayed confirmation to,
     * since it is a pure calibration signal.
     *
     * @return int the engine's shared accepted-outcome status:
     *             0 = missing / already confirmed / corrupt receipt (the
     *                 application can treat it as a no-op: a webhook retry
     *                 of an already-confirmed decision is harmless).
     *             1 = first confirmation; the calibration outcome was
     *                 recorded.
     *             2 = first confirmation, deliberately unsampled
     *                 (random_sample mode: the decision was not in the
     *                 server-selected sample, so it does not enter
     *                 calibration, but the confirmation is still consumed
     *                 and the caller may apply first-party reputation
     *                 exactly once).
     *
     * @throws \InvalidArgumentException when $samplingProbabilityPpm is
     *                                   outside 1..1_000_000.
     */
    public function confirmDecisionOutcome(string $decisionId, bool $legitimate, ?int $samplingProbabilityPpm = null): int
    {
        if ($samplingProbabilityPpm !== null && ($samplingProbabilityPpm < 1 || $samplingProbabilityPpm > 1_000_000)) {
            throw new \InvalidArgumentException(sprintf(
                'samplingProbabilityPpm must be 1..1000000 (got %d) — it is the inverse sampling probability in parts per million (weight = 1_000_000/ppm)',
                $samplingProbabilityPpm,
            ));
        }

        return $this->engine->confirmOutcome(
            $decisionId,
            $legitimate,
            $samplingProbabilityPpm !== null ? 1_000_000 / $samplingProbabilityPpm : null,
        );
    }

    /**
     * Correction of a confirmed outcome (e.g. a chargeback verdict or
     * moderation appeal flipped the label): the engine's
     * compensating-state API. Records the corrected class at most once
     * per decision, guarded by the outcome ledger (status flipped to 2;
     * the ledger TTL = calibration.outcome_receipt_ttl_secs). The
     * receipt itself is already consumed by the first confirmation, so
     * the ledger is the only gate. Works without calibration: the
     * once-only
     * guard
     * lives in the state store; with a calibration store attached the
     * correction additionally reverses the recorded bucket counts.
     * Calibration aggregates keep the first confirmed outcome, and a
     * correction compensates reputation and returns the buckets to the
     * pre-confirmation state.
     *
     * Same weight mapping as {@see confirmDecisionOutcome()}: the
     * $samplingProbabilityPpm is the inverse sampling probability in parts
     * per million, converted to weight = 1_000_000/ppm. Same one-shot
     * contract: a second correction of the same decision returns false
     * (no-op, so retries can never double-compensate).
     *
     * @return bool whether the compensation was applied (false = already
     *               corrected / ledger missing).
     *
     * @throws \InvalidArgumentException when $samplingProbabilityPpm is
     *                                   outside 1..1_000_000.
     */
    public function confirmCorrection(string $decisionId, bool $legitimate, ?int $samplingProbabilityPpm = null): bool
    {
        if ($samplingProbabilityPpm !== null && ($samplingProbabilityPpm < 1 || $samplingProbabilityPpm > 1_000_000)) {
            throw new \InvalidArgumentException(sprintf(
                'samplingProbabilityPpm must be 1..1000000 (got %d) — it is the inverse sampling probability in parts per million (weight = 1_000_000/ppm)',
                $samplingProbabilityPpm,
            ));
        }

        return $this->engine->confirmCorrection(
            $decisionId,
            $legitimate,
            $samplingProbabilityPpm !== null ? 1_000_000 / $samplingProbabilityPpm : null,
        );
    }

    /**
     * Confirmed-legitimate signal, application-only (e.g. from post-hoc
     * account checks): the context-ful reputation path, used when the
     * source/session/principal context is still available. Routes through
     * {@see recordConfirmedReputation()}: the engine confirms the decision
     * atomically against its outcome ledger (consuming the calibration
     * receipt when one exists), then records the ConfirmedLegitimate
     * reputation event. The decision id is required by the engine
     * contract; it throws InvalidArgumentException without one, and the
     * gateway lets that enforcement surface.
     *
     * $samplingProbabilityPpm (parts per million, 1..1_000_000) is the
     * inverse sampling probability for weighted calibration. It is passed
     * to the engine's confirmedLegitimate (which converts it to
     * weight = 1_000_000/ppm), so labels with known selection bias are
     * re-weighted into the population. Null in weighted mode reaches the
     * calibrator as a null weight, which weighted mode refuses; the
     * InvalidArgumentException propagates (documented behavior).
     *
     * @throws \InvalidArgumentException when the engine requires a decisionId
     *                                   for confirmed events and none is given.
     * @throws \InvalidArgumentException when $samplingProbabilityPpm is
     *                                   outside 1..1_000_000.
     * @throws \InvalidArgumentException when the calibration mode is
     *                                   'weighted' and $samplingProbabilityPpm
     *                                   is null (propagated from the engine).
     */
    public function confirmedLegitimate(string $scope, string $ip, ?string $session = null, ?string $idempotencyKey = null, ?string $decisionId = null, ?int $samplingProbabilityPpm = null): ?EventReceipt
    {
        return $this->recordConfirmedReputation(true, $scope, $ip, $session, $idempotencyKey, $decisionId, $samplingProbabilityPpm);
    }

    /**
     * Confirmed-abuse signal, application-only (e.g. from post-hoc account
     * checks): the context-ful reputation path, used when the
     * source/session/principal context is still available. Routes through
     * {@see recordConfirmedReputation()}: the engine confirms the decision
     * atomically against its outcome ledger (consuming the calibration
     * receipt when one exists), then records the ConfirmedAbuse reputation
     * event. The decision id is required by the engine contract; it
     * throws InvalidArgumentException without one, and the gateway lets
     * that enforcement surface.
     *
     * $samplingProbabilityPpm (parts per million, 1..1_000_000) is the
     * inverse sampling probability for weighted calibration. It is passed
     * to the engine's confirmedAbuse (which converts it to
     * weight = 1_000_000/ppm), so labels with known selection bias are
     * re-weighted into the population. Null in weighted mode reaches the
     * calibrator as a null weight, which weighted mode refuses; the
     * InvalidArgumentException propagates (documented behavior).
     *
     * @throws \InvalidArgumentException when the engine requires a decisionId
     *                                   for confirmed events and none is given.
     * @throws \InvalidArgumentException when $samplingProbabilityPpm is
     *                                   outside 1..1_000_000.
     * @throws \InvalidArgumentException when the calibration mode is
     *                                   'weighted' and $samplingProbabilityPpm
     *                                   is null (propagated from the engine).
     */
    public function confirmedAbuse(string $scope, string $ip, ?string $session = null, ?string $idempotencyKey = null, ?string $decisionId = null, ?int $samplingProbabilityPpm = null): ?EventReceipt
    {
        return $this->recordConfirmedReputation(false, $scope, $ip, $session, $idempotencyKey, $decisionId, $samplingProbabilityPpm);
    }

    /**
     * Context-ful confirmed-outcome path (legitimate/abuse): used when the
     * request's source/session/principal context is available. The engine
     * confirms the decision atomically against its outcome ledger, the
     * once-only gate: with a calibration store the receipt is consumed
     * and the score-weighted outcome recorded in the same script. It
     * then records the reputation event (source/session/principal
     * signals) via the engine's first-class confirmed* methods. Unlike
     * the calibration-only path, see {@see confirmDecisionOutcome()}, an
     * unparseable client IP has nothing to attribute the reputation event
     * to, so the signal is skipped (null).
     *
     * $samplingProbabilityPpm (parts per million, 1..1_000_000) is the
     * inverse sampling probability for weighted calibration
     * (weight = 1_000_000/ppm), passed through to the engine's confirmed*
     * methods. Null in weighted mode makes the engine's confirmOutcome
     * throw an InvalidArgumentException, and the gateway lets it
     * propagate.
     *
     * @throws \InvalidArgumentException when the engine requires a decisionId
     *                                   for confirmed events and none is given.
     * @throws \InvalidArgumentException when $samplingProbabilityPpm is
     *                                   outside 1..1_000_000.
     * @throws \InvalidArgumentException when the calibration mode is
     *                                   'weighted' and $samplingProbabilityPpm
     *                                   is null (propagated from the engine).
     */
    public function recordConfirmedReputation(bool $legitimate, string $scope, string $ip, ?string $session = null, ?string $idempotencyKey = null, ?string $decisionId = null, ?int $samplingProbabilityPpm = null): ?EventReceipt
    {
        if ($samplingProbabilityPpm !== null && ($samplingProbabilityPpm < 1 || $samplingProbabilityPpm > 1_000_000)) {
            throw new \InvalidArgumentException(sprintf(
                'samplingProbabilityPpm must be 1..1000000 (got %d) — it is the inverse sampling probability in parts per million (weight = 1_000_000/ppm)',
                $samplingProbabilityPpm,
            ));
        }
        $scopeId = $this->tryScopeId($scope);
        if ($scopeId === null) {
            return null;
        }
        if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            // Invalid client IP: nothing to attribute the signal to.
            return null;
        }
        $context = new RiskContext(
            scope: $scopeId,
            sourceIp: $ip,
            sessionId: $session,
            principalId: $this->resolvePrincipal($scope),
            event: $legitimate ? RiskEventKind::ConfirmedLegitimate : RiskEventKind::ConfirmedAbuse,
            networkFlags: $this->classifier->classify($ip),
            resources: $this->resources(),
        );

        // Route through the engine's first-class confirmation methods so
        // the package enforces the decisionId requirement
        // (InvalidArgumentException without it) and the once-only outcome
        // ledger; the gateway never infers confirmations itself. The ppm
        // is passed through so the engine can convert it to the
        // weighted-calibration weight.
        return $legitimate
            ? $this->engine->confirmedLegitimate($context, $decisionId, $idempotencyKey, $samplingProbabilityPpm)
            : $this->engine->confirmedAbuse($context, $decisionId, $idempotencyKey, $samplingProbabilityPpm);
    }

    /**
     * Server-derived signal: an application-level protected action succeeded
     * (e.g. the post-captcha operation completed). Feedback only — no
     * decision is produced.
     */
    public function protectedActionSuccess(string $scope, string $ip, ?string $session = null, ?string $idempotencyKey = null): ?EventReceipt
    {
        return $this->recordFeedback(RiskEventKind::ProtectedActionSuccess, $scope, $ip, $session, $idempotencyKey, null);
    }

    /** Server-derived signal: an application-level protected action failed. */
    public function protectedActionFailure(string $scope, string $ip, ?string $session = null, ?string $idempotencyKey = null): ?EventReceipt
    {
        return $this->recordFeedback(RiskEventKind::ProtectedActionFailure, $scope, $ip, $session, $idempotencyKey, null);
    }

    /** Server-derived signal: an authentication attempt succeeded. */
    public function authenticationSuccess(string $scope, string $ip, ?string $session = null, ?string $idempotencyKey = null): ?EventReceipt
    {
        return $this->recordFeedback(RiskEventKind::AuthenticationSuccess, $scope, $ip, $session, $idempotencyKey, null);
    }

    /** Server-derived signal: an authentication attempt failed. */
    public function authenticationFailure(string $scope, string $ip, ?string $session = null, ?string $idempotencyKey = null): ?EventReceipt
    {
        return $this->recordFeedback(RiskEventKind::AuthenticationFailure, $scope, $ip, $session, $idempotencyKey, null);
    }

    /**
     * Server-derived signal: a rate limit (issuer hard limit or risk denial)
     * turned the request away. Records RiskEventKind::RateLimitHit; the
     * controller calls this before returning 429 so the risk state learns
     * the source was refused.
     *
     * Prefer the attributed signals over this generic one:
     * {@see sourceRateLimitHit()} (per-source cap), {@see globalCapacityHit()}
     * (deployment-wide cap, identity-neutral) and {@see riskDenied()} (the
     * risk engine itself already denied — no double-counting).
     */
    public function rateLimitHit(string $scope, string $ip, ?string $session = null, ?string $idempotencyKey = null): ?EventReceipt
    {
        return $this->recordFeedback(RiskEventKind::RateLimitHit, $scope, $ip, $session, $idempotencyKey, null);
    }

    /**
     * Server-derived signal: the issuer's per-client rate limit turned the
     * request away. Records RiskEventKind::SourceRateLimitHit (bad +3000
     * on the source/session reputation). The scope is the already-resolved
     * risk-v1 int scope id (refusal paths run before any principal
     * resolution, so no principal signal is attached). An unparseable
     * client IP has nothing to attribute the signal to and is skipped.
     *
     * @return EventReceipt|null null when the signal was skipped (invalid
     *                           client IP).
     */
    public function sourceRateLimitHit(int $scope, string $ip, ?string $sessionId = null, ?string $idempotencyKey = null): ?EventReceipt
    {
        if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            // Invalid client IP: nothing to attribute the signal to.
            return null;
        }

        return $this->engine->sourceRateLimitHit(
            $this->rateContext($scope, $ip, $sessionId, RiskEventKind::SourceRateLimitHit),
            $idempotencyKey,
        );
    }

    /**
     * Server-derived signal: the deployment-global issuance cap turned the
     * request away. Records RiskEventKind::GlobalCapacityHit, global-only
     * bad pressure: the canonical risk-v1 Lua raises the global attack
     * pressure and never touches the source/session/principal reputation,
     * so deployment overload cannot contaminate an individual visitor.
     *
     * No source IP is needed: the event is identity-neutral, so the context
     * is built with the identity-neutral unspecified address (0.0.0.0) and
     * the Lua only ever mutates the global state for this event. The
     * session signal is still carried when one exists.
     */
    public function globalCapacityHit(int $scope, ?string $sessionId = null, ?string $idempotencyKey = null): ?EventReceipt
    {
        try {
            return $this->engine->globalCapacityHit(
                $this->rateContext($scope, '0.0.0.0', $sessionId, RiskEventKind::GlobalCapacityHit),
                $idempotencyKey,
            );
        } catch (\InvalidArgumentException) {
            return null;
        }
    }

    /**
     * Server-derived signal: the risk engine itself already denied this
     * request (RiskEventKind::RiskDenied, a deliberate no-op in the
     * canonical Lua, so a decision that already scored the evidence is
     * never double-counted). The controller does not call this on its
     * Deny path; it exists for applications that refuse a request based on
     * a risk decision outside the challenge flow.
     */
    public function riskDenied(int $scope, string $ip, ?string $sessionId = null, ?string $idempotencyKey = null): ?EventReceipt
    {
        if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            // Invalid client IP: nothing to attribute the signal to.
            return null;
        }

        return $this->engine->riskDenied(
            $this->rateContext($scope, $ip, $sessionId, RiskEventKind::RiskDenied),
            $idempotencyKey,
        );
    }

    /** The RiskContext for one int-scope rate/denial signal (no principal). */
    private function rateContext(int $scope, string $ip, ?string $sessionId, RiskEventKind $event): RiskContext
    {
        return new RiskContext(
            scope: $scope,
            sourceIp: $ip,
            sessionId: $sessionId,
            principalId: null,
            event: $event,
            networkFlags: $this->classifier->classify($ip),
            resources: $this->resources(),
        );
    }

    /**
     * The deployment namespace inside the risk state hash tag
     * ({kiwi:<ns>}:...), derived from the wired decision-key prefix
     * (`{kiwi:<ns>}:decision:`); falls back to `kiwi`. The namespace keys
     * the risk-v2 client-context tag derivation to the deployment.
     */
    private function contextNamespace(): string
    {
        if (preg_match('/^\{kiwi:([^{}:]+)\}:decision:$/D', $this->decisionKeyPrefix, $m) === 1) {
            return $m[1];
        }

        return 'kiwi';
    }

    /**
     * Server-derived signal: an issued challenge expired without a valid
     * solve. The bundle's verifier path already maps VerifyError::Expired to
     * RiskEventKind::ExpiredChallenge via {@see solveOutcome()}; this method
     * exists for applications that detect expiry outside the verifier (e.g.
     * a storage sweep).
     */
    public function expiredChallenge(string $scope, string $ip, ?string $session = null, ?string $idempotencyKey = null): ?EventReceipt
    {
        return $this->recordFeedback(RiskEventKind::ExpiredChallenge, $scope, $ip, $session, $idempotencyKey, null);
    }

    /**
     * Server-derived signal: an issued challenge was cancelled before any
     * verification (the exhaustion/deadline abandonment path). Records
     * RiskEventKind::ChallengeCancelled, which is risk-neutral (no state
     * mutation): the issue-debt contribution of the abandoned challenge
     * is never refunded: the issued-and-abandoned signal decays
     * naturally, and only an actual SolveSuccess repays it. The event
     * stays for observability (the cancellation is a resource-lifecycle
     * operation; the risk model must not forgive debt on a
     * client-influenceable request). The controller fires it only on the
     * fresh pending->cancelled transition and passes a nonce-derived
     * idempotency key, so repeated idempotent cancellation requests can
     * never record it twice.
     */
    public function challengeCancelled(string $scope, string $ip, ?string $session = null, ?string $idempotencyKey = null): ?EventReceipt
    {
        return $this->recordFeedback(RiskEventKind::ChallengeCancelled, $scope, $ip, $session, $idempotencyKey, null);
    }

    /**
     * The challenge profile the decision demands (null = issue as configured).
     */
    public function decisionProfile(RiskDecision $decision): ?ChallengeProfile
    {
        return $this->profileForAction($decision->action);
    }

    /**
     * The challenge profile a risk action demands, the same mapping the
     * pre-issue decisions flow through; {@see decisionProfile()} delegates
     * here. The stage-2 chain controller uses it to enforce the ticket's
     * signed required action. The effective action, the stronger of the
     * required action and the current pre-issue action, flows through
     * this mapping, so the issued profile is at least as strong as the
     * chain promised.
     *
     * @throws \LogicException for StepUp (controller-level application
     *                         step-up, never a challenge profile).
     */
    public function profileForAction(RiskAction $action): ?ChallengeProfile
    {
        return $this->resolver->profileFor($action);
    }

    /**
     * The degraded decision for a scope: the policy's degraded action,
     * clamped to the scope minimum, with the global floor at the idle
     * level 0 = Allow since a no-signal fallback consults no store state.
     * Does not touch the state store or the emergency limiter. Used when
     * no usable risk signal exists (e.g. an unparseable client IP from a
     * misconfigured proxy), so the configured degraded floor always
     * applies and issuance can never silently drop below it.
     *
     * @throws \LogicException when the policy is not wired (the extension
     *                         wires it automatically).
     */
    public function degradedDecisionForScope(int $scope): RiskDecision
    {
        if ($this->policy === null) {
            throw new \LogicException('degradedDecisionForScope requires the RiskPolicy to be wired into the RiskGateway');
        }

        return $this->policy->degradedDecision($scope, 0);
    }

    /**
     * The full nonce -> decision mapping key
     * ({kiwi:<ns>}:decision:<nonce>), the same hash-tagged key the
     * gateway's decision handle lives under. Read-only accessor: the
     * disposition store's claim consumes the mapping atomically with the
     * pending record write (GETDEL inside the claim's Lua), so a fallible
     * chain-state read before the claim can never lose the original
     * handle.
     */
    public function decisionKeyFor(string $nonce): string
    {
        return $this->decisionKeyPrefix.$nonce;
    }

    /**
     * Pair a challenge nonce to its decision id in the risk Redis:
     * {kiwi:<ns>}:decision:<nonce> holds the JSON string
     * {"decision_id": ...} with the risk.nonce_to_decision_ttl_secs TTL
     * (default 300 s), independent of the outcome lifetime. Server-side
     * handle only: the mapping carries no IP and no identity, and a Redis
     * failure is silent (the mapping must never break issuance).
     */
    public function attachDecisionForNonce(string $nonce, string $decisionId): void
    {
        if ($this->decisionRedis === null) {
            return;
        }
        try {
            $this->decisionRedis->set(
                $this->decisionKeyPrefix.$nonce,
                (string) json_encode(['decision_id' => $decisionId], JSON_UNESCAPED_SLASHES),
                'EX',
                $this->decisionTtlSecs,
            );
        } catch (\Throwable) {
            // Server-side handle only — never break issuance over it.
        }
    }

    /**
     * Consume the nonce -> decision mapping (GETDEL: atomic read + remove,
     * at most one consumer wins). Returns the paired decision id or null.
     */
    public function resolveDecisionForNonce(string $nonce): ?string
    {
        if ($this->decisionRedis === null) {
            return null;
        }
        try {
            $raw = $this->decisionRedis->getdel($this->decisionKeyPrefix.$nonce);
        } catch (\Throwable) {
            return null;
        }
        if (!\is_string($raw) || $raw === '') {
            return null;
        }
        $data = json_decode($raw, true);

        return \is_array($data) && \is_string($data['decision_id'] ?? null) ? $data['decision_id'] : null;
    }

    /** Engine metrics snapshot (counters/gauges/latencies, no identity labels). */
    public function metricsSnapshot(): array
    {
        return $this->engine->metrics()->snapshot();
    }

    /**
     * Sampling-resolution metrics of the random_sample calibration gate:
     * the namespace-wide sampled-decision total and resolved counters,
     * the resolution ratio (resolved/total; 0.0 when total is 0) and the
     * sampled-but-unresolved remainder (sampledExpired = total - resolved,
     * floored at 0). Delegates to the calibrator; when calibration is
     * disabled (or in complete/weighted mode, where the counters are
     * never touched) every value is zero.
     *
     * @return array{sampledTotal: int, sampledResolved: int, resolutionRatio: float, sampledExpired: int}
     */
    public function samplingMetrics(int $scope): array
    {
        if ($this->calibration === null) {
            return ['sampledTotal' => 0, 'sampledResolved' => 0, 'resolutionRatio' => 0.0, 'sampledExpired' => 0];
        }

        return $this->calibration->samplingMetrics($scope, (int) floor(microtime(true) * 1000));
    }

    /**
     * One feedback event through
     * {@see AdaptiveRiskEngine::record_feedback()}.
     *
     * Never throws for unavailable signals:
     *  - an unknown scope (reject/baseline modes) skips the signal with a
     *    debug log, so feedback paths never crash on unknown scopes.
     *  - An unparseable client IP has nothing to attribute the signal to
     *    and is skipped.
     *
     * Engine exceptions are deliberately not swallowed here: the engine's
     * InvalidArgumentException for confirmed events without a decisionId
     * is contract enforcement and must reach the application caller. The
     * engine also refuses ConfirmedLegitimate / ConfirmedAbuse through
     * record_feedback with a LogicException; the gateway never routes
     * confirmed events through this path, since they go through
     * {@see recordConfirmedReputation()} exclusively.
     *
     * @return EventReceipt|null null when the signal was skipped (unknown
     *                           scope or invalid client IP).
     */
    private function recordFeedback(RiskEventKind $event, string $scope, string $ip, ?string $session, ?string $idempotencyKey, ?string $decisionId): ?EventReceipt
    {
        $scopeId = $this->tryScopeId($scope);
        if ($scopeId === null) {
            return null;
        }
        if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            // Invalid client IP: nothing to attribute the signal to.
            return null;
        }

        return $this->engine->record_feedback(
            $event,
            new RiskContext(
                scope: $scopeId,
                sourceIp: $ip,
                sessionId: $session,
                principalId: $this->resolvePrincipal($scope),
                event: $event,
                networkFlags: $this->classifier->classify($ip),
                resources: $this->resources(),
            ),
            $idempotencyKey,
            $decisionId,
        );
    }

    /**
     * The raw principal of the current request (process memory only), or
     * null when no resolver is wired, no request is in scope, or the
     * resolver declines. The engine HMAC-pseudonymizes the raw value
     * before Redis storage.
     */
    private function resolvePrincipal(string $scope): ?string
    {
        if ($this->principalResolver === null || $this->requestStack === null) {
            return null;
        }
        $request = $this->requestStack->getMainRequest();
        if ($request === null) {
            return null;
        }

        return $this->principalResolver->resolve($request, $scope);
    }

    private function tryScopeId(string $scope): ?int
    {
        try {
            return $this->scopeId($scope);
        } catch (UnknownScopeException $e) {
            $this->logger?->debug('kiwicaptcha.risk: skipping feedback for unknown scope', ['scope' => $scope]);

            return null;
        }
    }

    private function resources(): ResourcePressure
    {
        return $this->resources?->snapshot() ?? new ResourcePressure(1000, 1000);
    }

    /**
     * Decision logging for operators. The decision id is deliberately not
     * included: it is an internal handle that pairs calibration receipts,
     * and logging it would let log analysis correlate decisions across
     * requests. Decision ids are only ever carried in process memory or
     * the short-lived server-side nonce mapping. No bearer material is
     * ever logged here or anywhere else in the bundle: no challenge token,
     * solution, result token, HMAC pseudonym, client IP, cookie value or
     * principal. The context is score/action/band/reasons only (bounded,
     * low cardinality).
     */
    private function logDecision(string $scope, RiskDecision $decision): void
    {
        if ($this->logger === null) {
            return;
        }
        $context = [
            'scope' => $scope,
            'action' => $decision->action->value,
            'score' => $decision->score,
            'band' => $decision->band,
            'global_level' => $decision->globalLevel,
            'policy_version' => $decision->policyVersion,
            'reasons' => array_map(static fn (RiskReason $r): string => $r->value, $decision->reasons),
            'retry_after_ms' => $decision->retryAfterMs,
        ];
        if ($decision->action === RiskAction::Deny) {
            $this->logger->warning('kiwicaptcha.risk: issuance denied by adaptive risk', $context);
        } else {
            $this->logger->info('kiwicaptcha.risk: issuance decision', $context);
        }
    }
}
