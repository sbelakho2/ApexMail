<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\ChallengeProfile;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\EventReceipt;
use KiwiCaptcha\Risk\Network\NetworkClassifierInterface;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskDecision;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskReason;
use KiwiCaptcha\VerifyError;
use Psr\Log\LoggerInterface;

/**
 * Bundle-side facade over the adaptive risk engine.
 *
 * Builds the risk-v1 context (scope id, source/subnet/session pseudonyms via
 * the engine's identity derivation, network flags, live resource pressure)
 * for the challenge controller's PRE-ISSUE assessment and feeds the engine's
 * POST-SOLVE outcome signals, maps decisions to challenge profiles, and logs
 * decisions without ever logging an IP or cookie value.
 *
 * All engine calls go through the contract surface: `assess(ctx,
 * idempotencyKey)` for decisions and `record_feedback(event, ctx,
 * idempotencyKey, decisionId)` for outcome signals (no limits, no decision),
 * so decision ids flow end-to-end and the calibration receipts keyed on them
 * are consumed. ConfirmedLegitimate / ConfirmedAbuse are APPLICATION signals
 * only — the gateway never derives them from its own decisions (the engine
 * requires a decision id for them and throws InvalidArgumentException without
 * one).
 *
 * Every FEEDBACK path is guarded against unknown scopes: when the scope is
 * not configured and unknown_scope.mode is "reject"/"baseline" (the engine
 * declines to evaluate), the signal is skipped with a debug log — feedback
 * must never crash the request path.
 *
 * Resource pressure comes from the injected provider
 * ({@see ResourcePressureProviderInterface}); without one every dimension is
 * nominal (1000 = no pressure).
 */
final class RiskGateway
{
    /**
     * @param array<string, int>                  $scopeIds         application scope string => risk-v1 int scope
     * @param array<string, bool>                 $postSolveScopes  application scope string => post_solve_check flag
     * @param 'reject'|'baseline'|'minimum'       $unknownScopeMode behavior for scopes absent from $scopeIds
     * @param int|null                            $unknownScopeId   synthetic policy scope id used in 'minimum' mode
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
        // evaluate unknown scopes. 'reject' surfaces as a TRUE rejection
        // (the controller returns the risk-denied 429); 'baseline' lets the
        // controller fall back to the default challenge profile.
        throw new UnknownScopeException(sprintf(
            'Risk scope "%s" is not configured and unknown_scope.mode is "%s" — the adaptive engine declines to evaluate it',
            $scope,
            $this->unknownScopeMode,
        ));
    }

    /** Whether a VALID solve of this scope must pass the post-solve re-assessment. */
    public function postSolveCheck(string $scope): bool
    {
        return $this->postSolveScopes[$scope] ?? false;
    }

    /**
     * PRE-ISSUE assessment: one observation (event PreIssue) + decision.
     *
     * @throws UnknownScopeException   when the scope is unknown in 'reject'/'baseline' mode
     * @throws \InvalidArgumentException when the client IP is not a valid
     *                                   IPv4/IPv6 address (the caller treats
     *                                   this as "no risk signal" and issues
     *                                   normally)
     */
    public function preIssue(string $scope, string $ip, ?string $session, ?string $idempotencyKey = null): RiskDecision
    {
        $decision = $this->engine->assess(
            new RiskContext(
                scope: $this->scopeId($scope),
                sourceIp: $ip,
                // The engine derives the keyed session pseudonym itself
                // (buildObservation) — pass the raw cookie value.
                sessionId: $session,
                principalId: null,
                event: RiskEventKind::PreIssue,
                networkFlags: $this->classifier->classify($ip),
                resources: $this->resources(),
            ),
            $idempotencyKey,
        );
        $this->logDecision($scope, $decision);

        return $decision;
    }

    /**
     * POST-SOLVE decision: a fresh assessment with the SolveSuccess event,
     * so a materially changed security context (e.g. a global attack storm
     * while the client was solving) can demand DENY or STEP-UP even after a
     * valid proof.
     *
     * The outcome is NOT fed back by the gateway: ConfirmedLegitimate /
     * ConfirmedAbuse are application-only signals (they require a decision
     * id), so the caller decides whether the solve really was a success and
     * records the confirmation itself with the returned decision id.
     *
     * @return RiskDecision|null the post-solve decision, or null when the
     *                           scope is unknown and the engine declines to
     *                           evaluate (feedback paths must never crash on
     *                           unknown scopes)
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
            principalId: $principal,
            event: RiskEventKind::SolveSuccess,
            networkFlags: $this->classifier->classify($ip),
            resources: $this->resources(),
        );
        $decision = $this->engine->assess($context, $idempotencyKey);
        $this->logDecision($scope, $decision);

        return $decision;
    }

    /** Post-issue signal: the challenge was actually minted (issue-debt). */
    public function challengeIssued(string $scope, string $ip, ?string $session, ?string $decisionId = null): void
    {
        $this->recordFeedback(RiskEventKind::ChallengeIssued, $scope, $ip, $session, null, $decisionId);
    }

    /**
     * POST-SOLVE feedback: the outcome of a verification attempt, mapped to
     * its risk-v1 event kind ({@see RiskFeedback}). Infrastructure failures
     * are mapped to null and skipped — never recorded as client abuse. An
     * unparseable client IP is not a risk signal and is skipped too (the
     * engine's identity derivation requires a valid IPv4/IPv6 address).
     */
    public function solveOutcome(string $scope, string $ip, ?string $session, ?VerifyError $error, ?string $decisionId = null): void
    {
        $event = RiskFeedback::eventFor($error);
        if ($event === null) {
            return;
        }
        $this->recordFeedback($event, $scope, $ip, $session, null, $decisionId);
    }

    /**
     * Confirmed-legitimate signal (APPLICATION-only, e.g. from post-hoc
     * account checks): routed through {@see AdaptiveRiskEngine::record_feedback()}
     * so the decision's calibration receipt is consumed. The decision id is
     * REQUIRED by the engine contract — it throws InvalidArgumentException
     * without one, and the gateway lets that enforcement surface.
     *
     * @throws \InvalidArgumentException when the engine requires a decisionId
     *                                   for confirmed events and none is given
     */
    public function confirmedLegitimate(string $scope, string $ip, ?string $session = null, ?string $idempotencyKey = null, ?string $decisionId = null): ?EventReceipt
    {
        return $this->recordConfirmation(RiskEventKind::ConfirmedLegitimate, $scope, $ip, $session, $idempotencyKey, $decisionId);
    }

    /**
     * Confirmed-abuse signal (APPLICATION-only, e.g. from post-hoc account
     * checks): routed through {@see AdaptiveRiskEngine::record_feedback()}
     * so the decision's calibration receipt is consumed. The decision id is
     * REQUIRED by the engine contract — it throws InvalidArgumentException
     * without one, and the gateway lets that enforcement surface.
     *
     * @throws \InvalidArgumentException when the engine requires a decisionId
     *                                   for confirmed events and none is given
     */
    public function confirmedAbuse(string $scope, string $ip, ?string $session = null, ?string $idempotencyKey = null, ?string $decisionId = null): ?EventReceipt
    {
        return $this->recordConfirmation(RiskEventKind::ConfirmedAbuse, $scope, $ip, $session, $idempotencyKey, $decisionId);
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
     * controller calls this BEFORE returning 429 so the risk state learns
     * the source was refused.
     */
    public function rateLimitHit(string $scope, string $ip, ?string $session = null, ?string $idempotencyKey = null): ?EventReceipt
    {
        return $this->recordFeedback(RiskEventKind::RateLimitHit, $scope, $ip, $session, $idempotencyKey, null);
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

    /** The challenge profile the decision demands (null = issue as configured). */
    public function decisionProfile(RiskDecision $decision): ?ChallengeProfile
    {
        return $this->resolver->profileFor($decision->action);
    }

    /** Engine metrics snapshot (counters/gauges/latencies, no identity labels). */
    public function metricsSnapshot(): array
    {
        return $this->engine->metrics()->snapshot();
    }

    private function recordConfirmation(RiskEventKind $kind, string $scope, string $ip, ?string $session, ?string $idempotencyKey, ?string $decisionId): ?EventReceipt
    {
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
            principalId: null,
            event: $kind,
            networkFlags: $this->classifier->classify($ip),
            resources: $this->resources(),
        );

        // Route through the engine's first-class confirmation methods so the
        // package enforces the decisionId requirement (InvalidArgumentException
        // without it) — the gateway never infers confirmations itself.
        return $kind === RiskEventKind::ConfirmedLegitimate
            ? $this->engine->confirmedLegitimate($context, $decisionId, $idempotencyKey)
            : $this->engine->confirmedAbuse($context, $decisionId, $idempotencyKey);
    }

    /**
     * One feedback event through {@see AdaptiveRiskEngine::record_feedback()}.
     *
     * Never throws for unavailable signals:
     *  - an unknown scope (reject/baseline modes) skips the signal with a
     *    debug log — feedback paths must never crash on unknown scopes;
     *  - an unparseable client IP has nothing to attribute the signal to and
     *    is skipped.
     *
     * Engine exceptions are deliberately NOT swallowed here: the engine's
     * InvalidArgumentException for confirmed events without a decisionId is
     * contract enforcement and must reach the application caller.
     *
     * @return EventReceipt|null null when the signal was skipped (unknown
     *                           scope or invalid client IP)
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
                principalId: null,
                event: $event,
                networkFlags: $this->classifier->classify($ip),
                resources: $this->resources(),
            ),
            $idempotencyKey,
            $decisionId,
        );
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
        return $this->resources?->snapshot() ?? new ResourcePressure(1000, 1000, 1000);
    }

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
            'decision_id' => $decision->decisionId,
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
