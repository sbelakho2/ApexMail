<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\ChallengeProfile;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
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
 * are consumed.
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
     * @param 'reject'|'minimum'                  $unknownScopeMode behavior for scopes absent from $scopeIds
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
        if (!\in_array($unknownScopeMode, ['reject', 'minimum'], true)) {
            throw new \InvalidArgumentException(sprintf('unknownScopeMode must be "reject" or "minimum" (got "%s")', $unknownScopeMode));
        }
    }

    /**
     * The risk-v1 int scope for an application scope string: the configured
     * id when present, otherwise the unknown-scope policy.
     *
     * @throws UnknownScopeException when the scope is not configured and
     *                               unknown_scope.mode is "reject" (the
     *                               adaptive engine declines to evaluate)
     */
    public function scopeId(string $scope): int
    {
        if (isset($this->scopeIds[$scope])) {
            return $this->scopeIds[$scope];
        }
        if ($this->unknownScopeMode === 'reject') {
            throw new UnknownScopeException(sprintf(
                'Risk scope "%s" is not configured and unknown_scope.mode is "reject" — the adaptive engine declines to evaluate it',
                $scope,
            ));
        }

        // 'minimum' mode: every unknown scope is assessed under the shared
        // synthetic policy (base_risk 100, minimum/degraded sha20).
        return $this->unknownScopeId ?? (crc32($scope) & 0x7fffffff);
    }

    /** Whether a VALID solve of this scope must pass the post-solve re-assessment. */
    public function postSolveCheck(string $scope): bool
    {
        return $this->postSolveScopes[$scope] ?? false;
    }

    /**
     * PRE-ISSUE assessment: one observation (event PreIssue) + decision.
     *
     * @throws UnknownScopeException   when the scope is unknown in 'reject' mode
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
     * while the client was solving) can demand DENY even after a valid
     * proof. The outcome is recorded as ConfirmedLegitimate / ConfirmedAbuse
     * feedback through {@see AdaptiveRiskEngine::record_feedback()} keyed on
     * the post-solve decision id, so the calibration receipt for that
     * decision is consumed. The caller maps a Deny to its own failure.
     */
    public function postSolveDecision(string $scope, string $ip, ?string $session = null, ?string $principal = null, ?string $idempotencyKey = null): RiskDecision
    {
        $context = new RiskContext(
            scope: $this->scopeId($scope),
            sourceIp: $ip,
            sessionId: $session,
            principalId: $principal,
            event: RiskEventKind::SolveSuccess,
            networkFlags: $this->classifier->classify($ip),
            resources: $this->resources(),
        );
        $decision = $this->engine->assess($context, $idempotencyKey);
        $this->logDecision($scope, $decision);

        $this->engine->record_feedback(
            $decision->action === RiskAction::Deny ? RiskEventKind::ConfirmedAbuse : RiskEventKind::ConfirmedLegitimate,
            $context,
            $idempotencyKey,
            $decision->decisionId,
        );

        return $decision;
    }

    /** Post-issue signal: the challenge was actually minted (issue-debt). */
    public function challengeIssued(string $scope, string $ip, ?string $session, ?string $decisionId = null): void
    {
        try {
            $this->engine->record_feedback(
                RiskEventKind::ChallengeIssued,
                new RiskContext(
                    scope: $this->scopeId($scope),
                    sourceIp: $ip,
                    sessionId: $session,
                    principalId: null,
                    event: RiskEventKind::ChallengeIssued,
                    networkFlags: $this->classifier->classify($ip),
                    resources: $this->resources(),
                ),
                null,
                $decisionId,
            );
        } catch (\InvalidArgumentException) {
            // Invalid client IP: the signal has nothing to attribute to —
            // never break issuance over the feedback path.
        }
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
        try {
            $this->engine->record_feedback(
                $event,
                new RiskContext(
                    scope: $this->scopeId($scope),
                    sourceIp: $ip,
                    sessionId: $session,
                    principalId: null,
                    event: $event,
                    networkFlags: $this->classifier->classify($ip),
                    resources: $this->resources(),
                ),
                null,
                $decisionId,
            );
        } catch (\InvalidArgumentException) {
            // Invalid client IP: nothing to attribute the signal to.
        }
    }

    /**
     * Confirmed-legitimate signal (e.g. from application-level post-hoc
     * checks): routed through {@see AdaptiveRiskEngine::record_feedback()}
     * so the decision's calibration receipt is consumed when a decision id
     * is supplied.
     */
    public function confirmedLegitimate(string $scope, string $ip, ?string $session = null, ?string $idempotencyKey = null, ?string $decisionId = null): void
    {
        $this->recordConfirmation(RiskEventKind::ConfirmedLegitimate, $scope, $ip, $session, $idempotencyKey, $decisionId);
    }

    /**
     * Confirmed-abuse signal (e.g. from application-level post-hoc checks):
     * routed through {@see AdaptiveRiskEngine::record_feedback()} so the
     * decision's calibration receipt is consumed when a decision id is
     * supplied.
     */
    public function confirmedAbuse(string $scope, string $ip, ?string $session = null, ?string $idempotencyKey = null, ?string $decisionId = null): void
    {
        $this->recordConfirmation(RiskEventKind::ConfirmedAbuse, $scope, $ip, $session, $idempotencyKey, $decisionId);
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

    private function recordConfirmation(RiskEventKind $kind, string $scope, string $ip, ?string $session, ?string $idempotencyKey, ?string $decisionId): void
    {
        try {
            $this->engine->record_feedback(
                $kind,
                new RiskContext(
                    scope: $this->scopeId($scope),
                    sourceIp: $ip,
                    sessionId: $session,
                    principalId: null,
                    event: $kind,
                    networkFlags: $this->classifier->classify($ip),
                    resources: $this->resources(),
                ),
                $idempotencyKey,
                $decisionId,
            );
        } catch (\InvalidArgumentException) {
            // Invalid client IP: nothing to attribute the signal to.
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
