<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\ChallengeProfile;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\NetworkClassifierInterface;
use KiwiCaptcha\Risk\ResourcePressure;
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
 * the engine's identity derivation, network flags, nominal resource pressure)
 * for the challenge controller's PRE-ISSUE assessment and feeds the engine's
 * POST-SOLVE outcome signals, maps decisions to challenge profiles, and logs
 * decisions without ever logging an IP or cookie value.
 *
 * Resource pressure is nominal (1000 = no pressure) in the bundle wiring:
 * the capacity-denial paths of the policy are optional hardening knobs for
 * deployments that feed their own telemetry — the bundle's rate limits and
 * saturations already bound the abuse surface. Documented, deliberate.
 */
final class RiskGateway
{
    /** @param array<string, int> $scopeIds application scope string => risk-v1 int scope */
    public function __construct(
        private readonly AdaptiveRiskEngine $engine,
        private readonly NetworkClassifierInterface $classifier,
        private readonly RiskProfileResolver $resolver,
        private readonly array $scopeIds,
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    /**
     * The risk-v1 int scope for an application scope string: the configured
     * id when present, otherwise crc32(name) & 0x7fffffff (stable across
     * deploys as long as the name stays the same).
     */
    public function scopeId(string $scope): int
    {
        return $this->scopeIds[$scope] ?? (crc32($scope) & 0x7fffffff);
    }

    /**
     * PRE-ISSUE assessment: one observation (event PreIssue) + decision.
     *
     * @throws \InvalidArgumentException when the client IP is not a valid
     *                                   IPv4/IPv6 address (the caller treats
     *                                   this as "no risk signal" and issues
     *                                   normally)
     */
    public function preIssue(string $scope, string $ip, ?string $session): RiskDecision
    {
        $decision = $this->engine->assess(new RiskContext(
            scope: $this->scopeId($scope),
            sourceIp: $ip,
            // The engine derives the keyed session pseudonym itself
            // (buildObservation) — pass the raw cookie value.
            sessionId: $session,
            principalId: null,
            event: RiskEventKind::PreIssue,
            networkFlags: $this->classifier->classify($ip),
            resources: new ResourcePressure(1000, 1000, 1000),
        ));
        $this->logDecision($scope, $decision);

        return $decision;
    }

    /** Post-issue signal: the challenge was actually minted (issue-debt). */
    public function challengeIssued(string $scope, string $ip, ?string $session): void
    {
        try {
            $this->engine->record(RiskEventKind::ChallengeIssued, $this->scopeId($scope), $ip, $session);
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
    public function solveOutcome(string $scope, string $ip, ?string $session, ?VerifyError $error): void
    {
        $event = RiskFeedback::eventFor($error);
        if ($event === null) {
            return;
        }
        try {
            $this->engine->record($event, $this->scopeId($scope), $ip, $session);
        } catch (\InvalidArgumentException) {
            // Invalid client IP: nothing to attribute the signal to.
        }
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
        if ($decision->action === \KiwiCaptcha\Risk\RiskAction::Deny) {
            $this->logger->warning('kiwicaptcha.risk: issuance denied by adaptive risk', $context);
        } else {
            $this->logger->info('kiwicaptcha.risk: issuance decision', $context);
        }
    }
}
