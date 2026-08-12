<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

use KiwiCaptcha\Risk\Breaker\CircuitBreaker;
use KiwiCaptcha\Risk\Metrics\RiskMetrics;
use KiwiCaptcha\Risk\Network\NetworkClassifierInterface;
use KiwiCaptcha\Risk\Storage\LocalEmergencyLimiter;
use KiwiCaptcha\Risk\Storage\RiskStateStoreInterface;
use KiwiCaptcha\Risk\Storage\RiskStoreException;

/**
 * Adaptive risk engine: assesses one request and returns a RiskDecision.
 *
 * Pipeline: emergency limiter -> observation -> circuit breaker -> state
 * store (EVALSHA) -> scorer -> policy. Backend failure degrades instead of
 * failing the request.
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
    ) {
    }

    public function metrics(): RiskMetrics
    {
        return $this->metrics;
    }

    public function assess(RiskContext $c): RiskDecision
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
            return $decision;
        }

        $observation = $this->buildObservation($c, $nowMs);

        if ($this->breaker->isOpen()) {
            $this->metrics->increment('degraded:breaker');
            $decision = $this->policy->degradedDecision($c->scope, $this->storeGlobalLevel());
            $this->recordDecisionMetrics($c->scope, $decision);
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
            return $decision;
        }
        $this->metrics->recordLatency('store:observe', (microtime(true) - $start) * 1000);
        $this->breaker->recordSuccess();

        $score = $this->scorer->score($this->policy->baseRisk($c->scope), $vector, $this->policy->weights);
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
        return $decision;
    }

    /** Outcome feedback path (e.g. a post-solve protected action). */
    public function record(RiskEventKind $kind, int $scope, string $ip, ?string $sessionId = null, ?string $principalId = null): void
    {
        $this->assess(new RiskContext(
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
        $this->record(RiskEventKind::ConfirmedLegitimate, (int) $scope, $ip, null, $principalId);
    }

    public function confirmedAbuse(string $scope, string $ip, ?string $principalId = null): void
    {
        $this->record(RiskEventKind::ConfirmedAbuse, (int) $scope, $ip, null, $principalId);
    }

    private function buildObservation(RiskContext $c, int $nowMs): RiskObservation
    {
        $nowSecs = intdiv($nowMs, 1000);
        return new RiskObservation(
            event: $c->event,
            scope: $c->scope,
            sourceId: $this->identityFactory->sourceId($c->sourceIp, $nowSecs),
            subnetId: $this->identityFactory->subnetId($c->sourceIp, $nowSecs),
            sessionId: $c->sessionId !== null ? $this->identityFactory->sessionId($c->sessionId) : null,
            principalId: $c->principalId !== null ? $this->identityFactory->principalId($c->principalId) : null,
            eventId: RiskObservation::newEventId(),
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

    private function recordDecisionMetrics(int $scope, RiskDecision $decision): void
    {
        $this->metrics->increment(sprintf('decisions:%d:%s:%d', $scope, $decision->action->value, $decision->band));
    }
}
