<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Metrics\RiskMetrics;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Tests\RiskStateStoreStub;
use PHPUnit\Framework\TestCase;

/**
 * AUDIT #35 — METRICS CARDINALITY.
 *
 * RiskMetrics counter keys must be BOUNDED: recording decisions with
 * distinct decisionIds/challengeIds must never grow the counters map (no
 * identity-bearing keys). The engine's key construction is the bounded
 * tuple "decisions:<scope>:<action>:<band>" (scope is deployment-config
 * bounded, action is an enum value, band is 0..10) plus a handful of fixed
 * literals (denied:limiter, degraded:breaker, degraded:store, gauges,
 * latencies) — the tests below pin that construction and prove the map
 * does not grow with the ids.
 */
final class RiskMetricsTest extends TestCase
{
    private function engine(RiskStateStoreStub $store): AdaptiveRiskEngine
    {
        $keys = RiskKeys::fromMaster(str_repeat(chr(0x42), 32));
        return new AdaptiveRiskEngine(
            store: $store,
            classifier: new CidrNetworkClassifier([]),
            identityFactory: new RiskIdentityFactory($keys),
            scorer: new RiskScorer(),
            policy: RiskPolicy::fromConfig([
                'version' => 3,
                'weights' => (new RiskWeights())->toArray(),
                'scopes' => [
                    1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20'],
                ],
                'global_floors' => [1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            ]),
            keys: $keys,
        );
    }

    private function context(): RiskContext
    {
        return new RiskContext(
            scope: 1,
            sourceIp: '198.51.100.7',
            sessionId: null,
            principalId: null,
            event: RiskEventKind::PreIssue,
            networkFlags: (new CidrNetworkClassifier([]))->classify('198.51.100.7'),
            resources: new ResourcePressure(1000, 1000),
        );
    }

    public function testCounterKeysAreTheBoundedTuple(): void
    {
        $metrics = new RiskMetrics();
        $metrics->increment('decisions:1:allow:0');
        $metrics->increment('decisions:1:allow:0');
        $metrics->increment('denied:limiter');
        $metrics->gauge('global:level', 2);
        $metrics->recordLatency('store:observe', 3.5);

        $snapshot = $metrics->snapshot();
        self::assertSame(2, $snapshot['counters']['decisions:1:allow:0'], 'repeated decisions aggregate into ONE bounded key');
        self::assertSame(1, $snapshot['counters']['denied:limiter']);
        self::assertCount(2, $snapshot['counters'], 'counter keys are the bounded tuple set, nothing else');
        self::assertSame(['global:level'], array_keys($snapshot['gauges']), 'gauges are fixed bounded keys');
        self::assertSame(['store:observe'], array_keys($snapshot['latencies']), 'latency keys are fixed bounded keys');
    }

    /**
     * Engine-level cardinality: 200 assessments with DISTINCT idempotency
     * keys (each a distinct challenge/event id) and DISTINCT decision ids
     * must leave the counters map bounded — no identity-bearing keys.
     */
    public function testEngineMetricsDoNotGrowWithDecisionIds(): void
    {
        $store = new class extends RiskStateStoreStub {
            public function observe(RiskObservation $observation): SignalVector
            {
                return SignalVector::zero();
            }
        };
        $engine = $this->engine($store);
        $decisionIds = [];

        for ($i = 0; $i < 200; $i++) {
            $decision = $engine->assess($this->context(), 'idem-key-' . $i);
            $decisionIds[] = $decision->decisionId;
        }

        $snapshot = $engine->metrics()->snapshot();
        $counterKeys = array_keys($snapshot['counters']);
        $allKeys = array_merge($counterKeys, array_keys($snapshot['gauges']), array_keys($snapshot['latencies']));

        // The decision counter key is the bounded tuple (scope:action:band).
        $decisionKeys = array_filter($counterKeys, static fn (string $k): bool => str_starts_with($k, 'decisions:'));
        self::assertCount(1, $decisionKeys, '200 distinct decisions must collapse into ONE counter key');
        self::assertMatchesRegularExpression(
            '/^decisions:\d+:(?:allow|sha16|sha18|sha20|deny):\d+$/',
            $decisionKeys[0],
            'the decision counter key must be the bounded scope:action:band tuple',
        );
        self::assertLessThanOrEqual(6, count($allKeys), 'the whole metric key set must stay bounded');

        // No key may embed any decision/challenge id.
        foreach ($allKeys as $key) {
            foreach ($decisionIds as $id) {
                self::assertStringNotContainsString($id, $key, "metric key {$key} must not carry the decision id {$id}");
            }
            self::assertStringNotContainsString('idem-key-', $key, "metric key {$key} must not carry a challenge/event id");
            self::assertMatchesRegularExpression(
                '/^(decisions:\d+:(?:allow|sha16|sha18|sha20|deny):\d+|denied:limiter|degraded:(?:breaker|store)|global:level|resources:argon_capacity|store:observe)$/',
                $key,
                "metric key {$key} must be a bounded literal or tuple key",
            );
        }
    }
}
