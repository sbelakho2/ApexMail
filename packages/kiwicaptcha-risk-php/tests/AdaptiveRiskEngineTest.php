<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Breaker\CircuitBreaker;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskDecision;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskReason;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\LocalEmergencyLimiter;
use KiwiCaptcha\Risk\Storage\RiskStateStoreInterface;
use KiwiCaptcha\Risk\Storage\RiskStoreException;
use PHPUnit\Framework\TestCase;

final class AdaptiveRiskEngineTest extends TestCase
{
    private function policy(): RiskPolicy
    {
        return RiskPolicy::fromConfig([
            'version' => 3,
            'weights' => (new RiskWeights())->toArray(),
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20'],
            ],
            'global_floors' => [1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
        ]);
    }

    private function engine(RiskStateStoreInterface $store, ?CircuitBreaker $breaker = null, ?LocalEmergencyLimiter $limiter = null): AdaptiveRiskEngine
    {
        $keys = RiskKeys::fromMaster(str_repeat(chr(0x42), 32));
        $classifier = new CidrNetworkClassifier([
            ['cidr' => '203.0.113.0/24', 'flags' => ['hosting']],
        ]);
        return new AdaptiveRiskEngine(
            store: $store,
            classifier: $classifier,
            identityFactory: new RiskIdentityFactory($keys),
            scorer: new RiskScorer(),
            policy: $this->policy(),
            keys: $keys,
            breaker: $breaker ?? new CircuitBreaker(),
            limiter: $limiter ?? new LocalEmergencyLimiter(),
        );
    }

    private function context(int $scope = 1, RiskEventKind $event = RiskEventKind::PreIssue): RiskContext
    {
        return new RiskContext(
            scope: $scope,
            sourceIp: '203.0.113.27',
            sessionId: null,
            principalId: null,
            event: $event,
            networkFlags: (new CidrNetworkClassifier([['cidr' => '203.0.113.0/24', 'flags' => ['hosting']]]))->classify('203.0.113.27'),
            resources: new ResourcePressure(1000, 1000, 1000),
        );
    }

    public function testAssessNormalPath(): void
    {
        $store = new class implements RiskStateStoreInterface {
            public int $globalLevel = 2;

            public function observe(RiskObservation $observation): SignalVector
            {
                return SignalVector::fromArray(['source_fast' => 500]);
            }

            public function lastGlobalLevel(): int
            {
                return $this->globalLevel;
            }

            public function lastCooldownUntilMs(): int
            {
                return 0;
            }
        };
        $engine = $this->engine($store);
        $decision = $engine->assess($this->context());
        self::assertSame(195, $decision->score); // 100 + weighted(500, 190)
        self::assertSame(\KiwiCaptcha\Risk\RiskAction::Sha18, $decision->action); // band Sha16 raised by global floor 2
        self::assertSame(3, $decision->policyVersion);
        self::assertSame(2, $decision->globalLevel);
        self::assertSame(1, $decision->band);

        $metrics = $engine->metrics()->snapshot();
        self::assertArrayHasKey('decisions:1:sha18:1', $metrics['counters']);
        self::assertSame(2, $metrics['gauges']['global:level']);
        self::assertArrayHasKey('store:observe', $metrics['latencies']);
    }

    public function testObservationCarriesPseudonymsAndNetworkRisk(): void
    {
        $captured = [];
        $store = new class($captured) implements RiskStateStoreInterface {
            public function __construct(private array &$captured)
            {
            }

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->captured[] = $observation;
                return SignalVector::zero();
            }
        };
        $engine = $this->engine($store);
        $engine->assess($this->context());

        $observation = $captured[0];
        self::assertSame(RiskEventKind::PreIssue, $observation->event);
        self::assertSame(1, $observation->scope);
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $observation->sourceId);
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $observation->subnetId);
        self::assertNull($observation->sessionId);
        self::assertNull($observation->principalId);
        self::assertSame(1000, $observation->networkRisk); // hosting flag
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $observation->eventId);
    }

    public function testEmergencyLimiterDeniesWithRetryAfter(): void
    {
        $limiter = new LocalEmergencyLimiter();
        for ($i = 0; $i < 100; $i++) {
            $limiter->allow();
        }
        $store = new class implements RiskStateStoreInterface {
            public int $calls = 0;

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->calls++;
                return SignalVector::zero();
            }
        };
        $engine = $this->engine($store, limiter: $limiter);
        $decision = $engine->assess($this->context());
        self::assertSame(\KiwiCaptcha\Risk\RiskAction::Deny, $decision->action);
        self::assertTrue($decision->hasReason(RiskReason::HardRateLimit));
        self::assertSame(1000, $decision->retryAfterMs);
        self::assertSame(0, $store->calls, 'the store must not be touched when the limiter is open');
    }

    public function testStoreFailureDegradesAndOpensBreaker(): void
    {
        $store = new class implements RiskStateStoreInterface {
            public int $calls = 0;

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->calls++;
                throw new RiskStoreException('redis down');
            }
        };
        $breaker = new CircuitBreaker(2, 60_000);
        $engine = $this->engine($store, $breaker);

        $d1 = $engine->assess($this->context());
        self::assertSame(\KiwiCaptcha\Risk\RiskAction::Sha20, $d1->action); // degraded sha20
        self::assertTrue($d1->hasReason(RiskReason::CapacityPressure));
        self::assertSame(1, $store->calls);

        $d2 = $engine->assess($this->context());
        self::assertSame(\KiwiCaptcha\Risk\RiskAction::Sha20, $d2->action);
        self::assertSame(2, $store->calls);

        // Breaker is now open: the store is bypassed.
        $d3 = $engine->assess($this->context());
        self::assertSame(\KiwiCaptcha\Risk\RiskAction::Sha20, $d3->action);
        self::assertSame(2, $store->calls, 'open breaker must bypass the store');
    }

    public function testBreakerRecoversAfterWindow(): void
    {
        $store = new class implements RiskStateStoreInterface {
            public int $calls = 0;

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->calls++;
                if ($this->calls <= 2) {
                    throw new RiskStoreException('redis down');
                }
                return SignalVector::fromArray(['source_fast' => 500]);
            }
        };
        $breaker = new CircuitBreaker(2, 50);
        $engine = $this->engine($store, $breaker);

        $engine->assess($this->context());
        $engine->assess($this->context());
        self::assertTrue($breaker->isOpen());

        usleep(60_000);
        $decision = $engine->assess($this->context());
        self::assertSame(195, $decision->score);
        self::assertSame(\KiwiCaptcha\Risk\RiskAction::Sha16, $decision->action);
        self::assertSame(3, $store->calls);
        self::assertFalse($breaker->isOpen());
    }

    public function testRecordMapsEvents(): void
    {
        $captured = [];
        $store = new class($captured) implements RiskStateStoreInterface {
            public function __construct(private array &$captured)
            {
            }

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->captured[] = $observation->event;
                return SignalVector::zero();
            }
        };
        $engine = $this->engine($store);
        $engine->record(RiskEventKind::ProtectedActionFailure, 1, '203.0.113.27', 'sess', null);
        $engine->confirmedLegitimate('1', '203.0.113.27');
        $engine->confirmedAbuse('1', '203.0.113.27', 'principal-1');
        self::assertSame([
            RiskEventKind::ProtectedActionFailure,
            RiskEventKind::ConfirmedLegitimate,
            RiskEventKind::ConfirmedAbuse,
        ], $captured);
    }

    public function testDecisionType(): void
    {
        $store = new class implements RiskStateStoreInterface {
            public function observe(RiskObservation $observation): SignalVector
            {
                return SignalVector::zero();
            }
        };
        $engine = $this->engine($store);
        $decision = $engine->assess($this->context());
        self::assertInstanceOf(RiskDecision::class, $decision);
        $json = json_decode((string) json_encode($decision), true);
        self::assertIsArray($json);
        self::assertSame('allow', $json['action']);
    }
}
