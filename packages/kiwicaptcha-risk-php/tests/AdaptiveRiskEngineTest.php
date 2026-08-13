<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Breaker\CircuitBreaker;
use KiwiCaptcha\Risk\Calibration\CalibrationStore;
use KiwiCaptcha\Risk\EventReceipt;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskAction;
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
use KiwiCaptcha\Risk\Storage\ProcessEmergencyCap;
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

    private function engine(RiskStateStoreInterface $store, ?CircuitBreaker $breaker = null, ?ProcessEmergencyCap $limiter = null, bool $enableGlobalPressure = true): AdaptiveRiskEngine
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
            limiter: $limiter ?? new ProcessEmergencyCap(),
            enableGlobalPressure: $enableGlobalPressure,
        );
    }

    private function context(int $scope = 1, RiskEventKind $event = RiskEventKind::PreIssue, ?string $principalId = null): RiskContext
    {
        return new RiskContext(
            scope: $scope,
            sourceIp: '203.0.113.27',
            sessionId: null,
            principalId: $principalId,
            event: $event,
            networkFlags: (new CidrNetworkClassifier([['cidr' => '203.0.113.0/24', 'flags' => ['hosting']]]))->classify('203.0.113.27'),
            resources: new ResourcePressure(1000, 1000),
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
        // Epoch-correct pseudonyms: each epoch key uses its OWN pseudonym.
        self::assertNotSame($observation->sourceId, $observation->sourceIdPrev);
        self::assertNotSame($observation->sourceId, $observation->sourceIdNext);
        self::assertNotSame($observation->subnetId, $observation->subnetIdPrev);
        self::assertNotSame($observation->subnetId, $observation->subnetIdNext);
        self::assertGreaterThan(0, $observation->sourceEpoch);
        self::assertSame($observation->sourceEpoch, $observation->subnetEpoch); // both 900 s epochs
        self::assertNull($observation->sessionId);
        self::assertNull($observation->principalId);
        self::assertSame(1000, $observation->networkRisk); // hosting flag
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $observation->eventId);
    }

    public function testAssessNormalizesIdempotencyKey(): void
    {
        $captured = [];
        $store = new class($captured) implements RiskStateStoreInterface {
            public function __construct(private array &$captured)
            {
            }

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->captured[] = $observation->eventId;
                return SignalVector::zero();
            }
        };
        $engine = $this->engine($store);
        $key = 'caller-supplied-event-42';
        $expected = hash('sha256', "kiwi-risk-event-v1\0" . $key);
        $engine->assess($this->context(), $key);
        self::assertSame([$expected], $captured, 'the caller idempotency key must be normalized (sha256) before the store');

        $engine->assess($this->context(), $key);
        self::assertSame([$expected, $expected], $captured, 'retries with the same key must normalize identically (dedupe by the Lua)');
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $expected);
    }

    public function testEmptyIdempotencyKeyBecomesRandom(): void
    {
        $captured = [];
        $store = new class($captured) implements RiskStateStoreInterface {
            public function __construct(private array &$captured)
            {
            }

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->captured[] = $observation->eventId;
                return SignalVector::zero();
            }
        };
        $engine = $this->engine($store);
        $engine->assess($this->context(), '');
        $engine->assess($this->context(), '');
        self::assertCount(2, $captured);
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $captured[0], 'empty key must become a fresh random 16-byte hex id');
        self::assertNotSame($captured[0], $captured[1], 'each empty key must get a fresh random id');
    }

    public function testIdempotencyKeyTooLongThrows(): void
    {
        $store = new class implements RiskStateStoreInterface {
            public function observe(RiskObservation $observation): SignalVector
            {
                return SignalVector::zero();
            }
        };
        $engine = $this->engine($store);
        $this->expectException(\InvalidArgumentException::class);
        $engine->assess($this->context(), str_repeat('x', 4097));
    }

    public function testNormalizedEventIdsAcrossAllEntryPoints(): void
    {
        $captured = [];
        $store = new class($captured) implements RiskStateStoreInterface {
            public function __construct(private array &$captured)
            {
            }

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->captured[] = $observation->eventId;
                return SignalVector::zero();
            }
        };
        $engine = $this->engine($store);
        $key = 'shared-idempotency-key';
        $expected = hash('sha256', "kiwi-risk-event-v1\0" . $key);

        $engine->assessPreIssue($this->context(), $key);
        $engine->reassess($this->context(), $key);
        $engine->record_feedback(RiskEventKind::RateLimitHit, $this->context(event: RiskEventKind::RateLimitHit), $key);
        $engine->confirmedLegitimate($this->context(event: RiskEventKind::ConfirmedLegitimate), str_repeat('a', 32), $key);
        $engine->confirmedAbuse($this->context(event: RiskEventKind::ConfirmedAbuse), str_repeat('b', 32), $key);
        $engine->record(RiskEventKind::ExpiredChallenge, 1, '203.0.113.27', 'sess', null);

        self::assertSame([$expected, $expected, $expected, $expected, $expected], array_slice($captured, 0, 5), 'every idempotency-key entry point must send the normalized 64-hex value');
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $captured[5], 'record() without a key gets a fresh random id');
    }

    public function testEmergencyLimiterDeniesWithRetryAfter(): void
    {
        $limiter = new ProcessEmergencyCap();
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

    public function testGlobalEmergencyLimiterDeniesWithRetryAfter(): void
    {
        $limiter = new ProcessEmergencyCap(globalPerSecond: 100);
        for ($i = 0; $i < 100; $i++) {
            $limiter->allowGlobal();
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
        self::assertSame(10, $decision->band);
        self::assertSame(0, $store->calls, 'the store must not be touched when the global window is open');
    }

    public function testReassessSkipsEmergencyLimiter(): void
    {
        // Both limiter windows fully exhausted: pre-issue assessment is
        // denied, but a post-solve reassessment must still score.
        $limiter = new ProcessEmergencyCap(globalPerSecond: 1, maxPerSecond: 1);
        for ($i = 0; $i < 100; $i++) {
            $limiter->allow();
            $limiter->allowGlobal();
        }
        $store = new class implements RiskStateStoreInterface {
            public int $calls = 0;

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->calls++;
                return SignalVector::fromArray(['source_fast' => 500]);
            }
        };
        $engine = $this->engine($store, limiter: $limiter);

        $preIssue = $engine->assessPreIssue($this->context());
        self::assertSame(\KiwiCaptcha\Risk\RiskAction::Deny, $preIssue->action);
        self::assertTrue($preIssue->hasReason(RiskReason::HardRateLimit));
        self::assertSame(0, $store->calls, 'pre-issue assessment is gated on the limiter');

        $reassessed = $engine->reassess($this->context());
        self::assertNotSame(\KiwiCaptcha\Risk\RiskAction::Deny, $reassessed->action, 'reassess must never be denied by the emergency caps');
        self::assertFalse($reassessed->hasReason(RiskReason::HardRateLimit));
        self::assertSame(195, $reassessed->score);
        self::assertSame(1, $store->calls, 'reassess must still run the full pipeline against the store');
    }

    public function testAssessIsAliasOfAssessPreIssue(): void
    {
        $limiter = new ProcessEmergencyCap(globalPerSecond: 1, maxPerSecond: 1);
        for ($i = 0; $i < 100; $i++) {
            $limiter->allow();
            $limiter->allowGlobal();
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

        $viaAlias = $engine->assess($this->context());
        $viaNew = $engine->assessPreIssue($this->context());
        self::assertSame(\KiwiCaptcha\Risk\RiskAction::Deny, $viaAlias->action);
        self::assertSame($viaAlias->action, $viaNew->action, 'assess() must behave identically to assessPreIssue()');
        self::assertTrue($viaAlias->hasReason(RiskReason::HardRateLimit));
        self::assertTrue($viaNew->hasReason(RiskReason::HardRateLimit));
        self::assertSame(0, $store->calls, 'the alias must gate on the limiter exactly like assessPreIssue');
    }

    public function testRecordFeedbackSkipsLimiterAndDecision(): void
    {
        $limiter = new ProcessEmergencyCap(globalPerSecond: 1, maxPerSecond: 1);
        $limiter->allow();
        $limiter->allowGlobal();

        $captured = [];
        $store = new class($captured) implements RiskStateStoreInterface {
            public function __construct(private array &$captured)
            {
            }

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->captured[] = $observation;
                return SignalVector::fromArray(['source_fast' => 500]);
            }
        };
        $engine = $this->engine($store, limiter: $limiter);

        $key = str_repeat('cd', 16);
        $receipt = $engine->record_feedback(RiskEventKind::ProtectedActionFailure, $this->context(event: RiskEventKind::ProtectedActionFailure), $key);
        self::assertInstanceOf(EventReceipt::class, $receipt);
        self::assertSame(hash('sha256', "kiwi-risk-event-v1\0" . $key), $receipt->eventId, 'feedback event ids are normalized too');
        self::assertFalse($receipt->isDuplicate);
        self::assertSame(500, $receipt->signals->sourceFast);
        self::assertSame(RiskEventKind::ProtectedActionFailure, $captured[0]->event, 'feedback must not be rewritten to PreIssue');

        // The deprecated alias routes to the same path.
        $receipt = $engine->record(RiskEventKind::ChallengeIssued, 1, '203.0.113.27', 'sess', null);
        self::assertInstanceOf(EventReceipt::class, $receipt);
        self::assertSame(RiskEventKind::ChallengeIssued, $captured[1]->event);
    }

    public function testRecordFeedbackStoreFailureIsSilent(): void
    {
        $store = new class implements RiskStateStoreInterface {
            public function observe(RiskObservation $observation): SignalVector
            {
                throw new RiskStoreException('redis down');
            }
        };
        $engine = $this->engine($store);
        $receipt = $engine->record_feedback(RiskEventKind::ReplayAttempt, $this->context(event: RiskEventKind::ReplayAttempt));
        self::assertFalse($receipt->isDuplicate);
        self::assertSame(SignalVector::zero()->toArray(), $receipt->signals->toArray());
    }

    public function testCalibrationReceiptRegisteredAndConsumed(): void
    {
        $capturedReceipts = [];
        $consumed = [];
        $recorded = [];
        $calibration = new class($capturedReceipts, $consumed, $recorded) implements CalibrationStore {
            public function __construct(
                private array &$capturedReceipts,
                private array &$consumed,
                private array &$recorded,
            ) {
            }

            public function record(int $scope, int $band, RiskAction $action, bool $legitimate): void
            {
                $this->recorded[] = [$scope, $band, $action, $legitimate];
            }

            public function biasForScope(int $scope, int $now): int
            {
                return 0;
            }

            public function recordReceipt(string $decisionId, int $scope, int $band, RiskAction $action): void
            {
                $this->capturedReceipts[] = [$decisionId, $scope, $band, $action];
            }

            public function consumeReceipt(string $decisionId): ?array
            {
                $this->consumed[] = $decisionId;
                return ['scope' => 1, 'band' => 1, 'action' => 'sha16'];
            }
        };

        $store = new class implements RiskStateStoreInterface {
            public function observe(RiskObservation $observation): SignalVector
            {
                return SignalVector::zero();
            }
        };
        $engine = new AdaptiveRiskEngine(
            store: $store,
            classifier: new CidrNetworkClassifier([['cidr' => '203.0.113.0/24', 'flags' => ['hosting']]]),
            identityFactory: new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat(chr(0x42), 32))),
            scorer: new RiskScorer(),
            policy: $this->policy(),
            keys: RiskKeys::fromMaster(str_repeat(chr(0x42), 32)),
            calibration: $calibration,
        );

        $decision = $engine->assess($this->context());
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $decision->decisionId);
        self::assertSame([[$decision->decisionId, 1, $decision->band, $decision->action]], $capturedReceipts);

        // ConfirmedAbuse with the decision id consumes the receipt and
        // records the outcome against the ORIGINAL scope/band/action.
        $engine->record_feedback(
            RiskEventKind::ConfirmedAbuse,
            $this->context(event: RiskEventKind::ConfirmedAbuse),
            null,
            $decision->decisionId,
        );
        self::assertSame([$decision->decisionId], $consumed);
        self::assertSame([[1, 1, RiskAction::Sha16, false]], $recorded);

        // A limiter-hit decision also registers a receipt (silently).
        $limiter = new ProcessEmergencyCap();
        for ($i = 0; $i < 100; $i++) {
            $limiter->allow();
        }
        $engine = new AdaptiveRiskEngine(
            store: $store,
            classifier: new CidrNetworkClassifier([['cidr' => '203.0.113.0/24', 'flags' => ['hosting']]]),
            identityFactory: new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat(chr(0x42), 32))),
            scorer: new RiskScorer(),
            policy: $this->policy(),
            keys: RiskKeys::fromMaster(str_repeat(chr(0x42), 32)),
            limiter: $limiter,
            calibration: $calibration,
        );
        $denied = $engine->assess($this->context());
        self::assertTrue($denied->hasReason(RiskReason::HardRateLimit));
        self::assertSame([[$denied->decisionId, 1, 10, RiskAction::Deny]], array_slice($capturedReceipts, 1));
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
        $engine->confirmedLegitimate(
            $this->context(event: RiskEventKind::ConfirmedLegitimate),
            str_repeat('a', 32),
        );
        $engine->confirmedAbuse(
            $this->context(event: RiskEventKind::ConfirmedAbuse, principalId: 'principal-1'),
            str_repeat('b', 32),
        );
        self::assertSame([
            RiskEventKind::ProtectedActionFailure,
            RiskEventKind::ConfirmedLegitimate,
            RiskEventKind::ConfirmedAbuse,
        ], $captured);
    }

    public function testConfirmedFeedbackRequiresDecisionId(): void
    {
        $store = new class implements RiskStateStoreInterface {
            public function observe(RiskObservation $observation): SignalVector
            {
                return SignalVector::zero();
            }
        };
        $engine = $this->engine($store);
        try {
            $engine->confirmedLegitimate($this->context(event: RiskEventKind::ConfirmedLegitimate), null);
            self::fail('confirmedLegitimate without a decision id must throw');
        } catch (\InvalidArgumentException) {
        }
        try {
            $engine->confirmedAbuse($this->context(event: RiskEventKind::ConfirmedAbuse), '');
            self::fail('confirmedAbuse with an empty decision id must throw');
        } catch (\InvalidArgumentException) {
        }
        self::assertTrue(true);
    }

    public function testEnableGlobalPressureFalseZeroesSignalLevelAndCooldown(): void
    {
        $store = new class implements RiskStateStoreInterface {
            public function observe(RiskObservation $observation): SignalVector
            {
                return SignalVector::fromArray(['global_pressure' => 1000]);
            }

            public function lastGlobalLevel(): int
            {
                return 4;
            }

            public function lastCooldownUntilMs(): int
            {
                return PHP_INT_MAX;
            }
        };

        // Enabled (default): the global level 4 + cooldown fire the deny.
        $enabled = $this->engine($store);
        $d1 = $enabled->assess($this->context());
        self::assertSame(4, $d1->globalLevel);
        self::assertTrue($d1->hasReason(RiskReason::Cooldown));
        self::assertSame(RiskAction::Deny, $d1->action);

        // Disabled: the signal is zeroed, the level and the cooldown are
        // zeroed, so the cooldown-deny branch can never fire.
        $disabled = $this->engine($store, enableGlobalPressure: false);
        $d2 = $disabled->assess($this->context());
        self::assertSame(0, $d2->globalLevel);
        self::assertFalse($d2->hasReason(RiskReason::Cooldown));
        self::assertFalse($d2->hasReason(RiskReason::GlobalAttack));
        self::assertNotSame(RiskAction::Deny, $d2->action);
        $metrics = $disabled->metrics()->snapshot();
        self::assertSame(0, $metrics['gauges']['global:level']);
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
