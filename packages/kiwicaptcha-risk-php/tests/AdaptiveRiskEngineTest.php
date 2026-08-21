<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Breaker\CircuitBreaker;
use KiwiCaptcha\Risk\Calibration\AggregateCalibrator;
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
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
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

    /**
     * A deterministic stub calibration store whose confirmOutcome returns
     * the given status (1|2 = first confirmation -> reputation authorized;
     * 0 = already confirmed -> no-op).
     */
    private function staticCalibration(int $confirmStatus): CalibrationStore
    {
        return new class($confirmStatus) implements CalibrationStore {
            public function __construct(private readonly int $confirmStatus)
            {
            }

            public function recordReceipt(string $decisionId, int $scope, int $band, RiskAction $action, int $score, int $sampled, int $decisionHour, float $weight = 1.0): bool
            {
                return true;
            }

            public function sample(): bool
            {
                return true;
            }

            public function confirmOutcome(string $decisionId, bool $legitimate, ?float $weight = null): int
            {
                return $this->confirmStatus;
            }

            public function correctOutcome(string $decisionId, bool $legitimate, ?float $weight = null): bool
            {
                return true;
            }

            public function samplingMetrics(int $scope, int $now): array
            {
                return ['sampledTotal' => 0, 'sampledResolved' => 0, 'resolutionRatio' => 1.0, 'sampledExpired' => 0];
            }

            public function biasForScope(int $scope, int $now): int
            {
                return 0;
            }
        };
    }

    /**
     * The engine's normalization contract: HMAC-SHA256 of the domain-
     * separated message, keyed by the master-derived event key.
     */
    private function expectedEventId(RiskEventKind $event, int $scope, string $key): string
    {
        return hash_hmac(
            'sha256',
            pack('N', $scope) . chr($event->value) . $key,
            RiskKeys::fromMaster(str_repeat(chr(0x42), 32))->event,
        );
    }

    public function testAssessNormalPath(): void
    {
        $store = new class extends RiskStateStoreStub {
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
        $store = new class($captured) extends RiskStateStoreStub {
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
        self::assertSame(600, $observation->networkRisk); // hosting flag
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $observation->eventId);
    }

    public function testAssessNormalizesIdempotencyKey(): void
    {
        $captured = [];
        $store = new class($captured) extends RiskStateStoreStub {
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
        $expected = $this->expectedEventId(RiskEventKind::PreIssue, 1, $key);
        $engine->assess($this->context(), $key);
        self::assertSame([$expected], $captured, 'the caller idempotency key must be normalized (HMAC, event+scope domain separated) before the store');

        $engine->assess($this->context(), $key);
        self::assertSame([$expected, $expected], $captured, 'retries with the same key must normalize identically (dedupe by the Lua)');
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $expected);
        self::assertStringNotContainsString($key, $expected, 'the raw caller key must never appear in the dedupe id');
    }

    public function testNormalizationIsDomainSeparatedByEventAndScope(): void
    {
        $captured = [];
        $store = new class($captured) extends RiskStateStoreStub {
            public function __construct(private array &$captured)
            {
            }

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->captured[] = [$observation->event, $observation->scope, $observation->eventId];
                return SignalVector::zero();
            }
        };
        $engine = $this->engine($store);
        $key = 'shared-raw-key';

        $engine->record_feedback(RiskEventKind::RateLimitHit, $this->context(event: RiskEventKind::RateLimitHit), $key);
        $engine->record_feedback(RiskEventKind::SourceRateLimitHit, $this->context(event: RiskEventKind::SourceRateLimitHit), $key);
        $engine->record_feedback(RiskEventKind::GlobalCapacityHit, $this->context(event: RiskEventKind::GlobalCapacityHit), $key);
        $engine->record_feedback(RiskEventKind::RiskDenied, $this->context(event: RiskEventKind::RiskDenied), $key);
        $engine->record_feedback(RiskEventKind::RateLimitHit, $this->context(scope: 2, event: RiskEventKind::RateLimitHit), $key);

        $ids = array_map(static fn (array $entry): string => $entry[2], $captured);
        self::assertSame([
            $this->expectedEventId(RiskEventKind::RateLimitHit, 1, $key),
            $this->expectedEventId(RiskEventKind::SourceRateLimitHit, 1, $key),
            $this->expectedEventId(RiskEventKind::GlobalCapacityHit, 1, $key),
            $this->expectedEventId(RiskEventKind::RiskDenied, 1, $key),
            $this->expectedEventId(RiskEventKind::RateLimitHit, 2, $key),
        ], $ids, 'the same raw key dedupes independently per event kind and scope');
        self::assertCount(5, array_unique($ids), 'event+scope domain separation must produce distinct ids');
    }

    public function testEmptyIdempotencyKeyBecomesRandom(): void
    {
        $captured = [];
        $store = new class($captured) extends RiskStateStoreStub {
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
        $store = new class extends RiskStateStoreStub {
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
        $store = new class($captured) extends RiskStateStoreStub {
            public function __construct(private array &$captured)
            {
            }

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->captured[] = $observation->eventId;
                return SignalVector::zero();
            }
        };
        // The confirmed* paths gate the reputation event on the calibration
        // status (1|2) — without a store the status is 0 and the event is a
        // no-op, so this idempotency-normalization test runs with a
        // status-1 stub.
        $engine = new AdaptiveRiskEngine(
            store: $store,
            classifier: new CidrNetworkClassifier([['cidr' => '203.0.113.0/24', 'flags' => ['hosting']]]),
            identityFactory: new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat(chr(0x42), 32))),
            scorer: new RiskScorer(),
            policy: $this->policy(),
            keys: RiskKeys::fromMaster(str_repeat(chr(0x42), 32)),
            calibration: $this->staticCalibration(1),
        );
        $key = 'shared-idempotency-key';
        $preIssue = $this->expectedEventId(RiskEventKind::PreIssue, 1, $key);

        $engine->assessPreIssue($this->context(), $key);
        $engine->reassess($this->context(), $key);
        $engine->record_feedback(RiskEventKind::RateLimitHit, $this->context(event: RiskEventKind::RateLimitHit), $key);
        $engine->confirmedLegitimate($this->context(event: RiskEventKind::ConfirmedLegitimate), str_repeat('a', 32), $key);
        $engine->confirmedAbuse($this->context(event: RiskEventKind::ConfirmedAbuse), str_repeat('b', 32), $key);
        $engine->record(RiskEventKind::ExpiredChallenge, 1, '203.0.113.27', 'sess', null);

        self::assertSame([
            $preIssue,
            $preIssue, // same event+scope retry dedupes identically
            $this->expectedEventId(RiskEventKind::RateLimitHit, 1, $key),
            $this->expectedEventId(RiskEventKind::ConfirmedLegitimate, 1, $key),
            $this->expectedEventId(RiskEventKind::ConfirmedAbuse, 1, $key),
        ], array_slice($captured, 0, 5), 'every idempotency-key entry point must send the normalized 64-hex value');
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $captured[5], 'record() without a key gets a fresh random id');
    }

    public function testEmergencyLimiterDeniesWithRetryAfter(): void
    {
        $limiter = new ProcessEmergencyCap(processPerSecond: 100, warmupRampSecs: 0);
        for ($i = 0; $i < 100; $i++) {
            $limiter->allow();
        }
        $store = new class extends RiskStateStoreStub {
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

    public function testCustomProcessCapDeniesWithRetryAfter(): void
    {
        $limiter = new ProcessEmergencyCap(processPerSecond: 1);
        self::assertTrue($limiter->allow(), 'the single allowance is consumed by the cap');
        $store = new class extends RiskStateStoreStub {
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
        self::assertSame(0, $store->calls, 'the store must not be touched when the process window is open');
    }

    public function testReassessSkipsEmergencyLimiter(): void
    {
        // The single process window fully exhausted: pre-issue assessment
        // is denied, but a post-solve reassessment must still score.
        $limiter = new ProcessEmergencyCap(processPerSecond: 1);
        $limiter->allow();
        $store = new class extends RiskStateStoreStub {
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
        self::assertNotSame(\KiwiCaptcha\Risk\RiskAction::Deny, $reassessed->action, 'reassess must never be denied by the emergency cap');
        self::assertFalse($reassessed->hasReason(RiskReason::HardRateLimit));
        self::assertSame(195, $reassessed->score);
        self::assertSame(1, $store->calls, 'reassess must still run the full pipeline against the store');
    }

    /**
     * Engine-level wiring: the engine passes its per-process
     * scope-action hysteresis map into the policy, so an oscillating
     * boundary score (449/451/449…) yields a stable action instead of a
     * flip-flopping challenge profile.
     */
    public function testScopeActionHysteresisStabilizesBoundaryScore(): void
    {
        $store = new class extends RiskStateStoreStub {
            public int $calls = 0;

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->calls++;
                // source_fast 900 + bad_proof 810/819 -> scores 449/451:
                // the 450 edge of the Sha18/Sha20 bands (both signals stay
                // below the hard-deny thresholds).
                return SignalVector::fromArray([
                    'source_fast' => 900,
                    'bad_proof' => $this->calls % 2 === 1 ? 810 : 819,
                ]);
            }
        };
        $engine = $this->engine($store);
        for ($i = 0; $i < 8; $i++) {
            $decision = $engine->assess($this->context());
            self::assertSame(
                \KiwiCaptcha\Risk\RiskAction::Sha18,
                $decision->action,
                sprintf('iteration %d: the oscillating boundary score must not flip the profile', $i)
            );
        }
    }

    public function testAssessIsAliasOfAssessPreIssue(): void
    {
        $limiter = new ProcessEmergencyCap(processPerSecond: 1);
        $limiter->allow();
        $store = new class extends RiskStateStoreStub {
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
        $limiter = new ProcessEmergencyCap(processPerSecond: 1);
        $limiter->allow();

        $captured = [];
        $store = new class($captured) extends RiskStateStoreStub {
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
        self::assertSame($this->expectedEventId(RiskEventKind::ProtectedActionFailure, 1, $key), $receipt->eventId, 'feedback event ids are normalized too');
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
        $store = new class extends RiskStateStoreStub {
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

    public function testCalibrationReceiptRegisteredWithScoreAndSampled(): void
    {
        $capturedReceipts = [];
        $confirmed = [];
        $observedEvents = [];
        $calibration = new class($capturedReceipts, $confirmed) implements CalibrationStore {
            public function __construct(
                private array &$capturedReceipts,
                private array &$confirmed,
            ) {
            }

            public function recordReceipt(string $decisionId, int $scope, int $band, RiskAction $action, int $score, int $sampled, int $decisionHour, float $weight = 1.0): bool
            {
                $this->capturedReceipts[] = [$decisionId, $scope, $band, $action, $score, $sampled, $decisionHour];
                return true;
            }

            public function sample(): bool
            {
                return true;
            }

            public function confirmOutcome(string $decisionId, bool $legitimate, ?float $weight = null): int
            {
                $this->confirmed[] = [$decisionId, $legitimate, $weight];
                return 1;
            }

            public function correctOutcome(string $decisionId, bool $legitimate, ?float $weight = null): bool
            {
                return true;
            }

            public function samplingMetrics(int $scope, int $now): array
            {
                return ['sampledTotal' => 0, 'sampledResolved' => 0, 'resolutionRatio' => 1.0, 'sampledExpired' => 0];
            }

            public function biasForScope(int $scope, int $now): int
            {
                return 0;
            }
        };

        $store = new class($observedEvents) extends RiskStateStoreStub {
            public function __construct(private array &$observedEvents)
            {
            }

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->observedEvents[] = $observation->event;
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
        $hour = intdiv((int) floor(microtime(true) * 1000), 3_600_000);
        self::assertSame(
            [[$decision->decisionId, 1, $decision->band, $decision->action, $decision->score, 1, $hour]],
            $capturedReceipts,
            'the receipt must carry the EXACT score, the assessment-time sampling flag and the decision hour'
        );

        // confirmedAbuse: the calibrator's atomic confirm runs first
        // (receipt consumed exactly once), then the reputation event.
        $engine->confirmedAbuse($this->context(event: RiskEventKind::ConfirmedAbuse), $decision->decisionId);
        self::assertSame([[$decision->decisionId, false, null]], $confirmed, 'the atomic confirm must run first (legitimate=false)');
        self::assertSame([RiskEventKind::PreIssue, RiskEventKind::ConfirmedAbuse], $observedEvents, 'the reputation event must still be recorded');

        // A limiter-hit decision also registers a receipt (silently).
        $limiter = new ProcessEmergencyCap(processPerSecond: 100, warmupRampSecs: 0);
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
        self::assertSame([[$denied->decisionId, 1, 10, RiskAction::Deny, 1000, 1, $hour]], array_slice($capturedReceipts, 1));
    }

    public function testConfirmedFeedbackGatesReputationOnStatus(): void
    {
        // The reputation event is booked only on a first confirmation
        // (status 1 or 2). Status 0 (already confirmed / missing / backend
        // failure) returns a duplicate-marked receipt with zero signals
        // and no observation, so a webhook retry cannot amplify a
        // ConfirmedAbuse.
        $run = function (int $status): array {
            $confirmed = [];
            $observedEvents = [];
            $calibration = new class($confirmed, $status) implements CalibrationStore {
                public function __construct(
                    private array &$confirmed,
                    private readonly int $status,
                ) {
                }

                public function recordReceipt(string $decisionId, int $scope, int $band, RiskAction $action, int $score, int $sampled, int $decisionHour, float $weight = 1.0): bool
                {
                    return true;
                }

                public function sample(): bool
                {
                    return true;
                }

                public function confirmOutcome(string $decisionId, bool $legitimate, ?float $weight = null): int
                {
                    $this->confirmed[] = [$decisionId, $legitimate, $weight];
                    return $this->status;
                }

                public function correctOutcome(string $decisionId, bool $legitimate, ?float $weight = null): bool
                {
                    return true;
                }

                public function samplingMetrics(int $scope, int $now): array
                {
                    return ['sampledTotal' => 0, 'sampledResolved' => 0, 'resolutionRatio' => 1.0, 'sampledExpired' => 0];
                }

                public function biasForScope(int $scope, int $now): int
                {
                    return 0;
                }
            };

            $store = new class($observedEvents) extends RiskStateStoreStub {
                public function __construct(private array &$observedEvents)
                {
                }

                public function observe(RiskObservation $observation): SignalVector
                {
                    $this->observedEvents[] = $observation->event;
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

            $decisionId = str_repeat('a', 32);
            $receipt = $engine->confirmedLegitimate($this->context(event: RiskEventKind::ConfirmedLegitimate), $decisionId);
            return [$confirmed, $observedEvents, $receipt];
        };

        // Status 0 (already consumed / missing): the atomic confirm still
        // runs, but NO reputation event is booked.
        [$confirmed, $observedEvents, $receipt] = $run(0);
        self::assertSame([[$confirmed[0][0], true, null]], $confirmed, 'the atomic confirm must still run');
        self::assertSame([], $observedEvents, 'status 0 must NOT record the reputation event');
        self::assertTrue($receipt->isDuplicate, 'a status-0 confirmation returns a duplicate-marked receipt');
        self::assertSame(SignalVector::zero()->toArray(), $receipt->signals->toArray(), 'the no-op receipt carries zero signals');

        // Status 1 (first confirmation recorded): the reputation event follows.
        [, $observedEvents, $receipt] = $run(1);
        self::assertSame([RiskEventKind::ConfirmedLegitimate], $observedEvents, 'status 1 authorizes the reputation event');
        self::assertFalse($receipt->isDuplicate);

        // Status 2 (first confirmation, deliberately unsampled): the
        // reputation event is still authorized exactly once.
        [, $observedEvents, $receipt] = $run(2);
        self::assertSame([RiskEventKind::ConfirmedLegitimate], $observedEvents, 'status 2 (unsampled) still authorizes the reputation event once');
        self::assertFalse($receipt->isDuplicate);
    }

    public function testConfirmOutcomeDelegatesStatus(): void
    {
        $confirmed = [];
        $calibration = new class($confirmed) implements CalibrationStore {
            public function __construct(private array &$confirmed)
            {
            }

            public function recordReceipt(string $decisionId, int $scope, int $band, RiskAction $action, int $score, int $sampled, int $decisionHour, float $weight = 1.0): bool
            {
                return true;
            }

            public function sample(): bool
            {
                return true;
            }

            public function confirmOutcome(string $decisionId, bool $legitimate, ?float $weight = null): int
            {
                $this->confirmed[] = [$decisionId, $legitimate, $weight];
                return 2;
            }

            public function correctOutcome(string $decisionId, bool $legitimate, ?float $weight = null): bool
            {
                return true;
            }

            public function samplingMetrics(int $scope, int $now): array
            {
                return ['sampledTotal' => 0, 'sampledResolved' => 0, 'resolutionRatio' => 1.0, 'sampledExpired' => 0];
            }

            public function biasForScope(int $scope, int $now): int
            {
                return 0;
            }
        };
        $store = new class extends RiskStateStoreStub {
            public function observe(RiskObservation $observation): SignalVector
            {
                return SignalVector::zero();
            }
        };
        $engine = new AdaptiveRiskEngine(
            store: $store,
            classifier: new CidrNetworkClassifier([]),
            identityFactory: new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat(chr(0x42), 32))),
            scorer: new RiskScorer(),
            policy: $this->policy(),
            keys: RiskKeys::fromMaster(str_repeat(chr(0x42), 32)),
            calibration: $calibration,
        );
        self::assertSame(2, $engine->confirmOutcome('dec-1', true, 4.0), 'confirmOutcome passes the calibrator status through');
        self::assertSame([['dec-1', true, 4.0]], $confirmed);
        self::assertSame(1, $this->engine($store)->confirmOutcome('dec-2', false), 'without a calibration store the OUTCOME LEDGER still confirms (store->confirmOutcome)');
        self::assertSame(['confirm', 'dec-2', false], $store->ledgerCalls[0], 'the store ledger CAS must run for the calibration-less confirmation');
    }

    /**
     * The outcome ledger is always on and independent of calibration:
     * ConfirmedLegitimate/ConfirmedAbuse behave identically with
     * calibration disabled. Every decision registers a pending ledger
     * entry at assessment time (store->registerOutcome without
     * calibration). The first confirmation flips the ledger exactly once
     * (status 1) and records the reputation event; a retry finds the
     * ledger already confirmed (status 0) and is a duplicate-marked
     * no-op.
     */
    public function testConfirmedWorksWithoutCalibration(): void
    {
        $observedEvents = [];
        $confirmedLedger = [];
        $store = new class($observedEvents, $confirmedLedger) extends RiskStateStoreStub {
            public function __construct(
                private array &$observedEvents,
                private array &$confirmedLedger,
            ) {
            }

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->observedEvents[] = $observation->event;
                return SignalVector::zero();
            }

            public function confirmOutcome(string $decisionId, bool $legitimate): int
            {
                $this->ledgerCalls[] = ['confirm', $decisionId, $legitimate];
                if (isset($this->confirmedLedger[$decisionId])) {
                    return 0;
                }
                $this->confirmedLedger[$decisionId] = true;
                return 1;
            }
        };
        $engine = $this->engine($store);

        // Assessment registers the pending ledger entry in the store.
        $decision = $engine->assess($this->context());
        $hour = intdiv((int) floor(microtime(true) * 1000), 3_600_000);
        self::assertSame(
            ['register', $decision->decisionId, 1, $hour, $decision->score],
            $store->ledgerCalls[0],
            'without calibration the decision still registers its PENDING ledger entry (scope + decision hour + score)'
        );

        // First confirmation: the ledger CAS flips once and the reputation
        // event is recorded, identical to the calibration-enabled path.
        $receipt = $engine->confirmedAbuse($this->context(event: RiskEventKind::ConfirmedAbuse), $decision->decisionId);
        self::assertFalse($receipt->isDuplicate, 'the FIRST confirmation records the reputation event without calibration');
        self::assertSame(['confirm', $decision->decisionId, false], $store->ledgerCalls[1], 'the store ledger CAS runs first');
        self::assertSame([RiskEventKind::PreIssue, RiskEventKind::ConfirmedAbuse], $observedEvents);

        // A retry finds the ledger already confirmed (status 0) and is a
        // duplicate-marked no-op, so webhook retries cannot amplify.
        $retry = $engine->confirmedAbuse($this->context(event: RiskEventKind::ConfirmedAbuse), $decision->decisionId);
        self::assertTrue($retry->isDuplicate, 'a retried confirmation is marked duplicate (ledger already confirmed)');
        self::assertSame(SignalVector::zero()->toArray(), $retry->signals->toArray());
        self::assertCount(2, $observedEvents, 'a retry must never record a second reputation event');

        // confirmedLegitimate works identically in the other direction.
        $second = $engine->assess($this->context());
        $legit = $engine->confirmedLegitimate($this->context(event: RiskEventKind::ConfirmedLegitimate), $second->decisionId);
        self::assertFalse($legit->isDuplicate);
        self::assertSame(RiskEventKind::ConfirmedLegitimate, $observedEvents[3], 'the second decision confirms legitimately too');
        self::assertSame([
            RiskEventKind::PreIssue,
            RiskEventKind::ConfirmedAbuse,
            RiskEventKind::PreIssue,
            RiskEventKind::ConfirmedLegitimate,
        ], $observedEvents);
        self::assertCount(5, $store->ledgerCalls, '2 registers + 3 confirms (first, retry, second decision)');
    }

    public function testRecordFeedbackRejectsConfirmationEvents(): void
    {
        $observedEvents = [];
        $store = new class($observedEvents) extends RiskStateStoreStub {
            public function __construct(private array &$observedEvents)
            {
            }

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->observedEvents[] = $observation->event;
                return SignalVector::zero();
            }
        };
        $engine = $this->engine($store);

        try {
            $engine->record_feedback(RiskEventKind::ConfirmedLegitimate, $this->context(event: RiskEventKind::ConfirmedLegitimate));
            self::fail('record_feedback must reject ConfirmedLegitimate');
        } catch (\LogicException $e) {
            self::assertStringContainsString('confirmOutcome/confirmed*', $e->getMessage());
        }
        try {
            $engine->record(RiskEventKind::ConfirmedAbuse, 1, '203.0.113.27');
            self::fail('record() must reject ConfirmedAbuse');
        } catch (\LogicException) {
        }
        self::assertSame([], $observedEvents, 'a rejected confirmation must never reach the store');
    }

    public function testConfirmCorrectionFlipsTheLedgerWithoutReputationEvents(): void
    {
        $corrected = [];
        $calibration = new class($corrected) implements CalibrationStore {
            public function __construct(private array &$corrected)
            {
            }

            public function recordReceipt(string $decisionId, int $scope, int $band, RiskAction $action, int $score, int $sampled, int $decisionHour, float $weight = 1.0): bool
            {
                return true;
            }

            public function sample(): bool
            {
                return true;
            }

            public function confirmOutcome(string $decisionId, bool $legitimate, ?float $weight = null): int
            {
                return 1;
            }

            public function correctOutcome(string $decisionId, bool $legitimate, ?float $weight = null): bool
            {
                if (in_array([$decisionId, $legitimate], $this->corrected, true)) {
                    return false;
                }
                $this->corrected[] = [$decisionId, $legitimate];
                return true;
            }

            public function samplingMetrics(int $scope, int $now): array
            {
                return ['sampledTotal' => 0, 'sampledResolved' => 0, 'resolutionRatio' => 1.0, 'sampledExpired' => 0];
            }

            public function biasForScope(int $scope, int $now): int
            {
                return 0;
            }
        };

        $store = new class extends RiskStateStoreStub {
            public array $observedEvents = [];

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->observedEvents[] = $observation->event;
                return SignalVector::zero();
            }
        };
        $engine = new AdaptiveRiskEngine(
            store: $store,
            classifier: new CidrNetworkClassifier([]),
            identityFactory: new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat(chr(0x42), 32))),
            scorer: new RiskScorer(),
            policy: $this->policy(),
            keys: RiskKeys::fromMaster(str_repeat(chr(0x42), 32)),
            calibration: $calibration,
        );

        // With calibration: the correction goes to the calibrator's
        // correction.lua (ledger flip + bucket reversal) — NO synthetic
        // identity event is recorded anywhere.
        self::assertTrue($engine->confirmCorrection('decision-c', true), 'the calibrator correction applies');
        self::assertSame([['decision-c', true]], $corrected, 'the calibrator receives the new outcome');
        self::assertSame([], $store->observedEvents, 'the correction must NOT record a synthetic reputation event');

        // Already carrying the target outcome -> the calibrator refuses.
        self::assertFalse($engine->confirmCorrection('decision-c', true));
        self::assertCount(1, $corrected);

        // The opposite direction (abuse -> legitimate) applies.
        self::assertTrue($engine->confirmCorrection('decision-d', false));
        self::assertSame([['decision-c', true], ['decision-d', false]], $corrected);

        // Without a calibration store the correction runs the store's
        // outcome_correct.lua (the ledger flip is the always-on authority).
        $plainStore = new class extends RiskStateStoreStub {
            public function observe(RiskObservation $observation): SignalVector
            {
                return SignalVector::zero();
            }
        };
        $plain = $this->engine($plainStore);
        self::assertTrue($plain->confirmCorrection('decision-e', true), 'without calibration the STORE ledger flips');
        self::assertSame(['correct', 'decision-e', true], $plainStore->ledgerCalls[0], 'the store correction must run for the calibration-less path');

        // Empty decision id is rejected up front.
        $this->expectException(\InvalidArgumentException::class);
        $engine->confirmCorrection('', true);
    }

    public function testStoreFailureDegradesAndOpensBreaker(): void
    {
        $store = new class extends RiskStateStoreStub {
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
        $store = new class extends RiskStateStoreStub {
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
        $store = new class($captured) extends RiskStateStoreStub {
            public function __construct(private array &$captured)
            {
            }

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->captured[] = $observation->event;
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
            calibration: $this->staticCalibration(1),
        );
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
        $store = new class extends RiskStateStoreStub {
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
        $store = new class extends RiskStateStoreStub {
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
        $store = new class extends RiskStateStoreStub {
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

    /**
     * End-to-end reputation gating against real Redis, skipped when no
     * Redis URL is configured. The first confirmation (status 1) records
     * the reputation event into the source state; a retry (status 0)
     * returns the duplicate-marked receipt and leaves the state
     * untouched, so a webhook retry cannot amplify ConfirmedAbuse (+5000
     * bad). A deliberately unsampled first confirmation (status 2) still
     * mutates reputation exactly once.
     */
    public function testReputationGatingIsOncePerDecisionWithRedis(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if (!is_string($url) || $url === '') {
            self::markTestSkipped('RISK_REDIS_URL not set; start redis with: docker run -d -p 6399:6379 redis:7-alpine');
        }
        $client = RedisRiskStateStore::createClient($url);
        $keys = RiskKeys::fromMaster(str_repeat(chr(0x42), 32));
        $identityFactory = new RiskIdentityFactory($keys);
        $classifier = new CidrNetworkClassifier([['cidr' => '203.0.113.0/24', 'flags' => ['hosting']]]);
        $ns = 'gt' . bin2hex(random_bytes(4));
        $store = new RedisRiskStateStore($client, namespace: $ns);
        $calibrator = new AggregateCalibrator($client, namespace: $ns, minSamples: 10, samplingMode: 'complete');
        $engine = new AdaptiveRiskEngine(
            store: $store,
            classifier: $classifier,
            identityFactory: $identityFactory,
            scorer: new RiskScorer(),
            policy: $this->policy(),
            keys: $keys,
            calibration: $calibrator,
        );

        // Assess registers the calibration receipt for the decision.
        $decision = $engine->assess($this->context());
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $decision->decisionId);

        $ctx = $this->context(event: RiskEventKind::ConfirmedAbuse);
        $nowSecs = intdiv((int) floor(microtime(true) * 1000), 1000);
        $epoch = intdiv($nowSecs, 900);
        $sourceKey = "{kiwi:{$ns}}:risk:src:{$epoch}:" . $identityFactory->sourceIdForEpoch($ctx, $epoch);

        $badBefore = (int) ($client->hget($sourceKey, 'bad') ?? 0);
        $first = $engine->confirmedAbuse($ctx, $decision->decisionId);
        self::assertFalse($first->isDuplicate, 'the FIRST confirmation records the reputation event');
        $badAfter = (int) ($client->hget($sourceKey, 'bad') ?? 0);
        self::assertGreaterThanOrEqual($badBefore + 5000, $badAfter, 'ConfirmedAbuse must add bad +5000 to the source state');

        // Retry of the same decision: status 0 -> duplicate-marked no-op,
        // no second reputation event.
        $retry = $engine->confirmedAbuse($ctx, $decision->decisionId);
        self::assertTrue($retry->isDuplicate, 'a retried confirmation is marked duplicate (status 0)');
        self::assertSame(SignalVector::zero()->toArray(), $retry->signals->toArray(), 'the retry receipt carries zero signals');
        self::assertSame($badAfter, (int) ($client->hget($sourceKey, 'bad') ?? 0), 'a retry must never amplify ConfirmedAbuse');

        // A deliberately unsampled first confirmation (status 2) still
        // mutates reputation exactly once (and never calibrates).
        $ns2 = 'gt2' . bin2hex(random_bytes(4));
        $store2 = new RedisRiskStateStore($client, namespace: $ns2);
        $calibrator2 = new AggregateCalibrator($client, namespace: $ns2, minSamples: 10, samplingMode: 'random_sample', samplingProbabilityPpm: 1_000_000);
        $engine2 = new AdaptiveRiskEngine(
            store: $store2,
            classifier: $classifier,
            identityFactory: $identityFactory,
            scorer: new RiskScorer(),
            policy: $this->policy(),
            keys: $keys,
            calibration: $calibrator2,
        );
        $calibrator2->recordReceipt('unsampled-dec', 1, 0, RiskAction::Allow, 100, 0, intdiv((int) floor(microtime(true) * 1000), 3_600_000));
        $sourceKey2 = "{kiwi:{$ns2}}:risk:src:{$epoch}:" . $identityFactory->sourceIdForEpoch($ctx, $epoch);
        $bad2 = (int) ($client->hget($sourceKey2, 'bad') ?? 0);
        $first2 = $engine2->confirmedAbuse($ctx, 'unsampled-dec');
        self::assertFalse($first2->isDuplicate, 'status 2 (unsampled) still authorizes the reputation event');
        self::assertGreaterThanOrEqual($bad2 + 5000, (int) ($client->hget($sourceKey2, 'bad') ?? 0), 'the unsampled first confirmation mutates reputation once');
        $retry2 = $engine2->confirmedAbuse($ctx, 'unsampled-dec');
        self::assertTrue($retry2->isDuplicate, 'a retried unsampled confirmation is a no-op');
        $badAfter2 = (int) ($client->hget($sourceKey2, 'bad') ?? 0);
        self::assertSame($badAfter2, (int) ($client->hget($sourceKey2, 'bad') ?? 0), 'no second reputation mutation');
        $hour = intdiv((int) floor(microtime(true) * 1000), 3_600_000);
        self::assertSame([], $client->hgetall("{kiwi:{$ns2}}:cal:1:{$hour}"), 'a status-2 outcome never reaches the calibration buckets');
    }
}
