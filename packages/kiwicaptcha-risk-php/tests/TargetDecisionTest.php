<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Breaker\CircuitBreaker;
use KiwiCaptcha\Risk\FormFieldTargetResolver;
use KiwiCaptcha\Risk\Marks\MarksEscalation;
use KiwiCaptcha\Risk\Marks\MarksReaderInterface;
use KiwiCaptcha\Risk\Marks\StoreMarksReader;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\Outcomes\KiwiOutcomes;
use KiwiCaptcha\Risk\Outcomes\Outcome;
use KiwiCaptcha\Risk\Outcomes\OutcomeHandle;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskReason;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\RiskV2Context;
use KiwiCaptcha\Risk\RiskV2Weights;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\Storage\KeyspaceMode;
use KiwiCaptcha\Risk\Storage\OutcomeRegistration;
use KiwiCaptcha\Risk\Storage\ProcessEmergencyCap;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use KiwiCaptcha\Risk\Storage\RiskStateStoreInterface;
use KiwiCaptcha\Risk\Storage\ShardedRedisRiskStateStore;
use PHPUnit\Framework\TestCase;

/**
 * Target-account protection in the decision path (the H2 done-when).
 *
 * A login assessment that resolves a target through the wired resolver
 * reads the target's failure state and feeds it into scoring as the
 * targetFailurePressure and targetSpread signals. The resolved
 * pseudonym also reaches the marks stage, whose attacked-target rule
 * maps an attacked account to exactly the interactive step-up. Proven
 * over both store layouts (classic and sharded) and the outcome bridge.
 */
final class TargetDecisionTest extends TestCase
{
    private const TARGET_FIELD = ['username' => 'victim@example.com'];

    private function policy(): RiskPolicy
    {
        return RiskPolicy::fromConfig([
            'version' => 3,
            'weights' => (new RiskWeights())->toArray(),
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20'],
            ],
            'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
        ]);
    }

    private function engine(RiskStateStoreInterface $store, ?MarksReaderInterface $reader = null): AdaptiveRiskEngine
    {
        $keys = RiskKeys::fromMaster(str_repeat(chr(0x42), 32));

        return new AdaptiveRiskEngine(
            store: $store,
            classifier: new CidrNetworkClassifier([]),
            identityFactory: new RiskIdentityFactory($keys),
            scorer: new RiskScorer(),
            policy: $this->policy(),
            keys: $keys,
            breaker: new CircuitBreaker(),
            limiter: new ProcessEmergencyCap(),
            targetResolver: new FormFieldTargetResolver([1 => 'username']),
            marksReader: $reader ?? new StoreMarksReader($store),
        );
    }

    private function loginContext(array $targetFields = self::TARGET_FIELD): RiskContext
    {
        return new RiskContext(
            scope: 1,
            sourceIp: '198.51.100.23',
            sessionId: null,
            principalId: null,
            event: RiskEventKind::PreIssue,
            networkFlags: (new CidrNetworkClassifier([]))->classify('198.51.100.23'),
            resources: new ResourcePressure(1000, 1000),
            targetFields: $targetFields,
        );
    }

    private function failureContext(string $ip, array $targetFields = self::TARGET_FIELD): RiskContext
    {
        return new RiskContext(
            scope: 1,
            sourceIp: $ip,
            sessionId: null,
            principalId: null,
            event: RiskEventKind::AuthenticationFailure,
            networkFlags: (new CidrNetworkClassifier([]))->classify($ip),
            resources: new ResourcePressure(1000, 1000),
            targetFields: $targetFields,
        );
    }

    private function redisUrl(): ?string
    {
        $url = getenv('RISK_REDIS_URL');

        return \is_string($url) && $url !== '' ? $url : null;
    }

    private static function observation(RiskEventKind $event, int $n): RiskObservation
    {
        return new RiskObservation(
            event: $event,
            scope: 1,
            sourceEpoch: 1888,
            sourceIdPrev: str_repeat('aa', 15) . '01',
            sourceId: str_repeat('aa', 16),
            sourceIdNext: str_repeat('aa', 15) . '03',
            subnetEpoch: 1888,
            subnetIdPrev: str_repeat('bb', 15) . '01',
            subnetId: str_repeat('bb', 16),
            subnetIdNext: str_repeat('bb', 15) . '03',
            sessionId: null,
            principalId: null,
            eventId: str_pad((string) $n, 32, '0', STR_PAD_LEFT),
            networkRisk: 0,
            nowMs: 1_700_000_000_000,
        );
    }

    /**
     * N accumulated failures against one target escalate the target's
     * next login to the interactive step-up. The failure assessments
     * record the leaky counter through the consolidated target block.
     * The marks stage compiles the attacked-target record from the live
     * state, and rule 3 maps it to exactly StepUp (never a lockout).
     */
    public function testAccumulatedTargetFailuresStepTheNextLoginUp(): void
    {
        $url = $this->redisUrl();
        if ($url === null) {
            self::markTestSkipped('RISK_REDIS_URL not set');
        }
        $namespace = 'tgtfail' . bin2hex(random_bytes(4));
        $store = new RedisRiskStateStore(RedisRiskStateStore::createClient($url), namespace: $namespace);
        $engine = $this->engine($store);

        // The attacker hammers the login form: every attempt is an
        // AuthenticationFailure observation whose assessment records one
        // leaky-bucket failure against the target (fresh event ids).
        for ($i = 0; $i < MarksEscalation::TARGET_ATTACK_THRESHOLD; $i++) {
            $decision = $engine->reassessV2(
                $this->failureContext('203.0.113.' . (10 + $i)),
                new RiskV2Context(),
                'stuffing-attempt-' . $i,
            );
            self::assertNotSame(RiskAction::Deny, $decision->action, "attempt $i must not be denied");
        }

        // The victim's clean login is now the interactive step-up with
        // the target-under-attack reason (never a lockout).
        $decision = $engine->reassessV2($this->loginContext(), new RiskV2Context());
        self::assertSame(RiskAction::StepUp, $decision->action, 'an attacked target steps up');
        self::assertTrue($decision->hasReason(RiskReason::TargetUnderAttack), 'the step-up carries the reason');

        // Cleanup: the target state keys of the run (the legacy family
        // carries the shared namespace tag).
        $client = RedisRiskStateStore::createClient($url);
        $keys = $client->keys('{kiwi:' . $namespace . ':*}');
        if ($keys !== []) {
            $client->del(...$keys);
        }
    }

    /**
     * A target whose failure spray exceeds the spread threshold raises
     * the numeric decision. The outcome bridge stores the failures with
     * their distinct source and asn spread elements, and the next
     * assessment's consolidated reply carries the spread into the score
     * through the existing signal-evaluation path.
     */
    public function testWideTargetSpreadRaisesTheNumericDecision(): void
    {
        $url = $this->redisUrl();
        if ($url === null) {
            self::markTestSkipped('RISK_REDIS_URL not set');
        }
        $namespace = 'tgtspread' . bin2hex(random_bytes(4));
        $store = new RedisRiskStateStore(RedisRiskStateStore::createClient($url), namespace: $namespace);
        $engine = $this->engine($store);
        $outcomes = new KiwiOutcomes($engine, $store);

        // The control login before any failure: the plain base score.
        $control = $engine->reassessV2($this->loginContext(), new RiskV2Context());

        $targetId = $engine->resolveTargetId(1, self::TARGET_FIELD);
        self::assertNotNull($targetId);
        for ($i = 0; $i < 24; $i++) {
            $ip = sprintf('198.51.%d.%d', 10 + intdiv($i, 250), 30 + $i);
            $outcomes->report(
                Outcome::AuthenticationFailure,
                OutcomeHandle::target($targetId),
                'spray-' . $i,
                $this->failureContext($ip),
            );
        }

        // The next login carries the saturated spread signal: strictly
        // above the control score.
        $decision = $engine->reassessV2($this->loginContext(), new RiskV2Context());
        self::assertGreaterThan(
            $control->score,
            $decision->score,
            'the sprayed target must outscore the control',
        );

        // Cleanup: the target state keys of the run (the legacy family
        // carries the shared namespace tag).
        $client = RedisRiskStateStore::createClient($url);
        $keys = $client->keys('{kiwi:' . $namespace . ':*}');
        if ($keys !== []) {
            $client->del(...$keys);
        }
    }

    /**
     * The sharded layout maintains the same target dimension: the read
     * rides the assessment batch, a failure observation writes through
     * the second phase, and the outcome bridge lands on the target
     * family slot through the same routed dispatch.
     */
    public function testShardedStoreMaintainsTheTargetDimension(): void
    {
        $url = $this->redisUrl();
        if ($url === null) {
            self::markTestSkipped('RISK_REDIS_URL not set');
        }
        $namespace = 'tgtsharded' . bin2hex(random_bytes(4));
        $store = new ShardedRedisRiskStateStore([$url], namespace: $namespace);

        $targetId = str_repeat('5e2a', 16);
        $registration = static fn (int $n): OutcomeRegistration => new OutcomeRegistration(
            decisionId: 'sharded-decision-' . $n,
            decisionHour: 1,
            baseRisk: 100,
            globalPressureEnabled: true,
            honeypotHit: false,
            weights: new RiskWeights(),
            v2Weights: new RiskV2Weights(),
            targetId: $targetId,
        );

        // Five failure observations against the target: each assessment
        // records one leaky-bucket failure through the second phase.
        for ($n = 1; $n <= 5; $n++) {
            $reply = $store->assessV2WithReply(
                self::observation(RiskEventKind::AuthenticationFailure, $n),
                null,
                null,
                $registration($n),
            );
            self::assertSame($n, $reply->targetFailures, "failure $n must be recorded by the assessment");
        }

        // A non-failure assessment still reads the live state back.
        $reply = $store->assessV2WithReply(
            self::observation(RiskEventKind::PreIssue, 6),
            null,
            null,
            $registration(6),
        );
        self::assertGreaterThanOrEqual(5, $reply->targetFailures, 'the counter persists');

        // The outcome bridge lands on the same target family through the
        // sharded store's own routed ops.
        $state = $store->registerTargetFailure($targetId, 'source-element', 'asn-element');
        self::assertSame(1, $state['spread_sources']);
        self::assertSame(1, $state['spread_asns']);
        $state = $store->readTargetState($targetId);
        self::assertSame(1, $state['spread_sources']);

        // The state lives on the target family's own tag: the sharded
        // keyspace builder's keys exist.
        $client = RedisRiskStateStore::createClient($url);
        foreach (KeyspaceMode::targetStateKeys($store->namespace(), $targetId, KeyspaceMode::Sharded) as $key) {
            self::assertSame(1, (int) $client->exists($key), "target key $key must exist");
        }

        // Cleanup: the target family keys of the run.
        $prefix = '{kiwi:' . $namespace . ':target:5e}';
        $keys = $client->keys($prefix . '*');
        if ($keys !== []) {
            $client->del(...$keys);
        }
    }
}
