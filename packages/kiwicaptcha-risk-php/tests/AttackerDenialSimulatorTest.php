<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Marks\MarksEscalation;
use KiwiCaptcha\Risk\Marks\MarksView;
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
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\OutcomeMarksStoreInterface;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use PHPUnit\Framework\TestCase;

/**
 * The credential-stuffing simulator: the done-when of decisive attacker
 * handling (change.md 3.3.3). One victim account; K attacker identities
 * (distinct session dimensions, three groups sharing an ASN bucket)
 * attempt M logins against the victim. Every attacker identity must be
 * denied within N = 3 attempts of its own traffic, while the victim
 * logs in with exactly one step-up and zero lockouts end-to-end.
 *
 * The simulation is deterministic and policy-layer only. Attempt j of an
 * attacker carries the accumulated invalid-proof evidence
 * bad_proof = min(1000, 250 * j) through the real scorer and policy.
 * The outcome plane writes the attacker's abuse marks (session plus ASN
 * bucket) once its evidence corroborates (bad_proof at the corroboration
 * floor, attempt 2). The target-attack state is the reader-side view
 * derived from the target's rolling failure count: the shape the
 * evidence plane's target-failure signal compiles into. A denied
 * attempt never reaches authentication, so it adds no target failure,
 * and the victim's relief needs both the decayed failure window and the
 * reported stepUpCompleted outcome credit. The marks store is
 * in-memory; with the Redis url variable set the identical simulation
 * runs over the real marks surface.
 */
final class AttackerDenialSimulatorTest extends TestCase
{
    private const K = 24;
    private const M = 6;
    /** Documented bound: every attacker identity is denied at attempt 2 or 3. */
    private const N = 3;
    private const GROUPS = 3;
    private const T0 = 1_700_000_000_000;
    private const TARGET_ATTACK_THRESHOLD = 5;
    private const QUIET_WINDOW_MS = 900_000;

    public function testStuffingStormDeniesAttackersAndSavesTheVictim(): void
    {
        $this->runSimulation($this->inMemoryLeg());
    }

    /**
     * The identical simulation against the real Redis marks surface
     * (marks.lua writes and reads).
     */
    public function testStuffingStormOverRealRedisMarks(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if (!is_string($url) || $url === '') {
            self::markTestSkipped('RISK_REDIS_URL not set; start redis with: redis-server --port 6424 --save "" --appendonly no --daemonize yes');
        }
        $client = RedisRiskStateStore::createClient($url);
        $client->ping();
        $namespace = 'stuffing-' . bin2hex(random_bytes(4));
        $store = new RedisRiskStateStore($client, namespace: $namespace);
        try {
            $this->runSimulation(['store' => $store, 'cleanup' => null]);
        } finally {
            $plain = new RedisRiskStateStore($client, namespace: $namespace);
            foreach ($this->markKeysToClean($plain) as $key) {
                $client->del([$key]);
            }
        }
    }

    /**
     * @return array{store: OutcomeMarksStoreInterface&\KiwiCaptcha\Risk\Storage\RiskStateStoreInterface, cleanup: null}
     */
    private function inMemoryLeg(): array
    {
        $store = new class extends RiskStateStoreStub {
            public function observe(RiskObservation $observation): SignalVector
            {
                return SignalVector::zero();
            }
        };

        return ['store' => $store, 'cleanup' => null];
    }

    /**
     * @return list<string> the attacker and victim mark keys of the run
     */
    private function markKeysToClean(OutcomeMarksStoreInterface $store): array
    {
        $keys = [];
        foreach ($this->attackerSessions() as $session) {
            $keys[] = $store->markKey('session', $session);
        }
        foreach ($this->asnBuckets() as $bucket) {
            $keys[] = $store->markKey('asn', $bucket);
        }

        return $keys;
    }

    /** @return list<string> K distinct session pseudonyms */
    private function attackerSessions(): array
    {
        $sessions = [];
        for ($i = 0; $i < self::K; $i++) {
            $sessions[] = sprintf('%032x', $i + 1);
        }

        return $sessions;
    }

    /** @return list<string> one shared ASN bucket id per attacker group */
    private function asnBuckets(): array
    {
        $buckets = [];
        for ($group = 0; $group < self::GROUPS; $group++) {
            $buckets[] = sprintf('a%d', 64496 + $group);
        }

        return $buckets;
    }

    /**
     * The deterministic stuffing storm over one marks store.
     *
     * @param array{store: OutcomeMarksStoreInterface&\KiwiCaptcha\Risk\Storage\RiskStateStoreInterface, cleanup: null} $leg
     */
    private function runSimulation(array $leg): void
    {
        $store = $leg['store'];
        $marks = $leg['store'];
        $weights = new RiskWeights();
        $scorer = new RiskScorer();
        $policy = RiskPolicy::fromConfig([
            'version' => 3,
            'weights' => $weights->toArray(),
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20'],
            ],
            'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
        ]);
        $healthy = new ResourcePressure(1000, 1000);
        $ttl = MarksEscalation::DEFAULT_MARK_TTL_MS;

        // Hex-only 32-char pseudonyms (the handle contract's shape).
        $victimSession = str_repeat('e5', 16);
        $victimPrincipal = str_repeat('f6', 16);
        $victimTarget = str_repeat('d4', 16);
        $sessions = $this->attackerSessions();
        $buckets = $this->asnBuckets();

        $lastFailureAt = 0;
        $stepUpCompleted = false;
        $marked = array_fill(0, self::K, false);
        $deniedAt = [];
        $victimActions = [];

        // The engine owns the target's failure counter: the outcome
        // bridge writes AuthenticationFailure against the target handle,
        // and MarksView::read compiles the attacked-target record from
        // that live state. The test never injects the record.
        $outcomes = new KiwiOutcomes($this->engine($store), $marks);

        // Round-robin attempts: round j runs attacker 0..K-1 in order, so
        // each group's first attacker writes the shared ASN bucket mark
        // before its group-mates attempt in the same round.
        for ($j = 1; $j <= self::M; $j++) {
            for ($i = 0; $i < self::K; $i++) {
                $now = self::T0 + ((($j - 1) * self::K) + $i) * 1000;
                $badProof = min(1000, 250 * $j);
                $signals = new SignalVector(0, 0, 0, 0, $badProof, 0, 0, 0, 0, 0, 0, 0, 0);
                $score = $scorer->score(100, $signals, $weights);
                $plain = $policy->decide(1, $score, $signals, $healthy, 0, $now);
                if ($j === 1) {
                    // The pre-mark floor check: the attacker's own plain
                    // evidence lands it in the Sha16 band, nothing weaker.
                    self::assertSame(RiskAction::Sha16, $plain->action);
                }
                $bucket = $buckets[intdiv($i * self::GROUPS, self::K)];
                $view = MarksView::read($marks, ['session' => $sessions[$i], 'asn' => $bucket], $victimTarget);
                $decision = MarksEscalation::apply($plain, $view, MarksEscalation::corroborated($signals, false), $now, $ttl, $healthy);
                if ($decision->action === RiskAction::Deny) {
                    $deniedAt[$i] ??= $j;
                } else {
                    // The attempt proceeds and fails authentication: the
                    // outcome bridge books the failure into the engine's
                    // target state (the test never counts it by hand).
                    $outcomes->report(
                        Outcome::AuthenticationFailure,
                        OutcomeHandle::target($victimTarget),
                        'attacker-'.$i.'-round-'.$j,
                        $this->victimContext(),
                    );
                    $lastFailureAt = $now;
                }
                if (!$marked[$i] && $badProof >= MarksEscalation::CORROBORATION_FLOOR) {
                    // The outcome plane confirms the abuse: long-memory
                    // marks on the attacker's session and ASN bucket.
                    $marks->writeMark('session', $sessions[$i], 'accountBanned', $now);
                    $marks->writeMark('asn', $bucket, 'accountBanned', $now);
                    $marked[$i] = true;
                }
            }

            if ($j === 2) {
                // The victim logs in while the target is under attack:
                // exactly the interactive step-up, never a lockout.
                $now = self::T0 + (self::K * 2) * 1000;
                $plain = $policy->decide(1, 100, SignalVector::zero(), $healthy, 0, $now);
                $view = MarksView::read($marks, ['session' => $victimSession, 'principal' => $victimPrincipal], $victimTarget);
                $decision = MarksEscalation::apply($plain, $view, false, $now, $ttl, $healthy);
                self::assertSame(RiskAction::StepUp, $decision->action);
                self::assertTrue($decision->hasReason(\KiwiCaptcha\Risk\RiskReason::TargetUnderAttack));
                $victimActions[] = $decision->action;

                // The victim completes the step-up: the outcome credit
                // through the typed outcomes facade over the same store,
                // on the target handle so the engine clears its counter.
                $receipt = $outcomes->report(
                    Outcome::StepUpCompleted,
                    OutcomeHandle::target($victimTarget),
                    'victim-step-up-credit',
                    $this->victimContext(),
                );
                self::assertTrue($receipt->channelBooked);
                self::assertSame(0, $receipt->marksWritten, 'a trust outcome never writes a mark');
                $stepUpCompleted = true;
            }
        }

        // (a) every attacker identity is denied within N attempts, and
        // the deny arrives only after corroborated evidence exists
        // (attempt 2 at the earliest).
        self::assertCount(self::K, $deniedAt, 'every attacker identity reaches a deny');
        $leaders = [];
        foreach ($deniedAt as $i => $attempt) {
            self::assertGreaterThanOrEqual(2, $attempt);
            self::assertLessThanOrEqual(self::N, $attempt);
            if ($attempt === self::N) {
                $leaders[] = $i;
            }
        }
        // Each group's first attacker is denied at attempt 3 (its own
        // marks land after its second attempt); its group-mates ride the
        // shared ASN bucket mark and are denied at attempt 2.
        self::assertSame([0, 8, 16], $leaders);

        // The attack subsides: denied attempts add no target failures, and
        // the victim's completed step-up cleared the engine counter, so a
        // quiet window leaves no attacked-target record at all.
        $quietAt = $lastFailureAt + self::QUIET_WINDOW_MS;
        self::assertGreaterThan(0, $quietAt);
        self::assertTrue($stepUpCompleted, 'the victim completed its step-up before the relief');
        $stateAfter = $marks->readTargetState($victimTarget);
        self::assertSame(0, $stateAfter['fails'], 'the step-up credit cleared the engine failure counter');

        // (b) the victim's next login is the plain allow again: no
        // step-up, no lockout, and exactly one step-up happened overall.
        $plain = $policy->decide(1, 100, SignalVector::zero(), $healthy, 0, $quietAt);
        $view = MarksView::read($marks, ['session' => $victimSession, 'principal' => $victimPrincipal], $victimTarget);
        $decision = MarksEscalation::apply($plain, $view, false, $quietAt, $ttl, $healthy);
        self::assertSame(RiskAction::Allow, $decision->action);
        self::assertFalse($decision->hasReason(\KiwiCaptcha\Risk\RiskReason::TargetUnderAttack));
        $victimActions[] = $decision->action;
        self::assertSame([RiskAction::StepUp, RiskAction::Allow], $victimActions);
        self::assertNotContains(RiskAction::Deny, $victimActions, 'the victim is never locked out');
    }

    private function engine($store): AdaptiveRiskEngine
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
                'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            ]),
            keys: $keys,
        );
    }

    private function victimContext(): RiskContext
    {
        return new RiskContext(
            scope: 1,
            sourceIp: '203.0.113.7',
            sessionId: '00112233445566778899aabbccddeeff',
            principalId: null,
            event: RiskEventKind::PreIssue,
            networkFlags: (new CidrNetworkClassifier([]))->classify('203.0.113.7'),
            resources: new ResourcePressure(1000, 1000),
        );
    }
}
