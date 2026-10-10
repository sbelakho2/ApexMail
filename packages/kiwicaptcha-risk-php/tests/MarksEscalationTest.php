<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Marks\MarksEscalation;
use KiwiCaptcha\Risk\Marks\MarksView;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
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
use KiwiCaptcha\Risk\SignalVector;
use PHPUnit\Framework\TestCase;

/**
 * The decisive attacker stage in isolation: the three rules of the
 * marks plane, the victim-protection and marked-identity properties,
 * plus the engine wiring. The stage runs on assessPreIssue only when a
 * marks reader is attached; an unwired engine keeps the plain decision.
 */
final class MarksEscalationTest extends TestCase
{
    private const T0 = 1_700_000_000_000;
    private const TTL = 7_776_000_000;
    private const SESSION = 'c7b3e1f9a5d24708b6e0c8a2f4d69123';

    private function policy(): RiskPolicy
    {
        return RiskPolicy::fromConfig([
            'version' => 3,
            'weights' => (new \KiwiCaptcha\Risk\RiskWeights())->toArray(),
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20'],
            ],
            'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
        ]);
    }

    private function healthy(): ResourcePressure
    {
        return new ResourcePressure(1000, 1000);
    }

    private function plain(int $score): \KiwiCaptcha\Risk\RiskDecision
    {
        return $this->policy()->decide(1, $score, SignalVector::zero(), $this->healthy(), 0, self::T0);
    }

    /** @return array{kind: string, count: int, first_ms: int, last_ms: int} */
    private function mark(int $lastMs): array
    {
        return ['kind' => 'accountBanned', 'count' => 1, 'first_ms' => $lastMs, 'last_ms' => $lastMs];
    }

    private function sessionView(int $lastMs): MarksView
    {
        return MarksView::fromParts(['session' => $this->mark($lastMs)], null);
    }

    private function targetView(): MarksView
    {
        return MarksView::fromParts([], $this->mark((int) self::T0));
    }

    public function testUnmarkedViewKeepsThePlainDecision(): void
    {
        $plain = $this->plain(500);
        $out = MarksEscalation::apply($plain, MarksView::empty(), true, self::T0, self::TTL, $this->healthy());
        self::assertSame(RiskAction::Sha20, $out->action);
        self::assertSame($plain->reasons, $out->reasons);
        self::assertNull($out->retryAfterMs);
    }

    public function testMarkedIdentityEscalatesToTheMaximumRung(): void
    {
        foreach ([0, 100, 500, 700] as $score) {
            $out = MarksEscalation::apply($this->plain($score), $this->sessionView((int) self::T0), false, self::T0, self::TTL, $this->healthy());
            self::assertSame(RiskAction::Argon64, $out->action, "score {$score}");
            self::assertTrue($out->hasReason(RiskReason::MarkedIdentity));
            self::assertNull($out->retryAfterMs);
        }
    }

    public function testMarkedIdentityNeverDowngradesStepUpOrDeny(): void
    {
        $step = MarksEscalation::apply($this->plain(950), $this->sessionView((int) self::T0), false, self::T0, self::TTL, $this->healthy());
        self::assertSame(RiskAction::StepUp, $step->action);
        $deny = MarksEscalation::apply($this->plain(980), $this->sessionView((int) self::T0), false, self::T0, self::TTL, $this->healthy());
        self::assertSame(RiskAction::Deny, $deny->action);
        self::assertTrue($deny->hasReason(RiskReason::MarkedIdentity));
    }

    public function testMarkedIdentityRespectsArgonCapacity(): void
    {
        $saturated = new ResourcePressure(299, 1000);
        $out = MarksEscalation::apply($this->plain(100), $this->sessionView((int) self::T0), false, self::T0, self::TTL, $saturated);
        self::assertSame(RiskAction::StepUp, $out->action);
        self::assertTrue($out->hasReason(RiskReason::MarkedIdentity));
        self::assertTrue($out->hasReason(RiskReason::CapacityPressure));
    }

    public function testCorroboratedMarkDeniesForTheRemainingTtl(): void
    {
        $signals = new SignalVector(0, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 0, 0);
        $base = $this->policy()->decide(1, 100, $signals, $this->healthy(), 0, self::T0);
        $out = MarksEscalation::apply($base, $this->sessionView((int) self::T0), true, self::T0 + 1000, self::TTL, $this->healthy());
        self::assertSame(RiskAction::Deny, $out->action);
        self::assertTrue($out->hasReason(RiskReason::CorroboratedAbuse));
        // 90 days minus one second exceeds the u32 wire field: saturated.
        self::assertSame(4294967295, $out->retryAfterMs);

        // A near-expired mark leaves a short, exact retry hint.
        $now = self::T0 + self::TTL - 5000;
        $out = MarksEscalation::apply($this->plain(100), $this->sessionView((int) self::T0), true, $now, self::TTL, $this->healthy());
        self::assertSame(RiskAction::Deny, $out->action);
        self::assertSame(5000, $out->retryAfterMs);
    }

    public function testCorroboratedEvidenceWithoutAMarkStaysPlain(): void
    {
        $signals = new SignalVector(0, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 0, 0);
        $base = $this->policy()->decide(1, 100, $signals, $this->healthy(), 0, self::T0);
        $out = MarksEscalation::apply($base, MarksView::empty(), true, self::T0, self::TTL, $this->healthy());
        self::assertSame($base->action, $out->action);
        self::assertFalse($out->hasReason(RiskReason::CorroboratedAbuse));
    }

    public function testExpiredOrCorruptMarkIsInert(): void
    {
        $now = self::T0 + self::TTL;
        $out = MarksEscalation::apply($this->plain(500), $this->sessionView((int) self::T0), true, $now, self::TTL, $this->healthy());
        self::assertSame(RiskAction::Sha20, $out->action);
        self::assertFalse($out->hasReason(RiskReason::MarkedIdentity));
        // A corrupt negative timestamp never reads as a live mark.
        $corrupt = MarksEscalation::apply($this->plain(500), $this->sessionView(-1), true, $now, self::TTL, $this->healthy());
        self::assertSame(RiskAction::Sha20, $corrupt->action);
    }

    public function testAttackedTargetMapsAClaimantToStepUpOnly(): void
    {
        $out = MarksEscalation::apply($this->plain(100), $this->targetView(), false, self::T0, self::TTL, $this->healthy());
        self::assertSame(RiskAction::StepUp, $out->action);
        self::assertTrue($out->hasReason(RiskReason::TargetUnderAttack));
        // Even a plain Argon64 band tops out at StepUp for the victim.
        $out = MarksEscalation::apply($this->plain(700), $this->targetView(), false, self::T0, self::TTL, $this->healthy());
        self::assertSame(RiskAction::StepUp, $out->action);
        // A different claimant presents no target: the plain action stands.
        $out = MarksEscalation::apply($this->plain(100), MarksView::empty(), false, self::T0, self::TTL, $this->healthy());
        self::assertSame(RiskAction::Allow, $out->action);
    }

    public function testOwnMarkDenyWinsOverTheTargetStepUp(): void
    {
        $view = MarksView::fromParts(
            ['session' => $this->mark((int) self::T0)],
            $this->mark((int) self::T0),
        );
        $out = MarksEscalation::apply($this->plain(100), $view, true, self::T0, self::TTL, $this->healthy());
        self::assertSame(RiskAction::Deny, $out->action);
        self::assertTrue($out->hasReason(RiskReason::CorroboratedAbuse));
        self::assertTrue($out->hasReason(RiskReason::TargetUnderAttack));
    }

    public function testFreshestMarkBacksTheDenyWindow(): void
    {
        $view = MarksView::fromParts(
            [
                'session' => $this->mark((int) self::T0),
                'asn' => ['kind' => 'accountBanned', 'count' => 1, 'first_ms' => self::T0 + 60_000, 'last_ms' => self::T0 + 60_000],
            ],
            null,
        );
        $out = MarksEscalation::apply($this->plain(100), $view, true, self::T0 + 61_000, self::TTL, $this->healthy());
        self::assertSame(RiskAction::Deny, $out->action);
        // The ASN mark written a minute later owns the window.
        self::assertSame(4294967295, $out->retryAfterMs);
    }

    /**
     * The victim-protection property: with only target-side evidence,
     * the final action equals the plain action or StepUp, and the score,
     * band and policy metadata pass through untouched.
     */
    public function testTargetOnlyEvidenceNeverEscalatesPastStepUp(): void
    {
        $policy = $this->policy();
        foreach ([0, 25, 50, 100] as $step) {
            for ($score = $step; $score <= 1000; $score += 50) {
                foreach ([0, 1, 2, 3, 4] as $level) {
                    $base = $policy->decide(1, $score, SignalVector::zero(), $this->healthy(), $level, self::T0);
                    $out = MarksEscalation::apply($base, $this->targetView(), true, self::T0, self::TTL, $this->healthy());
                    self::assertTrue(
                        $out->action === $base->action || $out->action === RiskAction::StepUp,
                        sprintf('score %d level %d: %s -> %s', $score, $level, $base->action->value, $out->action->value),
                    );
                    self::assertSame($base->score, $out->score);
                    self::assertSame($base->band, $out->band);
                    self::assertNull($out->retryAfterMs);
                }
            }
        }
    }

    /** The marked-identity property: an in-TTL own mark on any dimension floors the action at the maximum rung. */
    public function testOwnMarkNeverStaysBelowTheMaximumRung(): void
    {
        $policy = $this->policy();
        foreach (['principal', 'session', 'agent', 'asn'] as $dimension) {
            for ($score = 0; $score <= 1000; $score += 50) {
                $base = $policy->decide(1, $score, SignalVector::zero(), $this->healthy(), 0, self::T0);
                $view = MarksView::fromParts([$dimension => $this->mark((int) self::T0)], null);
                $out = MarksEscalation::apply($base, $view, false, self::T0, self::TTL, $this->healthy());
                self::assertTrue(
                    $out->action->rank() >= RiskAction::Argon64->rank(),
                    sprintf('%s score %d: %s', $dimension, $score, $out->action->value),
                );
            }
        }
    }

    public function testUnreadableMarksFloorFailClosedWithoutFabricatingADeny(): void
    {
        $out = MarksEscalation::applyUnreadable($this->plain(100), self::T0, $this->healthy());
        self::assertSame(RiskAction::Argon64, $out->action);
        self::assertTrue($out->hasReason(RiskReason::MarkedIdentity));
        self::assertNull($out->retryAfterMs);
        $saturated = new ResourcePressure(0, 1000);
        $out = MarksEscalation::applyUnreadable($this->plain(100), self::T0, $saturated);
        self::assertSame(RiskAction::StepUp, $out->action);
        // A plain Deny stays a Deny even when the surface is unreadable.
        $out = MarksEscalation::applyUnreadable($this->plain(980), self::T0, $this->healthy());
        self::assertSame(RiskAction::Deny, $out->action);
    }

    public function testCorroborationFloorMatchesThePolicyThresholds(): void
    {
        $below = new SignalVector(0, 0, 0, 0, 299, 299, 299, 0, 0, 0, 0, 0, 0);
        self::assertFalse(MarksEscalation::corroborated($below, false));
        self::assertTrue(MarksEscalation::corroborated(new SignalVector(0, 0, 0, 0, 300, 0, 0, 0, 0, 0, 0, 0, 0), false));
        self::assertTrue(MarksEscalation::corroborated(new SignalVector(0, 0, 0, 0, 0, 300, 0, 0, 0, 0, 0, 0, 0), false));
        self::assertTrue(MarksEscalation::corroborated(new SignalVector(0, 0, 0, 0, 0, 0, 300, 0, 0, 0, 0, 0, 0), false));
        self::assertTrue(MarksEscalation::corroborated(SignalVector::zero(), true));
    }

    /**
     * The engine wiring: the stage runs on the public assess surface
     * only when a marks reader is attached, and the engine hands the
     * reader the derived session pseudonym (32 hex chars), never the
     * raw cookie value.
     */
    public function testEngineAppliesTheStageOnlyWhenAReaderIsWired(): void
    {
        $store = new class extends RiskStateStoreStub {
            public ?RiskObservation $observed = null;

            public function observe(RiskObservation $observation): SignalVector
            {
                $this->observed = $observation;

                return SignalVector::zero();
            }
        };
        $keys = RiskKeys::fromMaster(str_repeat(chr(0x42), 32));
        $factory = new RiskIdentityFactory($keys);
        $classifier = new CidrNetworkClassifier([]);
        $base = [
            'store' => $store,
            'classifier' => $classifier,
            'identityFactory' => $factory,
            'scorer' => new RiskScorer(),
            'policy' => $this->policy(),
            'keys' => $keys,
        ];
        $context = new RiskContext(
            scope: 1,
            sourceIp: '198.51.100.7',
            sessionId: '00112233445566778899aabbccddeeff',
            principalId: null,
            event: RiskEventKind::PreIssue,
            networkFlags: $classifier->classify('198.51.100.7'),
            resources: new ResourcePressure(1000, 1000),
        );

        $unwired = new AdaptiveRiskEngine(...$base);
        self::assertSame(RiskAction::Allow, $unwired->assessPreIssue($context)->action);

        $seenSessions = [];
        $reader = new class ($store, $seenSessions) implements \KiwiCaptcha\Risk\Marks\MarksReaderInterface {
            public function __construct(
                private readonly RiskStateStoreStub $store,
                private array &$seenSessions,
            ) {
            }

            public function requestMarks(\KiwiCaptcha\Risk\Marks\MarksRequest $request): MarksView
            {
                $this->seenSessions[] = $request->session;

                return MarksView::read($this->store, ['session' => (string) $request->session], null);
            }

            public function markTtlMs(): int
            {
                return MarksEscalation::DEFAULT_MARK_TTL_MS;
            }
        };
        $wired = new AdaptiveRiskEngine(...[...$base, 'marksReader' => $reader]);
        // Unmarked: the wired engine answers the plain action too.
        self::assertSame(RiskAction::Allow, $wired->assessPreIssue($context)->action);

        $sessionPseudonym = $store->observed->sessionId;
        self::assertNotNull($sessionPseudonym);
        $store->writeMark('session', $sessionPseudonym, 'accountBanned', (int) floor(microtime(true) * 1000));
        $decision = $wired->assessPreIssue($context);
        self::assertSame(RiskAction::Argon64, $decision->action);
        self::assertTrue($decision->hasReason(RiskReason::MarkedIdentity));
        // The unwired engine still answers the plain action.
        self::assertSame(RiskAction::Allow, $unwired->assessPreIssue($context)->action);
        self::assertSame([$sessionPseudonym, $sessionPseudonym], $seenSessions);
        self::assertNotSame('00112233445566778899aabbccddeeff', $sessionPseudonym);
    }

    public function testUnreadableReaderFloorsFailClosedOnTheEnginePath(): void
    {
        $store = new class extends RiskStateStoreStub {
            public function observe(RiskObservation $observation): SignalVector
            {
                return SignalVector::zero();
            }
        };
        $keys = RiskKeys::fromMaster(str_repeat(chr(0x42), 32));
        $classifier = new CidrNetworkClassifier([]);
        $reader = new class implements \KiwiCaptcha\Risk\Marks\MarksReaderInterface {
            public function requestMarks(\KiwiCaptcha\Risk\Marks\MarksRequest $request): MarksView
            {
                throw new \KiwiCaptcha\Risk\Storage\RiskStoreException('marks backend down');
            }

            public function markTtlMs(): int
            {
                return MarksEscalation::DEFAULT_MARK_TTL_MS;
            }
        };
        $engine = new AdaptiveRiskEngine(
            store: $store,
            classifier: $classifier,
            identityFactory: new RiskIdentityFactory($keys),
            scorer: new RiskScorer(),
            policy: $this->policy(),
            keys: $keys,
            marksReader: $reader,
        );
        $context = new RiskContext(
            scope: 1,
            sourceIp: '198.51.100.7',
            sessionId: '00112233445566778899aabbccddeeff',
            principalId: null,
            event: RiskEventKind::PreIssue,
            networkFlags: $classifier->classify('198.51.100.7'),
            resources: new ResourcePressure(1000, 1000),
        );
        $decision = $engine->assessPreIssue($context);
        self::assertSame(RiskAction::Argon64, $decision->action);
        self::assertTrue($decision->hasReason(RiskReason::MarkedIdentity));
    }
}
