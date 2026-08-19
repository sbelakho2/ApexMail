<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Breaker\CircuitBreaker;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\RiskV2Context;
use KiwiCaptcha\Risk\RiskV2Weights;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\RiskStateStoreInterface;
use PHPUnit\Framework\TestCase;

/**
 * Engine-level risk-v2 wiring: the additive honeypot/decoy evidence and
 * session client-context consistency factors flow through the full
 * assessment pipeline (observation -> store -> scorer -> policy) without
 * touching the risk-v1 state contract.
 */
final class RiskV2EngineTest extends TestCase
{
    private function policy(): RiskPolicy
    {
        return RiskPolicy::fromConfig([
            'version' => 3,
            'weights' => (new RiskWeights())->toArray(),
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'sha20'],
            ],
            'global_floors' => [1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
        ]);
    }

    private function engine(RiskStateStoreInterface $store): AdaptiveRiskEngine
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
            breaker: new CircuitBreaker(),
        );
    }

    private function zeroStore(): RiskStateStoreInterface
    {
        return new class extends RiskStateStoreStub {
            public function observe(RiskObservation $observation): SignalVector
            {
                return SignalVector::zero();
            }
        };
    }

    private function context(RiskEventKind $event = RiskEventKind::PreIssue, ?string $sessionId = null): RiskContext
    {
        return new RiskContext(
            scope: 1,
            sourceIp: '203.0.113.27',
            sessionId: $sessionId,
            principalId: null,
            event: $event,
            networkFlags: (new CidrNetworkClassifier([['cidr' => '203.0.113.0/24', 'flags' => ['hosting']]]))->classify('203.0.113.27'),
            resources: new ResourcePressure(1000, 1000),
        );
    }

    private function v2(bool $honeypotHit = false, ?string $tag = null, ?string $tlsTag = null): RiskV2Context
    {
        return new RiskV2Context(honeypotHit: $honeypotHit, clientContextTag: $tag, tlsTag: $tlsTag);
    }

    public function testHoneypotEvidenceRaisesTheScoreButNeverDeniesAlone(): void
    {
        $engine = $this->engine($this->zeroStore());
        $clean = $engine->assessPreIssue($this->context());
        self::assertSame(100, $clean->score);
        self::assertSame(RiskAction::Allow, $clean->action);

        $hit = $this->engine($this->zeroStore())->assessPreIssueV2($this->context(), $this->v2(honeypotHit: true));
        self::assertSame(300, $hit->score, '100 + weighted(1000, honeypot 200)');
        self::assertSame(RiskAction::Sha18, $hit->action, 'a lone honeypot hit selects a stronger profile');
        self::assertNotSame(RiskAction::Deny, $hit->action, 'a lone honeypot hit must never deny');
    }

    public function testAnyHoneypotEventKindDerivesTheSignal(): void
    {
        $engine = $this->engine($this->zeroStore());
        foreach ([RiskEventKind::HoneypotTriggered, RiskEventKind::DecoyEndpointTouched, RiskEventKind::DecoyFieldSubmitted] as $kind) {
            $decision = $engine->assessPreIssueV2($this->context($kind), $this->v2());
            self::assertSame(300, $decision->score, sprintf('%s must derive the honeypot signal', $kind->name));
        }
    }

    public function testConsistentTagIsNeutral(): void
    {
        $store = $this->zeroStore();
        $engine = $this->engine($store);
        $session = str_repeat('ab', 16);

        $first = $engine->assessPreIssueV2($this->context(sessionId: $session), $this->v2(tag: 'aa'));
        self::assertSame(100, $first->score, 'the first tag-bearing request is neutral');

        $again = $engine->assessPreIssueV2($this->context(sessionId: $session), $this->v2(tag: 'aa'));
        self::assertSame(100, $again->score, 'an unchanged tag stays neutral');
    }

    public function testChangedTagRaisesTheAggregate(): void
    {
        $engine = $this->engine($this->zeroStore());
        $session = str_repeat('cd', 16);

        $engine->assessPreIssueV2($this->context(sessionId: $session), $this->v2(tag: 'aa'));
        $changed = $engine->assessPreIssueV2($this->context(sessionId: $session), $this->v2(tag: 'bb'));

        self::assertSame(220, $changed->score, '100 + weighted(1000, session_inconsistency 120)');
    }

    public function testAbsentTagIsNeutral(): void
    {
        $engine = $this->engine($this->zeroStore());
        $session = str_repeat('ef', 16);

        $decision = $engine->assessPreIssueV2($this->context(sessionId: $session), $this->v2(tag: 'aa'));
        self::assertSame(100, $decision->score);

        $noTag = $engine->assessPreIssueV2($this->context(sessionId: $session), $this->v2());
        self::assertSame(100, $noTag->score, 'a session without a tag stays neutral');
    }

    public function testEmptyV2ContextIsByteIdenticalToTheV1Path(): void
    {
        $engine = $this->engine($this->zeroStore());
        $plain = $engine->assessPreIssue($this->context());
        $empty = $engine->assessPreIssueV2($this->context(), $this->v2());
        self::assertSame($plain->score, $empty->score);
        self::assertSame($plain->action, $empty->action);
        self::assertSame($plain->band, $empty->band);
    }

    public function testConsistentTlsTagIsNeutral(): void
    {
        $store = $this->zeroStore();
        $engine = $this->engine($store);
        $session = str_repeat('2a', 16);

        $first = $engine->assessPreIssueV2($this->context(sessionId: $session), $this->v2(tlsTag: 'tls13|http2'));
        self::assertSame(100, $first->score, 'the first TLS tag-bearing request is neutral');

        $again = $engine->assessPreIssueV2($this->context(sessionId: $session), $this->v2(tlsTag: 'tls13|http2'));
        self::assertSame(100, $again->score, 'an unchanged TLS tag stays neutral');
    }

    public function testChangedTlsTagRaisesTheAggregate(): void
    {
        $engine = $this->engine($this->zeroStore());
        $session = str_repeat('2b', 16);

        $engine->assessPreIssueV2($this->context(sessionId: $session), $this->v2(tlsTag: 'tls13|http2'));
        $changed = $engine->assessPreIssueV2($this->context(sessionId: $session), $this->v2(tlsTag: 'tls12|http1'));

        self::assertSame(180, $changed->score, '100 + weighted(1000, tls 80)');
    }

    public function testAbsentTlsTagIsNeutral(): void
    {
        $engine = $this->engine($this->zeroStore());
        $session = str_repeat('2c', 16);

        $decision = $engine->assessPreIssueV2($this->context(sessionId: $session), $this->v2(tlsTag: 'tls13|http2'));
        self::assertSame(100, $decision->score);

        $noTag = $engine->assessPreIssueV2($this->context(sessionId: $session), $this->v2());
        self::assertSame(100, $noTag->score, 'a session without a TLS tag stays neutral');
    }

    public function testOversizedTlsTagIsTreatedAsAbsent(): void
    {
        $engine = $this->engine($this->zeroStore());
        $session = str_repeat('2d', 16);

        $decision = $engine->assessPreIssueV2($this->context(sessionId: $session), $this->v2(tlsTag: str_repeat('x', 65)));
        self::assertSame(100, $decision->score, 'a TLS tag over the 64-char bound is treated as absent');

        $again = $engine->assessPreIssueV2($this->context(sessionId: $session), $this->v2(tlsTag: str_repeat('y', 65)));
        self::assertSame(100, $again->score, 'an over-bound TLS tag must never raise the aggregate');
    }

    public function testV2WeightsOverrideTunesTheAdditiveFactors(): void
    {
        $engine = $this->engine($this->zeroStore());

        // Null override: the DEFAULT weights apply (100 + 1000*200/1000 = 300).
        $default = $engine->assessPreIssueV2($this->context(), $this->v2(honeypotHit: true), null, null);
        self::assertSame(300, $default->score, 'a null weights override must produce the default score');

        // Operator-tuned weights: honeypot weight 100 -> 100 + 1000*100/1000 = 200.
        $tuned = $engine->assessPreIssueV2($this->context(), $this->v2(honeypotHit: true), null, new RiskV2Weights(honeypot: 100));
        self::assertSame(200, $tuned->score, 'the v2 weights override must tune the additive factors');
    }

    public function testHoneypotEventRidesTheFeedbackPathAsANonConfirmationEvent(): void
    {
        $store = $this->zeroStore();
        $engine = $this->engine($store);
        $receipt = $engine->record_feedback(RiskEventKind::HoneypotTriggered, $this->context(RiskEventKind::HoneypotTriggered));
        self::assertFalse($receipt->isDuplicate);
        self::assertSame(SignalVector::zero()->toArray(), $receipt->signals->toArray());

        $receipt2 = $engine->record_feedback(RiskEventKind::DecoyFieldSubmitted, $this->context(RiskEventKind::DecoyFieldSubmitted));
        self::assertFalse($receipt2->isDuplicate);
    }
}
