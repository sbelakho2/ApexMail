<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Asn\AsnDataset;
use KiwiCaptcha\Risk\Breaker\CircuitBreaker;
use KiwiCaptcha\Risk\DecisionExplanation;
use KiwiCaptcha\Risk\ExplainedDecision;
use KiwiCaptcha\Risk\IdentityVector;
use KiwiCaptcha\Risk\IdentityVectorInput;
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
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\SignalVector;
use PHPUnit\Framework\TestCase;

/**
 * The explanation surface (change.md 3.8.3): the engine's assessed
 * result grows the additive names-only explanation, and no serialized
 * explanation ever carries a pseudonym value or a raw identifier. The
 * canary set mirrors the Rust lane (tests/explanation_privacy.rs).
 */
final class DecisionExplanationTest extends TestCase
{
    private const CANARY_IP = '203.0.113.27';
    private const CANARY_COOKIE_HEX = '5ae1a4b8c0d1e2f30011223344556677';
    private const CANARY_PRINCIPAL = 'principal-canary-42';
    private const CANARY_AGENT = 'agent-canary-7';
    private const CANARY_TARGET = 'canary.user+leak@gmail.com';

    private function policy(): RiskPolicy
    {
        return RiskPolicy::fromConfig([
            'version' => 3,
            'weights' => (new RiskWeights())->toArray(),
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'sha20'],
            ],
            'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
        ]);
    }

    private function engine(): AdaptiveRiskEngine
    {
        $keys = RiskKeys::fromMaster(str_repeat(chr(0x42), 32));
        $store = new class extends RiskStateStoreStub {
            public function observe(RiskObservation $observation): SignalVector
            {
                return SignalVector::fromArray([
                    'source_fast' => 900,
                    'replay' => 800,
                ] + SignalVector::zero()->toArray());
            }
        };

        return new AdaptiveRiskEngine(
            store: $store,
            classifier: new CidrNetworkClassifier([]),
            identityFactory: new RiskIdentityFactory($keys),
            scorer: new RiskScorer(),
            policy: $this->policy(),
            keys: $keys,
            breaker: new CircuitBreaker(),
        );
    }

    private function context(): RiskContext
    {
        return new RiskContext(
            scope: 1,
            sourceIp: self::CANARY_IP,
            sessionId: self::CANARY_COOKIE_HEX,
            principalId: self::CANARY_PRINCIPAL,
            event: RiskEventKind::PreIssue,
            networkFlags: new \KiwiCaptcha\Risk\Network\NetworkFlags(),
            resources: new ResourcePressure(1000, 1000),
        );
    }

    /** @return list<string> every pseudonym value of the canary request */
    private function canaryPseudonymValues(): array
    {
        $dataset = AsnDataset::open(dirname(__DIR__) . '/../../protocol/asn/sample-asn.tsv');
        $input = new IdentityVectorInput(
            clientIp: self::CANARY_IP,
            sessionCookieHex: self::CANARY_COOKIE_HEX,
            principalId: self::CANARY_PRINCIPAL,
            agentKeyId: self::CANARY_AGENT,
            targetNormalized: 'canary.user@gmail.com',
            asnDataset: $dataset,
            nowUnixSecs: 1700000000,
        );
        $vector = IdentityVector::derive($input, new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat(chr(0x42), 32))));
        $values = [];
        foreach (IdentityVector::DIMENSIONS as $name) {
            $value = $vector->dimension($name);
            if (\is_string($value)) {
                $values[] = $value;
            }
        }

        return $values;
    }

    public function testTheEngineResultCarriesTheAdditiveExplanation(): void
    {
        $explained = $this->engine()->assessPreIssueWithExplanation($this->context());
        self::assertInstanceOf(ExplainedDecision::class, $explained);
        self::assertInstanceOf(RiskAction::class, $explained->decision->action);
        // The engine sees source, subnet, session and principal on this
        // request; asn and agent belong to the caller's identity vector.
        self::assertSame(['source', 'subnet', 'session', 'principal'], $explained->explanation->dimensions);
        self::assertNotSame([], $explained->explanation->reasons, 'hot signals produce named contributors');
        self::assertFalse($explained->explanation->isEmpty());
        // The decision's own surface is unchanged.
        self::assertSame($explained->decision->score, $explained->jsonSerialize()['score']);
        self::assertArrayHasKey('explanation', $explained->jsonSerialize());
        self::assertSame(\count($explained->decision->jsonSerialize()) + 1, \count($explained->jsonSerialize()));
    }

    public function testASessionlessContextReportsOnlyTheVisibleDimensions(): void
    {
        $context = new RiskContext(
            scope: 1,
            sourceIp: self::CANARY_IP,
            sessionId: null,
            principalId: null,
            event: RiskEventKind::PreIssue,
            networkFlags: new \KiwiCaptcha\Risk\Network\NetworkFlags(),
            resources: new ResourcePressure(1000, 1000),
        );
        $explained = $this->engine()->assessPreIssueWithExplanation($context);
        self::assertSame(['source', 'subnet'], $explained->explanation->dimensions);
    }

    public function testSerializedExplanationsNeverCarryPseudonymValuesOrRawInputs(): void
    {
        $explained = $this->engine()->assessPreIssueWithExplanation($this->context());
        $serialized = json_encode($explained, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE);
        fwrite(STDERR, "\nexplanation privacy scan over: {$serialized}\n");

        foreach ($this->canaryPseudonymValues() as $forbidden) {
            self::assertStringNotContainsString(
                $forbidden,
                $serialized,
                "privacy hole: the serialized explanation carries {$forbidden}",
            );
        }
        foreach ([self::CANARY_IP, self::CANARY_COOKIE_HEX, self::CANARY_PRINCIPAL, self::CANARY_AGENT, self::CANARY_TARGET] as $raw) {
            self::assertStringNotContainsString($raw, $serialized);
        }

        // The composed full surface (every dimension name of the request
        // identity vector, a price rung name) stays names-only.
        $full = ExplainedDecision::wrap($explained->decision, IdentityVector::DIMENSIONS, 'sha20');
        $fullJson = json_encode($full, JSON_THROW_ON_ERROR);
        foreach ($this->canaryPseudonymValues() as $forbidden) {
            self::assertStringNotContainsString($forbidden, $fullJson);
        }
        self::assertSame(IdentityVector::DIMENSIONS, $full->explanation->dimensions);
        self::assertSame('sha20', $full->explanation->priceRung);
    }

    public function testTheDefaultExplanationIsNamesOnlyAndEmpty(): void
    {
        $empty = DecisionExplanation::empty();
        self::assertTrue($empty->isEmpty());
        self::assertSame(
            ['action' => 'allow', 'reasons' => [], 'dimensions' => [], 'price_rung' => null],
            $empty->jsonSerialize(),
        );
    }

    public function testUnknownDimensionNamesAreDropped(): void
    {
        $explained = $this->engine()->assessPreIssueWithExplanation($this->context());
        $composed = DecisionExplanation::forDecision($explained->decision, ['source', 'device', 'agent'], null);
        self::assertSame(['source', 'agent'], $composed->dimensions);
        self::assertSame($explained->decision->reasons, $composed->reasons);
        self::assertContains(RiskReason::SourceBurst, $composed->reasons);
    }
}
