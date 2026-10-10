<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\Evidence\EvidenceModel;
use KiwiCaptcha\Risk\Evidence\TelemetryPayloadV1;
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
use KiwiCaptcha\Risk\SignalVector;
use PHPUnit\Framework\TestCase;

/**
 * Shared evidence vectors (protocol/telemetry-v1/evidence-vectors.json):
 * the PHP mirror of the Rust evidence_vectors test. The corpus pins the
 * telemetry-v1 schema acceptance, the human-band and agent-evidence
 * corpora, the solve-anomaly reference table, the composed stage and
 * the decoy-escalation raise.
 */
final class EvidenceVectorsTest extends TestCase
{
    private const T0 = 1_700_000_000_000;

    /** @return array<string, mixed> */
    private static function corpus(): array
    {
        $path = dirname(__DIR__) . '/../../protocol/telemetry-v1/evidence-vectors.json';
        $raw = file_get_contents($path);
        self::assertNotFalse($raw, "evidence vectors readable at $path");

        return json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
    }

    public function testCorpusConstsEqualTheCompiledTable(): void
    {
        $corpus = self::corpus();
        foreach (EvidenceModel::CONSTS as $key => $value) {
            self::assertSame(
                $value,
                $corpus['consts'][$key],
                "the corpus consts value for $key must equal the compiled table"
            );
        }
        self::assertSame(
            $corpus['consts']['entropy_min_samples'],
            $corpus['consts']['sample_cap'],
            'the entropy rule must stay exactly reachable at the payload cap'
        );
    }

    public function testInteractionVectorsMatchExactly(): void
    {
        $corpus = self::corpus();
        $humanEdge = $corpus['consts']['human_band_edge'];
        $agentEdge = $corpus['consts']['agent_evidence_edge'];
        self::assertNotEmpty($corpus['interaction_vectors']);
        foreach ($corpus['interaction_vectors'] as $vector) {
            $name = $vector['name'];
            $payload = TelemetryPayloadV1::parse(self::canonicalJson($vector['payload']));
            self::assertNotNull($payload, "$name: the corpus payload must parse");
            $anomaly = EvidenceModel::interactionAnomaly($payload);
            self::assertNotNull($anomaly, "$name: a valid payload always scores");
            self::assertSame($vector['expected'], $anomaly, "$name: interaction anomaly mismatch");
            if ($vector['band'] === 'human') {
                self::assertLessThanOrEqual(
                    $humanEdge,
                    $anomaly,
                    "$name: a human-band payload must stay in the human band"
                );
            } else {
                self::assertGreaterThanOrEqual(
                    $agentEdge,
                    $anomaly,
                    "$name: an agent payload must be positive evidence"
                );
            }
        }
    }

    public function testInvalidPayloadsRejectAndScoreNeutral(): void
    {
        $corpus = self::corpus();
        self::assertNotEmpty($corpus['invalid_payloads']);
        foreach ($corpus['invalid_payloads'] as $vector) {
            $name = $vector['name'];
            $parsed = TelemetryPayloadV1::parse($vector['raw']);
            self::assertNull($parsed, "$name: expected a schema reject");
            self::assertNull(EvidenceModel::interactionAnomaly(null), "$name: rejected payloads score neutral");
            self::assertNull(EvidenceModel::interactionAnomaly(null), "$name: the absent payload scores neutral-unknown");
        }
    }

    public function testSolveVectorsMatchExactly(): void
    {
        $corpus = self::corpus();
        self::assertNotEmpty($corpus['solve_vectors']);
        foreach ($corpus['solve_vectors'] as $vector) {
            self::assertSame(
                $vector['expected'],
                EvidenceModel::solveAnomaly($vector['solve_ms'], $vector['rung']),
                $vector['name'] . ': solve anomaly mismatch'
            );
        }
    }

    public function testStageVectorsMatchExactly(): void
    {
        $corpus = self::corpus();
        $policy = $this->policyFromCorpus($corpus);
        $resources = new ResourcePressure(1000, 1000);
        self::assertNotEmpty($corpus['stage']['vectors']);
        foreach ($corpus['stage']['vectors'] as $vector) {
            $inputs = EvidenceModel::inputs(
                isset($vector['interaction']) && $vector['interaction'] !== null ? $this->payloadTextFor((int) $vector['interaction']) : null,
                $vector['solve_ms'] ?? null,
                $vector['rung'] ?? null,
            );
            if ($vector['interaction'] !== null) {
                self::assertSame($vector['interaction'], $inputs->interaction, $vector['name']);
            }
            $plain = $policy->decide(1, (int) $vector['score'], SignalVector::zero(), $resources, 0, self::T0);
            $out = EvidenceModel::apply($plain, $inputs, $resources);
            self::assertSame(
                $vector['expected_action'],
                $out->action->value,
                $vector['name'] . ': stage action mismatch'
            );
            $expected = $vector['expected_stage_reasons'];
            $actual = array_map(static fn ($r) => $r->value, $out->reasons);
            foreach ($expected as $i => $reason) {
                self::assertSame($reason, $actual[$i] ?? null, $vector['name'] . ': stage reasons prefix');
            }
        }
    }

    public function testDecoyEscalationVectorsMatchExactly(): void
    {
        $corpus = self::corpus();
        $policy = $this->policyFromCorpus($corpus);
        $resources = new ResourcePressure(1000, 1000);
        self::assertNotEmpty($corpus['decoy_escalation']['vectors']);
        foreach ($corpus['decoy_escalation']['vectors'] as $vector) {
            $plain = $policy->decide(1, (int) $vector['score'], SignalVector::zero(), $resources, 0, self::T0);
            self::assertSame(
                $vector['plain_action'],
                $plain->action->value,
                $vector['name'] . ': the plain action must match before the raise'
            );
            $out = \KiwiCaptcha\Risk\Evidence\DecoyEscalation::apply($plain, true);
            self::assertSame(
                $vector['expected_action'],
                $out->action->value,
                $vector['name'] . ': decoy escalation mismatch'
            );
        }
    }

    public function testEnginePathComposesTheStagesWhenWired(): void
    {
        $corpus = self::corpus();
        $policy = $this->policyFromCorpus($corpus);
        $keys = RiskKeys::fromMaster(str_repeat(chr(0x42), 32));
        $store = new class extends RiskStateStoreStub {
            public function observe(RiskObservation $observation): SignalVector
            {
                return SignalVector::zero();
            }
        };
        $engine = new AdaptiveRiskEngine(
            store: $store,
            classifier: new CidrNetworkClassifier([]),
            identityFactory: new RiskIdentityFactory($keys),
            scorer: new RiskScorer(),
            policy: $policy,
            keys: $keys,
        );
        $v2 = new \KiwiCaptcha\Risk\RiskV2Context(
            telemetryPayload: '{"v":1,"ec":{"fo":0,"ke":16,"pa":0,"po":0,"fm":16},"qe":0,"ft":1,"pt":0,"n":32}',
            solveMs: 100,
            solveRung: 'sha18',
        );
        $decision = $engine->assessPreIssueV2($this->context(), $v2);
        self::assertSame('sha16', $decision->action->value, 'the agent-shaped payload raises the rung');
        self::assertTrue($decision->hasReason(RiskReason::InteractionAnomaly));

        // The decoy escalation raises its one rung on a clean v2 path.
        $wired = new AdaptiveRiskEngine(
            store: $store,
            classifier: new CidrNetworkClassifier([]),
            identityFactory: new RiskIdentityFactory($keys),
            scorer: new RiskScorer(),
            policy: $policy,
            keys: $keys,
            decoyEscalationReader: new FixedLiveReader(),
        );
        $plain = $wired->assessPreIssueV2($this->context(), new \KiwiCaptcha\Risk\RiskV2Context());
        self::assertSame('sha16', $plain->action->value, 'a live record turns a plain allow into a priced rung');
        self::assertTrue($plain->hasReason(RiskReason::DecoyEscalation));

        // A v2 context without evidence keeps the unwired path untouched.
        $clean = $engine->assessPreIssueV2($this->context(), new \KiwiCaptcha\Risk\RiskV2Context());
        self::assertSame('allow', $clean->action->value);
        self::assertFalse($clean->hasReason(RiskReason::InteractionAnomaly));
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

    /**
     * Builds a payload text whose interaction anomaly equals $anomaly,
     * by a bounded deterministic search over the term mix (entropy 0..15
     * crossed with the focus and paste terms). The corpus stage vectors
     * pin anomalies the mix can express exactly.
     */
    private function payloadTextFor(int $anomaly): string
    {
        for ($qe = 15; $qe >= 0; $qe--) {
            foreach ([1, 0] as $focus) {
                foreach ([0, 1] as $paste) {
                    $payload = $paste === 1
                        ? ['v' => 1, 'ec' => ['fo' => 1, 'ke' => 0, 'pa' => 15, 'po' => 0, 'fm' => 16], 'qe' => $qe, 'ft' => $focus === 1 ? 1 : 0, 'pt' => 1000, 'n' => 32]
                        : ['v' => 1, 'ec' => ['fo' => 1, 'ke' => 15, 'pa' => 0, 'po' => 1, 'fm' => 15], 'qe' => $qe, 'ft' => $focus === 1 ? 1 : 0, 'pt' => 0, 'n' => 32];
                    $inputs = EvidenceModel::inputs(self::canonicalJson($payload), null, null);
                    if ($inputs->interaction === $anomaly) {
                        return self::canonicalJson($payload);
                    }
                }
            }
        }
        self::fail("no payload expresses anomaly $anomaly");
    }

    /** @param array<string, mixed> $corpus */
    private function policyFromCorpus(array $corpus): RiskPolicy
    {
        $p = $corpus['stage']['policy'];
        $scopes = [];
        foreach ($p['scopes'] as $id => $scope) {
            $scopes[(int) $id] = $scope;
        }
        $floors = [];
        foreach ($p['global_floors'] as $level => $action) {
            $floors[(int) $level] = $action;
        }

        return RiskPolicy::fromConfig([
            'version' => $p['version'],
            'weights' => $p['weights'],
            'scopes' => $scopes,
            'global_floors' => $floors,
        ]);
    }

    /** Deterministic canonical JSON encoding of an array. */
    private static function canonicalJson(array $data): string
    {
        $encoded = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        self::assertIsString($encoded);

        return $encoded;
    }
}

/**
 * The always-live decoy reader for the engine wiring test.
 */
final class FixedLiveReader implements \KiwiCaptcha\Risk\Evidence\DecoyEscalationReaderInterface
{
    public function escalationLive(?string $session): bool
    {
        return true;
    }
}
