<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Evidence\DecoyEscalation;
use KiwiCaptcha\Risk\Evidence\DecoyEscalationReaderInterface;
use KiwiCaptcha\Risk\Marks\MarksEscalation;
use KiwiCaptcha\Risk\Marks\MarksView;
use KiwiCaptcha\Risk\Marks\Quarantine;
use KiwiCaptcha\Risk\Marks\StoreMarksReader;
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
use KiwiCaptcha\Risk\SignalVector;
use PHPUnit\Framework\TestCase;

/**
 * The quarantine disposition (change.md 1.3 and 3.3.4). The shared
 * quarantine vectors (protocol/risk-v1/quarantine-vectors.json) pin the
 * selection and its severity-monotonic precedence across both cores.
 * The unit and property tests pin the decision-plane invariants the
 * corpus cannot express: the Allow-only rule, the escalation drop of
 * the composed stages, the metrics label. The vectors path environment
 * variable overrides the corpus location.
 */
final class QuarantineVectorsTest extends TestCase
{
    private const T0 = 1700000000000;
    private const TTL = 7776000000;

    private function vectorsPath(): string
    {
        $env = getenv('RISK_QUARANTINE_VECTORS_PATH');
        if (is_string($env) && $env !== '') {
            return $env;
        }

        return dirname(__DIR__) . '/../../protocol/risk-v1/quarantine-vectors.json';
    }

    public function testEverySharedVectorMatchesExactly(): void
    {
        $path = $this->vectorsPath();
        self::assertFileExists($path, sprintf('Quarantine vectors file not found at %s (set RISK_QUARANTINE_VECTORS_PATH)', $path));
        $vectors = json_decode((string) file_get_contents($path), true);
        self::assertIsArray($vectors);
        self::assertSame(1, $vectors['version'], 'the vectors pin the stage version');
        $policy = RiskPolicy::fromConfig(self::intScopeKeys($vectors['policy']));
        $ttl = (int) $vectors['mark_ttl_ms'];

        $rows = $vectors['vectors'];
        self::assertNotEmpty($rows);
        foreach ($rows as $vector) {
            $why = $vector['why'] ?? 'vector';
            $signals = SignalVector::fromArray($vector['signals']);
            $resources = new ResourcePressure((int) $vector['argon_capacity'], (int) $vector['issuance_capacity']);
            $now = (int) $vector['now_ms'];
            $plain = $policy->decide(
                scope: (int) $vector['scope'],
                score: (int) $vector['score'],
                s: $signals,
                r: $resources,
                globalLevel: (int) $vector['global_level'],
                nowMs: $now,
            );
            $view = MarksView::fromParts($vector['own_marks'], $vector['target_mark']);
            $out = MarksEscalation::apply(
                $plain,
                $view,
                (bool) $vector['corroborated'],
                $now,
                $ttl,
                $resources,
                true,
            );
            self::assertSame($vector['expected_action'], $out->action->value, "action mismatch: {$why}");
            self::assertSame((bool) $vector['expected_quarantined'], $out->quarantined, "quarantine mismatch: {$why}");
            self::assertSame($vector['expected_retry_after_ms'], $out->retryAfterMs, "retry mismatch: {$why}");
            $expectedReasons = $vector['expected_reasons'];
            $actualReasons = array_map(static fn ($reason): string => $reason->value, $out->reasons);
            self::assertSame($expectedReasons, $actualReasons, "reasons mismatch: {$why}");
        }
    }

    public function testQuarantineRidesTheAllowActionOnly(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new RiskDecision(100, RiskAction::Sha16, [], 3, 0, quarantined: true);
    }

    public function testDispositionLabelCountsQuarantineAsItsOwnAction(): void
    {
        $allow = new RiskDecision(100, RiskAction::Allow, [], 3, 0);
        self::assertSame('allow', $allow->dispositionLabel());
        self::assertFalse($allow->quarantined);
        $held = new RiskDecision(100, RiskAction::Allow, [RiskReason::SpamMarkQuarantine], 3, 0, quarantined: true);
        self::assertSame('quarantine', $held->dispositionLabel());
        // The wire action is untouched: quarantine is indistinguishable
        // from allow on every challenge-bearing surface.
        self::assertSame('allow', $held->action->value);
    }

    public function testWithoutQuarantineDropsOnlyTheFlag(): void
    {
        $held = new RiskDecision(100, RiskAction::Allow, [RiskReason::SpamMarkQuarantine], 3, 0, quarantined: true);
        $dropped = $held->withoutQuarantine();
        self::assertFalse($dropped->quarantined);
        self::assertSame($held->action, $dropped->action);
        self::assertSame($held->score, $dropped->score);
        self::assertSame($held->decisionId, $dropped->decisionId);
        // A clean decision is returned untouched (same instance).
        $clean = new RiskDecision(100, RiskAction::Allow, [], 3, 0);
        self::assertSame($clean, $clean->withoutQuarantine());
    }

    public function testSerializedDecisionCarriesTheFlagAsAnAdditiveField(): void
    {
        $held = new RiskDecision(100, RiskAction::Allow, [RiskReason::SpamMarkQuarantine], 3, 0, quarantined: true);
        $json = $held->jsonSerialize();
        self::assertTrue($json['quarantined']);
        self::assertSame('allow', $json['action']);
        $clean = new RiskDecision(100, RiskAction::Allow, [], 3, 0);
        self::assertFalse($clean->jsonSerialize()['quarantined']);
    }

    public function testSelectionRuleIsExact(): void
    {
        $spam = static fn (int $lastMs): array => ['kind' => Quarantine::SPAM_MARK_KIND, 'count' => 1, 'first_ms' => $lastMs, 'last_ms' => $lastMs];
        $fraud = static fn (int $lastMs): array => ['kind' => 'fraudConfirmed', 'count' => 1, 'first_ms' => $lastMs, 'last_ms' => $lastMs];

        // Spam-only live set selects; the same set with corroboration or
        // a target mark does not.
        $own = ['session' => $spam(self::T0)];
        self::assertTrue(Quarantine::selects(MarksView::fromParts($own, null), false, self::T0, self::TTL));
        self::assertFalse(Quarantine::selects(MarksView::fromParts($own, null), true, self::T0, self::TTL));
        self::assertFalse(Quarantine::selects(MarksView::fromParts($own, $spam(self::T0)), false, self::T0, self::TTL));
        // A non-spam mark in the live set never selects.
        $mixed = ['session' => $spam(self::T0), 'asn' => $fraud(self::T0)];
        self::assertFalse(Quarantine::selects(MarksView::fromParts($mixed, null), false, self::T0, self::TTL));
        // Expired marks are inert, never a quarantine.
        self::assertFalse(Quarantine::selects(MarksView::fromParts($own, null), false, self::T0 + self::TTL, self::TTL));
        // No live marks at all never selects.
        self::assertFalse(Quarantine::selects(MarksView::empty(), false, self::T0, self::TTL));
        // A non-spam-only live set keeps the legacy floor treatment.
        self::assertFalse(Quarantine::spamOnly(MarksView::fromParts($mixed, null), self::T0, self::TTL));
        self::assertTrue(Quarantine::spamOnly(MarksView::fromParts($own, null), self::T0, self::TTL));
    }

    /**
     * The severity-monotonic property over the whole score axis: a
     * spam-only identity quarantines exactly on the plain Allow band,
     * never overrides a stronger plain action, and corroborating
     * evidence denies for the remaining mark TTL.
     */
    public function testPrecedencePropertyOverTheScoreAxis(): void
    {
        $policy = RiskPolicy::fromConfig([
            'version' => 3,
            'weights' => [],
            'scopes' => [1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20']],
            'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
        ]);
        $view = MarksView::fromParts(['session' => ['kind' => Quarantine::SPAM_MARK_KIND, 'count' => 1, 'first_ms' => self::T0, 'last_ms' => self::T0]], null);
        $resources = new ResourcePressure(1000, 1000);
        for ($score = 0; $score <= 1000; $score += 10) {
            $plain = $policy->decide(scope: 1, score: $score, s: SignalVector::zero(), r: $resources, globalLevel: 0, nowMs: self::T0);
            $out = MarksEscalation::apply($plain, $view, false, self::T0, self::TTL, $resources, true);
            if ($plain->action === RiskAction::Allow) {
                self::assertTrue($out->quarantined, "score {$score}: clean spam identity must quarantine");
                self::assertSame(RiskAction::Allow, $out->action, "score {$score}: quarantine must not move the rung");
                self::assertTrue($out->hasReason(RiskReason::SpamMarkQuarantine));
            } else {
                self::assertFalse($out->quarantined, "score {$score}: severity wins over quarantine");
                self::assertSame($plain->action, $out->action, "score {$score}: a spam mark adds no rung above Allow");
                self::assertTrue($out->hasReason(RiskReason::MarkedIdentity));
            }

            $denied = MarksEscalation::apply($plain, $view, true, self::T0, self::TTL, $resources, true);
            self::assertSame(RiskAction::Deny, $denied->action, "score {$score}: corroboration denies");
            self::assertFalse($denied->quarantined, "score {$score}: deny outranks quarantine");
        }
    }

    /**
     * The composed pipeline: a live decoy escalation raises one rung and
     * the quarantine disposition drops with it; an inert stage keeps the
     * decision (flag included) byte-identical.
     */
    public function testComposedStageEscalationDropsTheQuarantine(): void
    {
        $policy = RiskPolicy::fromConfig([
            'version' => 3,
            'weights' => [],
            'scopes' => [1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20']],
            'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
        ]);
        $resources = new ResourcePressure(1000, 1000);
        $plain = $policy->decide(scope: 1, score: 100, s: SignalVector::zero(), r: $resources, globalLevel: 0, nowMs: self::T0);
        self::assertSame(RiskAction::Allow, $plain->action);
        $held = MarksEscalation::apply(
            $plain,
            MarksView::fromParts(['session' => ['kind' => Quarantine::SPAM_MARK_KIND, 'count' => 1, 'first_ms' => self::T0, 'last_ms' => self::T0]], null),
            false,
            self::T0,
            self::TTL,
            $resources,
            true,
        );
        self::assertTrue($held->quarantined);

        $live = new class implements DecoyEscalationReaderInterface {
            public function escalationLive(?string $session): bool
            {
                return true;
            }
        };
        $raised = DecoyEscalation::apply($held, $live->escalationLive(null));
        self::assertSame(RiskAction::Sha16, $raised->action);
        self::assertFalse($raised->quarantined, 'the raised action outranks the quarantine disposition');

        $inert = DecoyEscalation::apply($held, false);
        self::assertTrue($inert->quarantined, 'an inert stage keeps the decision byte-identical');
    }

    /**
     * End-to-end through the engine: the wired marks reader quarantines
     * the marked session, the decision metrics count the disposition as
     * its own label, and the issued action stays allow.
     */
    public function testEngineEmitsTheQuarantineDispositionAndItsMetricLabel(): void
    {
        $keys = RiskKeys::fromMaster('engine-quarantine-master-secret-32b');
        $policy = RiskPolicy::fromConfig([
            'version' => 3,
            'weights' => [],
            'scopes' => [1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20']],
            'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
        ]);
        $store = new class extends RiskStateStoreStub {
            public function observe(RiskObservation $observation): SignalVector
            {
                return SignalVector::zero();
            }
        };
        $session = str_repeat('a', 32);
        $pseudonym = (new RiskIdentityFactory($keys))->sessionId($session);
        // A live mark: written now, so the whole 90-day TTL window is
        // ahead of the assessment.
        $store->writeMark('session', $pseudonym, Quarantine::SPAM_MARK_KIND, (int) floor(microtime(true) * 1000));
        $reader = new StoreMarksReader($store);
        $classifier = new CidrNetworkClassifier([]);
        $engine = new AdaptiveRiskEngine(
            $store,
            $classifier,
            new RiskIdentityFactory($keys),
            new RiskScorer(),
            $policy,
            $keys,
            marksReader: $reader,
        );
        $context = new RiskContext(
            scope: 1,
            sourceIp: '203.0.113.27',
            sessionId: $session,
            principalId: null,
            event: RiskEventKind::PreIssue,
            networkFlags: $classifier->classify('203.0.113.27'),
            resources: new ResourcePressure(1000, 1000),
        );
        $decision = $engine->assessPreIssue($context);
        self::assertTrue($decision->quarantined);
        self::assertSame(RiskAction::Allow, $decision->action);
        self::assertTrue($decision->hasReason(RiskReason::SpamMarkQuarantine));
        $snapshot = $engine->metrics()->snapshot();
        $labels = array_values(array_filter(array_keys($snapshot['counters']), static fn (string $k): bool => str_contains($k, 'decisions:1:')));
        self::assertNotEmpty($labels, 'the decision metric exists');
        foreach ($labels as $label) {
            self::assertStringContainsString('decisions:1:quarantine:', $label, "the quarantine disposition counts as its own label: {$label}");
        }
    }

    /**
     * JSON decodes the scope keys as strings; the parser requires the
     * canonical integer keys, so the reader casts them back.
     *
     * @param array<string, mixed> $config
     * @return array<string, mixed>
     */
    private static function intScopeKeys(array $config): array
    {
        $scopes = [];
        foreach ($config['scopes'] as $scope => $row) {
            $scopes[(int) $scope] = $row;
        }
        $config['scopes'] = $scopes;

        return $config;
    }
}
