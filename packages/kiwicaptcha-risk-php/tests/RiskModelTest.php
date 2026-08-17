<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskDecision;
use KiwiCaptcha\Risk\RiskModel;
use KiwiCaptcha\Risk\RiskReason;
use PHPUnit\Framework\TestCase;

/**
 * MODEL REVISION: the risk packages expose the model
 * generation as RiskModel::REVISION (17), and every RiskDecision carries
 * it as modelRevision in the public JSON (bounded, unlike the internal
 * decisionId).
 */
final class RiskModelTest extends TestCase
{
    /** The revision constant exists with the shared cross-language value. */
    public function testRevisionConstantExistsWithTheSharedValue(): void
    {
        self::assertSame(17, RiskModel::REVISION);
        self::assertSame(17, $this->decision()->modelRevision);
    }

    public function testDecisionCarriesTheModelRevisionInThePublicJson(): void
    {
        $decision = $this->decision();
        self::assertSame(RiskModel::REVISION, $decision->modelRevision);

        $json = $decision->jsonSerialize();
        self::assertArrayHasKey('model_revision', $json);
        self::assertSame(17, $json['model_revision']);
        self::assertIsInt($json['model_revision'], 'the revision is a bounded integer');
    }

    public function testDecisionIdStaysOutOfThePublicJson(): void
    {
        $json = $this->decision()->jsonSerialize();
        self::assertArrayNotHasKey('decision_id', $json, 'decision_id is internal — never serialized');
        self::assertArrayNotHasKey('decisionId', $json);
    }

    public function testLimiterDenyDecisionCarriesTheRevision(): void
    {
        // The hard-rate-limit decision path constructs RiskDecision
        // directly; the defaulted modelRevision must apply there too.
        $decision = new RiskDecision(
            score: 1000,
            action: RiskAction::Deny,
            reasons: [RiskReason::HardRateLimit],
            policyVersion: 3,
            globalLevel: 0,
            retryAfterMs: 1000,
            band: 10,
        );
        self::assertSame(17, $decision->modelRevision);
        self::assertSame(17, $decision->jsonSerialize()['model_revision']);
    }

    private function decision(): RiskDecision
    {
        return new RiskDecision(
            score: 100,
            action: RiskAction::Sha16,
            reasons: [],
            policyVersion: 3,
            globalLevel: 0,
        );
    }
}
