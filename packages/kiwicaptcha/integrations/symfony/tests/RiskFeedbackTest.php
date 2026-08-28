<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\RiskFeedback;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;

/**
 * The canonical post-verification risk classification shared by the
 * native validator and the provider-compatible SiteVerify surface.
 * Server/infrastructure and deployment-context outcomes must never
 * produce a client risk event; retained-state replays map to
 * ReplayAttempt, not a generic bad proof.
 */
final class RiskFeedbackTest extends TestCase
{
    public function testNullErrorIsSolveSuccess(): void
    {
        self::assertSame(RiskEventKind::SolveSuccess, RiskFeedback::eventFor(null));
    }

    public function testRetainedStateReplaysMapToReplayAttempt(): void
    {
        self::assertSame(RiskEventKind::ReplayAttempt, RiskFeedback::eventFor(VerifyError::AlreadyConsumed));
        self::assertSame(RiskEventKind::ReplayAttempt, RiskFeedback::eventFor(VerifyError::RecordNotFound));
    }

    public function testCorruptionsMapToMalformedToken(): void
    {
        self::assertSame(RiskEventKind::MalformedToken, RiskFeedback::eventFor(VerifyError::MalformedToken));
        self::assertSame(RiskEventKind::MalformedToken, RiskFeedback::eventFor(VerifyError::MalformedRecord));
        self::assertSame(RiskEventKind::MalformedToken, RiskFeedback::eventFor(VerifyError::BadSignature));
    }

    public function testClientAbuseEvidenceMapsToInvalidProof(): void
    {
        self::assertSame(RiskEventKind::InvalidProof, RiskFeedback::eventFor(VerifyError::InsufficientWork));
        self::assertSame(RiskEventKind::InvalidProof, RiskFeedback::eventFor(VerifyError::TooFast));
        self::assertSame(RiskEventKind::InvalidProof, RiskFeedback::eventFor(VerifyError::TooManyAttempts));
        self::assertSame(RiskEventKind::InvalidProof, RiskFeedback::eventFor(VerifyError::TelemetryRejected));
        self::assertSame(RiskEventKind::InvalidProof, RiskFeedback::eventFor(VerifyError::WrongScope));
        self::assertSame(RiskEventKind::InvalidProof, RiskFeedback::eventFor(VerifyError::RequestBindingMismatch));
    }

    public function testInfrastructureAndDeploymentOutcomesProduceNoClientEvent(): void
    {
        foreach ([
            VerifyError::CapacityExceeded,
            VerifyError::AdmissionUnavailable,
            VerifyError::StorageUnavailable,
            VerifyError::ConsumeIndeterminate,
            VerifyError::WrongPolicyVersion,
            VerifyError::WrongIssuer,
            VerifyError::WrongRegion,
            VerifyError::UnknownKid,
            VerifyError::UnsupportedArgon2Params,
        ] as $error) {
            self::assertNull(RiskFeedback::eventFor($error), $error->value.' must never punish the client');
        }
        // The binding-circumstance evidence stays a client signal.
        self::assertSame(RiskEventKind::InvalidProof, RiskFeedback::eventFor(VerifyError::IpMismatch));
        self::assertSame(RiskEventKind::InvalidProof, RiskFeedback::eventFor(VerifyError::MissingClientIp));
        // The signed-deadline pass is an abandonment signal.
        self::assertSame(RiskEventKind::ExpiredChallenge, RiskFeedback::eventFor(VerifyError::Expired));
    }
}
