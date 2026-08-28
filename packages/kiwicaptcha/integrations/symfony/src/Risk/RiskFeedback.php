<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\VerifyError;

/**
 * Maps a core verification outcome to the risk-v1 event kind fed back into
 * the engine after a solve attempt (the "post-solve" signal).
 *
 * The mapping is conservative: anything that looks like a broken or
 * tampered proof is malformed traffic, a rejected-but-well-formed proof
 * is an invalid proof, and an expired challenge is expiry, not abuse. A
 * record-not-found is treated as a replay attempt: the one-shot record
 * is gone, either replayed or never existed. Infrastructure failures
 * (CapacityExceeded) return null: the request was not the client's fault
 * and must not pollute its risk state.
 */
final class RiskFeedback
{
    /**
     * The canonical post-verification risk classification, used by the
     * native validator AND the provider-compatible SiteVerify surface
     * (the single shared mapping). The provenance rule is preserved:
     * attacker-controllable proof outcomes may repay a specific debt
     * (SolveSuccess) or add risk (malformed / invalid / replay
     * evidence), but never subtract it.
     *
     * Categories:
     *  - SolveSuccess        (null error): repays the issuance debt.
     *  - ReplayAttempt:      the retained-state replay outcomes
     *                        (AlreadyConsumed, RecordNotFound).
     *  - MalformedToken:     the wire/shape/signature corruptions.
     *  - InvalidProof:       the client's insufficient-work and
     *                        binding-circumstance evidence
     *                        (InsufficientWork, TooFast, TooManyAttempts,
     *                        TelemetryRejected, WrongScope,
     *                        RequestBindingMismatch, IpMismatch,
     *                        MissingClientIp).
     *  - ExpiredChallenge:   the client let the signed deadline pass (an
     *                        abandonment signal, not an infrastructure
     *                        condition).
     *  - No client event:    server/infrastructure failures
     *                        (CapacityExceeded, AdmissionUnavailable,
     *                        StorageUnavailable, ConsumeIndeterminate)
     *                        and deployment-context outcomes
     *                        (WrongPolicyVersion, WrongIssuer,
     *                        WrongRegion, UnknownKid,
     *                        UnsupportedArgon2Params) — clients must
     *                        never be punished for backend or rollout
     *                        conditions outside their control.
     */
    public static function eventFor(?VerifyError $error): ?RiskEventKind
    {
        if ($error === null) {
            return RiskEventKind::SolveSuccess;
        }

        return match ($error) {
            VerifyError::AlreadyConsumed,
            VerifyError::RecordNotFound => RiskEventKind::ReplayAttempt,
            VerifyError::MalformedToken,
            VerifyError::MalformedRecord,
            VerifyError::BadSignature => RiskEventKind::MalformedToken,
            VerifyError::InsufficientWork,
            VerifyError::TooFast,
            VerifyError::TooManyAttempts,
            VerifyError::TelemetryRejected,
            VerifyError::WrongScope,
            VerifyError::RequestBindingMismatch,
            VerifyError::IpMismatch,
            VerifyError::MissingClientIp => RiskEventKind::InvalidProof,
            VerifyError::Expired => RiskEventKind::ExpiredChallenge,
            // Server/infrastructure + deployment-context outcomes:
            // no client risk event.
            VerifyError::CapacityExceeded,
            VerifyError::AdmissionUnavailable,
            VerifyError::StorageUnavailable,
            VerifyError::ConsumeIndeterminate,
            VerifyError::WrongPolicyVersion,
            VerifyError::WrongIssuer,
            VerifyError::WrongRegion,
            VerifyError::UnknownKid,
            VerifyError::UnsupportedArgon2Params => null,
        };
    }
}
