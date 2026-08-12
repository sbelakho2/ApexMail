<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\VerifyError;

/**
 * Maps a core verification outcome to the risk-v1 event kind fed back into
 * the engine after a solve attempt (the "post-solve" signal).
 *
 * The mapping is conservative: anything that looks like a broken/tampered
 * proof is malformed traffic, a rejected-but-well-formed proof is an
 * invalid proof, an expired challenge is expiry (not abuse), and a
 * record-not-found is treated as a replay attempt (the one-shot record is
 * gone — either replayed or never existed). Infrastructure failures
 * (CapacityExceeded) return null: the request was not the client's fault
 * and must not pollute its risk state.
 */
final class RiskFeedback
{
    public static function eventFor(?VerifyError $error): ?RiskEventKind
    {
        if ($error === null) {
            return RiskEventKind::SolveSuccess;
        }

        return match ($error) {
            VerifyError::Expired => RiskEventKind::ExpiredChallenge,
            VerifyError::RecordNotFound => RiskEventKind::ReplayAttempt,
            VerifyError::MalformedToken,
            VerifyError::MalformedRecord,
            VerifyError::BadSignature => RiskEventKind::MalformedToken,
            VerifyError::CapacityExceeded => null,
            default => RiskEventKind::InvalidProof,
        };
    }
}
