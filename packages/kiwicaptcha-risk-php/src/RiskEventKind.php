<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * Risk event kinds, fixed by the cross-language risk-v1 contract.
 *
 * Values 1..14 are authoritative and MUST NOT be renumbered: they are the
 * event identifiers passed into the canonical state script (risk.lua) and
 * must be byte-identical across the PHP and Rust implementations.
 */
enum RiskEventKind: int
{
    case PreIssue = 1;
    case ChallengeIssued = 2;
    case SolveSuccess = 3;
    case InvalidProof = 4;
    case MalformedToken = 5;
    case ExpiredChallenge = 6;
    case ReplayAttempt = 7;
    case ProtectedActionSuccess = 8;
    case ProtectedActionFailure = 9;
    case AuthenticationSuccess = 10;
    case AuthenticationFailure = 11;
    case ConfirmedLegitimate = 12;
    case ConfirmedAbuse = 13;
    case RateLimitHit = 14;
}
