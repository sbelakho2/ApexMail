<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * Risk event kinds, fixed by the cross-language risk-v1 contract.
 *
 * Values 1..17 are authoritative and MUST NOT be renumbered: they are the
 * event identifiers passed into the canonical state script (risk.lua) and
 * must be byte-identical across the PHP and Rust implementations.
 *
 * Values 18..20 are the additive risk-v2 surface: honeypot/decoy evidence
 * kinds. They ride the same observation path (idempotency domain separation,
 * dedupe receipt) but the state script treats them as no-ops (like
 * RiskDenied) — the honeypot signal itself is scored from the risk-v2
 * context, never from accumulated state.
 *
 * Value 21 is the cancellation surface: a server-issued challenge that
 * was cancelled before any verification. The event is risk-neutral: the
 * state script applies NO change, so the issued-and-abandoned challenge
 * keeps its issue-debt contribution (iss, which decays naturally and is
 * repaid only by an actual SolveSuccess). The kind stays for
 * observability — the cancellation is a resource-lifecycle operation
 * (the record is terminalized and the live-cap bookkeeping freed), never
 * a debt refund. Cancellation is client-influenceable (the endpoint
 * accepts possession of a pending nonce), so it must never erase the
 * issued-but-unsolved signal.
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
    case SourceRateLimitHit = 15;
    case GlobalCapacityHit = 16;
    case RiskDenied = 17;
    /** Risk-v2: a server-issued honeypot trap was filled by the client. */
    case HoneypotTriggered = 18;
    /** Risk-v2: a decoy (honeypot) endpoint was touched. */
    case DecoyEndpointTouched = 19;
    /** Risk-v2: a server-issued decoy form field was submitted. */
    case DecoyFieldSubmitted = 20;
    /** A server-issued challenge was cancelled before any verification. */
    case ChallengeCancelled = 21;

    /**
     * True for the three risk-v2 honeypot/decoy evidence kinds.
     *
     * The honeypot signal in the risk-v2 context is derived from ANY of
     * these kinds (probabilistic evidence — never a security gate).
     */
    public function isHoneypot(): bool
    {
        return match ($this) {
            self::HoneypotTriggered, self::DecoyEndpointTouched, self::DecoyFieldSubmitted => true,
            default => false,
        };
    }
}
