<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * Risk event kinds, fixed by the cross-language risk-v1 contract.
 *
 * Values 1..17 are authoritative and MUST NOT be renumbered. They are the
 * event identifiers passed into the canonical state script (risk.lua) and
 * must be byte-identical across the PHP and Rust implementations.
 *
 * Values 18..20 are the additive risk-v2 surface: honeypot/decoy evidence
 * kinds. They ride the same observation path (idempotency domain separation,
 * dedupe receipt) but the state script treats them as no-ops (like
 * RiskDenied). The honeypot signal itself is scored from the risk-v2
 * context, never from accumulated state.
 *
 * Value 21 is the cancellation surface: a server-issued challenge that
 * was cancelled before any verification. The event is risk-neutral: the
 * state script applies no change, so the issued-and-abandoned challenge
 * keeps its issue-debt contribution (iss, which decays naturally and is
 * repaid only by an actual SolveSuccess). The kind stays for
 * replay/compat compatibility.
 *
 * Value 22 is the step-up completion surface: a server-verified secondary
 * authentication finished successfully. The event is trust-positive on the
 * identity channels and the principal channel (the same trust credit as
 * ProtectedActionSuccess, 8). A completed step-up is server-confirmed, so
 * it may decrement risk under the trust-source invariant. Never 18: the live
 * runtime already assigns 18..20 to the honeypot/decoy evidence kinds and
 * 21 to cancellation; 22 is the next free contract value. Mixed-version
 * readiness: an older state script treats 22 as an unknown kind (no-op,
 * safe in the trust direction only), and an older tryFrom refuses it
 * fail-closed rather than aliasing it.
 *
 * The trust-source invariant: SolveSuccess is trust-neutral. A valid
 * PoW proves expenditure (which the economic model explicitly permits
 * bots to pay), never legitimacy. Only server/application-confirmed
 * outcomes (ProtectedActionSuccess, AuthenticationSuccess,
 * ConfirmedLegitimate) may decrement risk; attacker-controllable
 * evidence may add risk or repay a specific debt, never subtract it.
 * Mirrored in the canonical risk Lua and in the Rust risk package.
 * observability. The cancellation is a resource-lifecycle operation
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
    /** A server-verified step-up finished successfully (NOT 18: 18..20 are the honeypot/decoy kinds). */
    case StepUpCompleted = 22;

    /**
     * True for the three risk-v2 honeypot/decoy evidence kinds.
     *
     * The honeypot signal in the risk-v2 context is derived from any of
     * these kinds (probabilistic evidence, never a security gate).
     */
    public function isHoneypot(): bool
    {
        return match ($this) {
            self::HoneypotTriggered, self::DecoyEndpointTouched, self::DecoyFieldSubmitted => true,
            default => false,
        };
    }
}
