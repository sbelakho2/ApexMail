<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The typed result of the TERMINAL transitions of an ISSUED chain
 * ({@see TransactionalChainedChallengeStateStore::markVerified()} /
 * {@see TransactionalChainedChallengeStateStore::markStepUpRequired()} /
 * {@see TransactionalChainedChallengeStateStore::markDenied()}) — the
 * result names the terminal state the chain reached, so the consumer
 * surface never carries magic strings.
 */
enum ChainVerifiedResult: string
{
    /** issued(nonce) -> verified(nonce) — this call performed the transition. */
    case VerifiedNew = 'verified_new';
    /** Already verified with the SAME nonce (a retry) — the chain is confirmed terminal. */
    case VerifiedSame = 'verified_same';
    /** issued(nonce) -> step_up_required(nonce) — this call performed the transition. */
    case StepUpRequiredNew = 'step_up_required_new';
    /** Already step_up_required with the SAME nonce (a retry) — the chain is confirmed terminal. */
    case StepUpRequiredSame = 'step_up_required_same';
    /** issued(nonce) -> denied(nonce) — this call performed the transition. */
    case DeniedNew = 'denied_new';
    /** Already denied with the SAME nonce (a retry) — the chain is confirmed terminal. */
    case DeniedSame = 'denied_same';
    /** The chain holds a DIFFERENT nonce or is not in an issuable state. */
    case Conflict = 'conflict';
    /** The chain state is absent/expired. */
    case Missing = 'missing';
}
