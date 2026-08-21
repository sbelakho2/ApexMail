<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The typed result of the terminal transitions of an issued chain,
 * see {@see TransactionalChainedChallengeStateStore::markVerified()} /
 * {@see TransactionalChainedChallengeStateStore::markStepUpRequired()} /
 * {@see TransactionalChainedChallengeStateStore::markDenied()}, and of
 * the nonce-agnostic transaction terminalization of an open obligation,
 * see {@see TransactionalChainedChallengeStateStore::markTransactionDenied()}
 * / {@see TransactionalChainedChallengeStateStore::markTransactionStepUpRequired()}.
 * The result names the terminal state the chain reached, so the consumer
 * surface never carries magic strings.
 */
enum ChainVerifiedResult: string
{
    /** issued(nonce) -> verified(nonce) — this call performed the transition. */
    case VerifiedNew = 'verified_new';
    /** Already verified with the same nonce (a retry) — the chain is confirmed terminal. */
    case VerifiedSame = 'verified_same';
    /** issued(nonce) -> step_up_required(nonce) — this call performed the transition. */
    case StepUpRequiredNew = 'step_up_required_new';
    /** Already step_up_required (a retry) — the chain is confirmed terminal. */
    case StepUpRequiredSame = 'step_up_required_same';
    /** issued(nonce) -> denied(nonce) — this call performed the transition. */
    case DeniedNew = 'denied_new';
    /** Already denied (a retry) — the chain is confirmed terminal. */
    case DeniedSame = 'denied_same';
    /** The chain is already verified — the transaction already ended via Pass (its obligation is gone): the fresh disposition applies to the nonce alone. */
    case AlreadyVerified = 'already_verified';
    /** The chain holds a different nonce, is terminal with the other disposition, or is not in an issuable state. */
    case Conflict = 'conflict';
    /** The chain state is absent/expired. */
    case Missing = 'missing';
}
