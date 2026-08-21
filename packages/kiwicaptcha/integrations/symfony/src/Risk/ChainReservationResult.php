<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The typed result of the owner-scoped reservation claim, see
 * {@see TransactionalChainedChallengeStateStore::reserve()}: never magic
 * strings at the consumer surface.
 */
enum ChainReservationResult: string
{
    /** This call reserved the chain (or took over an expired lease). */
    case Available = 'available';
    /** Already reserved by the same owner token. */
    case Retry = 'retry';
    /** Reserved by another owner with a live lease — the in-progress 503. */
    case Busy = 'busy';
    /** Reserved by another owner with an expired lease — claimed by this call. */
    case TakenOver = 'taken_over';
    /** The chain already issued a stage-2 challenge — recover it. */
    case Issued = 'issued';
    /** The chain is terminal verified — recover the issued challenge. */
    case Verified = 'verified';
    /** The chain is terminal step-up-required — the obligation stays bound. */
    case StepUpRequired = 'step_up_required';
    /** The chain is terminal denied — the obligation stays bound. */
    case Denied = 'denied';
    /** No state exists (never issued / expired). */
    case Missing = 'missing';
}
