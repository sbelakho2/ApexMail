<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The typed outcome of an obligation-aware post-solve acceptance.
 *
 * The guarded claim and the guarded finalize verify the transaction's
 * chain obligation atomically with the acceptance, so a stale Pass can
 * never commit (or be replayed) after the transaction state advanced.
 *
 * - Finalized:            the acceptance committed; the disposition is
 *                         authoritative.
 * - ObligationChanged:    the obligation moved since the snapshot (a
 *                         chain opened, cleared or re-anchored): the
 *                         caller must re-resolve, never accept.
 * - TransactionDenied:    the transaction is terminally denied: the
 *                         accepted disposition must be Deny.
 * - TransactionStepUp:    the transaction is terminally step-up: the
 *                         accepted disposition must be StepUp.
 * - ChainRequired:        an open nonterminal chain exists and this
 *                         nonce is not its current stage-2 nonce: the
 *                         acceptance must be ChainRequired.
 * - OwnershipLost:        the claim was not held (fresh path).
 * - Missing:              the record is absent (fresh path).
 * - Corrupt:              the record violates the strict schema.
 */
enum PostSolveFinalizeOutcome: string
{
    case Finalized = 'finalized';
    case ObligationChanged = 'obligation-changed';
    case TransactionDenied = 'transaction-denied';
    case TransactionStepUp = 'transaction-step-up';
    case ChainRequired = 'chain-required';
    case OwnershipLost = 'ownership-lost';
    case Missing = 'missing';
    case Corrupt = 'corrupt';
}
