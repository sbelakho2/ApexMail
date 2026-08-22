<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * The outcome of the atomic cancellation transition,
 * {@see CancellableStorageInterface::cancel()}.
 *
 * The transition decides missing / consumed / cancelled-before /
 * cancelled-now in one storage operation, closing the check-then-flip
 * TOCTOU. A record a concurrent redeemer consumes between the caller's
 * decision and the flip is observed in its consumed state here and never
 * cancelled. The outcome carries the state only, never any record
 * contents, so a cancellation can never be an oracle for the record.
 */
final class CancellationResult
{
    /**
     * @param string $state 'cancelled-now' (this call performed the
     *                      pending->cancelled flip), 'cancelled' (already
     *                      cancelled — idempotent), or 'consumed' (the
     *                      record is finalized and was never cancelled);
     *                      a missing record is a null result, not a state
     */
    public function __construct(
        public readonly string $state,
    ) {
    }

    /** Whether this call performed the pending->cancelled flip. */
    public function wasCancelledNow(): bool
    {
        return $this->state === 'cancelled-now';
    }
}
