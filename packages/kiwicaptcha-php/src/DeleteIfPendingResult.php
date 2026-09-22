<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * The outcome of the atomic delete-if-pending cleanup,
 * {@see AtomicDeleteIfPendingInterface::deleteIfPending()}.
 *
 * The cleanup decision (missing / deleted-pending / consumed /
 * cancelled / corrupt) and the delete itself are one storage
 * transition. A record that a concurrent redeemer consumes between the
 * verifier's cheap failure and its cleanup can therefore never be
 * erased. The transition observes the consumed state, refuses the
 * delete, and returns the retained consumed state — the committed
 * result and the recorded operation identity — directly, with no
 * second lookup. A record carrying any runtime state other than the
 * exact pending marker is reported as 'corrupt' and left untouched:
 * the cleanup never destroys unknown state.
 */
final class DeleteIfPendingResult
{
    /**
     * @param string $state    one of five cleanup states.
     *                         'missing': no record exists.
     *                         'deleted-pending': the one-shot delete
     *                         ran.
     *                         'consumed': never deleted, evidence
     *                         preserved.
     *                         'cancelled': never deleted, dead but
     *                         retained.
     *                         'corrupt': the record carries an unknown
     *                         runtime state and is never mutated.
     * @param ConsumedRecord|null $consumed the retained consumed state,
     *                         present only for 'consumed'
     */
    public function __construct(
        public readonly string $state,
        public readonly ?ConsumedRecord $consumed = null,
    ) {
    }

    /** Whether the record was already consumed (and therefore kept). */
    public function wasConsumed(): bool
    {
        return $this->state === 'consumed';
    }

    /** Whether the record carries an unknown runtime state (never mutated). */
    public function isCorrupt(): bool
    {
        return $this->state === 'corrupt';
    }
}
