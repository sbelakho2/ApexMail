<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Outcomes;

/**
 * The receipt of one typed outcome report: what the report actually
 * did on each surface it touched.
 *
 * status is the shared accepted-outcome status of the ledger path (1 or
 * 2 = the first confirmation, 0 = nothing consumed) and stays 0 on the
 * identity path, which has no ledger entry. channelBooked is true when
 * the mapped feedback event was booked (a report context was given and
 * the ledger authorized it when the handle was a ledger handle).
 * marksWritten counts the long-memory marks written by this report and
 * markCount carries the mark's total count field after the write.
 * eventId is the deduped feedback event id when a channel was booked.
 */
final readonly class OutcomeReceipt
{
    public function __construct(
        public readonly Outcome $outcome,
        public readonly OutcomeHandleDimension $handleDimension,
        public readonly int $status,
        public readonly bool $channelBooked,
        public readonly int $marksWritten,
        public readonly int $markCount,
        public readonly ?string $eventId,
    ) {
    }
}
