<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The settlement of one claimed send lease: the claim's own stamps (the
 * compare-and-set key), the pre-claim state the store restores on a
 * refused delivery, and whether the delivery was actually handed off.
 *
 * A settlement whose lease stamp no longer matches the stored record
 * (the claim window expired and another worker recovered the slot)
 * settles nothing: the stale claimant's outcome is worthless.
 */
final class StepUpDemandSendSettlement
{
    public function __construct(
        public readonly string $demandId,
        /** The lease deadline the claim answered; the compare-and-set token. */
        public readonly int $leaseUntilMs,
        /** The claim second the claim answered; the second compare-and-set token. */
        public readonly int $claimAt,
        public readonly int $priorSends,
        public readonly ?int $priorLastSentAt,
        /**
         * True commits the claim's advanced send state (the delivery
         * was handed off, or its outcome is ambiguous — spent quota is
         * the fail-closed side). False restores the pre-claim state
         * exactly (the refusal happened before any handoff could).
         */
        public readonly bool $delivered,
    ) {
    }
}
