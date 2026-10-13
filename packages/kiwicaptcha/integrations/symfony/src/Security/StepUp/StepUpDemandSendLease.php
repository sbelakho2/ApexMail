<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The answer of a successful send-lease claim: the demand record as the
 * lease left it, the claim metadata the settlement compares against,
 * and the exact pre-claim state a refused delivery restores.
 *
 * Every timestamp the claim decided on (the resend spacing, the lease
 * deadline, the recovery of a crashed claim) was taken on the store's
 * own clock, never the claiming worker's.
 */
final class StepUpDemandSendLease
{
    public function __construct(
        public readonly StepUpDemand $demand,
        /** The unix second of the claim, on the store's clock. */
        public readonly int $claimAt,
        /** The lease deadline (epoch millis, store clock) the settlement's compare-and-set names. */
        public readonly int $leaseUntilMs,
        /** The sends counter as it stood before the claim. */
        public readonly int $priorSends,
        /** The last-delivery second as it stood before the claim, null before the first delivery. */
        public readonly ?int $priorLastSentAt,
        /**
         * True when the claim recovered a crashed holder's expired
         * lease: the send slot was already charged, so this claim paid
         * no new credit and the record's visible send state did not
         * move again.
         */
        public readonly bool $recovered,
    ) {
    }
}
