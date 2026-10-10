<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Calibration;

/**
 * The provenance class of a confirmed calibration label: who asserted
 * the outcome. The weights are frozen cross-language constants,
 * documented in resources/calibration_v2.lua and mirrored by the Rust
 * ProvenanceClass in the kiwicaptcha-risk crate. A payment-network
 * assertion (a chargeback or a cleared payment) is the strongest signal
 * and carries 1.2x the mass of a human review. A security-event
 * assertion (an automated ban pipeline) carries 0.8x. App-reported
 * labels default to human review; an automatic success signal must
 * never feed the calibrator at all (the engine's feedback guard already
 * refuses one).
 *
 * The wire ids are the argv values the canonical confirm_v2.lua script
 * validates (0/1/2).
 */
enum ProvenanceClass: int
{
    /** A person reviewed the outcome (support flag, manual review). */
    case HumanReview = 0;

    /** An automated security pipeline asserted the outcome. */
    case SecurityEvent = 1;

    /** The payment network asserted the outcome (chargeback, refund). */
    case PaymentNetwork = 2;

    /** The frozen class weight (the mass multiplier of every bucket contribution). */
    public function weight(): float
    {
        return match ($this) {
            self::HumanReview => 1.0,
            self::SecurityEvent => 0.8,
            self::PaymentNetwork => 1.2,
        };
    }
}
